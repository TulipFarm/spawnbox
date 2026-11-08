//! Per-VM network: a namespace with a tap device for the guest and a veth
//! link to the host. The host NATs the traffic out. Uses `ip` and `nft`.
//! Under gVisor the guest end is a veth pair into a second, inner namespace,
//! because runsc takes over every interface of the namespace it joins.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::netplan::{
    BLOCKED, EGRESS_MARK, GATEWAY_IP, GATEWAY_MAC, GUEST_IP, GUEST_MAC, LINK_RANGE, link_addresses,
};
use crate::sh::{run, run_with_input};

const NS_PREFIX: &str = "spawnbox-";
const HOST_LINK_PREFIX: &str = "sbx";
const HOST_TABLE: &str = "spawnbox";
pub const TAP: &str = "tap0";
/// The gateway end of the veth pair to a gVisor guest.
const GVISOR_GATEWAY: &str = "gv0";
const INNER_SUFFIX: &str = "-guest";

/// How the guest joins the namespace.
#[derive(Clone, Copy, Debug)]
pub enum GuestLink {
    /// A tap device for Firecracker, owned by the jailed user.
    Tap { owner: u32 },
    /// A veth pair whose guest end, `eth0`, is in an inner namespace for
    /// runsc.
    Veth,
}

/// What the namespace forwards from the guest. The egress proxy on the host
/// applies the rest of the policy to TCP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NetMode {
    /// TCP, UDP and ICMP, except blocked ranges and SMTP.
    Open,
    /// Only TCP and DNS.
    Restricted,
    /// Only TCP, which the proxy refuses and logs. No DNS.
    Closed,
}

pub struct Netns {
    name: String,
    /// The guest's namespace under gVisor.
    inner: Option<String>,
    link: String,
    host_ip: Ipv4Addr,
}

impl Netns {
    /// Limits what the guest sends and receives, in megabits per second.
    /// `None` adds no limit. Each direction is shaped where it leaves a
    /// link: received traffic on the host end, sent traffic on the
    /// namespace end.
    pub async fn set_rates(&self, send: Option<u32>, receive: Option<u32>) -> Result<()> {
        shape(None, &self.link, receive).await?;
        shape(Some(&self.name), "veth0", send).await
    }

    pub async fn create(
        id: &str,
        index: u32,
        guest: GuestLink,
        dns: Ipv4Addr,
        mode: NetMode,
    ) -> Result<Self> {
        let (host_ip, ns_ip) = link_addresses(index).context("too many VMs for the link range")?;
        let name = format!("{NS_PREFIX}{id}");
        let link = format!("{HOST_LINK_PREFIX}{index}");
        let ns = Self {
            inner: matches!(guest, GuestLink::Veth).then(|| format!("{name}{INNER_SUFFIX}")),
            name,
            link: link.clone(),
            host_ip,
        };
        let n = ns.name.as_str();

        run("ip", &["netns", "add", n]).await?;
        run(
            "ip",
            &[
                "link", "add", &link, "type", "veth", "peer", "name", "veth0", "netns", n,
            ],
        )
        .await?;
        run(
            "ip",
            &["addr", "add", &format!("{host_ip}/30"), "dev", &link],
        )
        .await?;
        run("ip", &["link", "set", &link, "up"]).await?;
        let gateway = format!("{GATEWAY_IP}/30");
        let ns_addr = format!("{ns_ip}/30");
        let host = host_ip.to_string();
        #[rustfmt::skip]
        let steps: [&[&str]; 4] = [
            &["link", "set", "lo", "up"],
            &["addr", "add", &ns_addr, "dev", "veth0"],
            &["link", "set", "veth0", "up"],
            &["route", "add", "default", "via", &host],
        ];
        for step in steps {
            let mut args = vec!["-n", n];
            args.extend_from_slice(step);
            run("ip", &args).await?;
        }
        let guest_if = match guest {
            GuestLink::Tap { owner } => {
                let owner = owner.to_string();
                // Owned by the jailed Firecracker user, so it can open the
                // device.
                run(
                    "ip",
                    &[
                        "-n", n, "tuntap", "add", TAP, "mode", "tap", "user", &owner, "group",
                        &owner,
                    ],
                )
                .await?;
                TAP
            }
            GuestLink::Veth => {
                let inner = ns.inner.as_deref().unwrap_or_default();
                add_guest_ns(n, inner).await?;
                GVISOR_GATEWAY
            }
        };
        run("ip", &["-n", n, "addr", "add", &gateway, "dev", guest_if]).await?;
        run(
            "ip",
            &[
                "-n",
                n,
                "link",
                "set",
                guest_if,
                "address",
                GATEWAY_MAC,
                "up",
            ],
        )
        .await?;
        run(
            "ip",
            &["netns", "exec", n, "sysctl", "-qw", "net.ipv4.ip_forward=1"],
        )
        .await?;
        run_with_input(
            "ip",
            &["netns", "exec", n, "nft", "-f", "-"],
            Some(&ns_rules(guest_if, dns, mode)),
        )
        .await?;
        Ok(ns)
    }

    pub fn path(&self) -> PathBuf {
        PathBuf::from("/var/run/netns").join(&self.name)
    }

    /// The namespace runsc joins, if any.
    pub fn guest_path(&self) -> Option<PathBuf> {
        self.inner
            .as_ref()
            .map(|inner| PathBuf::from("/var/run/netns").join(inner))
    }

    pub fn host_ip(&self) -> Ipv4Addr {
        self.host_ip
    }

    /// Deleting the namespace also deletes its tap and rules. The kernel
    /// does that later, in the background, so the host end of the veth pair
    /// is deleted first: its name and addresses are free again on return.
    pub async fn remove(self) {
        let mut steps = vec![
            ["link", "del", self.link.as_str()],
            ["netns", "del", self.name.as_str()],
        ];
        if let Some(inner) = &self.inner {
            steps.push(["netns", "del", inner.as_str()]);
        }
        for args in steps {
            if let Err(error) = run("ip", &args).await {
                eprintln!("warning: {error}");
            }
        }
    }
}

/// Adds the inner namespace with the guest's `eth0`: its addresses and route
/// tell runsc how to set up the guest's network.
async fn add_guest_ns(outer: &str, inner: &str) -> Result<()> {
    let guest = format!("{GUEST_IP}/30");
    let gateway = GATEWAY_IP.to_string();
    run("ip", &["netns", "add", inner]).await?;
    run(
        "ip",
        &[
            "-n",
            outer,
            "link",
            "add",
            GVISOR_GATEWAY,
            "type",
            "veth",
            "peer",
            "name",
            "eth0",
            "netns",
            inner,
        ],
    )
    .await?;
    #[rustfmt::skip]
    let steps: [&[&str]; 4] = [
        &["link", "set", "lo", "up"],
        &["addr", "add", &guest, "dev", "eth0"],
        &["link", "set", "eth0", "address", GUEST_MAC, "up"],
        &["route", "add", "default", "via", &gateway],
    ];
    for step in steps {
        let mut args = vec!["-n", inner];
        args.extend_from_slice(step);
        run("ip", &args).await?;
    }
    Ok(())
}

/// Puts a token bucket on the queue that leaves `dev`. `dev` is in namespace
/// `ns`, or on the host.
async fn shape(ns: Option<&str>, dev: &str, mbps: Option<u32>) -> Result<()> {
    let Some(mbps) = mbps else {
        return Ok(());
    };
    let rate = format!("{mbps}mbit");
    // A tenth of a second of traffic, and at least 64 KiB.
    let burst = (u64::from(mbps) * 1_000_000 / 8 / 10)
        .max(64 * 1024)
        .to_string();
    let mut args = match ns {
        Some(ns) => vec!["netns", "exec", ns, "tc"],
        None => vec![],
    };
    args.extend([
        "qdisc", "replace", "dev", dev, "root", "tbf", "rate", &rate, "burst", &burst, "latency",
        "50ms",
    ]);
    run(if ns.is_some() { "ip" } else { "tc" }, &args).await?;
    Ok(())
}

/// Removes the namespaces and host link that a failed start may have left.
pub async fn remove_failed(id: &str, index: u32) {
    let _ = run("ip", &["netns", "del", &format!("{NS_PREFIX}{id}")]).await;
    let _ = run(
        "ip",
        &["netns", "del", &format!("{NS_PREFIX}{id}{INNER_SUFFIX}")],
    )
    .await;
    let _ = run(
        "ip",
        &["link", "del", &format!("{HOST_LINK_PREFIX}{index}")],
    )
    .await;
}

/// Inside the namespace: DNS sent to the gateway goes to `dns`; the guest may
/// not reach the namespace itself, blocked ranges, or SMTP; nothing may
/// connect in to the guest. `mode` limits what else leaves. `guest` is the
/// guest's interface. Replies to the namespace's own connections, which
/// reach a gVisor guest's agent, may come in.
fn ns_rules(guest: &str, dns: Ipv4Addr, mode: NetMode) -> String {
    let dns_rule = match mode {
        NetMode::Closed => String::new(),
        _ => format!(
            "iifname \"{guest}\" ip daddr {GATEWAY_IP} meta l4proto {{ tcp, udp }} th dport 53 dnat ip to {dns}"
        ),
    };
    let out = match mode {
        NetMode::Open => format!(r#"iifname "{guest}" oifname "veth0" accept"#),
        NetMode::Restricted => {
            format!(r#"iifname "{guest}" oifname "veth0" meta l4proto tcp accept"#)
        }
        NetMode::Closed => format!(
            r#"iifname "{guest}" oifname "veth0" ip daddr {dns} th dport 53 drop
    iifname "{guest}" oifname "veth0" meta l4proto tcp accept"#
        ),
    };
    format!(
        r#"table inet spawnbox {{
  chain prerouting {{
    type nat hook prerouting priority dstnat;
    {dns_rule}
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat;
    oifname "veth0" ip saddr {GUEST_IP} masquerade
  }}
  chain input {{
    type filter hook input priority filter; policy accept;
    iifname "{guest}" ct state established accept
    iifname "{guest}" drop
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    iifname "{guest}" meta nfproto ipv6 drop
    iifname "{guest}" oifname "veth0" ct status dnat accept
    iifname "{guest}" oifname "veth0" ip daddr {{ {BLOCKED} }} drop
    iifname "{guest}" oifname "veth0" tcp dport 25 drop
    {out}
  }}
}}
"#
    )
}

/// Host ports of the egress proxy and DNS forwarder.
#[derive(Clone, Copy, Debug)]
pub struct ProxyPorts {
    pub tcp: u16,
    pub dns: u16,
}

/// Host-wide NAT and filtering for all namespace links.
pub struct HostNet {
    old_forward: String,
}

impl HostNet {
    /// With `proxy`, every DNS query from a namespace, to any address, goes
    /// to the DNS forwarder, and every other TCP connection goes to the
    /// egress proxy. The proxy's own connections, marked with `EGRESS_MARK`,
    /// may not reach the host.
    pub async fn setup(dns: Ipv4Addr, proxy: Option<ProxyPorts>) -> Result<Self> {
        // Rules from a crashed run; missing is fine.
        let _ = run("nft", &["delete", "table", "inet", HOST_TABLE]).await;
        let old_forward = run("sysctl", &["-n", "net.ipv4.ip_forward"])
            .await?
            .trim()
            .to_owned();
        let p = HOST_LINK_PREFIX;
        let (redirect, proxy_input) = match proxy {
            None => (String::new(), String::new()),
            Some(ProxyPorts {
                tcp: port,
                dns: dns_port,
            }) => (
                format!(
                    r#"
  chain prerouting {{
    type nat hook prerouting priority dstnat;
    iifname "{p}*" meta l4proto {{ tcp, udp }} th dport 53 redirect to :{dns_port}
    iifname "{p}*" meta l4proto tcp redirect to :{port}
  }}
  chain output {{
    type filter hook output priority filter; policy accept;
    meta mark {EGRESS_MARK} fib daddr type local meta l4proto tcp reject with tcp reset
  }}"#
                ),
                format!(
                    r#"iifname "{p}*" tcp dport {port} accept
    iifname "{p}*" meta l4proto {{ tcp, udp }} th dport {dns_port} accept
    iifname != "{p}*" tcp dport {port} drop
    iifname != "{p}*" meta l4proto {{ tcp, udp }} th dport {dns_port} drop
    "#
                ),
            ),
        };
        let rules = format!(
            r#"table inet {HOST_TABLE} {{{redirect}
  chain input {{
    type filter hook input priority filter; policy accept;
    {proxy_input}iifname "{p}*" drop
  }}
  chain forward {{
    type filter hook forward priority filter; policy accept;
    oifname "{p}*" ct state established,related accept
    oifname "{p}*" drop
    iifname "{p}*" ip daddr {dns} meta l4proto {{ tcp, udp }} th dport 53 accept
    iifname "{p}*" ip daddr {{ {BLOCKED} }} drop
    iifname "{p}*" tcp dport 25 drop
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat;
    ip saddr {LINK_RANGE} oifname != "{p}*" masquerade
  }}
}}
"#
        );
        run_with_input("nft", &["-f", "-"], Some(&rules)).await?;
        run("sysctl", &["-qw", "net.ipv4.ip_forward=1"]).await?;
        Ok(Self { old_forward })
    }

    pub async fn teardown(self) {
        let restore = format!("net.ipv4.ip_forward={}", self.old_forward);
        for (program, args) in [
            ("nft", vec!["delete", "table", "inet", HOST_TABLE]),
            ("sysctl", vec!["-qw", restore.as_str()]),
        ] {
            if let Err(error) = run(program, &args).await {
                eprintln!("warning: {error}");
            }
        }
    }
}

/// Removes VM namespaces left by a failed step or a crashed run.
pub async fn remove_stale_namespaces() -> Result<()> {
    for line in run("ip", &["netns", "list"]).await?.lines() {
        if let Some(name) = line
            .split_whitespace()
            .next()
            .filter(|n| n.starts_with(NS_PREFIX))
        {
            run("ip", &["netns", "del", name]).await?;
        }
    }
    Ok(())
}
