//! Ties the egress proxy to VM slots: a VM's traffic reaches the proxy from
//! its namespace address, which is fixed by its slot index.

use std::net::Ipv4Addr;

use spawn_egress::{Attached, Egress, Mode, Policy, Registration, policy::strictest};
use spawn_node::net::NetMode;
use spawn_node::netplan::link_addresses;

pub struct Network {
    pub proxy: Egress,
    /// The server's policy. Every connection must also pass it.
    pub policy: Policy,
    /// Trusted by every build, so intercepted HTTPS verifies.
    pub ca_pem: String,
}

/// Environment that points tools with their own CA bundle at the system
/// bundle, which has the egress CA.
pub const CA_ENV: [(&str, &str); 4] = [
    ("SSL_CERT_FILE", BUNDLE),
    ("REQUESTS_CA_BUNDLE", BUNDLE),
    ("NODE_EXTRA_CA_CERTS", BUNDLE),
    ("CURL_CA_BUNDLE", BUNDLE),
];
const BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

impl Network {
    /// What the namespace of a VM with `policies` forwards.
    pub fn mode(&self, policies: &[Policy]) -> NetMode {
        let mode = policies.iter().fold(self.policy.mode, |mode, policy| {
            strictest(mode, policy.mode)
        });
        match mode {
            Mode::AllowAll => NetMode::Open,
            Mode::Allowlist => NetMode::Restricted,
            Mode::DenyAll => NetMode::Closed,
        }
    }

    /// The send and receive limits, in megabits per second, of a VM with
    /// `policies`.
    pub fn rates(&self, policies: &[Policy]) -> (Option<u32>, Option<u32>) {
        spawn_egress::policy::rates(std::iter::once(&self.policy).chain(policies))
    }

    /// Call before the VM in slot `index` starts.
    pub fn register(
        &self,
        index: u32,
        sandbox: &str,
        tenant: Option<&str>,
        policies: Vec<Policy>,
        secrets: Vec<Attached>,
    ) {
        if let Some(addr) = source(index) {
            self.proxy.register(
                addr,
                Registration {
                    sandbox: sandbox.to_owned(),
                    tenant: tenant.map(str::to_owned),
                    policies,
                    secrets,
                },
            );
        }
    }

    /// Call once the VM in slot `index` is gone, before the slot is reused.
    pub fn unregister(&self, index: u32) {
        if let Some(addr) = source(index) {
            self.proxy.unregister(addr);
        }
    }
}

/// The address the proxy sees connections from slot `index` come from.
fn source(index: u32) -> Option<Ipv4Addr> {
    link_addresses(index).map(|(_, ns)| ns)
}
