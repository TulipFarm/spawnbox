//! Egress policies: which host names a sandbox may connect to.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

const MAX_PATTERNS: usize = 256;
const MAX_MBPS: u32 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Any host, except platform blocks and `deny`. With a `deny` list,
    /// only named TCP connections and DNS.
    AllowAll,
    /// Only hosts in `allow` and not in `deny`, by name, on ports 80 and 443.
    Allowlist,
    /// Nothing.
    DenyAll,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub mode: Mode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Most megabits per second a sandbox may send. The lowest limit of all
    /// policies that apply wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_egress_mbps: Option<u32>,
    /// Most megabits per second a sandbox may receive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ingress_mbps: Option<u32>,
}

impl Policy {
    pub fn allow_all() -> Self {
        Self {
            mode: Mode::AllowAll,
            allow: Vec::new(),
            deny: Vec::new(),
            max_egress_mbps: None,
            max_ingress_mbps: None,
        }
    }

    /// Checks the patterns and lowercases them.
    pub fn check(&mut self) -> Result<(), String> {
        if self.mode != Mode::Allowlist && !self.allow.is_empty() {
            return Err("egress.allow only applies to mode allowlist".into());
        }
        if self.mode == Mode::Allowlist && self.allow.is_empty() {
            return Err("egress.allow is empty; use mode deny_all to block everything".into());
        }
        if self.mode == Mode::DenyAll && !self.deny.is_empty() {
            return Err("egress.deny does not apply to mode deny_all".into());
        }
        for (name, mbps) in [
            ("max_egress_mbps", self.max_egress_mbps),
            ("max_ingress_mbps", self.max_ingress_mbps),
        ] {
            if mbps.is_some_and(|n| !(1..=MAX_MBPS).contains(&n)) {
                return Err(format!("egress.{name} must be 1 to {MAX_MBPS}"));
            }
        }
        if self.allow.len() + self.deny.len() > MAX_PATTERNS {
            return Err(format!("at most {MAX_PATTERNS} egress patterns"));
        }
        for pattern in self.allow.iter_mut().chain(self.deny.iter_mut()) {
            *pattern = check_pattern(pattern)?;
        }
        Ok(())
    }

    /// Whether this policy lets a connection to `host` through. `host` is
    /// `None` when the connection carries no name (not HTTP, or TLS without
    /// SNI); only `allow_all` without a `deny` list lets those through,
    /// since a `deny` list is checked by name.
    pub fn allows(&self, host: Option<&str>) -> bool {
        match (self.mode, host) {
            (Mode::DenyAll, _) => false,
            (Mode::AllowAll, None) => self.deny.is_empty(),
            (Mode::Allowlist, None) => false,
            (Mode::AllowAll, Some(host)) => !matches_any(&self.deny, host),
            (Mode::Allowlist, Some(host)) => {
                matches_any(&self.allow, host) && !matches_any(&self.deny, host)
            }
        }
    }
}

/// The lowest send and receive limits of `policies`, in megabits per
/// second.
pub fn rates<'a>(policies: impl IntoIterator<Item = &'a Policy>) -> (Option<u32>, Option<u32>) {
    let lowest = |a: Option<u32>, b: Option<u32>| match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    policies.into_iter().fold((None, None), |(up, down), p| {
        (
            lowest(up, p.max_egress_mbps),
            lowest(down, p.max_ingress_mbps),
        )
    })
}

/// The stricter of two modes.
pub fn strictest(a: Mode, b: Mode) -> Mode {
    let rank = |mode| match mode {
        Mode::AllowAll => 0,
        Mode::Allowlist => 1,
        Mode::DenyAll => 2,
    };
    if rank(a) >= rank(b) { a } else { b }
}

/// `pattern` matches `host` exactly, or `*.example.com` matches any name
/// below `example.com`. Both are lowercase.
pub fn matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(domain) => host
            .strip_suffix(domain)
            .is_some_and(|rest| rest.len() > 1 && rest.ends_with('.')),
        None => pattern == host,
    }
}

pub fn matches_any(patterns: &[String], host: &str) -> bool {
    patterns.iter().any(|p| matches(p, host))
}

/// A lowercase host pattern, or why it is not one.
pub fn check_pattern(pattern: &str) -> Result<String, String> {
    let (wildcard, name) = match pattern.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, pattern),
    };
    let name = normalize_host(name).ok_or_else(|| format!("bad host pattern: {pattern:?}"))?;
    if name.parse::<Ipv4Addr>().is_ok() {
        return Err(format!(
            "host patterns are names, not addresses: {pattern:?}"
        ));
    }
    Ok(if wildcard { format!("*.{name}") } else { name })
}

/// Lowercases a DNS name and drops a trailing dot. `None` if it is not a
/// valid name.
pub fn normalize_host(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    valid.then_some(host)
}

/// Addresses no sandbox may reach: this-network, private, shared, loopback,
/// link-local (cloud metadata), benchmark, multicast and reserved.
pub fn is_blocked(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_unspecified()
        || a == 0
        || ip.is_private()
        || (a == 100 && (64..128).contains(&b))
        || ip.is_loopback()
        || ip.is_link_local()
        || (a == 192 && b == 0 && ip.octets()[2] == 0)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 224
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: &str) -> Policy {
        let mut p: Policy = serde_json::from_str(json).unwrap();
        p.check().unwrap();
        p
    }

    #[test]
    fn wildcards_match_subdomains_only() {
        assert!(matches("*.github.com", "api.github.com"));
        assert!(matches("*.github.com", "a.b.github.com"));
        assert!(!matches("*.github.com", "github.com"));
        assert!(!matches("*.github.com", "evilgithub.com"));
        assert!(matches("github.com", "github.com"));
        assert!(!matches("github.com", "api.github.com"));
    }

    #[test]
    fn allowlist_needs_a_listed_name() {
        let p = policy(
            r#"{"mode":"allowlist","allow":["GitHub.com.","*.npmjs.org"],"deny":["bad.npmjs.org"]}"#,
        );
        assert_eq!(p.allow, ["github.com", "*.npmjs.org"]);
        assert!(p.allows(Some("github.com")));
        assert!(p.allows(Some("registry.npmjs.org")));
        assert!(!p.allows(Some("bad.npmjs.org")));
        assert!(!p.allows(Some("example.com")));
        assert!(!p.allows(None));
    }

    #[test]
    fn allowlist_must_list_something() {
        let mut p: Policy = serde_json::from_str(r#"{"mode":"allowlist"}"#).unwrap();
        assert!(p.check().is_err());
    }

    #[test]
    fn allow_all_and_deny_all() {
        assert!(Policy::allow_all().allows(None));
        let p = policy(r#"{"mode":"allow_all","deny":["example.com"]}"#);
        assert!(!p.allows(None), "a deny list needs a name to check");
        assert!(p.allows(Some("github.com")));
        assert!(!p.allows(Some("example.com")));
        assert!(!policy(r#"{"mode":"deny_all"}"#).allows(Some("github.com")));
    }

    #[test]
    fn rejects_bad_policies() {
        for json in [
            r#"{"mode":"allow_all","allow":["a.com"]}"#,
            r#"{"mode":"deny_all","deny":["a.com"]}"#,
            r#"{"mode":"allowlist","allow":["1.2.3.4"]}"#,
            r#"{"mode":"allowlist","allow":["a..com"]}"#,
            r#"{"mode":"allowlist","allow":["*"]}"#,
            r#"{"mode":"allowlist","allow":["a.com/x"]}"#,
        ] {
            let mut p: Policy = serde_json::from_str(json).unwrap();
            assert!(p.check().is_err(), "{json}");
        }
        assert!(serde_json::from_str::<Policy>(r#"{"mode":"allowlist","ports":[22]}"#).is_err());
    }

    #[test]
    fn lowest_rate_wins() {
        let server = policy(r#"{"mode":"allow_all","max_egress_mbps":100}"#);
        let tenant = policy(r#"{"mode":"allow_all","max_egress_mbps":20,"max_ingress_mbps":50}"#);
        let open = Policy::allow_all();
        assert_eq!(rates([&server, &tenant, &open]), (Some(20), Some(50)));
        assert_eq!(rates([&open]), (None, None));
        let mut zero: Policy =
            serde_json::from_str(r#"{"mode":"allow_all","max_ingress_mbps":0}"#).unwrap();
        assert!(zero.check().is_err());
    }

    #[test]
    fn strictest_mode_wins() {
        let open = Policy::allow_all();
        let list = policy(r#"{"mode":"allowlist","allow":["a.com"]}"#);
        let closed = policy(r#"{"mode":"deny_all"}"#);
        assert_eq!(strictest(open.mode, list.mode), Mode::Allowlist);
        assert_eq!(strictest(list.mode, closed.mode), Mode::DenyAll);
        assert_eq!(strictest(open.mode, open.mode), Mode::AllowAll);
    }

    #[test]
    fn blocks_private_and_metadata_addresses() {
        for ip in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "127.0.0.1",
            "100.64.0.1",
            "0.1.2.3",
            "224.0.0.1",
        ] {
            assert!(is_blocked(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "140.82.112.3", "100.128.0.1", "172.32.0.1"] {
            assert!(!is_blocked(ip.parse().unwrap()), "{ip}");
        }
    }
}
