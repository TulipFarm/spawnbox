//! Address plan for per-VM network namespaces. Every guest uses the same
//! address; each namespace gets its own /30 link to the host.

use std::net::Ipv4Addr;

pub const GUEST_IP: Ipv4Addr = Ipv4Addr::new(172, 16, 0, 2);
pub const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(172, 16, 0, 1);
pub const GUEST_MAC: &str = "06:00:ac:10:00:02";
/// Fixed so that a resumed guest's ARP cache still points at the new tap.
pub const GATEWAY_MAC: &str = "06:00:ac:10:00:01";
/// Host side of all namespace links. One /30 per VM.
pub const LINK_RANGE: &str = "10.200.0.0/16";
const LINK_BASE: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 0);
pub const MAX_LINKS: u32 = 1 << 14;

/// Firewall mark on the egress proxy's connections to servers. The host
/// firewall drops marked packets to the host's own addresses.
pub const EGRESS_MARK: u32 = 0x5bb0;

/// Destinations a sandbox may never reach: this-network, private, shared,
/// loopback, link-local (cloud metadata), benchmark, multicast and reserved.
pub const BLOCKED: &str = "0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, \
    169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3";

/// Host and namespace addresses of link `index`.
pub fn link_addresses(index: u32) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if index >= MAX_LINKS {
        return None;
    }
    let base = u32::from(LINK_BASE) + index * 4;
    Some((Ipv4Addr::from(base + 1), Ipv4Addr::from(base + 2)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gives_each_index_its_own_slash_30() {
        assert_eq!(
            link_addresses(0),
            Some((Ipv4Addr::new(10, 200, 0, 1), Ipv4Addr::new(10, 200, 0, 2)))
        );
        assert_eq!(
            link_addresses(64),
            Some((Ipv4Addr::new(10, 200, 1, 1), Ipv4Addr::new(10, 200, 1, 2)))
        );
        assert_eq!(
            link_addresses(MAX_LINKS - 1),
            Some((
                Ipv4Addr::new(10, 200, 255, 253),
                Ipv4Addr::new(10, 200, 255, 254)
            ))
        );
    }

    #[test]
    fn rejects_index_outside_the_range() {
        assert_eq!(link_addresses(MAX_LINKS), None);
    }
}
