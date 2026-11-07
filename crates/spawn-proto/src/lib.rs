//! Shared types for talking to `spawn-guest` over vsock, or TCP under gVisor.

pub mod guest {
    pub mod v1 {
        tonic::include_proto!("spawn.guest.v1");
    }
}

use guest::v1::ProtocolVersion;

/// The vsock port `spawn-guest` listens on.
pub const GUEST_VSOCK_PORT: u32 = 1024;

/// The TCP port `spawn-guest` listens on under gVisor, which has no vsock.
pub const GUEST_TCP_PORT: u16 = 1024;

pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 5 };

/// The host accepts guests with the same major version and at most
/// two minor versions apart, so older builds keep working after upgrades.
pub fn is_compatible(host: &ProtocolVersion, guest: &ProtocolVersion) -> bool {
    host.major == guest.major && host.minor.abs_diff(guest.minor) <= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(major: u32, minor: u32) -> ProtocolVersion {
        ProtocolVersion { major, minor }
    }

    #[test]
    fn accepts_up_to_two_minor_versions_apart_in_either_direction() {
        assert!(is_compatible(&v(1, 5), &v(1, 5)));
        assert!(is_compatible(&v(1, 5), &v(1, 3)));
        assert!(is_compatible(&v(1, 3), &v(1, 5)));
        assert!(!is_compatible(&v(1, 5), &v(1, 2)));
        assert!(!is_compatible(&v(1, 2), &v(1, 5)));
    }

    #[test]
    fn rejects_a_different_major_version() {
        assert!(!is_compatible(&v(1, 0), &v(2, 0)));
    }
}
