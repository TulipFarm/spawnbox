//! Fix-ups that make each restored clone a distinct machine.

/// Most bytes of host entropy accepted per call.
pub const MAX_ENTROPY_BYTES: usize = 4096;

/// Hostnames are set from sandbox IDs. Allow only DNS-label characters.
pub fn validate_hostname(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 63 {
        return Err("hostname must be 1 to 63 characters".to_owned());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("hostname may contain only letters, digits, '-' and '_'".to_owned());
    }
    Ok(())
}

/// Builds the `struct rand_pool_info` argument for the `RNDADDENTROPY` ioctl:
/// entropy bits, buffer size in bytes, then the bytes themselves.
pub fn rand_pool_info(entropy: &[u8]) -> Result<Vec<u8>, String> {
    if entropy.is_empty() || entropy.len() > MAX_ENTROPY_BYTES {
        return Err(format!("entropy must be 1 to {MAX_ENTROPY_BYTES} bytes"));
    }
    let bytes = i32::try_from(entropy.len()).map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(8 + entropy.len());
    buf.extend_from_slice(&(bytes * 8).to_ne_bytes());
    buf.extend_from_slice(&bytes.to_ne_bytes());
    buf.extend_from_slice(entropy);
    Ok(buf)
}

#[cfg(target_os = "linux")]
pub fn add_entropy(entropy: &[u8]) -> Result<(), String> {
    use std::os::fd::AsRawFd;

    // _IOW('R', 0x03, int[2]); not exported by the libc crate.
    const RNDADDENTROPY: libc::Ioctl = 0x4008_5203;

    let info = rand_pool_info(entropy)?;
    let urandom = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/urandom")
        .map_err(|e| format!("open /dev/urandom: {e}"))?;
    // SAFETY: `info` is a valid rand_pool_info whose buf_size matches the
    // bytes that follow the header, and it outlives the call.
    let rc = unsafe { libc::ioctl(urandom.as_raw_fd(), RNDADDENTROPY, info.as_ptr()) };
    if rc < 0 {
        return Err(format!(
            "RNDADDENTROPY: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_sandbox_ids_as_hostnames() {
        assert!(validate_hostname("sbx_8f2kq1").is_ok());
        assert!(validate_hostname("sbx-1").is_ok());
    }

    #[test]
    fn rejects_unsafe_or_oversized_hostnames() {
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("a.b").is_err());
        assert!(validate_hostname("a b").is_err());
        assert!(validate_hostname(&"a".repeat(64)).is_err());
    }

    #[test]
    fn rand_pool_info_has_bit_count_then_byte_count_then_bytes() {
        let info = rand_pool_info(&[7; 64]).unwrap();
        assert_eq!(&info[0..4], &512i32.to_ne_bytes());
        assert_eq!(&info[4..8], &64i32.to_ne_bytes());
        assert_eq!(&info[8..], &[7; 64]);
    }

    #[test]
    fn rand_pool_info_rejects_empty_or_oversized_entropy() {
        assert!(rand_pool_info(&[]).is_err());
        assert!(rand_pool_info(&vec![0; MAX_ENTROPY_BYTES + 1]).is_err());
    }
}
