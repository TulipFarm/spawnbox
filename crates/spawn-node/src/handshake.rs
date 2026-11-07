/// Parses Firecracker's reply to `CONNECT <port>`: `OK <host_port>`.
pub fn parse_ok(line: &[u8]) -> Result<u32, String> {
    let text = std::str::from_utf8(line).map_err(|_| "reply is not UTF-8".to_owned())?;
    text.trim_end()
        .strip_prefix("OK ")
        .and_then(|port| port.parse().ok())
        .ok_or_else(|| format!("unexpected vsock reply: {text:?}"))
}

#[cfg(test)]
mod tests {
    use super::parse_ok;

    #[test]
    fn accepts_ok_with_port() {
        assert_eq!(parse_ok(b"OK 1073741824"), Ok(1_073_741_824));
        assert_eq!(parse_ok(b"OK 5\r"), Ok(5));
    }

    #[test]
    fn rejects_other_replies() {
        for reply in [&b""[..], b"OK", b"OK x", b"NOPE 5", b"\xff"] {
            assert!(parse_ok(reply).is_err(), "{reply:?}");
        }
    }
}
