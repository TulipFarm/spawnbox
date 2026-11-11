//! Health checks of a service's port.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// What a check looks for.
#[derive(Clone, Debug)]
pub enum Check {
    /// A 2xx reply to `GET` of this path.
    Http(String),
    /// A connection.
    Tcp,
}

/// Whether the check passes within `timeout`.
pub async fn passes(check: &Check, port: u16, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, run(check, port))
        .await
        .unwrap_or(false)
}

async fn run(check: &Check, port: u16) -> bool {
    let Some(mut stream) = connect(port).await else {
        return false;
    };
    let Check::Http(path) = check else {
        return true;
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\nUser-Agent: spawnbox-health\r\n\
         Connection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).await.is_err() {
        return false;
    }
    let mut head = Vec::new();
    let mut buf = [0; 512];
    while !head.windows(2).any(|w| w == b"\r\n") && head.len() < 4096 {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    is_success(&head)
}

async fn connect(port: u16) -> Option<TcpStream> {
    for ip in [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()] {
        if let Ok(stream) = TcpStream::connect(SocketAddr::new(ip, port)).await {
            return Some(stream);
        }
    }
    None
}

/// Whether an HTTP reply starts with a 2xx status line.
fn is_success(head: &[u8]) -> bool {
    let line = head.split(|b| *b == b'\r').next().unwrap_or_default();
    let mut parts = line.split(|b| *b == b' ');
    parts.next().is_some_and(|v| v.starts_with(b"HTTP/"))
        && parts.next().is_some_and(|s| s.len() == 3 && s[0] == b'2')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_2xx_status_line_passes() {
        assert!(is_success(b"HTTP/1.1 200 OK\r\n"));
        assert!(is_success(b"HTTP/1.0 204 No Content\r\n"));
        assert!(!is_success(b"HTTP/1.1 500 Internal Server Error\r\n"));
        assert!(!is_success(b"HTTP/1.1 301 Moved\r\n"));
        assert!(!is_success(b"SSH-2.0-OpenSSH\r\n"));
        assert!(!is_success(b""));
    }
}
