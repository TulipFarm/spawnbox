//! Finds the host name in the first bytes a client sends: SNI for TLS, the
//! `Host` header for HTTP.

use http::uri::{Authority, Uri};
use http::{HeaderMap, header::HOST};

use crate::policy::normalize_host;

/// The most the proxy reads before it decides.
pub const MAX_SNIFF: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Sniffed {
    /// Need more bytes.
    Incomplete,
    /// A TLS ClientHello, with its server name if it sent a valid one.
    Tls(Option<String>),
    /// An HTTP request, with its `Host` if it sent a valid one.
    Http(Option<String>),
    /// Neither.
    Other,
}

pub fn sniff(buf: &[u8]) -> Sniffed {
    match buf.first() {
        None => Sniffed::Incomplete,
        // A TLS handshake record.
        Some(0x16) => tls(buf),
        Some(b) if b.is_ascii_uppercase() => http(buf),
        Some(_) => Sniffed::Other,
    }
}

fn tls(buf: &[u8]) -> Sniffed {
    let mut acceptor = rustls::server::Acceptor::default();
    let mut input = buf;
    while !input.is_empty() {
        if acceptor.read_tls(&mut input).is_err() {
            return Sniffed::Other;
        }
    }
    match acceptor.accept() {
        Ok(None) if buf.len() < MAX_SNIFF => Sniffed::Incomplete,
        Ok(None) | Err(_) => Sniffed::Other,
        Ok(Some(accepted)) => Sniffed::Tls(
            accepted
                .client_hello()
                .server_name()
                .and_then(normalize_host),
        ),
    }
}

fn http(buf: &[u8]) -> Sniffed {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(buf) {
        Ok(httparse::Status::Partial) if buf.len() < MAX_SNIFF => Sniffed::Incomplete,
        Ok(httparse::Status::Partial) | Err(_) => Sniffed::Other,
        Ok(httparse::Status::Complete(_)) => Sniffed::Http(
            request
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("host"))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .and_then(host_without_port)
                .and_then(normalize_host),
        ),
    }
}

fn host_without_port(value: &str) -> Option<&str> {
    let value = value.trim();
    match value.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => Some(host),
        Some(_) => None,
        None => Some(value),
    }
}

/// Whether every host name in a request (the URI and each `Host` header)
/// is `host`. Inside an intercepted TLS connection a client could otherwise
/// send an allowed name in SNI and route the request elsewhere with `Host`.
pub fn request_host_is(uri: &Uri, headers: &HeaderMap, host: &str) -> bool {
    let named = |name: Option<&str>| name.and_then(normalize_host).as_deref() == Some(host);
    uri.authority().is_none_or(|a| named(Some(a.host())))
        && headers.get_all(HOST).iter().all(|value| {
            let authority = value
                .to_str()
                .ok()
                .and_then(|v| v.parse::<Authority>().ok());
            named(authority.as_ref().map(Authority::host))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use std::sync::Arc;

    fn client_hello(name: &str) -> Vec<u8> {
        let config = rustls::ClientConfig::builder_with_provider(crate::tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let name = ServerName::try_from(name.to_owned()).unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    #[test]
    fn reads_sni() {
        let hello = client_hello("API.GitHub.com");
        assert_eq!(sniff(&hello), Sniffed::Tls(Some("api.github.com".into())));
        assert_eq!(sniff(&hello[..20]), Sniffed::Incomplete);
        // rustls sends no SNI for an address.
        assert_eq!(sniff(&client_hello("1.1.1.1")), Sniffed::Tls(None));
    }

    #[test]
    fn reads_the_host_header() {
        let req = b"GET / HTTP/1.1\r\nHost: Example.com:8080\r\nAccept: */*\r\n\r\n";
        assert_eq!(sniff(req), Sniffed::Http(Some("example.com".into())));
        assert_eq!(sniff(&req[..20]), Sniffed::Incomplete);
        assert_eq!(sniff(b"GET / HTTP/1.0\r\n\r\n"), Sniffed::Http(None));
        assert_eq!(
            sniff(b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n"),
            Sniffed::Http(None)
        );
    }

    #[test]
    fn other_protocols() {
        assert_eq!(sniff(b"SSH-2.0-OpenSSH_9.9\r\n"), Sniffed::Other);
        assert_eq!(sniff(b"\x00\x01"), Sniffed::Other);
        assert_eq!(sniff(b""), Sniffed::Incomplete);
        assert_eq!(sniff(&[b'G'; MAX_SNIFF]), Sniffed::Other);
    }

    #[test]
    fn request_host_must_match() {
        let headers = |host: &str| {
            let mut h = HeaderMap::new();
            h.insert(HOST, host.parse().unwrap());
            h
        };
        let path: Uri = "/x".parse().unwrap();
        assert!(request_host_is(
            &path,
            &headers("API.github.com:443"),
            "api.github.com"
        ));
        assert!(request_host_is(&path, &HeaderMap::new(), "api.github.com"));
        assert!(!request_host_is(
            &path,
            &headers("evil.com"),
            "api.github.com"
        ));
        let full: Uri = "https://evil.com/x".parse().unwrap();
        assert!(!request_host_is(&full, &HeaderMap::new(), "api.github.com"));
        let mut two = headers("api.github.com");
        two.append(HOST, "evil.com".parse().unwrap());
        assert!(!request_host_is(&path, &two, "api.github.com"));
    }
}
