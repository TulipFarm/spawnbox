//! Published ports: requests, preview host names and access tokens.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ids;
use crate::model::ApiError;

pub const DEFAULT_TOKEN_TTL_S: u64 = 86_400;
const MAX_TOKEN_TTL_S: u64 = 30 * 86_400;
/// Query parameter that carries a token link.
pub const TOKEN_PARAM: &str = "spawnbox_token";
/// Cookie a token link is traded for.
pub const COOKIE: &str = "spawnbox_preview";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// Anyone with the URL.
    Public,
    /// A link with an expiring token, traded for a cookie on first visit.
    #[default]
    Token,
    /// Needs the API key in `Authorization`.
    Private,
    /// Only the forward listener reaches it; previews answer `404`.
    Gateway,
}

/// `POST /v1/sandboxes/{id}/ports`
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publish {
    pub port: u32,
    #[serde(default)]
    pub access: Access,
    /// How long a token link works. Only for `token`.
    pub ttl_s: Option<u64>,
}

impl Publish {
    /// Returns the port and, for `token`, the token's lifetime.
    pub fn check(&self) -> Result<(u16, Option<u64>), ApiError> {
        let port = u16::try_from(self.port)
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| ApiError::invalid("port must be 1 to 65535"))?;
        match (self.access, self.ttl_s) {
            (Access::Token, ttl) => {
                let ttl = ttl.unwrap_or(DEFAULT_TOKEN_TTL_S);
                if ttl == 0 || ttl > MAX_TOKEN_TTL_S {
                    return Err(ApiError::invalid(format!(
                        "ttl_s must be 1 to {MAX_TOKEN_TTL_S}"
                    )));
                }
                Ok((port, Some(ttl)))
            }
            (_, Some(_)) => Err(ApiError::invalid("ttl_s is only for token access")),
            (_, None) => Ok((port, None)),
        }
    }
}

/// The first DNS label of a preview host: `3000-sbx-8f2k...`.
pub fn label(sandbox: &str, port: u16) -> String {
    format!("{port}-{}", ids::host_name(sandbox))
}

/// Reads the sandbox and port from a preview `Host` header.
pub fn parse_host(host: &str) -> Option<(String, u16)> {
    let label = host.split('.').next()?;
    let (port, name) = label.split_once('-')?;
    if port.starts_with('0') {
        return None;
    }
    let port: u16 = port.parse().ok().filter(|p| *p > 0)?;
    let id = name.to_ascii_lowercase().replacen('-', "_", 1);
    ids::is_valid_id("sbx", &id).then_some((id, port))
}

/// Fills `{label}` in the preview URL template.
pub fn url(template: &str, sandbox: &str, port: u16) -> String {
    template.replace("{label}", &label(sandbox, port))
}

pub fn new_token() -> std::io::Result<String> {
    Ok(format!("spt_{}", ids::base32(&ids::random::<20>()?)))
}

/// Compares hashes, so the time taken says nothing about the token.
pub fn token_matches(given: &str, expected: &str) -> bool {
    Sha256::digest(given.as_bytes()) == Sha256::digest(expected.as_bytes())
}

/// The value of `name` in a `Cookie` header.
pub fn cookie<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (key, value) = pair.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}

/// A `Cookie` header without `name`, or `None` if nothing is left.
pub fn without_cookie(header: &str, name: &str) -> Option<String> {
    let kept: Vec<&str> = header
        .split(';')
        .map(str::trim)
        .filter(|pair| !pair.is_empty() && pair.split('=').next() != Some(name))
        .collect();
    (!kept.is_empty()).then(|| kept.join("; "))
}

/// Splits `param` out of a query string. Returns its value and the rest.
pub fn take_param(query: &str, param: &str) -> (Option<String>, String) {
    let mut value = None;
    let rest: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let (key, v) = pair.split_once('=').unwrap_or((pair, ""));
            if key == param {
                value = Some(v.to_owned());
                false
            } else {
                !pair.is_empty()
            }
        })
        .collect();
    (value, rest.join("&"))
}

/// A redirect target that stays on the preview host. Browsers read `//x`
/// and `/\x` as a link to another site.
pub fn same_host_path(path: &str) -> String {
    format!("/{}", path.trim_start_matches(['/', '\\']))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "sbx_0123456789abcdef";

    #[test]
    fn redirects_stay_on_the_preview_host() {
        assert_eq!(same_host_path("/app/page"), "/app/page");
        assert_eq!(same_host_path("//evil.com/"), "/evil.com/");
        assert_eq!(same_host_path("/\\evil.com"), "/evil.com");
        assert_eq!(same_host_path(""), "/");
    }

    #[test]
    fn host_labels_round_trip() {
        assert_eq!(label(ID, 3000), "3000-sbx-0123456789abcdef");
        let host = format!("{}.preview.example.com:8443", label(ID, 3000));
        assert_eq!(parse_host(&host), Some((ID.to_owned(), 3000)));
        assert_eq!(
            parse_host("8080-SBX-0123456789ABCDEF.localhost"),
            Some((ID.to_owned(), 8080))
        );
        assert_eq!(
            url("https://{label}.p.dev", ID, 80),
            "https://80-sbx-0123456789abcdef.p.dev"
        );
    }

    #[test]
    fn bad_hosts_are_rejected() {
        for host in [
            "localhost:8081",
            "0-sbx-0123456789abcdef.x",
            "03000-sbx-0123456789abcdef.x",
            "70000-sbx-0123456789abcdef.x",
            "3000-key-0123456789abcdef.x",
            "3000-sbx-0123456789abcde.x",
            "3000-sbx-0123456789abcdei.x",
        ] {
            assert_eq!(parse_host(host), None, "{host}");
        }
    }

    #[test]
    fn publish_checks_port_and_ttl() {
        let check = |json: &str| {
            serde_json::from_str::<Publish>(json)
                .map_err(|e| e.to_string())?
                .check()
                .map_err(|e| e.message)
        };
        assert_eq!(
            check(r#"{"port":3000}"#),
            Ok((3000, Some(DEFAULT_TOKEN_TTL_S)))
        );
        assert_eq!(check(r#"{"port":80,"access":"public"}"#), Ok((80, None)));
        assert_eq!(
            check(r#"{"port":80,"access":"token","ttl_s":60}"#),
            Ok((80, Some(60)))
        );
        for json in [
            r#"{"port":0}"#,
            r#"{"port":65536}"#,
            r#"{"port":80,"access":"open"}"#,
            r#"{"port":80,"access":"private","ttl_s":60}"#,
            r#"{"port":80,"ttl_s":0}"#,
        ] {
            assert!(check(json).is_err(), "{json}");
        }
    }

    #[test]
    fn cookies_and_query_params() {
        let header = "a=1; spawnbox_preview=spt_x; b=2";
        assert_eq!(cookie(header, COOKIE), Some("spt_x"));
        assert_eq!(cookie(header, "c"), None);
        assert_eq!(without_cookie(header, COOKIE).as_deref(), Some("a=1; b=2"));
        assert_eq!(without_cookie("spawnbox_preview=x", COOKIE), None);
        assert_eq!(
            take_param("a=1&spawnbox_token=spt_y&b=2", TOKEN_PARAM),
            (Some("spt_y".to_owned()), "a=1&b=2".to_owned())
        );
        assert_eq!(take_param("a=1", TOKEN_PARAM), (None, "a=1".to_owned()));
        assert!(token_matches("spt_a", "spt_a"));
        assert!(!token_matches("spt_a", "spt_b"));
    }
}
