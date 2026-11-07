//! Secret values and how they are added to intercepted HTTPS requests.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::policy::matches_any;

pub const VALUE_MARKER: &str = "{value}";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Sets `header` to `format`, with `{value}` replaced by the value.
    HttpHeader,
    /// Sets `Authorization: Basic base64(username:value)`.
    GitHttps,
}

/// A secret as the proxy uses it. The value never leaves the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    pub name: String,
    pub kind: Kind,
    pub value: String,
    pub hosts: Vec<String>,
    pub header: String,
    pub format: String,
    pub username: String,
    pub version: u32,
}

impl Secret {
    pub fn allows(&self, host: &str) -> bool {
        matches_any(&self.hosts, host)
    }

    fn header_name(&self) -> HeaderName {
        match self.kind {
            Kind::GitHttps => AUTHORIZATION,
            Kind::HttpHeader => {
                HeaderName::from_bytes(self.header.as_bytes()).unwrap_or(AUTHORIZATION)
            }
        }
    }

    fn header_value(&self) -> String {
        match self.kind {
            Kind::GitHttps => format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", self.username, self.value))
            ),
            Kind::HttpHeader => self.format.replace(VALUE_MARKER, &self.value),
        }
    }
}

/// A header name a secret may set.
pub fn is_header_name(name: &str) -> bool {
    HeaderName::from_bytes(name.as_bytes()).is_ok()
}

/// Characters a secret value or format may hold: visible ASCII and space,
/// so it is always a valid header value.
pub fn is_header_text(text: &str) -> bool {
    text.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// Secrets by name, shared with the API, which changes them.
#[derive(Clone, Default)]
pub struct SecretStore(Arc<RwLock<HashMap<String, Arc<Secret>>>>);

impl SecretStore {
    pub fn set(&self, secret: Secret) {
        self.write().insert(secret.name.clone(), Arc::new(secret));
    }

    pub fn remove(&self, name: &str) {
        self.write().remove(name);
    }

    pub fn get(&self, name: &str) -> Option<Arc<Secret>> {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .cloned()
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, Arc<Secret>>> {
        self.0.write().unwrap_or_else(|e| e.into_inner())
    }
}

/// A secret attached to one sandbox, with the placeholder the sandbox sees.
#[derive(Clone, Debug)]
pub struct Attached {
    pub name: String,
    pub placeholder: String,
}

/// Adds each secret to `headers`. The placeholder is replaced with the value
/// only in the secret's own header, also inside `Basic` credentials: a
/// server may echo other headers, such as `Host`, back to the sandbox. A
/// secret whose header is missing sets it. Returns the names and versions
/// used.
pub fn inject(headers: &mut HeaderMap, secrets: &[(Arc<Secret>, &str)]) -> Vec<(String, u32)> {
    let mut used = Vec::new();
    for (secret, placeholder) in secrets {
        let name = secret.header_name();
        let mut replaced = false;
        for (_, value) in headers.iter_mut().filter(|(n, _)| **n == name) {
            if let Some(new) = replace(value, placeholder, &secret.value) {
                *value = new;
                replaced = true;
            }
        }
        if !replaced
            && !headers.contains_key(&name)
            && let Ok(value) = HeaderValue::from_str(&secret.header_value())
        {
            headers.insert(name, value);
            replaced = true;
        }
        if replaced {
            used.push((secret.name.clone(), secret.version));
        }
    }
    used
}

fn replace(value: &HeaderValue, placeholder: &str, secret: &str) -> Option<HeaderValue> {
    let text = value.to_str().ok()?;
    let new = if text.contains(placeholder) {
        text.replace(placeholder, secret)
    } else {
        let (scheme, encoded) = text.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("basic") {
            return None;
        }
        let decoded = String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()?;
        if !decoded.contains(placeholder) {
            return None;
        }
        format!(
            "{scheme} {}",
            STANDARD.encode(decoded.replace(placeholder, secret))
        )
    };
    HeaderValue::from_str(&new).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PH: &str = "sbx_ph_abc";

    fn secret(kind: Kind) -> Arc<Secret> {
        Arc::new(Secret {
            name: "gh".into(),
            kind,
            value: "tok123".into(),
            hosts: vec!["github.com".into(), "*.github.com".into()],
            header: "Authorization".into(),
            format: "Bearer {value}".into(),
            username: "x-access-token".into(),
            version: 2,
        })
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(k, v)| {
                (
                    HeaderName::from_bytes(k.as_bytes()).unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn replaces_the_placeholder_only_in_its_header() {
        let mut h = headers(&[
            ("authorization", &format!("token {PH}")),
            ("host", PH),
            ("x-other", &format!("a{PH}b")),
        ]);
        let used = inject(&mut h, &[(secret(Kind::HttpHeader), PH)]);
        assert_eq!(h["authorization"], "token tok123");
        assert_eq!(h["host"], PH);
        assert_eq!(h["x-other"], format!("a{PH}b"));
        assert_eq!(used, [("gh".to_owned(), 2)]);
    }

    #[test]
    fn sets_a_missing_header() {
        let mut h = HeaderMap::new();
        inject(&mut h, &[(secret(Kind::HttpHeader), PH)]);
        assert_eq!(h["authorization"], "Bearer tok123");
        let mut h = HeaderMap::new();
        inject(&mut h, &[(secret(Kind::GitHttps), PH)]);
        assert_eq!(
            h["authorization"],
            format!("Basic {}", STANDARD.encode("x-access-token:tok123"))
        );
    }

    #[test]
    fn keeps_a_header_the_client_set_without_the_placeholder() {
        let mut h = headers(&[("authorization", "Bearer mine")]);
        let used = inject(&mut h, &[(secret(Kind::HttpHeader), PH)]);
        assert_eq!(h["authorization"], "Bearer mine");
        assert!(used.is_empty());
    }

    #[test]
    fn replaces_the_placeholder_inside_basic_credentials() {
        let basic = format!("Basic {}", STANDARD.encode(format!("me:{PH}")));
        let mut h = headers(&[("authorization", &basic)]);
        inject(&mut h, &[(secret(Kind::GitHttps), PH)]);
        assert_eq!(
            h["authorization"],
            format!("Basic {}", STANDARD.encode("me:tok123"))
        );
    }

    #[test]
    fn checks_header_text() {
        assert!(is_header_text("Bearer abc-123_=."));
        assert!(!is_header_text("a\r\nX-Evil: 1"));
        assert!(is_header_name("X-Api-Key"));
        assert!(!is_header_name("bad header"));
    }
}
