//! Browser session tokens: short-lived JWTs (HS256) that let a browser open
//! one sandbox's terminal, or the private preview of one of its ports,
//! without holding an API key. The `aud` claim says which.
//!
//! A token names its sandbox and the key that made it, so revoking the key
//! ends its tokens too. Every host of a fleet checks tokens with the same
//! key, which the primary sends with the fleet config.

use std::path::Path;
use std::sync::RwLock;

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::hmac;
use serde::{Deserialize, Serialize};

use crate::db::Db;
use crate::ids;
use crate::model::{ApiError, Code};
use crate::tenancy::Caller;

pub const MAX_TTL_S: u64 = 900;
/// Query parameter for the terminal WebSocket, which browsers cannot send
/// headers on.
pub const PTY_PARAM: &str = "session_token";
/// Query parameter of a private preview link, traded for the cookie.
pub const PREVIEW_PARAM: &str = "spawnbox_session";
pub const COOKIE: &str = "spawnbox_session";
/// The audience of a token for the terminal.
pub const TERMINAL: &str = "terminal";

/// The audience of a token for the private preview on `port`.
pub fn preview(port: u16) -> String {
    format!("preview:{port}")
}

/// `{"alg":"HS256","typ":"JWT"}`. Tokens with any other header are refused,
/// so the algorithm cannot be chosen by the token.
const HEADER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// The sandbox.
    pub sub: String,
    pub tenant: String,
    /// What the token opens: [`TERMINAL`] or [`preview`] of one port.
    pub aud: String,
    /// The API key that made it.
    pub kid: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

/// The signing key. Workers have none until their first fleet sync.
#[derive(Default)]
pub struct Sessions(RwLock<Option<Vec<u8>>>);

impl Sessions {
    pub fn load(path: &Path) -> Result<Self> {
        let key = crate::secretbox::read_or_create_key(
            path,
            "losing it only ends open browser sessions",
        )?;
        Ok(Self(RwLock::new(Some(key))))
    }

    pub fn set(&self, key: Vec<u8>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = Some(key);
    }

    pub fn key_hex(&self) -> Option<String> {
        self.key()
            .map(|key| key.iter().map(|b| format!("{b:02x}")).collect())
    }

    fn key(&self) -> Option<Vec<u8>> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn unavailable() -> ApiError {
        ApiError::new(
            Code::Conflict,
            "this host has no session key yet; try again shortly",
        )
    }

    pub fn issue(&self, claims: &Claims) -> Result<String, ApiError> {
        let key = self.key().ok_or_else(Self::unavailable)?;
        let body = serde_json::to_vec(claims).map_err(|e| ApiError::internal(e.to_string()))?;
        let signed = format!("{HEADER}.{}", B64.encode(body));
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), signed.as_bytes());
        Ok(format!("{signed}.{}", B64.encode(tag.as_ref())))
    }

    /// The claims of a well-signed token that has not expired at `now_ms`.
    pub fn verify(&self, token: &str, now_ms: i64) -> Option<Claims> {
        let claims = self.claims(token)?;
        (now_ms < claims.exp.saturating_mul(1000)).then_some(claims)
    }

    /// Whether this host signed `token`, expired or not.
    pub fn signed(&self, token: &str) -> bool {
        self.claims(token).is_some()
    }

    /// The claims of a well-signed token.
    fn claims(&self, token: &str) -> Option<Claims> {
        let key = self.key()?;
        let (signed, tag) = token.rsplit_once('.')?;
        let (header, body) = signed.split_once('.')?;
        if header != HEADER {
            return None;
        }
        let tag = B64.decode(tag).ok()?;
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, &key),
            signed.as_bytes(),
            &tag,
        )
        .ok()?;
        serde_json::from_slice(&B64.decode(body).ok()?).ok()
    }

    /// The caller behind a token for audience `aud` of sandbox `id` (its
    /// key, if still active) and the token's claims. `None` for a bad,
    /// expired or revoked token, or one for another sandbox or audience.
    pub fn caller(
        &self,
        db: &Db,
        token: &str,
        id: &str,
        aud: &str,
        now_ms: i64,
    ) -> Result<Option<(Caller, Claims)>, ApiError> {
        let Some(claims) = self.verify(token, now_ms) else {
            return Ok(None);
        };
        if claims.sub != id || claims.aud != aud {
            return Ok(None);
        }
        let Some(key) = db.active_key(&claims.kid)? else {
            return Ok(None);
        };
        Ok(Some((Caller::from_key(&key)?, claims)))
    }
}

/// New claims for `caller` on audience `aud` of sandbox `id`, valid `ttl_s`
/// from `now_ms`.
pub fn claims(
    caller: &Caller,
    tenant: &str,
    id: &str,
    aud: &str,
    ttl_s: u64,
    now_ms: i64,
) -> Result<Claims> {
    let iat = now_ms / 1000;
    Ok(Claims {
        sub: id.to_owned(),
        tenant: tenant.to_owned(),
        aud: aud.to_owned(),
        kid: caller.key.clone(),
        iat,
        exp: iat + i64::try_from(ttl_s)?,
        jti: ids::base32(&ids::random::<10>()?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyed(byte: u8) -> Sessions {
        let s = Sessions::default();
        s.set(vec![byte; 32]);
        s
    }

    fn sample() -> Claims {
        Claims {
            sub: "sbx_a".into(),
            tenant: "default".into(),
            aud: TERMINAL.into(),
            kid: "key_a".into(),
            iat: 100,
            exp: 200,
            jti: "j".into(),
        }
    }

    #[test]
    fn header_is_hs256_jwt() {
        let text = String::from_utf8(B64.decode(HEADER).unwrap()).unwrap();
        assert_eq!(text, r#"{"alg":"HS256","typ":"JWT"}"#);
    }

    #[test]
    fn signs_and_verifies_until_expiry() {
        let s = keyed(1);
        let token = s.issue(&sample()).unwrap();
        assert_eq!(s.verify(&token, 150_000), Some(sample()));
        assert_eq!(s.verify(&token, 200_000), None);
    }

    #[test]
    fn refuses_other_keys_tampering_and_other_algorithms() {
        let token = keyed(1).issue(&sample()).unwrap();
        assert_eq!(keyed(2).verify(&token, 150_000), None);
        assert_eq!(Sessions::default().verify(&token, 150_000), None);

        let parts: Vec<&str> = token.split('.').collect();
        let mut other = sample();
        other.sub = "sbx_b".into();
        let body = B64.encode(serde_json::to_vec(&other).unwrap());
        let forged = format!("{}.{body}.{}", parts[0], parts[2]);
        assert_eq!(keyed(1).verify(&forged, 150_000), None);

        let none = B64.encode(r#"{"alg":"none","typ":"JWT"}"#);
        assert_eq!(
            keyed(1).verify(&format!("{none}.{}.", parts[1]), 150_000),
            None
        );
    }

    #[test]
    fn a_token_opens_only_its_audience() {
        let db = Db::memory().unwrap();
        let key = crate::ids::new_key(false).unwrap();
        let stored = db.insert_key(&key, None, None, None, 1).unwrap();
        let caller = Caller::from_key(&stored).unwrap();
        let s = keyed(1);
        let made = |aud: &str| {
            let claims = claims(&caller, "default", "sbx_a", aud, 900, 1_000).unwrap();
            s.issue(&claims).unwrap()
        };
        let opens =
            |token: &str, aud: &str| s.caller(&db, token, "sbx_a", aud, 2_000).unwrap().is_some();

        let terminal = made(TERMINAL);
        assert!(opens(&terminal, TERMINAL));
        assert!(!opens(&terminal, &preview(3000)));

        let web = made(&preview(3000));
        assert!(opens(&web, &preview(3000)));
        assert!(!opens(&web, &preview(3001)));
        assert!(!opens(&web, TERMINAL));
    }
}
