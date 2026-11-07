//! Random IDs and API keys.

use std::io::{self, Read};

use sha2::{Digest, Sha256};

/// Crockford base32, lowercase: no i, l, o or u.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
const ID_BYTES: usize = 10;
const KEY_BYTES: usize = 32;
pub const ORG_KEY_PREFIX: &str = "sbx_org_";
pub const TENANT_KEY_PREFIX: &str = "sbx_tn_";
/// Keys made before tenants existed. They work as org keys.
pub const OLD_KEY_PREFIX: &str = "sbk_";
const KEY_PREFIXES: [&str; 3] = [ORG_KEY_PREFIX, TENANT_KEY_PREFIX, OLD_KEY_PREFIX];

pub fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut buffer, mut bits) = (0u32, 0);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// A new ID such as `sbx_3n8s...`: the prefix, `_` and 16 random characters.
pub fn new_id(prefix: &str) -> io::Result<String> {
    Ok(format!("{prefix}_{}", base32(&random::<ID_BYTES>()?)))
}

/// A placeholder that stands for a secret inside one sandbox.
pub fn placeholder() -> io::Result<String> {
    Ok(format!("sbx_ph_{}", base32(&random::<20>()?)))
}

/// True if `id` could have come from `new_id(prefix)`. Checked before an ID
/// is used in a path or a database query.
pub fn is_valid_id(prefix: &str, id: &str) -> bool {
    id.strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('_'))
        .is_some_and(|rest| rest.len() == 16 && rest.bytes().all(|b| ALPHABET.contains(&b)))
}

/// The jailer, hostnames and network namespaces accept hyphens, not `_`.
pub fn host_name(id: &str) -> String {
    id.replace('_', "-")
}

pub struct NewKey {
    pub id: String,
    /// Shown once; never stored.
    pub secret: String,
    pub hash: Vec<u8>,
}

/// A new org key, or a tenant key if `tenant`.
pub fn new_key(tenant: bool) -> io::Result<NewKey> {
    let prefix = if tenant {
        TENANT_KEY_PREFIX
    } else {
        ORG_KEY_PREFIX
    };
    let secret = format!("{prefix}{}", base32(&random::<KEY_BYTES>()?));
    Ok(NewKey {
        id: new_id("key")?,
        hash: hash_key(&secret),
        secret,
    })
}

/// Keys have 256 random bits, so a plain SHA-256 is enough to store them.
pub fn hash_key(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

/// The key from an `Authorization: Bearer <key>` header value.
pub fn bearer(header: &str) -> Option<&str> {
    let (scheme, token) = header.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && KEY_PREFIXES.iter().any(|p| token.starts_with(p)))
        .then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_packs_five_bits_per_character() {
        assert_eq!(base32(&[]), "");
        assert_eq!(base32(&[0xff]), "zw");
        assert_eq!(base32(&[0; 10]), "0".repeat(16));
    }

    #[test]
    fn new_ids_are_valid_and_differ() {
        let a = new_id("sbx").unwrap();
        let b = new_id("sbx").unwrap();
        assert_ne!(a, b);
        assert!(is_valid_id("sbx", &a), "{a}");
        assert!(!is_valid_id("key", &a));
    }

    #[test]
    fn rejects_ids_that_could_escape_a_path() {
        for id in [
            "",
            "sbx_",
            "sbx-0123456789abcdef",
            "sbx_0123456789abcde",
            "sbx_0123456789abcdeu",
            "sbx_../../../etc/pas",
        ] {
            assert!(!is_valid_id("sbx", id), "{id}");
        }
        assert!(is_valid_id("sbx", "sbx_0123456789abcdef"));
    }

    #[test]
    fn host_names_have_no_underscores() {
        assert_eq!(host_name("sbx_0123456789abcdef"), "sbx-0123456789abcdef");
    }

    #[test]
    fn keys_hash_to_their_stored_value() {
        let key = new_key(false).unwrap();
        assert!(key.secret.starts_with(ORG_KEY_PREFIX));
        assert_eq!(key.secret.len(), ORG_KEY_PREFIX.len() + 52);
        assert!(new_key(true).unwrap().secret.starts_with(TENANT_KEY_PREFIX));
        assert_eq!(hash_key(&key.secret), key.hash);
        assert_ne!(hash_key("sbk_other"), key.hash);
    }

    #[test]
    fn reads_bearer_keys_only() {
        assert_eq!(bearer("Bearer sbk_abc"), Some("sbk_abc"));
        assert_eq!(bearer("bearer  sbk_abc "), Some("sbk_abc"));
        assert_eq!(bearer("Basic sbk_abc"), None);
        assert_eq!(bearer("Bearer other"), None);
        assert_eq!(bearer("sbk_abc"), None);
        assert_eq!(bearer("bearer sbx_org_abc"), Some("sbx_org_abc"));
        assert_eq!(bearer("bearer sbx_tn_abc"), Some("sbx_tn_abc"));
        assert_eq!(bearer("bearer sbx_ph_abc"), None);
    }
}
