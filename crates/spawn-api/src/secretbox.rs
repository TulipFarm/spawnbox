//! Encrypts secret values and the egress CA key at rest with
//! ChaCha20-Poly1305, under one key per install.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};

use crate::ids::random;

const KEY_LEN: usize = 32;

pub struct SecretBox(LessSafeKey);

impl SecretBox {
    /// Reads the key file, or creates it, readable only by its owner.
    pub fn open_or_create(path: &Path) -> Result<Self> {
        let key = read_or_create_key(path, "back it up, or secrets cannot be recovered")?;
        Self::new(&key).with_context(|| format!("{} must hold {KEY_LEN} bytes", path.display()))
    }

    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_LEN {
            bail!("the key must be {KEY_LEN} bytes");
        }
        let key =
            UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| anyhow::anyhow!("bad key"))?;
        Ok(Self(LessSafeKey::new(key)))
    }

    /// Nonce, then ciphertext and tag. `label` must match on `open`, so a
    /// value cannot be moved to another name.
    pub fn seal(&self, label: &str, plain: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = random::<NONCE_LEN>()?;
        let mut out = plain.to_vec();
        self.0
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(label.as_bytes()),
                &mut out,
            )
            .map_err(|_| io::Error::other("encrypt"))?;
        let mut sealed = nonce.to_vec();
        sealed.append(&mut out);
        Ok(sealed)
    }

    pub fn open(&self, label: &str, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < NONCE_LEN {
            return None;
        }
        let (nonce, body) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut body = body.to_vec();
        let plain = self
            .0
            .open_in_place(nonce, Aad::from(label.as_bytes()), &mut body)
            .ok()?;
        Some(plain.to_vec())
    }

    /// Seals a sandbox's whole env map, bound to the tenant and sandbox.
    pub fn seal_env(
        &self,
        tenant: &str,
        sandbox: &str,
        env: &BTreeMap<String, String>,
    ) -> io::Result<Vec<u8>> {
        let plain = serde_json::to_vec(env).map_err(io::Error::other)?;
        self.seal(&env_label(tenant, sandbox), &plain)
    }

    pub fn open_env(
        &self,
        tenant: &str,
        sandbox: &str,
        sealed: &[u8],
    ) -> Option<BTreeMap<String, String>> {
        let plain = self.open(&env_label(tenant, sandbox), sealed)?;
        serde_json::from_slice(&plain).ok()
    }
}

/// The format version is part of the label so that a later format cannot
/// be read as this one.
fn env_label(tenant: &str, sandbox: &str) -> String {
    format!("env:v1:{tenant}:{sandbox}")
}

/// The bytes of a key file, created with `KEY_LEN` random bytes if it is
/// missing. It must be readable only by its owner.
pub fn read_or_create_key(path: &Path, advice: &str) -> Result<Vec<u8>> {
    let key = match std::fs::File::open(path) {
        Ok(mut file) => {
            let mode = file.metadata()?.permissions().mode();
            if mode & 0o077 != 0 {
                bail!("{} must not be readable by group or others", path.display());
            }
            let mut key = Vec::new();
            file.read_to_end(&mut key)?;
            key
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let key = random::<KEY_LEN>()?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("create {}", path.display()))?;
            file.write_all(&key)?;
            file.sync_all()?;
            eprintln!("created the key {}; {advice}", path.display());
            key.to_vec()
        }
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_binds_the_label() {
        let sb = SecretBox::new(&[7; 32]).unwrap();
        let sealed = sb.seal("secret:gh", b"tok").unwrap();
        assert_eq!(sb.open("secret:gh", &sealed).as_deref(), Some(&b"tok"[..]));
        assert_eq!(sb.open("secret:other", &sealed), None);
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(sb.open("secret:gh", &tampered), None);
        assert_ne!(sb.seal("secret:gh", b"tok").unwrap(), sealed);
        assert_eq!(
            SecretBox::new(&[7; 32])
                .unwrap()
                .open("secret:gh", &sealed)
                .as_deref(),
            Some(&b"tok"[..])
        );
        assert_eq!(
            SecretBox::new(&[8; 32]).unwrap().open("secret:gh", &sealed),
            None
        );
    }

    #[test]
    fn env_is_bound_to_its_tenant_and_sandbox() {
        let sb = SecretBox::new(&[7; 32]).unwrap();
        let env = BTreeMap::from([("TOKEN".to_owned(), "s3cret".to_owned())]);
        let sealed = sb.seal_env("acme", "sbx_1", &env).unwrap();
        assert!(!sealed.windows(6).any(|w| w == b"s3cret"));
        assert_eq!(sb.open_env("acme", "sbx_1", &sealed), Some(env));
        assert_eq!(sb.open_env("acme", "sbx_2", &sealed), None);
        assert_eq!(sb.open_env("other", "sbx_1", &sealed), None);
        assert_eq!(sb.open("env:v2:acme:sbx_1", &sealed), None);
    }

    #[test]
    fn creates_the_key_file_once() {
        let dir = std::env::temp_dir().join(format!("spawnbox-sb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secrets.key");
        let _ = std::fs::remove_file(&path);
        let sealed = SecretBox::open_or_create(&path)
            .unwrap()
            .seal("a", b"b")
            .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            SecretBox::open_or_create(&path)
                .unwrap()
                .open("a", &sealed)
                .is_some()
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SecretBox::open_or_create(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
