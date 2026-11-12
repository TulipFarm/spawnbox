//! Encrypts secret values and the egress CA key at rest with
//! ChaCha20-Poly1305, under one key per install.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};

use crate::ids::random;
use crate::model::Service;

const KEY_LEN: usize = 32;

/// The label that seals the fleet CA's key in `fleet/ca.key`.
pub const FLEET_CA_LABEL: &str = "spawnbox fleet ca key v1";

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

    /// Seals a sandbox's env and the env of all its services as one blob,
    /// bound to the tenant and sandbox. Being one blob, no value can be
    /// moved to another variable, service or sandbox without failing the
    /// tag.
    pub fn seal_sandbox_env(
        &self,
        tenant: &str,
        sandbox: &str,
        env: &SandboxEnv,
    ) -> io::Result<Vec<u8>> {
        let plain = serde_json::to_vec(env).map_err(io::Error::other)?;
        self.seal(&sandbox_env_label(tenant, sandbox), &plain)
    }

    pub fn open_sandbox_env(
        &self,
        tenant: &str,
        sandbox: &str,
        sealed: &[u8],
    ) -> Option<SandboxEnv> {
        let plain = self.open(&sandbox_env_label(tenant, sandbox), sealed)?;
        serde_json::from_slice(&plain).ok()
    }

    /// Reads the earlier format, which sealed the env map and the services
    /// apart. An empty `services` means none.
    pub fn open_legacy(
        &self,
        tenant: &str,
        sandbox: &str,
        env: &[u8],
        services: &[u8],
    ) -> Option<SandboxEnv> {
        let env = self.open(&format!("env:v1:{tenant}:{sandbox}"), env)?;
        let services = if services.is_empty() {
            Vec::new()
        } else {
            let plain = self.open(&format!("services:v1:{tenant}:{sandbox}"), services)?;
            serde_json::from_slice(&plain).ok()?
        };
        Some(SandboxEnv {
            env: serde_json::from_slice(&env).ok()?,
            services,
        })
    }
}

/// What `SecretBox::seal_sandbox_env` protects: the sandbox's env and its
/// services, whose env may hold secrets.
#[derive(Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SandboxEnv {
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub services: Vec<Service>,
}

impl SandboxEnv {
    /// Whether it holds values the caller set, which a template made from
    /// the sandbox would expose.
    pub fn is_protected(&self) -> bool {
        !self.env.is_empty() || self.services.iter().any(|s| !s.env.is_empty())
    }
}

impl std::fmt::Debug for SandboxEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxEnv")
            .field("env", &self.env.keys().collect::<Vec<_>>())
            .field("services", &self.services)
            .finish()
    }
}

/// The format version is part of the label so that a later format cannot
/// be read as this one.
fn sandbox_env_label(tenant: &str, sandbox: &str) -> String {
    format!("env:v2:{tenant}:{sandbox}")
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

    fn sample() -> SandboxEnv {
        SandboxEnv {
            env: BTreeMap::from([("TOKEN".to_owned(), "s3cret".to_owned())]),
            services: serde_json::from_str(
                r#"[{"name":"web","command":["srv"],"env":{"KEY":"svc-secret"},"port":80}]"#,
            )
            .unwrap(),
        }
    }

    #[test]
    fn env_is_bound_to_its_tenant_and_sandbox() {
        let sb = SecretBox::new(&[7; 32]).unwrap();
        let env = sample();
        let sealed = sb.seal_sandbox_env("acme", "sbx_1", &env).unwrap();
        assert!(!sealed.windows(6).any(|w| w == b"s3cret"));
        assert!(!sealed.windows(10).any(|w| w == b"svc-secret"));
        assert_eq!(sb.open_sandbox_env("acme", "sbx_1", &sealed), Some(env));
        assert_eq!(sb.open_sandbox_env("acme", "sbx_2", &sealed), None);
        assert_eq!(sb.open_sandbox_env("other", "sbx_1", &sealed), None);
        assert_eq!(sb.open("env:v1:acme:sbx_1", &sealed), None);
        assert_eq!(sb.open("env:v3:acme:sbx_1", &sealed), None);
        let other_key = SecretBox::new(&[8; 32]).unwrap();
        assert_eq!(other_key.open_sandbox_env("acme", "sbx_1", &sealed), None);
    }

    #[test]
    fn reads_the_earlier_format() {
        let sb = SecretBox::new(&[7; 32]).unwrap();
        let want = sample();
        let env = sb
            .seal("env:v1:acme:sbx_1", &serde_json::to_vec(&want.env).unwrap())
            .unwrap();
        let services = sb
            .seal(
                "services:v1:acme:sbx_1",
                &serde_json::to_vec(&want.services).unwrap(),
            )
            .unwrap();
        assert_eq!(
            sb.open_legacy("acme", "sbx_1", &env, &services),
            Some(want.clone())
        );
        assert_eq!(sb.open_legacy("acme", "sbx_2", &env, &services), None);
        assert_eq!(
            sb.open_legacy("acme", "sbx_1", &env, b"").map(|e| e.env),
            Some(want.env)
        );
        assert_eq!(sb.open_sandbox_env("acme", "sbx_1", &env), None);
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
