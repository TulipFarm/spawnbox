//! Secrets: stored encrypted in SQLite, kept decrypted in memory for the
//! egress proxy, and never returned by the API. Also the egress CA.
//!
//! An org-wide secret is stored under its name; a tenant's own under
//! `tenant/name`. Calls take the namespace they work in: `Some(tenant)`
//! sees the tenant's own secrets and, read-only, the org-wide ones; `None`
//! works on org-wide ones.

use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result, bail};
use spawn_egress::{Ca, SecretStore};

use crate::db::{self, Db};
use crate::model::{
    ApiError, Code, SecretInput, SecretSpec, SecretView, is_secret_name, rfc3339_ms,
};
use crate::secretbox::SecretBox;
use crate::tenancy::{scoped, split};

const CA_CERT_FILE: &str = "egress-ca.crt";
const CA_KEY_FILE: &str = "egress-ca.key";
const CA_LABEL: &str = "egress-ca";

/// Sealing label. Uses the storage key, so a sealed value cannot be moved
/// to another tenant's row.
fn label(key: &str) -> String {
    format!("secret:{key}")
}

/// A secret with its value, for fleet hosts. Sent only over fleet TLS.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SecretCopy {
    pub key: String,
    pub spec: String,
    pub value: String,
    pub version: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct Secrets {
    db: Db,
    sbox: SecretBox,
    store: SecretStore,
    /// Serializes changes, so the store matches the database.
    writing: Mutex<()>,
}

impl Secrets {
    /// The key that seals secrets and other stored values.
    pub fn sbox(&self) -> &SecretBox {
        &self.sbox
    }

    /// Decrypts every saved secret into `store`.
    pub fn load(db: Db, sbox: SecretBox, store: SecretStore) -> Result<Self> {
        for row in db.list_secrets()? {
            let spec: SecretSpec = serde_json::from_str(&row.spec)?;
            let value = sbox
                .open(&label(&row.name), &row.value)
                .and_then(|v| String::from_utf8(v).ok())
                .with_context(|| {
                    format!("cannot decrypt secret {:?}: wrong secrets key?", row.name)
                })?;
            store.set(spec.to_secret(&row.name, value, row.version));
        }
        Ok(Self {
            db,
            sbox,
            store,
            writing: Mutex::new(()),
        })
    }

    fn writing(&self) -> MutexGuard<'_, ()> {
        self.writing.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn create(
        &self,
        ns: Option<&str>,
        input: SecretInput,
        now: i64,
    ) -> Result<SecretView, ApiError> {
        let (spec, value) = input.create()?;
        let key = scoped(ns, &spec.name);
        let sealed = self
            .sbox
            .seal(&label(&key), value.as_bytes())
            .map_err(ApiError::internal)?;
        let json = serde_json::to_string(&spec).map_err(ApiError::internal)?;
        let _writing = self.writing();
        if !self.db.insert_secret(&key, &json, &sealed, now)? {
            return Err(ApiError::new(
                Code::Conflict,
                format!(
                    "secret {:?} already exists; PATCH it to change it",
                    spec.name
                ),
            ));
        }
        self.store.set(spec.to_secret(&key, value, 1));
        eprintln!("secret {key:?} created (version 1)");
        view(self.row(&key)?)
    }

    /// The new secret, and the hosts it went to before.
    pub fn update(
        &self,
        ns: Option<&str>,
        name: &str,
        input: SecretInput,
        now: i64,
    ) -> Result<(SecretView, Vec<String>), ApiError> {
        let _writing = self.writing();
        let key = self.own(ns, name)?;
        let row = self.row(&key)?;
        let current: SecretSpec = serde_json::from_str(&row.spec).map_err(ApiError::internal)?;
        let (spec, value) = input.update(&current)?;
        let value = match value {
            Some(value) => value,
            None => self
                .sbox
                .open(&label(&key), &row.value)
                .and_then(|v| String::from_utf8(v).ok())
                .ok_or_else(|| ApiError::internal(format!("cannot decrypt secret {key:?}")))?,
        };
        let sealed = self
            .sbox
            .seal(&label(&key), value.as_bytes())
            .map_err(ApiError::internal)?;
        let json = serde_json::to_string(&spec).map_err(ApiError::internal)?;
        if !self
            .db
            .update_secret(&key, row.version, &json, &sealed, now)?
        {
            return Err(ApiError::new(
                Code::Conflict,
                "the secret changed; try again",
            ));
        }
        self.store.set(spec.to_secret(&key, value, row.version + 1));
        eprintln!("secret {key:?} updated (version {})", row.version + 1);
        if spec.allowed_hosts != current.allowed_hosts {
            eprintln!(
                "secret {key:?} allowed_hosts changed from {:?} to {:?}",
                current.allowed_hosts, spec.allowed_hosts
            );
        }
        Ok((view(self.row(&key)?)?, current.allowed_hosts))
    }

    pub fn get(&self, ns: Option<&str>, name: &str) -> Result<SecretView, ApiError> {
        view(self.resolve(ns, name)?)
    }

    /// With a namespace: its own secrets and the org-wide ones. Without:
    /// every secret of every tenant.
    pub fn list(&self, ns: Option<&str>) -> Result<Vec<SecretView>, ApiError> {
        self.db
            .list_secrets()?
            .into_iter()
            .filter(|row| ns.is_none() || split(&row.name).0.is_none_or(|t| Some(t) == ns))
            .map(view)
            .collect()
    }

    pub fn delete(&self, ns: Option<&str>, name: &str) -> Result<(), ApiError> {
        let _writing = self.writing();
        let key = self.own(ns, name)?;
        if !self.db.delete_secret(&key)? {
            return Err(not_found(name));
        }
        self.store.remove(&key);
        eprintln!("secret {key:?} deleted");
        Ok(())
    }

    /// The storage keys and settings of secrets a sandbox in `ns` asks for.
    /// Unknown names fail.
    pub fn specs(
        &self,
        ns: Option<&str>,
        names: &[String],
    ) -> Result<Vec<(String, SecretSpec)>, ApiError> {
        names
            .iter()
            .map(|name| {
                let row = self.resolve(ns, name).map_err(|error| match error.code {
                    Code::NotFound => ApiError::invalid(format!("secret {name:?} does not exist")),
                    _ => error,
                })?;
                let spec = serde_json::from_str(&row.spec).map_err(ApiError::internal)?;
                Ok((row.name, spec))
            })
            .collect()
    }

    /// The namespace's own secret, else the org-wide one.
    fn resolve(&self, ns: Option<&str>, name: &str) -> Result<db::Secret, ApiError> {
        if !is_secret_name(name) {
            return Err(not_found(name));
        }
        if let Some(tenant) = ns
            && let Some(row) = self.db.get_secret(&scoped(Some(tenant), name))?
        {
            return Ok(row);
        }
        self.db.get_secret(name)?.ok_or_else(|| not_found(name))
    }

    /// The key of a secret this namespace may change. Org-wide secrets are
    /// read-only to tenants.
    fn own(&self, ns: Option<&str>, name: &str) -> Result<String, ApiError> {
        let row = self.resolve(ns, name)?;
        if split(&row.name).0 != ns {
            return Err(ApiError::new(
                Code::Forbidden,
                format!("secret {name:?} is org-wide; it is read-only to tenants"),
            ));
        }
        Ok(row.name)
    }

    /// Fleet: of the storage keys in `held`, those a worker may get values
    /// for: keys in `pushed`, and the keys that `refs` (namespace and name of
    /// each secret its sandboxes and templates attach) may stand for. A
    /// tenant's name may stand for the tenant's own secret or the org-wide
    /// one, and a sandbox keeps the one it was started with even after the
    /// tenant adds or removes its own, so both are allowed.
    pub fn shareable(
        &self,
        held: &[String],
        pushed: &HashSet<String>,
        refs: &[(Option<String>, String)],
    ) -> Vec<String> {
        let mut allowed = pushed.clone();
        for (ns, name) in refs.iter().filter(|(_, name)| is_secret_name(name)) {
            allowed.insert(scoped(ns.as_deref(), name));
            allowed.insert(name.clone());
        }
        held.iter()
            .filter(|key| allowed.contains(*key))
            .cloned()
            .collect()
    }

    /// Fleet: the keys in `held` that no longer exist here.
    pub fn gone(&self, held: &[String]) -> Result<Vec<String>, ApiError> {
        let mut gone = Vec::new();
        for key in held {
            if self.db.get_secret(key)?.is_none() {
                gone.push(key.clone());
            }
        }
        Ok(gone)
    }

    /// Fleet: the current values of the secrets with these storage keys.
    /// Unknown keys are left out.
    pub fn export(&self, keys: &[String]) -> Result<Vec<SecretCopy>, ApiError> {
        let mut copies = Vec::new();
        for key in keys {
            let Some(row) = self.db.get_secret(key)? else {
                continue;
            };
            let value = self
                .sbox
                .open(&label(key), &row.value)
                .and_then(|v| String::from_utf8(v).ok())
                .ok_or_else(|| ApiError::internal(format!("cannot decrypt secret {key:?}")))?;
            copies.push(SecretCopy {
                key: row.name,
                spec: row.spec,
                value,
                version: row.version,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }
        Ok(copies)
    }

    /// Fleet workers: stores the primary's copies and removes the `gone`
    /// keys, which the primary has deleted. Other keys stay, so a sandbox
    /// never loses a secret because the primary left it out.
    pub fn import(&self, copies: &[SecretCopy], gone: &[String]) -> Result<(), ApiError> {
        let _writing = self.writing();
        for copy in copies {
            let spec: SecretSpec = serde_json::from_str(&copy.spec).map_err(ApiError::internal)?;
            let sealed = self
                .sbox
                .seal(&label(&copy.key), copy.value.as_bytes())
                .map_err(ApiError::internal)?;
            self.db.put_secret_copy(&db::Secret {
                name: copy.key.clone(),
                spec: copy.spec.clone(),
                value: sealed,
                version: copy.version,
                created_at: copy.created_at,
                updated_at: copy.updated_at,
            })?;
            self.store
                .set(spec.to_secret(&copy.key, copy.value.clone(), copy.version));
        }
        for key in gone {
            if !copies.iter().any(|c| &c.key == key) && self.db.delete_secret(key)? {
                self.store.remove(key);
            }
        }
        Ok(())
    }

    /// Storage keys of every secret here.
    pub fn keys(&self) -> Result<Vec<String>, ApiError> {
        Ok(self
            .db
            .list_secrets()?
            .into_iter()
            .map(|r| r.name)
            .collect())
    }

    fn row(&self, key: &str) -> Result<db::Secret, ApiError> {
        let (_, name) = split(key);
        self.db.get_secret(key)?.ok_or_else(|| not_found(name))
    }
}

fn not_found(name: &str) -> ApiError {
    ApiError::new(Code::NotFound, format!("secret {name:?} not found"))
}

fn view(row: db::Secret) -> Result<SecretView, ApiError> {
    Ok(SecretView {
        spec: serde_json::from_str(&row.spec).map_err(ApiError::internal)?,
        tenant: split(&row.name).0.map(str::to_owned),
        version: row.version,
        created_at: rfc3339_ms(row.created_at),
        updated_at: rfc3339_ms(row.updated_at),
    })
}

/// Loads the egress CA from `dir`, or creates it. The certificate is plain;
/// the key is encrypted with the secrets key.
pub fn egress_ca(dir: &Path, sbox: &SecretBox) -> Result<Ca> {
    let (cert, key) = egress_ca_pem(dir, sbox)?;
    Ca::load(&cert, &key)
}

/// The egress CA's certificate and key as PEM. Creates it if missing.
pub fn egress_ca_pem(dir: &Path, sbox: &SecretBox) -> Result<(String, String)> {
    let (cert_path, key_path) = (dir.join(CA_CERT_FILE), dir.join(CA_KEY_FILE));
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {}
        (false, false) => {
            let (cert, key) = spawn_egress::tls::generate_ca()?;
            let sealed = sbox.seal(CA_LABEL, key.as_bytes())?;
            write_new(&key_path, &sealed, 0o600)?;
            write_new(&cert_path, cert.as_bytes(), 0o644)?;
            eprintln!("created the egress CA {}", cert_path.display());
        }
        _ => bail!(
            "found only one of {} and {}; restore or remove both",
            cert_path.display(),
            key_path.display()
        ),
    }
    let cert = std::fs::read_to_string(&cert_path)?;
    let key = sbox
        .open(CA_LABEL, &std::fs::read(&key_path)?)
        .and_then(|k| String::from_utf8(k).ok())
        .with_context(|| format!("cannot decrypt {}: wrong secrets key?", key_path.display()))?;
    Ok((cert, key))
}

/// Makes `cert` and `key` the egress CA in `dir`, as a fleet worker does
/// with its primary's. Returns false if it already was.
pub fn install_egress_ca(dir: &Path, sbox: &SecretBox, cert: &str, key: &str) -> Result<bool> {
    Ca::load(cert, key).context("the primary's egress CA")?;
    if egress_ca_pem(dir, sbox).is_ok_and(|(c, k)| c == cert && k == key) {
        return Ok(false);
    }
    let (cert_path, key_path) = (dir.join(CA_CERT_FILE), dir.join(CA_KEY_FILE));
    let (cert_new, key_new) = (dir.join("egress-ca.crt.new"), dir.join("egress-ca.key.new"));
    let _ = std::fs::remove_file(&cert_new);
    let _ = std::fs::remove_file(&key_new);
    write_new(&key_new, &sbox.seal(CA_LABEL, key.as_bytes())?, 0o600)?;
    write_new(&cert_new, cert.as_bytes(), 0o644)?;
    // A crash between the two renames leaves a pair that does not match;
    // the next start then fetches the primary's again.
    std::fs::rename(&key_new, &key_path)?;
    std::fs::rename(&cert_new, &cert_path)?;
    Ok(true)
}

pub(crate) fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(json: &str) -> SecretInput {
        serde_json::from_str(json).unwrap()
    }

    fn memory() -> Secrets {
        let db = Db::memory().unwrap();
        Secrets::load(
            db,
            SecretBox::new(&[1; 32]).unwrap(),
            SecretStore::default(),
        )
        .unwrap()
    }

    fn create(secrets: &Secrets, ns: Option<&str>, name: &str) {
        secrets
            .create(
                ns,
                input(&format!(
                    r#"{{"name":"{name}","type":"http_header","value":"v","allowed_hosts":["a.com"]}}"#
                )),
                1,
            )
            .unwrap();
    }

    #[test]
    fn keeps_the_store_in_step_and_hides_values() {
        let db = Db::memory().unwrap();
        let store = SecretStore::default();
        let secrets =
            Secrets::load(db.clone(), SecretBox::new(&[1; 32]).unwrap(), store.clone()).unwrap();
        let view = secrets
            .create(None, input(r#"{"name":"gh","type":"http_header","value":"tok1","allowed_hosts":["github.com"]}"#), 1)
            .unwrap();
        assert!(!serde_json::to_string(&view).unwrap().contains("tok1"));
        assert!(
            !String::from_utf8_lossy(&db.get_secret("gh").unwrap().unwrap().value).contains("tok1")
        );
        assert_eq!(store.get("gh").unwrap().value, "tok1");
        let err = secrets
            .create(
                None,
                input(
                    r#"{"name":"gh","type":"http_header","value":"x","allowed_hosts":["a.com"]}"#,
                ),
                2,
            )
            .unwrap_err();
        assert_eq!(err.code, Code::Conflict);

        let (view, _) = secrets
            .update(None, "gh", input(r#"{"value":"tok2"}"#), 3)
            .unwrap();
        assert_eq!(view.version, 2);
        let live = store.get("gh").unwrap();
        assert_eq!((live.value.as_str(), live.version), ("tok2", 2));
        secrets
            .update(
                None,
                "gh",
                input(r#"{"value":"tok2","allowed_hosts":["api.github.com"]}"#),
                4,
            )
            .unwrap();
        let live = store.get("gh").unwrap();
        assert_eq!(
            (live.value.as_str(), live.hosts.as_slice()),
            ("tok2", &["api.github.com".to_owned()][..])
        );

        // A restart decrypts it again.
        let again = SecretStore::default();
        Secrets::load(db.clone(), SecretBox::new(&[1; 32]).unwrap(), again.clone()).unwrap();
        assert_eq!(again.get("gh").unwrap().value, "tok2");
        assert!(
            Secrets::load(
                db.clone(),
                SecretBox::new(&[2; 32]).unwrap(),
                SecretStore::default()
            )
            .is_err()
        );

        assert!(secrets.specs(None, &["gh".into()]).is_ok());
        assert_eq!(
            secrets.specs(None, &["nope".into()]).unwrap_err().code,
            Code::InvalidRequest
        );
        secrets.delete(None, "gh").unwrap();
        assert!(store.get("gh").is_none());
        assert_eq!(secrets.get(None, "gh").unwrap_err().code, Code::NotFound);
    }

    #[test]
    fn workers_get_only_the_secrets_they_use() {
        let secrets = memory();
        for (ns, name) in [(None, "org"), (Some("t1"), "own"), (Some("t2"), "other")] {
            create(&secrets, ns, name);
        }
        let held: Vec<String> = ["org", "t1/own", "t2/other", "t2/pushed"]
            .map(String::from)
            .into();
        let pushed = HashSet::from(["t2/pushed".to_owned()]);
        let refs = [
            (Some("t1".to_owned()), "own".to_owned()),
            (Some("t1".to_owned()), "org".to_owned()),
            (Some("t1".to_owned()), "gone".to_owned()),
        ];
        assert_eq!(
            secrets.shareable(&held, &pushed, &refs),
            ["org", "t1/own", "t2/pushed"]
        );
        assert!(secrets.shareable(&held, &HashSet::new(), &[]).is_empty());
    }

    #[test]
    fn a_worker_keeps_a_secret_a_tenant_later_shadows() {
        // A t1 sandbox started on a worker with the org-wide `gh`.
        let primary = memory();
        let worker = memory();
        create(&primary, None, "gh");
        worker
            .import(&primary.export(&["gh".to_owned()]).unwrap(), &[])
            .unwrap();
        // Then t1 adds its own `gh`, and the primary restarts, so it no
        // longer remembers what it pushed.
        create(&primary, Some("t1"), "gh");
        let held = worker.keys().unwrap();
        let refs = [(Some("t1".to_owned()), "gh".to_owned())];
        let shared = primary.shareable(&held, &HashSet::new(), &refs);
        assert_eq!(shared, ["gh"]);
        worker
            .import(
                &primary.export(&shared).unwrap(),
                &primary.gone(&held).unwrap(),
            )
            .unwrap();
        assert_eq!(worker.keys().unwrap(), ["gh"]);
        // A key the primary leaves out stays; one it deleted goes.
        worker.import(&[], &[]).unwrap();
        assert_eq!(worker.keys().unwrap(), ["gh"]);
        primary.delete(None, "gh").unwrap();
        worker.import(&[], &primary.gone(&held).unwrap()).unwrap();
        assert!(worker.keys().unwrap().is_empty());
    }

    #[test]
    fn tenants_see_their_own_and_read_org_wide_secrets() {
        let db = Db::memory().unwrap();
        let store = SecretStore::default();
        let secrets =
            Secrets::load(db.clone(), SecretBox::new(&[1; 32]).unwrap(), store.clone()).unwrap();
        let make = |ns, value: &str| {
            secrets
                .create(
                    ns,
                    input(&format!(
                        r#"{{"name":"gh","type":"http_header","value":"{value}","allowed_hosts":["github.com"]}}"#
                    )),
                    1,
                )
                .unwrap()
        };
        assert_eq!(make(None, "org").tenant, None);
        let own = make(Some("acme"), "acme");
        assert_eq!(
            (own.tenant.as_deref(), own.spec.name.as_str()),
            (Some("acme"), "gh")
        );
        assert_eq!(store.get("acme/gh").unwrap().value, "acme");

        // Own first, else org-wide.
        assert_eq!(
            secrets.specs(Some("acme"), &["gh".into()]).unwrap()[0].0,
            "acme/gh"
        );
        assert_eq!(
            secrets.specs(Some("other"), &["gh".into()]).unwrap()[0].0,
            "gh"
        );
        assert_eq!(secrets.get(Some("other"), "gh").unwrap().tenant, None);

        // Org-wide is read-only to tenants.
        let err = secrets
            .update(Some("other"), "gh", input(r#"{"value":"x"}"#), 2)
            .unwrap_err();
        assert_eq!(err.code, Code::Forbidden);
        assert_eq!(
            secrets.delete(Some("other"), "gh").unwrap_err().code,
            Code::Forbidden
        );

        assert_eq!(secrets.list(Some("acme")).unwrap().len(), 2);
        assert_eq!(secrets.list(Some("other")).unwrap().len(), 1);
        assert_eq!(secrets.list(None).unwrap().len(), 2);

        secrets.delete(Some("acme"), "gh").unwrap();
        assert!(store.get("acme/gh").is_none());
        assert_eq!(store.get("gh").unwrap().value, "org");

        // Reload decrypts tenant secrets under their own keys.
        make(Some("acme"), "again");
        let reloaded = SecretStore::default();
        Secrets::load(db, SecretBox::new(&[1; 32]).unwrap(), reloaded.clone()).unwrap();
        assert_eq!(reloaded.get("acme/gh").unwrap().value, "again");
    }

    #[test]
    fn creates_and_reloads_the_ca() {
        let dir = std::env::temp_dir().join(format!("spawnbox-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sbox = SecretBox::new(&[3; 32]).unwrap();
        let first = egress_ca(&dir, &sbox).unwrap();
        let second = egress_ca(&dir, &sbox).unwrap();
        assert_eq!(first.cert_pem(), second.cert_pem());
        assert!(egress_ca(&dir, &SecretBox::new(&[4; 32]).unwrap()).is_err());
        std::fs::remove_file(dir.join(CA_KEY_FILE)).unwrap();
        assert!(egress_ca(&dir, &sbox).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn installs_the_primarys_ca() {
        let dir = std::env::temp_dir().join(format!("spawnbox-ca-in-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sbox = SecretBox::new(&[3; 32]).unwrap();
        let own = egress_ca(&dir, &sbox).unwrap();
        let (cert, key) = spawn_egress::tls::generate_ca().unwrap();
        assert!(install_egress_ca(&dir, &sbox, &cert, &key).unwrap());
        assert!(!install_egress_ca(&dir, &sbox, &cert, &key).unwrap());
        let now = egress_ca(&dir, &sbox).unwrap();
        assert_eq!(now.cert_pem(), cert);
        assert_ne!(now.cert_pem(), own.cert_pem());
        assert!(install_egress_ca(&dir, &sbox, &cert, own.cert_pem()).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
