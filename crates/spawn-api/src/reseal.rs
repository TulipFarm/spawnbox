//! Brings env stored by earlier versions to the current format: the
//! sandbox's env and its services' env sealed together as one blob. Runs at
//! start, before any sandbox is loaded.

use std::collections::BTreeMap;

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Map, Value};

use crate::db::{Db, StartEnv};
use crate::model::Service;
use crate::secretbox::{SandboxEnv, SecretBox};

/// The key of the sealed blob in a stored saved state.
pub const SEALED: &str = "sealed";

/// Rows rewritten, and the sandboxes whose env could not be read, such as
/// ones sealed under another key.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Resealed {
    pub start_records: usize,
    pub saved: usize,
    pub unreadable: Vec<String>,
    /// Whether the SQLite file was rebuilt, which happens once.
    pub vacuumed: bool,
}

pub fn reseal(db: &Db, sbox: &SecretBox) -> Result<Resealed> {
    let mut done = Resealed::default();
    for StartEnv {
        sandbox,
        tenant,
        env,
        services,
    } in db.start_record_envs()?
    {
        if services.is_empty() && sbox.open_sandbox_env(&tenant, &sandbox, &env).is_some() {
            continue;
        }
        let Some(plain) = sbox.open_legacy(&tenant, &sandbox, &env, &services) else {
            done.unreadable.push(sandbox);
            continue;
        };
        let sealed = sbox.seal_sandbox_env(&tenant, &sandbox, &plain)?;
        if db.replace_start_env(&sandbox, (&env, &services), &sealed)? {
            done.start_records += 1;
        }
    }
    for (id, tenant, saved) in db.saved_states()? {
        match reseal_saved(sbox, &tenant, &id, &saved) {
            Some(None) => {}
            Some(Some(new)) => {
                if db.replace_saved(&id, &saved, &new)? {
                    done.saved += 1;
                }
            }
            None => done.unreadable.push(id),
        }
    }
    if done.start_records + done.saved > 0 {
        db.truncate_log()?;
    }
    // A paused persistent sandbox has both a start record and saved state.
    done.unreadable.sort();
    done.unreadable.dedup();
    done.vacuumed = db.vacuum_once()?;
    Ok(done)
}

/// `Some(None)` if `json` is current, `None` if it cannot be read.
/// Earlier versions stored env in plain, or sealed the env map and the
/// services apart, in `env_sealed` and `services_sealed`.
pub(crate) fn reseal_saved(
    sbox: &SecretBox,
    tenant: &str,
    id: &str,
    json: &str,
) -> Option<Option<String>> {
    let mut saved: Map<String, Value> = serde_json::from_str(json).ok()?;
    if let Some(sealed) = saved.get(SEALED) {
        let sealed = B64.decode(sealed.as_str()?).ok()?;
        sbox.open_sandbox_env(tenant, id, &sealed)?;
        return Some(None);
    }
    let mut legacy = |plain: &str, sealed: &str| -> Option<(Option<Vec<u8>>, Value)> {
        let sealed = match saved.remove(sealed) {
            Some(Value::String(b64)) => Some(B64.decode(b64).ok()?),
            Some(Value::Null) | None => None,
            Some(_) => return None,
        };
        Some((sealed, saved.remove(plain).unwrap_or(Value::Null)))
    };
    let (env_sealed, env) = legacy("env", "env_sealed")?;
    let (services_sealed, services) = legacy("services", "services_sealed")?;
    let mut plain = match env_sealed {
        Some(env) => sbox.open_legacy(tenant, id, &env, &services_sealed.unwrap_or_default())?,
        None => SandboxEnv {
            env: from_value::<BTreeMap<String, String>>(env)?,
            services: Vec::new(),
        },
    };
    if plain.services.is_empty() {
        plain.services = from_value::<Vec<Service>>(services)?;
    }
    let sealed = sbox.seal_sandbox_env(tenant, id, &plain).ok()?;
    saved.insert(SEALED.into(), Value::String(B64.encode(sealed)));
    serde_json::to_string(&saved).ok().map(Some)
}

fn from_value<T: Default + serde::de::DeserializeOwned>(value: Value) -> Option<T> {
    match value {
        Value::Null => Some(T::default()),
        value => serde_json::from_value(value).ok(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::{Sandbox, StartRecord};

    const CANARY: &str = "svc-secret-env";

    pub(crate) fn plain() -> SandboxEnv {
        SandboxEnv {
            env: BTreeMap::from([("TOKEN".to_owned(), "sandbox-secret-env".to_owned())]),
            services: serde_json::from_str(&format!(
                r#"[{{"name":"web","command":["srv"],"env":{{"KEY":"{CANARY}"}}}}]"#
            ))
            .unwrap(),
        }
    }

    fn row(id: &str) -> Sandbox {
        Sandbox {
            id: id.into(),
            tenant: "acme".into(),
            state: "paused".into(),
            template: "base".into(),
            build: Some("bld_1".into()),
            labels: BTreeMap::new(),
            secrets: Vec::new(),
            egress: spawn_egress::Policy::allow_all(),
            created_at: 1,
            expires_at: 2,
            idle_pause_s: 0,
            paused_at: Some(1),
            node: None,
            vcpus: 1,
            memory_mib: 256,
            volumes: Vec::new(),
            persistent: true,
            generation: 1,
            cold_starts: 0,
            last_cold_start_at: None,
        }
    }

    fn start(id: &str, env: Vec<u8>) -> StartRecord {
        StartRecord {
            sandbox: id.into(),
            tenant: "acme".into(),
            template: "base".into(),
            build: "bld_1".into(),
            spec: "{}".into(),
            vcpus: 1,
            memory_mib: 256,
            egress: spawn_egress::Policy::allow_all(),
            secrets: Vec::new(),
            volumes: Vec::new(),
            ports: "{}".into(),
            idle_pause_s: 0,
            env,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn legacy_start(db: &Db, sbox: &SecretBox, id: &str) {
        let want = plain();
        let env = sbox
            .seal(
                &format!("env:v1:acme:{id}"),
                &serde_json::to_vec(&want.env).unwrap(),
            )
            .unwrap();
        let services = sbox
            .seal(
                &format!("services:v1:acme:{id}"),
                &serde_json::to_vec(&want.services).unwrap(),
            )
            .unwrap();
        db.insert_persistent(&row(id), &start(id, env), None)
            .unwrap()
            .unwrap();
        db.set_legacy_start_services(id, &services).unwrap();
    }

    #[test]
    fn reseals_earlier_formats_once() {
        let db = Db::memory().unwrap();
        let sbox = SecretBox::new(&[7; 32]).unwrap();
        legacy_start(&db, &sbox, "sbx_start");
        let want = plain();
        // Stored in plain, before env was sealed.
        db.insert_sandbox(&row("sbx_plain")).unwrap().unwrap();
        let plain_json = serde_json::json!({
            "env": want.env, "ports": {}, "secrets": [], "vcpus": 1, "memory_mib": 256,
            "remaining_ms": 5, "services": want.services,
        })
        .to_string();
        db.set_saved("sbx_plain", 1, &plain_json).unwrap();
        // Env and services sealed apart.
        db.insert_sandbox(&row("sbx_split")).unwrap().unwrap();
        let env = sbox
            .seal(
                "env:v1:acme:sbx_split",
                &serde_json::to_vec(&want.env).unwrap(),
            )
            .unwrap();
        let services = sbox
            .seal(
                "services:v1:acme:sbx_split",
                &serde_json::to_vec(&want.services).unwrap(),
            )
            .unwrap();
        let split_json = serde_json::json!({
            "env_sealed": B64.encode(env), "ports": {}, "secrets": [], "vcpus": 1,
            "memory_mib": 256, "remaining_ms": 5, "services_sealed": B64.encode(services),
        })
        .to_string();
        db.set_saved("sbx_split", 1, &split_json).unwrap();
        // Sealed under a key this host does not have.
        db.insert_sandbox(&row("sbx_foreign")).unwrap().unwrap();
        let foreign = SecretBox::new(&[9; 32]).unwrap();
        let env = foreign
            .seal(
                "env:v1:acme:sbx_foreign",
                &serde_json::to_vec(&want.env).unwrap(),
            )
            .unwrap();
        let foreign_json = serde_json::json!({ "env_sealed": B64.encode(env) }).to_string();
        db.set_saved("sbx_foreign", 1, &foreign_json).unwrap();

        let done = reseal(&db, &sbox).unwrap();
        assert_eq!(done.start_records, 1);
        assert_eq!(done.saved, 2);
        assert_eq!(done.unreadable, vec!["sbx_foreign".to_owned()]);

        let start = db.get_start_record("sbx_start").unwrap().unwrap();
        assert_eq!(
            sbox.open_sandbox_env("acme", "sbx_start", &start.env),
            Some(want.clone())
        );
        let stored = db
            .start_record_envs()
            .unwrap()
            .into_iter()
            .find(|r| r.sandbox == "sbx_start")
            .unwrap();
        assert_eq!(stored.env, start.env);
        assert!(stored.services.is_empty());

        for (id, _, saved) in db.saved_states().unwrap() {
            assert!(!saved.contains(CANARY), "{id}: {saved}");
            assert!(!saved.contains("sandbox-secret-env"), "{id}: {saved}");
            if id == "sbx_foreign" {
                assert_eq!(saved, foreign_json);
                continue;
            }
            let saved: Map<String, Value> = serde_json::from_str(&saved).unwrap();
            for gone in ["env", "env_sealed", "services", "services_sealed"] {
                assert!(!saved.contains_key(gone), "{id}: {gone}");
            }
            assert_eq!(saved["vcpus"], 1);
            let sealed = B64.decode(saved[SEALED].as_str().unwrap()).unwrap();
            assert_eq!(
                sbox.open_sandbox_env("acme", &id, &sealed),
                Some(want.clone())
            );
        }

        let again = reseal(&db, &sbox).unwrap();
        assert_eq!((again.start_records, again.saved), (0, 0));

        // Paused, so it has saved state as well as its start record.
        let sealed = sbox.seal_sandbox_env("acme", "sbx_start", &want).unwrap();
        let paused = serde_json::json!({ SEALED: B64.encode(sealed) }).to_string();
        db.set_saved("sbx_start", 1, &paused).unwrap();
        assert!(
            db.saved_states()
                .unwrap()
                .iter()
                .any(|(id, ..)| id == "sbx_start")
        );

        // Under another key, none of it can be read, sealed rows included,
        // and each sandbox is named once.
        let other = SecretBox::new(&[3; 32]).unwrap();
        let lost = reseal(&db, &other).unwrap().unreadable;
        assert_eq!(lost, ["sbx_foreign", "sbx_plain", "sbx_split", "sbx_start"]);
    }

    #[test]
    fn leaves_rows_changed_meanwhile() {
        let db = Db::memory().unwrap();
        let sbox = SecretBox::new(&[7; 32]).unwrap();
        db.insert_sandbox(&row("sbx_a")).unwrap().unwrap();
        db.set_saved("sbx_a", 1, "{}").unwrap();
        assert!(!db.replace_saved("sbx_a", "{\"x\":1}", "{\"y\":1}").unwrap());
        assert!(db.replace_saved("sbx_a", "{}", "{\"y\":1}").unwrap());
        let sealed = sbox.seal_sandbox_env("acme", "sbx_a", &plain()).unwrap();
        legacy_start(&db, &sbox, "sbx_b");
        assert!(
            !db.replace_start_env("sbx_b", (b"old", b""), &sealed)
                .unwrap()
        );
    }

    /// A new empty directory for one test.
    pub(crate) fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("spawnbox-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A paused persistent sandbox of tenant `acme` whose start record holds
    /// `plain()` sealed in the current format.
    pub(crate) fn persistent(db: &Db, sbox: &SecretBox, id: &str) {
        let env = sbox.seal_sandbox_env("acme", id, &plain()).unwrap();
        db.insert_persistent(&row(id), &start(id, env), None)
            .unwrap()
            .unwrap();
    }

    /// Whether `canary` is in the database's files, the log included.
    pub(crate) fn on_disk(path: &std::path::Path, canary: &str) -> bool {
        ["", "-wal", "-shm"].iter().any(|suffix| {
            let mut file = path.as_os_str().to_owned();
            file.push(suffix);
            std::fs::read(file)
                .is_ok_and(|bytes| bytes.windows(canary.len()).any(|w| w == canary.as_bytes()))
        })
    }

    #[test]
    fn leaves_no_plain_copy_on_disk() {
        let dir = std::env::temp_dir().join(format!("spawnbox-reseal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("spawnbox.db");
        let db = Db::open(&path).unwrap();
        let sbox = SecretBox::new(&[7; 32]).unwrap();
        for i in 0..20 {
            let id = format!("sbx_{i}");
            db.insert_sandbox(&row(&id)).unwrap().unwrap();
            let json = serde_json::json!({
                "env": { "TOKEN": "sandbox-secret-env" }, "ports": {}, "secrets": [],
                "vcpus": 1, "memory_mib": 256, "remaining_ms": 5, "services": plain().services,
            });
            db.set_saved(&id, 1, &json.to_string()).unwrap();
        }
        assert!(on_disk(&path, CANARY));
        assert_eq!(reseal(&db, &sbox).unwrap().saved, 20);
        assert!(!on_disk(&path, CANARY));
        assert!(!on_disk(&path, "sandbox-secret-env"));
        drop(db);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn clears_env_that_earlier_versions_freed() {
        let dir = std::env::temp_dir().join(format!("spawnbox-vacuum-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("spawnbox.db");
        let db = Db::open(&path).unwrap();
        for i in 0..40 {
            db.insert_sandbox(&row(&format!("sbx_{i}")))
                .unwrap()
                .unwrap();
        }
        drop(db);
        // An earlier version: its schema, and no secure_delete.
        let old = rusqlite::Connection::open(&path).unwrap();
        old.execute_batch(
            "PRAGMA secure_delete = OFF;
             ALTER TABLE sandboxes RENAME COLUMN saved_state TO saved;
             DROP TABLE upkeep;
             ALTER TABLE nodes DROP COLUMN fenced_at;
             ALTER TABLE nodes DROP COLUMN fenced_by;
             ALTER TABLE builds DROP COLUMN guest;
             ALTER TABLE builds DROP COLUMN root;",
        )
        .unwrap();
        let version: i64 = old
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        old.pragma_update(None, "user_version", version - 3)
            .unwrap();
        let json = serde_json::json!({
            "env": { "TOKEN": "sandbox-secret-env" }, "ports": {}, "secrets": [],
            "vcpus": 1, "memory_mib": 256, "remaining_ms": 5, "services": plain().services,
        });
        old.execute("UPDATE sandboxes SET saved = ?1", [json.to_string()])
            .unwrap();
        // Resumed, and ended and removed.
        old.execute_batch(
            "UPDATE sandboxes SET saved = NULL WHERE id LIKE 'sbx_1%';
             DELETE FROM sandboxes WHERE id LIKE 'sbx_2%';
             PRAGMA wal_checkpoint(TRUNCATE);",
        )
        .unwrap();
        drop(old);
        assert!(on_disk(&path, CANARY));

        let db = Db::open(&path).unwrap();
        let sbox = SecretBox::new(&[7; 32]).unwrap();
        let done = reseal(&db, &sbox).unwrap();
        assert!(done.vacuumed);
        assert!(!on_disk(&path, CANARY));
        assert!(!on_disk(&path, "sandbox-secret-env"));
        assert!(!reseal(&db, &sbox).unwrap().vacuumed);
        drop(db);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
