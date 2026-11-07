//! SQLite state: tenants, API keys, sandbox records, templates and their
//! builds, secrets, events and usage.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, Row, params};
use spawn_egress::Policy;

use crate::events::{Event, Filter, NewEvent};
use crate::ids::NewKey;
use crate::metering::{Key as UsageKey, Totals};
use crate::tenancy::{Isolation, Quotas, Tenant, Usage};

/// Each entry upgrades the schema by one version. Never edit a shipped entry;
/// add a new one.
const MIGRATIONS: &[&str] = &[
    "CREATE TABLE api_keys (
        id TEXT PRIMARY KEY,
        hash BLOB NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        revoked_at INTEGER
    );
    CREATE TABLE sandboxes (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL,
        template TEXT NOT NULL,
        labels TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        ended_at INTEGER
    );
    CREATE INDEX sandboxes_state ON sandboxes (state, seq);",
    "CREATE TABLE templates (
        name TEXT PRIMARY KEY,
        spec TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE builds (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        template TEXT NOT NULL,
        spec TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        state TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        started_at INTEGER,
        finished_at INTEGER,
        error TEXT
    );
    CREATE INDEX builds_template ON builds (template, seq);
    ALTER TABLE sandboxes ADD COLUMN build TEXT;",
    "CREATE TABLE secrets (
        name TEXT PRIMARY KEY,
        spec TEXT NOT NULL,
        value BLOB NOT NULL,
        version INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    ALTER TABLE sandboxes ADD COLUMN secrets TEXT;
    ALTER TABLE sandboxes ADD COLUMN egress TEXT;",
    "ALTER TABLE sandboxes ADD COLUMN idle_pause_s INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE sandboxes ADD COLUMN paused_at INTEGER;
    ALTER TABLE sandboxes ADD COLUMN saved TEXT;",
    "CREATE TABLE tenants (
        id TEXT PRIMARY KEY,
        name TEXT,
        quotas TEXT NOT NULL,
        egress TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    INSERT INTO tenants (id, quotas, created_at, updated_at) VALUES (
        'default', '{}',
        CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER),
        CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
    );
    ALTER TABLE api_keys ADD COLUMN tenant TEXT;
    ALTER TABLE api_keys ADD COLUMN scopes TEXT;
    ALTER TABLE api_keys ADD COLUMN name TEXT;
    ALTER TABLE sandboxes ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';
    CREATE INDEX sandboxes_tenant ON sandboxes (tenant, seq);",
    "CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        tenant TEXT,
        sandbox TEXT,
        step_id TEXT,
        trace_id TEXT,
        actor TEXT,
        type TEXT NOT NULL,
        attrs TEXT NOT NULL
    );
    CREATE INDEX events_ts ON events (ts);
    CREATE INDEX events_tenant ON events (tenant, id);
    CREATE INDEX events_sandbox ON events (sandbox, id);
    CREATE INDEX events_step ON events (step_id, id);",
    "CREATE TABLE usage_hourly (
        tenant TEXT NOT NULL,
        hour INTEGER NOT NULL,
        sandbox TEXT NOT NULL,
        vcpu_s REAL NOT NULL DEFAULT 0,
        mem_gib_s REAL NOT NULL DEFAULT 0,
        disk_gib_h REAL NOT NULL DEFAULT 0,
        egress_bytes INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (tenant, hour, sandbox)
    ) WITHOUT ROWID;
    CREATE INDEX usage_hour ON usage_hourly (hour);",
    "ALTER TABLE builds ADD COLUMN store_key TEXT;
    ALTER TABLE builds ADD COLUMN uploaded_at INTEGER;",
    "CREATE TABLE nodes (
        id TEXT PRIMARY KEY,
        url TEXT NOT NULL,
        state TEXT NOT NULL,
        boot TEXT,
        seq INTEGER NOT NULL DEFAULT 0,
        report TEXT,
        last_seen INTEGER,
        created_at INTEGER NOT NULL,
        removed_at INTEGER
    );
    CREATE TABLE join_tokens (
        hash BLOB PRIMARY KEY,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        node TEXT
    );
    ALTER TABLE sandboxes ADD COLUMN node TEXT;
    ALTER TABLE sandboxes ADD COLUMN vcpus INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE sandboxes ADD COLUMN memory_mib INTEGER NOT NULL DEFAULT 0;
    CREATE INDEX sandboxes_node ON sandboxes (node, state);
    ALTER TABLE events ADD COLUMN source_node TEXT;
    ALTER TABLE events ADD COLUMN source_id INTEGER;
    CREATE UNIQUE INDEX events_source ON events (source_node, source_id)
        WHERE source_node IS NOT NULL;
    CREATE TABLE node_usage (
        node TEXT NOT NULL,
        tenant TEXT NOT NULL,
        hour INTEGER NOT NULL,
        sandbox TEXT NOT NULL,
        vcpu_s REAL NOT NULL DEFAULT 0,
        mem_gib_s REAL NOT NULL DEFAULT 0,
        disk_gib_h REAL NOT NULL DEFAULT 0,
        egress_bytes INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (node, tenant, hour, sandbox)
    ) WITHOUT ROWID;",
    "ALTER TABLE nodes ADD COLUMN draining INTEGER NOT NULL DEFAULT 0;",
    "ALTER TABLE tenants ADD COLUMN isolation TEXT NOT NULL DEFAULT 'any';",
    "CREATE TABLE volumes (
        id TEXT PRIMARY KEY,
        tenant TEXT NOT NULL,
        name TEXT NOT NULL,
        size_gib INTEGER NOT NULL,
        node TEXT,
        backend TEXT,
        created_at INTEGER NOT NULL,
        deleted_at INTEGER
    );
    CREATE UNIQUE INDEX volumes_name ON volumes (tenant, name) WHERE deleted_at IS NULL;
    ALTER TABLE sandboxes ADD COLUMN volumes TEXT;",
    "ALTER TABLE nodes ADD COLUMN kind TEXT NOT NULL DEFAULT 'worker';",
];

pub mod state {
    pub const STARTING: &str = "starting";
    pub const RUNNING: &str = "running";
    pub const PAUSED: &str = "paused";
    pub const FAILED: &str = "failed";
    pub const DELETED: &str = "deleted";
    pub const ALL: [&str; 5] = [STARTING, RUNNING, PAUSED, FAILED, DELETED];
}

pub mod build_state {
    pub const QUEUED: &str = "queued";
    pub const BUILDING: &str = "building";
    pub const READY: &str = "ready";
    pub const FAILED: &str = "failed";
    /// Made with another kernel, base disk or Firecracker. Its files are gone.
    pub const OUTDATED: &str = "outdated";
    /// Replaced by a newer build or its template was deleted. Its files are
    /// gone or about to be.
    pub const REMOVED: &str = "removed";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub name: String,
    /// JSON of `model::TemplateSpec`.
    pub spec: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Build {
    /// Higher is newer.
    pub seq: i64,
    pub id: String,
    pub template: String,
    /// The template's spec when the build was queued.
    pub spec: String,
    pub fingerprint: String,
    pub state: String,
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub error: Option<String>,
    /// Content address in the build store: same inputs, spec and egress
    /// policy give the same key. Set when the build starts.
    pub store_key: Option<String>,
    /// When its files were last confirmed in the build store.
    pub uploaded_at: Option<i64>,
}

/// An API key without its hash.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Key {
    pub id: String,
    /// `None` for org keys.
    pub tenant: Option<String>,
    /// JSON list of `tenancy::Scope`. `None` means all its kind allows.
    pub scopes: Option<String>,
    pub name: Option<String>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

/// Why a tenant cannot be deleted.
#[derive(Debug, PartialEq, Eq)]
pub enum InUse {
    Sandboxes(i64),
    Templates(i64),
    Secrets(i64),
    Volumes(i64),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Volume {
    pub id: String,
    pub tenant: String,
    pub name: String,
    pub size_gib: u32,
    /// The host with its file. `None`: this host, or no host yet when
    /// `backend` is `None`.
    pub node: Option<String>,
    /// The backend that first used it: `firecracker` or `gvisor`. `None`
    /// until a sandbox first mounts it, when its file is created.
    pub backend: Option<String>,
    pub created_at: i64,
}

/// A volume mounted in a sandbox. Its slot is its place in the list.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VolumeRef {
    /// The volume's ID.
    pub volume: String,
    pub name: String,
    pub path: String,
    pub read_only: bool,
    pub size_gib: u32,
}

/// A sandbox that has a volume mounted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeUser {
    pub sandbox: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Sandbox {
    pub id: String,
    pub tenant: String,
    pub state: String,
    pub template: String,
    pub build: Option<String>,
    pub labels: BTreeMap<String, String>,
    /// Names of the attached secrets.
    pub secrets: Vec<String>,
    pub egress: Policy,
    pub created_at: i64,
    /// Out of date while paused.
    pub expires_at: i64,
    /// 0 means never.
    pub idle_pause_s: u64,
    pub paused_at: Option<i64>,
    /// The worker it runs on. `None`: this host.
    pub node: Option<String>,
    pub vcpus: u32,
    pub memory_mib: u32,
    /// Absent in reports from older workers.
    #[serde(default)]
    pub volumes: Vec<VolumeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    pub name: String,
    /// JSON of `model::SecretSpec`.
    pub spec: String,
    /// Encrypted.
    pub value: Vec<u8>,
    pub version: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

/// One connection behind a lock. Queries are small and local, so they run
/// directly on the async threads.
#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        Self::init(Connection::open(path)?)
    }

    #[cfg(test)]
    pub fn memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> rusqlite::Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", true)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let tx = conn.transaction()?;
        for (i, sql) in MIGRATIONS
            .iter()
            .enumerate()
            .skip(usize::try_from(version).unwrap_or(0))
        {
            tx.execute_batch(sql)?;
            tx.pragma_update(
                None,
                "user_version",
                i64::try_from(i + 1).unwrap_or(i64::MAX),
            )?;
        }
        tx.commit()?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock cannot leave SQLite half-written.
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn insert_key(
        &self,
        key: &NewKey,
        tenant: Option<&str>,
        scopes: Option<&str>,
        name: Option<&str>,
        now: i64,
    ) -> rusqlite::Result<Key> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO api_keys (id, hash, created_at, tenant, scopes, name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![key.id, key.hash, now, tenant, scopes, name],
        )?;
        conn.query_row(
            &format!("SELECT {KEY_COLUMNS} FROM api_keys WHERE id = ?1"),
            [&key.id],
            key_from_row,
        )
    }

    /// The active key with this hash.
    pub fn find_key(&self, hash: &[u8]) -> rusqlite::Result<Option<Key>> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT {KEY_COLUMNS} FROM api_keys WHERE hash = ?1 AND revoked_at IS NULL"
                ),
                [hash],
                key_from_row,
            )
            .optional()
    }

    /// The key with this ID, if it is not revoked.
    pub fn active_key(&self, id: &str) -> rusqlite::Result<Option<Key>> {
        self.conn()
            .query_row(
                &format!("SELECT {KEY_COLUMNS} FROM api_keys WHERE id = ?1 AND revoked_at IS NULL"),
                [id],
                key_from_row,
            )
            .optional()
    }

    /// Every key, revoked ones too, oldest first.
    pub fn list_keys(&self) -> rusqlite::Result<Vec<Key>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {KEY_COLUMNS} FROM api_keys ORDER BY created_at, id"
        ))?;
        stmt.query_map([], key_from_row)?.collect()
    }

    /// Returns false if no such key exists. Revoking twice keeps the first
    /// time.
    pub fn revoke_key(&self, id: &str, now: i64) -> rusqlite::Result<bool> {
        let conn = self.conn();
        let exists = conn
            .query_row("SELECT 1 FROM api_keys WHERE id = ?1", [id], |_| Ok(()))
            .optional()?
            .is_some();
        conn.execute(
            "UPDATE api_keys SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            params![id, now],
        )?;
        Ok(exists)
    }

    /// Returns false if the ID is taken.
    pub fn insert_tenant(&self, tenant: &Tenant) -> rusqlite::Result<bool> {
        let added = self.conn().execute(
            "INSERT INTO tenants (id, name, quotas, egress, created_at, updated_at, isolation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT (id) DO NOTHING",
            params![
                tenant.id,
                tenant.name,
                to_json(&tenant.quotas),
                tenant.egress.as_ref().map(to_json),
                tenant.created_at,
                tenant.updated_at,
                tenant.isolation.as_str(),
            ],
        )?;
        Ok(added > 0)
    }

    pub fn update_tenant(&self, tenant: &Tenant) -> rusqlite::Result<bool> {
        let changed = self.conn().execute(
            "UPDATE tenants SET name = ?2, quotas = ?3, egress = ?4, updated_at = ?5,
                isolation = ?6
             WHERE id = ?1",
            params![
                tenant.id,
                tenant.name,
                to_json(&tenant.quotas),
                tenant.egress.as_ref().map(to_json),
                tenant.updated_at,
                tenant.isolation.as_str(),
            ],
        )?;
        Ok(changed > 0)
    }

    pub fn get_tenant(&self, id: &str) -> rusqlite::Result<Option<Tenant>> {
        self.conn()
            .query_row(
                &format!("SELECT {TENANT_COLUMNS} FROM tenants WHERE id = ?1"),
                [id],
                tenant_from_row,
            )
            .optional()
    }

    pub fn list_tenants(&self) -> rusqlite::Result<Vec<Tenant>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare(&format!("SELECT {TENANT_COLUMNS} FROM tenants ORDER BY id"))?;
        stmt.query_map([], tenant_from_row)?.collect()
    }

    /// Deletes a tenant that owns nothing and revokes its keys. `Ok(None)`
    /// if it does not exist.
    pub fn delete_tenant(&self, id: &str, now: i64) -> rusqlite::Result<Option<Result<(), InUse>>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let count = |sql: &str| tx.query_row(sql, [id], |row| row.get::<_, i64>(0));
        let sandboxes = count(
            "SELECT count(*) FROM sandboxes WHERE tenant = ?1 AND state NOT IN ('deleted', 'failed')",
        )?;
        let owned = "substr(name, 1, length(?1) + 1) = ?1 || '/'";
        let templates = count(&format!("SELECT count(*) FROM templates WHERE {owned}"))?;
        let secrets = count(&format!("SELECT count(*) FROM secrets WHERE {owned}"))?;
        let volumes =
            count("SELECT count(*) FROM volumes WHERE tenant = ?1 AND deleted_at IS NULL")?;
        let in_use = if sandboxes > 0 {
            Some(InUse::Sandboxes(sandboxes))
        } else if templates > 0 {
            Some(InUse::Templates(templates))
        } else if secrets > 0 {
            Some(InUse::Secrets(secrets))
        } else if volumes > 0 {
            Some(InUse::Volumes(volumes))
        } else {
            None
        };
        if let Some(in_use) = in_use {
            let exists = count("SELECT count(*) FROM tenants WHERE id = ?1")? > 0;
            return Ok(exists.then_some(Err(in_use)));
        }
        if tx.execute("DELETE FROM tenants WHERE id = ?1", [id])? == 0 {
            return Ok(None);
        }
        tx.execute(
            "UPDATE api_keys SET revoked_at = ?2 WHERE tenant = ?1 AND revoked_at IS NULL",
            params![id, now],
        )?;
        tx.commit()?;
        Ok(Some(Ok(())))
    }

    /// Adds a sandbox, unless one of its volumes is taken: mounted
    /// read-write by another sandbox, or read-only by another when this one
    /// writes. Then returns the volume's name.
    pub fn insert_sandbox(&self, sandbox: &Sandbox) -> rusqlite::Result<Result<(), String>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        for volume in &sandbox.volumes {
            if let Some(name) = volume_taken(&tx, volume, &sandbox.id)? {
                return Ok(Err(name));
            }
        }
        tx.execute(
            "INSERT INTO sandboxes
             (id, state, template, build, labels, created_at, expires_at, secrets, egress,
              idle_pause_s, tenant, node, vcpus, memory_mib, volumes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                sandbox.id,
                sandbox.state,
                sandbox.template,
                sandbox.build,
                to_json(&sandbox.labels),
                sandbox.created_at,
                sandbox.expires_at,
                to_json(&sandbox.secrets),
                to_json(&sandbox.egress),
                i64::try_from(sandbox.idle_pause_s).unwrap_or(i64::MAX),
                sandbox.tenant,
                sandbox.node,
                sandbox.vcpus,
                sandbox.memory_mib,
                volumes_json(&sandbox.volumes),
            ],
        )?;
        tx.commit()?;
        Ok(Ok(()))
    }

    /// Adds a volume. `false` if the tenant has one by that name.
    pub fn insert_volume(&self, volume: &Volume) -> rusqlite::Result<bool> {
        let added = self.conn().execute(
            "INSERT INTO volumes (id, tenant, name, size_gib, node, backend, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT DO NOTHING",
            params![
                volume.id,
                volume.tenant,
                volume.name,
                volume.size_gib,
                volume.node,
                volume.backend,
                volume.created_at,
            ],
        )?;
        Ok(added == 1)
    }

    /// Writes a volume as the primary has it, on a worker. A deleted one is
    /// not brought back.
    pub fn put_volume(&self, volume: &Volume) -> rusqlite::Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        // A volume deleted and made again under the same name.
        tx.execute(
            "UPDATE volumes SET deleted_at = ?4
             WHERE tenant = ?1 AND name = ?2 AND id != ?3 AND deleted_at IS NULL",
            params![volume.tenant, volume.name, volume.id, now_ms()],
        )?;
        tx.execute(
            "INSERT INTO volumes (id, tenant, name, size_gib, node, backend, created_at)
             VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6)
             ON CONFLICT (id) DO UPDATE SET backend = excluded.backend
             WHERE volumes.deleted_at IS NULL",
            params![
                volume.id,
                volume.tenant,
                volume.name,
                volume.size_gib,
                volume.backend,
                volume.created_at,
            ],
        )?;
        tx.commit()
    }

    pub fn get_volume(&self, tenant: &str, name: &str) -> rusqlite::Result<Option<Volume>> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT {VOLUME_COLUMNS} FROM volumes
                     WHERE tenant = ?1 AND name = ?2 AND deleted_at IS NULL"
                ),
                [tenant, name],
                volume_from_row,
            )
            .optional()
    }

    pub fn get_volume_by_id(&self, id: &str) -> rusqlite::Result<Option<Volume>> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT {VOLUME_COLUMNS} FROM volumes WHERE id = ?1 AND deleted_at IS NULL"
                ),
                [id],
                volume_from_row,
            )
            .optional()
    }

    /// One tenant's volumes, or every tenant's, by name.
    pub fn list_volumes(&self, tenant: Option<&str>) -> rusqlite::Result<Vec<Volume>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {VOLUME_COLUMNS} FROM volumes
             WHERE deleted_at IS NULL AND (?1 IS NULL OR tenant = ?1)
             ORDER BY tenant, name"
        ))?;
        stmt.query_map([tenant], volume_from_row)?.collect()
    }

    /// Records where a volume's file is. `node` `None`: this host.
    pub fn set_volume_home(
        &self,
        id: &str,
        node: Option<&str>,
        backend: &str,
    ) -> rusqlite::Result<()> {
        self.conn().execute(
            "UPDATE volumes SET node = ?2, backend = ?3 WHERE id = ?1 AND deleted_at IS NULL",
            params![id, node, backend],
        )?;
        Ok(())
    }

    /// Marks a volume deleted unless a sandbox that has not ended uses it.
    /// `Ok(Err(users))` if one does.
    pub fn delete_volume(
        &self,
        id: &str,
        now: i64,
    ) -> rusqlite::Result<Result<(), Vec<VolumeUser>>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let users = volume_users(&tx, id, "")?;
        if !users.is_empty() {
            return Ok(Err(users));
        }
        tx.execute(
            "UPDATE volumes SET deleted_at = ?2 WHERE id = ?1 AND deleted_at IS NULL",
            params![id, now],
        )?;
        tx.commit()?;
        Ok(Ok(()))
    }

    pub fn volume_users(&self, id: &str) -> rusqlite::Result<Vec<VolumeUser>> {
        volume_users(&self.conn(), id, "")
    }

    /// GiB of `tenant`'s volumes.
    pub fn volume_gib(&self, tenant: &str) -> rusqlite::Result<u64> {
        self.conn().query_row(
            "SELECT COALESCE(SUM(size_gib), 0) FROM volumes
             WHERE tenant = ?1 AND deleted_at IS NULL",
            [tenant],
            |row| row.get::<_, i64>(0).map(|n| n.unsigned_abs()),
        )
    }

    /// Volumes, deleted or not, that existed after `since`: for metering.
    pub fn volumes_since(&self, since: i64) -> rusqlite::Result<Vec<(Volume, Option<i64>)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {VOLUME_COLUMNS}, deleted_at FROM volumes
             WHERE deleted_at IS NULL OR deleted_at > ?1"
        ))?;
        stmt.query_map([since], |row| Ok((volume_from_row(row)?, row.get(7)?)))?
            .collect()
    }

    /// Records a pause, with what resuming needs.
    pub fn set_paused(&self, id: &str, paused_at: i64, saved: &str) -> rusqlite::Result<()> {
        self.conn().execute(
            "UPDATE sandboxes SET state = 'paused', paused_at = ?2, saved = ?3
             WHERE id = ?1 AND node IS NULL",
            params![id, paused_at, saved],
        )?;
        Ok(())
    }

    /// Updates what a paused sandbox needs to resume.
    pub fn set_saved(&self, id: &str, saved: &str) -> rusqlite::Result<()> {
        self.conn().execute(
            "UPDATE sandboxes SET saved = ?2 WHERE id = ?1 AND node IS NULL",
            params![id, saved],
        )?;
        Ok(())
    }

    pub fn set_resumed(&self, id: &str, expires_at: i64) -> rusqlite::Result<()> {
        self.conn().execute(
            "UPDATE sandboxes
             SET state = 'running', expires_at = ?2, paused_at = NULL, saved = NULL
             WHERE id = ?1 AND node IS NULL",
            params![id, expires_at],
        )?;
        Ok(())
    }

    /// Paused sandboxes with what resuming needs.
    pub fn paused_sandboxes(&self) -> rusqlite::Result<Vec<(Sandbox, Option<String>)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {SANDBOX_COLUMNS}, saved FROM sandboxes
             WHERE state = 'paused' AND node IS NULL ORDER BY seq"
        ))?;
        stmt.query_map([], |row| {
            Ok((sandbox_from_row(row)?, row.get(SANDBOX_COLUMN_COUNT)?))
        })?
        .collect()
    }

    /// Moves a sandbox of this host to `state`. `failed` and `deleted`
    /// record the time.
    pub fn set_state(&self, id: &str, state: &str, now: i64) -> rusqlite::Result<()> {
        let ended = matches!(state, state::FAILED | state::DELETED).then_some(now);
        self.conn().execute(
            "UPDATE sandboxes SET state = ?2, ended_at = COALESCE(?3, ended_at)
             WHERE id = ?1 AND node IS NULL",
            params![id, state, ended],
        )?;
        Ok(())
    }

    pub fn get_sandbox(&self, id: &str) -> rusqlite::Result<Option<Sandbox>> {
        self.conn()
            .query_row(
                &format!("SELECT {SANDBOX_COLUMNS} FROM sandboxes WHERE id = ?1"),
                [id],
                sandbox_from_row,
            )
            .optional()
    }

    /// One page, oldest first, of one tenant's or every tenant's
    /// sandboxes. Without `state`, deleted sandboxes are left out. Returns
    /// the cursor for the next page.
    pub fn list_sandboxes(
        &self,
        tenant: Option<&str>,
        state: Option<&str>,
        limit: u32,
        after: i64,
    ) -> rusqlite::Result<(Vec<Sandbox>, Option<i64>)> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {SANDBOX_COLUMNS}, seq
             FROM sandboxes
             WHERE seq > ?1 AND (?2 IS NULL AND state != 'deleted' OR state = ?2)
               AND (?4 IS NULL OR tenant = ?4)
             ORDER BY seq LIMIT ?3"
        ))?;
        let mut rows = stmt.query(params![after, state, i64::from(limit) + 1, tenant])?;
        let mut page = Vec::new();
        let mut last_seq = None;
        while let Some(row) = rows.next()? {
            if page.len() == limit as usize {
                return Ok((page, last_seq));
            }
            page.push(sandbox_from_row(row)?);
            last_seq = Some(row.get(SANDBOX_COLUMN_COUNT)?);
        }
        Ok((page, None))
    }

    /// Marks deleted the sandboxes whose VMs were lost when the server
    /// stopped. Returns their IDs and tenants.
    pub fn delete_unfinished(&self, now: i64) -> rusqlite::Result<Vec<(String, String)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "UPDATE sandboxes SET state = 'deleted', ended_at = ?1
             WHERE state IN ('starting', 'running') AND node IS NULL RETURNING id, tenant",
        )?;
        stmt.query_map([now], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect()
    }

    /// Creates or replaces a template. Returns whether it is new.
    pub fn put_template(&self, name: &str, spec: &str, now: i64) -> rusqlite::Result<bool> {
        let conn = self.conn();
        let updated = conn.execute(
            "UPDATE templates SET spec = ?2, updated_at = ?3 WHERE name = ?1",
            params![name, spec, now],
        )?;
        if updated == 0 {
            conn.execute(
                "INSERT INTO templates (name, spec, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3)",
                params![name, spec, now],
            )?;
        }
        Ok(updated == 0)
    }

    pub fn get_template(&self, name: &str) -> rusqlite::Result<Option<Template>> {
        self.conn()
            .query_row(
                "SELECT name, spec, created_at, updated_at FROM templates WHERE name = ?1",
                [name],
                template_from_row,
            )
            .optional()
    }

    pub fn list_templates(&self) -> rusqlite::Result<Vec<Template>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT name, spec, created_at, updated_at FROM templates ORDER BY name")?;
        stmt.query_map([], template_from_row)?.collect()
    }

    /// How many sandboxes each (tenant, template name) created since `since`.
    pub fn template_uses(&self, since: i64) -> rusqlite::Result<Vec<(String, String, u64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT tenant, template, COUNT(*) FROM sandboxes
             WHERE created_at >= ?1 GROUP BY tenant, template",
        )?;
        stmt.query_map([since], |row| {
            let count: i64 = row.get(2)?;
            Ok((row.get(0)?, row.get(1)?, count.unsigned_abs()))
        })?
        .collect()
    }

    /// Deletes a template and marks its unfinished and ready builds removed.
    /// Returns whether it existed.
    pub fn delete_template(&self, name: &str, now: i64) -> rusqlite::Result<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let deleted = tx.execute("DELETE FROM templates WHERE name = ?1", [name])?;
        tx.execute(
            "UPDATE builds SET state = 'removed', finished_at = COALESCE(finished_at, ?2)
             WHERE template = ?1 AND state IN ('queued', 'ready')",
            params![name, now],
        )?;
        tx.commit()?;
        Ok(deleted > 0)
    }

    /// Adds a queued build and returns it.
    pub fn insert_build(
        &self,
        id: &str,
        template: &str,
        spec: &str,
        fingerprint: &str,
        now: i64,
    ) -> rusqlite::Result<Build> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO builds (id, template, spec, fingerprint, state, created_at)
             VALUES (?1, ?2, ?3, ?4, 'queued', ?5)",
            params![id, template, spec, fingerprint, now],
        )?;
        conn.query_row(
            &format!("SELECT {BUILD_COLUMNS} FROM builds WHERE id = ?1"),
            [id],
            build_from_row,
        )
    }

    pub fn get_build(&self, id: &str) -> rusqlite::Result<Option<Build>> {
        self.conn()
            .query_row(
                &format!("SELECT {BUILD_COLUMNS} FROM builds WHERE id = ?1"),
                [id],
                build_from_row,
            )
            .optional()
    }

    pub fn latest_build(&self, template: &str) -> rusqlite::Result<Option<Build>> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT {BUILD_COLUMNS} FROM builds WHERE template = ?1
                     ORDER BY seq DESC LIMIT 1"
                ),
                [template],
                build_from_row,
            )
            .optional()
    }

    /// Builds in any of `states`, oldest first.
    pub fn builds_in(&self, states: &[&str]) -> rusqlite::Result<Vec<Build>> {
        let states = serde_json::to_string(states).unwrap_or_else(|_| "[]".into());
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {BUILD_COLUMNS} FROM builds
             WHERE state IN (SELECT value FROM json_each(?1)) ORDER BY seq"
        ))?;
        stmt.query_map([states], build_from_row)?.collect()
    }

    /// Moves a build to `state`. `building` records the start, and every
    /// later state the end.
    pub fn set_build_state(
        &self,
        id: &str,
        state: &str,
        now: i64,
        error: Option<&str>,
    ) -> rusqlite::Result<()> {
        let (started, finished) = match state {
            build_state::QUEUED => (None, None),
            build_state::BUILDING => (Some(now), None),
            _ => (None, Some(now)),
        };
        self.conn().execute(
            "UPDATE builds SET state = ?2,
                 started_at = COALESCE(?3, started_at),
                 finished_at = COALESCE(?4, finished_at),
                 error = COALESCE(?5, error)
             WHERE id = ?1",
            params![id, state, started, finished, error],
        )?;
        Ok(())
    }

    /// Builds that were running when the server stopped start over.
    /// Moves a queued build to `building`. False if it is not queued any
    /// more, for example because its template was deleted.
    pub fn start_build(
        &self,
        id: &str,
        fingerprint: &str,
        store_key: &str,
        now: i64,
    ) -> rusqlite::Result<bool> {
        let changed = self.conn().execute(
            "UPDATE builds SET state = 'building', started_at = ?3, fingerprint = ?2,
                 store_key = ?4
             WHERE id = ?1 AND state = 'queued'",
            params![id, fingerprint, now, store_key],
        )?;
        Ok(changed == 1)
    }

    pub fn set_build_uploaded(&self, id: &str, now: i64) -> rusqlite::Result<()> {
        self.conn().execute(
            "UPDATE builds SET uploaded_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        Ok(())
    }

    /// Marks a build failed unless it already finished.
    pub fn fail_build(&self, id: &str, now: i64, error: &str) -> rusqlite::Result<()> {
        self.conn().execute(
            "UPDATE builds SET state = 'failed', finished_at = ?2, error = ?3
             WHERE id = ?1 AND state IN ('queued', 'building')",
            params![id, now, error],
        )?;
        Ok(())
    }

    pub fn requeue_unfinished_builds(&self) -> rusqlite::Result<usize> {
        self.conn().execute(
            "UPDATE builds SET state = 'queued', started_at = NULL WHERE state = 'building'",
            [],
        )
    }
}

impl Db {
    /// Adds a secret at version 1. Returns false if the name is taken.
    pub fn insert_secret(
        &self,
        name: &str,
        spec: &str,
        value: &[u8],
        now: i64,
    ) -> rusqlite::Result<bool> {
        let added = self.conn().execute(
            "INSERT INTO secrets (name, spec, value, version, created_at, updated_at)
             VALUES (?1, ?2, ?3, 1, ?4, ?4) ON CONFLICT (name) DO NOTHING",
            params![name, spec, value, now],
        )?;
        Ok(added > 0)
    }

    /// Replaces a secret's spec and value if it is still at `version`, and
    /// bumps the version. Returns whether it changed.
    pub fn update_secret(
        &self,
        name: &str,
        version: i64,
        spec: &str,
        value: &[u8],
        now: i64,
    ) -> rusqlite::Result<bool> {
        let changed = self.conn().execute(
            "UPDATE secrets SET spec = ?3, value = ?4, version = version + 1, updated_at = ?5
             WHERE name = ?1 AND version = ?2",
            params![name, version, spec, value, now],
        )?;
        Ok(changed > 0)
    }

    pub fn get_secret(&self, name: &str) -> rusqlite::Result<Option<Secret>> {
        self.conn()
            .query_row(
                &format!("SELECT {SECRET_COLUMNS} FROM secrets WHERE name = ?1"),
                [name],
                secret_from_row,
            )
            .optional()
    }

    pub fn list_secrets(&self) -> rusqlite::Result<Vec<Secret>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {SECRET_COLUMNS} FROM secrets ORDER BY name"
        ))?;
        stmt.query_map([], secret_from_row)?.collect()
    }

    /// Writes a secret exactly as the primary has it.
    pub fn put_secret_copy(&self, secret: &Secret) -> rusqlite::Result<()> {
        self.conn().execute(
            "INSERT INTO secrets (name, spec, value, version, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (name) DO UPDATE SET spec = excluded.spec, value = excluded.value,
                 version = excluded.version, updated_at = excluded.updated_at",
            params![
                secret.name,
                secret.spec,
                secret.value,
                secret.version,
                secret.created_at,
                secret.updated_at,
            ],
        )?;
        Ok(())
    }

    /// Returns whether it existed.
    pub fn delete_secret(&self, name: &str) -> rusqlite::Result<bool> {
        Ok(self
            .conn()
            .execute("DELETE FROM secrets WHERE name = ?1", [name])?
            > 0)
    }
}

/// Events.
impl Db {
    /// Stores events in one transaction. Returns their IDs in order.
    pub fn insert_events(&self, events: &[NewEvent]) -> rusqlite::Result<Vec<i64>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let mut ids = Vec::with_capacity(events.len());
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO events (ts, tenant, sandbox, step_id, trace_id, actor, type, attrs)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for event in events {
                stmt.execute(params![
                    event.ts,
                    event.tenant,
                    event.sandbox,
                    event.step_id,
                    event.trace.as_ref().map(|t| &t.trace_id),
                    event.actor,
                    event.kind,
                    to_json(&event.attrs),
                ])?;
                ids.push(tx.last_insert_rowid());
            }
        }
        tx.commit()?;
        Ok(ids)
    }

    /// Up to `limit` events after ID `after` that match, oldest first, and
    /// whether there are more.
    pub fn list_events(
        &self,
        filter: &Filter,
        after: i64,
        limit: usize,
    ) -> rusqlite::Result<(Vec<Event>, bool)> {
        let mut sql = format!("SELECT {EVENT_COLUMNS} FROM events WHERE id > ?");
        let mut args: Vec<rusqlite::types::Value> = vec![after.into()];
        for (column, value) in [
            ("tenant", &filter.tenant),
            ("sandbox", &filter.sandbox),
            ("step_id", &filter.step_id),
        ] {
            if let Some(value) = value {
                sql.push_str(&format!(" AND {column} = ?"));
                args.push(value.clone().into());
            }
        }
        if let Some(since) = filter.since {
            sql.push_str(" AND ts >= ?");
            args.push(since.into());
        }
        if let Some(until) = filter.until {
            sql.push_str(" AND ts < ?");
            args.push(until.into());
        }
        if !filter.types.is_empty() {
            let mut any = Vec::new();
            for kind in &filter.types {
                if kind.ends_with('.') {
                    any.push("substr(type, 1, ?) = ?");
                    args.push(i64::try_from(kind.len()).unwrap_or(0).into());
                } else {
                    any.push("type = ?");
                }
                args.push(kind.clone().into());
            }
            sql.push_str(&format!(" AND ({})", any.join(" OR ")));
        }
        sql.push_str(" ORDER BY id LIMIT ?");
        args.push(i64::try_from(limit + 1).unwrap_or(i64::MAX).into());
        let conn = self.conn();
        let mut stmt = conn.prepare(&sql)?;
        let mut events: Vec<Event> = stmt
            .query_map(rusqlite::params_from_iter(args), event_from_row)?
            .collect::<rusqlite::Result<_>>()?;
        let more = events.len() > limit;
        events.truncate(limit);
        Ok((events, more))
    }

    /// The newest event's ID, or 0.
    pub fn latest_event_id(&self) -> rusqlite::Result<i64> {
        self.conn()
            .query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |r| r.get(0))
    }

    /// Deletes up to `batch` events older than `before`. Returns how many.
    pub fn prune_events(&self, before: i64, batch: usize) -> rusqlite::Result<usize> {
        self.conn().execute(
            "DELETE FROM events WHERE id IN
             (SELECT id FROM events WHERE ts < ?1 ORDER BY id LIMIT ?2)",
            params![before, i64::try_from(batch).unwrap_or(i64::MAX)],
        )
    }
}

/// Usage of one tenant (and sandbox, if grouped by it) in one hour.
#[derive(Debug, Clone, PartialEq)]
pub struct UsageRow {
    pub hour: i64,
    pub tenant: String,
    pub sandbox: Option<String>,
    pub totals: Totals,
}

impl Db {
    /// Adds to the hourly usage rows in one transaction.
    pub fn add_usage(&self, rows: &HashMap<UsageKey, Totals>) -> rusqlite::Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO usage_hourly
                 (tenant, hour, sandbox, vcpu_s, mem_gib_s, disk_gib_h, egress_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (tenant, hour, sandbox) DO UPDATE SET
                 vcpu_s = vcpu_s + excluded.vcpu_s,
                 mem_gib_s = mem_gib_s + excluded.mem_gib_s,
                 disk_gib_h = disk_gib_h + excluded.disk_gib_h,
                 egress_bytes = egress_bytes + excluded.egress_bytes",
            )?;
            for (key, totals) in rows {
                stmt.execute(params![
                    key.tenant,
                    key.hour,
                    key.sandbox,
                    totals.vcpu_s,
                    totals.mem_gib_s,
                    totals.disk_gib_h,
                    i64::try_from(totals.egress_bytes).unwrap_or(i64::MAX),
                ])?;
            }
        }
        tx.commit()
    }

    /// Usage in hours from `from` up to `to` (Unix ms), of one tenant or
    /// all, per tenant and hour or also per sandbox. Ordered by hour,
    /// tenant and sandbox.
    pub fn list_usage(
        &self,
        tenant: Option<&str>,
        from: i64,
        to: i64,
        by_sandbox: bool,
    ) -> rusqlite::Result<Vec<UsageRow>> {
        let (sandbox, group) = if by_sandbox {
            ("sandbox", ", sandbox")
        } else {
            ("NULL", "")
        };
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT hour, tenant, {sandbox}, SUM(vcpu_s), SUM(mem_gib_s), SUM(disk_gib_h),
             SUM(egress_bytes) FROM (
                 SELECT tenant, hour, sandbox, vcpu_s, mem_gib_s, disk_gib_h, egress_bytes
                 FROM usage_hourly
                 UNION ALL
                 SELECT tenant, hour, sandbox, vcpu_s, mem_gib_s, disk_gib_h, egress_bytes
                 FROM node_usage
             )
             WHERE hour >= ?1 AND hour < ?2 AND (?3 IS NULL OR tenant = ?3)
             GROUP BY hour, tenant{group} ORDER BY hour, tenant{group}"
        ))?;
        stmt.query_map(params![from, to, tenant], |row| {
            Ok(UsageRow {
                hour: row.get(0)?,
                tenant: row.get(1)?,
                sandbox: row.get(2)?,
                totals: Totals {
                    vcpu_s: row.get(3)?,
                    mem_gib_s: row.get(4)?,
                    disk_gib_h: row.get(5)?,
                    egress_bytes: u64::try_from(row.get::<_, i64>(6)?).unwrap_or(0),
                },
            })
        })?
        .collect()
    }

    /// `tenant`'s stored egress bytes in hours from `since` (Unix ms).
    pub fn egress_since(&self, tenant: &str, since: i64) -> rusqlite::Result<u64> {
        let bytes: i64 = self.conn().query_row(
            "SELECT COALESCE(SUM(egress_bytes), 0) FROM usage_hourly
             WHERE tenant = ?1 AND hour >= ?2",
            params![tenant, since],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(bytes).unwrap_or(0))
    }
}

/// A worker host, as the primary knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRow {
    pub id: String,
    /// Its internal listener, `https://host:port`.
    pub url: String,
    pub state: String,
    /// Changes every time the worker starts.
    pub boot: Option<String>,
    /// Of the last heartbeat taken from `boot`.
    pub seq: i64,
    /// JSON of the last heartbeat, without its sandboxes.
    pub report: Option<String>,
    pub last_seen: Option<i64>,
    pub created_at: i64,
    pub removed_at: Option<i64>,
    /// Gets no new sandboxes.
    pub draining: bool,
    /// `node_kind::WORKER` or `node_kind::EDGE`.
    pub kind: String,
}

pub mod node_kind {
    /// Runs sandboxes.
    pub const WORKER: &str = "worker";
    /// Only routes calls; runs no sandboxes.
    pub const EDGE: &str = "edge";
}

pub mod node_state {
    pub const READY: &str = "ready";
    /// No heartbeat for a while: no new sandboxes go there.
    pub const SUSPECT: &str = "suspect";
    pub const DOWN: &str = "down";
    pub const REMOVED: &str = "removed";
}

const NODE_COLUMNS: &str =
    "id, url, state, boot, seq, report, last_seen, created_at, removed_at, draining, kind";

fn node_from_row(row: &Row<'_>) -> rusqlite::Result<NodeRow> {
    Ok(NodeRow {
        id: row.get(0)?,
        url: row.get(1)?,
        state: row.get(2)?,
        boot: row.get(3)?,
        seq: row.get(4)?,
        report: row.get(5)?,
        last_seen: row.get(6)?,
        created_at: row.get(7)?,
        removed_at: row.get(8)?,
        draining: row.get(9)?,
        kind: row.get(10)?,
    })
}

/// Fleet: nodes, join tokens and the primary's copies of worker sandboxes.
impl Db {
    pub fn insert_join_token(
        &self,
        hash: &[u8],
        now: i64,
        expires_at: i64,
    ) -> rusqlite::Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM join_tokens WHERE expires_at < ?1", [now])?;
        conn.execute(
            "INSERT INTO join_tokens (hash, created_at, expires_at) VALUES (?1, ?2, ?3)",
            params![hash, now, expires_at],
        )?;
        Ok(())
    }

    /// Uses up the join token and adds the node, in one transaction.
    /// Returns false if the token is unknown, used or expired.
    pub fn join_node(&self, token_hash: &[u8], node: &NodeRow) -> rusqlite::Result<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let used = tx.execute(
            "UPDATE join_tokens SET node = ?2
             WHERE hash = ?1 AND node IS NULL AND expires_at > ?3",
            params![token_hash, node.id, node.created_at],
        )?;
        if used == 0 {
            return Ok(false);
        }
        tx.execute(
            &format!(
                "INSERT INTO nodes ({NODE_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
            ),
            params![
                node.id,
                node.url,
                node.state,
                node.boot,
                node.seq,
                node.report,
                node.last_seen,
                node.created_at,
                node.removed_at,
                node.draining,
                node.kind,
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn get_node(&self, id: &str) -> rusqlite::Result<Option<NodeRow>> {
        self.conn()
            .query_row(
                &format!("SELECT {NODE_COLUMNS} FROM nodes WHERE id = ?1"),
                [id],
                node_from_row,
            )
            .optional()
    }

    /// Nodes that are not removed, oldest first.
    /// Sandboxes on this host that have not ended, per state.
    pub fn count_local_sandboxes(&self) -> rusqlite::Result<Vec<(String, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT state, COUNT(*) FROM sandboxes
             WHERE node IS NULL AND state IN ('starting', 'running', 'paused')
             GROUP BY state",
        )?;
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect()
    }

    pub fn list_nodes(&self) -> rusqlite::Result<Vec<NodeRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {NODE_COLUMNS} FROM nodes WHERE state != 'removed' ORDER BY created_at, id"
        ))?;
        stmt.query_map([], node_from_row)?.collect()
    }

    /// Records a heartbeat. Returns false if the node is removed. The URL
    /// may change, as with a new IP address; fleet TLS still checks the
    /// node's name.
    pub fn node_seen(&self, seen: &NodeRow) -> rusqlite::Result<bool> {
        let changed = self.conn().execute(
            "UPDATE nodes SET url = ?2, boot = ?3, seq = ?4, report = ?5, last_seen = ?6,
                 state = 'ready'
             WHERE id = ?1 AND state != 'removed'",
            params![
                seen.id,
                seen.url,
                seen.boot,
                seen.seq,
                seen.report,
                seen.last_seen
            ],
        )?;
        Ok(changed > 0)
    }

    pub fn set_node_state(&self, id: &str, state: &str) -> rusqlite::Result<()> {
        self.conn().execute(
            "UPDATE nodes SET state = ?2 WHERE id = ?1 AND state != 'removed'",
            params![id, state],
        )?;
        Ok(())
    }

    /// Returns false if no such node is active.
    pub fn set_node_draining(&self, id: &str, draining: bool) -> rusqlite::Result<bool> {
        let changed = self.conn().execute(
            "UPDATE nodes SET draining = ?2 WHERE id = ?1 AND state != 'removed'",
            params![id, draining],
        )?;
        Ok(changed > 0)
    }

    /// Returns false if no such node is active.
    pub fn remove_node(&self, id: &str, now: i64) -> rusqlite::Result<bool> {
        let changed = self.conn().execute(
            "UPDATE nodes SET state = 'removed', removed_at = ?2
             WHERE id = ?1 AND state != 'removed'",
            params![id, now],
        )?;
        Ok(changed > 0)
    }

    /// Records an edge's routes call. Returns false if it is not an active
    /// edge.
    pub fn edge_seen(&self, id: &str, now: i64) -> rusqlite::Result<bool> {
        let changed = self.conn().execute(
            "UPDATE nodes SET last_seen = ?2, state = 'ready'
             WHERE id = ?1 AND kind = 'edge' AND state != 'removed'",
            params![id, now],
        )?;
        Ok(changed > 0)
    }

    /// IDs of edges that are not removed.
    pub fn edge_ids(&self) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id FROM nodes WHERE kind = 'edge' AND state != 'removed' ORDER BY id",
        )?;
        stmt.query_map([], |r| r.get(0))?.collect()
    }

    /// Sandbox and worker of each sandbox that has not ended and runs on a
    /// worker that is not down or removed.
    pub fn edge_routes(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT s.id, s.node FROM sandboxes s JOIN nodes n ON n.id = s.node
             WHERE s.state IN ('starting', 'running', 'paused')
                 AND n.kind = 'worker' AND n.state IN ('ready', 'suspect')
             ORDER BY s.id",
        )?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect()
    }

    /// Sandboxes of this host to report: all that have not ended, and those
    /// that ended since `ended_since`, so the primary learns how.
    pub fn local_report(&self, ended_since: i64) -> rusqlite::Result<Vec<Sandbox>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {SANDBOX_COLUMNS} FROM sandboxes
             WHERE node IS NULL AND (state NOT IN ('deleted', 'failed') OR ended_at >= ?1)
             ORDER BY seq"
        ))?;
        stmt.query_map([ended_since], sandbox_from_row)?.collect()
    }

    /// Writes what `node` reports about one of its sandboxes. A row that
    /// ended or that belongs to another host is never changed.
    pub fn put_mirror(&self, node: &str, sandbox: &Sandbox, now: i64) -> rusqlite::Result<()> {
        let ended = matches!(sandbox.state.as_str(), state::FAILED | state::DELETED).then_some(now);
        self.conn().execute(
            "INSERT INTO sandboxes
             (id, state, template, build, labels, created_at, expires_at, secrets, egress,
              idle_pause_s, tenant, node, vcpus, memory_mib, paused_at, ended_at, volumes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT (id) DO UPDATE SET
                 state = excluded.state, build = excluded.build, labels = excluded.labels,
                 expires_at = excluded.expires_at, secrets = excluded.secrets,
                 volumes = excluded.volumes,
                 egress = excluded.egress, idle_pause_s = excluded.idle_pause_s,
                 vcpus = excluded.vcpus, memory_mib = excluded.memory_mib,
                 paused_at = excluded.paused_at,
                 ended_at = COALESCE(excluded.ended_at, sandboxes.ended_at)
             WHERE sandboxes.node = excluded.node
               AND sandboxes.state NOT IN ('deleted', 'failed')",
            params![
                sandbox.id,
                sandbox.state,
                sandbox.template,
                sandbox.build,
                to_json(&sandbox.labels),
                sandbox.created_at,
                sandbox.expires_at,
                to_json(&sandbox.secrets),
                to_json(&sandbox.egress),
                i64::try_from(sandbox.idle_pause_s).unwrap_or(i64::MAX),
                sandbox.tenant,
                node,
                sandbox.vcpus,
                sandbox.memory_mib,
                sandbox.paused_at,
                ended,
                volumes_json(&sandbox.volumes),
            ],
        )?;
        Ok(())
    }

    /// Moves `node`'s sandbox to `state`, unless it has ended.
    pub fn set_mirror_state(
        &self,
        node: &str,
        id: &str,
        state: &str,
        now: i64,
    ) -> rusqlite::Result<()> {
        let ended = matches!(state, state::FAILED | state::DELETED).then_some(now);
        self.conn().execute(
            "UPDATE sandboxes SET state = ?3, ended_at = COALESCE(?4, ended_at)
             WHERE id = ?1 AND node = ?2 AND state NOT IN ('deleted', 'failed')",
            params![id, node, state, ended],
        )?;
        Ok(())
    }

    /// Marks deleted `node`'s sandboxes that have not ended, except those
    /// in `keep` and those created at or after `created_before`. Returns
    /// their IDs and tenants.
    pub fn end_mirrors(
        &self,
        node: &str,
        keep: &std::collections::HashSet<String>,
        created_before: i64,
        now: i64,
    ) -> rusqlite::Result<Vec<(String, String)>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let live: Vec<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, tenant FROM sandboxes
                 WHERE node = ?1 AND state NOT IN ('deleted', 'failed') AND created_at < ?2",
            )?;
            stmt.query_map(params![node, created_before], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        let gone: Vec<_> = live
            .into_iter()
            .filter(|(id, _)| !keep.contains(id))
            .collect();
        for (id, _) in &gone {
            tx.execute(
                "UPDATE sandboxes SET state = 'deleted', ended_at = ?2 WHERE id = ?1",
                params![id, now],
            )?;
        }
        tx.commit()?;
        Ok(gone)
    }

    /// How many sandboxes that have not ended each worker runs.
    pub fn node_sandbox_counts(&self) -> rusqlite::Result<HashMap<String, usize>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT node, count(*) FROM sandboxes
             WHERE node IS NOT NULL AND state NOT IN ('deleted', 'failed') GROUP BY node",
        )?;
        stmt.query_map([], |r| {
            Ok((r.get(0)?, usize::try_from(r.get::<_, i64>(1)?).unwrap_or(0)))
        })?
        .collect()
    }

    /// What `tenant`'s sandboxes that start or run on workers hold.
    pub fn mirror_usage(&self, tenant: &str) -> rusqlite::Result<Usage> {
        self.conn().query_row(
            "SELECT count(*), COALESCE(SUM(vcpus), 0), COALESCE(SUM(memory_mib), 0)
             FROM sandboxes
             WHERE tenant = ?1 AND node IS NOT NULL AND state IN ('starting', 'running')",
            [tenant],
            |r| {
                let count = |i| r.get::<_, i64>(i).map(|n| u64::try_from(n).unwrap_or(0));
                Ok(Usage {
                    running_sandboxes: count(0)?,
                    running_vcpus: count(1)?,
                    running_memory_mib: count(2)?,
                })
            },
        )
    }

    /// How many sandboxes of `tenant` have not ended, per host (`None`:
    /// this one).
    pub fn tenant_spread(&self, tenant: &str) -> rusqlite::Result<HashMap<Option<String>, u32>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT node, count(*) FROM sandboxes
             WHERE tenant = ?1 AND state NOT IN ('deleted', 'failed') GROUP BY node",
        )?;
        stmt.query_map([tenant], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect()
    }

    /// Makes `sandbox` a paused sandbox of this host, as a migration's
    /// target does. Returns the row's node before, for `undo_take_over`:
    /// `None` if there was no row.
    pub fn take_over(
        &self,
        sandbox: &Sandbox,
        paused_at: i64,
        saved: &str,
    ) -> rusqlite::Result<Option<Option<String>>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let prior: Option<Option<String>> = tx
            .query_row(
                "SELECT node FROM sandboxes WHERE id = ?1",
                [&sandbox.id],
                |r| r.get(0),
            )
            .optional()?;
        tx.execute(
            "INSERT INTO sandboxes
             (id, state, template, build, labels, created_at, expires_at, secrets, egress,
              idle_pause_s, tenant, node, vcpus, memory_mib, paused_at, saved, volumes)
             VALUES (?1, 'paused', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11, ?12, ?13, ?14,
                     ?15)
             ON CONFLICT (id) DO UPDATE SET
                 state = 'paused', build = excluded.build, labels = excluded.labels,
                 expires_at = excluded.expires_at, secrets = excluded.secrets,
                 volumes = excluded.volumes,
                 egress = excluded.egress, idle_pause_s = excluded.idle_pause_s,
                 node = NULL, vcpus = excluded.vcpus, memory_mib = excluded.memory_mib,
                 paused_at = excluded.paused_at, saved = excluded.saved, ended_at = NULL",
            params![
                sandbox.id,
                sandbox.template,
                sandbox.build,
                to_json(&sandbox.labels),
                sandbox.created_at,
                sandbox.expires_at,
                to_json(&sandbox.secrets),
                to_json(&sandbox.egress),
                i64::try_from(sandbox.idle_pause_s).unwrap_or(i64::MAX),
                sandbox.tenant,
                sandbox.vcpus,
                sandbox.memory_mib,
                paused_at,
                saved,
                volumes_json(&sandbox.volumes),
            ],
        )?;
        tx.commit()?;
        Ok(prior)
    }

    /// Gives a row back after a `take_over` whose migration failed.
    pub fn undo_take_over(&self, id: &str, prior: Option<Option<String>>) -> rusqlite::Result<()> {
        let conn = self.conn();
        match prior {
            None => conn.execute("DELETE FROM sandboxes WHERE id = ?1 AND node IS NULL", [id])?,
            Some(node) => conn.execute(
                "UPDATE sandboxes SET node = ?2, saved = NULL WHERE id = ?1 AND node IS NULL",
                params![id, node],
            )?,
        };
        Ok(())
    }

    /// Marks a sandbox of this host as run by `node` now. On the primary
    /// this makes the row a mirror; on a worker it only stops reports.
    pub fn hand_off(&self, id: &str, node: &str) -> rusqlite::Result<bool> {
        let changed = self.conn().execute(
            "UPDATE sandboxes SET node = ?2, saved = NULL WHERE id = ?1 AND node IS NULL",
            params![id, node],
        )?;
        Ok(changed > 0)
    }

    /// Points `from`'s copy of a sandbox at `to`.
    pub fn reassign(&self, id: &str, from: &str, to: &str) -> rusqlite::Result<bool> {
        let changed = self.conn().execute(
            "UPDATE sandboxes SET node = ?3 WHERE id = ?1 AND node = ?2",
            params![id, from, to],
        )?;
        Ok(changed > 0)
    }

    /// Sandboxes that run or are paused on `node`.
    pub fn node_sandboxes(&self, node: &str) -> rusqlite::Result<Vec<Sandbox>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {SANDBOX_COLUMNS} FROM sandboxes
             WHERE node = ?1 AND state IN ('running', 'paused') ORDER BY seq"
        ))?;
        stmt.query_map([node], sandbox_from_row)?.collect()
    }

    /// Of `ids`, which `node` reports, those this primary knows on another
    /// host.
    pub fn misplaced(&self, node: &str, ids: &[&str]) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare_cached("SELECT 1 FROM sandboxes WHERE id = ?1 AND node IS NOT ?2")?;
        let mut out = Vec::new();
        for id in ids {
            if stmt.exists(params![id, node])? {
                out.push((*id).to_owned());
            }
        }
        Ok(out)
    }

    /// Every key with its hash, for workers.
    pub fn list_key_hashes(&self) -> rusqlite::Result<Vec<(Key, Vec<u8>)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {KEY_COLUMNS}, hash FROM api_keys ORDER BY created_at, id"
        ))?;
        stmt.query_map([], |r| Ok((key_from_row(r)?, r.get(6)?)))?
            .collect()
    }

    /// Makes tenants and keys exactly the given ones, in one transaction.
    pub fn replace_tenants_and_keys(
        &self,
        tenants: &[Tenant],
        keys: &[(Key, Vec<u8>)],
    ) -> rusqlite::Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM api_keys", [])?;
        tx.execute("DELETE FROM tenants", [])?;
        for t in tenants {
            tx.execute(
                "INSERT INTO tenants (id, name, quotas, egress, created_at, updated_at, isolation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    t.id,
                    t.name,
                    to_json(&t.quotas),
                    t.egress.as_ref().map(to_json),
                    t.created_at,
                    t.updated_at,
                    t.isolation.as_str(),
                ],
            )?;
        }
        for (k, hash) in keys {
            tx.execute(
                "INSERT INTO api_keys (id, hash, created_at, revoked_at, tenant, scopes, name)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    k.id,
                    hash,
                    k.created_at,
                    k.revoked_at,
                    k.tenant,
                    k.scopes,
                    k.name
                ],
            )?;
        }
        tx.commit()
    }

    /// Stores a worker's events once each. Returns the ones that were new,
    /// with their IDs here.
    pub fn insert_remote_events(
        &self,
        node: &str,
        events: &[Event],
    ) -> rusqlite::Result<Vec<Event>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let mut stored = Vec::new();
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR IGNORE INTO events
                 (ts, tenant, sandbox, step_id, trace_id, actor, type, attrs, source_node,
                  source_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for event in events {
                let added = stmt.execute(params![
                    event.ts,
                    event.tenant,
                    event.sandbox,
                    event.step_id,
                    event.trace_id,
                    event.actor,
                    event.kind,
                    to_json(&event.attrs),
                    node,
                    event.id,
                ])?;
                if added > 0 {
                    stored.push(Event {
                        id: tx.last_insert_rowid(),
                        ..event.clone()
                    });
                }
            }
        }
        tx.commit()?;
        Ok(stored)
    }

    /// The newest event ID of `node` stored here, or 0.
    pub fn remote_event_cursor(&self, node: &str) -> rusqlite::Result<i64> {
        self.conn().query_row(
            "SELECT COALESCE(MAX(source_id), 0) FROM events WHERE source_node = ?1",
            [node],
            |r| r.get(0),
        )
    }

    /// This host's hourly usage rows from hour `from` (Unix ms).
    pub fn usage_rows(&self, from: i64) -> rusqlite::Result<Vec<(UsageKey, Totals)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT tenant, hour, sandbox, vcpu_s, mem_gib_s, disk_gib_h, egress_bytes
             FROM usage_hourly WHERE hour >= ?1",
        )?;
        stmt.query_map([from], |r| {
            Ok((
                UsageKey {
                    tenant: r.get(0)?,
                    hour: r.get(1)?,
                    sandbox: r.get(2)?,
                },
                Totals {
                    vcpu_s: r.get(3)?,
                    mem_gib_s: r.get(4)?,
                    disk_gib_h: r.get(5)?,
                    egress_bytes: u64::try_from(r.get::<_, i64>(6)?).unwrap_or(0),
                },
            ))
        })?
        .collect()
    }

    /// Takes a worker's hourly totals. Totals only grow, so the larger
    /// value wins and a late batch changes nothing.
    pub fn merge_node_usage(
        &self,
        node: &str,
        rows: &[(UsageKey, Totals)],
    ) -> rusqlite::Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO node_usage
                 (node, tenant, hour, sandbox, vcpu_s, mem_gib_s, disk_gib_h, egress_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT (node, tenant, hour, sandbox) DO UPDATE SET
                 vcpu_s = MAX(vcpu_s, excluded.vcpu_s),
                 mem_gib_s = MAX(mem_gib_s, excluded.mem_gib_s),
                 disk_gib_h = MAX(disk_gib_h, excluded.disk_gib_h),
                 egress_bytes = MAX(egress_bytes, excluded.egress_bytes)",
            )?;
            for (key, totals) in rows {
                stmt.execute(params![
                    node,
                    key.tenant,
                    key.hour,
                    key.sandbox,
                    totals.vcpu_s,
                    totals.mem_gib_s,
                    totals.disk_gib_h,
                    i64::try_from(totals.egress_bytes).unwrap_or(i64::MAX),
                ])?;
            }
        }
        tx.commit()
    }
}

fn to_json(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

const SANDBOX_COLUMNS: &str = "id, state, template, labels, created_at, expires_at, build, \
    secrets, egress, idle_pause_s, paused_at, tenant, node, vcpus, memory_mib, volumes";
const SANDBOX_COLUMN_COUNT: usize = 16;
const VOLUME_COLUMNS: &str = "id, tenant, name, size_gib, node, backend, created_at";
const KEY_COLUMNS: &str = "id, tenant, scopes, name, created_at, revoked_at";
const TENANT_COLUMNS: &str = "id, name, quotas, egress, created_at, updated_at, isolation";

fn key_from_row(row: &Row<'_>) -> rusqlite::Result<Key> {
    Ok(Key {
        id: row.get(0)?,
        tenant: row.get(1)?,
        scopes: row.get(2)?,
        name: row.get(3)?,
        created_at: row.get(4)?,
        revoked_at: row.get(5)?,
    })
}

fn tenant_from_row(row: &Row<'_>) -> rusqlite::Result<Tenant> {
    let quotas: String = row.get(2)?;
    Ok(Tenant {
        id: row.get(0)?,
        name: row.get(1)?,
        quotas: serde_json::from_str::<Quotas>(&quotas).unwrap_or_default(),
        egress: row
            .get::<_, Option<String>>(3)?
            .and_then(|s| serde_json::from_str(&s).ok()),
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        isolation: Isolation::parse(&row.get::<_, String>(6)?),
    })
}
const EVENT_COLUMNS: &str = "id, ts, tenant, sandbox, step_id, trace_id, actor, type, attrs";

fn event_from_row(row: &Row<'_>) -> rusqlite::Result<Event> {
    let attrs: String = row.get(8)?;
    Ok(Event {
        id: row.get(0)?,
        ts: row.get(1)?,
        tenant: row.get(2)?,
        sandbox: row.get(3)?,
        step_id: row.get(4)?,
        trace_id: row.get(5)?,
        actor: row.get(6)?,
        kind: row.get(7)?,
        attrs: serde_json::from_str(&attrs).unwrap_or_default(),
    })
}

const SECRET_COLUMNS: &str = "name, spec, value, version, created_at, updated_at";

fn secret_from_row(row: &Row<'_>) -> rusqlite::Result<Secret> {
    Ok(Secret {
        name: row.get(0)?,
        spec: row.get(1)?,
        value: row.get(2)?,
        version: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

const BUILD_COLUMNS: &str =
    "seq, id, template, spec, fingerprint, state, created_at, started_at, finished_at, error,
     store_key, uploaded_at";

fn template_from_row(row: &Row<'_>) -> rusqlite::Result<Template> {
    Ok(Template {
        name: row.get(0)?,
        spec: row.get(1)?,
        created_at: row.get(2)?,
        updated_at: row.get(3)?,
    })
}

fn build_from_row(row: &Row<'_>) -> rusqlite::Result<Build> {
    Ok(Build {
        seq: row.get(0)?,
        id: row.get(1)?,
        template: row.get(2)?,
        spec: row.get(3)?,
        fingerprint: row.get(4)?,
        state: row.get(5)?,
        created_at: row.get(6)?,
        started_at: row.get(7)?,
        finished_at: row.get(8)?,
        error: row.get(9)?,
        store_key: row.get(10)?,
        uploaded_at: row.get(11)?,
    })
}

fn sandbox_from_row(row: &Row<'_>) -> rusqlite::Result<Sandbox> {
    let labels: String = row.get(3)?;
    Ok(Sandbox {
        id: row.get(0)?,
        state: row.get(1)?,
        template: row.get(2)?,
        labels: serde_json::from_str(&labels).unwrap_or_default(),
        created_at: row.get(4)?,
        expires_at: row.get(5)?,
        build: row.get(6)?,
        secrets: row
            .get::<_, Option<String>>(7)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        egress: row
            .get::<_, Option<String>>(8)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(Policy::allow_all),
        idle_pause_s: u64::try_from(row.get::<_, i64>(9)?).unwrap_or(0),
        paused_at: row.get(10)?,
        tenant: row.get(11)?,
        node: row.get(12)?,
        vcpus: row.get(13)?,
        memory_mib: row.get(14)?,
        volumes: row
            .get::<_, Option<String>>(15)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
    })
}

fn volume_from_row(row: &Row<'_>) -> rusqlite::Result<Volume> {
    Ok(Volume {
        id: row.get(0)?,
        tenant: row.get(1)?,
        name: row.get(2)?,
        size_gib: row.get(3)?,
        node: row.get(4)?,
        backend: row.get(5)?,
        created_at: row.get(6)?,
    })
}

/// `NULL` for no volumes, so rows from before volumes look the same.
fn volumes_json(volumes: &[VolumeRef]) -> Option<String> {
    (!volumes.is_empty()).then(|| to_json(&volumes))
}

/// Sandboxes, other than `except`, that have volume `id` mounted and have
/// not ended.
fn volume_users(conn: &Connection, id: &str, except: &str) -> rusqlite::Result<Vec<VolumeUser>> {
    let mut stmt = conn.prepare_cached(
        "SELECT s.id, json_extract(v.value, '$.read_only')
         FROM sandboxes s, json_each(s.volumes) v
         WHERE s.volumes IS NOT NULL AND s.state NOT IN ('deleted', 'failed')
           AND json_extract(v.value, '$.volume') = ?1 AND s.id != ?2",
    )?;
    stmt.query_map([id, except], |row| {
        Ok(VolumeUser {
            sandbox: row.get(0)?,
            read_only: row.get::<_, Option<bool>>(1)?.unwrap_or(false),
        })
    })?
    .collect()
}

/// The volume's name if `volume` cannot be mounted next to its users.
fn volume_taken(
    conn: &Connection,
    volume: &VolumeRef,
    except: &str,
) -> rusqlite::Result<Option<String>> {
    let users = volume_users(conn, &volume.volume, except)?;
    let taken = users
        .iter()
        .any(|user| !user.read_only || !volume.read_only);
    Ok(taken.then(|| volume.name.clone()))
}

// The runtime module is Linux only; the database also builds on macOS for development.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(id: &str, state: &str) -> Sandbox {
        Sandbox {
            id: id.into(),
            tenant: "default".into(),
            state: state.into(),
            template: "base".into(),
            build: Some("bld_1".into()),
            labels: BTreeMap::from([("run".into(), "r1".into())]),
            secrets: vec!["gh".into()],
            egress: Policy {
                mode: spawn_egress::Mode::Allowlist,
                allow: vec!["github.com".into()],
                deny: Vec::new(),
                max_egress_mbps: None,
                max_ingress_mbps: None,
            },
            created_at: 1,
            expires_at: 2,
            idle_pause_s: 600,
            paused_at: None,
            node: None,
            vcpus: 2,
            memory_mib: 1024,
            volumes: Vec::new(),
        }
    }

    fn volume(id: &str, name: &str) -> Volume {
        Volume {
            id: id.into(),
            tenant: "default".into(),
            name: name.into(),
            size_gib: 1,
            node: None,
            backend: Some("firecracker".into()),
            created_at: 1,
        }
    }

    fn with_volume(id: &str, read_only: bool) -> Sandbox {
        let mut s = sandbox(id, state::RUNNING);
        s.volumes = vec![VolumeRef {
            volume: "vol_1".into(),
            name: "data".into(),
            path: "/data".into(),
            read_only,
            size_gib: 1,
        }];
        s
    }

    #[test]
    fn one_writer_or_many_readers() {
        let db = Db::memory().unwrap();
        assert!(db.insert_volume(&volume("vol_1", "data")).unwrap());
        assert!(!db.insert_volume(&volume("vol_2", "data")).unwrap());
        db.insert_sandbox(&with_volume("sbx_w", false))
            .unwrap()
            .unwrap();
        let taken = db.insert_sandbox(&with_volume("sbx_r", true)).unwrap();
        assert_eq!(taken, Err("data".to_owned()));
        assert!(db.delete_volume("vol_1", 5).unwrap().is_err());
        db.set_state("sbx_w", state::DELETED, 5).unwrap();
        db.insert_sandbox(&with_volume("sbx_r1", true))
            .unwrap()
            .unwrap();
        db.insert_sandbox(&with_volume("sbx_r2", true))
            .unwrap()
            .unwrap();
        let taken = db.insert_sandbox(&with_volume("sbx_w2", false)).unwrap();
        assert_eq!(taken, Err("data".to_owned()));
        assert_eq!(db.volume_users("vol_1").unwrap().len(), 2);
    }

    #[test]
    fn put_volume_replaces_a_deleted_name() {
        let db = Db::memory().unwrap();
        db.put_volume(&volume("vol_1", "data")).unwrap();
        db.put_volume(&volume("vol_2", "data")).unwrap();
        assert!(db.get_volume_by_id("vol_1").unwrap().is_none());
        assert_eq!(
            db.get_volume("default", "data").unwrap().unwrap().id,
            "vol_2"
        );
        db.delete_volume("vol_2", 5).unwrap().unwrap();
        db.put_volume(&volume("vol_2", "data")).unwrap();
        assert!(db.get_volume_by_id("vol_2").unwrap().is_none());
    }

    #[test]
    fn migrations_run_once() {
        let db = Db::memory().unwrap();
        let conn = db.conn();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, MIGRATIONS.len() as i64);
    }

    #[test]
    fn stores_lists_and_prunes_events() {
        use crate::events::Origin;
        use serde_json::json;
        let db = Db::memory().unwrap();
        assert_eq!(db.latest_event_id().unwrap(), 0);
        let origin = Origin::of_call(
            "key_a",
            Some("step_1"),
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        )
        .unwrap();
        let event = |kind, tenant, sandbox, ts| {
            NewEvent::new(kind, &origin, tenant, sandbox, json!({"n": ts}), ts)
        };
        let ids = db
            .insert_events(&[
                event("exec.started", Some("acme"), Some("sbx_1"), 10),
                event("exec.finished", Some("acme"), Some("sbx_1"), 20),
                event("file.written", Some("beta"), Some("sbx_2"), 30),
                event("key.created", None, None, 40),
            ])
            .unwrap();
        assert_eq!(ids, [1, 2, 3, 4]);
        assert_eq!(db.latest_event_id().unwrap(), 4);

        let all = Filter::default();
        let (page, more) = db.list_events(&all, 0, 2).unwrap();
        assert_eq!(page.iter().map(|e| e.id).collect::<Vec<_>>(), [1, 2]);
        assert!(more);
        assert_eq!(page[0].step_id.as_deref(), Some("step_1"));
        assert_eq!(
            page[0].trace_id.as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
        assert_eq!(page[0].attrs, json!({"n": 10}));
        let (page, more) = db.list_events(&all, 2, 2).unwrap();
        assert_eq!(page.iter().map(|e| e.id).collect::<Vec<_>>(), [3, 4]);
        assert!(!more);

        let filter = Filter {
            tenant: Some("acme".into()),
            types: Filter::parse_types("exec.*").unwrap(),
            since: Some(15),
            until: Some(40),
            ..Filter::default()
        };
        let (page, _) = db.list_events(&filter, 0, 10).unwrap();
        assert_eq!(page.iter().map(|e| e.id).collect::<Vec<_>>(), [2]);
        assert!(page.iter().all(|e| filter.matches(e)));
        let filter = Filter {
            sandbox: Some("sbx_2".into()),
            step_id: Some("step_1".into()),
            types: Filter::parse_types("exec.finished,file.written").unwrap(),
            ..Filter::default()
        };
        let (page, _) = db.list_events(&filter, 0, 10).unwrap();
        assert_eq!(page.iter().map(|e| e.id).collect::<Vec<_>>(), [3]);

        assert_eq!(db.prune_events(35, 2).unwrap(), 2);
        assert_eq!(db.prune_events(35, 2).unwrap(), 1);
        assert_eq!(db.prune_events(35, 2).unwrap(), 0);
        let (page, _) = db.list_events(&all, 0, 10).unwrap();
        assert_eq!(page.iter().map(|e| e.id).collect::<Vec<_>>(), [4]);
    }

    #[test]
    fn finds_only_active_keys() {
        let db = Db::memory().unwrap();
        let key = crate::ids::new_key(true).unwrap();
        let stored = db
            .insert_key(
                &key,
                Some("default"),
                Some(r#"["sandboxes:read"]"#),
                Some("ci"),
                1,
            )
            .unwrap();
        assert_eq!(db.find_key(&key.hash).unwrap(), Some(stored.clone()));
        assert_eq!(stored.tenant.as_deref(), Some("default"));
        assert_eq!(db.find_key(b"other").unwrap(), None);
        assert!(db.revoke_key(&key.id, 2).unwrap());
        assert!(db.revoke_key(&key.id, 3).unwrap());
        assert!(!db.revoke_key("key_nope", 3).unwrap());
        assert_eq!(db.find_key(&key.hash).unwrap(), None);
        assert_eq!(db.list_keys().unwrap()[0].revoked_at, Some(2));
    }

    #[test]
    fn upgrades_keep_old_rows_in_the_default_tenant() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        for sql in &MIGRATIONS[..4] {
            tx.execute_batch(sql).unwrap();
        }
        tx.pragma_update(None, "user_version", 4).unwrap();
        tx.execute(
            "INSERT INTO api_keys (id, hash, created_at) VALUES ('key_old', x'01', 1)",
            [],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO sandboxes (id, state, template, labels, created_at, expires_at)
             VALUES ('sbx_old', 'paused', 'base', '{}', 1, 2)",
            [],
        )
        .unwrap();
        tx.commit().unwrap();
        let db = Db::init(conn).unwrap();
        let key = db.find_key(&[1]).unwrap().unwrap();
        assert_eq!((key.tenant, key.scopes), (None, None));
        assert_eq!(
            db.get_sandbox("sbx_old").unwrap().unwrap().tenant,
            "default"
        );
        let default = db.get_tenant("default").unwrap().unwrap();
        assert_eq!(default.quotas, Quotas::default());
        assert!(default.created_at > 1_700_000_000_000);
    }

    #[test]
    fn deletes_only_unused_tenants() {
        let db = Db::memory().unwrap();
        let acme = Tenant {
            id: "acme".into(),
            name: Some("Acme".into()),
            quotas: Quotas::DEFAULTS,
            egress: Some(Policy::allow_all()),
            created_at: 1,
            updated_at: 1,
            isolation: Isolation::Any,
        };
        assert!(db.insert_tenant(&acme).unwrap());
        assert!(!db.insert_tenant(&acme).unwrap());
        assert_eq!(db.get_tenant("acme").unwrap(), Some(acme.clone()));
        let renamed = Tenant {
            name: None,
            updated_at: 2,
            isolation: Isolation::MicrovmOnly,
            ..acme.clone()
        };
        assert!(db.update_tenant(&renamed).unwrap());
        assert_eq!(db.list_tenants().unwrap()[0], renamed);

        let mut sandbox = sandbox("a", state::RUNNING);
        sandbox.tenant = "acme".into();
        db.insert_sandbox(&sandbox).unwrap().unwrap();
        db.put_template("acme/py", "{}", 1).unwrap();
        db.insert_secret("acme/gh", "{}", b"x", 1).unwrap();
        db.insert_secret("acmex/gh", "{}", b"x", 1).unwrap();
        let key = crate::ids::new_key(true).unwrap();
        db.insert_key(&key, Some("acme"), None, None, 1).unwrap();

        assert_eq!(
            db.delete_tenant("acme", 3).unwrap(),
            Some(Err(InUse::Sandboxes(1)))
        );
        db.set_state("a", state::DELETED, 3).unwrap();
        assert_eq!(
            db.delete_tenant("acme", 3).unwrap(),
            Some(Err(InUse::Templates(1)))
        );
        db.delete_template("acme/py", 3).unwrap();
        assert_eq!(
            db.delete_tenant("acme", 3).unwrap(),
            Some(Err(InUse::Secrets(1)))
        );
        db.delete_secret("acme/gh").unwrap();
        assert_eq!(db.delete_tenant("acme", 4).unwrap(), Some(Ok(())));
        assert_eq!(db.find_key(&key.hash).unwrap(), None);
        assert_eq!(db.delete_tenant("acme", 5).unwrap(), None);
        assert_eq!(db.delete_tenant("nope", 5).unwrap(), None);
    }

    #[test]
    fn stores_and_updates_sandboxes() {
        let db = Db::memory().unwrap();
        db.insert_sandbox(&sandbox("a", state::STARTING))
            .unwrap()
            .unwrap();
        db.set_state("a", state::RUNNING, 5).unwrap();
        assert_eq!(
            db.get_sandbox("a").unwrap(),
            Some(sandbox("a", state::RUNNING))
        );
        assert_eq!(db.get_sandbox("b").unwrap(), None);
    }

    #[test]
    fn paused_sandboxes_survive_restarts() {
        let db = Db::memory().unwrap();
        db.insert_sandbox(&sandbox("a", state::RUNNING))
            .unwrap()
            .unwrap();
        db.insert_sandbox(&sandbox("b", state::RUNNING))
            .unwrap()
            .unwrap();
        db.set_paused("a", 7, "{}").unwrap();
        db.set_saved("a", r#"{"x":1}"#).unwrap();
        assert_eq!(
            db.delete_unfinished(9).unwrap(),
            [("b".to_owned(), "default".to_owned())]
        );
        let paused = db.paused_sandboxes().unwrap();
        assert_eq!(paused.len(), 1);
        let (a, saved) = &paused[0];
        assert_eq!((a.state.as_str(), a.paused_at), (state::PAUSED, Some(7)));
        assert_eq!(saved.as_deref(), Some(r#"{"x":1}"#));

        db.set_resumed("a", 100).unwrap();
        let a = db.get_sandbox("a").unwrap().unwrap();
        assert_eq!(
            (a.state.as_str(), a.paused_at, a.expires_at),
            (state::RUNNING, None, 100)
        );
        assert!(db.paused_sandboxes().unwrap().is_empty());
    }

    #[test]
    fn pages_and_filters_by_state() {
        let db = Db::memory().unwrap();
        for (id, state) in [
            ("a", state::RUNNING),
            ("b", state::DELETED),
            ("c", state::RUNNING),
            ("d", state::FAILED),
        ] {
            db.insert_sandbox(&sandbox(id, state)).unwrap().unwrap();
        }
        let ids = |page: &[Sandbox]| page.iter().map(|s| s.id.clone()).collect::<Vec<_>>();
        let (first, cursor) = db.list_sandboxes(None, None, 2, 0).unwrap();
        assert_eq!(ids(&first), ["a", "c"]);
        let (rest, end) = db.list_sandboxes(None, None, 2, cursor.unwrap()).unwrap();
        assert_eq!(ids(&rest), ["d"]);
        assert_eq!(end, None);
        let (deleted, _) = db
            .list_sandboxes(None, Some(state::DELETED), 10, 0)
            .unwrap();
        assert_eq!(ids(&deleted), ["b"]);
        let mut other = sandbox("e", state::RUNNING);
        other.tenant = "acme".into();
        db.insert_sandbox(&other).unwrap().unwrap();
        let (acme, _) = db.list_sandboxes(Some("acme"), None, 10, 0).unwrap();
        assert_eq!(ids(&acme), ["e"]);
        let (default, _) = db.list_sandboxes(Some("default"), None, 10, 0).unwrap();
        assert_eq!(ids(&default), ["a", "c", "d"]);
    }

    #[test]
    fn tracks_templates_and_builds() {
        let db = Db::memory().unwrap();
        assert!(db.put_template("py", "{}", 1).unwrap());
        assert!(!db.put_template("py", r#"{"a":1}"#, 2).unwrap());
        let t = db.get_template("py").unwrap().unwrap();
        assert_eq!(
            (t.spec.as_str(), t.created_at, t.updated_at),
            (r#"{"a":1}"#, 1, 2)
        );

        let first = db.insert_build("b1", "py", "{}", "f", 3).unwrap();
        let second = db.insert_build("b2", "py", "{}", "f", 4).unwrap();
        assert!(second.seq > first.seq);
        db.set_build_state("b1", build_state::BUILDING, 5, None)
            .unwrap();
        db.set_build_state("b1", build_state::FAILED, 6, Some("boom"))
            .unwrap();
        let b1 = db.get_build("b1").unwrap().unwrap();
        assert_eq!(
            (b1.started_at, b1.finished_at, b1.error.as_deref()),
            (Some(5), Some(6), Some("boom"))
        );
        assert_eq!(db.latest_build("py").unwrap().unwrap().id, "b2");
        let queued = db.builds_in(&[build_state::QUEUED]).unwrap();
        assert_eq!(queued.len(), 1);

        assert!(db.start_build("b2", "new", "k", 7).unwrap());
        assert!(!db.start_build("b2", "new", "k", 7).unwrap());
        assert_eq!(db.get_build("b2").unwrap().unwrap().fingerprint, "new");
        assert_eq!(db.requeue_unfinished_builds().unwrap(), 1);
        assert!(db.delete_template("py", 8).unwrap());
        assert!(!db.start_build("b2", "new", "k", 9).unwrap());
        db.fail_build("b2", 9, "late").unwrap();
        let b2 = db.get_build("b2").unwrap().unwrap();
        assert_eq!((b2.state.as_str(), b2.error), (build_state::REMOVED, None));
        assert_eq!(
            db.get_build("b1").unwrap().unwrap().state,
            build_state::FAILED
        );
        assert!(db.get_template("py").unwrap().is_none());
    }

    #[test]
    fn deletes_sandboxes_left_by_a_stopped_server() {
        let db = Db::memory().unwrap();
        db.insert_sandbox(&sandbox("a", state::RUNNING))
            .unwrap()
            .unwrap();
        db.insert_sandbox(&sandbox("b", state::STARTING))
            .unwrap()
            .unwrap();
        db.insert_sandbox(&sandbox("c", state::FAILED))
            .unwrap()
            .unwrap();
        let mut lost = db.delete_unfinished(9).unwrap();
        lost.sort();
        assert_eq!(
            lost,
            [
                ("a".to_owned(), "default".to_owned()),
                ("b".to_owned(), "default".to_owned())
            ]
        );
        assert_eq!(db.get_sandbox("a").unwrap().unwrap().state, state::DELETED);
        assert_eq!(db.get_sandbox("c").unwrap().unwrap().state, state::FAILED);
    }

    #[test]
    fn stores_secrets() {
        let db = Db::memory().unwrap();
        assert!(db.insert_secret("gh", "{}", b"v1", 1).unwrap());
        assert!(!db.insert_secret("gh", "{}", b"v2", 2).unwrap());
        assert!(db.update_secret("gh", 1, "{\"x\":1}", b"v3", 3).unwrap());
        // A second writer that read version 1 loses.
        assert!(!db.update_secret("gh", 1, "{}", b"v4", 4).unwrap());
        let secret = db.get_secret("gh").unwrap().unwrap();
        assert_eq!(
            (
                secret.version,
                secret.value.as_slice(),
                secret.created_at,
                secret.updated_at
            ),
            (2, &b"v3"[..], 1, 3)
        );
        assert_eq!(db.list_secrets().unwrap().len(), 1);
        assert!(db.delete_secret("gh").unwrap());
        assert!(!db.delete_secret("gh").unwrap());
        assert_eq!(db.get_secret("gh").unwrap(), None);
    }

    fn node(id: &str, now: i64) -> NodeRow {
        NodeRow {
            id: id.into(),
            url: "https://10.0.0.2:7443".into(),
            state: node_state::SUSPECT.into(),
            boot: None,
            seq: 0,
            report: None,
            last_seen: None,
            created_at: now,
            removed_at: None,
            draining: false,
            kind: node_kind::WORKER.into(),
        }
    }

    #[test]
    fn draining_lasts_through_heartbeats() {
        let db = Db::memory().unwrap();
        db.insert_join_token(b"t", 0, 100).unwrap();
        db.join_node(b"t", &node("nod_a", 1)).unwrap();
        assert!(db.set_node_draining("nod_a", true).unwrap());
        assert!(!db.set_node_draining("nod_x", true).unwrap());
        db.node_seen(&node("nod_a", 2)).unwrap();
        let row = db.get_node("nod_a").unwrap().unwrap();
        assert!(row.draining);
        assert_eq!(row.state, node_state::READY);
        db.set_node_draining("nod_a", false).unwrap();
        assert!(!db.get_node("nod_a").unwrap().unwrap().draining);
    }

    #[test]
    fn edges_route_to_live_workers_only() {
        let db = Db::memory().unwrap();
        for (token, id) in [(b"a", "nod_a"), (b"b", "nod_b"), (b"e", "nod_e")] {
            db.insert_join_token(token, 0, 100).unwrap();
            let mut row = node(id, 1);
            if id == "nod_e" {
                row.kind = node_kind::EDGE.into();
            }
            db.join_node(token, &row).unwrap();
        }
        assert!(db.edge_seen("nod_e", 5).unwrap());
        assert!(!db.edge_seen("nod_a", 5).unwrap());
        let edge = db.get_node("nod_e").unwrap().unwrap();
        assert_eq!((edge.kind.as_str(), edge.state.as_str()), ("edge", "ready"));
        assert_eq!(db.edge_ids().unwrap(), ["nod_e"]);

        db.put_mirror("nod_a", &sandbox("sbx_r", state::RUNNING), 5)
            .unwrap();
        db.put_mirror("nod_a", &sandbox("sbx_d", state::DELETED), 5)
            .unwrap();
        db.put_mirror("nod_b", &sandbox("sbx_b", state::PAUSED), 5)
            .unwrap();
        db.set_node_state("nod_b", node_state::DOWN).unwrap();
        assert_eq!(
            db.edge_routes().unwrap(),
            [("sbx_r".to_owned(), "nod_a".to_owned())]
        );

        assert!(db.remove_node("nod_e", 6).unwrap());
        assert!(!db.edge_seen("nod_e", 7).unwrap());
        assert!(db.edge_ids().unwrap().is_empty());
    }

    #[test]
    fn sandboxes_move_between_hosts() {
        let db = Db::memory().unwrap();
        // A worker's sandbox comes to this host, then fails to resume.
        db.put_mirror("nod_a", &sandbox("sbx_m", state::RUNNING), 5)
            .unwrap();
        let prior = db
            .take_over(&sandbox("sbx_m", state::RUNNING), 9, "{}")
            .unwrap();
        assert_eq!(prior, Some(Some("nod_a".into())));
        let row = db.get_sandbox("sbx_m").unwrap().unwrap();
        assert_eq!((row.state.as_str(), row.node), (state::PAUSED, None));
        assert_eq!(db.paused_sandboxes().unwrap().len(), 1);
        db.undo_take_over("sbx_m", prior).unwrap();
        let row = db.get_sandbox("sbx_m").unwrap().unwrap();
        assert_eq!(row.node.as_deref(), Some("nod_a"));
        assert!(db.paused_sandboxes().unwrap().is_empty());

        // A new one is removed again on failure.
        let prior = db
            .take_over(&sandbox("sbx_n", state::PAUSED), 9, "{}")
            .unwrap();
        assert_eq!(prior, None);
        db.undo_take_over("sbx_n", prior).unwrap();
        assert!(db.get_sandbox("sbx_n").unwrap().is_none());

        // This host's sandbox goes to a worker, then to another one.
        db.insert_sandbox(&sandbox("sbx_l", state::PAUSED))
            .unwrap()
            .unwrap();
        assert!(db.hand_off("sbx_l", "nod_a").unwrap());
        assert!(!db.hand_off("sbx_l", "nod_b").unwrap());
        assert!(db.local_report(0).unwrap().is_empty());
        assert!(!db.reassign("sbx_l", "nod_b", "nod_c").unwrap());
        assert!(db.reassign("sbx_l", "nod_a", "nod_b").unwrap());

        // Copies that nod_a still reports belong elsewhere now.
        db.put_mirror("nod_a", &sandbox("sbx_a", state::RUNNING), 5)
            .unwrap();
        db.insert_sandbox(&sandbox("sbx_here", state::RUNNING))
            .unwrap()
            .unwrap();
        let wrong = db
            .misplaced("nod_a", &["sbx_a", "sbx_l", "sbx_m", "sbx_here", "sbx_new"])
            .unwrap();
        assert_eq!(wrong, ["sbx_l", "sbx_here"]);
    }

    #[test]
    fn join_token_works_once_and_not_after_expiry() {
        let db = Db::memory().unwrap();
        db.insert_join_token(b"t1", 100, 200).unwrap();
        assert!(!db.join_node(b"nope", &node("nod_a", 150)).unwrap());
        assert!(db.join_node(b"t1", &node("nod_a", 150)).unwrap());
        assert!(!db.join_node(b"t1", &node("nod_b", 160)).unwrap());
        db.insert_join_token(b"t2", 100, 200).unwrap();
        assert!(!db.join_node(b"t2", &node("nod_c", 200)).unwrap());
        let ids: Vec<_> = db.list_nodes().unwrap().into_iter().map(|n| n.id).collect();
        assert_eq!(ids, ["nod_a"]);

        assert!(db.remove_node("nod_a", 300).unwrap());
        assert!(!db.node_seen(&node("nod_a", 310)).unwrap());
        assert!(db.list_nodes().unwrap().is_empty());
    }

    #[test]
    fn mirrors_never_come_back_or_take_other_rows() {
        let db = Db::memory().unwrap();
        db.insert_sandbox(&sandbox("sbx_local", state::RUNNING))
            .unwrap()
            .unwrap();
        db.put_mirror("nod_a", &sandbox("sbx_local", state::DELETED), 5)
            .unwrap();
        let local = db.get_sandbox("sbx_local").unwrap().unwrap();
        assert_eq!((local.state.as_str(), local.node), (state::RUNNING, None));

        db.put_mirror("nod_a", &sandbox("sbx_m", state::RUNNING), 5)
            .unwrap();
        db.put_mirror("nod_b", &sandbox("sbx_m", state::DELETED), 6)
            .unwrap();
        assert_eq!(
            db.get_sandbox("sbx_m").unwrap().unwrap().state,
            state::RUNNING
        );

        db.set_mirror_state("nod_a", "sbx_m", state::DELETED, 7)
            .unwrap();
        db.put_mirror("nod_a", &sandbox("sbx_m", state::RUNNING), 8)
            .unwrap();
        let mirror = db.get_sandbox("sbx_m").unwrap().unwrap();
        assert_eq!(mirror.state, state::DELETED);
        assert_eq!(mirror.node.as_deref(), Some("nod_a"));
    }

    #[test]
    fn end_mirrors_spares_kept_and_new_rows() {
        let db = Db::memory().unwrap();
        let mut young = sandbox("sbx_young", state::STARTING);
        young.created_at = 50;
        for s in [
            sandbox("sbx_kept", state::RUNNING),
            sandbox("sbx_gone", state::RUNNING),
            young,
        ] {
            db.put_mirror("nod_a", &s, 0).unwrap();
        }
        db.insert_sandbox(&sandbox("sbx_local", state::RUNNING))
            .unwrap()
            .unwrap();
        let keep = std::collections::HashSet::from(["sbx_kept".to_owned()]);
        let gone = db.end_mirrors("nod_a", &keep, 10, 60).unwrap();
        assert_eq!(gone, [("sbx_gone".to_owned(), "default".to_owned())]);
        let state_of = |id| db.get_sandbox(id).unwrap().unwrap().state;
        assert_eq!(state_of("sbx_gone"), state::DELETED);
        assert_eq!(state_of("sbx_kept"), state::RUNNING);
        assert_eq!(state_of("sbx_young"), state::STARTING);
        assert_eq!(state_of("sbx_local"), state::RUNNING);
        let usage = db.mirror_usage("default").unwrap();
        assert_eq!(
            (
                usage.running_sandboxes,
                usage.running_vcpus,
                usage.running_memory_mib
            ),
            (2, 4, 2048)
        );
        assert_eq!(db.mirror_usage("other").unwrap(), Usage::default());
        assert!(db.end_mirrors("nod_a", &keep, 10, 61).unwrap().is_empty());
    }

    #[test]
    fn node_usage_keeps_the_larger_totals() {
        let db = Db::memory().unwrap();
        let key = UsageKey {
            tenant: "default".into(),
            hour: 3_600_000,
            sandbox: "sbx_1".into(),
        };
        let totals = |vcpu_s, egress_bytes| Totals {
            vcpu_s,
            mem_gib_s: 1.0,
            disk_gib_h: 0.5,
            egress_bytes,
        };
        db.merge_node_usage("nod_a", &[(key.clone(), totals(10.0, 100))])
            .unwrap();
        db.merge_node_usage("nod_a", &[(key.clone(), totals(4.0, 300))])
            .unwrap();
        db.merge_node_usage("nod_b", &[(key, totals(1.0, 1))])
            .unwrap();
        let rows = db.list_usage(None, 0, 7_200_000, false).unwrap();
        assert_eq!(rows.len(), 1);
        assert!((rows[0].totals.vcpu_s - 11.0).abs() < 1e-9);
        assert_eq!(rows[0].totals.egress_bytes, 301);
    }

    #[test]
    fn remote_events_are_stored_once() {
        use serde_json::json;
        let db = Db::memory().unwrap();
        let event = |id| Event {
            id,
            ts: 10,
            tenant: Some("default".into()),
            sandbox: Some("sbx_1".into()),
            step_id: None,
            trace_id: None,
            actor: None,
            kind: "exec.started".into(),
            attrs: json!({}),
        };
        assert_eq!(db.remote_event_cursor("nod_a").unwrap(), 0);
        let stored = db
            .insert_remote_events("nod_a", &[event(7), event(8)])
            .unwrap();
        assert_eq!(stored.iter().map(|e| e.id).collect::<Vec<_>>(), [1, 2]);
        let stored = db
            .insert_remote_events("nod_a", &[event(8), event(9)])
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert!(stored[0].id > 2);
        assert_eq!(
            db.insert_remote_events("nod_b", &[event(8)]).unwrap().len(),
            1
        );
        assert_eq!(db.remote_event_cursor("nod_a").unwrap(), 9);
    }
}
