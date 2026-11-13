//! State in SQLite, or Postgres for primaries that fail over: tenants, API keys, sandbox records, templates and their
//! builds, secrets, events and usage.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

mod sql;

use spawn_egress::Policy;
use sql::{Conn, OptionalExtension, Row, Value, params, params_from_iter};
pub use sql::{Error, PgTarget, Result};

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
    "CREATE TABLE scale_requests (
        id TEXT PRIMARY KEY,
        action TEXT NOT NULL,
        token_hash BLOB,
        node TEXT,
        reason TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        ended_at INTEGER,
        outcome TEXT
    );
    CREATE INDEX scale_requests_open ON scale_requests (ended_at);",
    "ALTER TABLE scale_requests ADD COLUMN token_sealed BLOB;
    CREATE TABLE retirements (
        node TEXT PRIMARY KEY,
        id TEXT NOT NULL,
        origin TEXT NOT NULL,
        migrate INTEGER NOT NULL,
        reason TEXT NOT NULL,
        state TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        ready_at INTEGER,
        ended_at INTEGER,
        failed_moves INTEGER NOT NULL DEFAULT 0
    );",
    "ALTER TABLE sandboxes ADD COLUMN persistent INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE sandboxes ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE sandboxes ADD COLUMN cold_starts INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE sandboxes ADD COLUMN last_cold_start_at INTEGER;
    ALTER TABLE sandboxes ADD COLUMN claim TEXT;
    ALTER TABLE sandboxes ADD COLUMN claim_deadline INTEGER;
    CREATE TABLE start_records (
        sandbox TEXT PRIMARY KEY,
        tenant TEXT NOT NULL,
        template TEXT NOT NULL,
        build TEXT NOT NULL,
        spec TEXT NOT NULL,
        vcpus INTEGER NOT NULL,
        memory_mib INTEGER NOT NULL,
        egress TEXT NOT NULL,
        secrets TEXT NOT NULL,
        volumes TEXT NOT NULL,
        ports TEXT NOT NULL,
        idle_pause_s INTEGER NOT NULL,
        env BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE INDEX start_records_build ON start_records (build);",
    "ALTER TABLE start_records ADD COLUMN services BLOB NOT NULL DEFAULT X'';",
    // Earlier versions read `saved` and would drop env stored in the
    // current format, so the rename makes them stop at start instead.
    "ALTER TABLE sandboxes RENAME COLUMN saved TO saved_state;
    CREATE TABLE upkeep (task TEXT PRIMARY KEY);
    INSERT INTO upkeep (task) VALUES ('vacuum');",
    "ALTER TABLE nodes ADD COLUMN fenced_at INTEGER;
    ALTER TABLE nodes ADD COLUMN fenced_by TEXT;",
    "ALTER TABLE builds ADD COLUMN guest TEXT;
    ALTER TABLE builds ADD COLUMN root INTEGER NOT NULL DEFAULT 0;",
    "CREATE TABLE endpoints (
        tenant TEXT NOT NULL,
        name TEXT NOT NULL,
        sandbox TEXT NOT NULL,
        port INTEGER NOT NULL,
        generation INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (tenant, name)
    );",
];

/// The same schema for Postgres, as of the last SQLite migration, and its
/// later upgrades. Text sorts byte by byte, as in SQLite.
const PG_MIGRATIONS: &[&str] = &[
    r#"
    CREATE TABLE api_keys (
        id TEXT COLLATE "C" PRIMARY KEY,
        hash BYTEA NOT NULL UNIQUE,
        created_at BIGINT NOT NULL,
        revoked_at BIGINT,
        tenant TEXT COLLATE "C",
        scopes TEXT COLLATE "C",
        name TEXT COLLATE "C"
    );
    CREATE TABLE sandboxes (
        seq BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
        id TEXT COLLATE "C" NOT NULL UNIQUE,
        state TEXT COLLATE "C" NOT NULL,
        template TEXT COLLATE "C" NOT NULL,
        labels TEXT COLLATE "C" NOT NULL,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        ended_at BIGINT,
        build TEXT COLLATE "C",
        secrets TEXT COLLATE "C",
        egress TEXT COLLATE "C",
        idle_pause_s BIGINT NOT NULL DEFAULT 0,
        paused_at BIGINT,
        saved TEXT COLLATE "C",
        tenant TEXT COLLATE "C" NOT NULL DEFAULT 'default',
        node TEXT COLLATE "C",
        vcpus BIGINT NOT NULL DEFAULT 0,
        memory_mib BIGINT NOT NULL DEFAULT 0,
        volumes TEXT COLLATE "C"
    );
    CREATE INDEX sandboxes_state ON sandboxes (state, seq);
    CREATE INDEX sandboxes_tenant ON sandboxes (tenant, seq);
    CREATE INDEX sandboxes_node ON sandboxes (node, state);
    CREATE TABLE templates (
        name TEXT COLLATE "C" PRIMARY KEY,
        spec TEXT COLLATE "C" NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    );
    CREATE TABLE builds (
        seq BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
        id TEXT COLLATE "C" NOT NULL UNIQUE,
        template TEXT COLLATE "C" NOT NULL,
        spec TEXT COLLATE "C" NOT NULL,
        fingerprint TEXT COLLATE "C" NOT NULL,
        state TEXT COLLATE "C" NOT NULL,
        created_at BIGINT NOT NULL,
        started_at BIGINT,
        finished_at BIGINT,
        error TEXT COLLATE "C",
        store_key TEXT COLLATE "C",
        uploaded_at BIGINT
    );
    CREATE INDEX builds_template ON builds (template, seq);
    CREATE TABLE secrets (
        name TEXT COLLATE "C" PRIMARY KEY,
        spec TEXT COLLATE "C" NOT NULL,
        value BYTEA NOT NULL,
        version BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    );
    CREATE TABLE tenants (
        id TEXT COLLATE "C" PRIMARY KEY,
        name TEXT COLLATE "C",
        quotas TEXT COLLATE "C" NOT NULL,
        egress TEXT COLLATE "C",
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        isolation TEXT COLLATE "C" NOT NULL DEFAULT 'any'
    );
    INSERT INTO tenants (id, quotas, created_at, updated_at) VALUES (
        'default', '{}',
        (extract(epoch FROM now()) * 1000)::bigint,
        (extract(epoch FROM now()) * 1000)::bigint
    );
    CREATE TABLE events (
        id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
        ts BIGINT NOT NULL,
        tenant TEXT COLLATE "C",
        sandbox TEXT COLLATE "C",
        step_id TEXT COLLATE "C",
        trace_id TEXT COLLATE "C",
        actor TEXT COLLATE "C",
        type TEXT COLLATE "C" NOT NULL,
        attrs TEXT COLLATE "C" NOT NULL,
        source_node TEXT COLLATE "C",
        source_id BIGINT
    );
    CREATE INDEX events_ts ON events (ts);
    CREATE INDEX events_tenant ON events (tenant, id);
    CREATE INDEX events_sandbox ON events (sandbox, id);
    CREATE INDEX events_step ON events (step_id, id);
    CREATE UNIQUE INDEX events_source ON events (source_node, source_id)
        WHERE source_node IS NOT NULL;
    CREATE TABLE usage_hourly (
        tenant TEXT COLLATE "C" NOT NULL,
        hour BIGINT NOT NULL,
        sandbox TEXT COLLATE "C" NOT NULL,
        vcpu_s DOUBLE PRECISION NOT NULL DEFAULT 0,
        mem_gib_s DOUBLE PRECISION NOT NULL DEFAULT 0,
        disk_gib_h DOUBLE PRECISION NOT NULL DEFAULT 0,
        egress_bytes BIGINT NOT NULL DEFAULT 0,
        PRIMARY KEY (tenant, hour, sandbox)
    );
    CREATE INDEX usage_hour ON usage_hourly (hour);
    CREATE TABLE nodes (
        id TEXT COLLATE "C" PRIMARY KEY,
        url TEXT COLLATE "C" NOT NULL,
        state TEXT COLLATE "C" NOT NULL,
        boot TEXT COLLATE "C",
        seq BIGINT NOT NULL DEFAULT 0,
        report TEXT COLLATE "C",
        last_seen BIGINT,
        created_at BIGINT NOT NULL,
        removed_at BIGINT,
        draining BIGINT NOT NULL DEFAULT 0,
        kind TEXT COLLATE "C" NOT NULL DEFAULT 'worker'
    );
    CREATE TABLE join_tokens (
        hash BYTEA PRIMARY KEY,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        node TEXT COLLATE "C"
    );
    CREATE TABLE node_usage (
        node TEXT COLLATE "C" NOT NULL,
        tenant TEXT COLLATE "C" NOT NULL,
        hour BIGINT NOT NULL,
        sandbox TEXT COLLATE "C" NOT NULL,
        vcpu_s DOUBLE PRECISION NOT NULL DEFAULT 0,
        mem_gib_s DOUBLE PRECISION NOT NULL DEFAULT 0,
        disk_gib_h DOUBLE PRECISION NOT NULL DEFAULT 0,
        egress_bytes BIGINT NOT NULL DEFAULT 0,
        PRIMARY KEY (node, tenant, hour, sandbox)
    );
    CREATE TABLE volumes (
        id TEXT COLLATE "C" PRIMARY KEY,
        tenant TEXT COLLATE "C" NOT NULL,
        name TEXT COLLATE "C" NOT NULL,
        size_gib BIGINT NOT NULL,
        node TEXT COLLATE "C",
        backend TEXT COLLATE "C",
        created_at BIGINT NOT NULL,
        deleted_at BIGINT
    );
    CREATE UNIQUE INDEX volumes_name ON volumes (tenant, name) WHERE deleted_at IS NULL;
    CREATE TABLE scale_requests (
        id TEXT COLLATE "C" PRIMARY KEY,
        action TEXT COLLATE "C" NOT NULL,
        token_hash BYTEA,
        node TEXT COLLATE "C",
        reason TEXT COLLATE "C" NOT NULL,
        created_at BIGINT NOT NULL,
        expires_at BIGINT,
        ended_at BIGINT,
        outcome TEXT COLLATE "C"
    );
    CREATE INDEX scale_requests_open ON scale_requests (ended_at);
    CREATE TABLE leader (
        id INTEGER PRIMARY KEY,
        holder TEXT NOT NULL,
        term BIGINT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE shared_files (
        name TEXT PRIMARY KEY,
        data BYTEA NOT NULL,
        updated_at BIGINT NOT NULL
    );"#,
    r#"
    ALTER TABLE scale_requests ADD COLUMN token_sealed BYTEA;
    CREATE TABLE retirements (
        node TEXT COLLATE "C" PRIMARY KEY,
        id TEXT COLLATE "C" NOT NULL,
        origin TEXT COLLATE "C" NOT NULL,
        migrate BIGINT NOT NULL,
        reason TEXT COLLATE "C" NOT NULL,
        state TEXT COLLATE "C" NOT NULL,
        created_at BIGINT NOT NULL,
        ready_at BIGINT,
        ended_at BIGINT,
        failed_moves BIGINT NOT NULL DEFAULT 0
    );"#,
    r#"
    ALTER TABLE sandboxes ADD COLUMN persistent BIGINT NOT NULL DEFAULT 0;
    ALTER TABLE sandboxes ADD COLUMN generation BIGINT NOT NULL DEFAULT 0;
    ALTER TABLE sandboxes ADD COLUMN cold_starts BIGINT NOT NULL DEFAULT 0;
    ALTER TABLE sandboxes ADD COLUMN last_cold_start_at BIGINT;
    ALTER TABLE sandboxes ADD COLUMN claim TEXT COLLATE "C";
    ALTER TABLE sandboxes ADD COLUMN claim_deadline BIGINT;
    CREATE TABLE start_records (
        sandbox TEXT COLLATE "C" PRIMARY KEY,
        tenant TEXT COLLATE "C" NOT NULL,
        template TEXT COLLATE "C" NOT NULL,
        build TEXT COLLATE "C" NOT NULL,
        spec TEXT NOT NULL,
        vcpus BIGINT NOT NULL,
        memory_mib BIGINT NOT NULL,
        egress TEXT NOT NULL,
        secrets TEXT NOT NULL,
        volumes TEXT NOT NULL,
        ports TEXT NOT NULL,
        idle_pause_s BIGINT NOT NULL,
        env BYTEA NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    );
    CREATE INDEX start_records_build ON start_records (build);"#,
    "ALTER TABLE start_records ADD COLUMN services BYTEA NOT NULL DEFAULT '';",
    // As in SQLite. Earlier versions also write their own, lower schema
    // version at start; the trigger turns that into an error.
    r#"
    ALTER TABLE sandboxes RENAME COLUMN saved TO saved_state;
    CREATE TABLE upkeep (task TEXT COLLATE "C" PRIMARY KEY);
    CREATE FUNCTION refuse_older_schema_version() RETURNS trigger AS $$
    BEGIN
        IF NEW.version < 5 THEN
            RAISE EXCEPTION 'this database was upgraded by a newer spawnbox; downgrades are not supported';
        END IF;
        RETURN NEW;
    END
    $$ LANGUAGE plpgsql;
    CREATE TRIGGER schema_version_floor BEFORE INSERT OR UPDATE ON schema_version
        FOR EACH ROW EXECUTE FUNCTION refuse_older_schema_version();"#,
    r#"
    ALTER TABLE nodes ADD COLUMN fenced_at BIGINT;
    ALTER TABLE nodes ADD COLUMN fenced_by TEXT COLLATE "C";"#,
    r#"
    ALTER TABLE builds ADD COLUMN guest TEXT COLLATE "C";
    ALTER TABLE builds ADD COLUMN root BIGINT NOT NULL DEFAULT 0;"#,
    r#"
    CREATE TABLE endpoints (
        tenant TEXT COLLATE "C" NOT NULL,
        name TEXT COLLATE "C" NOT NULL,
        sandbox TEXT COLLATE "C" NOT NULL,
        port BIGINT NOT NULL,
        generation BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (tenant, name)
    );"#,
];

pub mod state {
    pub const STARTING: &str = "starting";
    pub const RUNNING: &str = "running";
    pub const PAUSED: &str = "paused";
    pub const FAILED: &str = "failed";
    pub const DELETED: &str = "deleted";
    /// A persistent sandbox with no VM and no snapshot. The next call
    /// starts it again from its start record.
    pub const COLD: &str = "cold";
    pub const ALL: [&str; 6] = [STARTING, RUNNING, PAUSED, FAILED, DELETED, COLD];
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
    /// Its guest's protocol version, `major.minor`, if known.
    pub guest: Option<String>,
    /// Built again for persistent sandboxes whose own build was gone. It
    /// is never its template's current build.
    pub root: bool,
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

/// A stable name for one sandbox port. `generation` grows by 1 at each
/// switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub tenant: String,
    pub name: String,
    pub sandbox: String,
    pub port: u16,
    pub generation: i64,
    pub created_at: i64,
    pub updated_at: i64,
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
    #[serde(default)]
    pub persistent: bool,
    /// Bumped by each cold start. Updates from an older VM are ignored.
    #[serde(default)]
    pub generation: i64,
    #[serde(default)]
    pub cold_starts: i64,
    #[serde(default)]
    pub last_cold_start_at: Option<i64>,
}

/// What starting a persistent sandbox again needs, kept until it ends.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StartRecord {
    pub sandbox: String,
    pub tenant: String,
    pub template: String,
    pub build: String,
    /// JSON of the build's `model::TemplateSpec`.
    pub spec: String,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub egress: Policy,
    /// Names only.
    pub secrets: Vec<String>,
    pub volumes: Vec<VolumeRef>,
    /// JSON of the published ports.
    pub ports: String,
    pub idle_pause_s: u64,
    /// The sandbox's own env and its services, sealed with
    /// `SecretBox::seal_sandbox_env`.
    pub env: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// A start record's sealed env.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartEnv {
    pub sandbox: String,
    pub tenant: String,
    pub env: Vec<u8>,
    /// The services, as an earlier format sealed them apart from `env`.
    /// Empty in the current one.
    pub services: Vec<u8>,
}

/// Why a sandbox was not added.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The volume of this name is taken.
    Volume(String),
    /// The tenant has this many persistent sandboxes.
    Persistent(u64),
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

/// Refuses a database that a later version upgraded.
fn newer_than_binary(version: i64, known: usize) -> Result<()> {
    if version > i64::try_from(known).unwrap_or(i64::MAX) {
        return Err(Error::Connection(format!(
            "the database has schema version {version}, newer than this spawnbox knows \
             ({known}); downgrades are not supported"
        )));
    }
    Ok(())
}

fn same_as_binary(version: i64, known: usize) -> Result<()> {
    newer_than_binary(version, known)?;
    if version != i64::try_from(known).unwrap_or(i64::MAX) {
        return Err(Error::Connection(format!(
            "the database has schema version {version}, but this spawnbox writes version \
             {known}; start the matching spawn-api once to upgrade it, or check it with the \
             binary that wrote it"
        )));
    }
    Ok(())
}

/// One connection behind a lock. Queries are small, so they run directly
/// on the async threads. One connection also keeps check-then-write steps
/// whole, as only one primary writes at a time.
#[derive(Clone)]
pub struct Db(Arc<Mutex<Conn>>);

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        Self::init_sqlite(rusqlite::Connection::open(path)?)
    }

    /// Connects and brings the schema up to date. Primaries that share the
    /// database wait for each other's upgrades.
    pub fn open_postgres(target: PgTarget) -> Result<Self> {
        let mut conn = Conn::Postgres(sql::Pg::connect(target)?);
        let tx = conn.transaction()?;
        tx.execute_batch(
            "SELECT pg_advisory_xact_lock(736162);
             CREATE TABLE IF NOT EXISTS schema_version (version BIGINT NOT NULL);",
        )?;
        let version: Option<i64> = tx
            .query_row("SELECT version FROM schema_version", (), |r| r.get(0))
            .optional()?;
        let version = version.unwrap_or(0);
        newer_than_binary(version, PG_MIGRATIONS.len())?;
        for sql in PG_MIGRATIONS
            .iter()
            .skip(usize::try_from(version).unwrap_or(0))
        {
            tx.execute_batch(sql)?;
        }
        let latest = i64::try_from(PG_MIGRATIONS.len()).unwrap_or(i64::MAX);
        tx.execute("DELETE FROM schema_version", ())?;
        tx.execute("INSERT INTO schema_version (version) VALUES (?1)", [latest])?;
        tx.commit()?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    /// Opens an existing SQLite database read-only, without migrating it.
    /// Fails unless its schema is the version this binary writes.
    pub fn open_sqlite_read_only(path: &Path) -> Result<Self> {
        let conn = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        same_as_binary(version, MIGRATIONS.len())?;
        Ok(Self(Arc::new(Mutex::new(Conn::Sqlite(conn)))))
    }

    /// Connects in read-only transactions, without migrating or taking the
    /// upgrade lock. Fails unless the schema is the version this binary
    /// writes.
    pub fn open_postgres_read_only(target: PgTarget) -> Result<Self> {
        let mut conn = Conn::Postgres(sql::Pg::connect(target)?);
        conn.execute_batch("SET default_transaction_read_only = on")?;
        let tx = conn.transaction()?;
        let has_version: bool = tx.query_row(
            "SELECT to_regclass('schema_version') IS NOT NULL",
            (),
            |r| r.get(0),
        )?;
        let version: Option<i64> = if has_version {
            tx.query_row("SELECT version FROM schema_version", (), |r| r.get(0))
                .optional()?
        } else {
            None
        };
        tx.commit()?;
        same_as_binary(version.unwrap_or(0), PG_MIGRATIONS.len())?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    pub fn is_postgres(&self) -> bool {
        self.conn().is_postgres()
    }

    /// In memory, or in a fresh Postgres schema when
    /// `SPAWNBOX_TEST_DATABASE_URL` is set.
    #[cfg(test)]
    pub fn memory() -> Result<Self> {
        match std::env::var("SPAWNBOX_TEST_DATABASE_URL") {
            Ok(url) => Self::test_postgres(&url).map(|(db, _)| db),
            Err(_) => Self::init_sqlite(rusqlite::Connection::open_in_memory()?),
        }
    }

    /// A fresh schema, and how to reach it.
    #[cfg(test)]
    pub fn test_postgres(url: &str) -> Result<(Self, PgTarget)> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let target =
            |url: &str| PgTarget::new(url, None).map_err(|e| Error::Connection(e.to_string()));
        let schema = format!(
            "test_{}_{}_{}",
            std::process::id(),
            now_ms(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let admin = sql::Pg::connect(target(url)?)?;
        Conn::Postgres(admin).execute_batch(&format!("CREATE SCHEMA {schema}"))?;
        let sep = if url.contains('?') { '&' } else { '?' };
        let target = target(&format!("{url}{sep}options=-csearch_path%3D{schema}"))?;
        Ok((Self::open_postgres(target.clone())?, target))
    }

    fn init_sqlite(mut conn: rusqlite::Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", true)?;
        // Freed space is zeroed, so env that was rewritten sealed leaves no
        // plain copy behind.
        conn.pragma_update(None, "secure_delete", true)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        newer_than_binary(version, MIGRATIONS.len())?;
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
        Ok(Self(Arc::new(Mutex::new(Conn::Sqlite(conn)))))
    }

    fn conn(&self) -> MutexGuard<'_, Conn> {
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
    ) -> Result<Key> {
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
    pub fn find_key(&self, hash: &[u8]) -> Result<Option<Key>> {
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
    pub fn active_key(&self, id: &str) -> Result<Option<Key>> {
        self.conn()
            .query_row(
                &format!("SELECT {KEY_COLUMNS} FROM api_keys WHERE id = ?1 AND revoked_at IS NULL"),
                [id],
                key_from_row,
            )
            .optional()
    }

    /// Every key, revoked ones too, oldest first.
    pub fn list_keys(&self) -> Result<Vec<Key>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {KEY_COLUMNS} FROM api_keys ORDER BY created_at, id"
        ))?;
        stmt.query_map((), key_from_row)?.collect()
    }

    /// Returns false if no such key exists. Revoking twice keeps the first
    /// time.
    pub fn revoke_key(&self, id: &str, now: i64) -> Result<bool> {
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
    pub fn insert_tenant(&self, tenant: &Tenant) -> Result<bool> {
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

    pub fn update_tenant(&self, tenant: &Tenant) -> Result<bool> {
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

    pub fn get_tenant(&self, id: &str) -> Result<Option<Tenant>> {
        self.conn()
            .query_row(
                &format!("SELECT {TENANT_COLUMNS} FROM tenants WHERE id = ?1"),
                [id],
                tenant_from_row,
            )
            .optional()
    }

    pub fn list_tenants(&self) -> Result<Vec<Tenant>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare(&format!("SELECT {TENANT_COLUMNS} FROM tenants ORDER BY id"))?;
        stmt.query_map((), tenant_from_row)?.collect()
    }

    /// Deletes a tenant that owns nothing and revokes its keys. `Ok(None)`
    /// if it does not exist.
    pub fn delete_tenant(&self, id: &str, now: i64) -> Result<Option<Result<(), InUse>>> {
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
    pub fn insert_sandbox(&self, sandbox: &Sandbox) -> Result<Result<(), String>> {
        Ok(self
            .insert(sandbox, None)?
            .map_err(|refused| match refused {
                Refused::Volume(name) => name,
                Refused::Persistent(_) => unreachable!("only persistent sandboxes count"),
            }))
    }

    /// Adds a persistent sandbox and its start record at once, unless a
    /// volume is taken or its tenant already has `limit` of them.
    pub fn insert_persistent(
        &self,
        sandbox: &Sandbox,
        start: &StartRecord,
        limit: Option<u64>,
    ) -> Result<Result<(), Refused>> {
        self.insert(sandbox, Some((start, limit)))
    }

    fn insert(
        &self,
        sandbox: &Sandbox,
        start: Option<(&StartRecord, Option<u64>)>,
    ) -> Result<Result<(), Refused>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        for volume in &sandbox.volumes {
            if let Some(name) = volume_taken(&tx, volume, &sandbox.id)? {
                return Ok(Err(Refused::Volume(name)));
            }
        }
        if let Some((_, Some(limit))) = start {
            let in_use: i64 = tx.query_row(
                "SELECT count(*) FROM sandboxes
                 WHERE tenant = ?1 AND persistent = 1 AND state NOT IN ('deleted', 'failed')",
                [&sandbox.tenant],
                |r| r.get(0),
            )?;
            let in_use = u64::try_from(in_use).unwrap_or(0);
            if in_use >= limit {
                return Ok(Err(Refused::Persistent(in_use)));
            }
        }
        tx.execute(
            "INSERT INTO sandboxes
             (id, state, template, build, labels, created_at, expires_at, secrets, egress,
              idle_pause_s, tenant, node, vcpus, memory_mib, volumes, persistent, generation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
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
                i64::from(sandbox.persistent),
                sandbox.generation,
            ],
        )?;
        if let Some((start, _)) = start {
            tx.execute(
                "INSERT INTO start_records
                 (sandbox, tenant, template, build, spec, vcpus, memory_mib, egress, secrets,
                  volumes, ports, idle_pause_s, env, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    start.sandbox,
                    start.tenant,
                    start.template,
                    start.build,
                    start.spec,
                    start.vcpus,
                    start.memory_mib,
                    to_json(&start.egress),
                    to_json(&start.secrets),
                    to_json(&start.volumes),
                    start.ports,
                    i64::try_from(start.idle_pause_s).unwrap_or(i64::MAX),
                    start.env.clone(),
                    start.created_at,
                    start.updated_at,
                ],
            )?;
        }
        tx.commit()?;
        Ok(Ok(()))
    }

    pub fn get_start_record(&self, sandbox: &str) -> Result<Option<StartRecord>> {
        self.conn()
            .query_row(
                "SELECT sandbox, tenant, template, build, spec, vcpus, memory_mib, egress,
                        secrets, volumes, ports, idle_pause_s, env, created_at, updated_at
                 FROM start_records WHERE sandbox = ?1",
                [sandbox],
                |row| {
                    Ok(StartRecord {
                        sandbox: row.get(0)?,
                        tenant: row.get(1)?,
                        template: row.get(2)?,
                        build: row.get(3)?,
                        spec: row.get(4)?,
                        vcpus: row.get(5)?,
                        memory_mib: row.get(6)?,
                        egress: json_column(row, 7)?,
                        secrets: json_column(row, 8)?,
                        volumes: json_column(row, 9)?,
                        ports: row.get(10)?,
                        idle_pause_s: u64::try_from(row.get::<_, i64>(11)?).unwrap_or(0),
                        env: row.get(12)?,
                        created_at: row.get(13)?,
                        updated_at: row.get(14)?,
                    })
                },
            )
            .optional()
    }

    /// Every start record's sealed env.
    pub fn start_record_envs(&self) -> Result<Vec<StartEnv>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT sandbox, tenant, env, services FROM start_records ORDER BY sandbox")?;
        stmt.query_map((), |r| {
            Ok(StartEnv {
                sandbox: r.get(0)?,
                tenant: r.get(1)?,
                env: r.get(2)?,
                services: r.get(3)?,
            })
        })?
        .collect()
    }

    /// Replaces a start record's env if it still holds `old`. `false` if
    /// it changed or is gone.
    pub fn replace_start_env(
        &self,
        sandbox: &str,
        old: (&[u8], &[u8]),
        env: &[u8],
    ) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE start_records SET env = ?2, services = ?3
             WHERE sandbox = ?1 AND env = ?4 AND services = ?5",
            params![
                sandbox,
                env.to_vec(),
                Vec::<u8>::new(),
                old.0.to_vec(),
                old.1.to_vec()
            ],
        )?;
        Ok(changed > 0)
    }

    /// Writes the column an earlier format sealed the services in.
    #[cfg(test)]
    pub fn set_legacy_start_services(&self, sandbox: &str, services: &[u8]) -> Result<()> {
        self.conn().execute(
            "UPDATE start_records SET services = ?2 WHERE sandbox = ?1",
            params![sandbox, services.to_vec()],
        )?;
        Ok(())
    }

    /// Empties SQLite's write-ahead log, which may hold rows as they were
    /// before a rewrite. Postgres keeps old row versions until it vacuums.
    pub fn truncate_log(&self) -> Result<()> {
        let conn = self.conn();
        if !conn.is_postgres() {
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        }
        Ok(())
    }

    /// Rebuilds an SQLite file once after the upgrade that sealed env:
    /// pages that earlier versions freed may still hold it in plain.
    /// Whether it ran.
    pub fn vacuum_once(&self) -> Result<bool> {
        let conn = self.conn();
        if conn.is_postgres() {
            return Ok(false);
        }
        let due = conn
            .query_row("SELECT 1 FROM upkeep WHERE task = 'vacuum'", (), |_| Ok(()))
            .optional()?
            .is_some();
        if !due {
            return Ok(false);
        }
        conn.execute_batch("VACUUM")?;
        conn.execute("DELETE FROM upkeep WHERE task = 'vacuum'", ())?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(true)
    }

    /// The saved state of this host's sandboxes that have one, with their
    /// tenant.
    pub fn saved_states(&self) -> Result<Vec<(String, String, String)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, tenant, saved_state FROM sandboxes
             WHERE saved_state IS NOT NULL AND node IS NULL ORDER BY seq",
        )?;
        stmt.query_map((), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect()
    }

    /// Replaces a sandbox's saved state if it is still `old`.
    pub fn replace_saved(&self, id: &str, old: &str, saved: &str) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE sandboxes SET saved_state = ?2 WHERE id = ?1 AND saved_state = ?3 AND node IS NULL",
            params![id, saved, old],
        )?;
        Ok(changed > 0)
    }

    /// Records a persistent sandbox's published ports, for its next start.
    pub fn set_start_ports(&self, sandbox: &str, ports: &str, now: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE start_records SET ports = ?2, updated_at = ?3 WHERE sandbox = ?1",
            params![sandbox, ports, now],
        )?;
        Ok(())
    }

    /// Makes a persistent sandbox start from build `to` instead of `from`.
    /// False if its start record names another build by now.
    pub fn set_start_build(&self, sandbox: &str, from: &str, to: &str, now: i64) -> Result<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE start_records SET build = ?3, updated_at = ?4
             WHERE sandbox = ?1 AND build = ?2",
            params![sandbox, from, to, now],
        )?;
        if changed > 0 {
            tx.execute(
                "UPDATE sandboxes SET build = ?2 WHERE id = ?1",
                params![sandbox, to],
            )?;
        }
        tx.commit()?;
        Ok(changed > 0)
    }

    /// Builds that a persistent sandbox that has not ended starts from.
    pub fn build_roots(&self) -> Result<HashSet<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT r.build FROM start_records r JOIN sandboxes s ON s.id = r.sandbox
             WHERE s.state NOT IN ('deleted', 'failed')",
        )?;
        stmt.query_map((), |r| r.get(0))?.collect()
    }

    /// True while a start record of a live sandbox names build `id`.
    pub fn is_build_root(&self, id: &str) -> Result<bool> {
        self.conn()
            .prepare(
                "SELECT 1 FROM start_records r JOIN sandboxes s ON s.id = r.sandbox
                 WHERE r.build = ?1 AND s.state NOT IN ('deleted', 'failed') LIMIT 1",
            )?
            .exists([id])
    }

    /// Claims a cold sandbox of this host to start it on `node`, or here
    /// if `None`: it becomes `starting` with the next generation, which is
    /// returned. `None` if it is not cold.
    pub fn claim_cold(
        &self,
        id: &str,
        node: Option<&str>,
        claim: &str,
        deadline: i64,
    ) -> Result<Option<i64>> {
        self.conn()
            .query_row(
                "UPDATE sandboxes
                 SET state = 'starting', generation = generation + 1, claim = ?2,
                     claim_deadline = ?3, node = ?4
                 WHERE id = ?1 AND node IS NULL AND persistent = 1 AND state = 'cold'
                 RETURNING generation",
                params![id, claim, deadline, node],
                |r| r.get(0),
            )
            .optional()
    }

    /// Ends a claim with the sandbox running. `false` if the claim was
    /// lost: the sandbox was deleted, or the claim expired.
    pub fn finish_cold_start(
        &self,
        id: &str,
        node: Option<&str>,
        generation: i64,
        claim: &str,
        now: i64,
    ) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE sandboxes
             SET state = 'running', claim = NULL, claim_deadline = NULL,
                 cold_starts = cold_starts + 1, last_cold_start_at = ?4, paused_at = NULL,
                 saved_state = NULL
             WHERE id = ?1 AND generation = ?2 AND claim = ?3 AND state = 'starting'
               AND node IS NOT DISTINCT FROM ?5",
            params![id, generation, claim, now, node],
        )?;
        Ok(changed > 0)
    }

    /// Gives up a claim: the sandbox is cold again, and this host's.
    pub fn abandon_claim(
        &self,
        id: &str,
        node: Option<&str>,
        generation: i64,
        claim: &str,
    ) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE sandboxes SET state = 'cold', claim = NULL, claim_deadline = NULL, node = NULL
             WHERE id = ?1 AND generation = ?2 AND claim = ?3 AND state = 'starting'
               AND node IS NOT DISTINCT FROM ?4",
            params![id, generation, claim, node],
        )?;
        Ok(changed > 0)
    }

    /// Adds or replaces this host's copy of a persistent sandbox that the
    /// primary starts here, as cold at `sandbox.generation`.
    pub fn replace_persistent(&self, sandbox: &Sandbox, start: &StartRecord) -> Result<()> {
        {
            let conn = self.conn();
            conn.execute("DELETE FROM sandboxes WHERE id = ?1", [&sandbox.id])?;
            conn.execute(
                "DELETE FROM start_records WHERE sandbox = ?1",
                [&sandbox.id],
            )?;
        }
        self.insert(sandbox, Some((start, None)))?
            .map_err(|_| Error::Connection(format!("{}: a volume is taken", sandbox.id)))
    }

    /// Stops reporting this host's copy of a sandbox and drops its start
    /// record: the primary runs a newer copy, or none.
    pub fn drop_copy(&self, id: &str) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE sandboxes SET node = 'primary', saved_state = NULL
             WHERE id = ?1 AND node IS NULL",
            [id],
        )?;
        tx.execute("DELETE FROM start_records WHERE sandbox = ?1", [id])?;
        tx.commit()
    }

    /// Makes a persistent sandbox of this host cold, unless it ended or a
    /// newer VM runs it.
    pub fn set_cold(&self, id: &str, generation: i64) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE sandboxes
             SET state = 'cold', paused_at = NULL, saved_state = NULL, claim = NULL,
                 claim_deadline = NULL
             WHERE id = ?1 AND generation = ?2 AND persistent = 1 AND node IS NULL
               AND state NOT IN ('deleted', 'failed')",
            params![id, generation],
        )?;
        Ok(changed > 0)
    }

    /// Marks deleted a cold sandbox, or one being started again under a
    /// claim. A start that finishes later loses its claim. A first create
    /// is not deleted here.
    pub fn delete_cold(&self, id: &str, now: i64) -> Result<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE sandboxes
             SET state = 'deleted', ended_at = ?2, claim = NULL, claim_deadline = NULL
             WHERE id = ?1 AND node IS NULL AND persistent = 1
               AND (state = 'cold' OR (state = 'starting' AND claim IS NOT NULL))",
            params![id, now],
        )?;
        if changed > 0 {
            tx.execute("DELETE FROM start_records WHERE sandbox = ?1", [id])?;
        }
        tx.commit()?;
        Ok(changed > 0)
    }

    /// Makes cold the persistent sandboxes whose VMs were lost when the
    /// server stopped. Returns their IDs and tenants.
    pub fn cool_unfinished(&self) -> Result<Vec<(String, String)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "UPDATE sandboxes
             SET state = 'cold', claim = NULL, claim_deadline = NULL, paused_at = NULL,
                 saved_state = NULL
             WHERE state IN ('starting', 'running') AND persistent = 1 AND node IS NULL
             RETURNING id, tenant",
        )?;
        stmt.query_map((), |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect()
    }

    /// Persistent sandboxes this host's database says run, start or are
    /// paused here: after a failover, the old leader's. Returns their IDs,
    /// tenants and generations.
    pub fn unfinished_persistent(&self) -> Result<Vec<(String, String, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, tenant, generation FROM sandboxes
             WHERE state IN ('starting', 'running', 'paused') AND persistent = 1
               AND node IS NULL
             ORDER BY seq",
        )?;
        stmt.query_map((), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect()
    }

    /// Adds an endpoint. `false` if the tenant has one by that name.
    pub fn insert_endpoint(&self, endpoint: &Endpoint) -> Result<bool> {
        let added = self.conn().execute(
            "INSERT INTO endpoints
                 (tenant, name, sandbox, port, generation, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT DO NOTHING",
            params![
                endpoint.tenant,
                endpoint.name,
                endpoint.sandbox,
                i64::from(endpoint.port),
                endpoint.generation,
                endpoint.created_at,
                endpoint.updated_at,
            ],
        )?;
        Ok(added == 1)
    }

    pub fn get_endpoint(&self, tenant: &str, name: &str) -> Result<Option<Endpoint>> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT {ENDPOINT_COLUMNS} FROM endpoints WHERE tenant = ?1 AND name = ?2"
                ),
                [tenant, name],
                endpoint_from_row,
            )
            .optional()
    }

    /// One tenant's endpoints, or every tenant's, by name.
    pub fn list_endpoints(&self, tenant: Option<&str>) -> Result<Vec<Endpoint>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {ENDPOINT_COLUMNS} FROM endpoints
             WHERE CAST(?1 AS TEXT) IS NULL OR tenant = ?1
             ORDER BY tenant, name"
        ))?;
        stmt.query_map([tenant], endpoint_from_row)?.collect()
    }

    /// Points an endpoint at a new target, only if it is still at
    /// generation `expect`. Returns the endpoint after the switch, or
    /// `None` if another switch came first or it is gone.
    pub fn switch_endpoint(
        &self,
        tenant: &str,
        name: &str,
        sandbox: &str,
        port: u16,
        expect: i64,
        now: i64,
    ) -> Result<Option<Endpoint>> {
        let switched = self.conn().execute(
            "UPDATE endpoints SET sandbox = ?3, port = ?4, generation = generation + 1,
                 updated_at = ?6
             WHERE tenant = ?1 AND name = ?2 AND generation = ?5",
            params![tenant, name, sandbox, i64::from(port), expect, now],
        )?;
        if switched == 0 {
            return Ok(None);
        }
        self.get_endpoint(tenant, name)
    }

    /// Removes an endpoint. Returns whether there was one.
    pub fn delete_endpoint(&self, tenant: &str, name: &str) -> Result<bool> {
        let deleted = self.conn().execute(
            "DELETE FROM endpoints WHERE tenant = ?1 AND name = ?2",
            [tenant, name],
        )?;
        Ok(deleted == 1)
    }

    /// Adds a volume. `false` if the tenant has one by that name.
    pub fn insert_volume(&self, volume: &Volume) -> Result<bool> {
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
    pub fn put_volume(&self, volume: &Volume) -> Result<()> {
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

    pub fn get_volume(&self, tenant: &str, name: &str) -> Result<Option<Volume>> {
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

    pub fn get_volume_by_id(&self, id: &str) -> Result<Option<Volume>> {
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
    pub fn list_volumes(&self, tenant: Option<&str>) -> Result<Vec<Volume>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {VOLUME_COLUMNS} FROM volumes
             WHERE deleted_at IS NULL AND (CAST(?1 AS TEXT) IS NULL OR tenant = ?1)
             ORDER BY tenant, name"
        ))?;
        stmt.query_map([tenant], volume_from_row)?.collect()
    }

    /// Records where a volume's file is. `node` `None`: this host.
    pub fn set_volume_home(&self, id: &str, node: Option<&str>, backend: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE volumes SET node = ?2, backend = ?3 WHERE id = ?1 AND deleted_at IS NULL",
            params![id, node, backend],
        )?;
        Ok(())
    }

    /// Marks a volume deleted unless a sandbox that has not ended uses it.
    /// `Ok(Err(users))` if one does.
    pub fn delete_volume(&self, id: &str, now: i64) -> Result<Result<(), Vec<VolumeUser>>> {
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

    pub fn volume_users(&self, id: &str) -> Result<Vec<VolumeUser>> {
        volume_users(&self.conn(), id, "")
    }

    /// The sandboxes that may have volume `id` open now: its users that are
    /// not cold. A cold sandbox mounts its volumes only when it starts, and
    /// a start takes the fleet's volume lock, so its volumes can move.
    pub fn volume_holders(&self, id: &str) -> Result<Vec<VolumeUser>> {
        let conn = self.conn();
        let cold: HashSet<String> = conn
            .query_all(
                "SELECT id FROM sandboxes WHERE volumes LIKE '%' || ?1 || '%' AND state = 'cold'",
                [id],
            )?
            .iter()
            .map(|row| row.get(0))
            .collect::<Result<_>>()?;
        let mut users = volume_users(&conn, id, "")?;
        users.retain(|u| !cold.contains(&u.sandbox));
        Ok(users)
    }

    /// GiB of `tenant`'s volumes.
    pub fn volume_gib(&self, tenant: &str) -> Result<u64> {
        self.conn().query_row(
            "SELECT COALESCE(SUM(size_gib), 0) FROM volumes
             WHERE tenant = ?1 AND deleted_at IS NULL",
            [tenant],
            |row| row.get::<_, i64>(0).map(|n| n.unsigned_abs()),
        )
    }

    /// Volumes, deleted or not, that existed after `since`: for metering.
    pub fn volumes_since(&self, since: i64) -> Result<Vec<(Volume, Option<i64>)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {VOLUME_COLUMNS}, deleted_at FROM volumes
             WHERE deleted_at IS NULL OR deleted_at > ?1"
        ))?;
        stmt.query_map([since], |row| Ok((volume_from_row(row)?, row.get(7)?)))?
            .collect()
    }

    /// Records a pause, with what resuming needs.
    /// Updates of a sandbox's state take the generation of the VM they are
    /// about, and do nothing once a newer VM runs it.
    pub fn set_paused(&self, id: &str, generation: i64, paused_at: i64, saved: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE sandboxes SET state = 'paused', paused_at = ?2, saved_state = ?3
             WHERE id = ?1 AND generation = ?4 AND node IS NULL",
            params![id, paused_at, saved, generation],
        )?;
        Ok(())
    }

    /// Updates what a paused sandbox needs to resume.
    pub fn set_saved(&self, id: &str, generation: i64, saved: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE sandboxes SET saved_state = ?2 WHERE id = ?1 AND generation = ?3 AND node IS NULL",
            params![id, saved, generation],
        )?;
        Ok(())
    }

    pub fn set_resumed(&self, id: &str, generation: i64, expires_at: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE sandboxes
             SET state = 'running', expires_at = ?2, paused_at = NULL, saved_state = NULL
             WHERE id = ?1 AND generation = ?3 AND node IS NULL",
            params![id, expires_at, generation],
        )?;
        Ok(())
    }

    /// Paused sandboxes with what resuming needs.
    pub fn paused_sandboxes(&self) -> Result<Vec<(Sandbox, Option<String>)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {SANDBOX_COLUMNS}, saved_state FROM sandboxes
             WHERE state = 'paused' AND node IS NULL ORDER BY seq"
        ))?;
        stmt.query_map((), |row| {
            Ok((sandbox_from_row(row)?, row.get(SANDBOX_COLUMN_COUNT)?))
        })?
        .collect()
    }

    /// Moves a sandbox of this host to `state`. `failed` and `deleted`
    /// record the time and drop its start record. `generation` as for
    /// `set_paused`.
    /// Ends a create: `starting` becomes `running`. `false` if the row
    /// left `starting`, as after a delete.
    pub fn start_running(&self, id: &str, generation: i64) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE sandboxes SET state = 'running'
             WHERE id = ?1 AND generation = ?2 AND node IS NULL AND state = 'starting'",
            params![id, generation],
        )?;
        Ok(changed > 0)
    }

    pub fn set_state(&self, id: &str, generation: i64, state: &str, now: i64) -> Result<()> {
        let ended = matches!(state, state::FAILED | state::DELETED).then_some(now);
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE sandboxes SET state = ?2, ended_at = COALESCE(?3, ended_at)
             WHERE id = ?1 AND generation = ?4 AND node IS NULL",
            params![id, state, ended, generation],
        )?;
        if changed > 0 && ended.is_some() {
            tx.execute("DELETE FROM start_records WHERE sandbox = ?1", [id])?;
        }
        tx.commit()
    }

    pub fn get_sandbox(&self, id: &str) -> Result<Option<Sandbox>> {
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
    ) -> Result<(Vec<Sandbox>, Option<i64>)> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {SANDBOX_COLUMNS}, seq
             FROM sandboxes
             WHERE seq > ?1 AND (CAST(?2 AS TEXT) IS NULL AND state != 'deleted' OR state = ?2)
               AND (CAST(?4 AS TEXT) IS NULL OR tenant = ?4)
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
    pub fn delete_unfinished(&self, now: i64) -> Result<Vec<(String, String)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "UPDATE sandboxes SET state = 'deleted', ended_at = ?1
             WHERE state IN ('starting', 'running') AND persistent = 0 AND node IS NULL
             RETURNING id, tenant",
        )?;
        stmt.query_map([now], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect()
    }

    /// Creates or replaces a template. Returns whether it is new.
    pub fn put_template(&self, name: &str, spec: &str, now: i64) -> Result<bool> {
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

    pub fn get_template(&self, name: &str) -> Result<Option<Template>> {
        self.conn()
            .query_row(
                "SELECT name, spec, created_at, updated_at FROM templates WHERE name = ?1",
                [name],
                template_from_row,
            )
            .optional()
    }

    pub fn list_templates(&self) -> Result<Vec<Template>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT name, spec, created_at, updated_at FROM templates ORDER BY name")?;
        stmt.query_map((), template_from_row)?.collect()
    }

    /// How many sandboxes each (tenant, template name) created since `since`.
    pub fn template_uses(&self, since: i64) -> Result<Vec<(String, String, u64)>> {
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
    pub fn delete_template(&self, name: &str, now: i64) -> Result<bool> {
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
    ) -> Result<Build> {
        self.insert_build_as(id, template, spec, fingerprint, now, false)
    }

    /// Like `insert_build`; a `root` build is made for persistent
    /// sandboxes only.
    pub fn insert_build_as(
        &self,
        id: &str,
        template: &str,
        spec: &str,
        fingerprint: &str,
        now: i64,
        root: bool,
    ) -> Result<Build> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO builds (id, template, spec, fingerprint, state, created_at, root)
             VALUES (?1, ?2, ?3, ?4, 'queued', ?5, ?6)",
            params![id, template, spec, fingerprint, now, i64::from(root)],
        )?;
        conn.query_row(
            &format!("SELECT {BUILD_COLUMNS} FROM builds WHERE id = ?1"),
            [id],
            build_from_row,
        )
    }

    pub fn get_build(&self, id: &str) -> Result<Option<Build>> {
        self.conn()
            .query_row(
                &format!("SELECT {BUILD_COLUMNS} FROM builds WHERE id = ?1"),
                [id],
                build_from_row,
            )
            .optional()
    }

    pub fn latest_build(&self, template: &str) -> Result<Option<Build>> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT {BUILD_COLUMNS} FROM builds WHERE template = ?1 AND root = 0
                     ORDER BY seq DESC LIMIT 1"
                ),
                [template],
                build_from_row,
            )
            .optional()
    }

    /// Builds in any of `states`, oldest first.
    pub fn builds_in(&self, states: &[&str]) -> Result<Vec<Build>> {
        if states.is_empty() {
            return Ok(Vec::new());
        }
        let marks = vec!["?"; states.len()].join(", ");
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {BUILD_COLUMNS} FROM builds WHERE state IN ({marks}) ORDER BY seq"
        ))?;
        stmt.query_map(
            params_from_iter(states.iter().map(|s| Value::Text((*s).to_owned()))),
            build_from_row,
        )?
        .collect()
    }

    /// Moves a build to `state`. `building` records the start, and every
    /// later state the end.
    pub fn set_build_state(
        &self,
        id: &str,
        state: &str,
        now: i64,
        error: Option<&str>,
    ) -> Result<()> {
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
    ) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE builds SET state = 'building', started_at = ?3, fingerprint = ?2,
                 store_key = ?4
             WHERE id = ?1 AND state = 'queued'",
            params![id, fingerprint, now, store_key],
        )?;
        Ok(changed == 1)
    }

    pub fn set_build_guest(&self, id: &str, guest: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE builds SET guest = ?2 WHERE id = ?1",
            params![id, guest],
        )?;
        Ok(())
    }

    pub fn set_build_uploaded(&self, id: &str, now: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE builds SET uploaded_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        Ok(())
    }

    /// Marks a build failed unless it already finished.
    pub fn fail_build(&self, id: &str, now: i64, error: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE builds SET state = 'failed', finished_at = ?2, error = ?3
             WHERE id = ?1 AND state IN ('queued', 'building')",
            params![id, now, error],
        )?;
        Ok(())
    }

    pub fn requeue_unfinished_builds(&self) -> Result<usize> {
        self.conn().execute(
            "UPDATE builds SET state = 'queued', started_at = NULL WHERE state = 'building'",
            (),
        )
    }
}

impl Db {
    /// Adds a secret at version 1. Returns false if the name is taken.
    pub fn insert_secret(&self, name: &str, spec: &str, value: &[u8], now: i64) -> Result<bool> {
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
    ) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE secrets SET spec = ?3, value = ?4, version = version + 1, updated_at = ?5
             WHERE name = ?1 AND version = ?2",
            params![name, version, spec, value, now],
        )?;
        Ok(changed > 0)
    }

    pub fn get_secret(&self, name: &str) -> Result<Option<Secret>> {
        self.conn()
            .query_row(
                &format!("SELECT {SECRET_COLUMNS} FROM secrets WHERE name = ?1"),
                [name],
                secret_from_row,
            )
            .optional()
    }

    pub fn list_secrets(&self) -> Result<Vec<Secret>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {SECRET_COLUMNS} FROM secrets ORDER BY name"
        ))?;
        stmt.query_map((), secret_from_row)?.collect()
    }

    /// Writes a secret exactly as the primary has it.
    pub fn put_secret_copy(&self, secret: &Secret) -> Result<()> {
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
    pub fn delete_secret(&self, name: &str) -> Result<bool> {
        Ok(self
            .conn()
            .execute("DELETE FROM secrets WHERE name = ?1", [name])?
            > 0)
    }
}

/// Events.
impl Db {
    /// Stores events in one transaction. Returns their IDs in order.
    pub fn insert_events(&self, events: &[NewEvent]) -> Result<Vec<i64>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let mut ids = Vec::with_capacity(events.len());
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO events (ts, tenant, sandbox, step_id, trace_id, actor, type, attrs)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) RETURNING id",
            )?;
            for event in events {
                let mut rows = stmt.query(params![
                    event.ts,
                    event.tenant,
                    event.sandbox,
                    event.step_id,
                    event.trace.as_ref().map(|t| &t.trace_id),
                    event.actor,
                    event.kind,
                    to_json(&event.attrs),
                ])?;
                let row = rows.next()?.ok_or(Error::NoRows)?;
                ids.push(row.get(0)?);
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
    ) -> Result<(Vec<Event>, bool)> {
        let mut sql = format!("SELECT {EVENT_COLUMNS} FROM events WHERE id > ?");
        let mut args: Vec<Value> = vec![after.into()];
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
            .query_map(params_from_iter(args), event_from_row)?
            .collect::<Result<_>>()?;
        let more = events.len() > limit;
        events.truncate(limit);
        Ok((events, more))
    }

    /// The newest event's ID, or 0.
    pub fn latest_event_id(&self) -> Result<i64> {
        self.conn()
            .query_row("SELECT COALESCE(MAX(id), 0) FROM events", (), |r| r.get(0))
    }

    /// Deletes up to `batch` events older than `before`. Returns how many.
    pub fn prune_events(&self, before: i64, batch: usize) -> Result<usize> {
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
    pub fn add_usage(&self, rows: &HashMap<UsageKey, Totals>) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO usage_hourly
                 (tenant, hour, sandbox, vcpu_s, mem_gib_s, disk_gib_h, egress_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (tenant, hour, sandbox) DO UPDATE SET
                 vcpu_s = usage_hourly.vcpu_s + excluded.vcpu_s,
                 mem_gib_s = usage_hourly.mem_gib_s + excluded.mem_gib_s,
                 disk_gib_h = usage_hourly.disk_gib_h + excluded.disk_gib_h,
                 egress_bytes = usage_hourly.egress_bytes + excluded.egress_bytes",
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
    ) -> Result<Vec<UsageRow>> {
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
             ) AS u
             WHERE hour >= ?1 AND hour < ?2 AND (CAST(?3 AS TEXT) IS NULL OR tenant = ?3)
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
    pub fn egress_since(&self, tenant: &str, since: i64) -> Result<u64> {
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

/// A worker the autoscaler asked for, or is removing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScaleRequest {
    pub id: String,
    /// `scale_up` or `scale_down`.
    pub action: String,
    /// For a scale-up, the worker that joined with its token.
    pub node: Option<String>,
    pub reason: String,
    pub created_at: i64,
    /// When a scale-up's join token expires.
    pub expires_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub outcome: Option<String>,
}

/// A worker being emptied so that its machine can be stopped. At most one
/// per node; it cannot be undone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retirement {
    pub node: String,
    pub id: String,
    /// `retire_origin::API` or `retire_origin::AUTOSCALER`.
    pub origin: String,
    /// Move its sandboxes away, not wait for them to end.
    pub migrate: bool,
    pub reason: String,
    /// One of `retire_state`.
    pub state: String,
    pub created_at: i64,
    pub ready_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub failed_moves: i64,
}

pub mod retire_origin {
    pub const API: &str = "api";
    pub const AUTOSCALER: &str = "autoscaler";
}

pub mod retire_state {
    pub const DRAINING: &str = "draining";
    /// A full pass to move its sandboxes or volumes left some behind.
    pub const BLOCKED: &str = "blocked";
    /// Empty: its machine can be stopped.
    pub const READY: &str = "ready_to_terminate";
    pub const REMOVED: &str = "removed";
}

const RETIREMENT_COLUMNS: &str =
    "node, id, origin, migrate, reason, state, created_at, ready_at, ended_at, failed_moves";

fn retirement_from_row(row: &Row) -> Result<Retirement> {
    Ok(Retirement {
        node: row.get(0)?,
        id: row.get(1)?,
        origin: row.get(2)?,
        migrate: row.get(3)?,
        reason: row.get(4)?,
        state: row.get(5)?,
        created_at: row.get(6)?,
        ready_at: row.get(7)?,
        ended_at: row.get(8)?,
        failed_moves: row.get(9)?,
    })
}

/// Whether a node's copy of a persistent sandbox, at `generation`, must be
/// destroyed, given the primary's row: its node, state and generation.
pub fn is_stale(row: Option<&(Option<String>, String, i64)>, node: &str, generation: i64) -> bool {
    let Some((owner, state, current)) = row else {
        return true;
    };
    if owner.as_deref() != Some(node) || matches!(state.as_str(), state::DELETED | state::FAILED) {
        return true;
    }
    // A start here at a newer generation is under way; the old copy is
    // what it replaces.
    generation > *current || (generation < *current && state != state::STARTING)
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

fn node_from_row(row: &Row) -> Result<NodeRow> {
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
    pub fn insert_join_token(&self, hash: &[u8], now: i64, expires_at: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM join_tokens WHERE expires_at < ?1", [now])?;
        conn.execute(
            "INSERT INTO join_tokens (hash, created_at, expires_at) VALUES (?1, ?2, ?3)",
            params![hash, now, expires_at],
        )?;
        Ok(())
    }

    /// Saves a scale-up request and the join token its new worker uses.
    pub fn insert_scale_up(
        &self,
        id: &str,
        token_hash: &[u8],
        token_sealed: &[u8],
        reason: &str,
        now: i64,
        expires_at: i64,
    ) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM join_tokens WHERE expires_at < ?1", [now])?;
        tx.execute(
            "INSERT INTO join_tokens (hash, created_at, expires_at) VALUES (?1, ?2, ?3)",
            params![token_hash, now, expires_at],
        )?;
        tx.execute(
            "INSERT INTO scale_requests
                 (id, action, token_hash, token_sealed, reason, created_at, expires_at)
             VALUES (?1, 'scale_up', ?2, ?3, ?4, ?5, ?6)",
            params![id, token_hash, token_sealed, reason, now, expires_at],
        )?;
        tx.commit()
    }

    pub fn insert_scale_down(&self, id: &str, node: &str, reason: &str, now: i64) -> Result<()> {
        self.conn().execute(
            "INSERT INTO scale_requests (id, action, node, reason, created_at)
             VALUES (?1, 'scale_down', ?2, ?3, ?4)",
            params![id, node, reason, now],
        )?;
        Ok(())
    }

    /// Scale requests, newest first: only those not ended, or the last
    /// `limit` of all.
    pub fn scale_requests(&self, open: bool, limit: u32) -> Result<Vec<ScaleRequest>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT r.id, r.action, COALESCE(r.node, t.node), r.reason, r.created_at,
                    r.expires_at, r.ended_at, r.outcome
             FROM scale_requests r LEFT JOIN join_tokens t ON t.hash = r.token_hash
             WHERE ?1 = 0 OR r.ended_at IS NULL
             ORDER BY r.created_at DESC, r.id LIMIT ?2",
        )?;
        stmt.query_map(params![open, limit], |r| {
            Ok(ScaleRequest {
                id: r.get(0)?,
                action: r.get(1)?,
                node: r.get(2)?,
                reason: r.get(3)?,
                created_at: r.get(4)?,
                expires_at: r.get(5)?,
                ended_at: r.get(6)?,
                outcome: r.get(7)?,
            })
        })?
        .collect()
    }

    /// The sealed join token of scale-up `id`.
    pub fn scale_up_token(&self, id: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT token_sealed FROM scale_requests WHERE id = ?1",
                [id],
                |r| r.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten())
    }

    /// The scale-up that `node` joined for, if any.
    pub fn scale_up_of(&self, node: &str) -> Result<Option<String>> {
        self.conn()
            .query_row(
                "SELECT r.id FROM scale_requests r
                 LEFT JOIN join_tokens t ON t.hash = r.token_hash
                 WHERE r.action = 'scale_up' AND COALESCE(r.node, t.node) = ?1",
                [node],
                |r| r.get(0),
            )
            .optional()
    }

    /// Ends a scale request. `node` records the worker a scale-up got.
    pub fn end_scale_request(
        &self,
        id: &str,
        node: Option<&str>,
        outcome: &str,
        now: i64,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE scale_requests SET node = COALESCE(?2, node), outcome = ?3, ended_at = ?4
             WHERE id = ?1 AND ended_at IS NULL",
            params![id, node, outcome, now],
        )?;
        Ok(())
    }

    /// Uses up the join token and adds the node, in one transaction.
    /// Returns false if the token is unknown, used or expired.
    pub fn join_node(&self, token_hash: &[u8], node: &NodeRow) -> Result<bool> {
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

    pub fn get_node(&self, id: &str) -> Result<Option<NodeRow>> {
        self.conn()
            .query_row(
                &format!("SELECT {NODE_COLUMNS} FROM nodes WHERE id = ?1"),
                [id],
                node_from_row,
            )
            .optional()
    }

    /// Every sandbox row, per state.
    pub fn count_sandboxes(&self) -> Result<Vec<(String, i64)>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT state, COUNT(*) FROM sandboxes GROUP BY state ORDER BY state")?;
        stmt.query_map((), |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect()
    }

    /// Nodes that are not removed, oldest first.
    /// Sandboxes on this host that have not ended, per state.
    pub fn count_local_sandboxes(&self) -> Result<Vec<(String, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT state, COUNT(*) FROM sandboxes
             WHERE node IS NULL AND state IN ('starting', 'running', 'paused', 'cold')
             GROUP BY state",
        )?;
        stmt.query_map((), |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect()
    }

    pub fn list_nodes(&self) -> Result<Vec<NodeRow>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {NODE_COLUMNS} FROM nodes WHERE state != 'removed' ORDER BY created_at, id"
        ))?;
        stmt.query_map((), node_from_row)?.collect()
    }

    /// Records a heartbeat. Returns false if the node is removed. The URL
    /// may change, as with a new IP address; fleet TLS still checks the
    /// node's name.
    pub fn node_seen(&self, seen: &NodeRow) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE nodes SET url = ?2, boot = ?3, seq = ?4, report = ?5, last_seen = ?6,
                 state = 'ready', fenced_at = NULL, fenced_by = NULL
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

    pub fn set_node_state(&self, id: &str, state: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE nodes SET state = ?2 WHERE id = ?1 AND state != 'removed'",
            params![id, state],
        )?;
        Ok(())
    }

    /// Returns false if no such node is active, or it is retiring and
    /// `draining` is false.
    pub fn set_node_draining(&self, id: &str, draining: bool) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE nodes SET draining = ?2 WHERE id = ?1 AND state != 'removed'
             AND (?2 = 1 OR NOT EXISTS
                 (SELECT 1 FROM retirements WHERE node = ?1 AND ended_at IS NULL))",
            params![id, draining],
        )?;
        Ok(changed > 0)
    }

    /// Starts retiring `r.node` and stops new sandboxes going there, in one
    /// transaction. If it is already retiring, returns that retirement
    /// instead. `None` if there is no such active worker.
    pub fn retire_node(&self, r: &Retirement) -> Result<Option<Retirement>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE nodes SET draining = 1
             WHERE id = ?1 AND state != 'removed' AND kind = 'worker'",
            [&r.node],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        tx.execute(
            &format!(
                "INSERT INTO retirements ({RETIREMENT_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT (node) DO NOTHING"
            ),
            params![
                r.node,
                r.id,
                r.origin,
                r.migrate,
                r.reason,
                r.state,
                r.created_at,
                r.ready_at,
                r.ended_at,
                r.failed_moves
            ],
        )?;
        let row = tx.query_row(
            &format!("SELECT {RETIREMENT_COLUMNS} FROM retirements WHERE node = ?1"),
            [&r.node],
            retirement_from_row,
        )?;
        tx.commit()?;
        Ok(Some(row))
    }

    /// Every retirement, or only those not ended.
    pub fn retirements(&self, open: bool) -> Result<Vec<Retirement>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {RETIREMENT_COLUMNS} FROM retirements
             WHERE ?1 = 0 OR ended_at IS NULL ORDER BY created_at, node"
        ))?;
        stmt.query_map([open], retirement_from_row)?.collect()
    }

    pub fn retirement(&self, node: &str) -> Result<Option<Retirement>> {
        self.conn()
            .query_row(
                &format!("SELECT {RETIREMENT_COLUMNS} FROM retirements WHERE node = ?1"),
                [node],
                retirement_from_row,
            )
            .optional()
    }

    /// Updates an open retirement. `ready_to_terminate` is never left.
    pub fn set_retirement(
        &self,
        node: &str,
        state: &str,
        failed_moves: i64,
        now: i64,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE retirements SET state = ?2, failed_moves = ?3,
                 ready_at = CASE WHEN ?2 = 'ready_to_terminate' THEN ?4 ELSE ready_at END
             WHERE node = ?1 AND ended_at IS NULL AND state != 'ready_to_terminate'",
            params![node, state, failed_moves, now],
        )?;
        Ok(())
    }

    fn end_retirement(conn: &Conn, node: &str, now: i64) -> Result<()> {
        conn.execute(
            "UPDATE retirements SET state = ?3, ended_at = ?2
             WHERE node = ?1 AND ended_at IS NULL",
            params![node, now, retire_state::REMOVED],
        )?;
        Ok(())
    }

    /// Returns false if no such node is active.
    /// Also ends its retirement.
    pub fn remove_node(&self, id: &str, now: i64) -> Result<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE nodes SET state = 'removed', removed_at = ?2
             WHERE id = ?1 AND state != 'removed'",
            params![id, now],
        )?;
        Self::end_retirement(&tx, id, now)?;
        tx.commit()?;
        Ok(changed > 0)
    }

    /// Ends the retirement of a node that is gone.
    pub fn end_retirement_of(&self, node: &str, now: i64) -> Result<()> {
        Self::end_retirement(&self.conn(), node, now)
    }

    /// Records an edge's routes call. Returns false if it is not an active
    /// edge.
    pub fn edge_seen(&self, id: &str, now: i64) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE nodes SET last_seen = ?2, state = 'ready'
             WHERE id = ?1 AND kind = 'edge' AND state != 'removed'",
            params![id, now],
        )?;
        Ok(changed > 0)
    }

    /// IDs of edges that are not removed.
    pub fn edge_ids(&self) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id FROM nodes WHERE kind = 'edge' AND state != 'removed' ORDER BY id",
        )?;
        stmt.query_map((), |r| r.get(0))?.collect()
    }

    /// Sandbox and worker of each sandbox that has not ended and runs on a
    /// worker that is not down or removed.
    pub fn edge_routes(&self) -> Result<Vec<(String, String)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT s.id, s.node FROM sandboxes s JOIN nodes n ON n.id = s.node
             WHERE (s.state IN ('running', 'paused') OR (s.state = 'starting' AND s.persistent = 0))
                 AND n.kind = 'worker' AND n.state IN ('ready', 'suspect')
             ORDER BY s.id",
        )?;
        stmt.query_map((), |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect()
    }

    /// Sandboxes of this host to report: all that have not ended, and those
    /// that ended since `ended_since`, so the primary learns how.
    pub fn local_report(&self, ended_since: i64) -> Result<Vec<Sandbox>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {SANDBOX_COLUMNS} FROM sandboxes
             WHERE node IS NULL AND (state NOT IN ('deleted', 'failed') OR ended_at >= ?1)
             ORDER BY seq"
        ))?;
        stmt.query_map([ended_since], sandbox_from_row)?.collect()
    }

    /// Writes what `node` reports about one of its sandboxes. A row that
    /// ended or that belongs to another host is never changed. A persistent
    /// one changes only for its current generation, and never out of
    /// `cold` or `starting`; reported cold, it is this host's again.
    /// Returns whether the row changed.
    pub fn put_mirror(&self, node: &str, sandbox: &Sandbox, now: i64) -> Result<bool> {
        let ended = matches!(sandbox.state.as_str(), state::FAILED | state::DELETED).then_some(now);
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "INSERT INTO sandboxes
             (id, state, template, build, labels, created_at, expires_at, secrets, egress,
              idle_pause_s, tenant, node, vcpus, memory_mib, paused_at, ended_at, volumes,
              generation, persistent)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                     ?18, ?19)
             ON CONFLICT (id) DO UPDATE SET
                 state = excluded.state, build = excluded.build, labels = excluded.labels,
                 generation = excluded.generation,
                 expires_at = excluded.expires_at, secrets = excluded.secrets,
                 volumes = excluded.volumes,
                 egress = excluded.egress, idle_pause_s = excluded.idle_pause_s,
                 vcpus = excluded.vcpus, memory_mib = excluded.memory_mib,
                 paused_at = excluded.paused_at,
                 ended_at = COALESCE(excluded.ended_at, sandboxes.ended_at),
                 node = CASE WHEN excluded.state = 'cold' THEN NULL ELSE sandboxes.node END
             WHERE sandboxes.node = excluded.node
               AND sandboxes.state NOT IN ('deleted', 'failed')
               AND (sandboxes.persistent = 0
                    OR (sandboxes.state NOT IN ('cold', 'starting')
                        AND sandboxes.generation = excluded.generation))",
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
                sandbox.generation,
                sandbox.persistent,
            ],
        )?;
        if changed > 0 && ended.is_some() && sandbox.persistent {
            tx.execute(
                "DELETE FROM start_records WHERE sandbox = ?1",
                [&sandbox.id],
            )?;
        }
        tx.commit()?;
        Ok(changed > 0)
    }

    /// Of the persistent sandboxes `node` reports with their generations,
    /// those whose copy there must be destroyed.
    pub fn stale_copies(&self, node: &str, reported: &[(&str, i64)]) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT node, state, generation FROM sandboxes WHERE id = ?1 AND persistent = 1",
        )?;
        let mut out = Vec::new();
        for (id, generation) in reported {
            let row: Option<(Option<String>, String, i64)> = stmt
                .query_map([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .next()
                .transpose()?;
            if is_stale(row.as_ref(), node, *generation) {
                out.push((*id).to_owned());
            }
        }
        Ok(out)
    }

    /// Makes cold the persistent sandboxes that `node` runs, is starting
    /// or has paused: their copies there are known to be gone. Returns
    /// their IDs and tenants.
    pub fn cool_node(&self, node: &str) -> Result<Vec<(String, String)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "UPDATE sandboxes
             SET state = 'cold', node = NULL, claim = NULL, claim_deadline = NULL,
                 paused_at = NULL, saved_state = NULL
             WHERE node = ?1 AND persistent = 1 AND state IN ('starting', 'running', 'paused')
             RETURNING id, tenant",
        )?;
        stmt.query_map([node], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect()
    }

    /// Makes cold persistent sandbox `id`, which `node` ran or had paused at
    /// `generation` and has stopped for a drain. `false` if the row changed
    /// since: then the node's reports decide.
    pub fn cool_on_node(&self, id: &str, node: &str, generation: i64) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE sandboxes
             SET state = 'cold', node = NULL, claim = NULL, claim_deadline = NULL,
                 paused_at = NULL, saved_state = NULL
             WHERE id = ?1 AND node = ?2 AND generation = ?3 AND persistent = 1
               AND state IN ('running', 'paused')",
            params![id, node, generation],
        )?;
        Ok(changed > 0)
    }

    /// How many live volumes each worker is the home of.
    pub fn node_volume_counts(&self) -> Result<HashMap<String, usize>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT node, count(*) FROM volumes
             WHERE node IS NOT NULL AND deleted_at IS NULL GROUP BY node",
        )?;
        stmt.query_map((), |r| {
            Ok((r.get(0)?, usize::try_from(r.get::<_, i64>(1)?).unwrap_or(0)))
        })?
        .collect()
    }

    /// Makes cold the persistent sandboxes that `node`, which reports all
    /// it runs, no longer has. Ones started there since `started_before`
    /// may not be in its report yet.
    pub fn cool_missing(
        &self,
        node: &str,
        keep: &std::collections::HashSet<String>,
        started_before: i64,
    ) -> Result<Vec<(String, String)>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let live: Vec<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, tenant FROM sandboxes
                 WHERE node = ?1 AND persistent = 1 AND state IN ('running', 'paused')
                   AND COALESCE(last_cold_start_at, created_at) < ?2",
            )?;
            stmt.query_map(params![node, started_before], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<Result<_>>()?
        };
        let gone: Vec<_> = live
            .into_iter()
            .filter(|(id, _)| !keep.contains(id))
            .collect();
        for (id, _) in &gone {
            tx.execute(
                "UPDATE sandboxes SET state = 'cold', node = NULL, paused_at = NULL
                 WHERE id = ?1 AND node = ?2",
                params![id, node],
            )?;
        }
        tx.commit()?;
        Ok(gone)
    }

    /// Ends claims to start a sandbox on `node` that ran out, from what it
    /// reports: `(id, generation, state)`. A copy at the claimed generation
    /// that runs or is paused keeps running; otherwise the sandbox is cold
    /// and this host's again. Returns those made cold.
    pub fn settle_claims(
        &self,
        node: &str,
        reported: &[(&str, i64, &str)],
        now: i64,
    ) -> Result<Vec<(String, String)>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let expired: Vec<(String, String, i64)> = {
            let mut stmt = tx.prepare(
                "SELECT id, tenant, generation FROM sandboxes
                 WHERE node = ?1 AND persistent = 1 AND state = 'starting'
                   AND claim_deadline < ?2",
            )?;
            stmt.query_map(params![node, now], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<Result<_>>()?
        };
        let mut cooled = Vec::new();
        for (id, tenant, generation) in expired {
            let runs = reported.iter().find_map(|(rid, rgen, rstate)| {
                (*rid == id
                    && *rgen == generation
                    && matches!(*rstate, state::RUNNING | state::PAUSED))
                .then_some(*rstate)
            });
            if let Some(runs) = runs {
                tx.execute(
                    "UPDATE sandboxes
                     SET state = ?3, claim = NULL, claim_deadline = NULL,
                         cold_starts = cold_starts + 1, last_cold_start_at = ?4
                     WHERE id = ?1 AND node = ?2 AND state = 'starting'",
                    params![id, node, runs, now],
                )?;
            } else {
                tx.execute(
                    "UPDATE sandboxes
                     SET state = 'cold', node = NULL, claim = NULL, claim_deadline = NULL
                     WHERE id = ?1 AND node = ?2 AND state = 'starting'",
                    params![id, node],
                )?;
                cooled.push((id, tenant));
            }
        }
        tx.commit()?;
        Ok(cooled)
    }

    /// Records that `node`, down or removed, is known to run nothing: by
    /// `by`, an operator or the autoscaler. `false` if it is not down or
    /// removed.
    pub fn set_node_fenced(&self, node: &str, by: &str, now: i64) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE nodes SET fenced_at = ?3, fenced_by = ?2
             WHERE id = ?1 AND state IN ('down', 'removed')",
            params![node, by, now],
        )?;
        Ok(changed > 0)
    }

    /// Down or removed workers that still hold persistent sandboxes, and
    /// who said each is fenced, if anyone did.
    pub fn unfenced_nodes(&self) -> Result<Vec<(NodeRow, Option<String>)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {NODE_COLUMNS}, fenced_by FROM nodes n
             WHERE n.state IN ('down', 'removed')
               AND EXISTS (SELECT 1 FROM sandboxes s
                           WHERE s.node = n.id AND s.persistent = 1
                             AND s.state IN ('starting', 'running', 'paused'))
             ORDER BY n.id"
        ))?;
        stmt.query_map((), |r| Ok((node_from_row(r)?, r.get(11)?)))?
            .collect()
    }

    /// Moves `node`'s sandbox to `state`, unless it has ended.
    pub fn set_mirror_state(&self, node: &str, id: &str, state: &str, now: i64) -> Result<()> {
        let ended = matches!(state, state::FAILED | state::DELETED).then_some(now);
        self.conn().execute(
            "UPDATE sandboxes SET state = ?3, ended_at = COALESCE(?4, ended_at)
             WHERE id = ?1 AND node = ?2 AND state NOT IN ('deleted', 'failed')",
            params![id, node, state, ended],
        )?;
        Ok(())
    }

    /// Marks deleted `node`'s sandboxes that have not ended, except those
    /// in `keep`, persistent ones and those created at or after
    /// `created_before`. Returns
    /// their IDs and tenants.
    pub fn end_mirrors(
        &self,
        node: &str,
        keep: &std::collections::HashSet<String>,
        created_before: i64,
        now: i64,
    ) -> Result<Vec<(String, String)>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let live: Vec<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, tenant FROM sandboxes
                 WHERE node = ?1 AND state NOT IN ('deleted', 'failed') AND created_at < ?2
                   AND persistent = 0",
            )?;
            stmt.query_map(params![node, created_before], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<Result<_>>()?
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
    pub fn node_sandbox_counts(&self) -> Result<HashMap<String, usize>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT node, count(*) FROM sandboxes
             WHERE node IS NOT NULL AND state NOT IN ('deleted', 'failed') GROUP BY node",
        )?;
        stmt.query_map((), |r| {
            Ok((r.get(0)?, usize::try_from(r.get::<_, i64>(1)?).unwrap_or(0)))
        })?
        .collect()
    }

    /// What `tenant`'s sandboxes that start or run on workers hold.
    pub fn mirror_usage(&self, tenant: &str) -> Result<Usage> {
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
    pub fn tenant_spread(&self, tenant: &str) -> Result<HashMap<Option<String>, u32>> {
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
    ) -> Result<Option<Option<String>>> {
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
              idle_pause_s, tenant, node, vcpus, memory_mib, paused_at, saved_state, volumes,
              generation)
             VALUES (?1, 'paused', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11, ?12, ?13, ?14,
                     ?15, ?16)
             ON CONFLICT (id) DO UPDATE SET
                 state = 'paused', build = excluded.build, labels = excluded.labels,
                 generation = excluded.generation,
                 expires_at = excluded.expires_at, secrets = excluded.secrets,
                 volumes = excluded.volumes,
                 egress = excluded.egress, idle_pause_s = excluded.idle_pause_s,
                 node = NULL, vcpus = excluded.vcpus, memory_mib = excluded.memory_mib,
                 paused_at = excluded.paused_at, saved_state = excluded.saved_state, ended_at = NULL",
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
                sandbox.generation,
            ],
        )?;
        tx.commit()?;
        Ok(prior)
    }

    /// Gives a row back after a `take_over` whose migration failed.
    pub fn undo_take_over(&self, id: &str, prior: Option<Option<String>>) -> Result<()> {
        let conn = self.conn();
        match prior {
            None => conn.execute("DELETE FROM sandboxes WHERE id = ?1 AND node IS NULL", [id])?,
            Some(node) => conn.execute(
                "UPDATE sandboxes SET node = ?2, saved_state = NULL WHERE id = ?1 AND node IS NULL",
                params![id, node],
            )?,
        };
        Ok(())
    }

    /// Marks a sandbox of this host as run by `node` now. On the primary
    /// this makes the row a mirror; on a worker it only stops reports.
    pub fn hand_off(&self, id: &str, node: &str) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE sandboxes SET node = ?2, saved_state = NULL WHERE id = ?1 AND node IS NULL",
            params![id, node],
        )?;
        Ok(changed > 0)
    }

    /// Points `from`'s copy of a sandbox at `to`.
    pub fn reassign(&self, id: &str, from: &str, to: &str) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE sandboxes SET node = ?3 WHERE id = ?1 AND node = ?2",
            params![id, from, to],
        )?;
        Ok(changed > 0)
    }

    /// Sandboxes that run or are paused on `node`.
    pub fn node_sandboxes(&self, node: &str) -> Result<Vec<Sandbox>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {SANDBOX_COLUMNS} FROM sandboxes
             WHERE node = ?1 AND state IN ('running', 'paused') ORDER BY seq"
        ))?;
        stmt.query_map([node], sandbox_from_row)?.collect()
    }

    /// Of `ids`, which `node` reports, those this primary knows on another
    /// host.
    pub fn misplaced(&self, node: &str, ids: &[&str]) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare_cached("SELECT 1 FROM sandboxes WHERE id = ?1 AND node IS DISTINCT FROM ?2")?;
        let mut out = Vec::new();
        for id in ids {
            if stmt.exists(params![id, node])? {
                out.push((*id).to_owned());
            }
        }
        Ok(out)
    }

    /// Every key with its hash, for workers.
    pub fn list_key_hashes(&self) -> Result<Vec<(Key, Vec<u8>)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {KEY_COLUMNS}, hash FROM api_keys ORDER BY created_at, id"
        ))?;
        stmt.query_map((), |r| Ok((key_from_row(r)?, r.get(6)?)))?
            .collect()
    }

    /// Makes tenants and keys exactly the given ones, in one transaction.
    pub fn replace_tenants_and_keys(
        &self,
        tenants: &[Tenant],
        keys: &[(Key, Vec<u8>)],
    ) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM api_keys", ())?;
        tx.execute("DELETE FROM tenants", ())?;
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
    pub fn insert_remote_events(&self, node: &str, events: &[Event]) -> Result<Vec<Event>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let mut stored = Vec::new();
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO events
                 (ts, tenant, sandbox, step_id, trace_id, actor, type, attrs, source_node,
                  source_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT DO NOTHING RETURNING id",
            )?;
            for event in events {
                let mut added = stmt.query(params![
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
                if let Some(row) = added.next()? {
                    stored.push(Event {
                        id: row.get(0)?,
                        ..event.clone()
                    });
                }
            }
        }
        tx.commit()?;
        Ok(stored)
    }

    /// The newest event ID of `node` stored here, or 0.
    pub fn remote_event_cursor(&self, node: &str) -> Result<i64> {
        self.conn().query_row(
            "SELECT COALESCE(MAX(source_id), 0) FROM events WHERE source_node = ?1",
            [node],
            |r| r.get(0),
        )
    }

    /// This host's hourly usage rows from hour `from` (Unix ms).
    pub fn usage_rows(&self, from: i64) -> Result<Vec<(UsageKey, Totals)>> {
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
    pub fn merge_node_usage(&self, node: &str, rows: &[(UsageKey, Totals)]) -> Result<()> {
        let mut conn = self.conn();
        let max = if conn.is_postgres() {
            "GREATEST"
        } else {
            "MAX"
        };
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(&format!(
                "INSERT INTO node_usage
                 (node, tenant, hour, sandbox, vcpu_s, mem_gib_s, disk_gib_h, egress_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT (node, tenant, hour, sandbox) DO UPDATE SET
                 vcpu_s = {max}(node_usage.vcpu_s, excluded.vcpu_s),
                 mem_gib_s = {max}(node_usage.mem_gib_s, excluded.mem_gib_s),
                 disk_gib_h = {max}(node_usage.disk_gib_h, excluded.disk_gib_h),
                 egress_bytes = {max}(node_usage.egress_bytes, excluded.egress_bytes)"
            ))?;
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

/// Tables `import_sqlite` copies, in an order that keeps references valid.
const IMPORT_TABLES: &[&str] = &[
    "tenants",
    "api_keys",
    "templates",
    "builds",
    "secrets",
    "sandboxes",
    "start_records",
    "events",
    "usage_hourly",
    "nodes",
    "join_tokens",
    "node_usage",
    "volumes",
    "scale_requests",
    "retirements",
    "endpoints",
];

/// Postgres only: files that every primary of the database uses, and the
/// first copy of an SQLite database.
impl Db {
    /// Every shared file: its path under the data directory, and its
    /// sealed bytes.
    pub fn shared_files(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT name, data FROM shared_files ORDER BY name")?;
        stmt.query_map((), |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect()
    }

    /// Keeps the first copy of each file. Returns whether this one was kept.
    pub fn add_shared_file(&self, name: &str, data: &[u8], now: i64) -> Result<bool> {
        Ok(self.conn().execute(
            "INSERT INTO shared_files (name, data, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (name) DO NOTHING",
            params![name, data, now],
        )? > 0)
    }

    /// Copies every row of the SQLite database at `path` into this empty
    /// one. `None` if this one already has keys, sandboxes, templates or
    /// workers, so nothing was copied; else the number of rows.
    pub fn import_sqlite(&self, path: &Path) -> Result<Option<usize>> {
        let source = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let version: i64 = source.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != i64::try_from(MIGRATIONS.len()).unwrap_or(i64::MAX) {
            return Err(Error::Connection(format!(
                "{} has schema version {version}; start this version of spawnbox on it once \
                 to upgrade it, then import it",
                path.display()
            )));
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let used: i64 = tx.query_row(
            "SELECT (SELECT count(*) FROM api_keys) + (SELECT count(*) FROM sandboxes)
                  + (SELECT count(*) FROM templates) + (SELECT count(*) FROM nodes)",
            (),
            |r| r.get(0),
        )?;
        if used > 0 {
            return Ok(None);
        }
        tx.execute("DELETE FROM tenants", ())?;
        let mut copied = 0;
        for table in IMPORT_TABLES {
            let mut stmt = source.prepare(&format!("SELECT * FROM {table}"))?;
            let columns: Vec<String> = stmt.column_names().map(str::to_owned).collect();
            let insert = format!(
                "INSERT INTO {table} ({}) VALUES ({})",
                columns.join(", "),
                vec!["?"; columns.len()].join(", ")
            );
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let values = (0..columns.len())
                    .map(|i| row.get_ref(i).map(sql::from_sqlite))
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                tx.execute(&insert, params_from_iter(values))?;
                copied += 1;
            }
        }
        // New rows continue after the copied ones.
        for (table, column) in [("sandboxes", "seq"), ("builds", "seq"), ("events", "id")] {
            tx.query_row(
                &format!(
                    "SELECT setval(pg_get_serial_sequence('{table}', '{column}'),
                     COALESCE(MAX({column}), 0) + 1, false) FROM {table}"
                ),
                (),
                |_| Ok(()),
            )?;
        }
        tx.commit()?;
        Ok(Some(copied))
    }
}

fn to_json(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

const SANDBOX_COLUMNS: &str = "id, state, template, labels, created_at, expires_at, build, \
    secrets, egress, idle_pause_s, paused_at, tenant, node, vcpus, memory_mib, volumes, \
    persistent, generation, cold_starts, last_cold_start_at";
const SANDBOX_COLUMN_COUNT: usize = 20;
const VOLUME_COLUMNS: &str = "id, tenant, name, size_gib, node, backend, created_at";
const ENDPOINT_COLUMNS: &str = "tenant, name, sandbox, port, generation, created_at, updated_at";
const KEY_COLUMNS: &str = "id, tenant, scopes, name, created_at, revoked_at";
const TENANT_COLUMNS: &str = "id, name, quotas, egress, created_at, updated_at, isolation";

fn key_from_row(row: &Row) -> Result<Key> {
    Ok(Key {
        id: row.get(0)?,
        tenant: row.get(1)?,
        scopes: row.get(2)?,
        name: row.get(3)?,
        created_at: row.get(4)?,
        revoked_at: row.get(5)?,
    })
}

fn tenant_from_row(row: &Row) -> Result<Tenant> {
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

fn event_from_row(row: &Row) -> Result<Event> {
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

fn secret_from_row(row: &Row) -> Result<Secret> {
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
     store_key, uploaded_at, guest, root";

fn template_from_row(row: &Row) -> Result<Template> {
    Ok(Template {
        name: row.get(0)?,
        spec: row.get(1)?,
        created_at: row.get(2)?,
        updated_at: row.get(3)?,
    })
}

fn build_from_row(row: &Row) -> Result<Build> {
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
        guest: row.get(12)?,
        root: row.get::<_, i64>(13)? != 0,
    })
}

/// A JSON column that must parse: a start record must not start a
/// sandbox with less than it was made with.
fn json_column<T: serde::de::DeserializeOwned>(row: &Row, i: usize) -> Result<T> {
    serde_json::from_str(&row.get::<_, String>(i)?)
        .map_err(|e| sql::Error::Type(format!("column {i}: {e}")))
}

fn sandbox_from_row(row: &Row) -> Result<Sandbox> {
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
        persistent: row.get::<_, i64>(16)? != 0,
        generation: row.get(17)?,
        cold_starts: row.get(18)?,
        last_cold_start_at: row.get(19)?,
    })
}

fn endpoint_from_row(row: &Row) -> Result<Endpoint> {
    let port: i64 = row.get(3)?;
    Ok(Endpoint {
        tenant: row.get(0)?,
        name: row.get(1)?,
        sandbox: row.get(2)?,
        port: u16::try_from(port).unwrap_or(0),
        generation: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

fn volume_from_row(row: &Row) -> Result<Volume> {
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
fn volume_users(conn: &Conn, id: &str, except: &str) -> Result<Vec<VolumeUser>> {
    // The text match only narrows the rows; the JSON decides.
    let rows = conn.query_all(
        "SELECT id, volumes FROM sandboxes
         WHERE volumes LIKE '%' || ?1 || '%' AND state NOT IN ('deleted', 'failed')
           AND id != ?2",
        params![id, except],
    )?;
    let mut users = Vec::new();
    for row in rows {
        let sandbox: String = row.get(0)?;
        let volumes: Vec<VolumeRef> =
            serde_json::from_str(&row.get::<_, String>(1)?).unwrap_or_default();
        users.extend(
            volumes
                .iter()
                .filter(|v| v.volume == id)
                .map(|v| VolumeUser {
                    sandbox: sandbox.clone(),
                    read_only: v.read_only,
                }),
        );
    }
    Ok(users)
}

/// The volume's name if `volume` cannot be mounted next to its users.
fn volume_taken(conn: &Conn, volume: &VolumeRef, except: &str) -> Result<Option<String>> {
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
            persistent: false,
            generation: 1,
            cold_starts: 0,
            last_cold_start_at: None,
        }
    }

    fn start_record(id: &str, build: &str) -> StartRecord {
        StartRecord {
            sandbox: id.into(),
            tenant: "default".into(),
            template: "base".into(),
            build: build.into(),
            spec: "{}".into(),
            vcpus: 2,
            memory_mib: 1024,
            egress: Policy::allow_all(),
            secrets: vec!["gh".into()],
            volumes: Vec::new(),
            ports: "{}".into(),
            idle_pause_s: 600,
            env: vec![1, 2, 3],
            created_at: 1,
            updated_at: 1,
        }
    }

    fn persistent(id: &str, state: &str) -> Sandbox {
        Sandbox {
            persistent: true,
            expires_at: i64::MAX,
            ..sandbox(id, state)
        }
    }

    #[test]
    fn persistent_sandboxes_keep_a_start_record_and_a_quota() {
        let db = Db::memory().unwrap();
        db.insert_persistent(
            &persistent("a", state::RUNNING),
            &start_record("a", "b1"),
            Some(2),
        )
        .unwrap()
        .unwrap();
        db.insert_persistent(
            &persistent("b", state::RUNNING),
            &start_record("b", "b2"),
            Some(2),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            db.insert_persistent(
                &persistent("c", state::RUNNING),
                &start_record("c", "b3"),
                Some(2)
            )
            .unwrap(),
            Err(Refused::Persistent(2))
        );
        // Refused, so nothing was written.
        assert_eq!(db.get_start_record("c").unwrap(), None);
        assert_eq!(
            db.get_start_record("a").unwrap(),
            Some(start_record("a", "b1"))
        );
        let a = db.get_sandbox("a").unwrap().unwrap();
        assert!(a.persistent);
        assert_eq!(a.expires_at, i64::MAX);

        db.set_start_ports("a", r#"{"3000":{}}"#, 5).unwrap();
        let record = db.get_start_record("a").unwrap().unwrap();
        assert_eq!(
            (record.ports.as_str(), record.updated_at),
            (r#"{"3000":{}}"#, 5)
        );
        // Resuming leaves it.
        db.set_paused("a", 1, 7, "{}").unwrap();
        db.set_resumed("a", 1, i64::MAX).unwrap();
        assert!(db.get_start_record("a").unwrap().is_some());

        let roots = db.build_roots().unwrap();
        assert_eq!(roots, HashSet::from(["b1".to_owned(), "b2".to_owned()]));
        db.set_state("b", 1, state::DELETED, 9).unwrap();
        assert_eq!(db.get_start_record("b").unwrap(), None);
        assert_eq!(db.build_roots().unwrap(), HashSet::from(["b1".to_owned()]));
        assert!(db.is_build_root("b1").unwrap());
        assert!(!db.is_build_root("b2").unwrap());
        db.insert_persistent(
            &persistent("c", state::RUNNING),
            &start_record("c", "b3"),
            Some(2),
        )
        .unwrap()
        .unwrap();
        db.insert_sandbox(&sandbox("d", state::RUNNING))
            .unwrap()
            .unwrap();
        assert_eq!(
            db.insert_persistent(
                &persistent("e", state::RUNNING),
                &start_record("e", "b3"),
                None
            )
            .unwrap(),
            Ok(())
        );
    }

    #[test]
    fn cold_starts_are_claimed_once_and_bound_to_a_generation() {
        let db = Db::memory().unwrap();
        db.insert_persistent(
            &persistent("a", state::RUNNING),
            &start_record("a", "b1"),
            None,
        )
        .unwrap()
        .unwrap();
        db.insert_sandbox(&sandbox("n", state::RUNNING))
            .unwrap()
            .unwrap();
        // Only a cold, persistent sandbox can be claimed.
        assert_eq!(db.claim_cold("a", None, "c1", 100).unwrap(), None);
        assert!(db.set_cold("a", 1).unwrap());
        assert!(!db.set_cold("n", 1).unwrap());
        assert_eq!(db.get_sandbox("a").unwrap().unwrap().state, state::COLD);

        assert_eq!(db.claim_cold("a", None, "c1", 100).unwrap(), Some(2));
        assert_eq!(db.claim_cold("a", None, "c2", 100).unwrap(), None);
        // Updates for the older VM do nothing.
        db.set_state("a", 1, state::FAILED, 5).unwrap();
        assert!(!db.set_cold("a", 1).unwrap());
        assert!(!db.finish_cold_start("a", None, 2, "c2", 5).unwrap());
        assert!(db.abandon_claim("a", None, 2, "c1").unwrap());
        assert_eq!(db.get_sandbox("a").unwrap().unwrap().state, state::COLD);

        assert_eq!(db.claim_cold("a", None, "c3", 100).unwrap(), Some(3));
        assert!(db.finish_cold_start("a", None, 3, "c3", 50).unwrap());
        assert!(!db.abandon_claim("a", None, 3, "c3").unwrap());
        let a = db.get_sandbox("a").unwrap().unwrap();
        assert_eq!(
            (
                a.state.as_str(),
                a.generation,
                a.cold_starts,
                a.last_cold_start_at
            ),
            (state::RUNNING, 3, 1, Some(50))
        );

        // A delete during a start wins over the start.
        assert!(db.set_cold("a", 3).unwrap());
        assert_eq!(db.claim_cold("a", None, "c4", 100).unwrap(), Some(4));
        assert!(db.delete_cold("a", 60).unwrap());
        assert!(!db.finish_cold_start("a", None, 4, "c4", 61).unwrap());
        assert_eq!(db.get_sandbox("a").unwrap().unwrap().state, state::DELETED);
        assert_eq!(db.get_start_record("a").unwrap(), None);
        assert!(!db.delete_cold("a", 62).unwrap());
    }

    #[test]
    fn a_first_create_is_not_deleted_as_cold_and_ends_only_from_starting() {
        let db = Db::memory().unwrap();
        db.insert_persistent(
            &persistent("a", state::STARTING),
            &start_record("a", "b1"),
            None,
        )
        .unwrap()
        .unwrap();
        // No claim: the create still owns it.
        assert!(!db.delete_cold("a", 5).unwrap());
        assert!(db.get_start_record("a").unwrap().is_some());
        assert!(db.start_running("a", 1).unwrap());
        assert!(!db.start_running("a", 1).unwrap());

        db.insert_sandbox(&sandbox("n", state::STARTING))
            .unwrap()
            .unwrap();
        db.set_state("n", 1, state::DELETED, 6).unwrap();
        assert!(!db.start_running("n", 1).unwrap());
        assert_eq!(db.get_sandbox("n").unwrap().unwrap().state, state::DELETED);
    }

    #[test]
    fn a_restart_makes_persistent_sandboxes_cold() {
        let db = Db::memory().unwrap();
        db.insert_persistent(
            &persistent("a", state::RUNNING),
            &start_record("a", "b1"),
            None,
        )
        .unwrap()
        .unwrap();
        db.insert_persistent(
            &persistent("b", state::RUNNING),
            &start_record("b", "b1"),
            None,
        )
        .unwrap()
        .unwrap();
        db.insert_persistent(
            &persistent("p", state::RUNNING),
            &start_record("p", "b1"),
            None,
        )
        .unwrap()
        .unwrap();
        db.set_paused("p", 1, 7, "{}").unwrap();
        db.set_cold("b", 1).unwrap();
        assert_eq!(db.claim_cold("b", None, "c", 100).unwrap(), Some(2));
        db.insert_sandbox(&sandbox("n", state::RUNNING))
            .unwrap()
            .unwrap();
        let mut cooled = db.cool_unfinished().unwrap();
        cooled.sort();
        assert_eq!(
            cooled,
            [
                ("a".to_owned(), "default".to_owned()),
                ("b".to_owned(), "default".to_owned())
            ]
        );
        assert_eq!(
            db.delete_unfinished(9).unwrap(),
            [("n".to_owned(), "default".to_owned())]
        );
        assert_eq!(db.get_sandbox("p").unwrap().unwrap().state, state::PAUSED);
        assert_eq!(db.build_roots().unwrap(), HashSet::from(["b1".to_owned()]));
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
        db.set_state("sbx_w", 1, state::DELETED, 5).unwrap();
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

    /// Needs `SPAWNBOX_TEST_DATABASE_URL`; passes without it.
    #[test]
    fn earlier_versions_stop_and_later_databases_are_refused() {
        let db = Db::memory().unwrap();
        {
            let conn = db.conn();
            // Versions before env was sealed read this column at start.
            assert!(
                conn.query_row("SELECT saved FROM sandboxes", (), |_| Ok(()))
                    .optional()
                    .is_err()
            );
            if conn.is_postgres() {
                // They also write their own schema version at start.
                let error = conn
                    .execute("INSERT INTO schema_version (version) VALUES (4)", ())
                    .unwrap_err();
                assert!(error.to_string().contains("downgrades are not supported"));
            }
        }
        let path = std::env::temp_dir().join(format!("spawnbox-newer-{}.db", now_ms()));
        drop(Db::open(&path).unwrap());
        let later = i64::try_from(MIGRATIONS.len() + 1).unwrap();
        rusqlite::Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", later)
            .unwrap();
        let refused = Db::open(&path).err().unwrap().to_string();
        assert!(
            refused.contains("downgrades are not supported"),
            "{refused}"
        );
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
        if let Ok(url) = std::env::var("SPAWNBOX_TEST_DATABASE_URL") {
            let (db, target) = Db::test_postgres(&url).unwrap();
            let later = i64::try_from(PG_MIGRATIONS.len() + 1).unwrap();
            db.conn()
                .execute("UPDATE schema_version SET version = ?1", [later])
                .unwrap();
            let refused = Db::open_postgres(target).err().unwrap().to_string();
            assert!(
                refused.contains("downgrades are not supported"),
                "{refused}"
            );
        }
    }

    #[test]
    fn imports_sqlite_into_empty_postgres() {
        let Ok(url) = std::env::var("SPAWNBOX_TEST_DATABASE_URL") else {
            return;
        };
        let path = std::env::temp_dir().join(format!("spawnbox-import-{}.db", now_ms()));
        let old = Db::open(&path).unwrap();
        let key = crate::ids::new_key(false).unwrap();
        old.insert_key(&key, None, None, Some("ci"), 1).unwrap();
        old.insert_sandbox(&sandbox("sbx_1", state::RUNNING))
            .unwrap()
            .unwrap();
        old.insert_persistent(
            &persistent("sbx_p", state::COLD),
            &start_record("sbx_p", "bld_1"),
            None,
        )
        .unwrap()
        .unwrap();
        drop(old);
        let (db, _) = Db::test_postgres(&url).unwrap();
        assert!(db.import_sqlite(&path).unwrap().is_some());
        assert_eq!(
            db.find_key(&key.hash).unwrap().unwrap().name.as_deref(),
            Some("ci")
        );
        assert_eq!(
            db.get_sandbox("sbx_1").unwrap().unwrap(),
            sandbox("sbx_1", state::RUNNING)
        );
        assert!(db.get_tenant("default").unwrap().is_some());
        assert_eq!(
            db.get_start_record("sbx_p").unwrap(),
            Some(start_record("sbx_p", "bld_1"))
        );
        assert_eq!(
            db.build_roots().unwrap(),
            HashSet::from(["bld_1".to_owned()])
        );
        db.insert_sandbox(&sandbox("sbx_2", state::RUNNING))
            .unwrap()
            .unwrap();
        assert_eq!(db.import_sqlite(&path).unwrap(), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn migrations_run_once() {
        let db = Db::memory().unwrap();
        let conn = db.conn();
        let Conn::Sqlite(conn) = &*conn else { return };
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
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        for sql in &MIGRATIONS[..4] {
            tx.execute_batch(sql).unwrap();
        }
        tx.pragma_update(None, "user_version", 4).unwrap();
        tx.execute(
            "INSERT INTO api_keys (id, hash, created_at) VALUES ('key_old', x'01', 1)",
            (),
        )
        .unwrap();
        tx.execute(
            "INSERT INTO sandboxes (id, state, template, labels, created_at, expires_at)
             VALUES ('sbx_old', 'paused', 'base', '{}', 1, 2)",
            (),
        )
        .unwrap();
        tx.commit().unwrap();
        let db = Db::init_sqlite(conn).unwrap();
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
        db.set_state("a", 1, state::DELETED, 3).unwrap();
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
        db.set_state("a", 1, state::RUNNING, 5).unwrap();
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
        db.set_paused("a", 1, 7, "{}").unwrap();
        db.set_saved("a", 1, r#"{"x":1}"#).unwrap();
        assert_eq!(
            db.delete_unfinished(9).unwrap(),
            [("b".to_owned(), "default".to_owned())]
        );
        let paused = db.paused_sandboxes().unwrap();
        assert_eq!(paused.len(), 1);
        let (a, saved) = &paused[0];
        assert_eq!((a.state.as_str(), a.paused_at), (state::PAUSED, Some(7)));
        assert_eq!(saved.as_deref(), Some(r#"{"x":1}"#));

        db.set_resumed("a", 1, 100).unwrap();
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
    fn root_builds_and_guests_are_kept_apart_from_template_builds() {
        let db = Db::memory().unwrap();
        db.insert_build("b1", "py", "{}", "f", 1).unwrap();
        let root = db.insert_build_as("b2", "py", "{}", "f", 2, true).unwrap();
        assert!(root.root && root.guest.is_none());
        // A root build never becomes the template's current build.
        assert_eq!(db.latest_build("py").unwrap().unwrap().id, "b1");
        db.set_build_guest("b2", "0.4").unwrap();
        let b2 = db.get_build("b2").unwrap().unwrap();
        assert_eq!((b2.root, b2.guest.as_deref()), (true, Some("0.4")));
        assert!(!db.get_build("b1").unwrap().unwrap().root);
    }

    #[test]
    fn a_start_record_moves_to_a_new_build_only_from_the_one_it_names() {
        let db = Db::memory().unwrap();
        db.insert_persistent(
            &Sandbox {
                build: Some("b1".into()),
                ..persistent("a", state::COLD)
            },
            &start_record("a", "b1"),
            None,
        )
        .unwrap()
        .unwrap();
        assert!(!db.set_start_build("a", "b0", "b2", 5).unwrap());
        assert_eq!(db.get_start_record("a").unwrap().unwrap().build, "b1");
        assert!(db.set_start_build("a", "b1", "b2", 5).unwrap());
        let record = db.get_start_record("a").unwrap().unwrap();
        assert_eq!((record.build.as_str(), record.updated_at), ("b2", 5));
        assert_eq!(
            db.get_sandbox("a").unwrap().unwrap().build.as_deref(),
            Some("b2")
        );
        assert_eq!(db.build_roots().unwrap(), HashSet::from(["b2".to_owned()]));
        assert!(!db.set_start_build("b", "b1", "b2", 5).unwrap());
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
    fn retirement_is_kept_once_and_cannot_be_undone() {
        let db = Db::memory().unwrap();
        let node = NodeRow {
            id: "nod_a".into(),
            url: "https://10.0.0.2:7444".into(),
            state: node_state::READY.into(),
            boot: None,
            seq: 0,
            report: None,
            last_seen: None,
            created_at: 100,
            removed_at: None,
            draining: false,
            kind: node_kind::WORKER.into(),
        };
        db.insert_scale_up("scl_1", b"t", b"sealed", "load", 100, 200)
            .unwrap();
        assert!(db.join_node(b"t", &node).unwrap());
        let retire = |id: &str, origin: &str| Retirement {
            node: "nod_a".into(),
            id: id.into(),
            origin: origin.into(),
            migrate: true,
            reason: "idle".into(),
            state: retire_state::DRAINING.into(),
            created_at: 300,
            ready_at: None,
            ended_at: None,
            failed_moves: 0,
        };
        let first = db
            .retire_node(&retire("ret_1", retire_origin::API))
            .unwrap()
            .unwrap();
        let again = db
            .retire_node(&retire("ret_2", retire_origin::AUTOSCALER))
            .unwrap()
            .unwrap();
        assert_eq!(again.id, first.id);
        assert_eq!(again.origin, retire_origin::API);
        assert!(db.list_nodes().unwrap()[0].draining);
        assert!(!db.set_node_draining("nod_a", false).unwrap());
        assert!(db.list_nodes().unwrap()[0].draining);
        db.set_retirement("nod_a", retire_state::READY, 0, 400)
            .unwrap();
        db.set_retirement("nod_a", retire_state::BLOCKED, 1, 500)
            .unwrap();
        let r = db.retirement("nod_a").unwrap().unwrap();
        assert_eq!(
            (r.state.as_str(), r.ready_at),
            (retire_state::READY, Some(400))
        );
        db.end_retirement_of("nod_a", 600).unwrap();
        assert!(db.retirements(true).unwrap().is_empty());
        let r = db.retirement("nod_a").unwrap().unwrap();
        assert_eq!(
            (r.state.as_str(), r.ended_at),
            (retire_state::REMOVED, Some(600))
        );
        assert!(db.set_node_draining("nod_a", false).unwrap());
    }

    #[test]
    fn scale_up_learns_the_node_that_joined_with_its_token() {
        let db = Db::memory().unwrap();
        db.insert_scale_up("scl_1", b"t", b"sealed", "load", 100, 200)
            .unwrap();
        db.insert_scale_down("scl_2", "nod_old", "idle", 101)
            .unwrap();
        let open = db.scale_requests(true, 10).unwrap();
        assert_eq!(open.len(), 2);
        assert_eq!(open[1].node, None);
        let node = NodeRow {
            id: "nod_new".into(),
            url: "https://10.0.0.2:7444".into(),
            state: node_state::SUSPECT.into(),
            boot: None,
            seq: 0,
            report: None,
            last_seen: None,
            created_at: 150,
            removed_at: None,
            draining: false,
            kind: node_kind::WORKER.into(),
        };
        assert_eq!(
            db.scale_up_token("scl_1").unwrap().as_deref(),
            Some(&b"sealed"[..])
        );
        assert!(db.join_node(b"t", &node).unwrap());
        let up = db.scale_requests(true, 10).unwrap().pop().unwrap();
        assert_eq!(up.node.as_deref(), Some("nod_new"));
        assert_eq!(db.scale_up_of("nod_new").unwrap().as_deref(), Some("scl_1"));
        assert_eq!(db.scale_up_of("nod_old").unwrap(), None);
        db.end_scale_request("scl_1", up.node.as_deref(), "joined", 160)
            .unwrap();
        let open = db.scale_requests(true, 10).unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].node.as_deref(), Some("nod_old"));
        let all = db.scale_requests(false, 10).unwrap();
        assert_eq!(all[1].outcome.as_deref(), Some("joined"));
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
    fn persistent_mirrors_change_only_for_their_generation() {
        let db = Db::memory().unwrap();
        db.insert_persistent(
            &persistent("sbx_p", state::COLD),
            &start_record("sbx_p", "b1"),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            db.claim_cold("sbx_p", Some("nod_a"), "c1", 100).unwrap(),
            Some(2)
        );
        let row = db.get_sandbox("sbx_p").unwrap().unwrap();
        assert_eq!(
            (row.state.as_str(), row.node.as_deref()),
            (state::STARTING, Some("nod_a"))
        );
        let mut report = persistent("sbx_p", state::RUNNING);
        report.generation = 2;
        // A heartbeat never ends a start.
        assert!(!db.put_mirror("nod_a", &report, 5).unwrap());
        assert!(
            db.finish_cold_start("sbx_p", Some("nod_a"), 2, "c1", 6)
                .unwrap()
        );
        // Nor applies an older or newer copy.
        for generation in [1, 3] {
            let mut other = persistent("sbx_p", state::PAUSED);
            other.generation = generation;
            assert!(!db.put_mirror("nod_a", &other, 7).unwrap());
        }
        report.state = state::PAUSED.into();
        assert!(db.put_mirror("nod_a", &report, 8).unwrap());
        assert_eq!(
            db.get_sandbox("sbx_p").unwrap().unwrap().state,
            state::PAUSED
        );
        // Reported cold, the row is the primary's again, and stays cold.
        report.state = state::COLD.into();
        assert!(db.put_mirror("nod_a", &report, 9).unwrap());
        report.state = state::RUNNING.into();
        assert!(!db.put_mirror("nod_a", &report, 10).unwrap());
        let row = db.get_sandbox("sbx_p").unwrap().unwrap();
        assert_eq!((row.state.as_str(), row.node), (state::COLD, None));

        // A start that failed leaves it cold and here.
        assert_eq!(
            db.claim_cold("sbx_p", Some("nod_b"), "c2", 100).unwrap(),
            Some(3)
        );
        assert!(!db.abandon_claim("sbx_p", None, 3, "c2").unwrap());
        assert!(db.abandon_claim("sbx_p", Some("nod_b"), 3, "c2").unwrap());
        let row = db.get_sandbox("sbx_p").unwrap().unwrap();
        assert_eq!((row.state.as_str(), row.node), (state::COLD, None));

        // A delete on the worker ends the start record too.
        db.claim_cold("sbx_p", Some("nod_b"), "c3", 100).unwrap();
        db.finish_cold_start("sbx_p", Some("nod_b"), 4, "c3", 11)
            .unwrap();
        let mut deleted = persistent("sbx_p", state::DELETED);
        deleted.generation = 4;
        assert!(db.put_mirror("nod_b", &deleted, 12).unwrap());
        assert_eq!(db.get_start_record("sbx_p").unwrap(), None);
    }

    #[test]
    fn stale_copies_are_older_newer_or_elsewhere() {
        let row = |node: Option<&str>, state: &str, generation| {
            Some((node.map(str::to_owned), state.to_owned(), generation))
        };
        assert!(is_stale(None, "nod_a", 1));
        assert!(!is_stale(
            row(Some("nod_a"), state::RUNNING, 2).as_ref(),
            "nod_a",
            2
        ));
        assert!(is_stale(
            row(Some("nod_a"), state::RUNNING, 2).as_ref(),
            "nod_a",
            1
        ));
        assert!(is_stale(
            row(Some("nod_a"), state::RUNNING, 2).as_ref(),
            "nod_a",
            3
        ));
        assert!(is_stale(
            row(Some("nod_b"), state::RUNNING, 2).as_ref(),
            "nod_a",
            2
        ));
        assert!(is_stale(row(None, state::COLD, 2).as_ref(), "nod_a", 2));
        assert!(is_stale(
            row(Some("nod_a"), state::DELETED, 2).as_ref(),
            "nod_a",
            2
        ));
        // The copy that a start here replaces.
        assert!(!is_stale(
            row(Some("nod_a"), state::STARTING, 3).as_ref(),
            "nod_a",
            2
        ));

        let db = Db::memory().unwrap();
        db.insert_persistent(
            &persistent("sbx_p", state::COLD),
            &start_record("sbx_p", "b1"),
            None,
        )
        .unwrap()
        .unwrap();
        db.claim_cold("sbx_p", Some("nod_a"), "c", 100).unwrap();
        db.finish_cold_start("sbx_p", Some("nod_a"), 2, "c", 5)
            .unwrap();
        let stale = db
            .stale_copies("nod_a", &[("sbx_p", 2), ("sbx_q", 1)])
            .unwrap();
        assert_eq!(stale, ["sbx_q"]);
        assert_eq!(
            db.stale_copies("nod_b", &[("sbx_p", 2)]).unwrap(),
            ["sbx_p"]
        );
    }

    #[test]
    fn lost_nodes_keep_persistent_sandboxes_until_fenced() {
        let db = Db::memory().unwrap();
        db.insert_join_token(b"t", 0, 100).unwrap();
        db.join_node(b"t", &node("nod_a", 1)).unwrap();
        for id in ["sbx_p", "sbx_q"] {
            db.insert_persistent(&persistent(id, state::COLD), &start_record(id, "b1"), None)
                .unwrap()
                .unwrap();
            db.claim_cold(id, Some("nod_a"), "c", 100).unwrap();
            db.finish_cold_start(id, Some("nod_a"), 2, "c", 5).unwrap();
        }
        db.put_mirror("nod_a", &sandbox("sbx_t", state::RUNNING), 0)
            .unwrap();
        // Only the plain sandbox ends when it is no longer reported.
        let none = std::collections::HashSet::new();
        let gone = db.end_mirrors("nod_a", &none, 10, 60).unwrap();
        assert_eq!(gone, [("sbx_t".to_owned(), "default".to_owned())]);
        // A persistent one started since the report was made stays.
        let keep = std::collections::HashSet::from(["sbx_q".to_owned()]);
        assert!(db.cool_missing("nod_a", &keep, 5).unwrap().is_empty());
        let cooled = db.cool_missing("nod_a", &keep, 6).unwrap();
        assert_eq!(cooled, [("sbx_p".to_owned(), "default".to_owned())]);
        let row = db.get_sandbox("sbx_p").unwrap().unwrap();
        assert_eq!((row.state.as_str(), row.node), (state::COLD, None));

        assert!(!db.set_node_fenced("nod_a", "operator", 20).unwrap());
        assert!(db.unfenced_nodes().unwrap().is_empty());
        db.set_node_state("nod_a", node_state::DOWN).unwrap();
        let unfenced = db.unfenced_nodes().unwrap();
        assert_eq!(unfenced.len(), 1);
        assert_eq!(
            (unfenced[0].0.id.as_str(), unfenced[0].1.as_deref()),
            ("nod_a", None)
        );
        assert!(db.set_node_fenced("nod_a", "operator", 20).unwrap());
        assert_eq!(
            db.unfenced_nodes().unwrap()[0].1.as_deref(),
            Some("operator")
        );
        // A heartbeat proves it is back, so the proof no longer holds.
        db.node_seen(&node("nod_a", 21)).unwrap();
        db.set_node_state("nod_a", node_state::DOWN).unwrap();
        assert_eq!(db.unfenced_nodes().unwrap()[0].1, None);

        let cooled = db.cool_node("nod_a").unwrap();
        assert_eq!(cooled, [("sbx_q".to_owned(), "default".to_owned())]);
        let row = db.get_sandbox("sbx_q").unwrap().unwrap();
        assert_eq!((row.state.as_str(), row.node), (state::COLD, None));
        assert!(db.unfenced_nodes().unwrap().is_empty());
    }

    #[test]
    fn a_drain_makes_persistent_sandboxes_cold_and_frees_their_volumes() {
        let db = Db::memory().unwrap();
        db.insert_join_token(b"t", 0, 100).unwrap();
        db.join_node(b"t", &node("nod_a", 1)).unwrap();
        let mut home = volume("vol_1", "data");
        home.node = Some("nod_a".into());
        assert!(db.insert_volume(&home).unwrap());
        for id in ["sbx_p", "sbx_q"] {
            let mut row = persistent(id, state::COLD);
            if id == "sbx_p" {
                row.volumes = with_volume(id, false).volumes;
            }
            db.insert_persistent(&row, &start_record(id, "b1"), None)
                .unwrap()
                .unwrap();
            db.claim_cold(id, Some("nod_a"), "c", 100).unwrap();
            db.finish_cold_start(id, Some("nod_a"), 2, "c", 5).unwrap();
        }
        let mut paused = persistent("sbx_q", state::PAUSED);
        paused.generation = 2;
        assert!(db.put_mirror("nod_a", &paused, 6).unwrap());
        assert_eq!(db.node_sandbox_counts().unwrap()["nod_a"], 2);
        assert_eq!(db.node_volume_counts().unwrap()["nod_a"], 1);
        assert_eq!(db.volume_holders("vol_1").unwrap().len(), 1);

        // Only the copy the drain stopped: that node, that generation.
        assert!(!db.cool_on_node("sbx_p", "nod_b", 2).unwrap());
        assert!(!db.cool_on_node("sbx_p", "nod_a", 1).unwrap());
        assert!(db.cool_on_node("sbx_p", "nod_a", 2).unwrap());
        assert!(!db.cool_on_node("sbx_p", "nod_a", 2).unwrap());
        assert!(db.cool_on_node("sbx_q", "nod_a", 2).unwrap());
        for id in ["sbx_p", "sbx_q"] {
            let row = db.get_sandbox(id).unwrap().unwrap();
            assert_eq!((row.state.as_str(), row.node), (state::COLD, None));
        }
        assert!(!db.node_sandbox_counts().unwrap().contains_key("nod_a"));
        // The volume can move while its sandbox is cold, but not be
        // deleted or mounted by another.
        assert!(db.volume_holders("vol_1").unwrap().is_empty());
        assert_eq!(db.volume_users("vol_1").unwrap().len(), 1);
        // The next start is a new generation on another host.
        assert_eq!(
            db.claim_cold("sbx_p", Some("nod_b"), "d", 100).unwrap(),
            Some(3)
        );
        assert_eq!(db.volume_holders("vol_1").unwrap().len(), 1);
        // A report from the drained node's old copy changes nothing.
        let mut old = persistent("sbx_p", state::RUNNING);
        old.generation = 2;
        assert!(!db.put_mirror("nod_a", &old, 7).unwrap());
        // Deleted sandboxes are never cooled.
        db.set_state("sbx_q", 2, state::DELETED, 8).unwrap();
        assert!(!db.cool_on_node("sbx_q", "nod_a", 2).unwrap());
    }

    #[test]
    fn unfinished_cold_starts_settle_from_the_report() {
        let db = Db::memory().unwrap();
        db.insert_join_token(b"t", 0, 100).unwrap();
        db.join_node(b"t", &node("nod_a", 1)).unwrap();
        for id in ["sbx_p", "sbx_q", "sbx_r"] {
            db.insert_persistent(&persistent(id, state::COLD), &start_record(id, "b1"), None)
                .unwrap()
                .unwrap();
            db.claim_cold(id, Some("nod_a"), "c", 100).unwrap();
        }
        let generation = db.get_sandbox("sbx_p").unwrap().unwrap().generation;
        let report = [
            ("sbx_p", generation, state::RUNNING),
            ("sbx_q", generation - 1, state::RUNNING),
        ];
        // A claim still in time is left to its caller.
        assert!(db.settle_claims("nod_a", &report, 100).unwrap().is_empty());
        let cooled = db.settle_claims("nod_a", &report, 101).unwrap();
        let ids: Vec<&str> = cooled.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["sbx_q", "sbx_r"]);
        let p = db.get_sandbox("sbx_p").unwrap().unwrap();
        assert_eq!(
            (p.state.as_str(), p.node.as_deref()),
            (state::RUNNING, Some("nod_a"))
        );
        assert_eq!(p.generation, generation);
        for id in ["sbx_q", "sbx_r"] {
            let row = db.get_sandbox(id).unwrap().unwrap();
            assert_eq!((row.state.as_str(), row.node), (state::COLD, None));
        }
        // A settled claim can be made again.
        assert!(db.claim_cold("sbx_q", None, "d", 200).unwrap().is_some());
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
