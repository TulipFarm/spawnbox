//! `spawn-api`: the Spawnbox HTTP API for a Linux host, and the fleet's
//! edge.

// Pure helpers are used only by the Linux server but tested on every OS.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod check;
mod db;
mod events;
mod guard;
mod ids;
mod leader;
mod metering;
mod metrics;
mod model;
mod ports;
mod reseal;
mod secretbox;
mod secrets;
mod session;
mod tenancy;
mod utf8;
mod warm;

#[cfg(target_os = "linux")]
mod egress;
#[cfg(target_os = "linux")]
mod fleet;
#[cfg(target_os = "linux")]
mod hub;
#[cfg(target_os = "linux")]
mod otlp;
#[cfg(target_os = "linux")]
mod pages;
#[cfg(target_os = "linux")]
mod preview;
#[cfg(target_os = "linux")]
mod runtime;
#[cfg(target_os = "linux")]
mod server;
#[cfg(target_os = "linux")]
mod services;
#[cfg(target_os = "linux")]
mod store;
#[cfg(target_os = "linux")]
mod templates;
#[cfg(target_os = "linux")]
mod terminal;
#[cfg(target_os = "linux")]
mod tls;
#[cfg(target_os = "linux")]
mod traces;
#[cfg(target_os = "linux")]
mod volumes;

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;

pub const DEFAULT_DATA_DIR: &str = "/var/lib/spawnbox";
pub const DB_FILE: &str = "spawnbox.db";

#[derive(Parser)]
#[command(version, about)]
enum Cli {
    /// Build the base template and serve the HTTP API. Needs root and KVM.
    #[cfg(target_os = "linux")]
    Serve(Box<server::Args>),
    /// Route clients' calls for a fleet: data calls go straight to the host
    /// that runs the sandbox, the rest to the primary. Runs no sandboxes.
    #[cfg(target_os = "linux")]
    Edge(Box<fleet::edge::Args>),
    /// Create an API key. It is printed once and only its hash is stored.
    CreateKey {
        #[arg(long, default_value = DEFAULT_DATA_DIR)]
        data_dir: PathBuf,
        /// Make a tenant key that sees only this tenant. Without it, the key
        /// is an org key that sees every tenant.
        #[arg(long)]
        tenant: Option<String>,
        /// A label to tell keys apart.
        #[arg(long)]
        name: Option<String>,
        /// The server's Postgres database, if it uses one.
        #[arg(long, env = "SPAWNBOX_DATABASE_URL")]
        database_url: Option<String>,
        /// PEM CA certificates for the database's TLS certificate.
        #[arg(long, requires = "database_url")]
        database_ca_file: Option<PathBuf>,
    },
    /// Check a data directory and its database, as after a restore: count
    /// what they hold and decrypt every sealed value. Changes nothing.
    CheckData {
        #[arg(long, default_value = DEFAULT_DATA_DIR)]
        data_dir: PathBuf,
        /// The server's Postgres database, if it uses one.
        #[arg(long, env = "SPAWNBOX_DATABASE_URL")]
        database_url: Option<String>,
        /// PEM CA certificates for the database's TLS certificate.
        #[arg(long, requires = "database_url")]
        database_ca_file: Option<PathBuf>,
        /// The secrets key. Defaults to secrets.key in the data directory.
        #[arg(long)]
        secrets_key_file: Option<PathBuf>,
    },
    /// Started by `serve`: kills the server's VMs once the server is gone.
    #[command(hide = true)]
    Guard {
        /// The parent cgroup of the VM cgroups.
        #[arg(long)]
        cgroup_parent: PathBuf,
        /// The cgroup to move this process into.
        #[arg(long)]
        own_cgroup: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse() {
        #[cfg(target_os = "linux")]
        Cli::Serve(args) => tokio::runtime::Runtime::new()?.block_on(server::serve(*args)),
        #[cfg(target_os = "linux")]
        Cli::Edge(args) => tokio::runtime::Runtime::new()?.block_on(fleet::edge::run(*args)),
        Cli::Guard {
            cgroup_parent,
            own_cgroup,
        } => guard::run(&cgroup_parent, own_cgroup.as_deref()),
        Cli::CheckData {
            data_dir,
            database_url,
            database_ca_file,
            secrets_key_file,
        } => check::run(
            &data_dir,
            database_url.as_deref(),
            database_ca_file.as_deref(),
            secrets_key_file.as_deref(),
        ),
        Cli::CreateKey {
            data_dir,
            tenant,
            name,
            database_url,
            database_ca_file,
        } => {
            let data = open_data_dir(&data_dir)?;
            let db = leader::open(&data, database_url.as_deref(), database_ca_file.as_deref())?;
            create_key(&db, tenant.as_deref(), name.as_deref())
        }
    }
}

fn create_key(db: &db::Db, tenant: Option<&str>, name: Option<&str>) -> Result<()> {
    if let Some(tenant) = tenant
        && db.get_tenant(tenant)?.is_none()
    {
        anyhow::bail!("no tenant {tenant:?}; create it with POST /v1/tenants first");
    }
    let key = ids::new_key(tenant.is_some())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    db.insert_key(&key, tenant, None, name, i64::try_from(now)?)?;
    eprintln!(
        "created {}. Store this key now; it is not shown again:",
        key.id
    );
    println!("{}", key.secret);
    Ok(())
}

/// Creates the data directory readable only by its owner.
pub fn open_data_dir(dir: &Path) -> Result<PathBuf> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir.canonicalize()?)
}
