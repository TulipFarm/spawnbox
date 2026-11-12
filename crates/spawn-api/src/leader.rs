//! Several primaries can share one Postgres database. One leads and serves;
//! the others wait as standbys and take over when it stops renewing its
//! lease. A leader that cannot renew in time stops itself, before its lease
//! runs out, so two never serve at once. Before it exits, it kills its
//! persistent sandboxes, so a new leader can start them after the fence
//! time.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio_postgres::Client;

use crate::db::{Db, PgTarget};
use crate::secretbox::SecretBox;

/// How long a lease lasts after each renewal.
const LEASE_S: i64 = 15;
const RENEW_EVERY: Duration = Duration::from_secs(1);
/// Longest wait for one database call.
const CALL: Duration = Duration::from_secs(2);
/// A leader stops when it has not renewed for this long.
const GIVE_UP: Duration = Duration::from_secs(6);
/// Longest wait for the processes of killed VMs to end.
const KILL_WAIT: Duration = Duration::from_secs(1);
/// After it gives up, how long the server has to record its sandboxes as
/// stopped before the process exits.
const EXIT_AFTER: Duration = Duration::from_secs(2);
/// The latest a leader that cannot renew exits, counted from when its
/// lease was last extended: the renewal may have taken all of `CALL`, the
/// next check comes up to `RENEW_EVERY` and `CALL` late, and then it kills
/// its VMs and exits. Less than the lease, so two never serve at once.
const EXIT_BY: Duration = CALL
    .saturating_add(GIVE_UP)
    .saturating_add(RENEW_EVERY)
    .saturating_add(CALL)
    .saturating_add(KILL_WAIT)
    .saturating_add(EXIT_AFTER);
const _: () = assert!(EXIT_BY.as_secs() < LEASE_S as u64);

/// The term of the lease this process holds; 0 until it leads.
static TERM: AtomicI64 = AtomicI64::new(0);

/// The term of the lease this process holds, if it leads.
pub fn term() -> Option<i64> {
    Some(TERM.load(Ordering::Relaxed)).filter(|t| *t > 0)
}

/// Files under the data directory that every primary must have the same:
/// the egress and fleet CAs and the browser session key.
pub const SHARED: &[&str] = &[
    "egress-ca.crt",
    "egress-ca.key",
    "fleet/ca.crt",
    "fleet/ca.key",
    "session.key",
];

pub fn target(url: &str, ca_file: Option<&Path>) -> Result<PgTarget> {
    let ca = ca_file
        .map(|path| std::fs::read(path).with_context(|| format!("read {}", path.display())))
        .transpose()?;
    PgTarget::new(url, ca.as_deref())
}

/// The database: Postgres at `url`, or SQLite in the data directory.
pub fn open(data: &Path, url: Option<&str>, ca_file: Option<&Path>) -> Result<Db> {
    match url {
        Some(url) => Db::open_postgres(target(url, ca_file)?).context("open the Postgres database"),
        None => Db::open(&data.join(crate::DB_FILE)).context("open database"),
    }
}

/// The database as it is, read-only and without migrations, for checks
/// that must not change it.
pub fn open_read_only(data: &Path, url: Option<&str>, ca_file: Option<&Path>) -> Result<Db> {
    match url {
        Some(url) => {
            Db::open_postgres_read_only(target(url, ca_file)?).context("open the Postgres database")
        }
        None => Db::open_sqlite_read_only(&data.join(crate::DB_FILE)).context("open database"),
    }
}

/// This host's name in the lease, kept in the data directory.
pub fn host_id(data: &Path) -> Result<String> {
    let path = data.join("host-id");
    match std::fs::read_to_string(&path) {
        Ok(id) if !id.trim().is_empty() => Ok(id.trim().to_owned()),
        Ok(_) => bail!("{} is empty; remove it", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let id = crate::ids::new_id("host")?;
            std::fs::write(&path, &id).with_context(|| format!("write {}", path.display()))?;
            Ok(id)
        }
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

pub struct Leading {
    /// Who held the lease before, if anyone did.
    pub previous: Option<String>,
    /// Fires when the lease is lost. The process exits soon after.
    pub lost: tokio::sync::oneshot::Receiver<()>,
}

/// Waits until this host leads, then keeps the lease on a thread of its
/// own. The process exits soon after the lease is lost.
pub async fn lead(target: PgTarget, holder: String) -> Result<Leading> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let (lost_tx, lost) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("spawnbox-lease".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("start the lease runtime");
            rt.block_on(hold(&target, &holder, tx, lost_tx));
        })?;
    let previous = rx.await.context("the lease thread stopped")?;
    Ok(Leading { previous, lost })
}

/// Tells the server to stop and kills every VM here at once: the server
/// may be stuck on the database. Exits `linger` later at most.
async fn give_up(lost: tokio::sync::oneshot::Sender<()>, linger: Duration) -> ! {
    TERM.store(0, Ordering::Relaxed);
    let _ = lost.send(());
    kill_vms();
    tokio::time::sleep(linger).await;
    eprintln!("exiting without the leader lease");
    std::process::exit(1);
}

fn kill_vms() {
    #[cfg(target_os = "linux")]
    if !spawn_node::firecracker::kill_all_now(KILL_WAIT) {
        eprintln!("warning: processes of some sandboxes are still running");
    }
}

async fn hold(
    target: &PgTarget,
    holder: &str,
    led: tokio::sync::oneshot::Sender<Option<String>>,
    lost: tokio::sync::oneshot::Sender<()>,
) {
    let mut client = None;
    let mut said = false;
    let lease = loop {
        match tokio::time::timeout(CALL, acquire(&mut client, target, holder)).await {
            Ok(Ok(Some(lease))) => break lease,
            Ok(Ok(None)) if !said => {
                eprintln!("standby: another primary leads; waiting to take over");
                said = true;
            }
            Ok(Ok(None)) => {}
            Ok(Err(error)) => {
                eprintln!("warning: leader lease: {error}");
                client = None;
            }
            Err(_) => client = None,
        }
        tokio::time::sleep(RENEW_EVERY).await;
    };
    let term = lease.0;
    TERM.store(term, Ordering::Relaxed);
    eprintln!("leading the database as {holder}, term {term}");
    if led.send(lease.1).is_err() {
        return;
    }
    let mut renewed = Instant::now();
    loop {
        tokio::time::sleep(RENEW_EVERY).await;
        match tokio::time::timeout(CALL, renew(&mut client, target, holder, term)).await {
            Ok(Ok(true)) => renewed = Instant::now(),
            Ok(Ok(false)) => {
                eprintln!("another primary took the leader lease; stopping");
                give_up(lost, Duration::ZERO).await;
            }
            Ok(Err(_)) | Err(_) => client = None,
        }
        if renewed.elapsed() > GIVE_UP {
            eprintln!(
                "cannot renew the leader lease for {} s; stopping so a standby can lead",
                GIVE_UP.as_secs()
            );
            give_up(lost, EXIT_AFTER).await;
        }
    }
}

async fn connected<'c>(
    slot: &'c mut Option<Client>,
    target: &PgTarget,
) -> Result<&'c Client, tokio_postgres::Error> {
    if slot.as_ref().is_none_or(Client::is_closed) {
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new((*target.tls).clone());
        let (client, connection) = tokio_postgres::connect(&target.url, tls).await?;
        tokio::spawn(connection);
        *slot = Some(client);
    }
    Ok(slot.as_ref().expect("connected above"))
}

/// Takes the lease if it is free, ran out, or is already ours. The term
/// grows each time it is taken. Returns the term and the previous holder.
async fn acquire(
    slot: &mut Option<Client>,
    target: &PgTarget,
    holder: &str,
) -> Result<Option<(i64, Option<String>)>, tokio_postgres::Error> {
    let row = connected(slot, target)
        .await?
        .query_opt(
            "WITH previous AS (SELECT holder FROM leader WHERE id = 1)
             INSERT INTO leader (id, holder, term, expires_at)
             VALUES (1, $1, 1, now() + make_interval(secs => $2))
             ON CONFLICT (id) DO UPDATE SET
                 holder = excluded.holder, term = leader.term + 1,
                 expires_at = excluded.expires_at
             WHERE leader.expires_at < now() OR leader.holder = excluded.holder
             RETURNING term, (SELECT holder FROM previous)",
            &[&holder, &(LEASE_S as f64)],
        )
        .await?;
    Ok(row.map(|r| (r.get(0), r.get(1))))
}

/// False if another host took the lease.
async fn renew(
    slot: &mut Option<Client>,
    target: &PgTarget,
    holder: &str,
    term: i64,
) -> Result<bool, tokio_postgres::Error> {
    let n = connected(slot, target)
        .await?
        .execute(
            "UPDATE leader SET expires_at = now() + make_interval(secs => $3)
             WHERE id = 1 AND holder = $1 AND term = $2",
            &[&holder, &term, &(LEASE_S as f64)],
        )
        .await?;
    Ok(n == 1)
}

pub fn label(name: &str) -> String {
    format!("shared:{name}")
}

/// Writes the database's copies of the shared files over local ones, so
/// this host uses the same CAs and keys as the last leader.
pub fn pull_shared(db: &Db, data: &Path, sbox: &SecretBox) -> Result<()> {
    let mut fleet_ca_changed = false;
    for (name, sealed) in db.shared_files()? {
        if !SHARED.contains(&name.as_str()) {
            continue;
        }
        let plain = sbox.open(&label(&name), &sealed).with_context(|| {
            format!(
                "cannot decrypt the shared {name}: copy secrets.key from the other primary \
                 (or pass the same --secrets-key-file)"
            )
        })?;
        let path = data.join(&name);
        if std::fs::read(&path).is_ok_and(|local| local == plain) {
            continue;
        }
        write_private(&path, &plain)?;
        eprintln!("took {name} from the database");
        fleet_ca_changed |= name.starts_with("fleet/");
    }
    if fleet_ca_changed {
        // Signed by the old CA; made again from the new one.
        let identity = data.join("fleet").join("primary");
        if identity.exists() {
            std::fs::remove_dir_all(&identity)
                .with_context(|| format!("remove {}", identity.display()))?;
        }
    }
    Ok(())
}

/// Stores the shared files this host made, unless the database has them.
pub fn push_shared(db: &Db, data: &Path, sbox: &SecretBox) -> Result<()> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let now_ms = i64::try_from(now_ms)?;
    for name in SHARED {
        let path = data.join(name);
        let plain = match std::fs::read(&path) {
            Ok(plain) => plain,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        db.add_shared_file(name, &sbox.seal(&label(name), &plain)?, now_ms)?;
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let tmp = PathBuf::from(format!("{}.new", path.display()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("write {}", tmp.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs `SPAWNBOX_TEST_DATABASE_URL`; passes without it.
    #[test]
    fn one_holder_at_a_time() {
        let Ok(url) = std::env::var("SPAWNBOX_TEST_DATABASE_URL") else {
            return;
        };
        let (_db, t) = Db::test_postgres(&url).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut a, mut b) = (None, None);
            assert_eq!(
                acquire(&mut a, &t, "host_a").await.unwrap(),
                Some((1, None))
            );
            assert_eq!(acquire(&mut b, &t, "host_b").await.unwrap(), None);
            let again = Some((2, Some("host_a".to_owned())));
            assert_eq!(acquire(&mut a, &t, "host_a").await.unwrap(), again);
            assert!(renew(&mut a, &t, "host_a", 2).await.unwrap());
            assert!(!renew(&mut b, &t, "host_b", 2).await.unwrap());
            connected(&mut b, &t)
                .await
                .unwrap()
                .execute(
                    "UPDATE leader SET expires_at = now() - interval '1 second'",
                    &[],
                )
                .await
                .unwrap();
            let taken = Some((3, Some("host_a".to_owned())));
            assert_eq!(acquire(&mut b, &t, "host_b").await.unwrap(), taken);
            assert!(!renew(&mut a, &t, "host_a", 2).await.unwrap());
        });
    }
}
