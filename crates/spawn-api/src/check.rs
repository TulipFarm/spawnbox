//! `spawn-api check-data`: reads a data directory and its database without
//! changing them, and decrypts everything the secrets key seals. Run it
//! after a restore, before the server starts.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::db::{Db, StartEnv};
use crate::secretbox::{FLEET_CA_LABEL, SecretBox};

/// What was found, and every sealed value the key could not open.
#[derive(Debug, Default)]
pub struct Report {
    pub tenants: usize,
    pub keys: usize,
    pub templates: usize,
    pub secrets: usize,
    /// Sandbox rows per state.
    pub sandboxes: Vec<(String, i64)>,
    pub start_records: usize,
    pub saved: usize,
    pub shared_files: usize,
    /// Sealed key files found in the data directory.
    pub key_files: Vec<&'static str>,
    pub unreadable: Vec<String>,
}

/// Opens the data without creating anything, checks it and prints the
/// report. Fails if anything sealed cannot be read.
pub fn run(
    data: &Path,
    database_url: Option<&str>,
    database_ca_file: Option<&Path>,
    secrets_key_file: Option<&Path>,
) -> Result<()> {
    if !data.is_dir() {
        bail!("{} is not a directory", data.display());
    }
    let key_file = secrets_key_file.map_or_else(|| data.join("secrets.key"), Path::to_path_buf);
    let key = std::fs::read(&key_file).with_context(|| format!("read {}", key_file.display()))?;
    let sbox = SecretBox::new(&key).with_context(|| format!("{}", key_file.display()))?;
    let db_file = data.join(crate::DB_FILE);
    if database_url.is_none() && !db_file.exists() {
        bail!("no database at {}", db_file.display());
    }
    let db = crate::leader::open_read_only(data, database_url, database_ca_file)?;
    let report = check(&db, data, &sbox)?;
    print(&report);
    if !report.unreadable.is_empty() {
        bail!(
            "{} cannot read {} sealed values; is it the key this data was made with?",
            key_file.display(),
            report.unreadable.len()
        );
    }
    Ok(())
}

pub fn check(db: &Db, data: &Path, sbox: &SecretBox) -> Result<Report> {
    let mut report = Report {
        tenants: db.list_tenants()?.len(),
        keys: db.list_keys()?.len(),
        templates: db.list_templates()?.len(),
        sandboxes: db.count_sandboxes()?,
        ..Report::default()
    };
    for row in db.list_secrets()? {
        report.secrets += 1;
        let value = sbox.open(&crate::secrets::label(&row.name), &row.value);
        if value.and_then(|v| String::from_utf8(v).ok()).is_none() {
            report.unreadable.push(format!("secret {}", row.name));
        }
    }
    for StartEnv {
        sandbox,
        tenant,
        env,
        services,
    } in db.start_record_envs()?
    {
        report.start_records += 1;
        let current =
            services.is_empty() && sbox.open_sandbox_env(&tenant, &sandbox, &env).is_some();
        if !current
            && sbox
                .open_legacy(&tenant, &sandbox, &env, &services)
                .is_none()
        {
            report.unreadable.push(format!("env of {sandbox}"));
        }
    }
    for (id, tenant, saved) in db.saved_states()? {
        report.saved += 1;
        if crate::reseal::reseal_saved(sbox, &tenant, &id, &saved).is_none() {
            report.unreadable.push(format!("paused state of {id}"));
        }
    }
    let shared = if db.is_postgres() {
        db.shared_files()?
    } else {
        Vec::new()
    };
    for (name, sealed) in shared {
        report.shared_files += 1;
        if sbox.open(&crate::leader::label(&name), &sealed).is_none() {
            report.unreadable.push(format!("shared file {name}"));
        }
    }
    let files = [
        (crate::secrets::CA_KEY_FILE, crate::secrets::CA_LABEL),
        ("fleet/ca.key", FLEET_CA_LABEL),
    ];
    for (file, label) in files {
        let path = data.join(file);
        let sealed = match std::fs::read(&path) {
            Ok(sealed) => sealed,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        report.key_files.push(file);
        if sbox.open(label, &sealed).is_none() {
            report.unreadable.push(file.to_owned());
        }
    }
    Ok(report)
}

fn print(report: &Report) {
    let sandboxes = report
        .sandboxes
        .iter()
        .map(|(state, n)| format!("{n} {state}"))
        .collect::<Vec<_>>();
    println!("tenants: {}", report.tenants);
    println!("api keys: {}", report.keys);
    println!("templates: {}", report.templates);
    println!(
        "sandboxes: {}",
        if sandboxes.is_empty() {
            "none".to_owned()
        } else {
            sandboxes.join(", ")
        }
    );
    println!("secrets: {}", report.secrets);
    println!(
        "sealed env: {} start records, {} paused sandboxes",
        report.start_records, report.saved
    );
    println!("shared files in the database: {}", report.shared_files);
    println!("sealed key files: {}", report.key_files.join(", "));
    for what in &report.unreadable {
        println!("unreadable: {what}");
    }
    if report.unreadable.is_empty() {
        println!("ok: every sealed value can be read");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_values_sealed_under_another_key() {
        let dir = crate::reseal::tests::scratch_dir("check");
        let db = Db::memory().unwrap();
        let sbox = SecretBox::new(&[7; 32]).unwrap();
        let other = SecretBox::new(&[9; 32]).unwrap();
        db.put_template("base", "{}", 1).unwrap();
        db.insert_secret("TOKEN", "{}", &sbox.seal("secret:TOKEN", b"v").unwrap(), 1)
            .unwrap();
        crate::reseal::tests::persistent(&db, &sbox, "sbx_ok");
        std::fs::write(
            dir.join("egress-ca.key"),
            sbox.seal("egress-ca", b"pem").unwrap(),
        )
        .unwrap();

        let report = check(&db, &dir, &sbox).unwrap();
        assert_eq!(report.templates, 1);
        assert_eq!(report.secrets, 1);
        assert_eq!(report.start_records, 1);
        assert_eq!(report.sandboxes, vec![("paused".to_owned(), 1)]);
        assert_eq!(report.key_files, vec!["egress-ca.key"]);
        assert!(report.unreadable.is_empty(), "{:?}", report.unreadable);

        let report = check(&db, &dir, &other).unwrap();
        assert_eq!(
            report.unreadable,
            vec!["secret TOKEN", "env of sbx_ok", "egress-ca.key"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Runs deploy/backup.sh on a seeded data directory and database, wipes
    /// both, restores and reads everything back. Needs bash, gpg, tar,
    /// flock and sqlite3, and for Postgres (with
    /// `SPAWNBOX_TEST_DATABASE_URL`) psql, pg_dump and pg_restore. Runs
    /// only with `SPAWNBOX_TEST_BACKUP=1`. With `SPAWNBOX_TEST_API_BIN`, a
    /// built spawn-api, the script also runs its `check-data`.
    #[cfg(target_os = "linux")]
    #[test]
    fn backup_and_restore_round_trip() {
        if std::env::var("SPAWNBOX_TEST_BACKUP").as_deref() != Ok("1") {
            return;
        }
        round_trip(None);
        if let Ok(url) = std::env::var("SPAWNBOX_TEST_DATABASE_URL") {
            round_trip(Some(&url));
        }
    }

    #[cfg(target_os = "linux")]
    fn round_trip(admin_url: Option<&str>) {
        use std::process::Command;

        let dir = crate::reseal::tests::scratch_dir(if admin_url.is_some() {
            "backup-pg"
        } else {
            "backup-sqlite"
        });
        let data = dir.join("data");
        let psql = |sql: &str| {
            let status = Command::new("psql")
                .args(["-v", "ON_ERROR_STOP=1", "-qc", sql, admin_url.unwrap()])
                .status()
                .unwrap();
            assert!(status.success(), "{sql}");
        };
        let db_name = admin_url.map(|_| format!("spawnbox_backup_{}", std::process::id()));
        let url = admin_url.zip(db_name.as_deref()).map(|(admin, name)| {
            psql(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"));
            psql(&format!("CREATE DATABASE {name}"));
            with_database(admin, name)
        });
        let url = url.as_deref();

        let open = || {
            let db = crate::leader::open(&data, url, None).unwrap();
            let sbox = SecretBox::new(&std::fs::read(data.join("secrets.key")).unwrap()).unwrap();
            (db, sbox)
        };
        std::fs::create_dir(&data).unwrap();
        SecretBox::open_or_create(&data.join("secrets.key")).unwrap();
        let (db, sbox) = open();
        db.put_template("base", "{}", 1).unwrap();
        db.insert_secret(
            "TOKEN",
            "{}",
            &sbox.seal("secret:TOKEN", b"value").unwrap(),
            1,
        )
        .unwrap();
        crate::reseal::tests::persistent(&db, &sbox, "sbx_keep");
        crate::create_key(&db, None, Some("restore test")).unwrap();
        let ca = crate::secrets::egress_ca_pem(&data, &sbox).unwrap();
        if db.is_postgres() {
            crate::leader::push_shared(&db, &data, &sbox).unwrap();
        }
        drop(db);
        let key = std::fs::read(data.join("secrets.key")).unwrap();

        let passphrase = dir.join("passphrase");
        std::fs::write(&passphrase, "a test passphrase\n").unwrap();
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/backup.sh");
        let run_within = |seconds: u32, args: &[&str], passphrase: &std::path::Path| {
            let mut cmd = Command::new("timeout");
            cmd.args([&seconds.to_string(), "bash"])
                .arg(&script)
                .args(args)
                .env("SPAWNBOX_BACKUP_CONFIG", dir.join("none"))
                .env("SPAWNBOX_ENV_FILE", dir.join("none"))
                .env(
                    "SPAWNBOX_API_BIN",
                    std::env::var_os("SPAWNBOX_TEST_API_BIN")
                        .unwrap_or_else(|| dir.join("none").into()),
                )
                .env("SPAWNBOX_DATA_DIR", &data)
                .env("SPAWNBOX_BACKUP_TARGET", dir.join("backups"))
                .env("SPAWNBOX_BACKUP_KEEP", "1")
                .env("SPAWNBOX_BACKUP_PASSPHRASE_FILE", passphrase)
                .env("SPAWNBOX_BACKUP_METRICS_FILE", dir.join("backup.prom"))
                .env_remove("SPAWNBOX_DATABASE_URL");
            if let Some(url) = url {
                cmd.env("SPAWNBOX_DATABASE_URL", url);
            }
            cmd.output().unwrap()
        };
        let run = |args: &[&str], passphrase: &std::path::Path| run_within(300, args, passphrase);
        let ok = |out: std::process::Output| {
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        };

        // The first backup runs while another connection keeps writing, as
        // a busy server does. The database is large enough that a copy made
        // in steps (sqlite3 .backup) starts again after each write and does
        // not end in time; one read snapshot takes a few seconds.
        let writes = url.is_none().then(|| {
            let conn = rusqlite::Connection::open(data.join(crate::DB_FILE)).unwrap();
            conn.execute_batch(
                "CREATE TABLE busy (n INTEGER, pad BLOB);
                 WITH RECURSIVE i(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM i WHERE n < 20000)
                 INSERT INTO busy SELECT n, zeroblob(4000) FROM i;",
            )
            .unwrap();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let writer = std::thread::spawn({
                let stop = stop.clone();
                move || {
                    let mut n = 0;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        conn.execute("UPDATE busy SET n = n + 1 WHERE rowid = 1", ())
                            .unwrap();
                        n += 1;
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    n
                }
            });
            (stop, writer)
        });
        ok(run_within(60, &[], &passphrase));
        if let Some((stop, writer)) = writes {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            assert!(writer.join().unwrap() > 0);
        }
        // Backups are named by the second.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        ok(run(&[], &passphrase));
        let backups: Vec<_> = std::fs::read_dir(dir.join("backups"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(backups.len(), 1, "{backups:?}");
        let archive = std::fs::read(dir.join("backups").join(&backups[0])).unwrap();
        assert!(
            !archive.windows(key.len()).any(|w| w == key),
            "secrets.key in plain"
        );
        assert!(
            std::fs::read_to_string(dir.join("backup.prom"))
                .unwrap()
                .contains("spawnbox_backup_last_success_timestamp_seconds ")
        );
        assert!(!data.join(".backup").exists());

        // A restore over live data needs --force.
        assert!(!run(&["--restore", "latest"], &passphrase).status.success());

        std::fs::remove_dir_all(&data).unwrap();
        std::fs::create_dir(&data).unwrap();
        if let Some(name) = &db_name {
            psql(&format!("DROP DATABASE {name} WITH (FORCE)"));
            psql(&format!("CREATE DATABASE {name}"));
        }
        let wrong = dir.join("wrong");
        std::fs::write(&wrong, "another passphrase\n").unwrap();
        assert!(!run(&["--restore", "latest"], &wrong).status.success());
        assert!(!data.join("secrets.key").exists());
        ok(run(&["--restore", "latest"], &passphrase));

        assert_eq!(std::fs::read(data.join("secrets.key")).unwrap(), key);
        let (db, sbox) = open();
        let report = check(&db, &data, &sbox).unwrap();
        assert!(report.unreadable.is_empty(), "{:?}", report.unreadable);
        assert_eq!(
            (
                report.templates,
                report.keys,
                report.secrets,
                report.start_records
            ),
            (1, 1, 1, 1)
        );
        assert_eq!(report.sandboxes, vec![("paused".to_owned(), 1)]);
        assert_eq!(report.shared_files, if url.is_some() { 2 } else { 0 });
        let start = db.get_start_record("sbx_keep").unwrap().unwrap();
        assert_eq!(
            sbox.open_sandbox_env("acme", "sbx_keep", &start.env),
            Some(crate::reseal::tests::plain())
        );
        let secret = &db.list_secrets().unwrap()[0];
        assert_eq!(sbox.open("secret:TOKEN", &secret.value).unwrap(), b"value");
        assert_eq!(crate::secrets::egress_ca_pem(&data, &sbox).unwrap(), ca);
        drop(db);

        // --force replaces what is there and keeps the old files. With
        // Postgres, it refuses while a primary holds the lease, and drops
        // tables that the backup does not have.
        std::fs::write(data.join("egress-ca.crt"), "changed").unwrap();
        let in_db = |sql: &str| {
            let out = Command::new("psql")
                .args(["-v", "ON_ERROR_STOP=1", "-tAc", sql, url.unwrap()])
                .output()
                .unwrap();
            assert!(out.status.success(), "{sql}");
            String::from_utf8(out.stdout).unwrap().trim().to_owned()
        };
        if url.is_some() {
            in_db(
                "INSERT INTO leader (id, holder, term, expires_at)
                 VALUES (1, 'host_other', 1, now() + interval '1 hour')
                 ON CONFLICT (id) DO UPDATE SET holder = excluded.holder,
                     expires_at = excluded.expires_at",
            );
            in_db("CREATE TABLE added_later (id INTEGER)");
            let out = run(&["--restore", "latest", "--force"], &passphrase);
            assert!(!out.status.success());
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(stderr.contains("held by host_other"), "{stderr}");
            ok(run(
                &["--restore", "latest", "--ignore-lease", "--force"],
                &passphrase,
            ));
            assert_eq!(in_db("SELECT to_regclass('added_later') IS NULL"), "t");
            assert_eq!(in_db("SELECT count(*) FROM leader"), "0");
        } else {
            ok(run(&["--restore", "latest", "--force"], &passphrase));
        }
        assert_eq!(
            std::fs::read_to_string(data.join("egress-ca.crt.pre-restore")).unwrap(),
            "changed"
        );
        let (db, sbox) = open();
        assert!(check(&db, &data, &sbox).unwrap().unreadable.is_empty());
        assert_eq!(db.list_templates().unwrap().len(), 1);
        assert_eq!(crate::secrets::egress_ca_pem(&data, &sbox).unwrap(), ca);
        drop(db);

        if let Some(name) = &db_name {
            psql(&format!("DROP DATABASE {name} WITH (FORCE)"));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `url` with its database name replaced by `name`.
    #[cfg(target_os = "linux")]
    fn with_database(url: &str, name: &str) -> String {
        let (base, query) = url
            .split_once('?')
            .map_or((url, None), |(b, q)| (b, Some(q)));
        let host_end = base.find("://").map_or(0, |i| i + 3);
        let base = match base[host_end..].find('/') {
            Some(slash) => &base[..host_end + slash],
            None => base,
        };
        match query {
            Some(query) => format!("{base}/{name}?{query}"),
            None => format!("{base}/{name}"),
        }
    }

    #[test]
    fn refuses_another_schema_version_and_leaves_it() {
        let dir = crate::reseal::tests::scratch_dir("check-version");
        std::fs::write(dir.join("secrets.key"), [7; 32]).unwrap();
        let path = dir.join(crate::DB_FILE);
        drop(Db::open(&path).unwrap());
        run(&dir, None, None, None).unwrap();

        let version = |set: Option<i64>| {
            let conn = rusqlite::Connection::open(&path).unwrap();
            if let Some(v) = set {
                conn.pragma_update(None, "user_version", v).unwrap();
            }
            conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap()
        };
        let current = version(None);
        for other in [current - 1, current + 1] {
            version(Some(other));
            let error = run(&dir, None, None, None).unwrap_err();
            assert!(format!("{error:#}").contains("schema version"), "{error:#}");
            assert_eq!(version(None), other);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn creates_nothing_that_is_missing() {
        let dir = crate::reseal::tests::scratch_dir("check-missing");
        let error = run(&dir, None, None, None).unwrap_err();
        assert!(format!("{error:#}").contains("secrets.key"), "{error:#}");
        std::fs::write(dir.join("secrets.key"), [7; 32]).unwrap();
        let error = run(&dir, None, None, None).unwrap_err();
        assert!(error.to_string().contains("no database"), "{error}");
        assert!(!dir.join(crate::DB_FILE).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
