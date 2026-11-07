//! Pulls an OCI image and unpacks it, ready to boot, into an empty disk.
//!
//! The image is untrusted. Every path is kept inside the destination:
//! `tar` refuses entries that leave it, and the agent's own writes walk
//! each directory without following symbolic links.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::{PermissionsExt, chown};
use std::path::{Component, Path, PathBuf};

use oci_client::client::{Certificate, CertificateEncoding, ClientConfig, linux_amd64_resolver};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use spawn_proto::guest::v1::{UnpackEvent, UnpackRequest, unpack_event};
use tokio::sync::mpsc;
use tonic::Status;

const WHITEOUT: &str = ".wh.";
const OPAQUE: &str = ".wh..wh..opq";
const PULL_DIR: &str = ".spawnbox-pull";
const GUEST_PATH: &str = "usr/local/bin/spawn-guest";
const ENV_FILE: &str = "etc/profile.d/00-spawnbox-image.sh";
const USER_ID: u32 = 1000;
/// Files the host's network needs, copied from the builder VM, which runs
/// on that network. Images rarely have them: container runtimes add them.
const NETWORK_FILES: [&str; 2] = ["etc/resolv.conf", "etc/hosts"];

type Events = mpsc::Sender<Result<UnpackEvent, Status>>;

/// Runs the unpack in the background and streams its progress.
pub fn start(req: UnpackRequest) -> mpsc::Receiver<Result<UnpackEvent, Status>> {
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(async move {
        if let Err(error) = run(&req, &tx).await {
            let _ = tx.send(Err(Status::internal(error))).await;
        }
    });
    rx
}

async fn say(tx: &Events, line: String) {
    let event = unpack_event::Event::Line(line);
    let _ = tx.send(Ok(UnpackEvent { event: Some(event) })).await;
}

async fn run(req: &UnpackRequest, tx: &Events) -> Result<(), String> {
    let reference: Reference = req
        .reference
        .parse()
        .map_err(|e| format!("image reference {:?}: {e}", req.reference))?;
    let dest = PathBuf::from(&req.dest);
    // The disk is empty but for ext4's lost+found.
    if fs::read_dir(&dest)
        .map_err(|e| format!("{}: {e}", dest.display()))?
        .flatten()
        .any(|e| e.file_name() != "lost+found")
    {
        return Err(format!("{} is not empty", dest.display()));
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut config = ClientConfig {
        platform_resolver: Some(Box::new(linux_amd64_resolver)),
        ..ClientConfig::default()
    };
    if !req.extra_ca_pem.is_empty() {
        config.extra_root_certificates.push(Certificate {
            encoding: CertificateEncoding::Pem,
            data: req.extra_ca_pem.clone().into_bytes(),
        });
    }
    let client = Client::new(config);
    // A registry secret, if any, is added by the egress proxy.
    let (manifest, digest, image_config) = client
        .pull_manifest_and_config(&reference, &RegistryAuth::Anonymous)
        .await
        .map_err(|e| format!("pull {reference}: {e}"))?;
    say(
        tx,
        format!(
            "pulling {reference} ({digest}), {} layers",
            manifest.layers.len()
        ),
    )
    .await;
    let pull = dest.join(PULL_DIR);
    fs::create_dir(&pull).map_err(|e| format!("{}: {e}", pull.display()))?;
    for (i, layer) in manifest.layers.iter().enumerate() {
        let compression = Compression::of(&layer.media_type)?;
        let blob = pull.join(i.to_string());
        let file = tokio::fs::File::create(&blob)
            .await
            .map_err(|e| e.to_string())?;
        client
            .pull_blob(&reference, layer, file)
            .await
            .map_err(|e| format!("layer {}: {e}", layer.digest))?;
        let size = fs::metadata(&blob).map_or(0, |m| m.len());
        say(
            tx,
            format!(
                "layer {}/{}: {} MiB",
                i + 1,
                manifest.layers.len(),
                size >> 20
            ),
        )
        .await;
        let (into, from) = (dest.clone(), blob.clone());
        tokio::task::spawn_blocking(move || apply_layer(&from, compression, &into))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| format!("layer {}: {e}", layer.digest))?;
        let _ = fs::remove_file(&blob);
    }
    let _ = fs::remove_dir_all(&pull);
    let into = dest.clone();
    tokio::task::spawn_blocking(move || make_bootable(&into, &image_config))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("prepare the image: {e}"))?;
    nix::unistd::sync();
    say(tx, "image unpacked".to_owned()).await;
    let event = unpack_event::Event::Digest(digest);
    let _ = tx.send(Ok(UnpackEvent { event: Some(event) })).await;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Compression {
    None,
    Gzip,
    Zstd,
}

impl Compression {
    fn of(media_type: &str) -> Result<Self, String> {
        if media_type.ends_with("+gzip") || media_type.ends_with(".tar.gzip") {
            Ok(Self::Gzip)
        } else if media_type.ends_with("+zstd") {
            Ok(Self::Zstd)
        } else if media_type.ends_with(".tar") || media_type.ends_with("diff.tar") {
            Ok(Self::None)
        } else {
            Err(format!("unsupported layer type {media_type}"))
        }
    }

    fn open(self, path: &Path) -> io::Result<Box<dyn Read>> {
        let file = BufReader::new(File::open(path)?);
        Ok(match self {
            Self::None => Box::new(file),
            Self::Gzip => Box::new(flate2::read::GzDecoder::new(file)),
            Self::Zstd => Box::new(
                ruzstd::decoding::StreamingDecoder::new(file)
                    .map_err(|e| io::Error::other(e.to_string()))?,
            ),
        })
    }
}

/// Applies one layer: first its deletions, then its files.
fn apply_layer(blob: &Path, compression: Compression, dest: &Path) -> io::Result<()> {
    let mut archive = tar::Archive::new(compression.open(blob)?);
    for entry in archive.entries()? {
        let entry = entry?;
        let path = clean(&entry.path()?)?;
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let parent = path.parent().unwrap_or(Path::new(""));
        if name == OPAQUE {
            if let Some(dir) = walk(dest, parent)? {
                for child in fs::read_dir(&dir)? {
                    remove(&child?.path())?;
                }
            }
        } else if let Some(hidden) = name.strip_prefix(WHITEOUT)
            && let Some(dir) = walk(dest, parent)?
        {
            remove(&dir.join(hidden))?;
        }
    }

    let mut archive = tar::Archive::new(compression.open(blob)?);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(true);
    archive.set_overwrite(true);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = clean(&entry.path()?)?;
        let whiteout = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(WHITEOUT));
        if whiteout || path.as_os_str().is_empty() {
            continue;
        }
        if !entry.unpack_in(dest)? {
            return Err(io::Error::other(format!(
                "{} leaves the image",
                path.display()
            )));
        }
    }
    Ok(())
}

/// A tar path made relative. Refuses `..`.
fn clean(path: &Path) -> io::Result<PathBuf> {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(p) => out.push(p),
            Component::CurDir | Component::RootDir => {}
            _ => {
                return Err(io::Error::other(format!(
                    "{} leaves the image",
                    path.display()
                )));
            }
        }
    }
    Ok(out)
}

/// `dest/rel` if every directory on the way is a real directory, not a
/// link. `None` if one is missing or a link.
fn walk(dest: &Path, rel: &Path) -> io::Result<Option<PathBuf>> {
    let mut at = dest.to_owned();
    for part in clean(rel)?.components() {
        at.push(part);
        match fs::symlink_metadata(&at) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        }
    }
    Ok(Some(at))
}

/// Like `walk`, but makes missing directories.
fn make_dirs(dest: &Path, rel: &Path, mode: u32) -> io::Result<PathBuf> {
    let mut at = dest.to_owned();
    for part in clean(rel)?.components() {
        at.push(part);
        match fs::symlink_metadata(&at) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(io::Error::other(format!(
                    "/{} in the image is not a directory",
                    rel.display()
                )));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&at)?;
                fs::set_permissions(&at, fs::Permissions::from_mode(mode))?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(at)
}

/// A file the agent writes in the image: its directory is made, and a
/// link in its place is refused.
fn own_file(dest: &Path, rel: &str) -> io::Result<PathBuf> {
    let rel = Path::new(rel);
    let dir = make_dirs(dest, rel.parent().unwrap_or(Path::new("")), 0o755)?;
    let path = dir.join(rel.file_name().unwrap_or_default());
    if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(io::Error::other(format!(
            "/{} in the image is a link",
            rel.display()
        )));
    }
    Ok(path)
}

fn remove(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn exists(dest: &Path, rel: &str) -> bool {
    fs::symlink_metadata(dest.join(rel)).is_ok()
}

/// Adds what Spawnbox needs to boot and run commands in the image.
fn make_bootable(dest: &Path, image_config: &str) -> io::Result<()> {
    if !exists(dest, "bin/sh") {
        return Err(io::Error::other(
            "the image has no /bin/sh, so commands cannot run in it",
        ));
    }
    let guest = own_file(dest, GUEST_PATH)?;
    let _ = fs::remove_file(&guest);
    fs::copy("/proc/self/exe", &guest)?;
    fs::set_permissions(&guest, fs::Permissions::from_mode(0o755))?;

    for dir in [
        "spawn/upper",
        "spawn/layer",
        "spawn/newroot",
        "spawn/oldroot",
        "spawn/vol/0",
        "spawn/vol/1",
        "spawn/vol/2",
        "spawn/vol/3",
        "proc",
        "sys",
        "dev",
        "run",
        "etc",
    ] {
        make_dirs(dest, Path::new(dir), 0o755)?;
    }
    for rel in NETWORK_FILES {
        let etc = make_dirs(dest, Path::new("etc"), 0o755)?;
        let path = etc.join(Path::new(rel).file_name().unwrap_or_default());
        // A link, such as systemd's resolv.conf, is replaced.
        if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            fs::remove_file(&path)?;
        }
        fs::write(path, fs::read(Path::new("/").join(rel))?)?;
    }
    let tmp = make_dirs(dest, Path::new("tmp"), 0o1777)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o1777))?;

    let shell = if exists(dest, "bin/bash") {
        "/bin/bash"
    } else {
        "/bin/sh"
    };
    let passwd = own_file(dest, "etc/passwd")?;
    let users = fs::read_to_string(&passwd).unwrap_or_default();
    if !users.lines().any(|l| l.starts_with("user:")) {
        append(
            &passwd,
            &users,
            &format!("user:x:{USER_ID}:{USER_ID}:user:/home/user:{shell}"),
        )?;
    }
    let group = own_file(dest, "etc/group")?;
    let groups = fs::read_to_string(&group).unwrap_or_default();
    let has_gid = groups
        .lines()
        .any(|l| l.split(':').nth(2) == Some(&USER_ID.to_string()));
    if !has_gid {
        append(&group, &groups, &format!("user:x:{USER_ID}:"))?;
    }
    for dir in ["home/user", "workspace"] {
        let at = make_dirs(dest, Path::new(dir), 0o755)?;
        chown(&at, Some(USER_ID), Some(USER_ID))?;
    }

    let env = image_env(image_config);
    if !env.is_empty() {
        let mut script = String::from("# The image's environment.\n");
        for (key, value) in env {
            script.push_str(&format!(
                "export {key}='{}'\n",
                value.replace('\'', "'\\''")
            ));
        }
        fs::write(own_file(dest, ENV_FILE)?, script)?;
        let profile = own_file(dest, "etc/profile")?;
        if !profile.exists() {
            fs::write(
                profile,
                "for f in /etc/profile.d/*.sh; do [ -r \"$f\" ] && . \"$f\"; done\n",
            )?;
        }
    }
    chown(dest, Some(0), Some(0))?;
    fs::set_permissions(dest, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn append(path: &Path, old: &str, line: &str) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if !old.is_empty() && !old.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    writeln!(file, "{line}")
}

/// `KEY=value` pairs from the image config, with valid shell names.
fn image_env(config: &str) -> Vec<(String, String)> {
    let parsed: serde_json::Value = serde_json::from_str(config).unwrap_or_default();
    parsed["config"]["Env"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str()?.split_once('='))
        .filter(|(k, _)| {
            !k.is_empty()
                && !k.starts_with(|c: char| c.is_ascii_digit())
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("spawn-unpack-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn layer(path: &Path, files: &[(&str, Option<&[u8]>)]) {
        let mut builder = tar::Builder::new(File::create(path).unwrap());
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_uid(nix::unistd::getuid().as_raw().into());
            header.set_gid(nix::unistd::getgid().as_raw().into());
            header.set_mtime(0);
            match data {
                Some(data) => {
                    header.set_size(data.len() as u64);
                    header.set_mode(0o644);
                    header.set_entry_type(tar::EntryType::Regular);
                    builder.append_data(&mut header, name, *data).unwrap();
                }
                None => {
                    header.set_size(0);
                    header.set_mode(0o755);
                    header.set_entry_type(tar::EntryType::Directory);
                    builder.append_data(&mut header, name, &[][..]).unwrap();
                }
            }
        }
        builder.finish().unwrap();
    }

    #[test]
    fn applies_whiteouts_and_opaque_directories() {
        let root = temp("wh");
        let dest = root.join("dest");
        fs::create_dir(&dest).unwrap();
        let (one, two) = (root.join("1.tar"), root.join("2.tar"));
        layer(
            &one,
            &[
                ("etc/", None),
                ("etc/a", Some(b"a")),
                ("etc/b", Some(b"b")),
                ("opt/", None),
                ("opt/old", Some(b"old")),
            ],
        );
        layer(
            &two,
            &[
                ("etc/.wh.a", Some(b"")),
                ("opt/new", Some(b"new")),
                ("opt/.wh..wh..opq", Some(b"")),
            ],
        );
        apply_layer(&one, Compression::None, &dest).unwrap();
        apply_layer(&two, Compression::None, &dest).unwrap();
        assert!(!dest.join("etc/a").exists());
        assert_eq!(fs::read(dest.join("etc/b")).unwrap(), b"b");
        assert!(!dest.join("opt/old").exists());
        assert_eq!(fs::read(dest.join("opt/new")).unwrap(), b"new");
        assert!(!dest.join("opt/.wh..wh..opq").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn keeps_writes_inside_the_image() {
        let root = temp("esc");
        let (dest, outside) = (root.join("dest"), root.join("outside"));
        fs::create_dir_all(&dest).unwrap();
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, dest.join("etc")).unwrap();
        assert!(clean(Path::new("../x")).is_err());
        assert!(own_file(&dest, "etc/passwd").is_err());
        assert_eq!(walk(&dest, Path::new("etc")).unwrap(), None);
        let evil = root.join("evil.tar");
        layer(&evil, &[("etc/passwd", Some(b"root::0:0"))]);
        assert!(apply_layer(&evil, Compression::None, &dest).is_err());
        assert!(!outside.join("passwd").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reads_the_image_env() {
        let env = image_env(
            r#"{"config":{"Env":["PATH=/usr/bin","NODE_VERSION=22","bad-key=x","1X=y"]}}"#,
        );
        assert_eq!(
            env,
            vec![
                ("PATH".to_owned(), "/usr/bin".to_owned()),
                ("NODE_VERSION".to_owned(), "22".to_owned())
            ]
        );
    }
}
