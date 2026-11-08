//! A Firecracker pause can save only the guest memory written since the VM
//! was loaded (`vm.diff`), which is much less to write than all of it. The
//! memory it was loaded from is kept next to it as `vm.base`. Before the
//! sandbox resumes or moves, `finish_paused` writes them together into
//! `vm.mem`, a full snapshot again.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Context, Result, bail};
use nix::errno::Errno;
use nix::unistd::{Whence, lseek};

pub(crate) const DIFF: &str = "vm.diff";
pub(crate) const BASE: &str = "vm.base";
const MEMORY: &str = "vm.mem";
/// `vm.base` with `vm.diff` partly or fully written over it.
const MERGING: &str = "vm.mem.merging";
/// A copy of a shared `vm.base`, until it is complete.
const COPYING: &str = "vm.mem.copying";

static BUSY: LazyLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = LazyLock::new(Mutex::default);

/// Makes `dir/vm.mem` from `vm.base` and `vm.diff` if a pause left them.
/// Blocks; safe to call at the same time, and again after a crash.
pub fn finish_paused(dir: &Path) -> Result<()> {
    let lock = Arc::clone(
        BUSY.lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(dir.to_owned())
            .or_default(),
    );
    let merged = {
        let _merging = lock.lock().unwrap_or_else(|e| e.into_inner());
        merge(dir)
    };
    BUSY.lock().unwrap_or_else(|e| e.into_inner()).remove(dir);
    merged.with_context(|| format!("merge the memory of {}", dir.display()))
}

fn merge(dir: &Path) -> Result<()> {
    let (diff, base) = (dir.join(DIFF), dir.join(BASE));
    let merging = dir.join(MERGING);
    if !diff.exists() {
        return Ok(());
    }
    if !merging.exists() {
        // Only this sandbox had the memory it resumed from: write over it.
        // A template's memory is shared with other sandboxes: copy it.
        if std::fs::metadata(&base)?.nlink() == 1 {
            std::fs::rename(&base, &merging)?;
        } else {
            let copying = dir.join(COPYING);
            let status = std::process::Command::new("cp")
                .args(["--sparse=always", "--reflink=auto"])
                .arg(&base)
                .arg(&copying)
                .status()
                .context("run cp")?;
            if !status.success() {
                bail!("cp {} exited with {status}", base.display());
            }
            std::fs::rename(&copying, &merging)?;
        }
    }
    overlay(&diff, &merging)?;
    std::fs::set_permissions(&merging, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(&merging, dir.join(MEMORY))?;
    for name in [BASE, DIFF] {
        match std::fs::remove_file(dir.join(name)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Writes the data of sparse file `diff` over `dest` at the same offsets.
fn overlay(diff: &Path, dest: &Path) -> Result<()> {
    let src = File::open(diff)?;
    let dst = OpenOptions::new().write(true).open(dest)?;
    let len = i64::try_from(src.metadata()?.len())?;
    let mut buf = vec![0u8; 1 << 20];
    let mut at = 0i64;
    while at < len {
        let start = match lseek(src.as_fd(), at, Whence::SeekData) {
            Ok(start) => start,
            Err(Errno::ENXIO) => break,
            Err(errno) => return Err(errno.into()),
        };
        let end = lseek(src.as_fd(), start, Whence::SeekHole)?;
        let mut pos = u64::try_from(start)?;
        let end_u = u64::try_from(end)?;
        while pos < end_u {
            let n = usize::try_from((end_u - pos).min(buf.len() as u64))?;
            src.read_exact_at(&mut buf[..n], pos)?;
            dst.write_all_at(&buf[..n], pos)?;
            pos += n as u64;
        }
        at = end;
    }
    dst.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("spawn-diff-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sparse(path: &Path, len: u64, writes: &[(u64, &[u8])]) {
        let file = File::create(path).unwrap();
        file.set_len(len).unwrap();
        for (at, data) in writes {
            file.write_all_at(data, *at).unwrap();
        }
    }

    #[test]
    fn merges_over_a_private_base_and_copies_a_shared_one() {
        const LEN: u64 = 1 << 21;
        for shared in [false, true] {
            let dir = temp_dir(if shared { "shared" } else { "private" });
            let template = dir.join("template.mem");
            std::fs::write(&template, vec![7u8; LEN as usize]).unwrap();
            std::fs::hard_link(&template, dir.join(BASE)).unwrap();
            if !shared {
                std::fs::remove_file(&template).unwrap();
            }
            let page = vec![1u8; 4096];
            sparse(&dir.join(DIFF), LEN, &[(0, &page), (1 << 20, &page)]);
            finish_paused(&dir).unwrap();
            finish_paused(&dir).unwrap();
            let mem = std::fs::read(dir.join(MEMORY)).unwrap();
            assert_eq!(&mem[..4096], &page[..]);
            assert_eq!(mem[4096], 7);
            assert_eq!(&mem[1 << 20..(1 << 20) + 4096], &page[..]);
            assert!(!dir.join(DIFF).exists() && !dir.join(BASE).exists());
            if shared {
                assert_eq!(std::fs::read(&template).unwrap(), vec![7u8; LEN as usize]);
            }
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}
