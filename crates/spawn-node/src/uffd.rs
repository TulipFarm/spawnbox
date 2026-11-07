//! Serves a restored VM's memory through userfaultfd, so the VM can run
//! before its memory file is complete.
//!
//! During `PUT /snapshot/load` with the `Uffd` backend, Firecracker
//! connects to `uffd.sock` in its jail and sends its guest memory regions
//! as JSON, with the userfaultfd. Then each first touch of a page waits
//! until the handler copies data in. The handler copies the whole part
//! that holds the page, so nearby touches do not fault again.

use std::fs::File;
use std::io::{IoSliceMut, Read};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{Signal, kill};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
use nix::unistd::Pid;
use tokio::sync::oneshot;

/// How long a fault may wait for its part before the VM is stopped.
pub const PART_WAIT: Duration = Duration::from_secs(30);
const PAGE: u64 = 4096;
/// How long Firecracker has to connect after the pager starts.
const CONNECT_WAIT: Duration = Duration::from_secs(30);
const EVENT_PAGEFAULT: u8 = 0x12;
const EVENT_REMOVE: u8 = 0x15;
const MSG_BYTES: usize = 32;

/// Where a VM's memory comes from.
pub trait PageSource: Send + Sync + 'static {
    /// The size of a part. A multiple of the page size.
    fn part_bytes(&self) -> u64;
    /// Waits up to `timeout` for part `i`, then reads it into `buf`, which
    /// is as long as the part. False if the part is only zeros; `buf` is
    /// not changed then.
    fn read(&self, i: u32, buf: &mut [u8], timeout: Duration) -> Result<bool>;
}

/// A complete memory file.
pub struct LocalFile(File);

impl LocalFile {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self(
            File::open(path).with_context(|| format!("open {}", path.display()))?,
        ))
    }
}

impl PageSource for LocalFile {
    fn part_bytes(&self) -> u64 {
        2 * 1024 * 1024
    }

    fn read(&self, i: u32, buf: &mut [u8], _: Duration) -> Result<bool> {
        self.0
            .read_exact_at(buf, u64::from(i) * self.part_bytes())?;
        Ok(true)
    }
}

/// Serves one VM's page faults on its own thread. The thread ends when the
/// pager is dropped, or when Firecracker goes away.
pub struct Pager {
    stop: Arc<AtomicBool>,
    touched: Arc<Mutex<Vec<u32>>>,
    lost: Option<oneshot::Receiver<String>>,
}

impl Pager {
    /// Listens on `path` for Firecracker, which runs as `uid` with process
    /// ID `pid`. If a part cannot be served, the pager kills `pid` and
    /// reports why on `take_lost`.
    pub fn start(path: &Path, uid: u32, pid: u32, source: Arc<dyn PageSource>) -> Result<Self> {
        let listener =
            UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        std::os::unix::fs::chown(path, Some(uid), Some(uid))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let touched = Arc::new(Mutex::new(Vec::new()));
        let (tell, lost) = oneshot::channel();
        let (stop2, touched2) = (Arc::clone(&stop), Arc::clone(&touched));
        std::thread::Builder::new()
            .name("pager".into())
            .spawn(move || {
                let result = serve(&listener, source.as_ref(), &stop2, &touched2);
                if let Err(error) = result
                    && !stop2.load(Ordering::SeqCst)
                {
                    let pid = i32::try_from(pid).unwrap_or(i32::MAX);
                    let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
                    let _ = tell.send(format!("{error:#}"));
                }
            })?;
        Ok(Self {
            stop,
            touched,
            lost: Some(lost),
        })
    }

    /// The parts served for faults, in the order of the faults.
    pub fn touched(&self) -> Vec<u32> {
        self.touched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Gets a message if the pager had to stop the VM. Once only.
    pub fn take_lost(&mut self) -> Option<oneshot::Receiver<String>> {
        self.lost.take()
    }
}

impl Drop for Pager {
    fn drop(&mut self) {
        // The thread sees it within a poll interval, or after a wait for
        // a part ends.
        self.stop.store(true, Ordering::SeqCst);
    }
}

struct Region {
    base: u64,
    size: u64,
    offset: u64,
}

fn serve(
    listener: &UnixListener,
    source: &dyn PageSource,
    stop: &AtomicBool,
    touched: &Mutex<Vec<u32>>,
) -> Result<()> {
    let deadline = Instant::now() + CONNECT_WAIT;
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!("Firecracker did not connect to the page handler");
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let (regions, uffd) = handshake(stream.as_raw_fd())?;
    // Firecracker keeps its end open; so does this, until the VM is gone.
    let _stream = stream;
    let mut uffd = File::from(uffd);
    let size = regions.iter().map(|r| r.offset + r.size).max().unwrap_or(0);
    let part = source.part_bytes();
    if part == 0 || !part.is_multiple_of(PAGE) {
        bail!("bad part size {part}");
    }
    let mut done = vec![false; usize::try_from(size.div_ceil(part))?];
    let mut removed: Vec<(u64, u64)> = Vec::new();
    let mut buf = vec![0; usize::try_from(part)?];
    let mut events = [0u8; MSG_BYTES * 16];
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        let mut fds = [PollFd::new(uffd.as_fd(), PollFlags::POLLIN)];
        poll(&mut fds, PollTimeout::from(100u16))?;
        let revents = fds[0].revents().unwrap_or(PollFlags::empty());
        if revents.intersects(PollFlags::POLLERR | PollFlags::POLLHUP) {
            return Ok(());
        }
        let n = match uffd.read(&mut events) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error.into()),
        };
        for msg in events[..n].as_chunks::<MSG_BYTES>().0 {
            let word =
                |at: usize| u64::from_le_bytes(msg[at..at + 8].try_into().unwrap_or_default());
            match msg[0] {
                EVENT_PAGEFAULT => {
                    let page = word(16) & !(PAGE - 1);
                    let fd = uffd.as_raw_fd();
                    if removed.iter().any(|&(s, e)| (s..e).contains(&page)) {
                        // The guest gave the page back; it reads as zeros.
                        fill(fd, page, PAGE, None)?;
                        continue;
                    }
                    let offset = regions
                        .iter()
                        .find(|r| (r.base..r.base + r.size).contains(&page))
                        .map(|r| r.offset + (page - r.base))
                        .with_context(|| format!("fault at {page:#x} is outside guest memory"))?;
                    let i = usize::try_from(offset / part)?;
                    if done[i] {
                        // Faulted again before the copy woke it.
                        wake(fd, page, PAGE)?;
                        continue;
                    }
                    let index = u32::try_from(i)?;
                    let start = u64::from(index) * part;
                    let len = usize::try_from(part.min(size - start))?;
                    let data = source
                        .read(index, &mut buf[..len], PART_WAIT)
                        .with_context(|| format!("memory part {index} is not available"))?;
                    for r in &regions {
                        let from = start.max(r.offset);
                        let to = (start + len as u64).min(r.offset + r.size);
                        if from >= to {
                            continue;
                        }
                        let dst = r.base + (from - r.offset);
                        let src = if data {
                            let at = usize::try_from(from - start)?;
                            Some(&buf[at..at + usize::try_from(to - from)?])
                        } else {
                            None
                        };
                        fill(fd, dst, to - from, src)?;
                    }
                    done[i] = true;
                    touched
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(index);
                }
                EVENT_REMOVE => removed.push((word(8), word(16))),
                // Firecracker uses no other events.
                _ => {}
            }
        }
    }
}

/// Receives the regions and the userfaultfd.
fn handshake(socket: RawFd) -> Result<(Vec<Region>, OwnedFd)> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut space = nix::cmsg_space!(RawFd);
    let (bytes, fds) = {
        let mut iov = [IoSliceMut::new(&mut buf)];
        let msg = recvmsg::<()>(
            socket,
            &mut iov,
            Some(&mut space),
            MsgFlags::MSG_CMSG_CLOEXEC,
        )
        .context("receive the userfaultfd")?;
        let mut fds = Vec::new();
        for cmsg in msg.cmsgs()? {
            if let ControlMessageOwned::ScmRights(rights) = cmsg {
                fds.extend(rights);
            }
        }
        (msg.bytes, fds)
    };
    // SAFETY: the kernel just gave these descriptors to this process, and
    // nothing else owns them.
    let mut owned = fds
        .into_iter()
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    let uffd = owned.next().context("Firecracker sent no userfaultfd")?;
    let json: serde_json::Value =
        serde_json::from_slice(&buf[..bytes]).context("Firecracker sent bad memory regions")?;
    let field = |v: &serde_json::Value, name: &str| {
        v.get(name)
            .and_then(serde_json::Value::as_u64)
            .with_context(|| format!("memory region has no {name}"))
    };
    let mut regions = Vec::new();
    for v in json.as_array().context("memory regions are not a list")? {
        if field(v, "page_size")? != PAGE {
            bail!("only {PAGE}-byte pages are supported");
        }
        regions.push(Region {
            base: field(v, "base_host_virt_addr")?,
            size: field(v, "size")?,
            offset: field(v, "offset")?,
        });
    }
    Ok((regions, uffd))
}

#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}

#[repr(C)]
struct UffdioCopy {
    dst: u64,
    src: u64,
    len: u64,
    mode: u64,
    copy: i64,
}

#[repr(C)]
struct UffdioZeropage {
    range: UffdioRange,
    mode: u64,
    zeropage: i64,
}

nix::ioctl_read!(uffdio_wake, 0xAA, 0x02, UffdioRange);
nix::ioctl_readwrite!(uffdio_copy, 0xAA, 0x03, UffdioCopy);
nix::ioctl_readwrite!(uffdio_zeropage, 0xAA, 0x04, UffdioZeropage);

/// Fills `len` bytes of guest memory at `dst` with `src`, or zeros, and
/// wakes the threads waiting there. Pages that are already there are kept.
fn fill(fd: RawFd, dst: u64, len: u64, src: Option<&[u8]>) -> Result<()> {
    if fill_once(fd, dst, len, src).is_ok() {
        return Ok(());
    }
    // Some pages are there already, or memory changed meanwhile: go page by
    // page.
    let page_len = usize::try_from(PAGE)?;
    for at in (0..len).step_by(page_len) {
        let from = usize::try_from(at)?;
        let page = src.map(|s| &s[from..from + page_len]);
        let mut tries = 0;
        loop {
            match fill_once(fd, dst + at, PAGE, page) {
                Ok(()) | Err(nix::errno::Errno::EEXIST) => break,
                Err(nix::errno::Errno::EAGAIN) if tries < 100 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(errno) => bail!("fill guest memory at {:#x}: {errno}", dst + at),
            }
        }
    }
    wake(fd, dst, len)
}

fn fill_once(fd: RawFd, dst: u64, len: u64, src: Option<&[u8]>) -> nix::Result<()> {
    // SAFETY: the ioctls only read `src`, which is `len` bytes long, and
    // write the structs given; the guest memory belongs to Firecracker.
    unsafe {
        match src {
            Some(src) => {
                let mut copy = UffdioCopy {
                    dst,
                    src: src.as_ptr() as u64,
                    len,
                    mode: 0,
                    copy: 0,
                };
                uffdio_copy(fd, &raw mut copy)?;
            }
            None => {
                let mut zero = UffdioZeropage {
                    range: UffdioRange { start: dst, len },
                    mode: 0,
                    zeropage: 0,
                };
                uffdio_zeropage(fd, &raw mut zero)?;
            }
        }
    }
    Ok(())
}

fn wake(fd: RawFd, start: u64, len: u64) -> Result<()> {
    let mut range = UffdioRange { start, len };
    // SAFETY: the ioctl only reads the range.
    unsafe { uffdio_wake(fd, &raw mut range) }.context("wake faulting threads")?;
    Ok(())
}
