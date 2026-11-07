//! Loads a build's memory file from the build store part by part, while
//! sandboxes already run from it. A part a sandbox waits for is fetched
//! next, then the build's hot list, then the rest in order.

use std::collections::VecDeque;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use spawn_node::uffd::PageSource;
use tokio::sync::{Notify, watch};
use tokio::task::JoinSet;

use crate::store::{BuildStore, PART_BYTES_MEM, Paged};

/// Parts fetched at the same time.
const PARALLEL: usize = 8;
/// How long a part may keep failing before the load gives up.
const RETRY_FOR: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    Missing,
    Fetching,
    Here,
}

struct State {
    parts: Vec<Part>,
    /// Parts a sandbox waits for, newest first.
    asked: VecDeque<u32>,
    failed: Option<String>,
}

pub struct LazyMem {
    store: Arc<BuildStore>,
    paged: Paged,
    file: File,
    partial: PathBuf,
    dest: PathBuf,
    state: Mutex<State>,
    changed: Condvar,
    wake: Notify,
    done: watch::Sender<bool>,
}

impl LazyMem {
    /// Starts an empty sparse `<name>.lazy` in `dir`. Call `run` to fill it.
    pub fn new(store: Arc<BuildStore>, paged: Paged, dir: &Path) -> Result<Arc<Self>> {
        let partial = dir.join(format!("{}.lazy", paged.name));
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&partial)?;
        file.set_len(paged.size)?;
        let parts = (0..paged.count())
            .map(|i| {
                if paged.is_zero(i) {
                    Part::Here
                } else {
                    Part::Missing
                }
            })
            .collect();
        Ok(Arc::new(Self {
            store,
            dest: dir.join(&paged.name),
            paged,
            file,
            partial,
            state: Mutex::new(State {
                parts,
                asked: VecDeque::new(),
                failed: None,
            }),
            changed: Condvar::new(),
            wake: Notify::new(),
            done: watch::Sender::new(false),
        }))
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The next part to fetch, marked as being fetched.
    fn next(&self, order: &mut impl Iterator<Item = u32>) -> Option<u32> {
        let mut state = self.state();
        let i = loop {
            let i = match state.asked.pop_front() {
                Some(i) => i,
                None => order.next()?,
            };
            if state.parts[i as usize] == Part::Missing {
                break i;
            }
        };
        state.parts[i as usize] = Part::Fetching;
        Some(i)
    }

    /// Fetches every part, then moves the file to its name. On error,
    /// sandboxes waiting for a part get the error too.
    pub async fn run(self: &Arc<Self>) -> Result<()> {
        let result = self.fetch_all().await;
        if let Err(error) = &result {
            self.state().failed = Some(format!("{error:#}"));
            self.changed.notify_all();
            let _ = std::fs::remove_file(&self.partial);
        }
        result
    }

    async fn fetch_all(self: &Arc<Self>) -> Result<()> {
        let mut order = self
            .paged
            .hot
            .clone()
            .into_iter()
            .chain(0..self.paged.count());
        let mut running = JoinSet::new();
        loop {
            while running.len() < PARALLEL {
                let Some(i) = self.next(&mut order) else {
                    break;
                };
                let this = Arc::clone(self);
                running.spawn(async move { this.fetch(i).await.map(|()| i) });
            }
            if running.is_empty() {
                break;
            }
            tokio::select! {
                joined = running.join_next() => {
                    let Some(joined) = joined else { continue };
                    let i = joined??;
                    self.state().parts[i as usize] = Part::Here;
                    self.changed.notify_all();
                }
                () = self.wake.notified() => {}
            }
        }
        self.file.sync_all()?;
        std::fs::rename(&self.partial, &self.dest)?;
        Ok(())
    }

    /// Fetches part `i` into the file, retrying for `RETRY_FOR`.
    async fn fetch(&self, i: u32) -> Result<()> {
        let mut first_error = None;
        let mut delay = Duration::from_millis(100);
        loop {
            match self.store.read_part(&self.paged, i).await {
                Ok(bytes) => {
                    if let Some(bytes) = bytes {
                        let at = u64::from(i) * PART_BYTES_MEM;
                        self.file.write_all_at(&bytes, at)?;
                    }
                    return Ok(());
                }
                Err(error) => {
                    let since = *first_error.get_or_insert_with(Instant::now);
                    if since.elapsed() > RETRY_FOR {
                        return Err(error);
                    }
                    eprintln!("warning: fetch {}: {error:#}; retrying", self.paged.name);
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(5));
                }
            }
        }
    }

    /// Tells `wait_done` callers that the build is local now, or that the
    /// load ended without it.
    pub fn mark_done(&self) {
        self.done.send_replace(true);
    }

    pub async fn wait_done(&self) {
        let _ = self.done.subscribe().wait_for(|done| *done).await;
    }
}

impl PageSource for LazyMem {
    fn part_bytes(&self) -> u64 {
        PART_BYTES_MEM
    }

    fn read(&self, i: u32, buf: &mut [u8], timeout: Duration) -> Result<bool> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state();
        let Some(&part) = state.parts.get(i as usize) else {
            bail!("no memory part {i}");
        };
        if part != Part::Here {
            state.asked.push_front(i);
            self.wake.notify_one();
        }
        while state.parts[i as usize] != Part::Here {
            if let Some(why) = &state.failed {
                bail!("{why}");
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                bail!("timed out waiting for the build store");
            }
            state = self
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        drop(state);
        if self.paged.is_zero(i) {
            return Ok(false);
        }
        self.file
            .read_exact_at(buf, u64::from(i) * PART_BYTES_MEM)?;
        Ok(true)
    }
}
