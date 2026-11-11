//! A service's recent output, kept in a file of bounded size.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tokio::sync::broadcast;

pub struct Log {
    path: PathBuf,
    /// Bytes kept. The file may grow by a quarter more before it is cut.
    max: u64,
    writing: Mutex<()>,
    live: broadcast::Sender<Vec<u8>>,
}

impl Log {
    pub fn new(dir: &Path, name: &str, max: u64) -> Self {
        if let Err(error) = fs::create_dir_all(dir) {
            eprintln!("spawn-guest: create {}: {error}", dir.display());
        }
        Self {
            path: dir.join(format!("{name}.log")),
            max,
            writing: Mutex::default(),
            live: broadcast::channel(256).0,
        }
    }

    pub fn append(&self, data: &[u8]) {
        let _writing = self.writing.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(error) = self.write(data) {
            eprintln!("spawn-guest: write {}: {error}", self.path.display());
        }
        let _ = self.live.send(data.to_vec());
    }

    fn write(&self, data: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(data)?;
        let len = file.metadata()?.len();
        if len > self.max + self.max / 4 {
            let tail = self.tail()?;
            let cut = self.path.with_extension("log.cut");
            fs::write(&cut, tail)?;
            fs::rename(&cut, &self.path)?;
        }
        Ok(())
    }

    fn tail(&self) -> io::Result<Vec<u8>> {
        let mut file = match fs::File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let len = file.metadata()?.len();
        file.seek(SeekFrom::Start(len.saturating_sub(self.max)))?;
        let mut tail = Vec::new();
        file.read_to_end(&mut tail)?;
        Ok(tail)
    }

    /// The last `max` bytes, and a receiver of what is written after them.
    pub fn read(&self) -> (Vec<u8>, broadcast::Receiver<Vec<u8>>) {
        let _writing = self.writing.lock().unwrap_or_else(|e| e.into_inner());
        let tail = self.tail().unwrap_or_else(|error| {
            eprintln!("spawn-guest: read {}: {error}", self.path.display());
            Vec::new()
        });
        (tail, self.live.subscribe())
    }
}
