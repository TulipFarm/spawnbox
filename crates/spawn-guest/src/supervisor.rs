//! Services: programs that the guest keeps running.
//!
//! The supervisor runs in PID 1, so services outlive a restart of the
//! agent. It serves the `Services` gRPC service on a Unix socket that only
//! root can open; the agent forwards the host's calls to it.

mod health;
mod log;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::fcntl::OFlag;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use spawn_proto::guest::v1::service_health::Check as ProtoCheck;
use spawn_proto::guest::v1::services_server::{Services, ServicesServer};
use spawn_proto::guest::v1::{
    ServiceEvent, ServiceExit, ServiceLogChunk, ServiceLogsRequest, ServiceRestart,
    ServiceRestartRequest, ServiceRestartResponse, ServiceSpec, ServiceStatus, ServicesListRequest,
    ServicesListResponse, ServicesStartRequest, ServicesStartResponse, ServicesWatchRequest,
};
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_stream::Stream;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tonic::{Request, Response, Status};

use self::health::Check;
use self::log::Log;
use crate::reaper::Reaper;

/// Where the agent reaches the supervisor.
pub const SOCKET: &str = "/run/spawn/services.sock";

pub const STARTING: &str = "starting";
pub const HEALTHY: &str = "healthy";
pub const UNHEALTHY: &str = "unhealthy";
pub const BACKOFF: &str = "backoff";
pub const STOPPED: &str = "stopped";

/// Events kept for watchers that reconnect.
const BACKLOG: usize = 256;

const DEFAULT_INTERVAL_S: u32 = 10;
const DEFAULT_FAILURES: u32 = 3;

#[derive(Clone)]
pub struct Config {
    pub log_dir: PathBuf,
    /// Bytes of output kept per service.
    pub log_max: u64,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// A process that ran this long starts the next backoff from the
    /// minimum again.
    pub reset_after: Duration,
    /// From SIGTERM to SIGKILL.
    pub stop_grace: Duration,
    /// How long one second of `interval_s` is. Shorter in tests.
    pub second: Duration,
    /// Run each service as its user. Tests run as themselves.
    pub as_user: bool,
    /// Run the shell as a login shell, which reads the user's profile.
    pub login: bool,
}

impl Config {
    pub fn vm() -> Self {
        Self {
            log_dir: "/var/log/spawnbox".into(),
            log_max: 1 << 20,
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            reset_after: Duration::from_secs(60),
            stop_grace: Duration::from_secs(5),
            second: Duration::from_secs(1),
            as_user: true,
            login: true,
        }
    }
}

#[derive(Clone)]
pub struct Supervisor(Arc<Shared>);

struct Shared {
    config: Config,
    reaper: Arc<Reaper>,
    /// Held while services start or stop, so one `Start` runs at a time.
    services: tokio::sync::Mutex<BTreeMap<String, Handle>>,
    status: Mutex<BTreeMap<String, ServiceStatus>>,
    logs: Mutex<HashMap<String, Arc<Log>>>,
    events: Mutex<Events>,
    live: broadcast::Sender<ServiceEvent>,
}

#[derive(Default)]
struct Events {
    seq: u64,
    backlog: VecDeque<ServiceEvent>,
}

struct Handle {
    spec: ServiceSpec,
    control: mpsc::Sender<Control>,
    task: JoinHandle<()>,
}

enum Control {
    Restart,
    Stop,
}

/// How a run of a service's process ended.
enum Ended {
    Exited(ExitStatus),
    Unhealthy(ExitStatus),
    Restarted(ExitStatus),
    Stopped(ExitStatus),
    /// It could not be started.
    NotStarted,
}

/// What a dropped exit channel counts as.
const KILLED: i32 = libc::SIGKILL;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn exit_of(status: ExitStatus) -> ServiceExit {
    ServiceExit {
        code: status.code(),
        signal: status.signal(),
    }
}

fn event(name: &str, kind: &str) -> ServiceEvent {
    ServiceEvent {
        name: name.to_owned(),
        kind: kind.to_owned(),
        ..ServiceEvent::default()
    }
}

/// Sends `signal` to every process of the group that `pid` leads.
fn signal_group(pid: u32, signal: Signal) {
    if let Ok(pid) = i32::try_from(pid) {
        let _ = killpg(Pid::from_raw(pid), signal);
    }
}

/// A service's process group, killed when dropped: after its process
/// ends, children it left behind would hold its port, and if its
/// supervisor panics, the next one must not start a second copy.
struct Group(u32);

impl Drop for Group {
    fn drop(&mut self) {
        signal_group(self.0, Signal::SIGKILL);
    }
}

/// The name of a service whose supervisor panics once, after its process
/// started.
#[cfg(test)]
static PANIC_AFTER_SPAWN: Mutex<Option<String>> = Mutex::new(None);

fn check_of(spec: &ServiceSpec) -> Option<Check> {
    match &spec.health.as_ref()?.check {
        Some(ProtoCheck::Http(path)) => Some(Check::Http(path.clone())),
        Some(ProtoCheck::Tcp(true)) => Some(Check::Tcp),
        _ => None,
    }
}

pub fn check(specs: &[ServiceSpec]) -> Result<(), Status> {
    let mut names = std::collections::HashSet::new();
    for spec in specs {
        let valid = !spec.name.is_empty()
            && spec.name.len() <= 63
            && !spec.name.starts_with('-')
            && spec
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !valid {
            return Err(Status::invalid_argument(format!(
                "bad service name {:?}",
                spec.name
            )));
        }
        if !names.insert(&spec.name) {
            return Err(Status::invalid_argument(format!(
                "service {} is listed twice",
                spec.name
            )));
        }
        if spec.command.is_empty() {
            return Err(Status::invalid_argument(format!(
                "service {} has no command",
                spec.name
            )));
        }
        if check_of(spec).is_some() && spec.port == 0 {
            return Err(Status::invalid_argument(format!(
                "service {} has a health check but no port",
                spec.name
            )));
        }
    }
    Ok(())
}

impl Supervisor {
    pub fn new(config: Config, reaper: Arc<Reaper>) -> Self {
        Self(Arc::new(Shared {
            config,
            reaper,
            services: tokio::sync::Mutex::default(),
            status: Mutex::default(),
            logs: Mutex::default(),
            events: Mutex::default(),
            live: broadcast::channel(BACKLOG).0,
        }))
    }

    /// Makes the running services match `specs`. Returns the last event
    /// before it.
    pub async fn start(&self, specs: Vec<ServiceSpec>) -> Result<u64, Status> {
        check(&specs)?;
        let mut services = self.0.services.lock().await;
        let seq = lock(&self.0.events).seq;
        let wanted: BTreeMap<String, ServiceSpec> =
            specs.into_iter().map(|s| (s.name.clone(), s)).collect();
        let changed: Vec<String> = services
            .iter()
            .filter(|(name, handle)| {
                wanted.get(*name) != Some(&handle.spec) || handle.task.is_finished()
            })
            .map(|(name, _)| name.clone())
            .collect();
        let mut stopping = Vec::new();
        for name in changed {
            if let Some(handle) = services.remove(&name) {
                let _ = handle.control.send(Control::Stop).await;
                stopping.push((name, handle.task));
            }
        }
        for (name, task) in stopping {
            let _ = task.await;
            if !wanted.contains_key(&name) {
                lock(&self.0.status).remove(&name);
                lock(&self.0.logs).remove(&name);
            }
        }
        for (name, spec) in wanted {
            if services.contains_key(&name) {
                continue;
            }
            let handle = self.launch(spec);
            services.insert(name, handle);
        }
        Ok(seq)
    }

    fn launch(&self, spec: ServiceSpec) -> Handle {
        let name = spec.name.clone();
        let log = Arc::clone(lock(&self.0.logs).entry(name.clone()).or_insert_with(|| {
            Arc::new(Log::new(
                &self.0.config.log_dir,
                &name,
                self.0.config.log_max,
            ))
        }));
        lock(&self.0.status).insert(
            name.clone(),
            ServiceStatus {
                name: name.clone(),
                state: STARTING.into(),
                ..ServiceStatus::default()
            },
        );
        let (control, rx) = mpsc::channel(4);
        let shared = Arc::clone(&self.0);
        let task = tokio::spawn(shared.keep(spec.clone(), log, rx));
        Handle {
            spec,
            control,
            task,
        }
    }

    pub fn list(&self) -> Vec<ServiceStatus> {
        lock(&self.0.status).values().cloned().collect()
    }

    pub async fn restart(&self, name: &str) -> Result<(), Status> {
        let control = {
            let mut services = self.0.services.lock().await;
            let handle = services
                .get(name)
                .ok_or_else(|| Status::not_found(format!("no service {name}")))?;
            if handle.task.is_finished() {
                let spec = handle.spec.clone();
                services.insert(name.to_owned(), self.launch(spec));
                return Ok(());
            }
            handle.control.clone()
        };
        control
            .send(Control::Restart)
            .await
            .map_err(|_| Status::unavailable(format!("service {name} is stopping")))
    }

    /// The service's recent output, and a receiver of new output.
    pub fn logs(&self, name: &str) -> Result<(Vec<u8>, broadcast::Receiver<Vec<u8>>), Status> {
        let log = lock(&self.0.logs)
            .get(name)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("no service {name}")))?;
        Ok(log.read())
    }

    /// Kept events after `after` (`None`: from now), a receiver of new
    /// ones, and the sequence number they come after.
    pub fn watch(
        &self,
        after: Option<u64>,
    ) -> (Vec<ServiceEvent>, broadcast::Receiver<ServiceEvent>, u64) {
        let events = lock(&self.0.events);
        let rx = self.0.live.subscribe();
        // A sequence number from before a reboot of the guest is too high.
        let after = after.unwrap_or(events.seq).min(events.seq);
        let past: Vec<ServiceEvent> = events
            .backlog
            .iter()
            .filter(|e| e.seq > after)
            .cloned()
            .collect();
        let last = past.last().map_or(after, |e| e.seq);
        (past, rx, last)
    }
}

impl Shared {
    fn emit(&self, mut event: ServiceEvent) {
        let mut events = lock(&self.events);
        events.seq += 1;
        event.seq = events.seq;
        if events.backlog.len() == BACKLOG {
            events.backlog.pop_front();
        }
        events.backlog.push_back(event.clone());
        let _ = self.live.send(event);
    }

    fn set(&self, name: &str, f: impl FnOnce(&mut ServiceStatus)) {
        if let Some(status) = lock(&self.status).get_mut(name) {
            f(status);
        }
    }

    /// Runs [`Self::supervise`], and runs it again after a backoff if it
    /// panics, so a bug cannot leave a service that is never restarted.
    async fn keep(
        self: Arc<Self>,
        spec: ServiceSpec,
        log: Arc<Log>,
        control: mpsc::Receiver<Control>,
    ) {
        let name = spec.name.clone();
        let control = Arc::new(tokio::sync::Mutex::new(control));
        let mut reason = None;
        loop {
            let task = tokio::spawn(Arc::clone(&self).supervise(
                spec.clone(),
                Arc::clone(&log),
                Arc::clone(&control),
                reason,
            ));
            if task.await.is_ok() {
                return;
            }
            log.append(format!("spawnbox: supervising {name} failed\n").as_bytes());
            self.set(&name, |s| {
                s.pid = 0;
                s.state = BACKOFF.into();
            });
            let mut control = control.lock().await;
            tokio::select! {
                () = tokio::time::sleep(self.config.backoff_max) => reason = Some("exit"),
                c = control.recv() => match c {
                    Some(Control::Restart) => reason = Some("request"),
                    Some(Control::Stop) | None => {
                        self.set(&name, |s| s.state = STOPPED.into());
                        return;
                    }
                },
            }
        }
    }

    /// Keeps one service running until it is told to stop.
    async fn supervise(
        self: Arc<Self>,
        spec: ServiceSpec,
        log: Arc<Log>,
        control: Arc<tokio::sync::Mutex<mpsc::Receiver<Control>>>,
        mut reason: Option<&'static str>,
    ) {
        let mut control = control.lock_owned().await;
        let control = &mut *control;
        let config = &self.config;
        let name = spec.name.as_str();
        let on_failure = spec.restart == ServiceRestart::OnFailure as i32;
        let mut backoff = config.backoff_min;
        let mut restarts = lock(&self.status).get(name).map_or(0, |s| s.restarts);
        loop {
            if let Some(reason) = reason.take() {
                restarts += 1;
                self.set(name, |s| s.restarts = restarts);
                eprintln!("spawn-guest: restarting service {name} ({reason})");
                self.emit(ServiceEvent {
                    reason: reason.into(),
                    count: restarts,
                    ..event(name, "restarted")
                });
            }
            let began = Instant::now();
            let spawned =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.spawn(&spec, &log)))
                    .unwrap_or_else(|_| Err(std::io::Error::other("the spawn panicked")));
            let ended = match spawned {
                Ok((pid, exit)) => {
                    let group = Group(pid);
                    let state = if check_of(&spec).is_some() {
                        STARTING
                    } else {
                        HEALTHY
                    };
                    self.set(name, |s| {
                        s.pid = pid;
                        s.state = state.into();
                        s.started_at_ms = now_ms();
                    });
                    self.emit(ServiceEvent {
                        pid,
                        ..event(name, "started")
                    });
                    let ended = self.run(&spec, pid, exit, control).await;
                    drop(group);
                    ended
                }
                Err(error) => {
                    log.append(format!("spawnbox: cannot start {name}: {error}\n").as_bytes());
                    Ended::NotStarted
                }
            };
            let status = match &ended {
                Ended::Exited(s)
                | Ended::Unhealthy(s)
                | Ended::Restarted(s)
                | Ended::Stopped(s) => Some(*s),
                Ended::NotStarted => None,
            };
            if let Some(status) = status {
                self.set(name, |s| {
                    s.pid = 0;
                    s.started_at_ms = 0;
                    s.last_exit = Some(exit_of(status));
                });
                self.emit(ServiceEvent {
                    exit: Some(exit_of(status)),
                    ..event(name, "exited")
                });
            }
            match ended {
                Ended::Stopped(_) => {
                    self.set(name, |s| s.state = STOPPED.into());
                    return;
                }
                Ended::Restarted(_) => {
                    backoff = config.backoff_min;
                    reason = Some("request");
                    continue;
                }
                Ended::Exited(status) if on_failure && status.success() => {
                    self.set(name, |s| s.state = STOPPED.into());
                    match control.recv().await {
                        Some(Control::Restart) => {
                            backoff = config.backoff_min;
                            reason = Some("request");
                            continue;
                        }
                        Some(Control::Stop) | None => return,
                    }
                }
                Ended::Unhealthy(_) => reason = Some("unhealthy"),
                Ended::Exited(_) | Ended::NotStarted => reason = Some("exit"),
            }
            if began.elapsed() >= config.reset_after {
                backoff = config.backoff_min;
            }
            self.set(name, |s| s.state = BACKOFF.into());
            tokio::select! {
                () = tokio::time::sleep(backoff) => {
                    backoff = (backoff * 2).min(config.backoff_max);
                }
                c = control.recv() => match c {
                    Some(Control::Restart) => {
                        backoff = config.backoff_min;
                        reason = Some("request");
                    }
                    Some(Control::Stop) | None => {
                        self.set(name, |s| s.state = STOPPED.into());
                        return;
                    }
                },
            }
        }
    }

    /// Starts the service's process, with its output going to `log`.
    fn spawn(
        &self,
        spec: &ServiceSpec,
        log: &Arc<Log>,
    ) -> std::io::Result<(u32, oneshot::Receiver<ExitStatus>)> {
        let config = &self.config;
        let (read, write) = nix::unistd::pipe2(OFlag::O_CLOEXEC)?;
        let mut cmd = Command::new(crate::exec::shell());
        cmd.arg(if config.login { "-lc" } else { "-c" })
            .arg(r#"exec "$@""#)
            .arg(&spec.name)
            .args(&spec.command)
            .env_clear()
            .env("PATH", crate::init::PATH)
            .env("LANG", "C.UTF-8");
        if config.as_user {
            let user = crate::exec::user(&spec.user)
                .map_err(|status| std::io::Error::other(status.message().to_owned()))?;
            cmd.uid(user.uid.as_raw())
                .gid(user.gid.as_raw())
                .env("HOME", &user.dir)
                .env("USER", &user.name)
                .env("LOGNAME", &user.name);
        }
        cmd.envs(&spec.env)
            .current_dir(crate::exec::cwd(&spec.cwd))
            .stdin(Stdio::null())
            .stdout(Stdio::from(write.try_clone()?))
            .stderr(Stdio::from(write))
            // Its own group, so stopping it stops everything it started.
            .process_group(0);
        let (tx, rx) = oneshot::channel();
        let pid = self.reaper.spawn(cmd, move |status| {
            let _ = tx.send(status);
        })?;
        let mut pipe = tokio::net::unix::pipe::Receiver::from_owned_fd(read)?;
        let log = Arc::clone(log);
        tokio::spawn(async move {
            let mut buf = vec![0; 16 * 1024];
            while let Ok(n) = pipe.read(&mut buf).await
                && n > 0
            {
                log.append(&buf[..n]);
            }
        });
        Ok((pid, rx))
    }

    /// Watches one process, with health checks, until it ends or is told
    /// to restart or stop.
    async fn run(
        &self,
        spec: &ServiceSpec,
        pid: u32,
        mut exit: oneshot::Receiver<ExitStatus>,
        control: &mut mpsc::Receiver<Control>,
    ) -> Ended {
        let name = spec.name.as_str();
        #[cfg(test)]
        {
            let mut panic = lock(&PANIC_AFTER_SPAWN);
            if panic.as_deref() == Some(name) {
                *panic = None;
                drop(panic);
                panic!("supervising {name} failed");
            }
        }
        let second = self.config.second;
        let health = spec.health.as_ref();
        let check = check_of(spec);
        let interval_s = match health.map_or(0, |h| h.interval_s) {
            0 => DEFAULT_INTERVAL_S,
            n => n,
        };
        let failures = match health.map_or(0, |h| h.failures) {
            0 => DEFAULT_FAILURES,
            n => n,
        };
        let interval = second * interval_s;
        let timeout = interval.min(second * 5);
        let port = u16::try_from(spec.port).unwrap_or(0);
        let began = Instant::now();
        let mut passed = false;
        let mut failed = 0;
        loop {
            // Until the first pass, checks come every second, and the
            // service has `interval_s * failures` to pass one.
            let wait = if passed {
                interval
            } else {
                second.min(interval)
            };
            tokio::select! {
                status = &mut exit => {
                    return Ended::Exited(status.unwrap_or_else(|_| ExitStatus::from_raw(KILLED)));
                }
                c = control.recv() => {
                    let status = self.stop(pid, &mut exit).await;
                    return match c {
                        Some(Control::Restart) => Ended::Restarted(status),
                        Some(Control::Stop) | None => Ended::Stopped(status),
                    };
                }
                () = tokio::time::sleep(wait), if check.is_some() => {
                    let Some(check) = &check else { continue };
                    if health::passes(check, port, timeout).await {
                        failed = 0;
                        passed = true;
                        self.set(name, |s| s.state = HEALTHY.into());
                        continue;
                    }
                    let give_up = if passed {
                        failed += 1;
                        self.set(name, |s| s.state = UNHEALTHY.into());
                        failed >= failures
                    } else {
                        began.elapsed() >= interval * failures
                    };
                    if give_up {
                        self.emit(ServiceEvent {
                            count: if passed { failed } else { failures },
                            ..event(name, "unhealthy")
                        });
                        self.set(name, |s| s.state = UNHEALTHY.into());
                        return Ended::Unhealthy(self.stop(pid, &mut exit).await);
                    }
                }
            }
        }
    }

    /// SIGTERM to the process group, then SIGKILL after the grace period.
    async fn stop(&self, pid: u32, exit: &mut oneshot::Receiver<ExitStatus>) -> ExitStatus {
        signal_group(pid, Signal::SIGTERM);
        if let Ok(status) = tokio::time::timeout(self.config.stop_grace, &mut *exit).await {
            return status.unwrap_or_else(|_| ExitStatus::from_raw(KILLED));
        }
        signal_group(pid, Signal::SIGKILL);
        exit.await.unwrap_or_else(|_| ExitStatus::from_raw(KILLED))
    }
}

/// Serves the supervisor on `path` until the process ends.
pub async fn serve(supervisor: Supervisor, path: &Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    tonic::transport::Server::builder()
        .add_service(ServicesServer::new(supervisor))
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await
        .map_err(std::io::Error::other)
}

type Streamed<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl Services for Supervisor {
    type LogsStream = Streamed<ServiceLogChunk>;
    type WatchStream = Streamed<ServiceEvent>;

    async fn start(
        &self,
        req: Request<ServicesStartRequest>,
    ) -> Result<Response<ServicesStartResponse>, Status> {
        let seq = Self::start(self, req.into_inner().services).await?;
        Ok(Response::new(ServicesStartResponse { seq }))
    }

    async fn list(
        &self,
        _: Request<ServicesListRequest>,
    ) -> Result<Response<ServicesListResponse>, Status> {
        Ok(Response::new(ServicesListResponse {
            services: Self::list(self),
        }))
    }

    async fn restart(
        &self,
        req: Request<ServiceRestartRequest>,
    ) -> Result<Response<ServiceRestartResponse>, Status> {
        Self::restart(self, &req.into_inner().name).await?;
        Ok(Response::new(ServiceRestartResponse {}))
    }

    async fn logs(
        &self,
        req: Request<ServiceLogsRequest>,
    ) -> Result<Response<Self::LogsStream>, Status> {
        let req = req.into_inner();
        let (tail, mut live) = Self::logs(self, &req.name)?;
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            if tx.send(Ok(ServiceLogChunk { data: tail })).await.is_err() || !req.follow {
                return;
            }
            loop {
                let data = tokio::select! {
                    () = tx.closed() => return,
                    data = live.recv() => data,
                };
                match data {
                    Ok(data) => {
                        if tx.send(Ok(ServiceLogChunk { data })).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn watch(
        &self,
        req: Request<ServicesWatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let req = req.into_inner();
        let (past, mut live, mut last) = Self::watch(self, (!req.from_now).then_some(req.after));
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            for event in past {
                if tx.send(Ok(event)).await.is_err() {
                    return;
                }
            }
            loop {
                let event = tokio::select! {
                    () = tx.closed() => return,
                    event = live.recv() => event,
                };
                let event = match event {
                    Ok(event) if event.seq > last => event,
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // The watcher reconnects after its last event and
                        // gets the rest from the backlog.
                        let _ = tx.send(Err(Status::aborted("watcher fell behind"))).await;
                        return;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                last = event.seq;
                if tx.send(Ok(event)).await.is_err() {
                    return;
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

#[cfg(test)]
mod tests;
