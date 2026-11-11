use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use spawn_proto::guest::v1::ServiceHealth;

use super::*;

fn config() -> Config {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../target/test-services/{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    Config {
        log_dir: dir,
        log_max: 100_000,
        backoff_min: Duration::from_millis(50),
        backoff_max: Duration::from_millis(200),
        reset_after: Duration::from_secs(60),
        stop_grace: Duration::from_millis(300),
        second: Duration::from_millis(20),
        as_user: false,
        login: false,
    }
}

fn supervisor() -> Supervisor {
    Supervisor::new(config(), Reaper::direct())
}

fn spec(name: &str, script: &str) -> ServiceSpec {
    ServiceSpec {
        name: name.into(),
        command: vec!["sh".into(), "-c".into(), script.into()],
        cwd: "/".into(),
        ..ServiceSpec::default()
    }
}

fn status(sup: &Supervisor, name: &str) -> Option<ServiceStatus> {
    sup.list().into_iter().find(|s| s.name == name)
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn running(sup: &Supervisor, name: &str) -> u32 {
    until(name, || status(sup, name).is_some_and(|s| s.pid != 0)).await;
    status(sup, name).map(|s| s.pid).unwrap_or_default()
}

/// The next event of `kind` for `name`.
async fn next(rx: &mut broadcast::Receiver<ServiceEvent>, name: &str, kind: &str) -> ServiceEvent {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = rx.recv().await.expect("events");
            if event.name == name && event.kind == kind {
                return event;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {kind} event for {name}"))
}

fn log_text(sup: &Supervisor, name: &str) -> String {
    String::from_utf8_lossy(&sup.logs(name).expect("logs").0).into_owned()
}

#[tokio::test]
async fn start_reconciles_by_name_and_never_makes_a_second_copy() {
    let sup = supervisor();
    let (a, b) = (spec("a", "sleep 100"), spec("b", "sleep 100"));
    sup.start(vec![a.clone(), b.clone()]).await.unwrap();
    let (pid_a, pid_b) = (running(&sup, "a").await, running(&sup, "b").await);

    sup.start(vec![a.clone(), b]).await.unwrap();
    assert_eq!(running(&sup, "a").await, pid_a);
    assert_eq!(running(&sup, "b").await, pid_b);

    let mut changed = a;
    changed.env.insert("CHANGED".into(), "1".into());
    sup.start(vec![changed, spec("c", "sleep 100")])
        .await
        .unwrap();
    let names: Vec<String> = sup.list().into_iter().map(|s| s.name).collect();
    assert_eq!(names, ["a", "c"]);
    assert_ne!(running(&sup, "a").await, pid_a);
    running(&sup, "c").await;
    // Stopped processes are gone, with their groups.
    for pid in [pid_a, pid_b] {
        let gone = nix::sys::signal::kill(Pid::from_raw(pid as i32), None).is_err();
        assert!(gone, "process {pid} still runs");
    }
    sup.start(Vec::new()).await.unwrap();
    assert!(sup.list().is_empty());
}

#[tokio::test]
async fn bad_lists_are_refused() {
    let sup = supervisor();
    for specs in [
        vec![spec("-a", "true")],
        vec![spec("A", "true")],
        vec![spec("a", "true"), spec("a", "true")],
        vec![ServiceSpec {
            command: Vec::new(),
            ..spec("a", "")
        }],
        vec![ServiceSpec {
            health: Some(ServiceHealth {
                check: Some(ProtoCheck::Tcp(true)),
                ..ServiceHealth::default()
            }),
            ..spec("a", "true")
        }],
    ] {
        let error = sup.start(specs).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
}

#[tokio::test]
async fn always_restarts_with_doubling_backoff() {
    let sup = supervisor();
    let (_, mut rx, _) = sup.watch(None);
    sup.start(vec![spec("crash", "exit 3")]).await.unwrap();
    let mut starts = Vec::new();
    for _ in 0..4 {
        next(&mut rx, "crash", "started").await;
        starts.push(Instant::now());
        let exited = next(&mut rx, "crash", "exited").await;
        assert_eq!(exited.exit.and_then(|e| e.code), Some(3));
    }
    let restarted = next(&mut rx, "crash", "restarted").await;
    assert_eq!(restarted.reason, "exit");
    assert_eq!(restarted.count, 4);
    let gaps: Vec<Duration> = starts.windows(2).map(|w| w[1] - w[0]).collect();
    // 50 ms, 100 ms, then 200 ms.
    assert!(gaps[0] < Duration::from_millis(150), "{gaps:?}");
    assert!(gaps[2] >= Duration::from_millis(190), "{gaps:?}");
    let now = status(&sup, "crash").unwrap();
    assert_eq!(now.last_exit.and_then(|e| e.code), Some(3));
    assert!(now.restarts >= 4);
}

#[tokio::test]
async fn on_failure_stops_after_a_clean_exit() {
    let sup = supervisor();
    let (_, mut rx, _) = sup.watch(None);
    let on_failure = |name: &str, script: &str| ServiceSpec {
        restart: ServiceRestart::OnFailure as i32,
        ..spec(name, script)
    };
    sup.start(vec![
        on_failure("done", "exit 0"),
        on_failure("fails", "exit 1"),
    ])
    .await
    .unwrap();
    next(&mut rx, "fails", "restarted").await;
    until("done to stop", || {
        status(&sup, "done").is_some_and(|s| s.state == STOPPED)
    })
    .await;
    let done = status(&sup, "done").unwrap();
    assert_eq!(done.restarts, 0);
    assert_eq!(done.last_exit.and_then(|e| e.code), Some(0));

    // A restart starts it again.
    sup.restart("done").await.unwrap();
    let restarted = next(&mut rx, "done", "restarted").await;
    assert_eq!(restarted.reason, "request");
}

#[tokio::test]
async fn restart_stops_with_sigterm_then_sigkill() {
    let sup = supervisor();
    let (_, mut rx, _) = sup.watch(None);
    sup.start(vec![
        spec("polite", "sleep 100"),
        spec("stubborn", "trap '' TERM; while true; do sleep 0.05; done"),
    ])
    .await
    .unwrap();
    let first = running(&sup, "polite").await;
    running(&sup, "stubborn").await;

    sup.restart("polite").await.unwrap();
    let exited = next(&mut rx, "polite", "exited").await;
    assert_eq!(exited.exit.and_then(|e| e.signal), Some(libc::SIGTERM));
    assert_eq!(next(&mut rx, "polite", "restarted").await.reason, "request");
    assert_ne!(running(&sup, "polite").await, first);

    let asked = Instant::now();
    sup.restart("stubborn").await.unwrap();
    let exited = next(&mut rx, "stubborn", "exited").await;
    assert_eq!(exited.exit.and_then(|e| e.signal), Some(libc::SIGKILL));
    assert!(asked.elapsed() >= Duration::from_millis(300));

    let error = sup.restart("nope").await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);
}

/// An HTTP server on a free port that answers 200 while `ok` is set.
fn http_server(ok: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0; 1024];
            let _ = stream.read(&mut buf);
            let status = if ok.load(Ordering::SeqCst) {
                "200 OK"
            } else {
                "500 Internal Server Error"
            };
            let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
        }
    });
    port
}

fn checked(name: &str, port: u16, check: ProtoCheck) -> ServiceSpec {
    ServiceSpec {
        port: u32::from(port),
        health: Some(ServiceHealth {
            check: Some(check),
            interval_s: 1,
            failures: 3,
        }),
        ..spec(name, "sleep 100")
    }
}

#[tokio::test]
async fn failed_health_checks_restart_the_service() {
    let sup = supervisor();
    let (_, mut rx, _) = sup.watch(None);
    let ok = Arc::new(AtomicBool::new(true));
    let port = http_server(Arc::clone(&ok));
    sup.start(vec![checked(
        "web",
        port,
        ProtoCheck::Http("/healthz".into()),
    )])
    .await
    .unwrap();
    until("web to be healthy", || {
        status(&sup, "web").is_some_and(|s| s.state == HEALTHY)
    })
    .await;
    let pid = running(&sup, "web").await;

    ok.store(false, Ordering::SeqCst);
    let unhealthy = next(&mut rx, "web", "unhealthy").await;
    assert_eq!(unhealthy.count, 3);
    assert_eq!(next(&mut rx, "web", "restarted").await.reason, "unhealthy");
    ok.store(true, Ordering::SeqCst);
    until("web to be healthy again", || {
        status(&sup, "web").is_some_and(|s| s.state == HEALTHY && s.pid != pid && s.pid != 0)
    })
    .await;
}

#[tokio::test]
async fn a_service_is_starting_until_its_first_check_passes() {
    let sup = supervisor();
    let (_, mut rx, _) = sup.watch(None);
    // Nothing listens here once the listener is dropped.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    sup.start(vec![
        checked("slow", port, ProtoCheck::Tcp(true)),
        spec("plain", "sleep 100"),
    ])
    .await
    .unwrap();
    running(&sup, "slow").await;
    assert_eq!(status(&sup, "slow").unwrap().state, STARTING);
    assert_eq!(status(&sup, "plain").unwrap().state, HEALTHY);
    // It gets `interval_s * failures` to pass one, then is restarted.
    let unhealthy = next(&mut rx, "slow", "unhealthy").await;
    assert_eq!(unhealthy.count, 3);
    assert_eq!(next(&mut rx, "slow", "restarted").await.reason, "unhealthy");

    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    until("slow to be healthy", || {
        status(&sup, "slow").is_some_and(|s| s.state == HEALTHY)
    })
    .await;
    drop(listener);
}

#[tokio::test]
async fn output_goes_to_a_bounded_log() {
    let sup = supervisor();
    let mut env = spec(
        "env",
        "echo \"foo=$FOO home=${HOME:-none}\"; echo oops >&2; sleep 100",
    );
    env.env.insert("FOO".into(), "bar".into());
    let big = spec(
        "big",
        "i=0; while [ $i -lt 3000 ]; do echo \"line $i $(printf '%080d' 0)\"; i=$((i+1)); done; \
         echo last; sleep 100",
    );
    sup.start(vec![env, big]).await.unwrap();
    until("env output", || log_text(&sup, "env").contains("oops")).await;
    let text = log_text(&sup, "env");
    assert!(text.contains("foo=bar home=none\n"), "{text}");

    until("big output", || log_text(&sup, "big").ends_with("last\n")).await;
    let tail = sup.logs("big").unwrap().0;
    assert_eq!(tail.len(), 100_000);
    let file = sup.0.config.log_dir.join("big.log");
    let size = std::fs::metadata(file).unwrap().len();
    assert!(size <= 125_000, "log file is {size} bytes");
}

#[tokio::test]
async fn watchers_catch_up_from_a_sequence_number() {
    let sup = supervisor();
    let seq = sup.start(vec![spec("a", "sleep 100")]).await.unwrap();
    running(&sup, "a").await;
    let (past, _, last) = sup.watch(Some(seq));
    let kinds: Vec<&str> = past.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, ["started"]);
    assert_eq!(last, past[0].seq);
    let (past, _, _) = sup.watch(None);
    assert!(past.is_empty());
    // A number from before a reboot of the guest starts from now.
    let (past, _, last) = sup.watch(Some(1_000));
    assert!(past.is_empty());
    assert_eq!(last, seq + 1);
}

/// Runs `inner` alone in a new test process, where the reaper can reap
/// every child as PID 1 does.
fn alone(inner: &str) {
    let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            inner,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SPAWN_GUEST_ALONE", "1")
        .status()
        .expect("run the test alone");
    assert!(status.success(), "{inner} failed");
}

#[test]
fn a_service_that_cannot_start_keeps_retrying_with_the_real_reaper() {
    alone("supervisor::tests::cannot_start_with_the_real_reaper");
}

#[tokio::test]
#[ignore = "run alone by a_service_that_cannot_start_keeps_retrying_with_the_real_reaper"]
async fn cannot_start_with_the_real_reaper() {
    if std::env::var_os("SPAWN_GUEST_ALONE").is_none() {
        return;
    }
    static PANICS: AtomicU64 = AtomicU64::new(0);
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        PANICS.fetch_add(1, Ordering::SeqCst);
        hook(info);
    }));
    let me = nix::unistd::User::from_uid(nix::unistd::getuid())
        .expect("look up user")
        .expect("this user")
        .name;
    let sup = Supervisor::new(
        Config {
            as_user: true,
            backoff_min: Duration::from_millis(1),
            backoff_max: Duration::from_millis(5),
            ..config()
        },
        Reaper::pid1(),
    );
    // Keeps the reaper waiting for a child, as in a VM.
    let mut keeper = spec("keeper", "sleep 1000");
    keeper.user.clone_from(&me);
    // Set uid and gid make std fork and exec, which fails on the cwd.
    let broken = |name: &str| ServiceSpec {
        user: "nobody".into(),
        cwd: "/no/such/dir".into(),
        ..spec(name, "true")
    };
    let mut specs = vec![keeper];
    specs.extend(["a", "b", "c", "d"].map(broken));
    sup.start(specs.clone()).await.expect("start");
    running(&sup, "keeper").await;
    for name in ["a", "b", "c", "d"] {
        until(name, || {
            status(&sup, name).is_some_and(|s| s.restarts >= 50)
        })
        .await;
        assert!(log_text(&sup, name).contains("cannot start"));
    }
    assert_eq!(PANICS.load(Ordering::SeqCst), 0, "a spawn panicked");
    sup.restart("a").await.expect("restart");
    sup.start(specs).await.expect("start again");
    let before = status(&sup, "a").map_or(0, |s| s.restarts);
    until("a", || {
        status(&sup, "a").is_some_and(|s| s.restarts > before)
    })
    .await;
    sup.start(Vec::new()).await.expect("stop all");
    assert!(sup.list().is_empty());
}
