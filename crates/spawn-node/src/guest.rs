use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use hyper_util::rt::TokioIo;
use spawn_proto::guest::v1::exec_event::Event;
use spawn_proto::guest::v1::health_client::HealthClient;
use spawn_proto::guest::v1::identity_client::IdentityClient;
use spawn_proto::guest::v1::image_client::ImageClient;
use spawn_proto::guest::v1::process_client::ProcessClient;
use spawn_proto::guest::v1::volumes_client::VolumesClient;
use spawn_proto::guest::v1::{
    ApplyRequest, ExecEvent, ExecExit, ExecRequest, HelloRequest, MountRequest, SealRequest,
    UnpackRequest, VolumeMount, unpack_event,
};
use spawn_proto::{GUEST_TCP_PORT, GUEST_VSOCK_PORT, PROTOCOL_VERSION, is_compatible};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Status, Streaming};

use crate::handshake;
use crate::netplan::GUEST_IP;

/// How the host reaches a guest's agent.
#[derive(Clone, Debug)]
pub enum Dialer {
    /// Firecracker's vsock Unix socket.
    Vsock(PathBuf),
    /// TCP to the guest from inside this network namespace (gVisor).
    Tcp(PathBuf),
}

/// A stream to the agent; the connector returns one type for both dialers.
enum Stream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Dialer {
    async fn dial(self) -> io::Result<TokioIo<Stream>> {
        Ok(TokioIo::new(match self {
            Self::Vsock(uds) => Stream::Unix(dial_vsock(uds).await?),
            Self::Tcp(netns) => Stream::Tcp(dial_tcp(netns).await?),
        }))
    }
}

/// Opens a host-side stream to the guest agent through Firecracker's vsock
/// Unix socket.
async fn dial_vsock(uds: PathBuf) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(&uds).await?;
    stream
        .write_all(format!("CONNECT {GUEST_VSOCK_PORT}\n").as_bytes())
        .await?;
    // Read byte by byte so no gRPC bytes after the newline are consumed.
    let mut line = Vec::new();
    let mut byte = [0];
    while stream.read(&mut byte).await? == 1 && byte[0] != b'\n' && line.len() < 64 {
        line.push(byte[0]);
    }
    handshake::parse_ok(&line).map_err(io::Error::other)?;
    Ok(stream)
}

/// Connects to the agent from inside the namespace at `netns`. The socket is
/// made on a new thread that joins the namespace and then ends, so no other
/// work runs there.
async fn dial_tcp(netns: PathBuf) -> io::Result<TcpStream> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let connected = (|| {
            let ns = std::fs::File::open(&netns)?;
            nix::sched::setns(ns, nix::sched::CloneFlags::CLONE_NEWNET)?;
            let addr = SocketAddr::from((GUEST_IP, GUEST_TCP_PORT));
            let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
            stream.set_nonblocking(true)?;
            stream.set_nodelay(true)?;
            io::Result::Ok(stream)
        })();
        let _ = tx.send(connected);
    });
    let stream = rx.await.map_err(io::Error::other)??;
    TcpStream::from_std(stream)
}

impl tokio::io::AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Self::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Self::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
            Self::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Self::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Retries until the guest agent answers, because it may still be booting.
pub async fn connect(dialer: &Dialer, timeout: Duration) -> Result<Channel> {
    let deadline = Instant::now() + timeout;
    // A refused TCP connection costs a thread; vsock retries are cheap.
    let pause = match dialer {
        Dialer::Vsock(_) => Duration::from_millis(1),
        Dialer::Tcp(_) => Duration::from_millis(5),
    };
    loop {
        let dialer = dialer.clone();
        let connector = tower::service_fn(move |_: Uri| dialer.clone().dial());
        match Endpoint::from_static("http://guest")
            .connect_with_connector(connector)
            .await
        {
            Ok(channel) => return Ok(channel),
            Err(error) if Instant::now() > deadline => {
                return Err(error).context("guest agent did not answer");
            }
            Err(_) => tokio::time::sleep(pause).await,
        }
    }
}

pub async fn hello(channel: &Channel) -> Result<String> {
    let reply = HealthClient::new(channel.clone())
        .hello(HelloRequest {
            host_version: Some(PROTOCOL_VERSION),
        })
        .await?
        .into_inner();
    let guest = reply
        .guest_version
        .context("guest sent no protocol version")?;
    if !is_compatible(&PROTOCOL_VERSION, &guest) {
        bail!(
            "guest protocol {}.{} is not compatible",
            guest.major,
            guest.minor
        );
    }
    Ok(reply.agent_version)
}

pub async fn apply(channel: &Channel, request: ApplyRequest) -> Result<()> {
    IdentityClient::new(channel.clone()).apply(request).await?;
    Ok(())
}

/// Mounts attached volumes in the guest, each at its path. In a VM the
/// guest waits until each disk shows the volume's size.
pub async fn mount(channel: &Channel, volumes: &[(crate::Attach, String)]) -> Result<()> {
    if volumes.is_empty() {
        return Ok(());
    }
    let mut request = MountRequest::default();
    for (volume, path) in volumes {
        let size_bytes = std::fs::metadata(&volume.file)
            .with_context(|| format!("volume {}", volume.file.display()))?
            .len();
        request.volumes.push(VolumeMount {
            slot: volume.slot,
            path: path.clone(),
            read_only: volume.read_only,
            size_bytes,
        });
    }
    VolumesClient::new(channel.clone()).mount(request).await?;
    Ok(())
}

/// Flushes and freezes the guest's writable disk. Stop the VM right after.
pub async fn seal(channel: &Channel) -> Result<()> {
    ImageClient::new(channel.clone())
        .seal(SealRequest {})
        .await?;
    Ok(())
}

/// Pulls an image and unpacks it at `dest` in the guest, writing its
/// progress to `log`. Returns the image's digest.
pub async fn unpack(
    channel: &Channel,
    reference: &str,
    dest: &str,
    ca: Option<&str>,
    log: &mut (dyn std::io::Write + Send),
) -> Result<String> {
    let request = UnpackRequest {
        reference: reference.to_owned(),
        dest: dest.to_owned(),
        extra_ca_pem: ca.unwrap_or_default().to_owned(),
    };
    let mut events = ImageClient::new(channel.clone())
        .unpack(request)
        .await?
        .into_inner();
    let mut digest = None;
    while let Some(event) = events.message().await? {
        match event.event {
            Some(unpack_event::Event::Line(line)) => {
                let _ = writeln!(log, "{line}");
            }
            Some(unpack_event::Event::Digest(d)) => digest = Some(d),
            None => {}
        }
    }
    digest.context("the guest stopped before the image was unpacked")
}

pub struct Output {
    pub stdout: String,
    pub first_output: Option<Duration>,
}

/// Starts a command and returns its event stream. Dropping the stream kills
/// the command.
pub async fn exec_stream(
    channel: &Channel,
    request: ExecRequest,
) -> Result<Streaming<ExecEvent>, Status> {
    Ok(ProcessClient::new(channel.clone())
        .exec(request)
        .await?
        .into_inner())
}

/// Runs a command as `user` and fails unless it exits with 0.
pub async fn exec(channel: &Channel, cmd: &str) -> Result<Output> {
    let started = Instant::now();
    let request = ExecRequest {
        cmd: cmd.to_owned(),
        timeout_ms: 30_000,
        ..Default::default()
    };
    let mut events = exec_stream(channel, request).await?;
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let mut first_output = None;
    let mut exit: Option<ExecExit> = None;
    while let Some(event) = events.message().await? {
        match event.event {
            Some(Event::Stdout(bytes)) => {
                first_output.get_or_insert_with(|| started.elapsed());
                stdout.extend(bytes);
            }
            Some(Event::Stderr(bytes)) => stderr.extend(bytes),
            Some(Event::Exit(e)) => exit = Some(e),
            None => {}
        }
    }
    let exit = exit.context("exec stream ended without an exit event")?;
    if exit.exit_code != Some(0) {
        bail!(
            "`{cmd}` failed with {exit:?}: {}",
            String::from_utf8_lossy(&stderr)
        );
    }
    Ok(Output {
        stdout: String::from_utf8_lossy(&stdout).trim().to_owned(),
        first_output,
    })
}
