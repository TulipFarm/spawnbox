use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::process::ExitCode;

use spawn_proto::guest::v1::files_server::{Files, FilesServer};
use spawn_proto::guest::v1::health_server::{Health, HealthServer};
use spawn_proto::guest::v1::identity_server::{Identity, IdentityServer};
use spawn_proto::guest::v1::image_server::{Image, ImageServer};
use spawn_proto::guest::v1::ports_server::{Ports, PortsServer};
use spawn_proto::guest::v1::process_server::{Process, ProcessServer};
use spawn_proto::guest::v1::pty_server::{Pty, PtyServer};
use spawn_proto::guest::v1::services_client::ServicesClient;
use spawn_proto::guest::v1::services_server::{Services, ServicesServer};
use spawn_proto::guest::v1::volumes_server::{Volumes, VolumesServer};
use spawn_proto::guest::v1::{
    ApplyRequest, ApplyResponse, ExecEvent, ExecRequest, FileInfo, HelloRequest, HelloResponse,
    ListResponse, MountRequest, MountResponse, PathRequest, PortInput, PortOutput, PtyInput,
    PtyOutput, ReadChunk, RemoveRequest, RemoveResponse, SealRequest, SealResponse, ServiceEvent,
    ServiceLogChunk, ServiceLogsRequest, ServiceRestartRequest, ServiceRestartResponse,
    ServicesListRequest, ServicesListResponse, ServicesStartRequest, ServicesStartResponse,
    ServicesWatchRequest, UnpackEvent, UnpackRequest, WriteChunk, port_input, pty_input,
};
use spawn_proto::{GUEST_TCP_PORT, GUEST_VSOCK_PORT, PROTOCOL_VERSION};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_stream::{Stream, StreamExt};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Request, Response, Status, Streaming};

use crate::{exec, files, identity, ports, pty, unpack, volumes};

pub fn run() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("spawn-guest: cannot start runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("spawn-guest: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Under gVisor the host connects from the gateway address of the sandbox
/// network (`spawn_node::netplan::GATEWAY_IP`). Processes in the sandbox
/// cannot send from it, so they cannot use the agent.
const HOST_IP: Ipv4Addr = Ipv4Addr::new(172, 16, 0, 1);

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let services = services();
    if crate::under_gvisor() {
        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, GUEST_TCP_PORT))).await?;
        eprintln!("spawn-guest: listening on TCP port {GUEST_TCP_PORT}");
        let incoming = TcpListenerStream::new(listener).filter(|conn| match conn {
            Ok(stream) => stream
                .peer_addr()
                .is_ok_and(|peer| peer.ip() == std::net::IpAddr::V4(HOST_IP)),
            Err(_) => true,
        });
        services.serve_with_incoming(incoming).await?;
    } else {
        let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, GUEST_VSOCK_PORT))?;
        eprintln!("spawn-guest: listening on vsock port {GUEST_VSOCK_PORT}");
        services.serve_with_incoming(listener.incoming()).await?;
    }
    Ok(())
}

fn services() -> tonic::transport::server::Router {
    tonic::transport::Server::builder()
        .add_service(HealthServer::new(Agent))
        .add_service(IdentityServer::new(Agent))
        .add_service(ProcessServer::new(Agent))
        .add_service(FilesServer::new(Agent))
        .add_service(ImageServer::new(Agent))
        .add_service(PtyServer::new(Agent))
        .add_service(PortsServer::new(Agent))
        .add_service(VolumesServer::new(Agent))
        .add_service(ServicesServer::new(Agent))
}

struct Agent;

#[tonic::async_trait]
impl Health for Agent {
    async fn hello(&self, _: Request<HelloRequest>) -> Result<Response<HelloResponse>, Status> {
        Ok(Response::new(HelloResponse {
            guest_version: Some(PROTOCOL_VERSION),
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        }))
    }
}

#[tonic::async_trait]
impl Identity for Agent {
    async fn apply(&self, req: Request<ApplyRequest>) -> Result<Response<ApplyResponse>, Status> {
        let req = req.into_inner();
        // gVisor reads the host's clock and random source, so every clone
        // already has the right time and its own random numbers.
        let gvisor = crate::under_gvisor();

        if !req.entropy.is_empty() && !gvisor {
            identity::add_entropy(&req.entropy).map_err(Status::internal)?;
        }
        if req.wall_clock_unix_nanos > 0 && !gvisor {
            let nanos = req.wall_clock_unix_nanos;
            let time = nix::sys::time::TimeSpec::new(
                nanos.div_euclid(1_000_000_000),
                nanos.rem_euclid(1_000_000_000),
            );
            nix::time::clock_settime(nix::time::ClockId::CLOCK_REALTIME, time)
                .map_err(|e| Status::internal(format!("clock_settime: {e}")))?;
        }
        if !req.hostname.is_empty() {
            identity::validate_hostname(&req.hostname).map_err(Status::invalid_argument)?;
            nix::unistd::sethostname(&req.hostname)
                .map_err(|e| Status::internal(format!("sethostname: {e}")))?;
        }
        if !req.sandbox_id.is_empty() {
            identity::validate_hostname(&req.sandbox_id).map_err(Status::invalid_argument)?;
            std::fs::create_dir_all("/run/spawn")
                .and_then(|()| std::fs::write("/run/spawn/sandbox-id", &req.sandbox_id))
                .map_err(|e| Status::internal(format!("write sandbox id: {e}")))?;
        }
        Ok(Response::new(ApplyResponse {}))
    }
}

type ExecStream = Pin<Box<dyn Stream<Item = Result<ExecEvent, Status>> + Send>>;

#[tonic::async_trait]
impl Process for Agent {
    type ExecStream = ExecStream;

    async fn exec(&self, req: Request<ExecRequest>) -> Result<Response<ExecStream>, Status> {
        let req = req.into_inner();
        let timeout_ms = req.timeout_ms;
        let (child, started) = exec::start(req)?;
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(exec::run(child, started, timeout_ms, tx));
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

type ReadStream = Pin<Box<dyn Stream<Item = Result<ReadChunk, Status>> + Send>>;

#[tonic::async_trait]
impl Files for Agent {
    type ReadStream = ReadStream;

    async fn stat(&self, req: Request<PathRequest>) -> Result<Response<FileInfo>, Status> {
        let req = req.into_inner();
        files::stat(&req.path, &req.user).await.map(Response::new)
    }

    async fn read(&self, req: Request<PathRequest>) -> Result<Response<ReadStream>, Status> {
        let req = req.into_inner();
        let (file, info) = files::open(&req.path, &req.user).await?;
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(files::send_file(file, info, tx));
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn write(
        &self,
        req: Request<Streaming<WriteChunk>>,
    ) -> Result<Response<FileInfo>, Status> {
        files::write(req.into_inner()).await.map(Response::new)
    }

    async fn list(&self, req: Request<PathRequest>) -> Result<Response<ListResponse>, Status> {
        let req = req.into_inner();
        files::list(&req.path, &req.user).await.map(Response::new)
    }

    async fn remove(
        &self,
        req: Request<RemoveRequest>,
    ) -> Result<Response<RemoveResponse>, Status> {
        let req = req.into_inner();
        files::remove(&req.path, &req.user, req.recursive).await?;
        Ok(Response::new(RemoveResponse {}))
    }
}

type UnpackStream = Pin<Box<dyn Stream<Item = Result<UnpackEvent, Status>> + Send>>;

#[tonic::async_trait]
impl Image for Agent {
    type UnpackStream = UnpackStream;

    async fn unpack(
        &self,
        req: Request<UnpackRequest>,
    ) -> Result<Response<Self::UnpackStream>, Status> {
        let events = unpack::start(req.into_inner());
        Ok(Response::new(Box::pin(ReceiverStream::new(events))))
    }

    async fn seal(&self, _: Request<SealRequest>) -> Result<Response<SealResponse>, Status> {
        files::seal().await?;
        Ok(Response::new(SealResponse {}))
    }
}

#[tonic::async_trait]
impl Volumes for Agent {
    async fn mount(&self, req: Request<MountRequest>) -> Result<Response<MountResponse>, Status> {
        volumes::mount_all(req.into_inner().volumes).await?;
        Ok(Response::new(MountResponse {}))
    }
}

type PtyStream = Pin<Box<dyn Stream<Item = Result<PtyOutput, Status>> + Send>>;

#[tonic::async_trait]
impl Pty for Agent {
    type OpenStream = PtyStream;

    async fn open(&self, req: Request<Streaming<PtyInput>>) -> Result<Response<PtyStream>, Status> {
        let mut input = req.into_inner();
        let Some(PtyInput {
            input: Some(pty_input::Input::Start(start)),
        }) = input.message().await?
        else {
            return Err(Status::invalid_argument("the first message must be start"));
        };
        let session = pty::start(start)?;
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(pty::run(session, input, tx));
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

type PortStream = Pin<Box<dyn Stream<Item = Result<PortOutput, Status>> + Send>>;

#[tonic::async_trait]
impl Ports for Agent {
    type DialStream = PortStream;

    async fn dial(
        &self,
        req: Request<Streaming<PortInput>>,
    ) -> Result<Response<PortStream>, Status> {
        let mut input = req.into_inner();
        let Some(PortInput {
            input: Some(port_input::Input::Open(open)),
        }) = input.message().await?
        else {
            return Err(Status::invalid_argument("the first message must be open"));
        };
        let stream = ports::open(open.port).await?;
        let (tx, rx) = mpsc::channel(16);
        ports::run(stream, input, tx);
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

/// The supervisor in PID 1, which runs the services.
async fn supervisor() -> Result<ServicesClient<Channel>, Status> {
    let channel = Endpoint::from_static("http://supervisor")
        .connect_with_connector(tower::service_fn(|_: Uri| async {
            tokio::net::UnixStream::connect(crate::supervisor::SOCKET)
                .await
                .map(hyper_util::rt::TokioIo::new)
        }))
        .await
        .map_err(|e| Status::unavailable(format!("the services supervisor is not running: {e}")))?;
    Ok(ServicesClient::new(channel))
}

/// The agent forwards the host's calls to the supervisor.
#[tonic::async_trait]
impl Services for Agent {
    type LogsStream = Streaming<ServiceLogChunk>;
    type WatchStream = Streaming<ServiceEvent>;

    async fn start(
        &self,
        req: Request<ServicesStartRequest>,
    ) -> Result<Response<ServicesStartResponse>, Status> {
        supervisor().await?.start(req.into_inner()).await
    }

    async fn list(
        &self,
        req: Request<ServicesListRequest>,
    ) -> Result<Response<ServicesListResponse>, Status> {
        supervisor().await?.list(req.into_inner()).await
    }

    async fn restart(
        &self,
        req: Request<ServiceRestartRequest>,
    ) -> Result<Response<ServiceRestartResponse>, Status> {
        supervisor().await?.restart(req.into_inner()).await
    }

    async fn logs(
        &self,
        req: Request<ServiceLogsRequest>,
    ) -> Result<Response<Self::LogsStream>, Status> {
        supervisor().await?.logs(req.into_inner()).await
    }

    async fn watch(
        &self,
        req: Request<ServicesWatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        supervisor().await?.watch(req.into_inner()).await
    }
}
