//! Connections from the host to TCP ports inside the guest, for preview
//! URLs. Going through vsock means servers bound to localhost work too.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use spawn_proto::guest::v1::port_input::Input;
use spawn_proto::guest::v1::{PortInput, PortOutput};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tonic::{Status, Streaming};

pub type OutputSender = mpsc::Sender<Result<PortOutput, Status>>;

/// Connects to `port` on 127.0.0.1, then on ::1.
pub async fn open(port: u32) -> Result<TcpStream, Status> {
    let port = u16::try_from(port)
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| Status::invalid_argument(format!("bad port {port}")))?;
    let mut last = None;
    for ip in [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()] {
        match TcpStream::connect(SocketAddr::new(ip, port)).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(error) => last = Some(error),
        }
    }
    Err(Status::unavailable(format!(
        "nothing listens on port {port}: {}",
        last.map(|e| e.to_string()).unwrap_or_default()
    )))
}

/// Copies bytes both ways until either side closes.
pub fn run(stream: TcpStream, input: Streaming<PortInput>, tx: OutputSender) {
    let (read, write) = stream.into_split();
    tokio::spawn(send_output(read, tx));
    tokio::spawn(forward_input(input, write));
}

async fn send_output(mut read: OwnedReadHalf, tx: OutputSender) {
    let mut buf = vec![0; 64 * 1024];
    loop {
        match read.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let data = buf[..n].to_vec();
                if tx.send(Ok(PortOutput { data })).await.is_err() {
                    return;
                }
            }
        }
    }
}

async fn forward_input(mut input: Streaming<PortInput>, mut write: OwnedWriteHalf) {
    while let Ok(Some(message)) = input.message().await {
        if let Some(Input::Data(data)) = message.input
            && write.write_all(&data).await.is_err()
        {
            return;
        }
    }
    let _ = write.shutdown().await;
}
