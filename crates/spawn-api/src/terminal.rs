//! `GET /v1/sandboxes/{id}/pty`: an interactive terminal over a WebSocket.
//!
//! Binary frames carry terminal bytes both ways. Text frames are JSON:
//! `{"type":"resize","cols","rows"}` or `{"type":"input","data"}` from the
//! client, and one `{"type":"exit",...}` or `{"type":"error","message"}`
//! from the server before it closes.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use std::time::Instant;

use axum::extract::{Extension, Path, Query, State};
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};
use spawn_proto::guest::v1::pty_client::PtyClient;
use spawn_proto::guest::v1::pty_input::Input;
use spawn_proto::guest::v1::pty_output::Output;
use spawn_proto::guest::v1::{PtyInput, PtyOutput, PtySize, PtyStart};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Code as GrpcCode, Streaming};

use crate::events::Origin;
use crate::model::{ApiError, check_user};
use crate::server::AppState;

const MAX_CMD_BYTES: usize = 64 * 1024;
const MAX_SIZE: u32 = 1000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PtyQuery {
    cols: Option<u32>,
    rows: Option<u32>,
    user: Option<String>,
    cwd: Option<String>,
    cmd: Option<String>,
    /// Read by the auth layer.
    #[serde(rename = "session_token")]
    _session_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    Resize { cols: u32, rows: u32 },
    Input { data: String },
}

impl PtyQuery {
    fn check(&self) -> Result<(), ApiError> {
        for (name, n) in [("cols", self.cols), ("rows", self.rows)] {
            if n.is_some_and(|n| n == 0 || n > MAX_SIZE) {
                return Err(ApiError::invalid(format!("{name} must be 1 to {MAX_SIZE}")));
            }
        }
        if let Some(user) = &self.user {
            check_user(user)?;
        }
        if let Some(cwd) = &self.cwd
            && (!cwd.starts_with('/') || cwd.contains('\0'))
        {
            return Err(ApiError::invalid("cwd must be an absolute path"));
        }
        if let Some(cmd) = &self.cmd
            && (cmd.len() > MAX_CMD_BYTES || cmd.contains('\0'))
        {
            return Err(ApiError::invalid(format!(
                "cmd must be at most {MAX_CMD_BYTES} bytes with no NUL"
            )));
        }
        Ok(())
    }
}

pub async fn open(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path(id): Path<String>,
    Query(query): Query<PtyQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    query.check()?;
    let opened = app.sandboxes.open(&id, &origin).await?;
    let (tenant, channel, env, busy) = (opened.tenant, opened.channel, opened.env, opened.busy);
    let opened_attrs = json!({
        "cmd": query.cmd,
        "cwd": query.cwd,
        "user": query.user,
    });
    let (tx, rx) = mpsc::channel(64);
    let start = PtyStart {
        cmd: query.cmd.unwrap_or_default(),
        cwd: query.cwd.unwrap_or_default(),
        env: env.into_iter().collect(),
        user: query.user.unwrap_or_default(),
        cols: query.cols.unwrap_or(80),
        rows: query.rows.unwrap_or(24),
    };
    // Sent before the call, which returns once the guest started the shell.
    let _ = tx
        .send(PtyInput {
            input: Some(Input::Start(start)),
        })
        .await;
    let output = PtyClient::new(channel)
        .open(ReceiverStream::new(rx))
        .await
        .map_err(|status| match status.code() {
            GrpcCode::InvalidArgument | GrpcCode::FailedPrecondition => {
                ApiError::invalid(status.message())
            }
            _ => ApiError::internal(format!("guest agent: {}", status.message())),
        })?
        .into_inner();
    let sandboxes = app.sandboxes.clone();
    Ok(ws.on_upgrade(move |socket| async move {
        // The sandbox is busy while the terminal is open.
        let _busy = busy;
        let _running = sandboxes.hub.begin(&id, &origin);
        let started = Instant::now();
        sandboxes.event("pty.opened", &origin, &tenant, &id, opened_attrs);
        let mut closed = bridge(socket, tx, output).await;
        if closed.get("duration_ms").is_none() {
            closed["duration_ms"] =
                json!(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
        }
        sandboxes.event("pty.closed", &origin, &tenant, &id, closed);
    }))
}

/// Returns how the terminal ended, for `pty.closed`.
async fn bridge(
    mut socket: WebSocket,
    input: mpsc::Sender<PtyInput>,
    mut output: Streaming<PtyOutput>,
) -> Value {
    let send = |input: Input| PtyInput { input: Some(input) };
    loop {
        tokio::select! {
            message = socket.recv() => {
                let input_message = match message {
                    Some(Ok(Message::Binary(data))) => send(Input::Data(data.to_vec())),
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<ClientMessage>(text.as_str()) {
                            Ok(ClientMessage::Resize { cols, rows }) => {
                                send(Input::Resize(PtySize { cols, rows }))
                            }
                            Ok(ClientMessage::Input { data }) => send(Input::Data(data.into_bytes())),
                            Err(error) => {
                                let _ = socket.send(error_frame(&format!("bad message: {error}"))).await;
                                continue;
                            }
                        }
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                    // The client left: hang up the terminal.
                    Some(Ok(Message::Close(_)) | Err(_)) | None => {
                        drop(input);
                        drain(&mut output).await;
                        return json!({ "reason": "client left" });
                    }
                };
                if input.send(input_message).await.is_err() {
                    return json!({ "reason": "guest connection closed" });
                }
            }
            message = output.message() => {
                match message {
                    Ok(Some(PtyOutput { output: Some(Output::Data(data)) })) => {
                        if socket.send(Message::Binary(data.into())).await.is_err() {
                            return json!({ "reason": "client left" });
                        }
                    }
                    Ok(Some(PtyOutput { output: Some(Output::Exit(exit)) })) => {
                        let mut exit = json!({
                            "type": "exit",
                            "exit_code": exit.exit_code,
                            "signal": exit.signal,
                            "duration_ms": exit.duration_ms,
                        });
                        let _ = socket.send(Message::Text(exit.to_string().into())).await;
                        let _ = socket.send(Message::Close(None)).await;
                        if let Some(map) = exit.as_object_mut() {
                            map.remove("type");
                        }
                        return exit;
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        let _ = socket.send(error_frame("terminal ended without an exit status")).await;
                        let _ = socket.send(Message::Close(None)).await;
                        return json!({ "error": "terminal ended without an exit status" });
                    }
                    Err(status) => {
                        eprintln!("pty: guest agent: {}", status.message());
                        let _ = socket.send(error_frame(&format!("guest agent: {}", status.message()))).await;
                        let _ = socket.send(Message::Close(None)).await;
                        return json!({ "error": format!("guest agent: {}", status.message()) });
                    }
                }
            }
        }
    }
}

/// Waits briefly for the hung-up shell to exit, so the guest can reap it
/// before the call is cancelled.
async fn drain(output: &mut Streaming<PtyOutput>) {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Ok(Some(_)) = output.message().await {}
    })
    .await;
}

fn error_frame(message: &str) -> Message {
    Message::Text(
        json!({ "type": "error", "message": message })
            .to_string()
            .into(),
    )
}
