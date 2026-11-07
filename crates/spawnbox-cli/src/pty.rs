//! `spawnbox sh`: a terminal in the sandbox over the PTY WebSocket.

use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{Connector, connect_async_tls_with_config};

use crate::api::{Api, ApiError, seg};

pub struct Options<'a> {
    pub user: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub cmd: Option<&'a str>,
}

/// Restores the terminal even when the session fails.
struct RawMode;

impl RawMode {
    fn enable() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().context("set the terminal to raw mode")?;
        Ok(Self)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Runs the session and returns the shell's exit code.
pub async fn run(api: &Api, id: &str, options: &Options<'_>) -> Result<i32> {
    let tty = std::io::stdin().is_terminal();
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let mut url = url::Url::parse(&format!("{}/v1/sandboxes/{}/pty", api.base(), seg(id)))?;
    let secure = url.scheme() == "https";
    url.set_scheme(if secure { "wss" } else { "ws" })
        .map_err(|()| anyhow::anyhow!("cannot make a WebSocket URL from {}", api.base()))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("cols", &cols.to_string());
        query.append_pair("rows", &rows.to_string());
        for (name, value) in [
            ("user", options.user),
            ("cwd", options.cwd),
            ("cmd", options.cmd),
        ] {
            if let Some(value) = value {
                query.append_pair(name, value);
            }
        }
    }
    let mut request = url.as_str().into_client_request()?;
    let headers = request.headers_mut();
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", api.key())).context("API key")?,
    );
    if let Some(step) = api.step() {
        headers.insert("X-Spawnbox-Step", HeaderValue::from_str(step)?);
    }
    let connector = if secure {
        use rustls_platform_verifier::ConfigVerifierExt;
        Some(Connector::Rustls(Arc::new(
            rustls::ClientConfig::with_platform_verifier()?,
        )))
    } else {
        None
    };
    let (socket, _) = match connect_async_tls_with_config(request, None, true, connector).await {
        Ok(connected) => connected,
        Err(WsError::Http(response)) => {
            let status = response.status().as_u16();
            let body = response.body().clone().unwrap_or_default();
            let status = reqwest::StatusCode::from_u16(status)?;
            return Err(ApiError::from_body(status, &body).into());
        }
        Err(error) => return Err(error).with_context(|| format!("cannot reach {}", api.base())),
    };
    let (mut sink, mut stream) = socket.split();

    let _raw = if tty { Some(RawMode::enable()?) } else { None };
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut buf = vec![0u8; 16 * 1024];
    let mut stdin_open = true;
    let mut resized = resize_signal()?;

    loop {
        tokio::select! {
            message = stream.next() => {
                let message = match message {
                    Some(message) => message.context("the terminal connection broke")?,
                    None => bail!("the terminal closed without an exit status"),
                };
                match message {
                    Message::Binary(bytes) => {
                        stdout.write_all(&bytes).await?;
                        stdout.flush().await?;
                    }
                    Message::Text(text) => {
                        let value: Value = serde_json::from_str(&text).unwrap_or_default();
                        if value["type"] == "exit" {
                            let _ = sink.close().await;
                            return Ok(exit_code(&value));
                        }
                    }
                    Message::Close(_) => bail!("the terminal closed without an exit status"),
                    _ => {}
                }
            }
            read = stdin.read(&mut buf), if stdin_open => {
                let n = read.context("read stdin")?;
                if n == 0 {
                    stdin_open = false;
                } else {
                    sink.send(Message::binary(buf[..n].to_vec())).await?;
                }
            }
            () = next_resize(&mut resized) => {
                if let Ok((cols, rows)) = crossterm::terminal::size() {
                    let frame = json!({"type": "resize", "cols": cols, "rows": rows});
                    sink.send(Message::text(frame.to_string())).await?;
                }
            }
        }
    }
}

/// `exit_code`, or 128 + the signal number, like a shell.
pub fn exit_code(exit: &Value) -> i32 {
    if let Some(code) = exit["exit_code"].as_i64() {
        return i32::try_from(code).unwrap_or(1);
    }
    exit["signal"]
        .as_i64()
        .and_then(|signal| i32::try_from(128 + signal).ok())
        .unwrap_or(1)
}

#[cfg(unix)]
type Resize = tokio::signal::unix::Signal;
#[cfg(not(unix))]
type Resize = ();

#[cfg(unix)]
fn resize_signal() -> Result<Resize> {
    use tokio::signal::unix::{SignalKind, signal};
    signal(SignalKind::window_change()).context("listen for terminal resizes")
}

#[cfg(not(unix))]
fn resize_signal() -> Result<Resize> {
    Ok(())
}

#[cfg(unix)]
async fn next_resize(signal: &mut Resize) {
    if signal.recv().await.is_none() {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(unix))]
async fn next_resize(_: &mut Resize) {
    std::future::pending::<()>().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_follows_shell_rules() {
        assert_eq!(exit_code(&json!({"exit_code": 3, "signal": null})), 3);
        assert_eq!(exit_code(&json!({"exit_code": null, "signal": 9})), 137);
        assert_eq!(exit_code(&json!({})), 1);
    }
}
