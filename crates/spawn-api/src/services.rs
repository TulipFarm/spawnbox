//! The `/services` API of a sandbox: state, restarts and logs.

use std::convert::Infallible;

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::events::Origin;
use crate::ids;
use crate::model::{ApiError, Code};
use crate::server::AppState;
use crate::utf8::Utf8Stream;

/// `GET /v1/sandboxes/{id}/services`
pub async fn list(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let services = app.sandboxes.services(&id, &origin).await?;
    Ok(Json(json!({ "services": services })))
}

/// `POST /v1/sandboxes/{id}/services/{name}:restart`. The router sees the
/// action as part of the name.
pub async fn action(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path((id, name_action)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let Some((name, "restart")) = name_action.split_once(':') else {
        return Err(ApiError::new(Code::NotFound, "no such endpoint"));
    };
    let name = name.to_owned();
    tokio::spawn(async move { app.sandboxes.restart_service(&id, &name, &origin).await })
        .await
        .map_err(|error| ApiError::internal(format!("task failed: {error}")))??;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct LogsQuery {
    #[serde(default)]
    follow: bool,
}

/// `GET /v1/sandboxes/{id}/services/{name}/logs`: the service's recent
/// output as text, or with `?follow=true` as SSE `output` events with
/// `{"text": ...}` that go on with new output.
pub async fn logs(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path((id, name)): Path<(String, String)>,
    Query(query): Query<LogsQuery>,
) -> Result<Response, ApiError> {
    let (mut chunks, busy) = app
        .sandboxes
        .service_logs(&id, &name, query.follow, &origin)
        .await?;
    if !query.follow {
        let mut text = Vec::new();
        while let Some(chunk) = chunks
            .message()
            .await
            .map_err(|status| ApiError::from_guest(&status))?
        {
            text.extend_from_slice(&chunk.data);
        }
        drop(busy);
        let headers = [(header::CONTENT_TYPE, "text/plain; charset=utf-8")];
        return Ok((headers, String::from_utf8_lossy(&text).into_owned()).into_response());
    }
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(32);
    tokio::spawn(async move {
        let _busy = busy;
        let mut text = Utf8Stream::default();
        loop {
            let message = tokio::select! {
                message = chunks.message() => message,
                () = tx.closed() => return,
            };
            let event = match message {
                Ok(Some(chunk)) => {
                    let text = text.push(&chunk.data);
                    if text.is_empty() {
                        continue;
                    }
                    Event::default()
                        .event("output")
                        .data(json!({ "text": text }).to_string())
                }
                Ok(None) => return,
                Err(status) => {
                    let error = ApiError::from_guest(&status);
                    let request_id = ids::new_id("req").unwrap_or_default();
                    eprintln!("{request_id}: {}", error.message);
                    let event = Event::default()
                        .event("error")
                        .data(error.body(&request_id).to_string());
                    let _ = tx.send(Ok(event)).await;
                    return;
                }
            };
            if tx.send(Ok(event)).await.is_err() {
                return;
            }
        }
    });
    Ok(Sse::new(ReceiverStream::new(rx))
        .keep_alive(KeepAlive::default())
        .into_response())
}
