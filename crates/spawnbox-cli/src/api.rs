//! The HTTP client: base URL, API key, step header and error bodies.

use std::fmt;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::Value;

use crate::sse;

pub struct Api {
    http: reqwest::Client,
    base: String,
    key: String,
    step: Option<String>,
}

/// An error body from the server: `{"error": {"code", "message", "request_id"}}`.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)?;
        if let Some(id) = &self.request_id {
            write!(f, " (request {id})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    pub fn from_body(status: StatusCode, body: &[u8]) -> Self {
        let parsed: Option<Value> = serde_json::from_slice(body).ok();
        let error = parsed.as_ref().and_then(|v| v.get("error"));
        let text = |key: &str| {
            error
                .and_then(|e| e.get(key))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        Self {
            status,
            code: text("code").unwrap_or_else(|| format!("http_{}", status.as_u16())),
            message: text("message").unwrap_or_else(|| {
                let body = String::from_utf8_lossy(body).trim().to_owned();
                if body.is_empty() {
                    status.canonical_reason().unwrap_or("error").to_owned()
                } else {
                    body
                }
            }),
            request_id: text("request_id"),
        }
    }

    pub fn is(error: &anyhow::Error, status: StatusCode) -> bool {
        error
            .downcast_ref::<Self>()
            .is_some_and(|e| e.status == status)
    }
}

/// Encodes one path segment, such as a template or secret name.
pub fn seg(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

impl Api {
    pub fn new(base: &str, key: String, step: Option<String>) -> Result<Self> {
        let base = base.trim_end_matches('/').to_owned();
        let parsed = url::Url::parse(&base).with_context(|| format!("server URL {base:?}"))?;
        anyhow::ensure!(
            matches!(parsed.scheme(), "http" | "https"),
            "server URL must start with http:// or https://"
        );
        let http = reqwest::Client::builder()
            .user_agent(concat!("spawnbox-cli/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            base,
            key,
            step,
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn step(&self) -> Option<&str> {
        self.step.as_deref()
    }

    /// A request to `/v1{path}` with the key and step headers.
    pub fn request(&self, method: Method, path: &str) -> RequestBuilder {
        let mut builder = self
            .http
            .request(method, format!("{}/v1{path}", self.base))
            .bearer_auth(&self.key);
        if let Some(step) = &self.step {
            builder = builder.header("X-Spawnbox-Step", step);
        }
        builder
    }

    /// Sends and turns a non-2xx response into an [`ApiError`].
    pub async fn send(&self, builder: RequestBuilder) -> Result<Response> {
        let response = builder
            .send()
            .await
            .with_context(|| format!("cannot reach {}", self.base))?;
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        Err(ApiError::from_body(status, &body).into())
    }

    pub async fn json(&self, builder: RequestBuilder) -> Result<Value> {
        let response = self.send(builder).await?;
        let body = response.bytes().await?;
        if body.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&body).context("server sent invalid JSON")
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        self.json(self.request(Method::GET, path)).await
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.json(self.request(Method::POST, path).json(body)).await
    }

    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.json(self.request(Method::DELETE, path)).await
    }

    /// Calls `each` for every event of an SSE response, until it returns
    /// `Some` or the stream ends.
    pub async fn events<T>(
        &self,
        builder: RequestBuilder,
        mut each: impl FnMut(sse::Event) -> Result<Option<T>>,
    ) -> Result<Option<T>> {
        let response = self
            .send(builder.header("Accept", "text/event-stream"))
            .await?;
        let mut body = response.bytes_stream();
        let mut parser = sse::Parser::default();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.context("the stream broke")?;
            for event in parser.push(&chunk) {
                if let Some(done) = each(event)? {
                    return Ok(Some(done));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_spawnbox_and_plain_error_bodies() {
        let body = br#"{"error":{"code":"not_found","message":"no such sandbox","request_id":"req_1","retryable":false}}"#;
        let error = ApiError::from_body(StatusCode::NOT_FOUND, body);
        assert_eq!(
            error.to_string(),
            "not_found: no such sandbox (request req_1)"
        );
        let error = ApiError::from_body(StatusCode::BAD_GATEWAY, b"upstream down\n");
        assert_eq!(error.to_string(), "http_502: upstream down");
        let error = ApiError::from_body(StatusCode::UNAUTHORIZED, b"");
        assert_eq!(error.to_string(), "http_401: Unauthorized");
    }

    #[test]
    fn encodes_path_segments() {
        assert_eq!(seg("py-3"), "py-3");
        assert_eq!(seg("a/b c"), "a%2Fb%20c");
    }
}
