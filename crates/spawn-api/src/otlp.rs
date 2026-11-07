//! Sends every stored event to an OpenTelemetry collector as an OTLP log
//! record over HTTP.

use anyhow::{Context, Result};
use opentelemetry::logs::{AnyValue, LogRecord, Logger, LoggerProvider, Severity};
use opentelemetry::{SpanId, TraceFlags, TraceId};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::{SdkLogger, SdkLoggerProvider};
use serde_json::Value;

use crate::events::NewEvent;

pub struct Otlp {
    provider: SdkLoggerProvider,
    logger: SdkLogger,
}

impl Otlp {
    /// `endpoint` is the collector's base URL; `/v1/logs` is added. Headers
    /// come from `OTEL_EXPORTER_OTLP_HEADERS`.
    pub fn new(endpoint: &str) -> Result<Self> {
        let url = format!("{}/v1/logs", endpoint.trim_end_matches('/'));
        let exporter = opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_endpoint(url)
            .build()
            .context("create the OTLP log exporter")?;
        let provider = SdkLoggerProvider::builder()
            .with_resource(Resource::builder().with_service_name("spawnbox").build())
            .with_batch_exporter(exporter)
            .build();
        let logger = provider.logger("spawnbox");
        Ok(Self { provider, logger })
    }

    /// Queues one event. The batch processor sends it from its own thread.
    pub fn export(&self, id: i64, event: &NewEvent) {
        let mut record = self.logger.create_log_record();
        record.set_event_name(event.kind);
        record.set_body(AnyValue::from(event.kind));
        record.set_severity_number(Severity::Info);
        record.set_severity_text("INFO");
        if let Ok(ms) = u64::try_from(event.ts) {
            record.set_timestamp(std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms));
        }
        record.add_attribute("spawnbox.event.id", id);
        for (key, value) in [
            ("spawnbox.tenant", &event.tenant),
            ("spawnbox.sandbox", &event.sandbox),
            ("spawnbox.step_id", &event.step_id),
            ("spawnbox.actor", &event.actor),
        ] {
            if let Some(value) = value {
                record.add_attribute(key, value.clone());
            }
        }
        if let Value::Object(attrs) = &event.attrs {
            for (key, value) in attrs {
                if let Some(value) = any_value(value) {
                    record.add_attribute(format!("spawnbox.{key}"), value);
                }
            }
        }
        if let Some(trace) = &event.trace
            && let (Ok(trace_id), Ok(span_id)) = (
                TraceId::from_hex(&trace.trace_id),
                SpanId::from_hex(&trace.span_id),
            )
        {
            let flags = if trace.sampled {
                TraceFlags::SAMPLED
            } else {
                TraceFlags::default()
            };
            record.set_trace_context(trace_id, span_id, Some(flags));
        }
        self.logger.emit(record);
    }

    /// Sends what is queued and stops. Blocks.
    pub fn shutdown(&self) {
        if let Err(err) = self.provider.shutdown() {
            eprintln!("otlp: shutdown: {err}");
        }
    }
}

fn any_value(value: &Value) -> Option<AnyValue> {
    Some(match value {
        Value::Null => return None,
        Value::Bool(b) => AnyValue::Boolean(*b),
        Value::Number(n) => match n.as_i64() {
            Some(i) => AnyValue::Int(i),
            None => AnyValue::Double(n.as_f64()?),
        },
        Value::String(s) => AnyValue::from(s.clone()),
        Value::Array(items) => {
            AnyValue::ListAny(Box::new(items.iter().filter_map(any_value).collect()))
        }
        Value::Object(map) => AnyValue::Map(Box::new(
            map.iter()
                .filter_map(|(k, v)| Some((k.clone().into(), any_value(v)?)))
                .collect(),
        )),
    })
}
