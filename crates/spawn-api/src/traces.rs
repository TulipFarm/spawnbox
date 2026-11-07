//! OTLP traces: each create and exec is one trace, with a span per step.
//!
//! A call's span is a child of the caller's `traceparent`, if it sent one.
//! Events of the call carry the call's span, so logs and traces join up.
//! With no `--otlp-endpoint`, nothing here does anything.

use std::sync::OnceLock;
use std::time::{Instant, SystemTime};

use anyhow::{Context as _, Result};
use opentelemetry::trace::{
    Span as _, SpanContext, SpanKind, Status, TraceContextExt, TraceFlags, TraceId, TraceState,
    Tracer as _, TracerProvider as _,
};
use opentelemetry::{Context, KeyValue, SpanId};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};

use crate::events::{Origin, Trace};

static TRACER: OnceLock<(SdkTracerProvider, SdkTracer)> = OnceLock::new();

/// Sends traces to `endpoint` (the collector's base URL; `/v1/traces` is
/// added). Headers come from `OTEL_EXPORTER_OTLP_HEADERS`.
pub fn init(endpoint: &str) -> Result<()> {
    let url = format!("{}/v1/traces", endpoint.trim_end_matches('/'));
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(url)
        .build()
        .context("create the OTLP span exporter")?;
    install(
        SdkTracerProvider::builder()
            .with_resource(Resource::builder().with_service_name("spawnbox").build())
            .with_batch_exporter(exporter)
            .build(),
    );
    Ok(())
}

fn install(provider: SdkTracerProvider) {
    let tracer = provider.tracer("spawnbox");
    let _ = TRACER.set((provider, tracer));
}

/// Sends what is queued and stops. Blocks.
pub fn shutdown() {
    if let Some((provider, _)) = TRACER.get()
        && let Err(err) = provider.shutdown()
    {
        eprintln!("otlp: traces: shutdown: {err}");
    }
}

/// One call's span. Ends when dropped.
pub struct Traced {
    span: Option<(Context, Instant, SystemTime)>,
}

/// Starts the span of a call and makes `origin` point at it, so the call's
/// events name this span.
pub fn start(name: &'static str, origin: &mut Origin, attrs: Vec<KeyValue>) -> Traced {
    let Some((_, tracer)) = TRACER.get() else {
        return Traced { span: None };
    };
    let parent = origin
        .trace
        .as_ref()
        .and_then(remote_parent)
        .unwrap_or_default();
    let span = tracer
        .span_builder(name)
        .with_kind(SpanKind::Server)
        .with_attributes(attrs)
        .start_with_context(tracer, &parent);
    let context = span.span_context();
    origin.trace = Some(Trace {
        trace_id: format!("{:032x}", context.trace_id()),
        span_id: format!("{:016x}", context.span_id()),
        sampled: context.is_sampled(),
    });
    Traced {
        span: Some((parent.with_span(span), Instant::now(), SystemTime::now())),
    }
}

fn remote_parent(trace: &Trace) -> Option<Context> {
    let flags = if trace.sampled {
        TraceFlags::SAMPLED
    } else {
        TraceFlags::default()
    };
    let context = SpanContext::new(
        TraceId::from_hex(&trace.trace_id).ok()?,
        SpanId::from_hex(&trace.span_id).ok()?,
        flags,
        true,
        TraceState::default(),
    );
    Some(Context::new().with_remote_span_context(context))
}

impl Traced {
    /// Records a finished step as a child span.
    pub fn step(&self, name: &'static str, from: Instant, to: Instant) {
        self.step_with(name, from, to, Vec::new());
    }

    pub fn step_with(&self, name: &'static str, from: Instant, to: Instant, attrs: Vec<KeyValue>) {
        let (Some((context, began, wall)), Some((_, tracer))) = (&self.span, TRACER.get()) else {
            return;
        };
        let at = |t: Instant| match t.checked_duration_since(*began) {
            Some(after) => *wall + after,
            None => *wall - began.duration_since(t),
        };
        let mut span = tracer
            .span_builder(name)
            .with_kind(SpanKind::Internal)
            .with_start_time(at(from))
            .with_attributes(attrs)
            .start_with_context(tracer, context);
        span.end_with_timestamp(at(to));
    }

    pub fn attr(&self, attr: KeyValue) {
        if let Some((context, ..)) = &self.span {
            context.span().set_attribute(attr);
        }
    }

    pub fn fail(&self, message: impl Into<String>) {
        if let Some((context, ..)) = &self.span {
            context.span().set_status(Status::error(message.into()));
        }
    }

    /// A `traceparent` header for a call this span makes to another host.
    pub fn traceparent(&self) -> Option<String> {
        let (context, ..) = self.span.as_ref()?;
        let span = context.span();
        let context = span.span_context();
        Some(format!(
            "00-{:032x}-{:016x}-{:02x}",
            context.trace_id(),
            context.span_id(),
            context.trace_flags().to_u8()
        ))
    }
}

impl Drop for Traced {
    fn drop(&mut self) {
        if let Some((context, ..)) = &self.span {
            context.span().end();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use opentelemetry_sdk::trace::InMemorySpanExporter;

    use super::*;

    #[test]
    fn call_span_is_a_child_of_the_caller_and_steps_are_children_of_it() {
        let exporter = InMemorySpanExporter::default();
        install(
            SdkTracerProvider::builder()
                .with_simple_exporter(exporter.clone())
                .build(),
        );
        let caller = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let mut origin = Origin {
            trace: Trace::parse(caller),
            ..Origin::default()
        };
        let span = start("sandbox.create", &mut origin, Vec::new());
        let ours = origin.trace.clone().unwrap();
        assert_eq!(ours.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert_ne!(ours.span_id, "b7ad6b7169203331");
        assert_eq!(
            span.traceparent().unwrap(),
            format!("00-{}-{}-01", ours.trace_id, ours.span_id)
        );
        let begin = Instant::now();
        span.step("restore", begin, begin + Duration::from_millis(5));
        span.fail("no");
        drop(span);

        let spans = exporter.get_finished_spans().unwrap();
        let root = spans.iter().find(|s| s.name == "sandbox.create").unwrap();
        let step = spans.iter().find(|s| s.name == "restore").unwrap();
        assert_eq!(format!("{:016x}", root.parent_span_id), "b7ad6b7169203331");
        assert_eq!(
            format!("{:016x}", root.span_context.span_id()),
            ours.span_id
        );
        assert_eq!(step.parent_span_id, root.span_context.span_id());
        assert_eq!(
            step.end_time.duration_since(step.start_time).unwrap(),
            Duration::from_millis(5)
        );
        assert!(matches!(root.status, Status::Error { .. }));
    }
}
