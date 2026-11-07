# OTLP traces

Status: done. Tested on the KVM primary and worker with a small OTLP/HTTP
receiver: a create sent with a `traceparent` made `sandbox.place` on the
primary (child of the caller), `sandbox.create` on the worker (child of
`sandbox.place`) with `claim`, `restore` and `fixups`, and an exec made
`sandbox.exec` with `open`, `start` and `exit_code`. The events of the
calls had the same trace ID.

## Goal

The spec's Traces section: each create, exec and snapshot is one trace
with a span per step on the hot path.

## Design

- `traces.rs` uses the OpenTelemetry SDK that already sends events as
  logs, with the `trace` features. `--otlp-endpoint` sends both; there is
  no new flag. Without it, every call here does nothing.
- A call's span is a child of the caller's `traceparent`, or a new trace.
  The call's `Origin` is changed to point at the new span, so its events
  (and the egress events during an exec) join the trace.
- Step spans are made after the step with explicit start and end times
  (`Instant` mapped to wall time). The create code keeps its shape; it only
  notes when each step starts.
- `Runtime::create` wraps `create_traced`; an error sets the span status.
- `exec`'s span lives in the `ExecLog` and ends when the command ends, with
  `exit_code`, `cancelled` or an error status.
- The primary's `sandbox.place` span replaces the `traceparent` it sends
  to the worker, so the worker's spans are its children.
- Snapshot spans come with the snapshot API.
