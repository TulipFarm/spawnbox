# M2 part 2: events with step IDs, `GET /v1/events` and OTLP

Status: done.

The second of three M2 merges. The last one is usage metering.

## Event shape

```json
{
  "id": "1842",
  "ts": "2026-11-04T01:41:03.118Z",
  "tenant": "acme",
  "sandbox": "sbx_8f2kq1...",
  "step_id": "run_42/step_7",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "actor": "key_9dK2...",
  "type": "exec.finished",
  "attrs": { "exec_id": "ex_...", "cmd": "npm test", "exit_code": 1 }
}
```

- `id` grows with every event and is the cursor. There is one implicit org,
  so events have no `org`.
- `actor` is the API key ID, `system` for the server's own actions (expiry,
  idle pause, crash recovery), or `null` for network events and preview
  requests.
- `tenant` is the sandbox's tenant, or the tenant an admin action touched.
  Org-wide admin actions (an org-wide secret or template, an org key) have
  `null` and only org keys see them.

## Step IDs and traces

- `X-Spawnbox-Step` (1 to 256 visible ASCII characters, else `400`) and
  W3C `traceparent` are read on every `/v1` call and attached to every event
  the call causes. An invalid `traceparent` is ignored, as the W3C spec
  says.
- Network and secret events are tagged with a step only when every exec and
  terminal running in that sandbox carries the same step. Otherwise
  `step_id` is `null`, so a connection is never pinned on the wrong step.
  Matching by process tree in the guest is a later change.

## Event types

| Group | Types |
| --- | --- |
| Lifecycle | `sandbox.created`, `.paused`, `.resumed`, `.killed`, `.expired`, `.lost` |
| Process | `exec.started`, `exec.finished`, `pty.opened`, `pty.closed` |
| Files | `file.written` (path, size, SHA-256), `file.deleted` |
| Network | `net.connection`, `net.blocked` |
| Secrets | `secret.injected` (name, version, host) |
| Ports | `port.published`, `port.unpublished` |
| Admin | `tenant.created`, `.updated`, `.deleted`, `key.created`, `.revoked`, `secret.created`, `.updated`, `.rotated`, `.deleted`, `template.saved`, `.deleted` |

- `exec.finished` has exit code, signal, timeout, duration, byte counts and
  the last `--events-output-bytes` (default 64 KiB, `0` turns it off) of
  stdout and stderr. A client that disconnects first gives
  `"cancelled": true`. Exec stdin is counted, never stored.
- Not yet: `snapshotted`, `forked`, `oom.kill`, `exec.signaled`,
  `files.uploaded`, `net.dns`, sampled `port.request`, and file changes
  made inside the sandbox. Those need features that do not exist yet.

## Storage and API

- An `events` table in the same SQLite database (migration 6). A writer task
  batches inserts so calls never wait on them. If its queue (10,000) is
  full, events are dropped and the drop count is logged.
- Retention: `--events-retention-s` (default 7 days, `0` keeps forever),
  pruned every minute in batches.
- `GET /v1/events?tenant=&sandbox=&step_id=&type=&since=&until=&limit=&cursor=`
  needs `audit:read`. Tenant keys see only their tenant. `type` is a comma
  list; `exec.*` matches a group. `since` and `until` are RFC 3339. Oldest
  first; `limit` 1 to 1000 (default 100). Returns `events`, `next_cursor`
  and `has_more`.
- `follow=true` turns it into server-sent events: stored events after
  `cursor` (or `since`, or `Last-Event-ID`) first, then live ones. Without
  any of those it starts at now. `GET /v1/sandboxes/{id}/events` is the
  same for one sandbox.

## OTLP

- `--otlp-endpoint` (or `OTEL_EXPORTER_OTLP_ENDPOINT`) turns on export of
  every stored event as an OTLP log record over HTTP/protobuf, with the
  official `opentelemetry` crates and the batch processor. Headers come from
  `OTEL_EXPORTER_OTLP_HEADERS`.
- The record's event name and body are the type; attributes are
  `spawnbox.*`; the trace context comes from `traceparent`; the resource has
  `service.name=spawnbox`.
- Traces with spans per create and exec step are a later merge.
