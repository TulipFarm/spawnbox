# M2 part 3: usage metering, `GET /v1/usage` and usage quotas

Status: done.

The last of three M2 merges.

## What is metered

| Field | Unit | Counted |
|---|---|---|
| `vcpu_s` | vCPU-seconds | Reserved vCPUs while the sandbox runs (also while it pauses or resumes). Paused: 0. |
| `mem_gib_s` | GiB-seconds | Reserved memory while it runs. Paused: 0. |
| `disk_gib_h` | GiB-hours | Bytes stored on the host for the sandbox: its own disk layer while it runs, its disk and memory snapshot while it is paused. The shared template disk is not counted. |
| `egress_bytes` | bytes | TCP bytes both ways through the egress proxy, counted in the hour a connection closes. |

- Time is counted from each sandbox's last settle to now, at every change of
  state (create, pause, resume, delete, expiry, loss, shutdown) and every
  10 seconds. Intervals are split at hour boundaries.
- Disk is measured from allocated blocks (`du`-like), every 10 seconds and
  after each pause and resume.
- Only time the server runs is metered. A paused sandbox's storage while the
  server is down is not.
- Template builds are not metered.
- Not counted: UDP and ICMP in allow-all mode (they skip the proxy), and DNS.

## Storage

- `usage_hourly (tenant, sandbox, hour, vcpu_s, mem_gib_s, disk_gib_h,
  egress_bytes)`, one row per tenant, sandbox and hour; `hour` is Unix ms at
  the start of the UTC hour. Rows are added to in place and kept forever.
- Totals build up in memory and are written every 10 seconds, at shutdown,
  and before `GET /v1/usage` answers.

## `GET /v1/usage`

- Needs the new `usage:read` scope. Keys without a scope list have it.
- `tenant`: org keys may name any tenant, also a deleted one, or leave it out
  for all tenants. Tenant keys see only their own; naming another is `404`.
- `from`, `to`: RFC 3339. Default: start of the current UTC month to now.
  `from` rounds down and `to` up to the hour. At most 93 days.
- `group_by=sandbox` adds a row per sandbox; otherwise rows are per tenant
  and hour.

```json
{
  "from": "2026-11-01T00:00:00Z",
  "to": "2026-11-04T13:00:00Z",
  "usage": [
    { "hour": "2026-11-04T10:00:00Z", "tenant": "acme", "sandbox": "sbx_...",
      "vcpu_s": 7200.0, "mem_gib_s": 3600.0, "disk_gib_h": 0.12,
      "egress_bytes": 48211 }
  ],
  "total": { "vcpu_s": 7200.0, "mem_gib_s": 3600.0, "disk_gib_h": 0.12,
             "egress_bytes": 48211 }
}
```

## Quotas

Both default to no limit.

- `monthly_egress_bytes`: egress bytes this UTC month.
  - Create and resume fail with `429 quota_exceeded` once it is reached.
  - Checked every 10 seconds; once reached, the proxy refuses the tenant's
    new TCP connections (`net.blocked`, reason `egress quota`). Open
    connections are not cut, so usage can pass the limit.
- `snapshot_storage_gib`: bytes of the tenant's paused sandboxes.
  - A pause fails with `429 quota_exceeded` if the paused sandboxes' stored
    bytes plus this one's memory size and disk would pass it.
  - An idle pause over quota is skipped; the sandbox keeps running and is
    tried again after another idle period.
- `GET /v1/tenants/{id}` adds `monthly_egress_bytes` and
  `snapshot_storage_bytes` to `usage`.

## Files

- `metering.rs` (new): `Meter` with in-memory totals, hour splitting,
  flush, and the usage query shape.
- `db.rs`: migration 7, `add_usage`, `list_usage`, `egress_since`.
- `runtime.rs`: settle on every state change, the 10-second tick, disk
  measurement, both quota checks.
- `server.rs`: tick in the reaper, egress bytes from the proxy sink, flush
  at shutdown, `GET /v1/usage`, tenant usage fields.
- `tenancy.rs`: new quotas and scope.
- `spawn-egress`: refuse new connections of blocked tenants.

## Tests

- Unit: hour splitting, totals merge, flush upsert and query grouping,
  quota input, scope routing, blocked tenant check.
- Smoke on the KVM host (`m1_smoke.py usage`): vCPU and memory seconds
  match the reserved size and time, disk and egress are positive, a paused
  sandbox adds only disk, `group_by`, tenant isolation, both quotas.
