# Drain and migration

Status: done.

## Goal

Take a host out of service without losing sandboxes. An operator marks a
node `draining`, so it gets no new sandboxes, and can move its sandboxes
to other hosts now. A moved sandbox keeps its ID, preview URLs and
secrets. Clients see a pause of a few seconds. Live migration (no pause)
is out of scope.

## Decisions

- Migration is pause, copy, resume. The source pauses the VM to its
  paused directory, streams the files to the target through the primary,
  and the target resumes it.
- A snapshot resumes only where the kernel, base disk, Firecracker and CPU
  match. The template fingerprint already hashes the kernel, base disk,
  Firecracker and egress CA. Heartbeats now carry the fingerprint and the
  CPU model, and a migration target must match both.
- One egress CA for the fleet. Today each host makes its own, so
  fingerprints never match and a moved guest would not trust the new
  host's proxy. A worker now takes the primary's egress CA when it starts
  (at join, and on each later start if the primary answers). A worker
  whose CA changes rebuilds its templates once.
- The base disk is not sent: equal fingerprints mean equal base disks, so
  the target links its own. The memory, state, writable disk and the
  template layer (if any) are sent, sparse and zstd-compressed.
- The primary drives every migration, also when it is the source or the
  target. Workers never call each other.
- Only the primary can be the API for this. The primary itself cannot be
  drained; its sandboxes can be migrated one by one.

## Design

### Node state

- `nodes.draining` (new column, default 0). `node_seen` does not touch it,
  so it lasts through suspect and down.
- Placement and migration targets skip draining nodes.
- `POST /v1/nodes/{id}:drain` with `{"migrate": true|false}` (default
  false). Sets draining and records `node.draining`. With `migrate`, a
  background task moves the node's sandboxes one at a time, running ones
  first, and records `node.drained` with counts when done. Returns 202 and
  the node.
- `POST /v1/nodes/{id}:undrain` clears it.
- Node views show `draining`.

### Migrate one sandbox

`POST /v1/sandboxes/{id}:migrate` with optional `{"node": "nod_..."}`.
Needs `tenants:admin`. Never forwarded. Only on a primary.

1. The sandbox must be running or paused. The primary marks it moving:
   other calls for it wait (up to 2 minutes), then see where it went.
2. Pick the target: a ready, not draining host (the primary or a worker)
   other than the source, with the source's fingerprint and CPU, room for
   one more VM if it runs, and memory for it. Most free memory first.
3. Get a worker target ready: config sync if stale, then push the
   sandbox's secrets.
4. Export on the source (`POST /fleet/v1/migrate/export`): pause it if it
   runs (event `sandbox.paused`, reason `migrate`; no snapshot quota
   check), mark the record moving (resumes, idle pause and expiry skip
   it), and stream a package: header JSON (sandbox row, saved state,
   whether it ran, fingerprint, CPU), then each file.
5. Import on the target (`POST /fleet/v1/migrate/import`, body is the
   source's stream): unpack into a staging dir, check fingerprint and CPU,
   link the base disk, move the dir into place, store the row as this
   host's paused sandbox, and resume it if it ran (event
   `sandbox.resumed`, reason `migrate`).
6. Success: the primary points its row at the target, tells the source to
   release its copy (no events), and records `sandbox.migrated` with
   `from`, `to` and `duration_ms`.
7. Failure before the target has it: the source is told to abort; it
   clears moving and resumes the sandbox if it ran. If the target's resume
   fails, the target drops its copy quietly and the source resumes.

### Safety net

- Heartbeat replies carry `release`: sandboxes the worker reports that the
  primary knows on another host and that are not moving now. The worker
  drops them quietly. This covers a lost release call and a primary that
  stopped halfway.
- A moving mark on the source ends after 15 minutes, so a sandbox is never
  stuck if the primary goes away.
- Staging dirs left by a crash are removed at start (the paused dir
  cleanup already does this).

### Wire format

zstd stream: `u32` header length, header JSON, then per file a `u16` name
length, the name, and the sparse blob from the build store
(`SBXBLOB1`, `(offset, len, bytes)` records, `(size, 0)` end), then a
SHA-256 of all bytes before it. The target rejects unknown file names.

## Tests

- DB: `draining` survives heartbeats; `take_over` and `hand_off`; the
  release list.
- Package round trip: sparse files and a bad checksum.
- Two hosts: migrate running and paused sandboxes both ways (worker to
  primary, primary to worker), files and processes survive, preview URL
  works after, secrets still injected; drain with `migrate`; placement
  skips a draining node; abort when the target cannot resume.

## Out of scope

- Live migration.
- Draining the primary.
- Autoscaling triggers.
- Migration between hosts with different CPUs or base images.
