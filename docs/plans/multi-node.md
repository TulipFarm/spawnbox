# Multi-node

Status: built; tested on two hosts.

## Goal

Run sandboxes on more than one host behind one API. A client keeps using
one URL and one API key; Spawnbox places each sandbox on a node and sends
every later call for it to that node.

## Decisions

- One binary, two roles. The **primary** is today's server plus a fleet
  role: it owns tenants, keys, secrets and templates, schedules sandboxes,
  and forwards calls. It also runs sandboxes itself. A **worker** is the
  same server started with `--primary`; it gets its config from the
  primary and runs sandboxes.
- The primary forwards the client's HTTP request as it is (body streamed,
  WebSocket upgrades kept) to the worker's internal listener, over HTTPS
  with mutual TLS. Workers check the forwarded API key against the copy of
  the keys they get from the primary, so no handler changes for auth.
  This replaces the spec's gRPC `Node` and `NodeData` services for now.
- SQLite on the primary. One primary only; Postgres and more than one
  control plane instance come later. `spawn-edge` comes later too; for now
  the primary carries data streams and preview traffic.

## Design

### Identity

- The primary keeps a fleet CA (`<data-dir>/fleet/ca.{crt,key}`, the key
  encrypted with the secrets key) and its own certificate from it.
- `POST /v1/nodes/tokens` (org admin) makes a join token, valid one hour,
  stored hashed, used once (`ttl_s` from 60 s to 7 days). The response
  holds `token`, `expires_at` and `ca_sha256`, the values for
  `--join-token` and `--primary-ca-sha256`.
- A worker with no certificate joins: it makes a key and a CSR, sends them
  with the token and its `--advertise` URL to `POST /fleet/v1/join`, and
  checks the primary's CA by its SHA-256. The primary uses the token and
  makes the node row in one transaction, signs the key for a new node ID
  (`nod_...`; names in the CSR are ignored), and sends the certificate and
  the CA. They are kept in `<data-dir>/fleet/`; later starts skip the join.
- The advertise URL must be `https://host:port` with no path or user part.
  The primary checks that the worker's server certificate names that node.
- Workers accept internal calls only from the `primary` certificate. The
  primary accepts fleet calls only from node certificates of nodes that
  are not removed, checked on every call. No connection is pooled, so a
  removed node is cut off at once.

### Listeners

- Primary: `--fleet-listen` turns the fleet role on. It serves
  `/fleet/v1/*` to workers: join, heartbeat, config, events, usage.
- Worker: `--node-listen` (internal, mTLS) is its only listener; clients
  call the primary. The primary forwards API calls
  as they are, and preview requests with the header
  `x-spawnbox-route: preview` (a client copy of it is removed first; only
  the primary reaches this listener). Hop-by-hop headers are dropped,
  except `upgrade`/`connection` for WebSockets. Workers use the same
  `--preview-url` as the primary.
- The heartbeat carries the advertise URL, so a worker that gets a new
  IP address keeps working after a restart with a new `--advertise`.

### Heartbeat

- Every 5 s a worker sends: its boot ID (new each start) and a sequence
  number, free sandbox slots and memory, ready templates with a hash of
  the spec each was built from, warm VM counts per template and network
  mode, its config version, and all its sandbox records that are not
  deleted, with their resources.
- The primary ignores a heartbeat older than the last one of the same boot.
- The report is the full inventory. A mirror row of that node that is not
  in it and is older than 30 s is marked deleted (`sandbox.lost` with
  reason `gone from node`). A new boot ID means the worker restarted: all
  its earlier sandboxes are gone.
- No heartbeat for 15 s: node `suspect`, no new placements. 30 s: `down`
  (`node.down` event); calls for its sandboxes return `503`. Their rows
  stay, as the node can come back; only the inventory rule above or
  removing the node ends them.

### Config sync

- The primary bumps a config version on every change to tenants, keys,
  secrets and templates (and at start).
- A worker whose version differs calls `POST /fleet/v1/config` with the
  secrets it holds, and gets tenants,
  key hashes, template specs, and the secrets that sandboxes on that node
  use (values over mTLS only; the worker encrypts them with its own key).
  Other secrets are not sent. The worker applies the full set in one
  transaction, then reloads its in-memory secrets and templates.
- Before it forwards a create, the primary tells a worker with an old
  config version to sync, and pushes the secrets the create attaches.
- On a worker, the public API rejects changes to tenants, keys, secrets
  and templates with `409`, as the primary owns them.

### Mirror rows

- The primary's `sandboxes` table gets `node`, `vcpus` and `memory_mib`
  columns. `node IS NULL` is a local sandbox. Rows of remote sandboxes are
  a mirror, written from the create response and from heartbeats.
- Database calls are split: local calls (start-up cleanup, paused load,
  state changes, expiry, idle pause, metering) all require
  `node IS NULL`; mirror calls require the expected node.

### Routes

- One function classifies a request path: sandbox ID or none. It is used
  by auth and by forwarding. A `%` in a sandbox ID segment is rejected for
  every caller. The result (tenant, node) is put on the request.

### Scheduling and admission

1. Admission: under one fleet lock, the primary adds the tenant's local
   usage, mirror rows and creates in flight, checks the quota, and
   reserves the create. The reservation ends when the create ends.
2. Filter: the primary itself and `ready` workers whose ready template
   spec hash matches, with a free slot or a warm VM of that template and
   network mode, and enough free memory.
3. Score: warm VM (+100), most free memory (+0 to 30), fewer sandboxes of
   this tenant on the node (+0 to 10). Creates in flight per node count
   against its free slots and warm VMs.
4. Place: the worker picks the sandbox ID, as warm VMs have theirs
   already. A refused connection or a `503` tries the next node (three
   tries, then `503 no_capacity`). Any other failure after the request was
   sent returns `502`; if the worker made the sandbox, its next heartbeat
   adds the mirror row.

The worker checks quotas again with its own rows, which is never stricter.

### Forwarding

- After auth, a call for a sandbox on a worker is forwarded to that worker
  as a raw HTTP request; a PTY upgrade is joined both ways.
- The preview proxy looks up the sandbox; a remote one is forwarded.
- `GET /v1/sandboxes/{id}/events` is not forwarded: the primary has
  every node's events, with its own cursors.

### Events and usage

- Workers send events in batches with their own event IDs; the primary
  stores `source_node` and `source_id` (unique), so a resent batch adds
  nothing, and answers with the last ID it has. Primary event IDs stay
  the cursors of `/v1/events`.
- Workers send their hourly usage rows of the last two hours every 60 s,
  as totals. The primary keeps them in `node_usage` (node, tenant, hour,
  sandbox) and keeps the larger value of each field, so a late batch
  cannot lower a total. Usage calls add `node_usage` to local rows.
- Monthly egress and snapshot quotas stay per node: soft limits that a
  tenant can pass by what other nodes used before their next report.

### Templates

- The primary's template builds stay the ones `/v1/templates` shows.
  Build IDs in a worker's sandbox views are that worker's.

### API

- `GET /v1/nodes`, `GET /v1/nodes/{id}`, `DELETE /v1/nodes/{id}` (its
  sandboxes become lost), `POST /v1/nodes/tokens`. Scope `tenants:admin`.
- `SandboxView` gets `node` (`null` for the primary and single hosts).

## Steps

1. Identity, join, listeners, heartbeat, nodes table and API.
2. Config sync and the worker's read-only config.
3. Mirror rows, scheduler and forwarding of sandbox calls.
4. Preview forwarding.
5. Events and usage from workers.
6. Health states and lost sandboxes.
7. Test on two KVM hosts; README, ARCHITECTURE and spec.

## Not in this step

- `spawn-edge` as its own process, Postgres, more than one primary.
- Drain and migration, prefetch on join, autoscaling hooks.
- A control plane that runs no sandboxes.
