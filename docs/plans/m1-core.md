# M1 step 1: core sandbox API

## Goal

A user on a single Linux KVM host can create a sandbox, run commands in it
and delete it over HTTP, with an API key. This is the first slice of M1.

## Scope

- New library crate `spawn-node`: the Firecracker, jailer, network and guest
  code from `spawn-bench`, plus template build and restore. `spawn-bench`
  uses it. The spec's `spawn-node` daemon and its gRPC API come later; for
  now `spawn-api` uses the library in the same process.
- New binary crate `spawn-api`:
  - `spawn-api serve`: builds the `base` template at start, then serves HTTP.
    Listens on `127.0.0.1:8080` by default. There is no TLS yet.
  - `spawn-api create-key`: creates an API key and prints it once. Only the
    SHA-256 hash is stored.
- State in SQLite (`<data-dir>/spawnbox.db`). The spec's Postgres comes with
  multi-node work; SQLite keeps single-node installs to one file.
- Endpoints:
  - `GET /healthz` (no auth)
  - `POST /v1/sandboxes`: `template` (only `base`), `timeout_s`, `env`,
    `labels`. Unknown fields are rejected, so unsupported spec fields fail
    loudly instead of being ignored. Returns `201` with `timings_ms`.
  - `GET /v1/sandboxes` (with `state`, `limit`, `cursor`) and
    `GET /v1/sandboxes/{id}`
  - `DELETE /v1/sandboxes/{id}`
  - `POST /v1/sandboxes/{id}/exec`: `cmd`, `cwd`, `env`, `user`,
    `timeout_s`. Plain JSON with output capped at 1 MiB per stream, or SSE
    when `Accept: text/event-stream`.
- Errors use the spec's `{ "error": { code, message, retryable, request_id } }`.
- Sandboxes are deleted when `timeout_s` passes.
- On start, rows left `starting` or `running` by a stopped server become
  `deleted`, and leftover jails and namespaces are removed.
- On SIGINT or SIGTERM, all VMs stop and host firewall rules are removed.

## Not in this step

Templates other than `base`, template builds, files, PTY, git clone,
secrets, egress policies, ports, pause and resume, idempotency keys, step
headers, OpenAPI, the TypeScript SDK, CLI commands, MCP and the installer.

## Done when

- Unit tests pass for the pure parts (IDs, keys, UTF-8 streaming, request
  checks).
- `scripts/m1-smoke.sh` passes on the KVM host: auth is required, create
  returns `201`, JSON and SSE exec work, env and labels apply, two sandboxes
  are isolated, expiry deletes a sandbox, delete works, and after shutdown
  no VM processes, namespaces, cgroups or firewall tables are left.
- `scripts/m0.sh` still passes.
- README, CONTRIBUTING and the spec describe only what works.
