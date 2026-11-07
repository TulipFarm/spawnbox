# spawn-edge

Status: done

## Goal

A front door for a fleet. Clients call the edge. Calls that move data
(exec, PTY, files, git clone and previews) go straight to the host that
runs the sandbox. All other calls go to the primary. When the primary is
down, data calls to running sandboxes still work.

## Decisions

- Same binary, new subcommand: `spawn-api edge`. It runs no VMs and needs
  no root, KVM or rootfs.
- The edge joins the fleet with a join token, like a worker. It is a row in
  `nodes` with `kind = 'edge'`. `GET /v1/nodes` shows it and
  `DELETE /v1/nodes/{id}` removes it. Edges never send heartbeats, so they
  never get sandboxes, moves or volumes. Drain is refused for edges.
- Public TLS comes from certificate and key files, re-read when they change
  (`tls::Bound`), on `--listen` and `--preview-listen`.
- Routing table: every second the edge calls `POST /fleet/v1/routes` on the
  primary. The reply has every live worker (ID and URL) and every sandbox
  that a worker runs and that is not moving. The poll also counts as the
  edge's liveness, so `check_nodes` marks a silent edge down.
- Direct paths: `/v1/sandboxes/{id}/exec|pty|files|git:clone`, and preview
  hosts. The edge sends them to the worker over fleet mTLS, checking the
  worker's node ID. Everything else, and every sandbox not in the table,
  goes to the primary's fleet listener.

## Changes

- `db.rs`: migration `ALTER TABLE nodes ADD COLUMN kind`, `NodeRow.kind`,
  `edge_seen`, `edge_routes`.
- `fleet/mod.rs`: `JoinRequest.kind`, `Config.edges`, `Routes`, node kinds.
- `fleet/pki.rs`: a server config that needs any fleet certificate.
- `fleet/primary.rs`: join edges (no URL check), `worker()` accepts only
  workers, `/fleet/v1/routes`, a fallback on the fleet listener that serves
  the API and preview routers to edges, `bump()` on edge join and removal,
  `kind` in node views, no drain for edges.
- `fleet/worker.rs`: the node listener needs a fleet certificate. Fleet
  routes take only the primary. The API and preview fallback also take
  edges listed in the config.
- `fleet/edge.rs`: new. Join, poll, forward.
- `main.rs`: the `edge` subcommand.
- `server.rs`: Peer connect info on the worker listener.

## Security

- Only the primary may call a worker's `/fleet/v1/*` routes.
- An edge must show a fleet certificate for its node ID, name that ID in
  `x-spawnbox-node`, and be a non-removed edge (primary: database; worker:
  config copy).
- The edge removes `x-spawnbox-route` and `x-spawnbox-node` from client
  requests before it sets its own.
- The edge does not check API keys. The host that serves the call does.
- A removed edge gets 403 from the primary's routes call. It then stops
  serving and answers 503. Workers stop taking it at their next config copy
  (one heartbeat, 5 s).

## Limits

- The full table is sent every second. Fine for thousands of sandboxes.
- A call in the first second of a move can reach the old host and fail.
  Retry it.
- When the primary is down, creates, deletes and other control calls fail.

## Test plan

- Unit: direct path matching, routes query, kind filtering, worker peer
  checks.
- Live: edge on the primary host (other ports). Exec, PTY, files and
  previews on a worker sandbox reach the worker directly (worker logs and
  primary request metrics). Control calls work. Stop the primary: exec on a
  worker sandbox still works. Remove the edge: it answers 403 and the worker
  refuses it.

## Results

Tested on two EC2 hosts, with the edge on the primary host as a non-root
user:

- Create through the edge put the sandbox on the worker. Exec, files, PTY
  (101) and a preview (200) went straight to the worker.
- A sandbox on the primary: exec, files, PTY, pause and resume through the
  primary's fleet fallback.
- Primary stopped: exec, files, PTY and preview still worked; control calls
  gave 503. Routes came back after the primary started.
- The edge cert gets 403 on `/fleet/v1/sync`, heartbeat and config. The
  worker refuses an edge with no or a wrong `x-spawnbox-node`, and a client
  with no cert. A spoofed `x-spawnbox-route` from a client is stripped.
- Drain of an edge gives 400. Remove gives 204; the edge answers 403
  `forbidden` within 2 s and the worker refuses its cert within 5 s.
