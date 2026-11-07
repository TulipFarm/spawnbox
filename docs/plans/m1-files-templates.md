# M1 step 2: files and custom templates

Status: done.

## Goal

A user can define a template as setup commands on top of the Debian base,
build it in the background, start sandboxes from it as fast as from `base`,
and read, write, list and delete files in a running sandbox.

## Templates

- Spec: `name`, `setup` (run as root, with network), `warmup` (run as
  `user` right before the snapshot), `env`, and
  `resources: {vcpus, memory_mib, disk_gib}`. Unknown fields are rejected,
  so `base:` with an OCI image fails until OCI images are supported.
- Endpoints:
  - `POST /v1/templates`: create or replace a template and queue a build.
    Returns `202` with the template and the build.
  - `GET /v1/templates`, `GET /v1/templates/{name}`,
    `DELETE /v1/templates/{name}`
  - `GET /v1/templates/{name}/builds/{build_id}`: state, error, timings
    and the last 64 KiB of the build log.
- `base` is built in. It is rebuilt only when the kernel, base disk,
  Firecracker binary or default resources change.
- Builds run in the background, at most `--max-builds` at once. Each one
  uses a VM slot from the same pool as sandboxes.
- A build boots twice:
  1. Base disk plus an empty writable disk. Run `setup`. The guest flushes
     and freezes the writable disk, then the VM is killed. That disk becomes
     the template's read-only layer.
  2. Base disk, layer, and a new empty writable disk. Run `warmup`, then
     pause and snapshot.
  Each sandbox copies only the small writable disk from step 2 and links
  the rest, so creating from a custom template costs the same as `base`.
  Templates without `setup` skip step 1.
- Builds are kept in `<data-dir>/builds/<build_id>` and recorded in SQLite
  with a fingerprint of the kernel, base disk and Firecracker binary, taken
  when the build starts. On
  start, builds with another fingerprint are marked `outdated` and rebuilt;
  builds that were running are queued again.
- The newest ready build of a template is the one new sandboxes use. A
  replaced build's files are removed once no create is still using them.

## Files

- `GET /v1/sandboxes/{id}/files?path=`: a file's bytes, or a JSON listing
  for a directory.
- `PUT /v1/sandboxes/{id}/files?path=`: write the request body to a file,
  creating parent directories. The file is replaced only once the whole
  body arrived.
- `DELETE /v1/sandboxes/{id}/files?path=[&recursive=true]`
- Relative paths are under `/workspace`. Operations run as `user` unless
  `user=` is given. Files are streamed in 1 MiB chunks; there is no size
  limit beyond the sandbox's disk.

## Not in this step

OCI images and devcontainers as a base, build caching by step, snapshots
of running sandboxes, fork, tar upload, mkdir, move, stat and watch.

## Done when

- Unit tests cover template spec checks and path checks.
- `scripts/m1-smoke.sh` passes on the KVM host, including a custom template
  build with setup and warmup, sandboxes from it, a failing build, file
  round trips (binary, large, nested, listing, delete, permissions), and a
  restart that keeps builds without rebuilding them.
- `scripts/m0.sh` still passes.
- README, CONTRIBUTING and the spec describe only what works.
