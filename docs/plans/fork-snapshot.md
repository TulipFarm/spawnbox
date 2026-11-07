# Fork and snapshot

Status: done.

## Goal

`POST /v1/sandboxes/{id}:snapshot` saves a running sandbox as a template.
`POST /v1/sandboxes/{id}:fork` starts copies of a running sandbox on its
host. The source keeps running in both cases.

## Node

- `Node::save_running(vm, dir)` writes a running sandbox to `dir` in the
  layout of a build, then lets it run on, and returns a new guest channel.
  - Firecracker: pause the VM, `snapshot/create` to `/snap.state` and
    `/snap.mem`, move them out, link `rootfs.ext4` and `layer.ext4`, copy
    `upper.ext4` while the VM is paused, resume. If the resume fails, the
    error is `Frozen`.
  - gVisor: `runsc checkpoint --leave-running`, then link the disks.
  - Firecracker resets vsock on every `snapshot/create`, so the old guest
    channel is dead after the save. A new connection that fails counts as
    `Frozen`.
  - The memory file is dirty page cache charged to the VM's cgroup. Putting
    `memory.max` back while it is dirty got the running VM OOM-killed. The
    limit stays lifted until the files are fsynced (through handles opened
    before a fork removes the directory). A counter on the VM lets saves
    overlap.
- `new_identity` after every restore gives each copy its own entropy,
  hostname and clock.

## Snapshot

- Body: `{"name": "with-deps"}`. The template goes in the sandbox's tenant
  namespace. An existing template with that name is a conflict.
- The template spec gets `snapshot: {id, sandbox, build, layer}`. Users
  cannot set it. Its `env` is the sandbox's env without the CA variables
  and secret placeholders; `resources` are its vCPUs and memory. Secrets
  are not kept: processes that read a placeholder before the snapshot keep
  one that no longer works.
- A snapshot build is never built again:
  - A host without the files only fetches them from the build store. With
    no store, or when the fetch fails, the build fails with a reason.
  - When new runtime inputs make it outdated, it is not rebuilt.
- With a build store, the files are uploaded before the reply, so other
  hosts can fetch them. Placement already sends sandboxes only to hosts
  with a ready build.
- Fleet: the primary saves the template and bumps the config version after
  the worker's reply. A worker keeps new snapshot templates for 60 s even
  when the primary's list does not have them yet.
- Event: `sandbox.snapshotted` with `template`, `build`, `duration_ms`.

## Fork

- Body: `{"count": N}`, 1 to 16, default 1. Reply:
  `{"sandboxes": [...], "failed": F}`, one view per copy that started.
- The copies get the source's tenant, template, build, labels, env,
  secrets (the same placeholders), egress, rate limits, idle pause and
  remaining timeout. Each is admitted against quotas and takes a slot.
- The snapshot goes to a temporary build, every copy restores from it, and
  then it is removed; the VMs keep their own links and copies.
- Fleet: the primary reserves quota for the copies and records them as
  sandboxes of the worker.
- Event: `sandbox.forked` on the source with `sandboxes` and
  `duration_ms`; each copy records `sandbox.created` with `forked_from`.

## Limits

- Sandboxes with volumes cannot be forked or saved.
- Copies start on the source's host.

## CLI

`spawnbox snapshot <id> --name <name>` and `spawnbox fork <id> [--count N]`.

## Results

Measured on the two EC2 test hosts (Firecracker, 2 vCPU, 1 GiB sandboxes):

| Case | Time |
| --- | --- |
| Fork, 5 copies, primary | 587 ms |
| Fork, 10 copies, primary | 701 ms |
| Fork, 5 and 10 copies, worker through the primary | 615 ms, 594 ms |
| Snapshot to a template | 399 to 438 ms |

- Copies kept a file and a background process from the source, had their
  own hostname, and read different `/dev/urandom` bytes.
- The source ran on after each fork and snapshot.
- A sandbox from the snapshot template kept the file, the process and the
  env. On the worker, the primary sent it to the worker.
- `memory.max` was `max` during the save and back to 1.25 GiB 20 s later.
- Refused: count 0 and 17 (400), a reserved name (400), a duplicate name
  (409), a paused sandbox (409), a sandbox with volumes (400).
- Not tested live: gVisor `--leave-running`, and fetching a snapshot build
  from a build store on another host.
