# M1 gaps: pause and resume, exec stdin, TLS

Status: done.

## Pause and resume

- `POST /v1/sandboxes/{id}:pause` and `:resume`. Both are idempotent and
  return the sandbox. A new state, `paused`.
- Pause: the VM is paused, a full snapshot (memory and VM state) is written,
  and Firecracker stops. The snapshot, the writable disk and hard links to
  the build's read-only disks move to `<data-dir>/paused/<id>`, so the
  sandbox no longer needs its build and uses no CPU, RAM or slot. Open
  exec streams and terminals end.
- Resume: a new jail and network (any free slot) load that snapshot, then
  the identity fix-ups run again (clock, entropy). Processes, files and
  published ports are as they were; preview URLs and tokens stay the same.
- Idle pause: `idle_pause_s` on create (default `--idle-pause-s`, 600; `0`
  turns it off). A sandbox with no exec, file call, terminal or preview
  request in flight for that long is paused.
- Any call that needs the VM (exec, files, terminal, git clone, a preview
  request that passed its access check) resumes a paused sandbox first.
  Ports can be published and listed while paused.
- `timeout_s` counts running time only: while paused, `expires_at` is
  `null` and `paused_at` is set; resume moves `expires_at` by the paused
  time.
- Paused sandboxes survive server restarts: what resume needs is stored in
  SQLite. They are deleted after `--paused-retention-s` (default 7 days).
  Snapshot files that no paused sandbox owns are removed at start.
- Calls that change the VM (pause, resume, delete) take a per-sandbox lock.
  A call that finds the sandbox mid-change waits for it.

## Exec stdin

- `"stdin": "text"` on exec (and SSE exec) is written to the command's
  standard input, which is then closed. Without it, stdin is `/dev/null`
  as before. Guest `ExecRequest.stdin`; protocol minor 4.

## TLS

- `--tls-cert` and `--tls-key` serve the API over HTTPS;
  `--preview-tls-cert` and `--preview-tls-key` serve previews over HTTPS
  (use a wildcard certificate for the preview domain). PEM files, as from
  certbot or lego.
- Certificate files are re-read when they change (checked every 10 s),
  so renewals need no restart.
- Handshakes run in their own tasks with a timeout, so a slow client cannot
  block others.

## Also

- README: the preview example used `python3`, which the base image does
  not have.

## Not in this step

Diff snapshots, pausing on server shutdown, pause on memory pressure,
resume on another node, ACME, streaming stdin.

## Done when

- Unit tests for the new request fields, state handling and certificate
  loading.
- `scripts/m1-smoke.sh` passes with new checks: explicit and idle pause,
  resume by exec, files, terminal and preview; a background process and
  files survive; the clock is right after resume; delete while paused; a
  paused sandbox survives a restart; stdin; HTTPS on both listeners and a
  certificate reload.
- `scripts/m0.sh` passes.
- README, CONTRIBUTING and the spec describe only what works.

## Results

All of the above passes on the EC2 test host, whose EBS disk writes about 145 MB/s with fsync.
Resume takes about 65 ms. Pause took 12 s at first: Firecracker fsyncs the
1 GiB memory file. It now skips that, flushes in the background, and
lifts the sandbox cgroup's `memory.max` while saving, so a pause on an
idle disk takes about 0.7 s. Back-to-back pauses still take up to about
12 s on this disk, because Firecracker's disk flush waits on earlier
memory files in the same ext4 journal. Diff snapshots are the next step
for that.
