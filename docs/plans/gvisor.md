# gVisor fallback

Status: done.

## Goal

Run Spawnbox on hosts without `/dev/kvm`, such as most cloud VMs without
nested virtualization. Sandboxes run in gVisor (`runsc`) instead of
Firecracker. The API, templates, pause and resume, warm pools, previews,
secrets, egress policy, the build store and migration work the same.
Firecracker stays the default. gVisor is a weaker boundary, so a tenant can
refuse it.

## Decisions

- One backend per host: `--backend auto|firecracker|gvisor`. `auto` uses
  Firecracker when `/dev/kvm` opens read-write, otherwise gVisor. The node
  reports its backend; `GET /v1/nodes` shows it.
- The backend lives in `spawn-node`. `spawn-api` sees one `Vm` type with
  the same calls for both backends.
- Same base disk and template layer format. The base `rootfs.ext4` and the
  layer `layer.ext4` are loop-mounted read-only on the host for each
  sandbox and joined with overlayfs. That overlay is the container root.
  The build store and migration copy the same files as before.
- The writable layer is gVisor's own overlay (`--overlay2=root:dir=...`,
  `size=<disk_gib>g`): it lives in a hidden file and is part of every
  checkpoint. This is also the disk size limit.
- Template setup steps run with `--overlay2=none` on a host overlay whose
  upper directory is in a new `layer.ext4`. After the steps, the container
  stops and the disk is unmounted: that file is the layer, with the same
  `root/` layout the Firecracker guest uses.
- Snapshot, pause and resume use `runsc checkpoint` and `runsc restore`.
  A build's snapshot is `checkpoint.img`, `pages.img`, `pages_meta.img`.
  A paused sandbox has the same three files plus links to its disks.
  Restore from one image can run many times at once.
- Warm pools use `runsc pause` and `runsc resume`.
- Network: the same per-sandbox namespace, host link and firewall rules.
  runsc takes over every interface of the namespace it joins and removes
  their addresses, so the guest gets a second, inner namespace. A veth
  pair joins them: `gv0` (gateway, 172.16.0.1) in the outer namespace and
  `eth0` (guest, 172.16.0.2) in the inner one, with the same fixed MACs.
  The rules name the guest interface (`tap0` or `gv0`).
- Agent channel: under gVisor there is no vsock. `spawn-guest` listens on
  TCP port 1024 and accepts only connections from the gateway address. A
  process in the sandbox cannot use that source address (tested, also as
  an unprivileged user with `IP_FREEBIND`). The host connects from inside
  the outer namespace. The outer namespace's input chain lets replies to
  its own connections in.
- `spawn-guest` learns the backend from `SPAWN_BACKEND=gvisor` in the OCI
  process environment. As PID 1 it then skips the disk and mount steps:
  runsc and the OCI mounts do them. Setting the clock and adding entropy
  are skipped: gVisor uses the host clock and the host's random source,
  so clones differ already.
- Limits: OCI `resources` set CPU and memory in the cgroup
  `/spawnbox/<id>`, so the existing cleanup also kills gVisor sandboxes.
  The memory limit is exactly the sandbox's memory, with no overhead:
  gVisor shows the cgroup limit to the guest as its RAM and has no limit
  of its own.
- Disk metering: the sandbox process holds the writable layer open as a
  deleted file in the bundle's `fs/`. At start the host finds it in
  `/proc/<pid>/fd` and measures its blocks there.
- `--backend firecracker` on a host where `/dev/kvm` does not open stops
  at start with an error.
- The template fingerprint adds the backend name and hashes the `runsc`
  binary instead of Firecracker. Builds and migration therefore never mix
  backends.
- Migration sends the backend's snapshot files. Equal fingerprints mean
  equal backends, so both sides agree on the file list.
- Tenants get `isolation`: `any` (default) or `microvm-only`. A
  `microvm-only` tenant's sandboxes go only to Firecracker hosts. On a
  single gVisor host, creating them fails with `no_capacity`.
- `deploy/install.sh` installs a pinned runsc release, checked with its
  SHA-512, and no longer requires `/dev/kvm`.

## Known limits

- gVisor does not implement every Linux system call. Most developer tools
  work; some low-level tools (for example, nested containers or kernel
  modules) do not.
- runsc uses the `systrap` platform: no KVM needed, slower system calls.

## Tested before the plan (runsc release-20261102.0)

- Restore of one checkpoint into two namespaces at once, with the same
  guest IP: files, processes and HTTP kept.
- Restore onto a copy of the disks (as on another host).
- Memory and CPU limits from OCI resources; disk limit from `size=`.
- Checkpoint with a 300 MB file: 2.5 s, 310 MB image. Restore: 31 ms.
- Checkpoint with an open TCP connection; deleting the image after restore.

## Steps

1. `spawn-guest`: gVisor mode (init, TCP listener with peer check,
   identity).
2. `spawn-node`: `Backend`, build file sets, `gvisor` module (bundle,
   mounts, run, checkpoint, restore, pause), inner namespace, TCP dialer,
   one `Vm` type.
3. `spawn-api`: `--backend`, `--runsc`, fingerprint, migration file list,
   node backend, tenant isolation.
4. Install script, README, ARCHITECTURE, spec.
5. Test on the EC2 hosts with `--backend gvisor`: smoke tests, templates
   with setup, pause and resume, warm pools, previews, secrets, egress
   policy, migration between two gVisor hosts.

## Results (EC2, runsc release-20261102.0, systrap)

- `scripts/m1-smoke.sh` passes with `SPAWNBOX_BACKEND=gvisor`: API,
  templates with setup and warmup, terminals, previews, pause and resume,
  egress policies and secrets, tenants, events, usage, restart with
  paused sandboxes, crash recovery and TLS.
- Template builds in the service: `base` 4.4 s; a template with
  `apt-get install` steps and egress 24.4 s.
- Pause 23 to 56 ms (one 251 ms while earlier pauses flushed). Resume
  73 to 157 ms.
- Mixed fleet (Firecracker primary, gVisor worker): `microvm-only`
  tenants stayed on the primary; other sandboxes went to both hosts; a
  move from gVisor to Firecracker was refused.
- Two gVisor hosts: a running move in 0.2 s and a paused move in 17 ms,
  with files, a background process and egress kept.
- Firecracker regression: `scripts/m1-smoke.sh` and `scripts/cli-smoke.sh`
  pass.
