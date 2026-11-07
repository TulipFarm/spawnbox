# Spawnbox — Technical Spec

Nov 4, 2026 · @Dhruv Jain

## Overview

Spawnbox is an open-source, self-hosted sandbox fleet for agent platforms. Each sandbox is a Firecracker microVM (gVisor where KVM is missing) that an agent uses as a full Linux machine with root.

**Who it is for.** Teams building agent harnesses and platforms that serve their own customers. They need an isolated, audited, metered sandbox per customer, on machines they control.

**Positioning.** "The self-hosted sandbox fleet for agent platforms." Spawnbox does not compete on hosted price or fastest boot. It competes on multi-tenancy, observability of agent actions, and painless self-hosting.

**Current scope.** Build and launch the open-source, self-hosted project. Users run the full stack on their own infrastructure. A company may follow if the project earns sustained real-world use, but managed hosting and commercial products are not part of this plan.

### Goals

- Run any command or CLI as root inside a hardware-isolated VM.
- Sandbox ready in under 100 ms p50 (warm pool) and under 300 ms p95 (cached template).
- Secrets never enter the VM.
- Multi-tenant by design: tenants, quotas, per-tenant secrets and egress rules.
- Every agent action is logged and linked to the agent step that caused it.
- One install on any Linux host, bare metal or a nested-virtualization VM.
- An E2B-compatible API, so existing users switch by changing a base URL.

### Non-goals for v1

- GPUs.
- Windows or macOS guests, and macOS hosts.
- Laptop-first local use.
- A CI product. A GitHub Actions runner template may ship later as an extra.
- Spawnbox-operated hosting, a hosted control plane for customer-owned nodes, paid tiers, billing integrations, or enterprise service commitments.

### Principles

- Components talk over the network even on one box, so one node becomes many without a rewrite.
- Every step of the hot path is timed from day one.
- Fail closed. Unknown tenant, secret host or egress target means deny.
- Boring dependencies: Postgres, S3-compatible storage, OpenTelemetry.

## Glossary

These words mean one thing each, everywhere in code, API and docs.

| Term | Meaning |
| --- | --- |
| Node | A Linux host that runs sandboxes. Bare metal or a VM with nested virtualization. |
| `spawn-node` | The node agent. Runs on every node. Starts, pauses and kills VMs. |
| `spawn-api` | The control plane. Public API, scheduler, state in Postgres. |
| `spawn-edge` | The edge proxy. Routes preview URLs and streams to the right node. |
| `spawn-egress` | The per-node egress proxy. Enforces network policy and injects secrets. |
| `spawn-guest` | The agent inside each VM. Runs as PID 1. Talks to the host over vsock. |
| Backend | The isolation tech for a sandbox: `firecracker` or `gvisor`. |
| Sandbox | One running or paused VM made from a template. |
| Template | A named recipe: base image, setup steps, warm-up commands. |
| Build | One immutable result of building a template: disk, memory snapshot, VM state. |
| Snapshot | A saved sandbox state that new sandboxes can start from. |
| Fork | N new sandboxes made from one running sandbox's exact state. |
| Warm pool | VMs already restored and paused on a node, waiting to be claimed. |
| Org | An organization using Spawnbox, for example a harness company. |
| Tenant | One of the org's own customers. Owns sandboxes, secrets, quotas. |
| Secret | A credential stored on the host. Injected at the network edge, never into the VM. |
| Egress policy | Rules for which hosts a sandbox may reach. |
| Step ID | The harness's ID for one agent step. Attached to every event it causes. |

## System architecture

Spawnbox has five server components. One control plane (`spawn-api`) and one edge (`spawn-edge`) serve many nodes. Each node runs `spawn-node`, `spawn-egress` and its sandboxes.

&#91;embedded content: system architecture · control plane, node, sandboxes\]

Control calls go through `spawn-api`. Heavy data streams (exec output, PTY, files, preview traffic) go through `spawn-edge` straight to the node. Every byte a sandbox sends out passes `spawn-egress`.

### Components

| Component | Language | Runs on | Job |
| --- | --- | --- | --- |
| `spawn-api` | Rust (axum, tonic) | Control plane, 2+ instances | Public API, auth, quotas, scheduler, events, usage |
| `spawn-edge` | Rust (hyper, rustls) | Control plane, 2+ instances | TLS for preview URLs, routing to nodes, data streams |
| `spawn-node` | Rust (tokio) | Every node | VM lifecycle, jailer, snapshots, warm pools, build cache, netns setup |
| `spawn-egress` | Rust (tokio, rustls) | Every node | Egress policy, TLS passthrough or interception, secret injection, DNS, package cache |
| `spawn-guest` | Rust (musl, static) | Inside every VM | PID 1, exec, PTY, files, fix-ups, ssh-agent bridge |
| `spawnbox` CLI | Rust (clap) | User machines | Client CLI |
| `@spawnbox/sdk`, `@spawnbox/mcp` | TypeScript | User code | SDK and MCP server |
| `spawnbox` (Python) | Python | User code | SDK |

### Dependencies

- Firecracker and its jailer, pinned per release. gVisor `runsc` for the fallback.
- Postgres 15 or newer. The only stateful service the control plane needs.
- Any S3-compatible object store for builds, snapshots and stored output.
- OpenTelemetry for traces and logs. Prometheus format for metrics.

### Repository layout

```
spawnbox/
  crates/
    spawn-api/         spawn-edge/        spawn-node/
    spawn-egress/      spawn-guest/       spawn-proto/   (protobuf, shared types)
    backend-firecracker/                  backend-gvisor/
    spawnbox-cli/      spawn-bench/
  guest/
    kernel/            (config, build script)
    images/            (base images: debian, node, python, browser)
  sdk/ts/  sdk/python/  mcp/
  deploy/              (install.sh, compose, helm)
  docs/
```

All Spawnbox components in this plan live in the public repository. No private component or Spawnbox-operated service is required.

## Isolation backends

Firecracker is the default backend. gVisor is the fallback for hosts without `/dev/kvm`. Both sit behind one Rust trait, so the rest of the system never knows which one runs.

### Backend trait

```rust
trait Backend {
    async fn restore(&self, build: &BuildRef, spec: &VmSpec) -> Result<VmHandle>;
    async fn pause(&self, vm: &VmHandle) -> Result<()>;
    async fn resume(&self, vm: &VmHandle) -> Result<()>;
    async fn snapshot(&self, vm: &VmHandle, kind: SnapshotKind) -> Result<SnapshotFiles>;
    async fn kill(&self, vm: &VmHandle) -> Result<()>;
    async fn stats(&self, vm: &VmHandle) -> Result<VmStats>;
    fn caps(&self) -> BackendCaps; // fork, memory snapshot, balloon, rate limits
}
```

### Firecracker

- Version pinned per release. The version is recorded in every snapshot manifest.
- Every VM runs under the Firecracker `jailer`: its own chroot, its own unprivileged uid and gid, a cgroup v2 slice, and the default seccomp filter.
- One API socket per VM. `spawn-node` drives it over that socket.
- Restore uses the File memory backend. The memory file is `mmap`ed `MAP_PRIVATE`, so pages load lazily and stay shared in the host page cache across clones.
- On a host that does not have the build yet, restore uses the UFFD memory backend: a page handler thread in `spawn-node` serves faults from parts that `spawn-api` fetches from the build store, so a restore starts before the memory file is downloaded. Built so far: the create path only; warm pools, fork and snapshot wait for the full file.
- Devices: one virtio-net, two or three virtio-blk (base rootfs read-only, upper disk, optional `/data`), one vsock, a balloon, the VMGenID device.
- Rate limiters on disk and network, set from the sandbox spec.

### gVisor fallback

- `runsc` with an OCI bundle built from the same rootfs.
- Pause and resume use `runsc checkpoint` and `restore`. Restore is slower, so warm pools matter more here.
- Snapshots are backend-specific. A template is built once per backend it must run on.
- A tenant can set `isolation: microvm-only`. The scheduler then never places it on a gVisor node.

### Host detection

At start, `spawn-node` checks, in order:

1. `/dev/kvm` exists and opens read-write.
2. `KVM_GET_API_VERSION` returns 12.
3. The CPU model and flags, hashed into a CPU fingerprint.
4. cgroup v2 is mounted and delegated.

The node reports `backends: [firecracker | gvisor]` and its CPU fingerprint to the control plane.

### CPU compatibility

A Firecracker memory snapshot only restores on a compatible CPU. Each build records the CPU fingerprint and the Firecracker CPU template it used. The scheduler places a restore only on a node with a matching fingerprint. A fleet with mixed CPUs builds one variant per CPU family.

### Guest kernel

One kernel, built and shipped by Spawnbox, on the newest long-term (LTS) line that the pinned Firecracker release tests: 6.18 today. It starts from Firecracker's guest config for that line. Required features:

| Need | Kernel feature |
| --- | --- |
| Base | virtio-net, virtio-blk, vsock, ext4, tmpfs, devpts |
| Overlay root | overlayfs |
| Docker inside the sandbox | cgroup v2, namespaces, veth, bridge, nftables |
| Chromium and Playwright | user namespaces, seccomp |
| FUSE tools | fuse |
| Safe clones | VMGenID, CRNG reseed on generation change |
| Memory return | virtio-balloon with free page reporting |

A kernel test runs a tool matrix before each kernel release (see Testing).

## Guest image and guest agent

`spawn-guest` is a static Rust binary (musl) that runs as PID 1 in every VM. It is the only way the host talks to the guest. It speaks gRPC over vsock.

### Boot duties (as PID 1)

1. Mount `/proc`, `/sys`, `/dev`, `/dev/pts`, `/run`, `/tmp`.
2. Mount `/dev/shm` at 1 GiB (Chromium crashes on a small one).
3. Mount the root overlay: base rootfs (read-only) as lower, the upper disk as upper.
4. When the host asks, mount up to 4 volumes at the paths given at create.
5. Bring up `eth0` with the fixed guest address `172.16.0.2/30`, gateway `172.16.0.1`.
6. Install the tenant's egress CA into the system trust store, if the template has none yet.
7. Start the vsock gRPC server on port 1024 and the SSH agent bridge.
8. Reap zombies forever.

### Users

- `spawn-guest` runs as root. It is not trusted by the host. The VM boundary is the security boundary.
- User commands run as `user` (uid 1000) with passwordless `sudo`. Agents can still install anything.
- Home is `/home/user`. The default working directory is `/workspace`.

### Transport

- The host connects through the Firecracker vsock Unix socket, sends `CONNECT 1024`, then runs gRPC (tonic) on that stream.
- Every connection starts with `Hello{protocol_version}`. The host refuses guests more than two minor versions apart.
- The host enforces size limits on every message from the guest and treats all of it as untrusted input.

### Services

| Service | Calls | Notes |
| --- | --- | --- |
| `Process` | `Start`, `Stream`, `SendStdin`, `Signal`, `Wait`, `List` | `cmd` (run with `bash -lc`) or `argv` (no shell). Env, cwd, user, timeout. Background jobs survive the client disconnecting. |
| `Pty` | `Open`, `Stream`, `Resize`, `Close` | Bidirectional stream. Used by the terminal WebSocket. |
| `Files` | `Stat`, `List`, `Read`, `Write`, `Mkdir`, `Remove`, `Move`, `Watch` | Read and write stream in 1 MiB chunks. Binary-safe. |
| `Identity` | `Apply` | Sets clock, entropy, hostname, sandbox ID, env. Called on every resume. |
| `Health` | `Ping`, `Stats` | CPU, memory, disk, OOM kill count. |
| `Ssh` | `AgentBridge` | Carries ssh-agent requests from the guest socket to the host. |

### Exec result

```json
{
  "exec_id": "ex_7Qm2",
  "exit_code": 0,
  "signal": null,
  "oom_killed": false,
  "duration_ms": 412,
  "stdout": "...",
  "stderr": "...",
  "stdout_truncated": false,
  "stderr_truncated": false
}
```

Non-streaming output is capped at 1 MiB per stream. Streaming has no cap. Binary output is returned base64 with `encoding: "base64"`.

### Resume fix-ups

Every clone wakes up as the same machine. `Identity.Apply` runs before a sandbox is reported ready:

| Problem | Fix |
| --- | --- |
| Same random state in every clone | VMGenID changes on restore, so the kernel reseeds. The host also pushes 64 bytes of fresh entropy with `RNDADDENTROPY`. |
| Clock frozen at snapshot time | Host sends wall time. Guest calls `clock_settime`. |
| Same hostname and ID | Host sends the new sandbox ID. Guest sets the hostname to it. |
| Env and secret placeholders | Host sends them. Guest writes `/run/spawn/env` and the login profile. |
| Same IP in every clone | Expected. Each VM sits in its own network namespace (see Networking). |

The entropy fix is security-critical. Without it, two tenants' sandboxes can generate the same keys.

## Templates and snapshots

A template is built once into an immutable build: a read-only disk, a memory snapshot and a VM state file. Every sandbox starts from a build. Nothing boots from scratch on the hot path.

### Template spec

```yaml
name: node22-playwright
base: docker.io/library/node:22-bookworm
backend: [firecracker]
resources: { vcpus: 2, memory_mib: 4096, disk_gib: 20 }
env: { NODE_ENV: development }
setup:
  - apt-get update && apt-get install -y git ffmpeg
  - npx -y playwright install --with-deps chromium
warmup:
  - node -e "require('playwright')"
  - python3 -c "import json"
```

- `setup` runs once at build time, as root, with network.
- `warmup` runs right before the snapshot, so runtime pages are already hot in memory.
- Also accepted: a `devcontainer.json`, or a plain OCI image with no setup.

### Build pipeline

1. Pull the OCI image inside a builder microVM, never on the host. A hostile image cannot exploit the host's tar extractor.
2. Flatten the layers into a directory. Inject `spawn-guest` and the guest kernel modules.
3. Write an ext4 image, sparse, sized to fit plus 25 percent.
4. Boot a fresh VM from that image with network.
5. Run `setup` steps through `spawn-guest`. Stream logs to the build record.
6. Run `warmup`. Do not drop caches.
7. Pause the VM. Take a full snapshot: `mem.snap` and `vm.state`.
8. Hash every file. Compress with zstd for storage. Upload to the object store. Holes in sparse files are not stored.
9. Mark the build `ready`. Tell nodes to prefetch it if the template is popular.

Built so far: steps 1 to 3 run in the guest agent of a builder VM with the new disk mounted at `/spawn/image`; the disk is shrunk with `resize2fs -M`, not sized plus 25 percent, and kernel modules are not added. With a build store, a host claims the build with a create-only object (`<prefix>/claims/<key>.json`) and rewrites it every 30 s. Other hosts wait, then fetch. A claim not rewritten for 3 minutes is taken over. The uploaded build is the signal; there is no push to nodes.

A failed step marks the build `failed` with the step, exit code and last 64 KiB of output.

### Artifact layout

```
s3://<bucket>/builds/<org>/<build_id>/
  manifest.json
  rootfs.ext4.zst
  mem.snap.zst
  vm.state
```

`manifest.json` records: template ID, backend, Firecracker version, guest kernel version, `spawn-guest` protocol version, CPU fingerprint, resource shape, file sizes, SHA-256 per file, parent build (if any).

Nodes store builds decompressed under `/var/lib/spawnbox/builds/<build_id>/`, content-addressed by hash.

### Restore path

Covered step by step in Lifecycle. In short: claim a warm VM, or restore from the cached build, then run `Identity.Apply`, then report ready.

### Snapshot from a running sandbox

- `POST /v1/sandboxes/{id}:snapshot` pauses the VM and saves memory, VM state and the **upper disk only**. The base disk is shared and never copied.
- The result is a new build whose `parent` is the original build. New sandboxes start from it like any template.
- Chains are capped at depth 3. A fourth level is flattened into a new full rootfs in the background.

### Fork

- `POST /v1/sandboxes/{id}:fork {count: N}` makes N children with the source's exact state.
- Same node: pause the source, write its memory to a local file, reflink-copy its upper disk N times, restore N VMs mapping the same memory file `MAP_PRIVATE`, run fix-ups on each, resume the source.
- Target: 10 children in under 1 second on one node.
- Cross-node fork: snapshot, upload, restore elsewhere. Seconds, not milliseconds.

Built so far: same-node fork (1 to 16 children) and snapshot to a template, both leaving the source running. The memory file is written once and every child maps it; the upper disk is copied once (`cp --reflink=auto`) while the source is paused. A snapshot is a template with a `snapshot` field, not a build with a `parent`: it is never rebuilt, other hosts get it only from the build store, and without a store sandboxes from it are placed on the source's host. Not built: cross-node fork, chains and flattening, and fork or snapshot of sandboxes with volumes. Measured on EC2: 10 children in about 0.7 s, a snapshot in about 0.4 s.

### Dependency snapshots

A build can be keyed by a lockfile hash: `hash(parent_build + repo_url + lockfile)`. The harness asks for that key. On a hit, the sandbox starts with `node_modules` (or the venv, or `target/`) ready. On a miss, Spawnbox installs and saves a new build. These builds are always per tenant, never shared.

### Retention and garbage collection

- Builds are reference counted: by templates, snapshots and running sandboxes.
- A build with no references for 7 days is deleted from the object store. Each node rewrites the manifests of the builds it uses once a day, so "no references" means "no node rewrote it for 7 days".
- Each node keeps an LRU cache of builds with a size cap (default 70 percent of its build disk).
- Per-tenant quota on stored snapshot bytes.

## Sandbox lifecycle

A sandbox moves through seven states. Running and Paused are the two a user sees most. Every transition emits an event.

&#91;embedded content: sandbox lifecycle · 7 states\]

A paused sandbox's memory and disk sit on the node's disk, so it costs storage, not CPU or RAM. Resume brings it back where it stopped.

### States

| State | Meaning | Uses CPU and RAM |
| --- | --- | --- |
| Requested | Accepted, quota checked, not placed yet | No |
| Scheduled | A node is reserved | No |
| Starting | Restoring from a warm VM or a build, then fix-ups | Yes |
| Running | Ready. Exec, files, PTY and ports work | Yes |
| Paused | vCPUs stopped, memory saved to disk | No |
| Failed | Could not start after 3 tries. Kept 24 hours for inspection | No |
| Deleted | Gone. Only events remain | No |

A sandbox on a node that stops heartbeating becomes `lost`. If the node returns within 10 minutes, its sandboxes are reconciled back to their real state. Otherwise they become Deleted.

### Hot path: create

1. `spawn-api` authenticates the key, checks the tenant's quotas, writes the sandbox row as Requested.
2. The scheduler filters and scores nodes, then reserves capacity with a conditional update. State: Scheduled.
3. `spawn-api` calls `spawn-node.CreateSandbox`. State: Starting.
4. `spawn-node` claims a warm VM of that build. If none, it restores from the cached build: create the upper disk, set up the network namespace, launch the jailed Firecracker, load the snapshot.
5. `spawn-node` calls `Identity.Apply` in the guest: clock, entropy, hostname, env, placeholders.
6. The guest replies ready. `spawn-node` reports Running with step timings.
7. `spawn-api` returns `201` with the sandbox and `timings_ms`.

### Timeouts

| Timer | Default | Effect |
| --- | --- | --- |
| `timeout_s` | 1800 s | Running time limit. Extendable with `PATCH` up to the operator-configured maximum. Then Deleted |
| `idle_pause_s` | 600 s | No exec, PTY, file call or port traffic for this long: Paused |
| Paused retention | 7 days | Then Deleted |
| Start timeout | 30 s | Starting longer than this counts as a failed try |
| Max lifetime | 24 hours running | Hard cap configured by the operator |

### Transition rules

- Pause and resume are idempotent. Pausing a Paused sandbox returns `200` and changes nothing.
- Resume can land on a different node if the original is full or gone. The ID, URLs and secrets stay the same.
- A request to a published port with `auto_resume` on resumes a Paused sandbox and holds the request until Running.
- Single-node M1 differs: every exec, file, terminal, clone or preview request wakes a Paused sandbox and waits for it, with no `auto_resume` setting. `idle_pause_s` counts from the end of the last call, so traffic inside the sandbox alone does not keep it awake. Paused time does not count toward `timeout_s`.
- Delete works from any state.

## Storage

The root filesystem is an overlay assembled inside the guest: a shared read-only base disk plus a small per-sandbox upper disk. This makes snapshots and forks cheap, because only the upper disk is ever copied.

### Disks per sandbox

| Disk | Device | Lifetime | Default size |
| --- | --- | --- | --- |
| Base rootfs | `vda`, read-only, shared by every sandbox of the build | As long as the build | Fits the image |
| Upper | `vdb`, read-write, sparse ext4 | Until the sandbox is deleted | 20 GiB logical |
| Volumes (optional, up to 4) | `vdc`–`vdf` read-write, `vdg`–`vdj` read-only, sparse ext4 | Until explicitly deleted, survives the sandbox | 10 GiB logical |
| Template layer | `vdk`, read-only, shared by every sandbox of the build | As long as the build | Fits the setup |

Why guest-side overlay over host-side device mapper:

- No special host filesystem or LVM setup. Works on plain ext4 or XFS.
- The base disk's pages are shared in the host page cache across all sandboxes of a build.
- A snapshot or fork copies only the upper disk, which is usually megabytes.

### Host layout

```
/var/lib/spawnbox/
  builds/<build_id>/        rootfs.ext4, mem.snap, vm.state, manifest.json
  sandboxes/<sandbox_id>/   upper.ext4, data.ext4, jailer chroot, sockets
  cache/                    package pull-through cache
  tmp/
```

- Upper disks are created with reflink on XFS, or as sparse files on ext4.
- XFS with reflink is recommended. Forks are instant there.
- NVMe recommended. Network block storage works but slows restores.

### Limits

- Disk bandwidth and IOPS per sandbox through Firecracker's rate limiter. Default 200 MB/s and 10k IOPS.
- Upper disk logical size is limited by operator configuration. The host tracks real bytes used per tenant for quota.
- Node keeps 15 percent of its disk free. Below that it refuses new placements and garbage-collects the build cache.

### Package caches

A pull-through cache on each node serves npm, PyPI, crates.io, Debian apt, Docker Hub and GitHub release assets through `spawn-egress`.

- Content-addressed. A cached object is served only if its hash matches what the registry published (npm integrity, PyPI hashes, apt `Release` signatures).
- Shared across tenants, because it stores exactly what the public registry served. Nothing a tenant wrote can enter it.
- Private registries are never cached across tenants.
- Size cap with LRU eviction. Default 100 GiB.

## Networking

Every sandbox gets its own Linux network namespace on the host, and all of its outbound traffic goes through `spawn-egress`. Nothing leaves a sandbox without a policy decision and a log line.

### Per-sandbox wiring

```
guest eth0 172.16.0.2/30
   |
 tap0 (172.16.0.1)          inside netns sbx-<id>
   |
 nftables in netns: DNAT tcp 80,443 -> spawn-egress transparent port
                    DNAT udp/tcp 53 -> node DNS resolver
                    DROP everything else not allowed by policy
   |
 veth pair -> host bridge spawn0 (10.200.0.0/16, one /30 per netns)
   |
 spawn-egress -> host NAT -> internet
```

- The guest address is the same in every VM. The namespace keeps them apart. Clones need no IP change.
- Sandboxes can never reach each other, the node's own services (except DNS and the proxy), or private ranges.
- Always blocked: `169.254.169.254` and every cloud metadata address, RFC 1918 ranges of the host network, SMTP port 25.
- IPv6 is off inside the guest in v1.

### DNS

A per-node resolver answers every sandbox. It logs each query with the sandbox ID. Policy is checked on the name, and again on the IP at connect time, to stop DNS rebinding tricks.

### Egress policy

```json
{
  "mode": "allowlist",
  "allow": ["registry.npmjs.org", "pypi.org", "*.pythonhosted.org", "github.com", "*.githubusercontent.com"],
  "deny": [],
  "allow_ports": [80, 443, 22],
  "max_egress_mbps": 100
}
```

- Modes: `allow_all`, `allowlist`, `deny_all`.
- Order of precedence: platform blocks, then tenant policy, then sandbox policy. A sandbox can only narrow its tenant's policy, never widen it.
- The default policy is `allow_all` with every connection logged, so installs and tools work out of the box. Operators narrow it with `--egress-policy`; with tenants, per tenant.

### spawn-egress

One process per node, written in Rust on tokio.

- **No secret for this host:** read the TLS SNI, check policy, then pass the bytes through untouched. No decryption.
- **A secret matches this host:** terminate TLS with the tenant's CA, inject the credential, open a new TLS connection to the real host and verify its certificate. See Secrets.
- Plain HTTP: check the `Host` header against policy.
- Every connection is logged: sandbox, step ID, host, port, bytes each way, verdict, duration.
- Per-sandbox bandwidth limit and per-tenant egress metering.

### Ports and preview URLs

- `POST /v1/sandboxes/{id}/ports {port: 3000, access: "token"}` returns a URL like `https://3000-sbx_8f2k.<domain>`.
- Access modes: `public` (anyone), `token` (signed link, expiring), `private` (API key or session token required).
- HTTP, WebSocket and server-sent events all work.
- A request to a paused sandbox can resume it, if `auto_resume` is on for that port.

### spawn-edge

- Terminates TLS for the wildcard domain. Certificates come from ACME with DNS-01.
- Looks up `sandbox ID -> node` in a cache filled from the control plane. Cache miss falls back to the API.
- Forwards to `spawn-node` on the right host over mTLS. `spawn-node` connects into the sandbox's namespace to the guest port.
- Also carries the exec stream, PTY WebSocket and file transfer traffic to nodes, so the API never sits in the data path at scale.
- Stateless. Run several behind a TCP load balancer.

As built (M3): `spawn-edge` is the subcommand `spawn-api edge`, not a separate binary. It joins with a join token like a worker (row in `nodes` with `kind = edge`; no heartbeats, so never a placement or move target) and polls `GET /fleet/v1/routes` on the primary every second for the full `node -> url` and `sandbox -> node` table. Exec, PTY, files and `git:clone` calls and all preview traffic go straight to the sandbox's host over mTLS with the header `x-spawnbox-node`; other calls go to the primary's fleet listener. The serving host checks the API key. Workers accept edges listed in the config they sync; the primary checks the edge row on each call. TLS comes from cert and key files (no ACME yet). A removed edge gets `403` from the routes call and refuses all calls. Limits: the full table each second, calls in the first second of a move can reach the old host, and control calls fail while the primary is down.

## Secrets and credential proxy

Secrets live only on the host side. The guest sees a worthless placeholder. A real value is added on the way out, only for hosts the secret allows. A hacked agent can use a secret through Spawnbox, but can never copy it.

### Secret object

```json
{
  "name": "github",
  "tenant": "tn_acme",
  "type": "http_header",
  "allowed_hosts": ["github.com", "api.github.com", "*.githubusercontent.com"],
  "header": "Authorization",
  "format": "Bearer {value}",
  "env": "GITHUB_TOKEN",
  "version": 3
}
```

Types: `http_header`, `http_basic`, `git_https`, `ssh_key`. M1 ships `http_header` (`header` and `format`) and `git_https` (`username`, default `x-access-token`, sent as Basic auth), without `tenant`.

### Storage

- Envelope encryption. One data key per tenant, wrapped by a key-encryption key.
- The key-encryption key comes from a cloud KMS, HashiCorp Vault, or a local key file for single-node installs.
- Values are write-only through the API. Reads return metadata, never the value.
- Rotation: a new version takes effect for running sandboxes on their next request.

### HTTPS injection

1. The sandbox is created with `secrets: ["github"]`.
2. Fix-ups write `GITHUB_TOKEN=sbx_ph_<random>` into the guest env, so tools that need the variable to exist still work.
3. The guest calls `https://api.github.com`. `spawn-egress` sees the host matches the secret.
4. It terminates TLS with the tenant's CA, which the guest trusts.
5. It checks that the request's `Host` names the TLS host, so a shared front end cannot route the secret elsewhere. It replaces the placeholder with the real value only in the secret's own header, or sets the header if absent. Other headers keep the placeholder, so a server that echoes them cannot reveal the value.
6. It opens a new TLS connection to the real host, verifies the real certificate, and forwards.
7. If the placeholder is sent to any host not in `allowed_hosts`, it goes out unchanged. The receiver gets nothing usable.

### Git over HTTPS

The proxy sets `Authorization` on requests to the secret's hosts when the request has none, so `git clone` and `git push` over HTTPS work with no credential setup and no real token in the VM. Tools that need a token in a variable use the placeholder.

### Git over SSH

- For each sandbox, `spawn-node` holds an ssh-agent with only the keys attached to it.
- `spawn-guest` exposes `/run/spawn/ssh-agent.sock` and sets `SSH_AUTH_SOCK`. Requests travel over vsock.
- The guest can ask for a signature. It can never read the key.
- Port 22 egress is allowed only to hosts listed for that key.

### Per-tenant CA

- One CA per tenant, created on first use. Installed into templates at build time and at fix-up time for older builds.
- The CA private key is stored encrypted, like a secret. Nodes hold it in memory only while a sandbox of that tenant runs.
- Rotation yearly, or on demand.

### Audit

Every injection is an event: secret name, version, host, sandbox, step ID, time. Never the value.

## Tenancy, auth and quotas

The hierarchy is org, then tenant, then sandbox. An org is a platform that uses Spawnbox. A tenant is one of that platform's own customers. This is the feature that sets Spawnbox apart, so it is open source and built in from v1.

### Hierarchy

```
Org (a harness company)
  Tenant (one of their customers)
    Sandboxes, templates, snapshots, secrets, egress policy, quotas
  Org-wide templates and policies, shared by all its tenants
```

A single-team self-host has one org and one default tenant. The API still works the same.

### API keys

| Key kind | Prefix | Can touch |
| --- | --- | --- |
| Org admin | `sbx_org_` | Everything in the org: tenants, quotas, keys, all sandboxes |
| Tenant | `sbx_tn_` | Only its own tenant's resources |
| Session token | JWT | One sandbox, for 15 minutes. For browser PTY and private preview URLs. |

- Keys are shown once, stored as SHA-256 with a lookup prefix.
- Scopes: `sandboxes:read`, `sandboxes:write`, `templates:write`, `secrets:write`, `tenants:admin`, `audit:read`.
- A request for another tenant's resource returns `404`, never `403`. Existence never leaks.

### Quotas per tenant

| Quota | Default |
| --- | --- |
| Running sandboxes | 20 |
| Total running vCPU | 40 |
| Total running memory | 80 GiB |
| Snapshot storage | 50 GiB |
| Egress per month | 100 GiB |
| Max session length | 24 hours |
| Max paused retention | 7 days |

Quotas are checked at admission in the control plane, before scheduling. Over quota returns `429 quota_exceeded` with the quota name.

### Limits per sandbox

- vCPU 1 to 8, memory 512 MiB to 16 GiB, upper disk 1 to 100 GiB. Operators can raise the caps.
- Shapes must be allowed by the operator's configuration for the tenant, or `400 spec_not_allowed`.

### Metering

- `spawn-node` reports usage every 10 seconds: vCPU-seconds, GiB-seconds of memory, disk GiB-hours, egress bytes.
- The control plane rolls them up per tenant per hour in `usage_hourly`.
- `GET /v1/usage?tenant=...&from=...&to=...` returns the rollups. A harness bills its own customers from this.
- Billing integrations are out of scope. Platforms can use the usage API in their own billing systems.

### Rate limits

Token bucket per API key. Default 50 requests per second, burst 200. Exec and file calls have their own bucket, so a chatty agent cannot block lifecycle calls.

## Public HTTP API

One REST API under `/v1` is the product. SDKs, CLI and MCP are thin wrappers over it. An OpenAPI 3.1 document is generated from the Rust handlers and published with every release.

### Conventions

- JSON bodies. Auth with `Authorization: Bearer <key>`.
- Every mutating call accepts `Idempotency-Key`. A repeat within 24 hours returns the first result.
- `X-Spawnbox-Step: <step id>` and W3C `traceparent` are accepted on every call and attached to every event the call causes.
- Custom actions use `:verb` on the resource: `POST /v1/sandboxes/{id}:pause`.
- Lists use cursor pagination: `?limit=50&cursor=...`.
- Create is synchronous by default and returns when the sandbox is ready. `?wait=false` returns `202` at once.
- Template builds are always asynchronous and return an operation to poll or stream.

### Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/v1/sandboxes` | Create from a template, build or snapshot |
| GET | `/v1/sandboxes` | List. Filter by tenant, state, labels |
| GET | `/v1/sandboxes/{id}` | Get state, spec, node, timestamps |
| PATCH | `/v1/sandboxes/{id}` | Change timeout, labels, egress policy (narrower only) |
| DELETE | `/v1/sandboxes/{id}` | Kill and delete |
| POST | `/v1/sandboxes/{id}:pause` | Pause, keep memory |
| POST | `/v1/sandboxes/{id}:resume` | Resume |
| POST | `/v1/sandboxes/{id}:snapshot` | Save state as a new build |
| POST | `/v1/sandboxes/{id}:fork` | Make N copies of the exact state |
| POST | `/v1/sandboxes/{id}/exec` | Run a command. Plain JSON, or SSE when `Accept: text/event-stream` |
| GET | `/v1/sandboxes/{id}/exec/{exec_id}` | Status and stored output of a past or background command |
| POST | `/v1/sandboxes/{id}/exec/{exec_id}:signal` | Send a signal |
| GET (WS) | `/v1/sandboxes/{id}/pty` | Interactive terminal |
| GET | `/v1/sandboxes/{id}/files?path=` | Read a file, or list a directory |
| PUT | `/v1/sandboxes/{id}/files?path=` | Write a file |
| DELETE | `/v1/sandboxes/{id}/files?path=` | Delete |
| POST | `/v1/sandboxes/{id}/files:upload` | Upload a tar stream and extract it |
| POST | `/v1/sandboxes/{id}/git:clone` | Clone with an attached secret |
| POST | `/v1/sandboxes/{id}/ports` | Publish a port, get a URL |
| DELETE | `/v1/sandboxes/{id}/ports/{port}` | Unpublish |
| GET (SSE) | `/v1/sandboxes/{id}/events` | Live events for this sandbox |
| POST | `/v1/templates` | Create a template and start a build |
| GET | `/v1/templates/{id}/builds/{build_id}` | Build status and logs |
| POST | `/v1/secrets` | Create a secret. Value is write-only |
| PATCH | `/v1/secrets/{name}` | Rotate |
| POST | `/v1/tenants` | Create a tenant |
| PATCH | `/v1/tenants/{id}` | Set quotas and default egress policy |
| GET | `/v1/usage` | Metered usage rollups |
| GET | `/v1/events` | Query the audit and activity log |
| POST | `/v1/keys` | Create an API key |

### Create a sandbox

```json
POST /v1/sandboxes
{
  "tenant": "tn_acme",
  "template": "node22-playwright",
  "resources": { "vcpus": 2, "memory_mib": 4096 },
  "timeout_s": 1800,
  "idle_pause_s": 600,
  "secrets": ["github"],
  "egress": { "mode": "allowlist", "allow": ["github.com"] },
  "env": { "CI": "1" },
  "labels": { "agent_run": "run_42" }
}
```

```json
201 Created
{
  "id": "sbx_8f2kq1",
  "state": "running",
  "build": "bld_3n8s",
  "node": "nd_fra1_07",
  "created_at": "2026-11-04T01:40:12.381Z",
  "expires_at": "2026-11-04T02:10:12.381Z",
  "timings_ms": { "schedule": 2, "claim": 6, "fixups": 9, "total": 31 }
}
```

`timings_ms` is always returned. It keeps the hot path honest.

### Errors

```json
{ "error": { "code": "no_capacity", "message": "...", "retryable": true, "retry_after_s": 5, "request_id": "req_..." } }
```

| Code | HTTP | Retry |
| --- | --- | --- |
| `invalid_request` | 400 | No |
| `spec_not_allowed` | 400 | No |
| `unauthorized` | 401 | No |
| `missing_scope` | 403 | No |
| `not_found` | 404 | No |
| `conflict` (wrong state for the action) | 409 | No |
| `quota_exceeded` | 429 | After usage drops |
| `rate_limited` | 429 | Yes, after `retry_after_s` |
| `no_capacity` | 503 | Yes |
| `node_unreachable` | 503 | Yes |
| `internal` | 500 | Yes, with backoff |

Clients branch on `code`, never on `message`.

### E2B compatibility

- Goal: an existing E2B SDK user changes the API URL and domain, and core calls work: create, run command, read and write files, kill, pause, resume.
- E2B's SDK talks to two things: the API, and an agent inside each sandbox reached on a per-sandbox domain. Spawnbox serves both: a compat router under `/e2b/` on the API, and a compat surface on `spawn-edge` for the per-sandbox domain.
- Gaps are documented in a public table, not hidden.
- The exact wire protocol and license terms must be checked before building (see Risks).

## SDKs, CLI and MCP server

The TypeScript SDK ships first, because harness builders mostly write TypeScript. Python follows in the same milestone. Both are generated from the OpenAPI document, then wrapped by hand for a good API.

### TypeScript SDK: `@spawnbox/sdk`

Functional style. Plain functions and plain objects. Streams are async iterators. Every call takes an `AbortSignal`.

```ts
import { createClient } from "@spawnbox/sdk";

const sbx = createClient({ apiKey: process.env.SPAWNBOX_API_KEY });

const box = await sbx.create({
  tenant: "tn_acme",
  template: "node22-playwright",
  secrets: ["github"],
});

const step = sbx.withStep("run_42/step_7");

await step.git.clone(box, { url: "https://github.com/acme/app", dir: "/workspace/app" });

for await (const ev of step.exec.stream(box, { cmd: "npm test", cwd: "/workspace/app" })) {
  if (ev.type === "stdout") process.stdout.write(ev.data);
  if (ev.type === "exit") console.log("exit", ev.code);
}

const [a, b] = await sbx.fork(box, { count: 2 });
await sbx.kill(box);
```

- `withStep(id)` returns the same client with `X-Spawnbox-Step` set on every call.
- Errors are typed: `SpawnboxError` with `code`, `retryable`, `retryAfterS`.
- Retries with backoff on retryable codes, on by default for idempotent calls.
- Works in Node 20+, Bun and Deno. No browser build in v1 (keys must not reach browsers).

### Python SDK: `spawnbox`

Sync and async clients with the same surface: `Spawnbox` and `AsyncSpawnbox`.

### CLI: `spawnbox`

One Rust binary for users. Server binaries are separate.

```
spawnbox login
spawnbox create --template node22 --name demo
spawnbox ls
spawnbox exec demo -- npm test
spawnbox sh demo                     # interactive shell over PTY
spawnbox cp ./src demo:/workspace/src
spawnbox pause|resume|kill demo
spawnbox fork demo --count 3
spawnbox snapshot demo --name with-deps
spawnbox ports publish demo 3000 --access token
spawnbox templates build ./spawnbox.json
spawnbox secrets set github --hosts github.com,api.github.com
spawnbox tenants create acme
spawnbox events demo --follow
spawnbox doctor                      # host checks, for operators
```

### MCP server: `@spawnbox/mcp`

- Transports: stdio and streamable HTTP.
- A short tool list, because models pick tools worse when there are many:

| Tool | Does |
| --- | --- |
| `sandbox_create` | Create from a template. Returns the ID |
| `sandbox_exec` | Run a command. Returns exit code and capped output |
| `sandbox_read_file` | Read a file, capped size |
| `sandbox_write_file` | Write a file |
| `sandbox_git_clone` | Clone a repo with an attached secret |
| `sandbox_kill` | Delete the sandbox |

- Optional tools behind a flag: `sandbox_publish_port`, `sandbox_snapshot`, `sandbox_fork`.
- Every tool takes an optional `step_id`.
- Output is capped at 60k characters per call, with a note on how to read the rest.

### Agent skills

A `SKILL.md` for Claude Code, Codex and Gemini CLI that teaches the CLI and the common flows. Installed with `spawnbox skills install`.

## Control plane

`spawn-api` is stateless. Postgres is the only source of truth. Run two or more instances behind a load balancer. There is no Redis and no message queue in v1: Postgres `LISTEN/NOTIFY` and in-memory caches are enough.

### Data model

| Table | Key columns |
| --- | --- |
| `orgs` | id, name, settings |
| `tenants` | id, org\_id, name, quotas (jsonb), egress\_policy (jsonb), isolation |
| `api_keys` | id, org\_id, tenant\_id (nullable), prefix, hash, scopes, expires\_at, revoked\_at |
| `nodes` | id, region, addr, backends, cpu\_fingerprint, capacity (vcpu, mem, disk), committed, state, last\_heartbeat |
| `templates` | id, org\_id, tenant\_id (nullable), name, spec (jsonb), latest\_build\_id |
| `builds` | id, template\_id, parent\_build\_id, backend, cpu\_fingerprint, manifest (jsonb), state, refcount |
| `sandboxes` | id, tenant\_id, build\_id, node\_id, state, spec (jsonb), labels, created\_at, expires\_at, paused\_at |
| `secrets` | id, tenant\_id, name, type, allowed\_hosts, wrapped\_value, version |
| `ports` | sandbox\_id, port, access, url |
| `operations` | id, kind, target, state, progress, result, error |
| `idempotency_keys` | key, key\_owner, request\_hash, response, expires\_at |
| `usage_hourly` | tenant\_id, hour, vcpu\_s, mem\_gib\_s, disk\_gib\_h, egress\_bytes |
| `events` | ts, org\_id, tenant\_id, sandbox\_id, step\_id, trace\_id, actor, type, attrs. Partitioned by day |

Migrations follow expand, then contract. Each release runs against the schema of the release before it.

### Scheduler

Runs inside each `spawn-api` instance, per request. No central scheduler process.

1. **Filter** nodes: state `ready`, right backend, CPU fingerprint matches the build, region allowed, tenant isolation rules (for example dedicated nodes), enough free capacity after overcommit.
2. **Score**: warm VM of this build available (+100), build cached on disk (+50), most free memory (+0 to 30), fewer sandboxes of this tenant on the node (+0 to 10, spreads blast radius).
3. **Reserve**: a conditional `UPDATE nodes SET committed = committed + $need WHERE id = $id AND committed + $need <= capacity * ratio`. Zero rows means someone else won; take the next node.
4. **Place**: call `spawn-node.CreateSandbox`. On failure, release the reservation and try the next node. Three tries, then `503 no_capacity`.

As built (M3, SQLite): the primary `spawn-api` runs the scheduler for itself and its workers. Reservations are in-memory on the primary and count mirror rows of worker sandboxes. CPU fingerprint and region filters, the build-cached score and overcommit wait for the Postgres control plane.

### Node registration and health

- A new node runs `spawn-node join --token <bootstrap>`. It gets a node ID and an mTLS certificate.
- Heartbeat every 5 seconds: capacity, committed, sandbox states, cached builds, warm pool counts, backend health.
- Three missed heartbeats: `suspect`, no new placements. Thirty seconds: `down`. Its sandboxes become `lost`. If the node comes back, it reports its sandboxes and they are reconciled.

As built (M3): a worker is `spawn-api serve --primary <url> --join-token <token> --primary-ca-sha256 <hash>`; tokens come from `POST /v1/nodes/tokens` and are used once. Calls for sandboxes on a `down` node return `503 node_unreachable`, and their rows stay until the node reports again (sandboxes missing from a report for 30 s become `lost`) or `DELETE /v1/nodes/{id}` removes it.

### Internal RPC

gRPC with mTLS between `spawn-api`, `spawn-edge` and `spawn-node`.

| Service | Calls |
| --- | --- |
| `Node` | `CreateSandbox`, `Pause`, `Resume`, `Snapshot`, `Fork`, `Kill`, `Prefetch`, `Drain`, `Stats` |
| `NodeData` | `Exec`, `Pty`, `Files`, `PortForward` (streams; called by `spawn-edge`) |
| `Control` | `Heartbeat`, `ReportEvents`, `ReportUsage` (called by nodes) |

As built (M3): no gRPC between hosts yet. The primary forwards the client's HTTP request as it is (streams and WebSocket upgrades kept) to the worker's `--node-listen` over mTLS, and the worker checks the API key against the copy it syncs. `Control` is JSON over HTTPS at `/fleet/v1/{join,heartbeat,config,events,usage}` on the primary's `--fleet-listen`. Without an edge, the primary carries data streams and previews; with `spawn-api edge`, they go straight from the edge to the worker.

### Reconciliation

A loop in each node compares what Postgres says it should run with what it actually runs, every 30 seconds. Sandboxes past `expires_at` are killed. VMs with no record are killed and logged as an anomaly.

## Fleet

One node becomes many by adding nodes, not by changing code. These parts keep a fleet fast and cheap: warm pools, a build cache, overcommit, autoscaling and drain.

### Warm pools

- A warm VM is a build already restored on a node with its vCPUs paused. Claiming one skips the restore.
- Pools are kept per node, per build, per network mode (the namespace firewall depends on it). A build fixes the resource shape.
- Target size per build: `max(min_warm, creates in the last 30 s)`. Popular templates stay warm. Rare ones fall to zero.
- A node spends at most 10 percent of its memory on warm VMs.
- A claimed VM is replaced in the background.

### Build cache

- Each node keeps builds on local disk, LRU, content-addressed.
- Downloads use parallel range requests and verify SHA-256 before use.
- The store key covers the inputs fingerprint, the host CPU model, the spec and the egress policy. Hosts can share builds only if their kernel, base disk and Firecracker are byte-identical, so nodes get these inputs from one source, not by building them.
- A node that joins prefetches the 20 most-used builds for its region.
  - Built so far: a joining worker queues every template, most sandboxes in the last 7 days first. With `--build-cache-gib` full, a build that the store has is recorded as ready but left in the store until first use. There is no fixed count of 20 and no regions yet.
- Memory pages are fetched on demand over UFFD, so a cold node can start a sandbox before the full memory file arrives. The store keeps `vm.mem` as a paged object (2 MiB zstd parts, each with a SHA-256). The build records the parts that a test restore touches (the hot list); a cold node fetches the parts the guest asks for first, then the hot list, then the rest. If a part cannot be fetched for 30 s, the sandbox is stopped and marked `failed` with `sandbox.lost`.

### Overcommit

| Resource | Default ratio | Safety valve |
| --- | --- | --- |
| vCPU | 4 to 1 | CPU pressure (PSI) above 40 percent stops new placements |
| Memory | 1.2 to 1 | KSM on, balloon reclaims free guest pages, PSI memory pressure pauses idle sandboxes to disk |
| Disk | Thin, by real bytes | Refuse placement below 15 percent free |

The host is never allowed to OOM. Under memory pressure, the node pauses the longest-idle sandboxes to disk first, then refuses placements.

### Autoscaling

- Open source: a pluggable hook. When the fleet needs a node, `spawn-api` runs a command or calls a webhook (`scale_up {region, shape}`). The operator's script creates the machine and runs `spawn-node join`.
- Built-in providers for AWS (C8i/M8i/R8i with nested virtualization) and GCP (N2 with nested virtualization) in v2.
- Triggers: committed memory above 70 percent for 2 minutes, add a node. Below 30 percent for 20 minutes, drain one.
- Recommended shape: bare metal for the always-on base, cloud VMs for bursts.
- As built (M3): `--autoscale-hook` takes an absolute program path or a webhook URL. The primary checks load every 10 s; load is the larger of used slots and used memory over the primary and ready, undrained workers. The defaults match the triggers above, with `--autoscale-min-workers` and `--autoscale-max-workers` bounds and one change at a time. `scale_up` carries a fresh join token (30-minute TTL) and the CA hash, not region or shape. `scale_down` drains the worker with the fewest sandboxes, migrates them, and calls the hook only once the worker is empty, then removes it. Webhooks are signed with HMAC-SHA256 when `--autoscale-secret` is set. Requests are stored in `scale_requests`, shown at `GET /v1/nodes/autoscale` and recorded as `autoscale.*` events. Built-in cloud providers are not built.

### Drain and migration

1. Mark the node `draining`. No new placements.
2. Running sandboxes may finish until their timeout, or migrate now if the operator asks.
3. Migrate one sandbox: pause, snapshot memory and upper disk, upload, restore on another node, re-run fix-ups, update routing.
4. The sandbox ID, preview URLs and secrets stay the same. Clients see a pause of a few seconds.

Live migration (no pause) is out of scope. Sandboxes move only between hosts with the same kernel, base rootfs, Firecracker, egress CA and CPU model. Workers share the primary's egress CA for this reason.

## Observability and audit

Every action in a sandbox becomes an event tagged with the agent step that caused it. A harness can then answer its customer's question "what did the agent do in step 7?" with commands, files and network calls, not guesses.

### Event shape

```json
{
  "ts": "2026-11-04T01:41:03.118Z",
  "org": "org_h1",
  "tenant": "tn_acme",
  "sandbox": "sbx_8f2kq1",
  "step_id": "run_42/step_7",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "actor": "key_9dK2",
  "type": "exec.finished",
  "attrs": { "exec_id": "ex_7Qm2", "cmd": "npm test", "cwd": "/workspace/app", "exit_code": 1, "duration_ms": 8120, "stdout_bytes": 18233 }
}
```

### Event types

| Group | Types |
| --- | --- |
| Lifecycle | `sandbox.created`, `.paused`, `.resumed`, `.snapshotted`, `.forked`, `.killed`, `.expired`, `.lost` |
| Process | `exec.started`, `exec.finished`, `exec.signaled`, `oom.kill`, `pty.opened`, `pty.closed` |
| Files (API-made) | `file.written`, `file.deleted`, `files.uploaded` with path, size, SHA-256 |
| Network | `net.connection` (host, port, bytes, verdict), `net.dns`, `net.blocked` |
| Secrets | `secret.injected` (name, version, host) |
| Ports | `port.published`, `port.unpublished`, `port.request` (sampled) |
| Admin | `key.created`, `tenant.updated`, `secret.rotated`, `policy.changed` |

In v2, the guest agent also reports file changes made by commands inside the sandbox, using fanotify on `/workspace`.

### How step IDs flow

- The harness sets `X-Spawnbox-Step` per call, or uses `withStep()` in the SDK.
- Exec and PTY sessions carry their step ID to the node. Network events are tagged with the step of the exec that opened the connection, matched by process tree in the guest.
- Network connections opened outside any exec are tagged `step_id: null`.

### Where events go

- Events are written to the `events` table (7-day retention by default, configurable by the operator) and exported over OTLP to any OpenTelemetry backend. `GET /v1/events` and `GET /v1/sandboxes/{id}/events` query them.
- Dedicated SIEM connectors and a search and replay UI are out of scope for this plan. Operators can use their existing observability tools through OTLP.

### Output capture

- The last 64 KiB of stdout and stderr per exec is kept with the event.
- Full output can be stored in the object store, per tenant setting.
- PTY sessions can be recorded in asciicast format (v2).

### Metrics

Prometheus on every component.

| Metric | Labels |
| --- | --- |
| `spawnbox_create_seconds` (histogram) | path (warm, cached, cold), backend, region |
| `spawnbox_create_step_seconds` (histogram) | step (auth, schedule, claim, restore, fixups) |
| `spawnbox_sandboxes` (gauge) | state, node |
| `spawnbox_node_committed_ratio` (gauge) | resource, node |
| `spawnbox_warm_pool_hits_total` / `_misses_total` | build |
| `spawnbox_egress_connections_total` | verdict |
| `spawnbox_api_errors_total` | code |

### Traces

Each create, exec and snapshot is one trace with a span per step on the hot path. A slow create is explained by its trace, not by guessing.

## Security and threat model

Assume the code inside every sandbox is hostile and has root in the guest. The design goal: a fully compromised guest can harm only itself, and can use, but never steal, the secrets attached to it.

### What we protect

- The host kernel and the node.
- Other tenants' sandboxes, data and secrets.
- Secret values.
- The control plane and its database.
- Cloud metadata and the operator's private network.

### Who attacks

- Agent-generated or user code running as root in a guest.
- A malicious template image.
- A stolen tenant API key.
- A curious tenant trying to see another tenant's data.

### Threats and controls

| Threat | Control |
| --- | --- |
| VM escape through a device bug | Firecracker's small device model. Jailer: chroot, unprivileged uid per VM, cgroups, seccomp. No shared filesystem devices (no virtio-fs or 9p) in v1. |
| Host kernel bug reached from a VM | Patch Firecracker and host kernels within 72 hours of a critical advisory. Drain and reboot nodes on a rolling basis. |
| gVisor is a weaker boundary | Documented. Tenants can require `microvm-only`. |
| CPU side channels between tenants | Mitigations on. Optional dedicated nodes per tenant. Optional SMT off on those nodes. |
| Network pivot | Per-sandbox namespace. Cloud metadata, host services, private ranges and other sandboxes always blocked. |
| Secret theft | Values never enter the VM. Placeholders are worthless off-allowlist. Per-tenant CA. Every injection logged. |
| A stolen worker disk | Workers hold the primary's egress CA key (encrypted with their secrets key) so sandboxes can move between hosts. Treat every worker as trusted as the primary; use disk encryption. |
| Cloned random state | VMGenID reseed plus host-pushed entropy on every restore. Tested by asserting two clones produce different keys. |
| Hostile image exploits the host unpacker | Images are unpacked inside a builder microVM, never on the host. |
| Malformed data from the guest agent | Host treats all guest messages as untrusted: size caps, strict parsing, fuzzed parsers. |
| Stolen API key | Scoped keys, tenant keys cannot cross tenants, revocation, audit of every call. |
| Data left behind on reused disks | Upper disks and memory files are deleted, sparse files never reused. Node disks encrypted at rest (LUKS) recommended. |
| Abuse of a self-hosted fleet (mining, spam, scanning) | Port 25 blocked, egress rate limits, tenant quotas, operator can revoke keys and kill sandboxes. |
| Supply chain | Reproducible builds, signed release artifacts (Sigstore), SBOM per release. |

### Accepted risks

- Clones share memory layout (ASLR offsets) with their template. Accepted for v1. Documented.
- A tenant's CA private key sits in node memory while that tenant has a running sandbox.

### Before public launch

- External penetration test focused on escape, cross-tenant access and secret theft.
- A public security policy and disclosure address.

## Performance targets

A sandbox must be ready in under 100 ms p50 from a warm pool, measured from the API receiving the request to the response leaving it. These are design targets, not measurements. Milestone M0 measures the real numbers and this table is updated.

### Create path budget (warm pool hit, same region)

| Step | p50 target | p95 target |
| --- | --- | --- |
| Auth, quota check | 3 ms | 8 ms |
| Schedule and reserve | 2 ms | 6 ms |
| API to node RPC | 2 ms | 5 ms |
| Claim warm VM | 5 ms | 12 ms |
| Fix-ups (`Identity.Apply`) | 8 ms | 20 ms |
| Response | 1 ms | 3 ms |
| **Total** | **21 ms** | **54 ms** |

### M0 measurements

Measured with `scripts/m0.sh` on an AWS `m8i.2xlarge` (nested virtualization,
gp3 disk), Firecracker v1.17.0 under the jailer, our Linux 6.18.60 kernel,
2 vCPUs, 1 GiB memory, 20 runs. Each VM has its own jail, cgroup, network
namespace and upper disk. Commands run as `user` through `bash -lc`.

Preparing a VM (jail files, upper disk copy, network namespace) took 19 ms
p50 and 20 ms p95. Copying the sparse upper disk took 2.6 ms of that. A warm
pool does this ahead of time. Times below start after preparation:

| Step | p50 | p95 |
| --- | --- | --- |
| Jailer started, Firecracker API ready | 10.7 ms | 17.0 ms |
| Snapshot loaded and resumed | 15.1 ms | 20.9 ms |
| Guest agent answers `Hello` over vsock | 38.8 ms | 44.6 ms |
| `Identity.Apply` done | 41.6 ms | 47.6 ms |
| First output of `echo ready` | 72.5 ms | 78.0 ms |

Ten clones restored at once from one memory file all passed: unique random
bytes and SSH keys, commands run as `user`, overlay root writable with
`sudo`, internet reachable, cloud metadata and the host blocked. Random bytes
already differed before `Identity.Apply`, so the kernel's VMGenID reseed
works. Creating the 1 GiB full snapshot took 8.3 s, limited by disk speed.

### Targets by path

| Path | p50 | p95 |
| --- | --- | --- |
| Warm pool hit | under 50 ms | under 100 ms |
| Restore from cached build | under 150 ms | under 300 ms |
| Build not on node (download) | under 2 s | under 5 s |
| First exec output after ready (`echo`) | under 30 ms | under 80 ms |
| First exec of a runtime (`node -e 1`) | under 150 ms | under 300 ms |
| Fork, 10 children, same node | under 800 ms | under 1.5 s |
| Pause | under 200 ms | under 500 ms |
| Resume from local disk | under 150 ms | under 300 ms |

### Density

- At least 25 strict (no overcommit) sandboxes of 1 vCPU and 2 GiB on a 6-core, 64 GiB node.
- At least 80 mostly idle sandboxes of that shape on the same node with overcommit.
- Firecracker overhead under 10 MiB of host memory per VM.

### Throughput

- 50 creates per second per node from warm pools.
- 500 creates per second across a fleet of 20 nodes.

### How we hold the line

- `spawnbox bench` runs a fixed suite and prints the tables above.
- CI runs the suite on every merge to main on a KVM runner. A p95 regression over 15 percent fails the build.

## Install, deploy and upgrades

One command installs a working single node. A multi-node fleet uses the same binaries. "Self-host that doesn't hurt" is a product feature, so this section gets the same care as the API.

### Host requirements

| Need | Minimum | Recommended |
| --- | --- | --- |
| OS | Linux x86\_64, kernel 5.10 | Ubuntu 24.04 or Debian 12, kernel 6.1+ |
| Virtualization | `/dev/kvm` (else gVisor fallback) | Bare metal, or AWS C8i/M8i/R8i or GCP N2 with nested virtualization |
| CPU and RAM | 4 vCPU, 8 GiB | 16+ cores, 64+ GiB |
| Disk | 100 GiB SSD | NVMe, XFS with reflink |
| Database | Postgres 15 | Managed Postgres with point-in-time recovery |
| Object store | Any S3-compatible | S3, R2, GCS, or bundled MinIO for single node |

### Install modes

**Single node (one command).**

```
curl -fsSL https://spawnbox.run/install.sh | sh
spawnbox-server init        # asks domain, storage, admin email
```

Installs `spawn-api`, `spawn-node`, `spawn-edge`, `spawn-egress`, Postgres and MinIO as systemd units. Gets a TLS certificate. Prints an admin API key.

**Fleet.**

- Control plane (`spawn-api`, `spawn-edge`) as containers: Docker Compose or a Helm chart.
- Nodes as a systemd binary on bare hosts: `spawn-node join --api https://api.example.com --token <bootstrap>`.
- Nodes can also run as a privileged Kubernetes DaemonSet on nodes with `/dev/kvm`.

### Configuration

One TOML file per component. Every key can be overridden by an environment variable.

```toml
# /etc/spawnbox/node.toml
[node]
region = "fra1"
data_dir = "/var/lib/spawnbox"

[backend]
prefer = "firecracker"
fallback = "gvisor"

[overcommit]
vcpu_ratio = 4.0
memory_ratio = 1.2

[warm_pool]
memory_budget_pct = 10

[cache]
packages_max_gib = 100
```

### Doctor

`spawnbox doctor` checks KVM access, kernel features, cgroup v2 delegation, disk type and free space, reflink support, clock sync, network reachability to API and object store. Each failure prints the fix.

### Upgrades

- Control plane: rolling. Database migrations are backward compatible with the previous release.
- Nodes: drain, upgrade, rejoin, one at a time. `spawnbox-server upgrade --rolling` automates it.
- Guest protocol: the host supports the current and two previous minor versions, so old builds keep working.
- A Firecracker or kernel version change can invalidate memory snapshots. Each manifest records versions. Affected templates rebuild automatically before nodes switch over.

### Backups

- Postgres: point-in-time recovery.
- Object store: versioning on.
- Secrets key-encryption key: backed up separately, offline. Without it, secrets cannot be recovered. The installer says this loudly.

## Testing strategy

The tests that matter most prove three things: a sandbox cannot escape, a secret cannot leak, and the hot path stays fast. Everything runs in CI on a KVM-capable runner: a self-hosted bare-metal box, or a cloud VM with nested virtualization.

### Layers

| Layer | What | Runs |
| --- | --- | --- |
| Unit | Each Rust crate and the SDKs | Every push |
| Fuzz | Host-side parsers of guest messages, the egress proxy's HTTP and TLS parsing, the API's JSON | Nightly, `cargo-fuzz` |
| Integration | One real node: create, exec, files, PTY, pause, resume, snapshot, fork, kill | Every push |
| End to end | SDK and CLI against a 3-node fleet | Every merge to main |
| Performance | `spawnbox bench`, with regression gates | Every merge to main |
| Chaos | Kill a node mid-exec, cut the network, fail over Postgres, fill a disk | Nightly |

### Security tests

- **Secret never in guest.** Attach a secret, run a workload that uses it, then search the guest's memory file and upper disk for the value. Must find nothing.
- **Placeholder off-allowlist.** Send the placeholder to a host not on the list. The receiving test server must see only the placeholder.
- **Entropy.** Fork 10 clones, read 32 bytes of `/dev/urandom` in each, generate an SSH key in each. All must differ.
- **Network blocks.** From a guest, try cloud metadata, the host's IPs, another sandbox, port 25, a denied host. All must fail and log `net.blocked`.
- **Cross-tenant.** Every API endpoint, called with tenant A's key on tenant B's resources, must return `404`.

### Tool matrix

Each guest kernel and base image release must pass:

- `npm`, `pnpm`, `bun`, `pip`, `uv`, `cargo build`, `go build`.
- Playwright with Chromium, headless, taking a screenshot.
- `ffmpeg` transcoding a short clip.
- Docker inside the sandbox: `docker run hello-world`.
- `git clone` and `git push` over HTTPS and SSH with injected credentials.

### Compatibility

The E2B SDK's core examples run against the compat API in CI. Any failure is a documented gap or a bug.

### Before public launch

An external penetration test (see Security).

## Open-source scope

Spawnbox's own code is Apache-2.0. Third-party components keep their own licenses. The project can be self-hosted for personal or commercial use without a paid Spawnbox component.

- The full self-hosted stack is included: runtime, Firecracker and gVisor backends, API, SDKs, CLI, MCP, credential proxy, fleet management, tenants, quotas, usage and events.
- Operators run the control plane, nodes, edge and egress proxies, database and object store on infrastructure they choose, including their own cloud accounts.
- Operators own deployment, backups, upgrades and availability. The project provides install tooling, documentation and community support, not a hosted service or an uptime SLA.
- Managed hosting, managed customer-cloud deployments, pricing, billing exports, enterprise identity integrations and compliance certifications are outside the current roadmap. There is no paid/free feature split to build now.

Success means independent teams can install Spawnbox, keep using it for real agent workloads, and provide useful feedback or contributions. Track repeat use and how much maintainer help an install needs, not only stars or downloads. Any future company plan is a separate decision based on that traction.

## Roadmap

Five milestones, M0 through M4, take the project from a technical spike to an open-source public launch. M1 matters most: it puts a design partner's real agent work on a self-hosted Spawnbox install.

Milestones describe outcomes, not months or fixed deadlines. There is no managed-hosting milestone in this plan.

### M0 Spike: tasks

- [x] Build a guest kernel (6.18 LTS) with the required features
- [x] Debian base rootfs with a minimal `spawn-guest` (exec only) as PID 1
- [x] Boot under the jailer, pause, take a full snapshot
- [x] Restore from snapshot with the File memory backend; time every step
- [x] Exec over vsock with gRPC; time first output
- [x] Restore 10 clones from one memory file; verify entropy differs
- [x] Write up real numbers and update Performance targets

### M1 progress

- [x] Single-node `spawn-api`: create, get, list, delete, exec (JSON and SSE), API keys, expiry, crash cleanup. State in SQLite for single-node installs. `spawn-node` is a library inside `spawn-api` for now, not a separate daemon.
- [x] Custom templates (Debian base plus setup and warmup commands) with background builds that survive restarts; file read, write, list and delete. OCI and devcontainer bases are done: `base` is an image reference, which the guest agent pulls and unpacks in a builder VM onto a new disk (layers checked by digest, whiteouts applied, writes kept inside the disk), then `spawn-guest` is added, the disk is shrunk, and setup runs on it. `registry_secrets` are attached only while pulling. The CLI maps image-based `devcontainer.json` files. Tested on both backends with `node:22-bookworm-slim`, `alpine:3` and `python:3.13-slim`, including snapshot, fork and migration. Private registry pulls are not tested live yet.
- [x] Egress policy (`allow_all`, `allowlist`, `deny_all`; server and sandbox policy both apply) and the HTTPS secrets proxy (`http_header`, `git_https`) inside `spawn-api`, with secrets encrypted by a local key file and every connection logged. Per-sandbox bandwidth limits (`max_egress_mbps`, `max_ingress_mbps`, shaped with `tc tbf` on both ends of the sandbox's link) and DNS logging (a forwarder on the host that every port-53 query is redirected to; it refuses names the policy denies and records `net.dns`) are done. Checking resolved IPs against the policy is not done yet.
- [x] Terminals over WebSocket, `git:clone`, preview ports (`public`, `token`, `private`; HTTP/1.1 and WebSocket) on a second listener, and `deploy/install.sh` (systemd, upgrade, uninstall). Browser session tokens (HS256 JWT for one sandbox, at most 15 minutes) open the terminal and `private` previews; revoking the issuing key ends them.
- [x] Pause and resume (explicit, idle auto-pause, wake on any call; survive restarts), exec `stdin`, and HTTPS on the API and preview listeners with certificate reload. Resume measured about 65 ms. Pause writes full memory snapshots: about 0.7 s on an idle EBS disk and up to about 12 s while earlier pauses flush, so the 200 ms target needs diff snapshots or faster disks.
- [x] CLI for every endpoint that exists (`login`, sandboxes, `exec`, `sh`, `cp`, `clone`, `ports`, `templates`, `secrets`, `tenants`, `keys`, `events`, `usage`), installed by `deploy/install.sh`. `fork` and `snapshot` are done; YAML template files are not.
- [ ] TS SDK, MCP (deferred)

### M2 progress

- [x] Tenants with quotas and an egress policy, org and tenant API keys with scopes, tenant-private and org-wide templates and secrets, and `429 quota_exceeded` on create and resume. One implicit org per install.
- [x] Events with step IDs (`X-Spawnbox-Step`) and trace IDs (`traceparent`), `GET /v1/events` and `GET /v1/sandboxes/{id}/events` with filters, paging and live SSE follow, exec output tails, and export as OTLP/HTTP log records. Events are stored in SQLite with a retention period. OTLP traces: each create, exec and fleet placement is one span (a child of the caller's `traceparent`), with child spans for `fetch_build`, `volumes`, `claim`, `restore`, `fixups`, `open`, `start` and each tried `node`; the primary passes its span to the worker, and the call's events carry its trace ID. Fork and snapshot calls are not traced yet. Output in an object store is not done yet.
- [x] Usage metering and `GET /v1/usage`, with monthly egress and snapshot storage quotas

### M3 progress

- [x] Warm pools on a single node: VMs restored ahead of time with paused vCPUs, per build and network mode, with a target of `max(--warm-pool-min, creates in the last 30 s)` inside a memory budget (`--warm-pool-memory-pct`, default 10). `GET /v1/warm-pools` shows them; creates report `started_from`. Measured on the M0 host: about 8 ms from request to response for a warm hit, against about 70 ms for a restore. Templates set `min_warm` (0 to 16) per host; changing it alone does not rebuild. Prometheus metrics are served on `--metrics-listen` by every host: create time by path (warm, cached, cold), create steps, API errors, egress verdicts, sandboxes by state, committed slots and memory, warm pool ready, hits and misses, and fleet nodes by state. Each host reports only itself, so there are no `node` or `region` labels; Prometheus adds `instance`.
- [x] Build store (`--build-store s3://bucket/prefix` or `file:///path`): ready builds are saved as content-addressed, zstd-compressed blobs. The key hashes the build inputs, host CPU model, template spec and egress policy; a build whose key is in the store is fetched instead of built (measured: 4.8 s against 53 s for a template with `apt-get install`). Blobs hold only the data parts of sparse files, and downloads use parallel range requests and check SHA-256. `--build-cache-gib` caps local build disk: idle builds that are in the store are removed locally (least recently used first, after 10 minutes idle) and fetched again on use. Store objects that no host has refreshed for 7 days are deleted. Each template is built on one host and fetched by the others (create-only claim objects, taken over after 3 minutes; measured: a second host fetched in 1.2 s, and a host killed mid-build was replaced 3 minutes later). A joining worker queues templates most-used first, and with a full cache leaves builds in the store until first use. On a Firecracker host, a create from a build that is only in the store downloads the disks, then starts with UFFD while the memory loads (measured with the store limited to 20 MB/s: 1.34 s against 38 s for a full fetch).
- [x] Multi-node with one SQLite primary: workers join with a one-time token and mTLS, send heartbeats with capacity and their full sandbox list every 5 s, sync tenants, keys, templates and held secrets from the primary, and send back events (stored once each) and hourly usage (merged by maximum). The primary places each sandbox on itself or a worker (warm VM, free memory, tenant spread), forwards API calls, terminals and previews, and exposes `GET/DELETE /v1/nodes` and `POST /v1/nodes/tokens`. Sandboxes show their `node`. Tested on two EC2 hosts: placement on both, exec, files, PTY, pause and resume, previews, secrets, a network partition, a worker crash, and removing and rejoining a node. Postgres is not done yet.
- [x] `spawn-edge` as `spawn-api edge`: joins with a token, polls a routes table each second, sends data calls and previews straight to the sandbox's host and other calls to the primary. Tested on two EC2 hosts: exec, files, PTY and previews on worker and primary sandboxes, data calls while the primary was stopped, mTLS and header checks, and removal (`403` within 5 s).
- [x] Drain and migration: `POST /v1/nodes/{id}:drain` (optional `{"migrate":true}`) and `:undrain`, and `POST /v1/sandboxes/{id}:migrate` (optional target node). The primary pauses the sandbox on the source, streams a checksummed zstd package (memory, state, upper and layer disks; not the base rootfs) to the target, which adopts and resumes it; then routing moves and the source copy is released. Calls for a moving sandbox wait. Hosts must share a fingerprint (kernel, base rootfs, Firecracker, egress CA) and CPU model, so workers use the primary's egress CA. Tested on two EC2 hosts: moves both ways in 3 to 7 s with files, processes, previews and secrets intact, paused moves, a full drain, and a worker killed mid-transfer (the sandbox resumed on its source). Draining the primary and live migration are not supported.
- [x] Autoscaling hook: `--autoscale-hook` runs a program or calls a signed webhook to add a worker (with a join token) when fleet load stays high and to remove one after draining it when load stays low, within min and max bounds, one change at a time. `GET /v1/nodes/autoscale` shows state and recent requests. Tested with unit tests and a real hook program; not yet tested against a live cloud. Built-in AWS and GCP providers are not built.
- [x] gVisor fallback: `--backend auto|firecracker|gvisor` (auto picks Firecracker when `/dev/kvm` opens). Under gVisor each sandbox is a `runsc` container (systrap, no KVM) on the same base disk and template layer, with gVisor's own overlay as the writable layer; the agent listens on TCP 1024 on a private veth link (peer-checked) instead of vsock, and runsc gets an inner network namespace behind the usual firewall namespace. Builds, pause and resume use `runsc checkpoint`/`restore`; warm pools use `runsc pause`. The fingerprint covers the backend, so builds and moves never mix backends. Tenants get `isolation: any | microvm-only`; the primary places `microvm-only` tenants only on Firecracker hosts. Tested on EC2: the full M1 smoke test passes on gVisor; pause 23 to 56 ms, resume 73 to 157 ms; moves between two gVisor hosts in 0.2 s (running) and 17 ms (paused).
- [x] Fork and snapshot: `POST /v1/sandboxes/{id}:fork` (`count` 1 to 16) starts copies on the source's host with its memory, processes, files, labels, env, secrets, egress and remaining timeout; `POST /v1/sandboxes/{id}:snapshot` saves it as a tenant template that is never rebuilt and moves between hosts only through the build store. The source runs on; each copy gets a new identity. Through the primary, quota is reserved per copy and the template is synced to every host. Tested on two EC2 hosts: 10 copies in 0.6 to 0.7 s, a snapshot in about 0.4 s, distinct entropy per copy. Cross-node fork, gVisor live tests and sandboxes with volumes are not done.

### What each later phase must ship

| Phase | Must ship | Can slip to next phase |
| --- | --- | --- |
| M1 | Single-node API, templates and builds, exec, files, PTY, git clone, secrets proxy (HTTPS), egress policy, ports, TS SDK, CLI, MCP, installer | SSH agent bridge, dependency snapshots |
| M2 | Tenants, quotas, usage API, events with step IDs, OTLP export, `GET /v1/events` | Output stored in object store |
| M3 | Multi-node scheduler, `spawn-edge`, warm pools, build cache, drain and migration, gVisor fallback, Python SDK, E2B compat core | Built-in cloud autoscalers |
| M4 | Docs, `spawnbox doctor`, benchmark post, pen test, integrations in 2 agent frameworks, open-source public launch |  |

## Risks and open questions

The biggest product risk is building a broad sandbox platform that teams do not keep using. The self-hosting, multi-tenant and observability benefits must be tested with real users, not assumed from launch attention.

### Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Crowded market (E2B, Daytona, InstaBox, CubeSandbox, microsandbox and more) | Hard to get noticed | Sharp positioning for platforms. Integrations into agent frameworks before launch. |
| Interest without repeat use | Stars and demos do not prove the project solves a real problem | Work with independent teams on real workloads and track repeat use and install friction. |
| A VM escape or secret leak | Trust gone overnight | Firecracker plus jailer, fast patching, external pen test, security tests in CI. |
| One maintainer carrying development and support | Burnout, slow fixes | Keep the supported setup narrow at first, document operations, and make contributions easier. Users operate their own fleets; no hosted on-call commitment. |
| Snapshot incompatibility across CPUs and versions | Restores fail after upgrades | CPU fingerprints in manifests. Automatic rebuilds before version switches. |
| E2B compatibility drifts | Switching promise breaks | Compat suite in CI. Public gap table. |
| Employment agreement (IP and side-project clauses) | Legal risk to the project | Review before any public code. |

### Open questions

- [ ] E2B compat: what exact wire protocol does its SDK use for the in-sandbox agent, and do its license terms allow a compatible server?
- [x] Rust or TypeScript for `spawn-api`? Rust, like the rest of the server side. TypeScript stays for the SDK and MCP.
- [ ] Which object store and Postgres to bundle in single-node mode: MinIO and Postgres 16, or lighter options? Single-node M1 uses SQLite for now; this is still open for multi-node.
- [x] Guest-side overlay vs host-side device mapper for the upper disk: guest-side overlay. In M0, copying a sparse 20 GiB upper disk took 2.6 ms p50 on ext4.
- [x] Default egress policy: `allow_all` with every connection logged. Operators can narrow it with a server flag.
- [ ] Where step IDs come from when a harness does not send them: leave null, or infer from exec boundaries?
- [ ] License for the guest kernel config and base images: Apache-2.0 like the rest, or separate?
