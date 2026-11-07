# UFFD lazy memory loading

Status: done.

## Goal

A host that does not have a build locally can start a Firecracker sandbox
from the build store before the memory file is fully downloaded. Memory
pages come in when the guest touches them.

## Decisions

- Only the create path of a cold host uses it: the build is in the store
  but its files are not local. Local builds keep the `File` memory backend.
  Warm pools and other callers wait for the full files.
- If a needed page cannot be fetched for 30 s, the sandbox is stopped,
  marked `failed`, and a `sandbox.lost` event is recorded.
- The build records the order in which a test restore touches memory (the
  hot list). A cold host fetches those parts first, then the rest in order.
  A guest fault moves its part to the front.
- gVisor is not changed.

## Store format

- Manifest version 2. All store keys change, so builds are uploaded again.
- `vm.mem` is no longer a blob. It is a paged object
  `pages/<sha256 of the index>.sbxp`:
  - Header: `SBXPAGE1`, the file size (u64), the part size (u32, 2 MiB),
    the part count (u32).
  - Index: for each part, the start of its zstd frame in the object (u64),
    the frame length (u64, 0 for an all-zero part) and the SHA-256 of the
    uncompressed part.
  - The frames.
- The manifest has `pages: {name, object, size, hot}`. `hot` is the list of
  part numbers in first-touch order. It can be empty.
- A full download reads the paged object too, in parallel.

## Host

- `spawn-node`:
  - `uffd.rs`: a page handler on its own thread for one VM. It binds
    `uffd.sock` in the jail before `PUT /snapshot/load` with
    `backend_type: Uffd`, receives the userfaultfd and the memory regions,
    and serves faults. For a fault, it waits until the part is in the local
    file, then copies the part (cut to the region) with `UFFDIO_COPY`.
    `UFFD_EVENT_REMOVE` ranges are served with zero pages afterwards.
  - A failure kills Firecracker (the jailer execs it, so it has the child
    PID) and is reported on a channel. The thread stops when the VM stops.
    If it waits for a part, it can stay up to 30 s more.
  - It records the parts it copied for faults, in order.
  - `Node::restore_lazy` restores with a `PageSource`. `Vm::take_lost`
    gives the channel that reports a failure.
  - Build: when the recipe asks for it, after the snapshot a test restore
    with the handler reads the local `vm.mem`, waits for the guest agent,
    runs `true`, and writes the hot list to `vm.mem.hot`.
- `spawn-api`:
  - `pages.rs`: `LazyMem`, a `PageSource` that downloads parts into a
    sparse `vm.mem.part`: requested parts first, then the hot list, then
    the rest, 8 at a time. Each part is checked against its SHA-256. At the
    end, `vm.mem.part` becomes `vm.mem`, and the build is local.
  - `Templates::ensure_startable`: local, or a `LazyMem` after the other
    files are downloaded. One `LazyMem` per build is shared.
  - The create path watches `lost` and stops a failed sandbox.

## Limits

- A lazily loaded VM's pages are private memory, not shared page cache.
- Pausing, forking or snapshotting such a VM first loads all of its memory.
- Disks are still downloaded in full before the start.
- Firecracker only. A gVisor host downloads the full build.

## Tests

- Unit: paged object round trip (full download, parts, all-zero parts),
  and a changed part or index refused.
- Live, two hosts with a `file://` store on shared storage or S3:
  - Cold create time against a full fetch.
  - Exec, files, pause and resume, fork of a lazily loaded sandbox.
  - Store made unreachable during the load: the sandbox fails after 30 s
    with `sandbox.lost`.

## Results

Live, two EC2 hosts, SeaweedFS 4.52 S3 on the primary. Traffic from the
store to the worker was limited to 160 Mbit/s (20 MB/s). The worker had
`--build-cache-gib 1`, so new builds stayed in the store. Templates wrote
400 MB of random data to `/dev/shm` in `warmup`, so it is in the memory
file.

- Hot list: a 1 GiB VM touched 45 of 512 parts (90 MiB) to start and run
  `true`.
- Full fetch of a build on the worker: 38 s and 43 s.
- Lazy create on the worker: 1.34 s. The first exec took 0.04 s. Reading
  the 400 MB file took 19.9 s while its parts came in. All memory was
  local after 29.4 s. The file's MD5 was the same as on the primary.
- On the lazily loaded sandbox: pause 0.58 s, resume 0.07 s, fork
  0.61 s. The fork read the same MD5.
- Store blocked (`iptables DROP`) right after a lazy create: an exec that
  read the file failed after 30.0 s. The sandbox was `failed` 2 s later,
  with `sandbox.lost` and reason `memory pages could not be fetched`.
  After the store was back, the same build finished loading, and the
  next sandbox from it worked.
- `create_seconds` in the metrics shows `path="lazy"` for these creates.
