# Persistent volumes

Status: done.

## Goal

Files that outlive a sandbox. A tenant creates a named volume, attaches it
to a new sandbox at a path, deletes the sandbox, and attaches the same
volume to a later sandbox with the files intact. Volumes stay on local
disks: no object store in this step.

## Decisions

- A volume is an ext4 disk image file on one host:
  `<data>/volumes/<vol_id>.ext4`, sparse, `size_gib` logical size. The
  host makes it on first use; the root directory belongs to `user` (uid
  1000).
- Up to 4 volumes per sandbox, each at an absolute path the caller picks.
  Paths may not overlap or sit under `/proc`, `/sys`, `/dev`, `/run`,
  `/spawn` or be `/`.
- Attach only at create. The attachment lasts while the sandbox exists:
  running, paused or moving.
- One writer at a time. Read-only attachments may share a volume with
  each other, but not with a writer: a volume has either one read-write
  sandbox or any number of read-only ones. (A read-only guest that shares
  a block device with a writer would read a file system that changes
  under it.)
- A volume belongs to one backend, set when it is first used. A
  Firecracker guest writes the image's raw blocks, so the host never
  mounts it; a gVisor host loop-mounts it and only the host kernel writes
  it. So a Firecracker volume never goes to a gVisor host, and the other
  way round.
- Placement first: a sandbox with volumes goes to the host that holds
  them. Copy next: when that host has no room, is draining, or is not
  current for the template, and the volume is not attached, the primary
  copies it to the chosen host (sparse, zstd) and the volume's home moves.
  When the holding host is down, the create fails with
  `node_unreachable`.
- Delete is refused (409) while a sandbox uses the volume.
- Quota `volume_storage_gib`: the sum of a tenant's volume sizes. Usage
  counts each volume's full size as disk, keyed by volume ID, on the
  primary or a single server only.

## Design

### API

- `POST /v1/volumes` `{"name", "size_gib"}`; names are per tenant, like
  sandbox labels: `[a-z0-9-]{1,63}`. Default size 10 GiB, at most 1024.
- `GET /v1/volumes`, `GET /v1/volumes/{name}`, `DELETE /v1/volumes/{name}`.
  Org keys pass `?tenant=`. Scopes: reads need `sandboxes:read`, writes
  `sandboxes:write`.
- `POST /v1/sandboxes` takes
  `"volumes": [{"volume": "cache", "path": "/data", "read_only": false}]`.
  Sandbox views list them.
- A volume view has `id`, `name`, `tenant`, `size_gib`, `node`, `backend`,
  `created_at`, and `mounts` (`{sandbox, read_only}`).

### Storage and metadata

- Table `volumes (id, tenant, name, size_gib, node, backend, created_at,
  deleted_at)`. `node` NULL is this host; `backend` NULL until first use.
- Column `sandboxes.volumes`: JSON list of `{volume, name, path,
  read_only, size_gib}`. Mirrors carry it, so the primary sees every
  attachment in the fleet.
- Live attachments: rows of sandboxes not ended. The home host checks
  the one-writer rule in the transaction that inserts the sandbox; every
  user of a volume runs on its home, so that check is enough.

### Firecracker

- Templates get 8 placeholder drives: `vol0`..`vol3` read-write and
  `ro0`..`ro3` read-only, each a 1 MiB sparse file in the jail.
- After a restore (cold or warm), the host links the volume into the jail
  as `volume<i>.ext4` (or `rovolume<i>.ext4`) and sends
  `PATCH /drives/{id}` with the new path. Firecracker swaps the backing
  file and the guest kernel sees the new size (tested on 1.17: capacity
  2048 -> 4194304 sectors).
- A pause snapshot records the patched path. Resume links the same
  names before the snapshot loads.
- Drive order is fixed, because Firecracker's virtio serial is not the
  drive ID: `vda` rootfs, `vdb` upper, `vdc`–`vdf` vol0–3, `vdg`–`vdj`
  ro0–3, `vdk` layer.
- Before stop and before pause, the guest runs `sync`. A Firecracker kill
  drops the guest page cache, so the last writes would be lost.

### gVisor

- The base image has mount points `/spawn/vol/0`..`/spawn/vol/3`. Every
  container's OCI config binds `<bundle>/vol<i>` there, also in template
  builds, so restores match the checkpoint.
- Before a container starts, the host loop-mounts each volume on
  `<bundle>/vol<i>` (`ro,noload` for read-only). An unattached slot stays
  an empty directory. Restore with a new bind source works (tested).
- Warm containers cannot take a volume: creates with volumes start cold.

### Guest

- New service `Volumes.Mount` (protocol 0.5). For each volume: index,
  path, read-only, size. Firecracker: waits for the device to reach the
  size, then mounts ext4 at the path. gVisor: bind-mounts
  `/spawn/vol/<i>` at the path.

### Fleet

- The primary has a volume `RwLock`. A create whose placed volumes share
  one home, with none new, takes the read lock and may go only to that
  home. It checks this again under the lock and takes the write lock if
  a copy changed it. Anything else (new volumes, volumes on several
  hosts, moves, drain, volume delete) takes the write lock.
- Under the write lock: candidates must have the volumes' backend and are
  scored +1000 per GiB already there. Each placed volume not on the
  chosen host is copied there first; a copy of a volume in use is
  refused with 409.
- Before forwarding, it pushes the volume rows to the worker
  (`/fleet/v1/volumes/put`), as it does secrets. After the create, new
  volumes get the worker as home (also when the reply was lost, because
  the sandbox may exist), and the mirror row lists the mounts.
- Copy: `/fleet/v1/volumes/export` on the source streams a one-file
  package (the migration format) to the primary, which streams it to
  `/fleet/v1/volumes/import` on the target. Then the source drops its
  file (`/fleet/v1/volumes/drop`) and the home changes. If the source
  refuses because a sandbox there uses it, the new copy is removed and
  the copy fails with 409.
- Sandbox migration takes the volumes along, only when no other sandbox
  uses them. The package carries `vol<slot>.ext4` files.
- Drain copies the unused volumes of the node to the host with the same
  backend and the most free memory, after its sandboxes move.
- Volume delete removes the file on its home (`drop` with `deleted`).

### Fingerprint

A build-format number joins the template fingerprint, so old builds
(without volume slots) are rebuilt.

## Out of scope

Object-store backing, snapshots of volumes, resize, attach after create,
shared writers, volume upload/download without a sandbox.

## Tests

- Unit: validation, attachment rules, DB queries, package round trip.
- Firecracker and gVisor on the worker: write, delete, reattach, read;
  read-only refuses writes; pause/resume with a volume; restart while
  paused.
- Two hosts: affinity, copy when the home is full or draining, migration
  with a volume, refusal when the home is down.
