# Build prefetch

Status: done.

## Goal

With a build store, each template is built once in the fleet and fetched
by the other hosts. A host that joins gets the most-used templates first.
With a cache limit, it gets only what fits and leaves the rest in the
store until first use.

Without a build store nothing changes: every host builds every template.

## Build once

- Before a host builds, it writes a claim object `claims/<key>` to the
  store with a create-only put (`If-None-Match: *` on S3). The key already
  covers the build inputs, CPU model, spec and egress policy, so only hosts
  that can share a build compete for the same claim.
- The host that gets the claim builds, uploads, then deletes the claim.
  While it builds and uploads, it writes the claim again every 30 s.
- A host that finds a claim waits without a build slot or permit. Every
  5 s it looks for the manifest (then it fetches) and for the claim. A
  missing claim, or one not written for 3 min, means the builder is gone:
  the host deletes it and claims again.
- A failed build deletes its claim. The waiting host then builds and most
  likely fails the same way, as each host does today.
- A store without create-only puts: every host builds, as today, with one
  warning.
- With a claim, the upload runs before the build permit is released, so
  the claim is not deleted before the manifest exists.
- `collect` deletes claims older than the store's maximum age.
- Snapshot templates never build, so they never claim.

## Join order

- `TemplateCopy` gets `uses`: sandboxes created from the template in the
  last 7 days, counted on the primary by tenant and name.
- A worker syncs templates with the most uses first. Builds queue in that
  order, and the build permits are taken in order.

## Cache limit on join

- With `--build-cache-gib`, a host whose builds directory is already at
  the limit does not download a build that the store has. It records the
  build as ready and only in the store, like a build that `trim` removed.
  The first sandbox fetches it.

## Tests

- Unit: claim create, held, stale take-over, and release on a `file://`
  store.
- Live, two EC2 hosts and SeaweedFS S3 on the primary:
  - A new template: one host builds, the other logs that it waits and
    then fetches.
  - Kill the builder mid-build: the other host takes over after 3 min.
  - A worker with many templates and a small cache: the most-used are
    local, the rest are fetched on first use.

## Results

Live, two EC2 hosts, SeaweedFS 4.52 S3 on the primary (it answers a
second `If-None-Match: *` put with 412):

- New template: the primary built it in 10.8 s; the worker logged that it
  waited, then fetched it in 1.2 s.
- Builder killed (`SIGKILL`) 20 s into a 90 s build: the worker took the
  claim exactly 3 min after the last write and built it. The restarted
  primary queued its interrupted build again and fetched it in 1.1 s.
- Worker with `--build-cache-gib 1` (4.6 GiB used): a new template was
  recorded as ready and left in the store. The first sandbox on the
  worker fetched it in 1.2 s and saw the template's file.
- Join order: checked only the usage counts the primary sends. A fresh
  join was not repeated, because it needs a new worker identity.
