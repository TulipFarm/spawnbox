# Build store

Status: done. Tested on the KVM host against SeaweedFS (S3 API): upload of
`base` in 1.3 s and of a 1 GiB template in 4.2 s, a recreated template
fetched in 4.8 s instead of built in 53 s, fetch on first use after local
files were removed (5.1 s), LRU removal past `--build-cache-gib` followed by
on-demand fetches (1.1 s and 4.0 s), upload again of builds a wiped store
lost, and `scripts/cli-smoke.sh` and `scripts/m1-smoke.sh`. The fallback to
a rebuild when a fetch fails is covered by reading only, not by a test.

## Goal

Keep ready builds in any S3-compatible object store, so a host can fetch a
build instead of building it again, and cap the disk builds use locally.
This is the base for multi-node: another node fetches what one node built.

## Design

- Flags: `--build-store s3://bucket/prefix` (endpoint, region and
  credentials from `AWS_*` variables) or `file:///path`, and
  `--build-cache-gib` (0, the default, means no limit). Without a store,
  nothing changes.
- Layout: `builds/<key>.json` is a manifest of file names, SHA-256 and
  sizes. `blobs/<sha256>.zst` is one file, zstd-compressed. Equal files are
  stored once.
- Key: SHA-256 of the inputs fingerprint (kernel, base disk, Firecracker,
  egress CA), the host CPU model, the template spec and the egress policy
  the build runs under. Recorded per build as `store_key` when it starts.
- Blob format: only the data parts of a file (found with `SEEK_DATA` and
  `SEEK_HOLE`), as offset, length, bytes records. A 20 GiB disk with
  100 MiB of data costs about 100 MiB to read, hash and send, and is
  written back sparse.
- Upload: after a build is ready, in the background. The manifest goes
  last, so a build is only visible when complete. Failed uploads are tried
  again every minute.
- Fetch: a queued build first looks up its key. If found, it is downloaded
  (parallel 8 MiB ranges), checked, and published without a VM slot.
  Otherwise it is built as before.
- Local cache: past the limit, idle builds that are in the store lose
  their files, least recently used first. A build used in the last 10
  minutes, or held by a create or warm pool, is kept. The next create
  fetches it; if the fetch fails, the template is built again.
- Clean-up: once a day, each host rewrites the manifests of its current
  builds, then deletes manifests and unreferenced blobs older than 7 days.

## Not in this step

- Prefetch on node join and UFFD lazy memory: they need the scheduler.
- Sharing between hosts needs byte-identical inputs. Today
  `deploy/install.sh` builds the base disk on each host, and its hash can
  change between hosts and upgrades.
