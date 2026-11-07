# OCI and devcontainer template bases

Status: done.

## Goal

A template may start from an OCI image instead of the Debian base disk:

```json
{ "name": "node22", "base": "docker.io/library/node:22-bookworm-slim",
  "registry_secrets": ["ghcr"], "setup": ["npm i -g pnpm"] }
```

The CLI also turns an image-based `devcontainer.json` into such a
template. Both backends are supported.

## Pipeline

1. The host makes a blank, sparse ext4 disk (`image.ext4`, 32 GiB).
2. A builder VM boots from the shared Debian base, with the blank disk
   mounted at `/spawn/image`. Its network follows the tenant's egress
   policy and carries the template's `registry_secrets`. Only this stage
   gets secrets; setup steps still get none.
3. The guest agent's new `Image.Unpack` RPC pulls the image for
   `linux/amd64` with `oci-client` and checks each layer's SHA-256. It
   applies the layers in order, with whiteouts and opaque directories,
   through `tar`'s `unpack_in`, which refuses paths outside the disk.
   The host never parses the image.
4. The agent makes the tree bootable:
   - copies itself to `/usr/local/bin/spawn-guest`;
   - makes `/spawn/*`, `/workspace`, `/proc`, `/sys`, `/dev`, `/tmp`;
   - adds `user` (UID and GID 1000) if missing;
   - writes the image's `Env` to `/etc/profile.d/00-spawnbox-image.sh`.
   It fails if the image has no `/bin/sh`.
5. The disk becomes the build's own `rootfs.ext4`. Setup, warmup and the
   snapshot run as before, on that disk.

## Changes

- `spawn-proto`: `Image.Unpack(UnpackRequest) returns (stream UnpackEvent)`
  (log lines, then the image digest).
- `spawn-guest`:
  - `unpack.rs`.
  - Commands use `/bin/bash` if the image has it, else `/bin/sh`.
- `spawn-node`:
  - `Build.own_rootfs`: the rootfs is uploaded, fetched and kept like the
    snapshot files, and not linked from the shared base.
  - Fresh boots take volumes.
  - `Node::unpack_image`.
  - `trust_ca` also works without `update-ca-certificates`.
- `spawn-api`:
  - `TemplateSpec.base`, `TemplateSpec.registry_secrets`.
  - The build runs the unpack stage with secrets attached, then the normal
    build.
  - A snapshot of an image sandbox keeps the image rootfs.
  - Migration sends `rootfs.ext4` when it is not the shared base.
- CLI: `spawnbox templates build --devcontainer <file> --name <n>`.
  - Reads JSONC.
  - Maps `image` to `base`, `containerEnv` and `remoteEnv` to `env`, and
    `onCreateCommand`, `updateContentCommand` and `postCreateCommand` to
    `setup`.
  - Ignores `remoteUser` and `workspaceFolder`: commands run as `user`
    (UID 1000) in `/workspace`.
  - Refuses `build`, `dockerFile`, `features` and `dockerComposeFile`.

## Limits

- `linux/amd64` images only.
- Image `Entrypoint`, `Cmd`, `User` and `WorkingDir` are ignored.
- A tag is read at build time. Use a digest to pin it.

## Tests

- Unit:
  - Whiteouts and opaque directories.
  - Path escape refused.
  - devcontainer mapping.
- Live, both backends:
  - `node:22-bookworm-slim` and `alpine:3`: build, create, exec, image env.
  - Private image through a held secret: not tested live. The egress
    proxy trusts only public CAs, so a local registry cannot be used.
  - Snapshot and migrate a sandbox from an image template.

## Results

- Firecracker: `node:22-bookworm-slim` ready in 24 s, `alpine:3` in 15 s;
  create 70 ms. DNS, HTTPS (Node `fetch`, BusyBox `wget`) and the image
  env work.
- gVisor: both images ready in 12 s. Owners (root files, `user` home and
  `/workspace`) and HTTPS are correct.
- Snapshot, create from the snapshot, fork and migration (Firecracker:
  worker to primary in 2.7 s; gVisor: primary to worker in 0.5 s) keep
  the image disk.
- CLI: `python:3.13-slim` devcontainer with comments, a trailing comma,
  env and two commands: ready in 34 s.
- Fixed during tests: images without `/etc/resolv.conf` had no DNS.
