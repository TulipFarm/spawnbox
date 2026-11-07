#!/usr/bin/env bash
# Runs the M0 check end to end on a Linux KVM host: builds the guest agent,
# guest kernel and base disk, fetches Firecracker, and runs spawn-bench.
# spawn-bench runs with sudo: it creates jails, cgroups, network namespaces
# and firewall rules, and removes them when it finishes.
set -euo pipefail

work="${1:-$HOME/.cache/spawnbox/m0}"
artifacts="${SPAWNBOX_ARTIFACTS:-$HOME/.cache/spawnbox/artifacts}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

scripts/build-artifacts.sh "$artifacts"
cargo build --release --locked -p spawn-bench

sudo target/release/spawn-bench m0 \
  --firecracker "$artifacts/bin/firecracker" \
  --jailer "$artifacts/bin/jailer" \
  --kernel "$artifacts/vmlinux" \
  --rootfs "$artifacts/rootfs.ext4" \
  --work-dir "$work/run" \
  "${@:2}"
