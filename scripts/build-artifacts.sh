#!/usr/bin/env bash
# Builds what a Linux host needs to run sandboxes, into <dir>:
#   bin/firecracker, bin/jailer  pinned Firecracker release
#   bin/runsc, bin/gvisor-bin/   pinned gVisor release, for hosts without KVM
#   vmlinux                      guest kernel
#   rootfs.ext4                  Debian base disk with spawn-guest
# Each part is rebuilt only when its inputs changed.
set -euo pipefail

out="${1:?usage: build-artifacts.sh <dir>}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"
mkdir -p "$out"

for tool in debootstrap mkfs.ext4 ip nft; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

guest_target="x86_64-unknown-linux-musl"
cargo build --release --locked -p spawn-guest --target "$guest_target"

scripts/fetch-firecracker.sh "$out/bin"
scripts/fetch-gvisor.sh "$out/bin"

kernel="$out/vmlinux"
if [[ ! -f "$kernel" || guest/kernel/build.sh -nt "$kernel" || guest/kernel/spawnbox.config -nt "$kernel" ]]; then
  guest/kernel/build.sh "$kernel"
fi

guest_bin="target/${guest_target}/release/spawn-guest"
rootfs="$out/rootfs.ext4"
if [[ ! -f "$rootfs" || "$guest_bin" -nt "$rootfs" || guest/images/debian/build.sh -nt "$rootfs" ]]; then
  guest/images/debian/build.sh "$guest_bin" "$rootfs"
fi
