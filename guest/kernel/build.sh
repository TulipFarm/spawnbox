#!/usr/bin/env bash
# Builds the Spawnbox guest kernel (an uncompressed vmlinux for Firecracker).
# Needs Linux with: build-essential bc bison flex libelf-dev libssl-dev.
set -euo pipefail

KERNEL_VERSION="6.18.60"
KERNEL_SHA256="3c2f44ef6acc021a7ad444d9a2e6ec1ef488ff09368793d0004a6080f69d621e"
# Firecracker's tested guest config for this kernel line, pinned by release tag.
BASE_CONFIG_URL="https://raw.githubusercontent.com/firecracker-microvm/firecracker/v1.17.0/resources/guest_configs/microvm-kernel-ci-x86_64-6.18.config"
BASE_CONFIG_SHA256="ba22401a0c7292a4c024ebcd10a562d4a1f1bfd2faed671406d3b159c0cf5215"

# Options Spawnbox relies on. The build fails if any is missing.
REQUIRED=(
  VIRTIO_NET VIRTIO_BLK VIRTIO_VSOCKETS EXT4_FS TMPFS DEVTMPFS OVERLAY_FS
  CGROUPS MEMCG CGROUP_PIDS NAMESPACES USER_NS NET_NS PID_NS
  VETH BRIDGE NF_TABLES NFT_MASQ BRIDGE_NETFILTER
  SECCOMP SECCOMP_FILTER FUSE_FS VMGENID VIRTIO_BALLOON PAGE_REPORTING IP_PNP
)

out="${1:?usage: build.sh <out-vmlinux> [work-dir]}"
work="${2:-$HOME/.cache/spawnbox/kernel}"
here="$(cd "$(dirname "$0")" && pwd)"
out="$(realpath -m "$out")"
mkdir -p "$work"
cd "$work"

tarball="linux-${KERNEL_VERSION}.tar.xz"
if [[ ! -f "$tarball" ]]; then
  curl -fsSL -o "$tarball.part" "https://cdn.kernel.org/pub/linux/kernel/v6.x/${tarball}"
  echo "${KERNEL_SHA256}  $tarball.part" | sha256sum -c -
  mv "$tarball.part" "$tarball"
fi
curl -fsSL -o base.config "$BASE_CONFIG_URL"
echo "${BASE_CONFIG_SHA256}  base.config" | sha256sum -c -

src="linux-${KERNEL_VERSION}"
rm -rf "$src"
tar -xf "$tarball"
cd "$src"
cp ../base.config .config
scripts/kconfig/merge_config.sh -m .config "$here/spawnbox.config" >/dev/null
make -s olddefconfig

missing=()
for option in "${REQUIRED[@]}"; do
  grep -q "^CONFIG_${option}=y" .config || missing+=("$option")
done
if (( ${#missing[@]} )); then
  echo "kernel config is missing: ${missing[*]}" >&2
  exit 1
fi

make -s -j"$(nproc)" vmlinux
install -D -m 0644 vmlinux "$out"
echo "built $out (Linux ${KERNEL_VERSION})"
