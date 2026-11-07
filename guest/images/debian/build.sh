#!/usr/bin/env bash
# Builds a minimal Debian 13 ext4 root disk with spawn-guest as PID 1.
# Needs Linux, sudo, debootstrap, and e2fsprogs.
set -euo pipefail

SUITE="trixie"
MIRROR="https://deb.debian.org/debian"
PACKAGES="bash,ca-certificates,coreutils,curl,git,iproute2,openssh-client,procps,sudo"

guest_bin="${1:?usage: build.sh <spawn-guest-binary> <out.ext4>}"
out="${2:?usage: build.sh <spawn-guest-binary> <out.ext4>}"

root="$(mktemp -d)"
trap 'sudo rm -rf "$root"' EXIT

sudo debootstrap --variant=minbase --include="$PACKAGES" "$SUITE" "$root" "$MIRROR"
sudo install -D -m 0755 "$guest_bin" "$root/usr/local/bin/spawn-guest"
echo "spawnbox" | sudo tee "$root/etc/hostname" >/dev/null

# Commands run as `user` (uid 1000), who may use sudo without a password.
sudo chroot "$root" useradd --create-home --uid 1000 --shell /bin/bash user
echo "user ALL=(ALL) NOPASSWD:ALL" | sudo tee "$root/etc/sudoers.d/user" >/dev/null
sudo chmod 0440 "$root/etc/sudoers.d/user"
sudo install -d -o 1000 -g 1000 "$root/workspace"

# Mount points for the overlay root that spawn-guest builds at boot.
sudo install -d "$root/spawn/upper" "$root/spawn/layer" "$root/spawn/newroot" "$root/spawn/oldroot" \
  "$root/spawn/vol/0" "$root/spawn/vol/1" "$root/spawn/vol/2" "$root/spawn/vol/3"

# The host forwards DNS sent to the gateway. IPv6 is off in the guest.
echo "nameserver 172.16.0.1" | sudo tee "$root/etc/resolv.conf" >/dev/null
printf '127.0.0.1 localhost\n' | sudo tee "$root/etc/hosts" >/dev/null
sudo rm -rf "$root"/var/cache/apt/archives/*.deb "$root"/var/lib/apt/lists/*

# 25% headroom plus 64 MiB for ext4 metadata.
used_mib="$(sudo du -sm "$root" | cut -f1)"
size_mib=$(( used_mib * 5 / 4 + 64 ))
rm -f "$out"
sudo mkfs.ext4 -q -F -L spawnbox-root -d "$root" "$out" "${size_mib}M"
sudo chown "$(id -u):$(id -g)" "$out"
echo "built $out (${size_mib} MiB)"
