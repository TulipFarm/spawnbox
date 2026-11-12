#!/usr/bin/env bash
# Builds a minimal Debian 13 ext4 root disk with Node.js, Python and spawn-guest as PID 1.
# Needs Linux, sudo, debootstrap, and e2fsprogs.
set -euo pipefail

SUITE="trixie"
MIRROR="https://deb.debian.org/debian"
PACKAGES="bash,ca-certificates,coreutils,curl,git,iproute2,libatomic1,openssh-client,procps,sudo"

# Node.js and Python go in /usr/local. Python comes from python-build-standalone, as python.org has no Linux builds.
NODE_VERSION="26.13.1"
NODE_SHA256="5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864"
PYTHON_VERSION="3.15.2"
PYTHON_BUILD="20261110"
PYTHON_SHA256="ad23d1b73fac26440b0306ae06911031344c49a90ec19716c8362e7fa40cae43"

guest_bin="${1:?usage: build.sh <spawn-guest-binary> <out.ext4>}"
out="${2:?usage: build.sh <spawn-guest-binary> <out.ext4>}"

root="$(mktemp -d)"
downloads="$(mktemp -d)"
trap 'sudo rm -rf "$root" "$downloads"' EXIT

# fetch <url> <sha256> <file>
fetch() {
  curl -fsSL --retry 3 -o "$downloads/$3" "$1"
  echo "$2  $downloads/$3" | sha256sum -c --quiet
}

sudo debootstrap --variant=minbase --include="$PACKAGES" "$SUITE" "$root" "$MIRROR"
sudo install -D -m 0755 "$guest_bin" "$root/usr/local/bin/spawn-guest"

fetch "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" "$NODE_SHA256" node.tar.xz
sudo tar -xJf "$downloads/node.tar.xz" -C "$root/usr/local" --strip-components=1 --no-same-owner \
  --exclude='*/CHANGELOG.md' --exclude='*/LICENSE' --exclude='*/README.md'

fetch "https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_BUILD}/cpython-${PYTHON_VERSION}+${PYTHON_BUILD}-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz" \
  "$PYTHON_SHA256" python.tar.gz
sudo tar -xzf "$downloads/python.tar.gz" -C "$root/usr/local" --strip-components=1 --no-same-owner
for link in python:python3 pip:pip3; do
  [[ -e "$root/usr/local/bin/${link%%:*}" ]] || sudo ln -s "${link#*:}" "$root/usr/local/bin/${link%%:*}"
done
sudo chroot "$root" node --version
sudo chroot "$root" python3 --version
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
