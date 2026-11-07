#!/usr/bin/env bash
# Downloads a pinned Firecracker release (firecracker and jailer) into a
# directory and checks its SHA-256 sum.
set -euo pipefail

FIRECRACKER_VERSION="v1.17.0"

dest="${1:?usage: fetch-firecracker.sh <dest-dir>}"
mkdir -p "$dest"
cd "$dest"

if [[ ! -x firecracker ]]; then
  base="https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}"
  tarball="firecracker-${FIRECRACKER_VERSION}-x86_64.tgz"
  curl -fsSLO "${base}/${tarball}"
  curl -fsSLO "${base}/${tarball}.sha256.txt"
  sha256sum -c "${tarball}.sha256.txt"
  tar -xzf "$tarball"
  release="release-${FIRECRACKER_VERSION}-x86_64"
  install -m 0755 "${release}/firecracker-${FIRECRACKER_VERSION}-x86_64" firecracker
  install -m 0755 "${release}/jailer-${FIRECRACKER_VERSION}-x86_64" jailer
  rm -rf "$tarball" "${tarball}.sha256.txt" "$release"
fi

./firecracker --version | head -1
