#!/usr/bin/env bash
# Downloads a pinned gVisor release (runsc and its gvisor-bin helpers) into
# a directory and checks its SHA-512 sum. Hosts without KVM run sandboxes
# with it.
set -euo pipefail

GVISOR_VERSION="20261102.0"
GVISOR_SHA512="3c400f72be459b57b99b1c4f69be96bcd67eef3caf2078e595fc98e688b6b9a3af7802646b3dde7da8a9aba96d34f86be303e0430c7868ab2d13becdd403c0c1"

dest="${1:?usage: fetch-gvisor.sh <dest-dir>}"
mkdir -p "$dest"
cd "$dest"

if [[ ! -x runsc ]] || ! ./runsc --version | grep -qF "release-${GVISOR_VERSION}"; then
  tarball="gvisor.tar.zstd"
  curl -fsSLO "https://storage.googleapis.com/gvisor/releases/release/${GVISOR_VERSION}/x86_64/${tarball}"
  echo "${GVISOR_SHA512}  ${tarball}" | sha512sum -c --quiet
  rm -rf gvisor-bin runsc
  tar --zstd -xf "$tarball" runsc gvisor-bin
  chmod 0755 runsc
  rm -f "$tarball"
fi

./runsc --version | head -1
