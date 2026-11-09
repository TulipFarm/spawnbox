#!/bin/sh
# Installs or upgrades Spawnbox on this host:
#
#   curl -fsSL https://spawnbox.tulipfarm.ai/install.sh | sh
#
# It downloads the latest release (built programs, kernel and base disk),
# checks its SHA-256 sum and runs its deploy/install.sh. Settings:
#   SPAWNBOX_VERSION      release tag, for example v0.1.0 (default latest)
#   SPAWNBOX_FROM_SOURCE  set to 1 to clone the code and compile it instead
#                         (about 30 minutes); then SPAWNBOX_REF picks the
#                         branch or tag (default main) and SPAWNBOX_DIR the
#                         directory (default ~/spawnbox)
# To remove Spawnbox: sudo /opt/spawnbox/install.sh --uninstall (or --purge).
set -eu

# Everything is in main, so a partial download runs nothing.
main() {
  github=https://github.com/TulipFarm/spawnbox
  sudo=""
  [ "$(id -u)" -eq 0 ] || sudo=sudo
  [ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || fail "Spawnbox needs Linux on x86_64"
  command -v apt-get >/dev/null 2>&1 || fail "only Debian and Ubuntu are supported"

  if [ "${SPAWNBOX_FROM_SOURCE:-}" = 1 ]; then
    from_source "$@"
  else
    from_release "$@"
  fi
}

from_release() {
  version="${SPAWNBOX_VERSION:-latest}"
  if [ "$version" = latest ]; then
    url="$github/releases/latest/download"
  else
    url="$github/releases/download/$version"
  fi
  need curl
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  echo "==> downloading Spawnbox ($version)"
  file=spawnbox-x86_64-linux.tar.gz
  curl -fsSL -o "$tmp/$file.sha256" "$url/$file.sha256" ||
    fail "no release found at $url; to build from source, set SPAWNBOX_FROM_SOURCE=1"
  curl -fL --progress-bar -o "$tmp/$file" "$url/$file"
  (cd "$tmp" && sha256sum -c --quiet "$file.sha256") || fail "the download does not match its SHA-256 sum"
  tar -xzf "$tmp/$file" -C "$tmp"
  rm -f "$tmp/$file"
  "$tmp/spawnbox/deploy/install.sh" "$@" </dev/null
}

from_source() {
  HOME="${HOME:-$(getent passwd "$(id -u)" | cut -d: -f6)}"
  dir="${SPAWNBOX_DIR:-$HOME/spawnbox}"
  ref="${SPAWNBOX_REF:-main}"
  need git
  if [ -d "$dir/.git" ]; then
    echo "==> updating $dir to $ref"
    git -C "$dir" fetch -q --depth 1 origin "$ref"
    git -C "$dir" checkout -q --force FETCH_HEAD
  elif [ -e "$dir" ]; then
    fail "$dir exists and is not a Git checkout; set SPAWNBOX_DIR"
  else
    echo "==> downloading the Spawnbox code ($ref) into $dir"
    git clone -q --depth 1 --branch "$ref" "$github.git" "$dir"
  fi
  exec "$dir/deploy/install.sh" "$@" </dev/null
}

need() {
  command -v "$1" >/dev/null 2>&1 && return
  echo "==> installing $1"
  $sudo apt-get update -qq
  $sudo env DEBIAN_FRONTEND=noninteractive apt-get install -yqq "$1" ca-certificates >/dev/null
}

fail() {
  echo "error: $*" >&2
  exit 1
}

main "$@"
