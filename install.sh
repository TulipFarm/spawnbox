#!/bin/sh
# Downloads Spawnbox and runs deploy/install.sh. Usage:
#
#   curl -fsSL https://raw.githubusercontent.com/TulipFarm/spawnbox/main/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --uninstall
#
# Run it again to upgrade. Settings:
#   SPAWNBOX_DIR   where the code goes (default ~/spawnbox)
#   SPAWNBOX_REF   branch or tag (default main)
#   SPAWNBOX_REPO  Git URL (default the GitHub repository)
set -eu

# Everything is in main, so a partial download runs nothing.
main() {
  repo="${SPAWNBOX_REPO:-https://github.com/TulipFarm/spawnbox.git}"
  ref="${SPAWNBOX_REF:-main}"
  dir="${SPAWNBOX_DIR:-$HOME/spawnbox}"
  sudo=""
  [ "$(id -u)" -eq 0 ] || sudo=sudo

  if ! command -v git >/dev/null 2>&1; then
    command -v apt-get >/dev/null 2>&1 || { echo "error: only Debian and Ubuntu are supported" >&2; exit 1; }
    echo "==> installing git"
    $sudo apt-get update -qq
    $sudo env DEBIAN_FRONTEND=noninteractive apt-get install -yqq git >/dev/null
  fi

  if [ -d "$dir/.git" ]; then
    echo "==> updating $dir to $ref"
    git -C "$dir" fetch -q --depth 1 origin "$ref"
    git -C "$dir" checkout -q --force FETCH_HEAD
  elif [ -e "$dir" ]; then
    echo "error: $dir exists and is not a Git checkout; set SPAWNBOX_DIR" >&2
    exit 1
  else
    echo "==> downloading Spawnbox ($ref) into $dir"
    git clone -q --depth 1 --branch "$ref" "$repo" "$dir"
  fi

  exec "$dir/deploy/install.sh" "$@" </dev/null
}

main "$@"
