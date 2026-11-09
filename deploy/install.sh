#!/usr/bin/env bash
# Installs Spawnbox on one Linux host, from a release bundle (made by
# .github/workflows/release.yml, with bin/ next to deploy/) or from a source
# checkout, which it compiles first.
#
#   deploy/install.sh              install, or upgrade an existing install
#   deploy/install.sh --uninstall  remove the service and binaries; keep
#                                  settings and data
#   deploy/install.sh --purge      also remove settings and data: the
#                                  database, templates and secrets
#
# Needs Ubuntu 22.04+ or Debian 12+ on x86_64, and root or sudo. With
# /dev/kvm, sandboxes are Firecracker microVMs; without it, gVisor
# containers. From source, run it as the user who owns the checkout: it
# builds there with that user's Rust toolchain, then installs with sudo.
#
# Layout:
#   /opt/spawnbox/                 spawn-api, the spawnbox CLI, Firecracker,
#                                  gVisor, kernel, base disk, this script
#   /usr/local/bin/spawnbox        link to the CLI
#   /etc/spawnbox/spawnbox.env     server flags (SPAWNBOX_ARGS); kept on upgrade
#   /var/lib/spawnbox/             database, templates, secrets key, logs
#   spawnbox.service               systemd unit
set -euo pipefail

prefix=/opt/spawnbox
config_dir=/etc/spawnbox
config="$config_dir/spawnbox.env"
data=/var/lib/spawnbox
unit=/etc/systemd/system/spawnbox.service
cli_link=/usr/local/bin/spawnbox
repo="$(cd "$(dirname "$0")/.." && pwd)"
artifacts="${SPAWNBOX_ARTIFACTS:-$HOME/.cache/spawnbox/artifacts}"
bundle=no
[[ -x "$repo/bin/spawn-api" ]] && bundle=yes

sudo=""
[[ $EUID -eq 0 ]] || sudo=sudo

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

stop_service() {
  if systemctl is-active --quiet spawnbox 2>/dev/null; then
    say "stopping spawnbox (running sandboxes are deleted)"
    $sudo systemctl stop spawnbox
  fi
}

uninstall() {
  local purge="$1"
  stop_service
  $sudo systemctl disable spawnbox >/dev/null 2>&1 || true
  $sudo rm -f "$unit"
  $sudo systemctl daemon-reload
  $sudo systemctl reset-failed spawnbox >/dev/null 2>&1 || true
  $sudo rm -rf "$prefix"
  [[ -L "$cli_link" ]] && $sudo rm -f "$cli_link"
  if [[ "$purge" == yes ]]; then
    $sudo rm -rf "$config_dir" "$data"
    echo "removed Spawnbox, its settings and its data"
  else
    echo "removed Spawnbox; kept $config_dir and $data (use --purge to remove them)"
  fi
}

case "${1:-}" in
  "") ;;
  --uninstall) uninstall no; exit 0 ;;
  --purge) uninstall yes; exit 0 ;;
  -h | --help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) die "unknown option $1 (see --help)" ;;
esac

say "checking this host"
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || die "Spawnbox needs Linux on x86_64"
command -v systemctl >/dev/null || die "systemd is required"
command -v apt-get >/dev/null || die "only Debian and Ubuntu are supported"
[[ $EUID -eq 0 ]] || $sudo true || die "needs root or sudo"
if [[ ! -c /dev/kvm ]]; then
  echo "note: /dev/kvm is missing, so sandboxes run in gVisor, with weaker"
  echo "isolation than microVMs. For microVMs, use bare metal or a VM with"
  echo "nested virtualization."
fi

[[ "$bundle" == yes || -f "$repo/Cargo.toml" ]] || die "run this from a release bundle or a source checkout"

if [[ "$bundle" == yes ]]; then
  say "installing the tools Spawnbox runs"
  $sudo apt-get update -qq
  $sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    e2fsprogs nftables iproute2 procps curl ca-certificates >/dev/null
  bins="$repo/bin"
  artifacts="$repo"
else
  say "installing build tools"
  $sudo apt-get update -qq
  $sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    build-essential bc bison flex libelf-dev libssl-dev pkg-config musl-tools \
    debootstrap e2fsprogs nftables iproute2 curl git ca-certificates xz-utils zstd >/dev/null

  if ! command -v rustup >/dev/null && [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
  fi
  if ! command -v rustup >/dev/null; then
    say "installing Rust with rustup"
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs |
      sh -s -- -y --profile minimal --default-toolchain none --no-modify-path
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
  fi

  say "building (the first build takes a while: it compiles a kernel)"
  cd "$repo"
  # rust-toolchain.toml pins the toolchain; rustup installs it on first use.
  cargo build --release --locked -p spawn-api -p spawnbox-cli
  scripts/build-artifacts.sh "$artifacts"
  install -m 0755 target/release/spawn-api target/release/spawnbox "$artifacts/bin/"
  bins="$artifacts/bin"
fi

first_install=no
$sudo test -f "$data/spawnbox.db" || first_install=yes

stop_service
say "installing into $prefix"
$sudo install -d -m 0755 "$prefix/bin"
$sudo install -m 0755 "$bins/spawn-api" "$bins/spawnbox" "$bins/firecracker" "$bins/jailer" "$bins/runsc" "$prefix/bin/"
$sudo rm -rf "$prefix/bin/gvisor-bin"
$sudo cp -r "$bins/gvisor-bin" "$prefix/bin/"
if [[ ! -e "$cli_link" || -L "$cli_link" ]]; then
  $sudo ln -sfn "$prefix/bin/spawnbox" "$cli_link"
fi
$sudo install -m 0644 "$artifacts/vmlinux" "$artifacts/rootfs.ext4" "$prefix/"
$sudo install -m 0755 "$repo/deploy/install.sh" "$prefix/install.sh"
# A release bundle names its tag; a source build has none.
version=""
if [[ -f "$repo/VERSION" ]]; then
  $sudo install -m 0644 "$repo/VERSION" "$prefix/VERSION"
  version="$(cat "$repo/VERSION")"
else
  $sudo rm -f "$prefix/VERSION"
fi
$sudo install -d -m 0755 "$config_dir"
if ! $sudo test -f "$config"; then
  $sudo tee "$config" >/dev/null <<'EOF'
# Flags for `spawn-api serve`; see `/opt/spawnbox/bin/spawn-api serve --help`.
# The API has no TLS. Keep it on localhost, or put a TLS proxy in front.
# Previews route by host name: point a wildcard DNS name at the preview
# listener and set --preview-url to match, for example
#   --preview-listen 0.0.0.0:8081 --preview-url https://{label}.preview.example.com
SPAWNBOX_ARGS="--listen 127.0.0.1:8080 --preview-listen 127.0.0.1:8081 --preview-url http://{label}.localhost:8081"
EOF
fi

$sudo tee "$unit" >/dev/null <<EOF
[Unit]
Description=Spawnbox sandboxes
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=$config
ExecStart=$prefix/bin/spawn-api serve \\
  --firecracker $prefix/bin/firecracker \\
  --jailer $prefix/bin/jailer \\
  --runsc $prefix/bin/runsc \\
  --kernel $prefix/vmlinux \\
  --rootfs $prefix/rootfs.ext4 \\
  --data-dir $data \\
  \$SPAWNBOX_ARGS
# The server stops its sandboxes on SIGTERM; give it time before SIGKILL.
KillMode=mixed
TimeoutStopSec=120
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

key=""
if [[ "$first_install" == yes ]]; then
  key="$($sudo "$prefix/bin/spawn-api" create-key --data-dir "$data" 2>/dev/null)"
fi

say "starting spawnbox"
$sudo systemctl daemon-reload
$sudo systemctl enable --now spawnbox >/dev/null 2>&1

args="$($sudo bash -c "source '$config'; echo \"\$SPAWNBOX_ARGS\"")"
if grep -qE -- '--primary([ =]|$)' <<<"$args"; then
  # A fleet worker serves only the primary, so check that it stays up.
  sleep 10
  restarts="$(systemctl show -p NRestarts --value spawnbox)"
  if ! systemctl is-active --quiet spawnbox || [[ "${restarts:-0}" -gt 0 ]]; then
    $sudo journalctl -u spawnbox -n 30 --no-pager >&2 || true
    die "spawnbox failed to start; see: journalctl -u spawnbox"
  fi
  say "Spawnbox is running as a fleet worker; clients call the primary"
  echo "see its state with GET /v1/nodes on the primary, or: journalctl -u spawnbox"
  exit 0
fi
listen="$(grep -oP -- '--listen[ =]\K\S+' <<<"$args" || true)"
listen="${listen:-127.0.0.1:8080}"
host="${listen%:*}"
[[ "$host" == 0.0.0.0 || "$host" == "[::]" ]] && host=127.0.0.1
url="http://$host:${listen##*:}"
# The first start builds the base template, which takes a few seconds.
for _ in $(seq 300); do
  curl -fs "$url/healthz" >/dev/null 2>&1 && break
  restarts="$(systemctl show -p NRestarts --value spawnbox)"
  if systemctl is-failed --quiet spawnbox || [[ "${restarts:-0}" -gt 0 ]]; then
    $sudo journalctl -u spawnbox -n 30 --no-pager >&2 || true
    die "spawnbox failed to start; see: journalctl -u spawnbox"
  fi
  sleep 1
done
curl -fs "$url/healthz" >/dev/null || die "spawnbox did not answer on $url; see: journalctl -u spawnbox"

say "Spawnbox ${version:-from source} is running at $url"
if [[ -n "$key" ]]; then
  cat <<EOF

API key (shown once; create more with
  sudo $prefix/bin/spawn-api create-key --data-dir $data):

  $key

Log in to the CLI once (it asks for the key), then try it:
  spawnbox login --url $url
  S=\$(spawnbox create)
  spawnbox exec \$S -- uname -a

Or with curl:
  curl -s -X POST $url/v1/sandboxes -H "Authorization: Bearer $key"

!!! Back up $data/secrets.key now. Stored secrets cannot be read
!!! without it.
EOF
else
  echo "upgraded; settings in $config were kept"
fi
