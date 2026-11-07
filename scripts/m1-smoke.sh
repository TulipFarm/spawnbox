#!/usr/bin/env bash
# Runs the spawn-api checks end to end on a Linux host. Set
# SPAWNBOX_BACKEND=gvisor to run them on gVisor instead of Firecracker:
#   1. builds everything and starts `spawn-api serve` with a fresh database
#   2. runs scripts/m1_smoke.py against it: the API checks, custom
#      templates and file access, terminals, git clone and previews,
#      pause and resume, volumes, secrets and egress policies, tenants, keys and
#      quotas, then the event log and its export to a test OTLP receiver,
#      and usage metering with its quotas
#   3. stops the server with SIGTERM and checks nothing is left behind
#   4. starts it again and checks the template build is reused, not rebuilt,
#      and the sandbox left paused resumes
#   5. starts it again, creates a sandbox, kills the server with SIGKILL,
#      and checks that the next start cleans up and records the sandbox as
#      deleted
#   6. starts it with HTTPS on both listeners, and checks a renewed
#      certificate is picked up without a restart
# The server runs with sudo: it creates jails, cgroups, network namespaces
# and firewall rules.
set -euo pipefail

data="${1:-$HOME/.cache/spawnbox/m1}"
artifacts="${SPAWNBOX_ARTIFACTS:-$HOME/.cache/spawnbox/artifacts}"
port="${SPAWNBOX_PORT:-18080}"
backend="${SPAWNBOX_BACKEND:-firecracker}"
case "$backend" in
  firecracker) vm_process=firecracker ;;
  gvisor) vm_process=gvisor_sentry ;;
  *) echo "SPAWNBOX_BACKEND must be firecracker or gvisor" >&2; exit 2 ;;
esac
base="http://127.0.0.1:${port}"
preview_port="$((port + 1))"
export SPAWNBOX_PREVIEW="http://127.0.0.1:${preview_port}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

scripts/build-artifacts.sh "$artifacts"
cargo build --release --locked -p spawn-api
api="$repo/target/release/spawn-api"

sudo rm -rf "$data"
key="$(sudo "$api" create-key --data-dir "$data")"
pidfile="$data/server.pid"
log="$(mktemp)"

server_pid() { sudo cat "$pidfile" 2>/dev/null || echo 0; }

# Extra `serve` flags, for the TLS phase.
extra=()
curl_tls=()

start_server() {
  if curl -s -o /dev/null "${curl_tls[@]}" "$base/healthz"; then
    echo "something already listens on port $port" >&2
    return 1
  fi
  # A stale pid would look like a server that died while starting.
  sudo rm -f "$pidfile"
  sudo bash -c 'echo $$ > "$1" && shift && exec "$@"' _ "$pidfile" \
    "$api" serve \
    --backend "$backend" \
    --runsc "$artifacts/bin/runsc" \
    --firecracker "$artifacts/bin/firecracker" \
    --jailer "$artifacts/bin/jailer" \
    --kernel "$artifacts/vmlinux" \
    --rootfs "$artifacts/rootfs.ext4" \
    --data-dir "$data" \
    --listen "127.0.0.1:${port}" \
    --preview-listen "127.0.0.1:${preview_port}" \
    --preview-url "http://{label}.localhost:${preview_port}" "${extra[@]}" >>"$log" 2>&1 &
  for _ in $(seq 120); do
    curl -fs "${curl_tls[@]}" "$base/healthz" >/dev/null 2>&1 && return 0
    pid="$(server_pid)"
    [[ "$pid" == 0 ]] || sudo kill -0 "$pid" 2>/dev/null || break
    sleep 1
  done
  echo "server did not start; log:" >&2
  cat "$log" >&2
  return 1
}

stop_server() {
  local signal="$1" pid
  pid="$(server_pid)"
  sudo kill "-$signal" "$pid" 2>/dev/null || true
  # Shutdown waits for paused sandboxes' memory to reach the disk.
  for _ in $(seq 240); do
    sudo kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.5
  done
  echo "server did not stop" >&2
  return 1
}

# An address on this host, outside the always-blocked ranges, with a web
# server: sandboxes must not reach it through the egress proxy.
host_ip="198.51.100.7"
listener_pid=""
otlp_pid=""
otlp_port="$((port + 2))"
otlp_log="$(mktemp)"

finish() {
  if sudo kill -0 "$(server_pid)" 2>/dev/null; then
    stop_server TERM || true
  fi
  [[ -n "$listener_pid" ]] && kill "$listener_pid" 2>/dev/null
  [[ -n "$otlp_pid" ]] && kill "$otlp_pid" 2>/dev/null
  sudo ip addr del "$host_ip/32" dev lo 2>/dev/null || true
  echo "server log: $log"
}
trap finish EXIT

leftovers() {
  local found=0
  pgrep -x firecracker >/dev/null && { echo "firecracker still running" >&2; found=1; }
  pgrep -x jailer >/dev/null && { echo "jailer still running" >&2; found=1; }
  pgrep -f '^\S*runsc ' >/dev/null && { echo "runsc still running" >&2; found=1; }
  ip netns list | grep -q '^spawnbox-' && { echo "network namespaces left" >&2; found=1; }
  [[ -e /sys/fs/cgroup/spawnbox ]] && { echo "cgroup left" >&2; found=1; }
  sudo nft list tables | grep -q 'inet spawnbox' && { echo "firewall table left" >&2; found=1; }
  ip -o link show | grep -q ' sbx[0-9]' && { echo "host links left" >&2; found=1; }
  return "$found"
}

forward_before="$(sysctl -n net.ipv4.ip_forward)"

# Appends every OTLP/HTTP request body to $otlp_log.
python3 - "$otlp_port" "$otlp_log" <<'PY' &
import http.server, sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/v1/logs":
            with open(sys.argv[2], "ab") as f:
                f.write(body)
        self.send_response(200)
        self.send_header("Content-Type", "application/x-protobuf")
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *args):
        pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
otlp_pid=$!
extra=(--otlp-endpoint "http://127.0.0.1:${otlp_port}")
start_server
python3 scripts/m1_smoke.py "$base" "$key" api | tee "$data.report.json"
python3 scripts/m1_smoke.py "$base" "$key" templates | tee "$data.templates.json"
python3 scripts/m1_smoke.py "$base" "$key" interactive | tee "$data.interactive.json"
python3 scripts/m1_smoke.py "$base" "$key" pause | tee "$data.pause.json"
python3 scripts/m1_smoke.py "$base" "$key" volumes | tee "$data.volumes.json"
grep -q 'sbx_[a-z0-9]* paused in [0-9]* ms' "$log" || { echo "no pause timing log" >&2; exit 1; }
grep -q 'sbx_[a-z0-9]* resumed in [0-9]* ms' "$log" || { echo "no resume timing log" >&2; exit 1; }
grep -q 'sbx_[a-z0-9]* is idle; pausing' "$log" || { echo "no idle pause log" >&2; exit 1; }
sudo ip addr add "$host_ip/32" dev lo
python3 -m http.server --bind "$host_ip" 18999 --directory /tmp >/dev/null 2>&1 &
listener_pid=$!
for _ in $(seq 20); do curl -fs -o /dev/null "http://$host_ip:18999/" && break; sleep 0.2; done
SPAWNBOX_HOST_IP="$host_ip" python3 scripts/m1_smoke.py "$base" "$key" egress | tee "$data.egress.json"
kill "$listener_pid"; listener_pid=""
sudo ip addr del "$host_ip/32" dev lo
grep -q 'egress: sandbox=sbx_.* verdict=allow' "$log" || { echo "no egress allow log" >&2; exit 1; }
grep -q 'egress: sandbox=sbx_.* verdict=deny' "$log" || { echo "no egress deny log" >&2; exit 1; }
grep -q 'egress: sandbox=sbx_.* host=postman-echo.com request=GET status=200 secrets=echo_token@v2' "$log" ||
  { echo "no secret use log" >&2; exit 1; }
grep -q 's3cret-' "$log" && { echo "secret value in the server log" >&2; exit 1; }
python3 scripts/m1_smoke.py "$base" "$key" tenants | tee "$data.tenants.json"
SPAWNBOX_OTLP_LOG="$otlp_log" python3 scripts/m1_smoke.py "$base" "$key" events | tee "$data.events.json"
python3 scripts/m1_smoke.py "$base" "$key" usage | tee "$data.usage.json"
build="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["template_build_id"])' "$data.templates.json")"
paused="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["paused_id"])' "$data.pause.json")"
stop_server TERM
kill "$otlp_pid"; otlp_pid=""
extra=()
leftovers
sudo test -d "$data/paused/$paused" || { echo "paused sandbox files were not kept" >&2; exit 1; }
[[ "$(sysctl -n net.ipv4.ip_forward)" == "$forward_before" ]] || { echo "ip_forward not restored" >&2; exit 1; }
echo "clean shutdown: ok"

mark="$(wc -l <"$log")"
start_server
python3 scripts/m1_smoke.py "$base" "$key" restart "$build" "$paused" >/dev/null
vcpu_s="$(curl -fsS -H "Authorization: Bearer $key" "$base/v1/usage" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["total"]["vcpu_s"])')"
python3 -c 'import sys; sys.exit(float(sys.argv[1]) <= 0)' "$vcpu_s" ||
  { echo "usage from before the restart is missing" >&2; exit 1; }
if tail -n "+$((mark + 1))" "$log" | grep -q 'building template'; then
  echo "templates were rebuilt after a restart" >&2
  exit 1
fi
stop_server TERM
leftovers
sudo test -e "$data/paused/$paused" && { echo "resumed sandbox files were not removed" >&2; exit 1; }
echo "restart keeps builds and paused sandboxes: ok"

start_server
id="$(curl -fsS -X POST -H "Authorization: Bearer $key" "$base/v1/sandboxes" -d '{}' |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
pgrep -x "$vm_process" >/dev/null || { echo "no sandbox running before the crash" >&2; exit 1; }
stop_server KILL
echo "killed server with sandbox $id running"

start_server
state="$(curl -fsS -H "Authorization: Bearer $key" "$base/v1/sandboxes/$id" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')"
[[ "$state" == "deleted" ]] || { echo "after crash, $id is $state" >&2; exit 1; }
lost="$(curl -fsS -H "Authorization: Bearer $key" "$base/v1/sandboxes/$id/events?type=sandbox.lost" |
  python3 -c 'import json,sys; print(len(json.load(sys.stdin)["events"]))')"
[[ "$lost" == "1" ]] || { echo "no sandbox.lost event after the crash" >&2; exit 1; }
[[ "$(pgrep -xc "$vm_process" || true)" == "0" ]] || { echo "sandbox from the crashed run survived" >&2; exit 1; }
stop_server TERM
leftovers
echo "crash recovery: ok"

tls="$(mktemp -d)"
new_cert() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj "/CN=$1" -addext "subjectAltName=DNS:localhost,DNS:3000-sbx-0000000000000000.localhost,IP:127.0.0.1" \
    -keyout "$tls/key.tmp" -out "$tls/cert.tmp" 2>/dev/null
  cp "$tls/cert.tmp" "$tls/$1.pem"
  mv "$tls/key.tmp" "$tls/key.pem"
  mv "$tls/cert.tmp" "$tls/cert.pem"
}
new_cert first
base="https://127.0.0.1:${port}"
extra=(--tls-cert "$tls/cert.pem" --tls-key "$tls/key.pem"
  --preview-tls-cert "$tls/cert.pem" --preview-tls-key "$tls/key.pem")
curl_tls=(--cacert "$tls/first.pem")
start_server
curl -fsS "${curl_tls[@]}" "$base/healthz" >/dev/null
curl -s -o /dev/null "http://127.0.0.1:${port}/healthz" && { echo "plain HTTP on the TLS port" >&2; exit 1; }
curl -s -o /dev/null --max-time 5 "$base/healthz" && { echo "an unknown certificate was trusted" >&2; exit 1; }
status="$(curl -s -o /dev/null -w '%{http_code}' "${curl_tls[@]}" \
  --resolve "3000-sbx-0000000000000000.localhost:${preview_port}:127.0.0.1" \
  "https://3000-sbx-0000000000000000.localhost:${preview_port}/")"
[[ "$status" == "404" ]] || { echo "HTTPS preview returned $status" >&2; exit 1; }
# A client that never finishes its handshake must not block others.
exec 3<>"/dev/tcp/127.0.0.1/${port}"
curl -fsS --max-time 5 "${curl_tls[@]}" "$base/healthz" >/dev/null
exec 3>&-
new_cert second
for _ in $(seq 30); do
  curl -fs --cacert "$tls/second.pem" "$base/healthz" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS --cacert "$tls/second.pem" "$base/healthz" >/dev/null
grep -q 'loaded new certificate' "$log" || { echo "no reload log" >&2; exit 1; }
curl_tls=(--cacert "$tls/second.pem")
stop_server TERM
leftovers
rm -rf "$tls"
echo "tls and certificate reload: ok"
