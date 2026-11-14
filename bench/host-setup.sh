#!/usr/bin/env bash
# Prepares a dedicated Ubuntu 24.04 x86_64 host with /dev/kvm for the Better-Auth benchmark.
# Run it as a sudo-capable user on a machine used for nothing else.
set -euo pipefail

SPAWNBOX_VERSION=${SPAWNBOX_VERSION:-v0.1.13}
HUGE_PAGES=${HUGE_PAGES:-16384} # 2 MiB pages: 16384 is 32 GiB, room for four 8 GiB sandboxes
BENCH_REPO=${BENCH_REPO:-https://github.com/TulipFarm/hpc-sandbox-benchmarks}
BENCH_REF=${BENCH_REF:-add-spawnbox-provider}
BENCH_DIR=${BENCH_DIR:-$HOME/hpc-sandbox-benchmarks}
TEMPLATE=sandbox-benchmarks-toolchain-v8
IMAGE=ghcr.io/starslingdev/sandbox-benchmarks-toolchain:v8

[ -e /dev/kvm ] || { echo "/dev/kvm is missing; use a bare-metal or nested-virt host" >&2; exit 1; }

echo "== stop automatic upgrades (they restart services, and Spawnbox, mid-run)"
sudo systemctl stop apt-daily.timer apt-daily-upgrade.timer unattended-upgrades || true

echo "== packages"
sudo apt-get update -qq
sudo apt-get install -y -qq curl git jq unzip >/dev/null

echo "== Spawnbox $SPAWNBOX_VERSION"
curl -fsSL https://spawnbox.tulipfarm.ai/install.sh |
  SPAWNBOX_VERSION=$SPAWNBOX_VERSION SPAWNBOX_AGENT_TEMPLATES=0 sh | tee ~/spawnbox-install.log
key=$(grep -o 'sbx_org_[A-Za-z0-9_]*' ~/spawnbox-install.log | head -1 || true)
[ -n "$key" ] || key=$(sudo /opt/spawnbox/bin/spawn-api create-key --data-dir /var/lib/spawnbox)
umask 077 && echo "$key" >~/.spawnbox-key && umask 022

echo "== huge pages: $HUGE_PAGES x 2 MiB"
sudo sysctl -w vm.nr_hugepages="$HUGE_PAGES"
grep -E 'HugePages_(Total|Free)' /proc/meminfo
sudo sed -i 's/^SPAWNBOX_ARGS="\(.*\)"/SPAWNBOX_ARGS="\1 --memory-overcommit-pct 100 --huge-pages"/' /etc/spawnbox/spawnbox.env
grep SPAWNBOX_ARGS /etc/spawnbox/spawnbox.env
sudo systemctl restart spawnbox
for _ in $(seq 60); do curl -fs http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 2; done
sudo journalctl -u spawnbox --no-pager -n 20 | grep -E "2 MiB pages|sandboxes run in"

echo "== template $TEMPLATE (4 vCPU, 8 GiB, 42 GiB disk)"
curl -fsS -X POST http://127.0.0.1:8080/v1/templates \
  -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
  -d "{\"name\":\"$TEMPLATE\",\"base\":\"$IMAGE\",\"resources\":{\"vcpus\":4,\"memory_mib\":8192,\"disk_gib\":42}}" >/dev/null
for _ in $(seq 120); do
  s=$(curl -fs -H "Authorization: Bearer $key" "http://127.0.0.1:8080/v1/templates/$TEMPLATE" | jq -r '.latest_build.state')
  echo "template: $s"
  [ "$s" = ready ] && break
  [ "$s" = failed ] && exit 1
  sleep 15
done

echo "== benchmark repo $BENCH_REPO@$BENCH_REF"
[ -x ~/.bun/bin/bun ] || curl -fsSL https://bun.sh/install | bash -s bun-v1.4.0
[ -d "$BENCH_DIR/.git" ] || git clone -q "$BENCH_REPO" "$BENCH_DIR"
git -C "$BENCH_DIR" fetch -q origin "$BENCH_REF" && git -C "$BENCH_DIR" checkout -q FETCH_HEAD
printf 'SPAWNBOX_API_KEY=%s\nSPAWNBOX_URL=http://127.0.0.1:8080\n' "$key" >"$BENCH_DIR/.env"
(cd "$BENCH_DIR" && ~/.bun/bin/bun install --frozen-lockfile --ignore-scripts >/dev/null)
echo "ready: run bench/run-better-auth.sh"
