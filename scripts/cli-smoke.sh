#!/usr/bin/env bash
# Runs every `spawnbox` CLI command against a real server and checks the
# results. Needs an installed server (deploy/install.sh) and an org key.
#
#   SPAWNBOX_API_KEY=sbx_org_... scripts/cli-smoke.sh [path/to/spawnbox]
#
# It creates sandboxes, a template, a secret, a tenant and a key named
# `cli-smoke-*`, and deletes them at the end.
set -euo pipefail

sb="${1:-spawnbox}"
: "${SPAWNBOX_API_KEY:?set SPAWNBOX_API_KEY to an org key}"
export SPAWNBOX_URL="${SPAWNBOX_URL:-http://127.0.0.1:8080}"
work="$(mktemp -d)"
ids=()

cleanup() {
  for id in "${ids[@]}"; do "$sb" kill "$id" >/dev/null 2>&1 || true; done
  "$sb" templates rm cli-smoke-tpl >/dev/null 2>&1 || true
  "$sb" secrets rm cli-smoke-secret >/dev/null 2>&1 || true
  "$sb" tenants rm cli-smoke-tn >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

pass() { printf 'ok    %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; exit 1; }
expect() { # expect NAME WANT GOT
  [[ "$3" == *"$2"* ]] || fail "$1: want '$2', got '$3'"
  pass "$1"
}

expect "login" "Logged in" "$(XDG_CONFIG_HOME="$work/cfg" "$sb" login <<<"$SPAWNBOX_API_KEY")"
expect "login file mode" "600" "$(stat -c %a "$work/cfg/spawnbox/config.json")"

S="$("$sb" create --label suite=cli-smoke --env GREETING=hi)"
ids+=("$S")
expect "create" "sbx_" "$S"
expect "ls" "$S" "$("$sb" ls)"
expect "get" '"state": "running"' "$("$sb" get "$S")"

expect "exec output" "hi from sandbox" "$("$sb" exec "$S" -- 'echo $GREETING from sandbox')"
expect "exec quoting" "a b|it's" "$("$sb" exec "$S" -- printf '%s|%s' 'a b' "it's")"
expect "exec stdin" "3" "$(printf '1\n2\n3\n' | "$sb" exec -i "$S" -- wc -l)"
set +e
"$sb" exec "$S" -- 'echo to-stderr >&2; exit 7' 2>"$work/err"
code=$?
set -e
expect "exec exit code" "7" "$code"
expect "exec stderr" "to-stderr" "$(cat "$work/err")"
expect "exec json" '"exit_code": 0' "$("$sb" --json exec "$S" -- true)"
expect "exec step id" "cli-smoke-step" \
  "$("$sb" --step cli-smoke-step exec "$S" -- true && "$sb" events --step-id cli-smoke-step)"

mkdir -p "$work/src/sub"
echo one >"$work/src/a.txt"
echo two >"$work/src/sub/b.txt"
head -c 3000000 /dev/urandom >"$work/src/big.bin"
"$sb" cp "$work/src" "$S:/workspace/up" 2>/dev/null
expect "cp dir up" "two" "$("$sb" exec "$S" -- cat /workspace/up/sub/b.txt)"
"$sb" cp "$S:/workspace/up" "$work/down" 2>/dev/null
cmp "$work/src/big.bin" "$work/down/big.bin" || fail "cp big file round trip"
expect "cp dir down" "two" "$(cat "$work/down/sub/b.txt")"
echo piped | "$sb" cp - "$S:notes.txt"
expect "cp stdin/stdout" "piped" "$("$sb" cp "$S:notes.txt" -)"

expect "sh" "pty-ok" "$("$sb" sh "$S" --cmd 'echo pty-ok' </dev/null)"

expect "clone" "/workspace/Hello-World" \
  "$("$sb" clone "$S" https://github.com/octocat/Hello-World --depth 1)"

"$sb" exec "$S" -- 'setsid python3 -m http.server 3000 --bind 127.0.0.1 >/dev/null 2>&1 &'
url="$("$sb" ports publish "$S" 3000 --access public)"
expect "ports publish" "http" "$url"
expect "ports ls" "3000" "$("$sb" ports ls "$S")"
"$sb" ports rm "$S" 3000
expect "ports rm" "" "$("$sb" ports ls "$S" | grep -c 3000 || true)"

expect "pause" "$S paused" "$("$sb" pause "$S")"
expect "resume" "$S running" "$("$sb" resume "$S")"
expect "exec after resume" "alive" "$("$sb" exec "$S" -- echo alive)"

cat >"$work/tpl.json" <<'EOF'
{"name": "cli-smoke-tpl", "setup": ["echo built > /etc/cli-smoke"]}
EOF
expect "templates build" "cli-smoke-tpl is ready" "$("$sb" templates build "$work/tpl.json" 2>/dev/null)"
expect "templates ls" "cli-smoke-tpl" "$("$sb" templates ls)"
expect "templates logs" "" "$("$sb" templates logs cli-smoke-tpl >/dev/null && echo)"
T="$("$sb" create --template cli-smoke-tpl)"
ids+=("$T")
expect "create from template" "built" "$("$sb" exec "$T" -- cat /etc/cli-smoke)"

expect "secrets set" "created" \
  "$(echo s3cret | "$sb" secrets set cli-smoke-secret --hosts postman-echo.com --env SMOKE_TOKEN)"
expect "secrets update" "updated (version 2)" \
  "$(SMOKE_VALUE=v2 "$sb" secrets set cli-smoke-secret --from-env SMOKE_VALUE)"
expect "secrets ls" "cli-smoke-secret" "$("$sb" secrets ls)"
X="$("$sb" create --secret cli-smoke-secret --allow postman-echo.com)"
ids+=("$X")
expect "secret injected" "Bearer v2" \
  "$("$sb" exec "$X" -- 'curl -s https://postman-echo.com/headers')"
expect "allowlist blocks" "blocked" \
  "$("$sb" exec "$X" -- 'curl -s -m 5 https://example.com >/dev/null && echo open || echo blocked')"

expect "tenants create" "cli-smoke-tn" "$("$sb" tenants create cli-smoke-tn --quota running_sandboxes=1)"
expect "tenants set" "updated" "$("$sb" tenants set cli-smoke-tn --quota running_sandboxes=2)"
expect "tenants get" '"running_sandboxes": 2' "$("$sb" tenants get cli-smoke-tn)"
key="$("$sb" keys create --tenant cli-smoke-tn --name cli-smoke-key 2>/dev/null)"
expect "keys create" "sbx_tn_" "$key"
key_id="$("$sb" keys ls | awk '/cli-smoke-key/ && $NF == "-" {print $1}' | tail -1)"
expect "tenant key sees own sandboxes only" "" "$(SPAWNBOX_API_KEY="$key" "$sb" ls | grep "$S" || true)"
"$sb" keys rm "$key_id"
expect "keys rm" "unauthorized" "$(SPAWNBOX_API_KEY="$key" "$sb" ls 2>&1 || true)"

expect "events for a sandbox" "sandbox.created" "$("$sb" events "$S" --type 'sandbox.*')"
timeout 3 "$sb" events --follow >"$work/follow" 2>&1 &
sleep 1
"$sb" exec "$S" -- true
wait || true
expect "events follow" "exec.finished" "$(cat "$work/follow")"
expect "usage" "Total" "$("$sb" usage --by-sandbox)"

expect "kill" "$S" "$("$sb" kill "$S")"
expect "killed sandbox state" '"state": "deleted"' "$("$sb" get "$S")"
expect "missing sandbox error" "not_found" "$("$sb" get sbx_doesnotexist0000 2>&1 || true)"

echo "all CLI checks passed"
