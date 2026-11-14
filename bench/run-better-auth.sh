#!/usr/bin/env bash
# Runs the Better-Auth task one replicate at a time, so only one sandbox is ever running.
# usage: run-better-auth.sh <run-id> [replicates]   (default 12; run it inside tmux)
set -uo pipefail

run=${1:?usage: run-better-auth.sh <run-id> [replicates]}
reps=${2:-12}
suite=realworld-better-auth
bench=${BENCH_DIR:-$HOME/hpc-sandbox-benchmarks}
out=$HOME/results/$run
mkdir -p "$out"
cd "$bench" || exit 1

for r in $(seq 0 $((reps - 1))); do
  echo "== replicate $r $(date -u +%T)"
  ~/.bun/bin/bun apps/cli/src/bin/bench-suite.ts spawnbox "$suite" "$run" \
    --replicates "$r" --require spawnbox >"$out/r$r.log" 2>&1
  echo "replicate $r exit $?"
  mv data/runs/"$run"-r"$r".json "$out/" 2>/dev/null
done

~/.bun/bin/bun apps/cli/src/bin/aggregate.ts "$run" "$out/agg" "$out"/"$run"-r*.json >/dev/null
jq -r '.providers[] | select(.providerId == "spawnbox") | .metrics[]
  | select(.metricId | test("realworld_better_auth_task"))
  | "\(.metricId | sub("realworld_better_auth_task_"; ""))\t\(.aggregates.p50)"' "$out/agg/runs/$run.json" |
  awk -F'\t' '{ printf "%-16s %8.2f s\n", $1, $2; t += $2 } END { printf "%-16s %8.2f s\n", "total", t }'
