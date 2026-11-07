# Warm pools

Status: done. Tested on the KVM host: warm hits about 8 ms total (restore about 70 ms), fair budget sharing between pools, `deny_all` egress on warm VMs, template rebuilds, restart with no leftovers, `scripts/cli-smoke.sh` and `scripts/m1-smoke.sh`.

## Goal

A create takes a VM that is already restored instead of restoring one.
Target from the spec: under 50 ms p50 and under 100 ms p95 for a warm hit.

## Design

- A warm VM is a template build restored in its own jail, network namespace
  and slot, with its vCPUs paused. Its sandbox ID is chosen when it is made,
  so jail, namespace and log names match the sandbox that claims it.
- Pools are keyed by build and network mode, because the namespace firewall
  depends on the mode. A tenant's own template has its own build, so a warm
  VM never crosses tenants.
- Claim: register the egress proxy for the slot, resume the vCPUs, apply a
  new identity (clock, entropy, hostname). Quotas and metering start at the
  claim, as for a cold create.
- Target per pool: `max(min, creates in the last 30 s)`. `--warm-pool-min`
  (default 1) keeps that many for `base` with the server's network policy.
  Other pools come from demand and fall to zero.
- Limits: warm VMs use at most `--warm-pool-memory-pct` of host memory
  (default 10; 0 turns pools off). Pools never take the last
  `--max-builds` free slots, so template builds can start. A cold create or
  resume with no free slot stops a warm VM of a different pool.
- At most 2 warm VMs are restored at once. A pool whose build is replaced
  or removed is stopped.
- `GET /v1/warm-pools` (org keys, `tenants:admin`) shows each pool. The
  create response has `started_from`: `warm_pool` or `build`.

## Not in scope

- Per-template `min_warm` settings.
- Prometheus metrics.

## Tests

- Unit tests for the pool logic: demand, target, budget, slot reserve,
  retired builds, eviction.
- KVM host: warm hits after the first create, create timings, pool status,
  egress policy on a warm VM, template replace, shutdown and restart with no
  leftovers.
