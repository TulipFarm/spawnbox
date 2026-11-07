# Prometheus metrics

Status: done. Tested on the KVM primary and worker: warm and cached creates,
create steps, a `not_found` error, an allowed egress connection, warm pool
hits and misses, slots and memory ratios, and fleet node counts all show at
`/metrics`.

## Goal

The metrics in the spec's Metrics table, so an operator can graph create
times, errors and capacity per host.

## Design

- `metrics.rs` writes the Prometheus text format by hand. No new crate.
  One process-wide registry (a mutex over sorted maps) keeps counters and
  histograms. A static table gives each metric's `HELP` and `TYPE`.
- Gauges are read at scrape time: sandboxes by state from the database
  (local rows only), free slots, `MemAvailable` against `MemTotal`, warm
  pools, and on a primary the workers by state.
- `--metrics-listen ADDR` serves `GET /metrics` on its own plain HTTP
  listener, on every role. It is off by default and has no auth; bind it
  to a private address.
- Every metric is about the host that serves it, so there is no `node`
  label. Prometheus adds `instance`. `region` waits for regions.
- Create `path`: `warm` if a warm VM was used, `cold` if the build was
  fetched from the build store for this create, else `cached`. The time
  starts before the fetch. `ensure_local` now returns whether it fetched.
- Create steps are `prepare`, `restore` and `fixups`, from the existing
  timings. The spec's `auth`, `schedule` and `claim` steps wait for traces.
- API errors are counted where every error becomes a response.
- Egress connections are counted for sandboxes and template builds.

## Also fixed

After `min_warm`, a template's spec hash on the primary no longer matched
the build spec hash that workers report, so a `min_warm` change stopped
creates from going to workers. Both sides now hash the build part of the
spec (`fleet::build_hash`). Tested: after a `min_warm`-only change, creates
are placed on the worker again.
