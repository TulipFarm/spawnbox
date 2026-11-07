# Per-template min_warm

Status: done. Tested on the KVM host: a template with `min_warm: 1` keeps
one warm VM, a create takes it, setting `min_warm: 0` keeps the build and
empties the pool, 17 is refused, and saving the same template builds again.

## Goal

A template can ask each host to keep a minimum number of warm VMs, as the
spec's pool target `max(min_warm, creates in the last 30 s)` says.

## Design

- `TemplateSpec.min_warm` (0 to 16, default 0). It is left out of the
  JSON when 0, so the stored specs and build store keys of existing
  templates do not change.
- `TemplateSpec::for_build()` drops `min_warm`. Build checks (`wanted`) and
  the build store key use it, so `min_warm` never makes a new build.
- `POST /v1/templates` still builds again when the same spec is saved (the
  README promises this). When only `min_warm` changed, it keeps the latest
  queued, building or ready build. Fleet workers' `sync` does the same.
- Every refill (1 s), the runtime gives the warm pools a full list of
  minimums: `base` with `--warm-pool-min`, and each template with
  `min_warm`. Pools not in the list get minimum 0, so lowering or removing
  `min_warm` empties them.
- A tenant template's pool uses the tenant's egress policy plus
  `allow_all`; org-wide templates use `allow_all`.
- In a fleet each host keeps `min_warm` VMs (the spec is synced as is).
