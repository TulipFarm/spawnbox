# M2 part 1: tenants, scoped keys and quotas

Status: done.

The first of three M2 merges. The others: events with step IDs,
`GET /v1/events` and OTLP; then usage metering and `GET /v1/usage`.

## Model

- One implicit org per install. There is no orgs table or orgs API.
- Tenants have an ID chosen at create (`a-z`, digits and `-`, starting with
  a letter, at most 63), an optional display name, quotas and an optional
  egress policy.
- The `default` tenant always exists and cannot be deleted.

## Keys

- Org keys (`sbx_org_...`) touch everything: tenants, keys and every
  tenant's resources. Tenant keys (`sbx_tn_...`) touch only their tenant.
  Keys made before tenants (`sbk_...`) keep working as org keys.
- Scopes: `sandboxes:read`, `sandboxes:write`, `templates:write`,
  `secrets:write`, `tenants:admin`, `audit:read`. A key without a scope
  list has every scope its kind allows; `tenants:admin` is org-only.
  `audit:read` is stored for the events API.
- `POST /v1/keys` (`tenant`, `scopes`, `name`) returns the key once.
  `GET /v1/keys` lists them; `DELETE /v1/keys/{id}` revokes. Needs
  `tenants:admin`. `spawn-api create-key --tenant <id>` makes tenant keys
  from the host.
- Another tenant's sandbox, template, secret or build returns `404`.

## Ownership

- Every sandbox has a tenant. Tenant keys create in their tenant; org keys
  pass `"tenant"` on create or get `default`. Lists show the caller's
  tenant; org keys see all, or filter with `?tenant=`.
- Templates and secrets are org-wide (made by an org key without
  `?tenant=`) or private to one tenant. Tenants can use org-wide ones but
  not change them. A name resolves to the tenant's own first, then the
  org-wide one. Org keys work in a tenant's namespace with `?tenant=`.
- Upgrades: existing keys become org keys, existing sandboxes move to
  `default`, existing templates and secrets become org-wide.

## Quotas

- Per tenant: `running_sandboxes`, `running_vcpus`, `running_memory_mib`,
  `max_session_s`, `max_paused_retention_s`. `null` means no limit.
- New tenants get the spec defaults (20, 40, 81920 MiB, 24 h, 7 days) for
  fields they leave out. `default` starts with no limits, so upgrades keep
  working.
- Create and resume are admitted against running sandboxes (starting,
  running and pausing) of the tenant. Over a quota returns
  `429 quota_exceeded` naming the quota. Session length caps `timeout_s`;
  paused retention is the lower of the tenant's and the server's.
- Snapshot storage and monthly egress quotas wait for metering.

## Tenant API

- `POST /v1/tenants`, `GET /v1/tenants`, `GET`, `PATCH` and `DELETE
  /v1/tenants/{id}`. Needs `tenants:admin`. `GET` includes current usage.
- `PATCH` sets the name, quotas (per field) and egress policy (`null`
  removes it). A tenant's egress policy applies on top of the server's
  and the sandbox's, from the next create or resume.
- `DELETE` fails while the tenant has sandboxes that are not deleted,
  templates or secrets; it revokes the tenant's keys.

## Tests

- Unit: key kinds and scopes, path to scope, quota checks, name
  resolution, migrations from version 4.
- Smoke on KVM: tenant and keys lifecycle, cross-tenant 404 on every
  sandbox, template and secret endpoint, scope 403, org-wide template use,
  quota 429 on create and resume, tenant egress policy.
