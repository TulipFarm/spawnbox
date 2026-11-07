# M1 step 3: egress policy and secrets proxy

Status: done.

## Goal

Every TCP connection a sandbox opens passes a proxy on the host that checks
an egress policy and logs the connection. Secrets stay on the host: the
sandbox sees a placeholder, and the proxy adds the real value to HTTPS
requests for the hosts the secret allows.

## Egress policy

- `{"mode": "allow_all" | "allowlist" | "deny_all", "allow": [...],
  "deny": [...]}`. Patterns are a host name or `*.example.com` (any
  subdomain, not the apex). Unknown fields are rejected.
- The server default comes from `--egress-policy '<json>'` and is
  `{"mode": "allow_all"}`. A sandbox's `egress` can only narrow it: a
  connection must pass both. Builds use the server default.
- Platform blocks always apply: private, link-local (cloud metadata),
  loopback and other reserved ranges, and port 25.
- `allow_all`: TCP to any port is relayed to the address the guest asked
  for. UDP and ICMP are forwarded as before.
- `allowlist`: only TCP ports 80 and 443. The host name comes from the
  `Host` header (HTTP) or SNI (TLS). The proxy resolves that name itself
  and connects there, so a fake SNI or `Host` cannot reach another address.
  DNS works; other UDP and ICMP are dropped.
- `deny_all`: every TCP connection is refused; DNS, UDP and ICMP are
  dropped.
- Every connection is logged to stderr: sandbox, host, port, verdict,
  bytes each way, duration. DNS queries are not logged yet.

## Wiring

- In the sandbox's namespace, DNS still goes to the host resolver. The
  namespace's nftables drop UDP and ICMP for `allowlist` and `deny_all`,
  and DNS too for `deny_all`.
- On the host, TCP arriving from any `sbx*` link (except DNS) is redirected
  to the proxy port (`--egress-port`, default 15001). The proxy reads the
  original destination with `SO_ORIGINAL_DST` and finds the sandbox from
  the source address, which is unique per VM slot. A source with no
  registered sandbox is refused.
- The proxy port only accepts connections from `sbx*` links.

## Secrets

- `POST /v1/secrets` `{name, type, value, allowed_hosts, env, header,
  format, username}`. Types: `http_header` and `git_https`.
  `PATCH /v1/secrets/{name}` changes the value or settings and bumps the
  version. `GET /v1/secrets`, `GET /v1/secrets/{name}` (never the value),
  `DELETE /v1/secrets/{name}`.
- Values are encrypted in SQLite with ChaCha20-Poly1305 under a key in
  `<data-dir>/secrets.key` (created on first start, mode 0600), or
  `--secrets-key-file`. One key per install until tenants exist.
- `POST /v1/sandboxes` takes `secrets: ["name"]`. Each gets a random
  placeholder `sbx_ph_...` per sandbox, set as the secret's `env` variable.
- HTTPS to a host in a secret's `allowed_hosts` is intercepted: the proxy
  answers with a certificate signed by the install's egress CA, offers only
  HTTP/1.1, and connects to the real host with certificate checks (Mozilla
  roots). Each request's `Host` and URI must name the TLS host, or the
  connection is closed. The placeholder is replaced only in the secret's
  own header, including inside `Basic` credentials, so a server echoing
  other headers cannot reveal it; the header is set when it is missing:
  - `http_header`: `header` (default `Authorization`) set to `format` with
    `{value}` replaced (default `Bearer {value}`).
  - `git_https`: `Authorization: Basic base64(username:value)` (username
    default `x-access-token`). Works for `git clone` and `git push` with no
    credential helper.
- Plain HTTP is never given a secret. A placeholder sent anywhere else goes
  out unchanged.
- Rotation applies to the next request of running sandboxes. Each
  injection is logged with name, version, host and sandbox, never the
  value.

## Egress CA

- Created on first start: `<data-dir>/egress-ca.crt`, with its private key
  encrypted like a secret. One CA per install until tenants exist.
- Every template build installs the CA certificate into the guest's trust
  store before warmup. The CA is part of the build fingerprint.
- Sandboxes get `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`
  and `CURL_CA_BUNDLE` pointing at the system bundle, for tools that carry
  their own.

## Not in this step

`http_basic` and `ssh_key` secrets, HTTP/2 to intercepted hosts, the DNS
resolver with per-query logs and name checks, ports other than 80 and 443 in
`allowlist`, bandwidth limits, egress metering, events in the API, tenants
and per-tenant CAs, changing a running sandbox's policy.

## Done when

- Unit tests: policy matching and combining, SNI and `Host` extraction,
  header rewriting, secret encryption, database rows.
- `scripts/m1-smoke.sh` passes on the KVM host, including: allowlist allows
  and denies by name over HTTP and HTTPS, fake SNI does not escape, no-SNI
  TLS is refused, UDP is dropped; deny_all; a secret injected for an allowed
  host, not for another, never visible in the guest, and rotated; custom
  templates trust the CA.
- `scripts/m0.sh` still passes.
- README, CONTRIBUTING and the spec describe only what works.
