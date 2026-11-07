# M1 step 4: terminals, git clone, preview ports and installer

Status: done.

Differences from the plan below: the guest RPC is `Ports.Dial` (tonic
already generates a `connect` method on clients). Preview links carry a
random token kept in memory and compared by hash, not a signature; it has
the same effect, since both are lost on restart. The ::1 fallback is there
for kernels with IPv6, but the current guest kernel has none.

## Scope

The rest of M1, except the SDKs, CLI and MCP server, which wait: the HTTP
API is the interface for now.

## Terminals

- Guest `Pty.Open`: a bidirectional stream. The first message starts the
  session (`cmd`, `cwd`, `env`, `user`, `cols`, `rows`); later messages are
  input bytes or a resize. The guest replies with output bytes, then one exit.
- The process gets a new session with the PTY as its controlling terminal,
  `TERM=xterm-256color`, and runs `bash -l` unless `cmd` is given. When the
  client goes away, its process group gets SIGHUP, then SIGKILL.
- `GET /v1/sandboxes/{id}/pty?cols=&rows=&user=&cwd=&cmd=` upgrades to a
  WebSocket. Binary frames are terminal bytes both ways. Text frames are
  JSON: from the client `{"type":"resize","cols","rows"}` or
  `{"type":"input","data"}`; from the server one
  `{"type":"exit","exit_code","signal"}` or `{"type":"error","message"}`,
  then close. Auth is the API key header; browser session tokens come with
  tenants.

## Git clone

- `git` is in the base image.
- `POST /v1/sandboxes/{id}/git:clone`
  `{"url", "path", "branch", "depth", "user", "timeout_s"}` runs `git clone`
  in the sandbox and returns `{"path", "commit", "branch", "duration_ms"}`.
- Only `https://` and `http://` URLs, with no credentials in the URL.
  Attached secrets whose hosts match are injected by the egress proxy, so no
  token enters the VM. `GIT_TERMINAL_PROMPT=0`, so a missing credential
  fails fast. `path` defaults to `/workspace/<repo>`.

## Preview ports

- Guest `Ports.Connect`: a bidirectional byte stream to a TCP port inside
  the guest, tried on 127.0.0.1 then ::1, so servers bound to localhost
  work.
- `POST /v1/sandboxes/{id}/ports {"port", "access"}` publishes a port and
  returns its URL. `GET` lists, `DELETE /v1/sandboxes/{id}/ports/{port}`
  unpublishes. Ports live as long as the sandbox.
- A second listener, `--preview-listen` (default `127.0.0.1:8081`), routes
  by the first label of `Host`: `{port}-{sandbox host name}`. URLs come from
  `--preview-url` (default `http://{label}.localhost:8081`).
- Access: `public`; `token` (default): the URL carries a signed link that
  expires (`ttl_s`, default 24 h); the first visit trades it for an HttpOnly
  cookie and redirects; `private`: the API key in `Authorization`. The
  proxy removes its own credentials before forwarding. Signing keys live in
  memory: sandboxes do not survive a restart either.
- HTTP/1.1 and WebSocket (any upgrade) are forwarded. `X-Forwarded-Host` and
  `X-Forwarded-Proto` are added; `Host` is kept.

## Installer

- `deploy/install.sh` installs a single node from a source checkout on
  Ubuntu 24.04 or Debian 12+: build dependencies, Rust, the release build
  and artifacts into `/opt/spawnbox`, data in `/var/lib/spawnbox`, settings
  in `/etc/spawnbox/spawnbox.env`, and a `spawnbox` systemd unit. A first
  install prints an API key and says loudly to back up `secrets.key`.
- Running it again upgrades. `--uninstall` removes the service and binaries
  and keeps data; `--purge` also removes data.

## Not in this step

SDKs, CLI, MCP, stdin for exec, pause and resume, browser session tokens,
TLS on the preview listener, HTTP/2 previews.

## Done when

- Unit tests for preview labels, link signing, clone request checks and PTY
  messages.
- `scripts/m1-smoke.sh` passes, including a terminal session with resize, a
  clone (also in an allowlist sandbox), and a preview server bound to
  localhost with each access mode and a WebSocket echo.
- `scripts/m0.sh` passes.
- `deploy/install.sh` installs, serves a sandbox, upgrades and uninstalls
  on the KVM host.
- README, CONTRIBUTING and the spec describe only what works.
