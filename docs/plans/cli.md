# CLI

Status: done. `scripts/cli-smoke.sh` passes on the KVM host (45 checks), and `sh` was checked on a real pseudo-terminal.

## Goal

`spawnbox` becomes a client for the HTTP API, so users stop typing `curl`.
It runs on Linux and macOS. `spawnbox doctor` stays as the host check.

## Scope

Only commands that map to endpoints that exist today:

| Command | Endpoint |
| --- | --- |
| `login` | saves URL and key to `~/.config/spawnbox/config.json` (mode 0600) after `GET /v1/sandboxes` works |
| `create`, `ls`, `get`, `kill`, `pause`, `resume` | `/v1/sandboxes` |
| `exec ID -- CMD...` | `POST .../exec` as SSE; exits with the command's exit code |
| `sh ID` | `GET .../pty` WebSocket, raw terminal, resize on SIGWINCH |
| `cp SRC DST` | `.../files`; files and directories, both directions |
| `clone ID URL` | `POST .../git:clone` |
| `ports publish/ls/rm` | `.../ports` |
| `templates build/ls/get/rm` | `/v1/templates`; `build FILE --wait` polls the build |
| `secrets set/ls/get/rm` | `/v1/secrets`; value from stdin or env, never argv |
| `tenants create/ls/get/set/rm` | `/v1/tenants` |
| `keys create/ls/rm` | `/v1/keys` |
| `events [ID] --follow` | `/v1/events`, SSE |
| `usage` | `/v1/usage` |

Global flags: `--url`, `--key` (env `SPAWNBOX_URL`, `SPAWNBOX_API_KEY`),
`--step` (sends `X-Spawnbox-Step`), `--json` (raw JSON output).

Not in scope: `fork`, `snapshot` (no API yet), YAML template files (JSON
only), SDKs, MCP, `skills install`.

## Design

- One async binary: tokio, reqwest (rustls with ring, like `spawn-api`),
  tokio-tungstenite for the terminal, crossterm for raw mode.
- `api.rs`: client, auth header, error body to `error: code: message`.
- `sse.rs`: a small SSE line parser shared by exec and events.
- Exit codes: 0 ok, 1 API or network error, 2 usage error, exec passes
  the command's exit code through (128+signal when killed).

## Tests

- Unit: SSE parser, `ID:/path` parsing, shell quoting, config file.
- Integration on the KVM host: a scripted run of every command against
  a real install.
