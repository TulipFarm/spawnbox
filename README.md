<a href="https://spawnbox.tulipfarm.ai">
  <img src=".github/assets/spawnbox-hero.svg" alt="Spawnbox: sandboxes for AI agents, on your own servers" width="100%">
</a>

<div align="center">

# Spawnbox

**Open-source sandboxes for AI agents. Run them on your own servers.**

[Website](https://spawnbox.tulipfarm.ai) ·
[Get started](#getting-started) ·
[API reference](#api-reference) ·
[Releases](https://github.com/TulipFarm/spawnbox/releases) ·
[How it works](ARCHITECTURE.md) ·
[TulipFarm](https://tulipfarm.ai)

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-1d4ed8?style=flat-square)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/TulipFarm/spawnbox?style=flat-square&color=1d4ed8&label=release)](https://github.com/TulipFarm/spawnbox/releases)
[![GitHub stars](https://img.shields.io/github/stars/TulipFarm/spawnbox?style=flat-square&color=1d4ed8)](https://github.com/TulipFarm/spawnbox/stargazers)
[![Built with Rust](https://img.shields.io/badge/built_with-Rust-0a1f4d?style=flat-square&logo=rust)](Cargo.toml)
[![Runtime: Firecracker and gVisor](https://img.shields.io/badge/runtime-Firecracker_·_gVisor-0a1f4d?style=flat-square)](#how-spawnbox-works)

[![Follow on X](https://img.shields.io/badge/@TulipFarmAI-000000?style=flat-square&logo=x)](https://x.com/TulipFarmAI)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-tulipfarmai-0a66c2?style=flat-square)](https://linkedin.com/company/tulipfarmai)
[![YouTube](https://img.shields.io/badge/YouTube-@tulipfarmai-ff0000?style=flat-square&logo=youtube&logoColor=white)](https://youtube.com/@tulipfarmai)

</div>

Spawnbox is an open-source sandbox server for AI agent platforms. You
install it on your own Linux server.

A sandbox is a small, isolated Linux computer. Each sandbox is a
Firecracker microVM. On a host without KVM, each sandbox is a gVisor
container. An agent can use a sandbox to run code, read and
write files, open a terminal and show a web app. A sandbox starts in less
than 100 ms. It can connect only to the internet hosts that you allow.
Your API keys do not go into the sandbox.

> [!WARNING]
> **Status: early development (milestone M3 of M4).** Do not use Spawnbox
> for production work or for code that you do not trust. This README
> shows only the functions that operate now.

## Install in one line

On a Linux server, as your usual user (not `sudo`):

```sh
curl -fsSL https://spawnbox.tulipfarm.ai/install.sh | sh
```

Then give each agent its own box:

```sh
spawnbox create --timeout 600
spawnbox exec $S -- python3 main.py
spawnbox ports publish $S 3000
spawnbox fork $S --count 3
spawnbox pause $S
```

The full steps are in [Getting started](#getting-started).

## Tested at scale

<a href="https://spawnbox.tulipfarm.ai/#scale">
  <img src=".github/assets/spawnbox-numbers.svg" alt="6,484 sandboxes at the same time. 768 AI agents at once. About 8 ms to start. 0 failures from Spawnbox in 3,707 agent runs." width="100%">
</a>

768 coding agents ran at once, and every one finished. Each agent got its
own 2 GiB microVM, ran Claude Code, wrote a file and pushed a commit. The
fleet grew by itself from 26 to 37 servers. Measured on AWS m8i.2xlarge
workers, 10 Nov 2026.
[How we tested](https://spawnbox.tulipfarm.ai/#scale).

## Contents

- [Install in one line](#install-in-one-line)
- [Tested at scale](#tested-at-scale)
- [Why use Spawnbox](#why-use-spawnbox)
- [Features](#features)
- [Getting started](#getting-started)
- [Use the CLI](#use-the-cli)
- [How to use Spawnbox](#how-to-use-spawnbox)
- [Use more than one host](#use-more-than-one-host)
- [Back up and restore](#back-up-and-restore)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [How Spawnbox works](#how-spawnbox-works)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)
- [Links](#links)

## Why use Spawnbox

Agent products must run the code that their AI models write. This code
can be dangerous. Hosted sandbox services can run this code, but your
customers' code and data then go to a different company. Spawnbox gives
you the same service on your own servers.

- **Strong isolation.** Each sandbox is a Firecracker microVM. AWS Lambda
  uses the same technology. A sandbox does not share the kernel of the
  server. On a host without KVM, Spawnbox uses gVisor. gVisor gives a
  sandbox its own kernel in user space.
- **Fast start.** Spawnbox does not boot a new computer for each sandbox.
  It restores a saved memory snapshot. On the test server, this takes
  60 to 75 ms. With a warm pool, a create takes approximately 8 ms.
- **Many customers.** Tenants, API keys with scopes, quotas, an event log
  and usage records let one installation serve many customers.
- **Safe credentials.** The code in a sandbox sees only a placeholder for
  each secret. Spawnbox adds the real value to the HTTPS request outside
  the sandbox.

## Features

These functions operate now:

| Area | Function |
| --- | --- |
| Sandboxes | Create, list, get and delete sandboxes. Set a timeout, environment variables and labels. |
| Commands | Run commands. Get the output as JSON or as a live stream. Send stdin. |
| Files | Read, write, list and delete files and directories. |
| Terminals | Open an interactive shell through a WebSocket. |
| Browser sessions | Give a browser a short token for one sandbox. The token opens its terminal and its private preview URLs, without an API key. |
| Git | Clone `https://` repositories. Use a secret for private repositories. |
| Templates | Make your own sandbox image with `setup` and `warmup` commands. Start from the Debian base, which has Node.js 26 and Python 3.15, a container image such as `node:22`, or an image-based `devcontainer.json`. |
| Warm pools | Keep VMs ready with paused vCPUs, so that a create takes approximately 8 ms. The pool size follows the number of creates. |
| More than one host | Add worker hosts to one primary host. Clients use only the primary. The primary puts each sandbox on the host that has the most free space. Drain a worker to move its sandboxes to other hosts. Add an edge that sends commands, terminals, files and previews directly to the correct host. |
| Build store | Keep template builds in an S3-compatible object store. Get a build from the store instead of building it again. Build each template on one host only: the other hosts wait and get it from the store. Set a limit for the disk that builds use. On a Firecracker host, start a sandbox before all of its memory is on the host. |
| Two backends | Run sandboxes in Firecracker microVMs on hosts with KVM. Run them in gVisor on hosts without KVM, for example usual cloud VMs. A tenant can require microVMs. |
| Volumes | Keep files after a sandbox ends. Mount the same volume in the next sandbox. Mount one volume in many sandboxes to read only. |
| Pause and resume | Save the memory, processes and files of a sandbox to disk. Resume in approximately 65 ms. An idle sandbox pauses automatically. A new request resumes it. |
| Persistent sandboxes | Keep a sandbox until you delete it. If its VM is lost, the next request starts it again from its template, with the same ID, env, secrets, volumes and ports. One host only. |
| Fork and snapshot | Start up to 16 copies of a running sandbox, with its memory, processes and files, in less than 1 s. Save a running sandbox as a new template. The sandbox continues to run. |
| Preview URLs | Show a web app from a sandbox at a `public`, `token` or `private` URL. |
| Services | Keep programs such as web servers running in a sandbox. Restart them when they stop or fail a health check. Keep their recent output. |
| Network control | Allow all hosts, only listed hosts, or no hosts. Set a speed limit for each direction. Spawnbox records each connection and each DNS query. |
| Secrets | Keep secrets encrypted. Add them to HTTPS requests only for allowed hosts. |
| Tenants | Give each customer its own API keys, quotas, templates, secrets and network rules. |
| Events | Record each command, file change, connection and secret use. Stream events live. Send events and traces to OpenTelemetry. |
| Metrics | Show Prometheus metrics for each host: create times, errors, connections, DNS queries, sandboxes, free space and warm pools. Alert rules are included. |
| Backups | Back up the database and keys each day into one encrypted file, in a directory or S3, and restore them with a check that every secret decrypts. |
| Usage | Measure vCPU, memory, disk and network use for each tenant and sandbox, each hour. |
| CLI | Use the `spawnbox` command for sandboxes, commands, terminals, files, templates, volumes, secrets, tenants, events and usage. |
| Operation | Install with one script as a systemd service. Use HTTPS. Recover after a crash. |

These functions are not available yet:

- TypeScript and Python SDKs and an MCP server
- Disk speed limits

Until the SDKs are available, use the `spawnbox` CLI, or use the HTTP API
with `curl` or a different HTTP client.

## Getting started

In these steps, you install Spawnbox on a Linux server. Then you create
your first sandbox.

Two computers are used in these steps:

- **Your computer**: your laptop or desktop. You use it to connect to the
  host.
- **The host**: the Linux server that runs Spawnbox and the sandboxes.

Each step tells you on which computer to type the commands.

> **WARNING:** Do not use your personal computer or a production server as
> the host. Sandboxes run code that you do not trust.

> **NOTE:** You cannot run Spawnbox on macOS or Windows. You can use them
> only as "your computer" to connect to the host.

### Step 1: Get a host

Get a Linux server that agrees with these requirements:

| Item | Requirement |
| --- | --- |
| CPU | x86_64 (Intel or AMD). ARM is not supported. |
| Virtualization | KVM (`/dev/kvm`) is recommended, but it is not necessary. With KVM, sandboxes are Firecracker microVMs. Use a bare-metal server, or a cloud VM with nested virtualization, for example AWS C8i, M8i or R8i, or Google Cloud N2. Without KVM, sandboxes are gVisor containers. See [Firecracker or gVisor](#firecracker-or-gvisor). |
| Operating system | Ubuntu 22.04 or later, or Debian 12 or later |
| Memory | Minimum 4 GiB. Each sandbox uses 1 GiB by default. |
| Disk | Minimum 40 GiB free. An SSD or NVMe disk makes pause and resume faster. |
| Access | A user account with `sudo`, and internet access |

### Step 2: Connect to the host

On **your computer**, type this command. Use the user name and the IP
address of your host:

```sh
ssh ubuntu@203.0.113.10
```

> [!NOTE]
> `ubuntu` and `203.0.113.10` are examples. Replace them with the user name
> and the public IP address of your host. Your cloud console shows these
> values. For AWS EC2, the user name for Ubuntu images is `ubuntu`.

Type all the commands in steps 3 to 7 on **the host**.

### Step 3: Find out if KVM is available

1. Type this command:

   ```sh
   ls -l /dev/kvm
   ```

2. Make sure that the output shows a line like this:

   ```text
   crw-rw---- 1 root kvm 10, 232 Nov  4 10:00 /dev/kvm
   ```

3. If the output shows `No such file or directory`, KVM is not available.
   You can continue. Spawnbox then runs sandboxes in gVisor. For
   Firecracker microVMs, use a different host, or turn on nested
   virtualization for this host.

### Step 4: Install Spawnbox

> **CAUTION:** Run the installer as your usual user, not with `sudo`. The
> installer uses `sudo` when it must.

1. Type this command:

   ```sh
   curl -fsSL https://spawnbox.tulipfarm.ai/install.sh | sh
   ```

   The command downloads the latest
   [release](https://github.com/TulipFarm/spawnbox/releases), checks its
   SHA-256 sum and installs it. A release has the built programs, a Linux
   kernel for the sandboxes, a Debian disk image, Firecracker and gVisor
   (`runsc`). The installer also installs the system tools that Spawnbox
   uses, and starts the `spawnbox` systemd service. It takes about a
   minute.

   To upgrade later, type the same command again. To install a specific
   release, set `SPAWNBOX_VERSION`, for example
   `curl -fsSL ... | SPAWNBOX_VERSION=v0.1.0 sh`.

   You cannot go back to a release before the one that encrypts stored
   env. Its first start changes the database, and earlier releases then
   stop at start instead of losing the env. Back up `<data-dir>` (or the
   Postgres database) before you upgrade.

   To compile Spawnbox from the code instead, set `SPAWNBOX_FROM_SOURCE=1`.
   The command then downloads the code into `~/spawnbox`, installs the
   build tools and Rust, and compiles everything. This takes about 30
   minutes because it compiles a kernel. You can also clone the
   repository yourself and type `deploy/install.sh`.

2. Wait until the installer stops. The last lines of the output must look
   like this:

   ```text
   ==> Spawnbox is running at http://127.0.0.1:8080

   API key (shown once; ...):
   sbx_org_...
   ```

3. Copy the API key and keep it in a safe location.

   > **CAUTION:** Spawnbox shows the key only one time. If you lose it,
   > make a new key with this command:
   > `sudo /opt/spawnbox/bin/spawn-api create-key --data-dir /var/lib/spawnbox`

On a first install, the installer also starts builds of the
[coding agent templates](#ready-made-coding-agent-templates). To skip them,
set `SPAWNBOX_AGENT_TEMPLATES=0`, for example
`curl -fsSL https://spawnbox.tulipfarm.ai/install.sh | SPAWNBOX_AGENT_TEMPLATES=0 sh`.

The installer puts files in these locations:

| Location | Contents |
| --- | --- |
| `/opt/spawnbox` | Programs, kernel, base disk and template files |
| `/etc/spawnbox/spawnbox.env` | Server settings |
| `/var/lib/spawnbox` | Database, templates, paused sandboxes and secrets |

### Step 5: Make sure that Spawnbox operates

1. Type this command:

   ```sh
   curl http://127.0.0.1:8080/healthz
   ```

2. Make sure that the output is `ok`.
3. If the output is not `ok`, go to [Troubleshooting](#troubleshooting).
4. To see the backend of the host, type this command:

   ```sh
   sudo journalctl -u spawnbox | grep "sandboxes run in"
   ```

   The output shows `sandboxes run in firecracker` or
   `sandboxes run in gvisor`.

### Step 6: Create your first sandbox

1. Keep the server address and your API key in two variables. Put your
   key in place of `<your-key>`:

   ```sh
   export B=http://127.0.0.1:8080/v1
   export A="Authorization: Bearer <your-key>"
   ```

2. Create a sandbox and keep its ID in the variable `S`:

   ```sh
   S=$(curl -s -H "$A" -d '{"timeout_s": 600}' $B/sandboxes |
     python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
   echo $S
   ```

   The output shows an ID, for example `sbx_c7mty9fysaf0t3d5`.

3. Run a command in the sandbox:

   ```sh
   curl -s -H "$A" -d '{"cmd": "uname -a && whoami"}' $B/sandboxes/$S/exec
   ```

   The output is JSON. The `stdout` field shows the Linux version and the
   user name `user`.

4. Delete the sandbox:

   ```sh
   curl -s -H "$A" -X DELETE $B/sandboxes/$S
   ```

Commands in a sandbox run as `user` in the directory `/workspace`. The
user `user` can use `sudo`.

### Step 7 (optional): Use Spawnbox from your computer

The API listens only on the host (`127.0.0.1`). To use it from your
computer, make an SSH tunnel.

1. On **your computer**, open a new terminal.
2. Type this command and keep the terminal open:

   ```sh
   ssh -N -L 8080:127.0.0.1:8080 -L 8081:127.0.0.1:8081 ubuntu@203.0.113.10
   ```

3. On **your computer**, in a different terminal, use
   `http://127.0.0.1:8080` as the server address. Port 8081 gives you the
   preview URLs.

## Use the CLI

The installer puts the `spawnbox` command in `/usr/local/bin` on the host.
The CLI sends the same requests as the HTTP API.

1. On the host, keep the server address and your API key:

   ```sh
   spawnbox login --url http://127.0.0.1:8080
   ```

   The CLI asks for the key. It keeps the address and the key in
   `~/.config/spawnbox/config.json`. Only your user can read this file.

2. Create a sandbox, run a command and delete the sandbox:

   ```sh
   S=$(spawnbox create --timeout 600)
   spawnbox exec $S -- uname -a
   spawnbox kill $S
   ```

   The exit code of `spawnbox exec` is the exit code of the command.

These are the other commands:

```sh
spawnbox ls                                   # list sandboxes
spawnbox sh $S                                # open a terminal
spawnbox cp ./src $S:/workspace/src           # copy files into a sandbox
spawnbox cp $S:/workspace/out.txt .           # copy files from a sandbox
spawnbox clone $S https://github.com/octocat/Hello-World
spawnbox ports publish $S 3000                # show the preview URL
spawnbox create --service-file services.json  # start services in a new sandbox
spawnbox services $S                          # show the state of its services
spawnbox services restart $S web
spawnbox services logs $S web --follow
spawnbox pause $S
spawnbox resume $S
spawnbox fork $S --count 3                    # print the IDs of 3 copies
spawnbox snapshot $S --name with-deps         # save as a template
spawnbox templates build ./py.json            # same body as POST /v1/templates
spawnbox templates build .devcontainer/devcontainer.json --devcontainer --name web
spawnbox secrets set openai --hosts api.openai.com --env OPENAI_API_KEY
spawnbox volumes create work --size 5         # a 5 GiB volume
spawnbox create -v work:/data                 # mount it at /data
spawnbox create -v work:/data:ro              # mount it to read only
spawnbox tenants create acme
spawnbox keys create --tenant acme --name acme-prod
spawnbox events --follow
spawnbox usage
```

To see all the options of a command, type `spawnbox <command> --help`. To
get JSON output, add `--json`. To use the CLI from your computer, build it
with `cargo build --release -p spawnbox-cli` and use the SSH tunnel from
step 7.

You can also set the server address and the key with the environment
variables `SPAWNBOX_URL` and `SPAWNBOX_API_KEY`.

## How to use Spawnbox

Type these commands on the host, or on your computer with the SSH tunnel
from step 7. The examples use the variables `A`, `B` and `S` from step 6.

### Run commands

```sh
# Get the result as JSON: stdout, stderr, exit_code and duration_ms
curl -s -H "$A" -d '{"cmd": "ls -la", "cwd": "/tmp"}' $B/sandboxes/$S/exec

# Send data to stdin
curl -s -H "$A" -d '{"cmd": "wc -l", "stdin": "a\nb\n"}' $B/sandboxes/$S/exec

# Get the output live, as server-sent events
curl -N -H "$A" -H "Accept: text/event-stream" \
  -d '{"cmd": "for i in 1 2 3; do echo $i; sleep 1; done"}' $B/sandboxes/$S/exec

# Start a background process that continues after the request ends
curl -s -H "$A" -d '{"cmd": "setsid python3 -m http.server 3000 >/dev/null 2>&1 &"}' \
  $B/sandboxes/$S/exec
```

### Read and write files

```sh
curl -s -H "$A" -X PUT --data-binary @main.py "$B/sandboxes/$S/files?path=main.py"
curl -s -H "$A" "$B/sandboxes/$S/files?path=main.py"        # file contents
curl -s -H "$A" "$B/sandboxes/$S/files?path=/workspace"     # directory list as JSON
curl -s -H "$A" -X DELETE "$B/sandboxes/$S/files?path=old&recursive=true"
```

### Make your own template

A template is a start image for sandboxes. Spawnbox runs the `setup`
commands one time. Then it saves a snapshot. Sandboxes from your template
start as fast as sandboxes from the `base` template.

1. Create the template:

   ```sh
   curl -s -H "$A" $B/templates -d '{
     "name": "py",
     "setup": ["apt-get update && apt-get install -y build-essential", "pip install requests"],
     "env": {"PYTHONUNBUFFERED": "1"},
     "resources": {"vcpus": 2, "memory_mib": 2048, "disk_gib": 20}
   }'
   ```

2. Get the template. Do this again until `latest_build.state` is `ready`:

   ```sh
   curl -s -H "$A" $B/templates/py
   ```

3. Create a sandbox from the template:

   ```sh
   curl -s -H "$A" -d '{"template": "py"}' $B/sandboxes
   ```

> **NOTE:** The base disk is Debian 13 with Node.js 26.13.1 (with npm) and
> Python 3.15.2 (with pip) in `/usr/local`. It has no apt package lists.
> Run `apt-get update` before you install packages.

### Ready-made coding agent templates

The `templates/` directory has template files for three coding agent
CLIs. Each file installs one pinned npm package on the base disk:

| File | Package | Command |
| --- | --- | --- |
| `templates/claude-code.json` | `@anthropic-ai/claude-code@2.1.322` | `claude` |
| `templates/codex.json` | `@openai/codex@0.167.2` | `codex` |
| `templates/copilot.json` | `@github/copilot@1.0.109` | `copilot` |

A first install starts a build of each template in the background. The
builds take a few minutes, one time for each server. Builds stay after a
restart. Then each sandbox starts from the saved snapshot, as fast as a
sandbox from `base`:

```sh
spawnbox templates ls                   # wait until the build is ready
spawnbox create --template claude-code
```

The installer copies the files to `/opt/spawnbox/templates`. If you
upgraded from an older version, or the install skipped the builds, build a
template with the CLI:

```sh
spawnbox templates build /opt/spawnbox/templates/claude-code.json
```

Each template uses 2 vCPUs, 4096 MiB of memory and 20 GiB of disk. To get a
newer agent, change the version in the file and build it again.

Give the agent its API key as a held secret, so the real key never enters
the sandbox:

```sh
# Claude Code sends the key in the x-api-key header.
curl -s -H "$A" $B/secrets -d '{
  "name": "anthropic", "type": "http_header", "value": "sk-ant-...",
  "allowed_hosts": ["api.anthropic.com"], "env": "ANTHROPIC_API_KEY",
  "header": "x-api-key", "format": "{value}"
}'
curl -s -H "$A" -d '{"template": "claude-code", "secrets": ["anthropic"]}' $B/sandboxes
```

For Codex, use the `openai` secret from
[Use a secret safely](#use-a-secret-safely) (`OPENAI_API_KEY`).

> **NOTE:** The held-secret setup for Copilot CLI is not documented here,
> because the hosts that it sends its token to are not verified.

### Start a template from a container image

Set `base` to a container image. Spawnbox gets the image inside a builder
VM, not on the host. Then it runs `setup` and saves a snapshot, as for
other templates.

```sh
curl -s -H "$A" $B/templates -d '{
  "name": "node22",
  "base": "node:22-bookworm-slim",
  "setup": ["npm install -g pnpm"],
  "resources": {"disk_gib": 10}
}'
```

- Use an image for `linux/amd64`. Use a digest, for example
  `node@sha256:...`, to always get the same image. Spawnbox reads a tag
  only when it builds the template.
- The image environment variables (`ENV`) are set in each sandbox.
- Spawnbox ignores the image `ENTRYPOINT`, `CMD`, `USER` and `WORKDIR`.
  Commands run as `user` (UID 1000) in `/workspace`. `setup` commands run
  as root.
- The image must have `/bin/sh`. The unpacked image must fit in
  `disk_gib`.
- The tenant's network rules apply to the image download.
- For a private registry, make a held secret for the registry host (for
  example an `http_header` secret with `Authorization: Basic ...`). Put its
  name in `registry_secrets`. Spawnbox adds it only while it gets the
  image. You can set a maximum of 4.

#### Use a devcontainer.json

The CLI changes an image-based `devcontainer.json` into a template:

```sh
spawnbox templates build .devcontainer/devcontainer.json --devcontainer --name web
```

- `image` becomes `base`. `containerEnv` and `remoteEnv` become `env`.
- `onCreateCommand`, `updateContentCommand` and `postCreateCommand` become
  `setup` commands. They run as root.
- The CLI refuses `build`, `dockerFile`, `dockerComposeFile` and
  `features`. It refuses values with `${...}`.
- The CLI shows the other fields that it ignores, for example
  `forwardPorts`.

### Keep builds in an object store

Spawnbox can save each template build in an S3-compatible object store, for
example Amazon S3, Cloudflare R2, Garage or SeaweedFS. Then:

- When you make a template again with the same settings, Spawnbox gets the
  build from the store. This is faster than a new build.
- If the build files on the host are lost, Spawnbox gets them from the
  store.
- You can set a limit for the disk that builds use on the host.

1. Make a bucket in your object store, for example `spawnbox-builds`.
2. On the host, open the settings file:

   ```sh
   sudo nano /etc/spawnbox/spawnbox.env
   ```

3. Add `--build-store s3://spawnbox-builds/builds` to the `SPAWNBOX_ARGS`
   line.
4. Add the access settings of your object store on new lines. Use your
   values:

   ```sh
   AWS_ENDPOINT=https://s3.example.com
   AWS_REGION=us-east-1
   AWS_ACCESS_KEY_ID=your-access-key
   AWS_SECRET_ACCESS_KEY=your-secret-key
   ```

   For Amazon S3, do not add `AWS_ENDPOINT`. For a store without HTTPS,
   also add `AWS_ALLOW_HTTP=true`.

5. Optional: to limit the disk that builds use, add
   `--build-cache-gib 50` to the `SPAWNBOX_ARGS` line.
6. Save the file and restart the service:

   ```sh
   sudo systemctl restart spawnbox
   ```

7. Make sure that the build store operates:

   ```sh
   sudo journalctl -u spawnbox -n 50 | grep "build store"
   ```

   After each new build, the log shows `saved to the build store`.

> **NOTE:** With `--build-cache-gib`, Spawnbox removes builds from the host
> when the disk is more than the limit. It removes only builds that are in
> the store and that nobody used in the last 10 minutes. The next sandbox
> from such a template waits while Spawnbox gets the build (approximately
> 5 seconds for 1 GiB).

> **NOTE:** With a build store, only one host builds a new template. That
> host writes a claim object under `<prefix>/claims/`. The other hosts log
> `is being built on another host; waiting` and get the build from the
> store when it is there. If the host that builds stops, the other hosts
> wait until its claim is 3 minutes old. Then one of them builds the
> template. The store must support create-only writes
> (`If-None-Match: *`). If it does not, the log shows a warning and each
> host builds the template.

> **NOTE:** A worker that joins gets the templates with the most sandboxes
> in the last 7 days first. If its builds already use all of
> `--build-cache-gib`, it does not download more builds. It gets each one
> from the store when a sandbox first uses it.

> **NOTE:** On a Firecracker host, the first sandbox from a build that is
> only in the store does not wait for all of the memory. Spawnbox gets the
> disks, starts the sandbox, and gets the memory while it runs. The parts
> that the sandbox asks for come first. If a part is not available for 30
> seconds, Spawnbox stops the sandbox. Its state becomes `failed`, and it
> gets a `sandbox.lost` event. A pause or a fork of such a sandbox waits
> until its memory is on the host.

> **NOTE:** If a sandbox's VM stops on its own, for example because the
> guest crashed, Spawnbox notices within a second. The sandbox's state
> becomes `failed`, it gets a `sandbox.lost` event, and calls to it return
> `409 conflict`. A warm VM that stopped is replaced by a normal start.

> **NOTE:** Spawnbox deletes objects in the store that no host used for 7
> days. Do not keep other data under the same prefix.

### Open a terminal

Install [websocat](https://github.com/vi/websocat). Then type:

```sh
websocat -H "$A" --binary "ws://127.0.0.1:8080/v1/sandboxes/$S/pty?cols=120&rows=40"
```

Type `exit` to close the terminal.

### Open a terminal or a private preview in a browser

Do not give your API key to a browser. Get a session token for one
sandbox from your server, and give the token to the browser. A token
opens one thing: the terminal, or the `private` preview of one port.

```sh
curl -s -H "$A" -d '{"ttl_s": 900, "audience": "terminal"}' $B/sandboxes/$S/session-tokens
curl -s -H "$A" -d '{"ttl_s": 900, "audience": "preview", "port": 3000}' \
  $B/sandboxes/$S/session-tokens
```

- For the terminal, the browser opens
  `ws://127.0.0.1:8080/v1/sandboxes/$S/pty?session_token=<token>`.
- For a `private` preview URL, add `?spawnbox_session=<token>` to the
  URL. At the first visit, the token becomes a cookie.

The token stops after `ttl_s` seconds (maximum 900). It also stops when
you revoke the API key that made it.

### Clone a repository

```sh
curl -s -H "$A" -d '{"url": "https://github.com/octocat/Hello-World", "depth": 1}' \
  $B/sandboxes/$S/git:clone
```

### Show a web app with a preview URL

1. Start a web server in the sandbox. The server can listen on
   `127.0.0.1`.
2. Publish its port:

   ```sh
   curl -s -H "$A" -d '{"port": 3000}' $B/sandboxes/$S/ports
   ```

3. Open the `url` from the output in your browser.

### Keep a program running with a service

A service is a program that Spawnbox keeps running in the sandbox. Give
the services when you create the sandbox:

```sh
curl -s -H "$A" $B/sandboxes -d '{
  "services": [{
    "name": "web",
    "command": ["python3", "-m", "http.server", "8000"],
    "cwd": "/workspace",
    "env": {"LOG_LEVEL": "info"},
    "port": 8000,
    "access": "private",
    "health": {"http": "/", "interval_s": 10, "failures": 3},
    "restart": "always"
  }]
}'
```

- Spawnbox starts each service as `user`, with the env of the sandbox
  and then the env of the service.
- If a service stops, Spawnbox starts it again. It waits 1 s, then 2 s,
  4 s and up to 30 s. After 60 s of good operation, the wait is 1 s
  again. With `"restart": "on-failure"`, a service that exits with code 0
  stays stopped.
- A health check is `{"http": "/path"}` (a `GET` must give a 2xx status)
  or `{"tcp": true}` (the port must accept a connection). If the check
  fails `failures` times one after the other, Spawnbox restarts the
  service.
- Spawnbox publishes the `port` of a service with its `access` (default
  `private`). A preview request waits up to 30 s for the service to be
  healthy.
- The last 1 MiB of output of each service is in
  `/var/log/spawnbox/<name>.log` in the sandbox.
- A pause keeps the services and their processes. A resume does not
  restart them. A cold start of a persistent sandbox starts them again.
- Sandboxes from a template made before services were added cannot have
  services. The create gives `409 conflict`. Build the template again.

### Pause and resume a sandbox

```sh
curl -s -H "$A" -X POST $B/sandboxes/$S:pause    # releases CPU and memory
curl -s -H "$A" -X POST $B/sandboxes/$S:resume   # processes continue
```

Usually, you do not need these commands. A sandbox pauses automatically
after 10 minutes without requests. The next exec, file, terminal, clone or
preview request resumes it.

### Keep a sandbox until you delete it

```sh
S=$(curl -s -H "$A" -d '{"persistent": true}' $B/sandboxes | jq -r .id)
```

A persistent sandbox has no timeout. It pauses after 10 minutes without
requests and stays paused until the next request. Paused retention does
not delete it.

If Spawnbox cannot keep its memory, the sandbox becomes `cold`. This
occurs when the server crashes, the VM stops on its own, a pause or a
resume fails, the `snapshot_storage_gib` quota has no room for its idle
pause, or the server stops before the sandbox can pause. The `sandbox.cold`
event has the reason. The next
exec, file, terminal, clone, preview or resume request starts it again
from its template build. The processes and the files outside its volumes
are gone. Its ID, env, secrets, network rules, volumes and published
ports are the same.

A tenant needs the `persistent_sandboxes` quota. It is `0` by default.
Persistent sandboxes are created on the primary, and you cannot move
them. In a fleet, a cold sandbox can start again on any worker that has
its template build. Refer to [Fence lost hosts](#fence-lost-hosts). To
run one on another host, let it become cold: it then starts on the host
that takes the next call, from a build of that host.

#### Upgrades and old builds

The guest in a sandbox is part of its template build. A host accepts
guests up to two minor versions older or newer than its own. A
persistent sandbox can live longer than that, and the host that starts
it can lack its build, for example after a leader failover. So:

- A paused persistent sandbox whose guest the host no longer accepts is
  not resumed. It becomes `cold` with the reason `guest_too_old`, and the
  call starts it again from its start record.
- A cold start uses the recorded build if this host has it, or can get it
  from the build store, and accepts its guest. If not, it uses a ready
  build of this host made from the same template spec, or builds that
  spec again with the current guest, as a template rebuild does. The
  sandbox then starts from that build from now on, and the event
  `sandbox.rebuilt` shows `from_build`, `to_build` and the `reason`:
  `missing` (no host file and not in the store), `outdated` (made with
  another kernel, base disk or runtime) or `guest_too_old`.
- Cold starts on one host that need the same spec wait for one build.
  On the primary, the call waits up to 60 seconds for it. When the
  sandbox starts on a worker, the call does not wait. In both cases, the
  call gives `503 rebuilding` while the build goes on; try again.
- If the spec cannot be built, the call gives `409 build_failed` with the
  error, and the sandbox stays `cold`. The same error is given for the
  next 5 minutes, then the next call builds again. If a worker cannot
  build the spec, the primary starts the sandbox itself, and does not ask
  that worker to build the spec again for 5 minutes. A sandbox from a
  snapshot template cannot be built again on another host or version.
- When a paused sandbox on a worker becomes `cold` this way, the worker
  tells the primary at once, and the primary starts the sandbox again for
  the same call. If that takes too long, the call gives
  `503 sandbox_cold`; try again.

### Fork a sandbox or save it as a template

```sh
curl -s -H "$A" -d '{"count": 3}' $B/sandboxes/$S:fork
curl -s -H "$A" -d '{"name": "with-deps"}' $B/sandboxes/$S:snapshot
curl -s -H "$A" -d '{"template": "with-deps"}' $B/sandboxes
```

Each copy starts with the files and the running processes of `$S`. `$S`
continues to run. Use a fork to try different changes from the same
point. Use a snapshot when you will need the same state again later.

### Keep files in a volume

The files of a sandbox go away when you delete the sandbox. To keep files,
put them in a volume. A volume is a disk with a name. It stays until you
delete it.

1. Create a volume of 5 GiB:

   ```sh
   curl -s -H "$A" $B/volumes -d '{"name": "work", "size_gib": 5}'
   ```

2. Create a sandbox that mounts the volume at `/data`, and write a file:

   ```sh
   S=$(curl -s -H "$A" $B/sandboxes -d '{
     "volumes": [{"volume": "work", "path": "/data"}]
   }' | jq -r .id)
   curl -s -H "$A" $B/sandboxes/$S/exec -d '{"cmd": "echo hello > /data/note"}'
   ```

3. Delete the sandbox. Then create a new sandbox with the same volume. The
   file `/data/note` is there.

Rules:

- One sandbox can write to a volume at a time.
- Many sandboxes can mount a volume with `"read_only": true` at the same
  time. They cannot do this while a sandbox writes to the volume.
- If a volume is in use, the response is `409`.
- A sandbox can mount 1 to 4 volumes.
- The user `user` owns the files on a new volume.
- A volume keeps its data when the sandbox pauses, resumes or moves to a
  different host.
- A volume works only with the backend of the first sandbox that mounted
  it: Firecracker or gVisor.

> **CAUTION:** A volume is on the disk of one host. Spawnbox does not
> make a backup copy. If you lose the host, you lose the volume.

### Control network access

This sandbox can connect only to `github.com` and to subdomains of
`pypi.org`:

```sh
curl -s -H "$A" $B/sandboxes -d '{
  "egress": {"mode": "allowlist", "allow": ["github.com", "*.pypi.org"]}
}'
```

### Use a secret safely

1. Save the secret:

   ```sh
   curl -s -H "$A" $B/secrets -d '{
     "name": "openai", "type": "http_header", "value": "sk-...",
     "allowed_hosts": ["api.openai.com"], "env": "OPENAI_API_KEY"
   }'
   ```

2. Create a sandbox with the secret:

   ```sh
   curl -s -H "$A" -d '{"secrets": ["openai"]}' $B/sandboxes
   ```

In the sandbox, `$OPENAI_API_KEY` contains a placeholder, for example
`sbx_ph_...`. When code sends an HTTPS request to `api.openai.com`,
Spawnbox puts the real key in the request. Other hosts get only the
placeholder.

### Serve many customers

Use your org key to create a tenant and a key for that tenant. The tenant
key can see only the sandboxes of its tenant.

```sh
curl -s -H "$A" $B/tenants -d '{"id": "acme", "name": "Acme",
  "quotas": {"running_sandboxes": 5, "monthly_egress_bytes": 10000000000}}'
curl -s -H "$A" $B/keys -d '{"tenant": "acme", "name": "acme-prod"}'
```

### Firecracker or gVisor

Spawnbox has two backends. A backend is the technology that isolates a
sandbox. Each host uses one backend for all its sandboxes.

| Item | Firecracker | gVisor |
| --- | --- | --- |
| Host | Needs KVM | Does not need KVM. A usual cloud VM is sufficient. |
| Isolation | Each sandbox is a microVM with its own Linux kernel. The CPU hardware isolates it. | Each sandbox has the gVisor kernel. This kernel is a program on the host that does the system calls of the sandbox. This isolation is less strong than a microVM. |
| Linux functions | All | Most. Some programs that use special kernel functions do not operate, for example programs that load kernel modules. |
| API and functions | All | All. Pause, resume, warm pools and moves between hosts operate the same. |

Spawnbox selects the backend when it starts:

- If Spawnbox can open `/dev/kvm`, it uses Firecracker.
- If it cannot open `/dev/kvm`, it uses gVisor.

To select a backend yourself, add `--backend firecracker` or
`--backend gvisor` to the settings. Refer to [Configuration](#configuration).

To see the backend of a host, type this command on the host:

```sh
sudo journalctl -u spawnbox | grep "sandboxes run in"
```

Some customers must have microVM isolation. Set `isolation` of their
tenant to `microvm-only`:

```sh
curl -s -H "$A" -X PATCH $B/tenants/acme -d '{"isolation": "microvm-only"}'
```

Then Spawnbox puts the sandboxes of this tenant only on Firecracker hosts.
If no Firecracker host has space, a create gives `503 no_capacity`. The
default value of `isolation` is `any`.

### See events and usage

```sh
# Tag a request with the step ID of your agent, then find its events
curl -s -H "$A" -H "X-Spawnbox-Step: tool-call-42" -d '{"cmd": "make"}' $B/sandboxes/$S/exec
curl -s -H "$A" "$B/events?step_id=tool-call-42"

# Stream all new events
curl -N -H "$A" "$B/events?follow=true"

# Get the usage for this month, for each sandbox
curl -s -H "$A" "$B/usage?group_by=sandbox"
```

### See metrics in Prometheus

Start the server with `--metrics-listen 127.0.0.1:9464`. Then each host
shows Prometheus metrics at `http://127.0.0.1:9464/metrics`. This address
has no authentication. Use only a private address.

```sh
curl -s http://127.0.0.1:9464/metrics | grep spawnbox_create_seconds_count
```

Each metric is about the host that shows it. On a fleet, scrape each host.
Prometheus adds the `instance` label.

| Metric | Labels | Meaning |
| --- | --- | --- |
| `spawnbox_create_seconds` (histogram) | `path` (`warm`, `cached`, `cold`), `backend` | Time to create a sandbox. `cold` means that the host got the build from the build store first. |
| `spawnbox_create_step_seconds` (histogram) | `step` (`prepare`, `restore`, `fixups`), `backend` | Time of each step of a create |
| `spawnbox_api_errors_total` | `code` | Error responses |
| `spawnbox_egress_connections_total` | `verdict` | Connections from sandboxes and template builds |
| `spawnbox_dns_queries_total` | `verdict` | DNS queries from sandboxes and template builds |
| `spawnbox_sandboxes` (gauge) | `state` | Sandboxes on the host that are `starting`, `running`, `paused` or `cold` |
| `spawnbox_node_committed_ratio` (gauge) | `resource` (`slots`, `memory`) | Part of the host in use, from 0 to 1 |
| `spawnbox_warm_pool_ready` (gauge) | `template`, `build`, `network` | Warm VMs ready |
| `spawnbox_warm_pool_hits_total`, `spawnbox_warm_pool_misses_total` | `build` | Creates that got or did not get a warm VM |
| `spawnbox_fleet_nodes` (gauge) | `state` | Primary only: workers in each state |
| `spawnbox_fleet_load` (gauge) | None | Primary only: load of the primary and the ready workers that are not drained, from 0 to 1 |
| `spawnbox_service_restarts_total` (counter) | `reason` | Restarts of services |
| `spawnbox_fleet_create_refused_total` (counter) | `reason` | Primary only: creates refused with `no_capacity` |
| `spawnbox_self_fences_total` (counter) | `reason` (`self_fenced`, `lease_lost`) | Times this host stopped its persistent sandboxes because it lost the primary or its lease |
| `spawnbox_fenced_cold_total` (counter) | `reason` | Primary only: persistent sandboxes of a lost host that became `cold`, by proof (`operator`, `autoscaler`, `self_fence`, `failover`) |
| `spawnbox_stale_copies_total` (counter) | None | Copies of persistent sandboxes from an older generation that a host deleted |
| `spawnbox_sandbox_rebuilds_total` (counter) | `reason` (`missing`, `outdated`, `guest_too_old`) | Cold starts of persistent sandboxes that used a new build of their template spec, because the recorded build could not be used |
| `spawnbox_fleet_retirements` (gauge) | `state` | Primary only: workers that retire, in each state (`draining`, `blocked`, `ready_to_terminate`) |
| `spawnbox_creates_total` (counter) | `result` (`ok` or an error code) | Create calls, by result |
| `spawnbox_cold_starts_total` (counter) | `result` (`ok` or an error code) | Cold starts of persistent sandboxes on this host, by result |
| `spawnbox_cold_start_seconds` (histogram) | None | Time of each cold start that worked |
| `spawnbox_leader_term` (gauge) | None | The term of the database lease this server holds as the primary. Only the leader shows it. It goes up at each failover. |
| `spawnbox_data_dir_available_bytes`, `spawnbox_data_dir_size_bytes` (gauges) | None | Free space and size of the file system of `--data-dir` |
| `spawnbox_start_time_seconds` (gauge) | None | When this server process started, in seconds since the Unix epoch. It changes at each restart. |

[`deploy/prometheus/spawnbox-alerts.yml`](deploy/prometheus/spawnbox-alerts.yml)
has alert rules for these metrics. Each alert is described, with its likely
cause and first response, in
[`deploy/prometheus/README.md`](deploy/prometheus/README.md).

## Use more than one host

You can run sandboxes on more than one host. One host is the **primary**.
The other hosts are **workers**.

- Your clients send all requests to the primary. They use the same URL and
  the same API keys as before.
- The primary also runs sandboxes. For each new sandbox, it selects a host.
  It selects a host with a warm VM first, then the host with the most free
  memory.
- The primary sends each request for a sandbox to the host of the sandbox.
- You make tenants, keys, secrets and templates only on the primary. The
  primary copies them to the workers. Each worker builds the templates
  itself.
- Workers send their events and usage to the primary. `GET /v1/events` and
  `GET /v1/usage` on the primary show the data of all hosts.

The hosts talk on two ports, with HTTPS and certificates on the two sides
(mutual TLS):

| Port | On | Function |
| --- | --- | --- |
| 7443 | Primary | Workers join and send reports |
| 7444 | Each worker | The primary sends requests for sandboxes |

> **WARNING:** Use a private network between the hosts. Do not open ports
> 7443 and 7444 to the internet.

### Step 1: Prepare the hosts

1. Install Spawnbox on each host. Do the steps in
   [Getting started](#getting-started) on each host.
2. Make sure that the hosts can connect to each other on ports 7443 and
   7444. On AWS, add an inbound rule to the security group of the hosts:
   type **All TCP**, source **the same security group**.
3. Find the private IP address of each host. On each host, type:

   ```sh
   hostname -I
   ```

   In these steps, the primary is `10.0.0.1` and the worker is `10.0.0.2`.
   Use your addresses.
4. To move sandboxes between hosts (refer to
   [Drain a worker](#drain-a-worker-and-move-its-sandboxes)), all hosts
   must have the same backend, the same files and the same CPU model. Copy
   `/opt/spawnbox/vmlinux` and `/opt/spawnbox/rootfs.ext4` from the
   primary to each worker. Do not build these files again on each host.
   Each build gives different bytes. Copy to a new file name, then use
   `sudo mv` to replace the old file. Do not write into the old file:
   paused sandboxes and builds use it. Then restart the worker. Install
   the same Spawnbox release on all hosts.
5. You can mix Firecracker hosts and gVisor hosts in one fleet. Sandboxes
   of a `microvm-only` tenant go only to Firecracker hosts. Refer to
   [Firecracker or gVisor](#firecracker-or-gvisor).

### Step 2: Make the primary

Type these commands on the primary.

1. Open the settings file:

   ```sh
   sudo nano /etc/spawnbox/spawnbox.env
   ```

2. Add `--fleet-listen 10.0.0.1:7443` to the `SPAWNBOX_ARGS` line.
3. Save the file and restart the service:

   ```sh
   sudo systemctl restart spawnbox
   ```

4. Make a join token. The token is valid for one hour and for one worker
   only:

   ```sh
   curl -s -H "$A" -X POST http://127.0.0.1:8080/v1/nodes/tokens
   ```

   The response has `token` and `ca_sha256`. Keep them for step 3.

### Step 3: Add a worker

Type these commands on the worker.

1. Open the settings file:

   ```sh
   sudo nano /etc/spawnbox/spawnbox.env
   ```

2. Replace the `SPAWNBOX_ARGS` line with these lines. Use your addresses,
   and the `token` and `ca_sha256` from step 2. Use the same
   `--preview-url` as the primary.

   ```sh
   SPAWNBOX_ARGS="--preview-url http://{label}.localhost:8081 --primary https://10.0.0.1:7443 --node-listen 10.0.0.2:7444 --advertise https://10.0.0.2:7444 --primary-ca-sha256 CA_SHA256"
   SPAWNBOX_JOIN_TOKEN=TOKEN
   ```

3. Save the file and restart the service:

   ```sh
   sudo systemctl restart spawnbox
   ```

4. Make sure that the worker joined:

   ```sh
   sudo journalctl -u spawnbox -n 20 | grep "fleet worker"
   ```

   The log shows `fleet worker nod_...`.

5. On the primary, make sure that the worker is `ready`:

   ```sh
   curl -s -H "$A" http://127.0.0.1:8080/v1/nodes
   ```

A worker uses the token only one time. After this, it uses its
certificate in `/var/lib/spawnbox/fleet/worker/`.

> **NOTE:** A worker does not take API requests from clients. It does not
> use `--listen` and `--preview-listen`.

### What occurs when a host stops

- **No report from a worker for 15 seconds.** The primary puts no new
  sandboxes on it.
- **No report for 30 seconds.** The state of the worker becomes `down`.
  Requests for its sandboxes give `503 node_unreachable`. Try again
  later. When the worker comes back, its sandboxes operate again.
- **A worker restarts.** Its running sandboxes are deleted, as on one
  host. Its paused sandboxes stay. To keep the running sandboxes,
  [drain the worker](#drain-a-worker-and-move-its-sandboxes) before you
  restart it.
- **Persistent sandboxes on a `down` worker** stay on that worker until
  Spawnbox knows that their VMs are stopped. Refer to
  [Fence lost hosts](#fence-lost-hosts).

### Fence lost hosts

A `down` worker can still run its VMs: maybe only its network to the
primary is cut. If Spawnbox started a persistent sandbox again on a
different host, two copies of its programs could run. So a persistent
sandbox of a `down` or removed worker becomes `cold` only when one of
these proves that its VM is stopped:

- The worker comes back and reports the sandbox stopped or missing.
- The fleet uses `--self-fence`, and `--fence-after-s` plus
  `--fence-margin-s` passed since the last report of the worker.
- The autoscaler hook removed the machine of the worker.
- You tell the primary that the host is off:

  ```sh
  curl -s -H "$A" -X POST http://127.0.0.1:8080/v1/nodes/NODE_ID:fenced \
    -d '{"reason":"machine powered off"}'
  ```

  Do this only after you stop the machine. The primary records the
  `node.fenced` event with your key.

`DELETE /v1/nodes/{id}` and the `down` state alone prove nothing. Until
there is a proof, requests for these sandboxes give
`503 node_unreachable`.

**Self-fencing.** A worker with `--self-fence` that cannot reach the
primary for `--fence-after-s` seconds (default 60) stops all its
persistent VMs. Each one becomes `cold` on the worker, with a
`sandbox.fenced` event. Other sandboxes continue to run. Add
`--self-fence` to every worker: each worker tells the primary if it uses
the flag, and the primary waits for a time only for the workers that do.

```sh
SPAWNBOX_ARGS="... --primary https://10.0.0.1:7443 --self-fence --fence-after-s 60"
```

On the primary, `--fence-margin-s` (default 30) is the time to add for
clocks and slow hosts. The worker counts from when it sent its last
heartbeat that got an answer, and the primary from when it got that
heartbeat, so the worker always fences first. Keep the margin above 10
seconds: a worker can take a few seconds to see the fence time and stop
its VMs.

**When the server process dies.** VMs run in their own cgroups, outside
the `spawn-api` process and its systemd service, so they would keep
running after a crash. The time proofs above need them stopped. So
`spawn-api serve` starts a small guard process, `spawn-api guard`, before
any VM. When the server process ends in any way, also with `kill -9`, the
out-of-memory killer or a crash, the guard kills all the VMs of the host
within about a second. A normal stop with `SIGTERM` stops the VMs first
and then tells the guard to exit. The guard is in its own cgroup,
`/sys/fs/cgroup/spawnbox-guard`, and ignores `SIGINT` and `SIGTERM`, so
stopping the service does not stop it too early. If the guard cannot
start, a server with `--self-fence`, `--fleet-listen` or `--database-url`
does not start. If the guard stops while such a server runs, the server
kills its VMs and exits.

**Generations.** Each cold start adds 1 to the `generation` of the
sandbox. A host runs a sandbox only for the generation that the primary
gave it. When a worker comes back with an older copy, the primary tells
it to delete that copy (`sandbox.fenced` with the reason
`stale_generation`). The old copy never resumes.

**Where a cold sandbox starts.** Calls for a `cold` or `starting`
sandbox go to the primary, also through an edge. The primary checks the
key, starts the sandbox on a host with its template build and room, then
forwards the call. Previews start it on the primary. If the start on a
worker fails before the worker got it, the primary starts it on itself.

### Keep the API up when the primary stops

With one primary, the API stops when the primary stops. To prevent this,
run two or more primaries on one Postgres database. One primary is the
**leader** and serves the API. The others are **standbys**: they wait and
do not listen on any port. When the leader stops, a standby becomes the
leader in about 15 seconds. The new leader serves at once and builds its
own copy of the `base` template in the background; until that is ready,
new sandboxes start on workers.

1. Make a Postgres 15 (or later) database, for example on Amazon RDS.
2. Copy `/var/lib/spawnbox/secrets.key` from the primary to the same path
   on each standby host. All primaries must use the same key.
3. On each primary, add the database to `/etc/spawnbox/spawnbox.env`:

   ```sh
   SPAWNBOX_DATABASE_URL=postgres://spawnbox:PASSWORD@db.internal:5432/spawnbox
   ```

   Also add `--fleet-listen` to `SPAWNBOX_ARGS`, as in
   [step 2](#step-2-make-the-primary).
4. To keep the data of an existing primary, add
   `--import-sqlite /var/lib/spawnbox/spawnbox.db` on that primary for its
   first start. It copies the data only when the database is empty.
5. Start the primaries. The first one to start becomes the leader.
6. Put a load balancer in front of the primaries, with a health check on
   `GET /healthz`. Only the leader passes it.
7. On workers and edges, give each primary in `--primary`, separated by
   commas:

   ```sh
   --primary https://10.0.0.1:7443,https://10.0.0.5:7443
   ```

The leader keeps the fleet CA, the egress CA and the browser session key
in the database, encrypted with the secrets key. A new leader uses the
same ones, so workers and browser sessions continue to operate.

When a standby becomes the leader:

- Sandboxes on workers continue to run.
- Sandboxes that ran on the old leader are lost. Paused sandboxes whose
  files were on the old leader are marked `failed`.
- Volumes whose file was on the old leader are lost.
- Persistent sandboxes of the old leader become `cold` after
  `--fence-after-s` plus `--fence-margin-s`. Until then, requests for them
  give `409`. The next request starts them on the new leader, or on a
  worker. If that host lacks their build, it builds their template spec
  again first. Refer to [Upgrades and old builds](#upgrades-and-old-builds).
- If the leader cannot reach the database for 6 seconds, or another
  primary took its lease, it stops taking requests, kills all its VMs and
  exits, before its lease ends. So two primaries never serve at the same
  time.

To use TLS with a certificate check, give the CA of the database in
`--database-ca-file`. Without it, the connection uses TLS if the server
offers it, but accepts any certificate.

### Drain a worker and move its sandboxes

Do these steps before you update, restart or remove a worker. Type the
commands on the primary.

1. Drain the worker. The primary puts no new sandboxes on it, and moves
   its sandboxes to other hosts:

   ```sh
   curl -s -H "$A" -d '{"migrate":true}' http://127.0.0.1:8080/v1/nodes/NODE_ID:drain
   ```

   To stop only new sandboxes, and not move the sandboxes, use
   `{"migrate":false}`.

2. Wait until the worker has no sandboxes. `sandboxes` in this response
   must be `0`:

   ```sh
   curl -s -H "$A" http://127.0.0.1:8080/v1/nodes/NODE_ID
   ```

   When the moves are complete, the event `node.drained` shows the number
   of sandboxes that moved and that did not move. The primary also moves
   the [volumes](#volumes-on-more-than-one-host) of the worker.

3. Do your work on the worker.
4. Let the worker take new sandboxes again:

   ```sh
   curl -s -H "$A" -d '{}' http://127.0.0.1:8080/v1/nodes/NODE_ID:undrain
   ```

You can also move one sandbox. The primary selects the host with the most
free memory. To select a host, add `"node"` with a node ID or `"primary"`:

```sh
curl -s -H "$A" -d '{"node":"primary"}' http://127.0.0.1:8080/v1/sandboxes/SANDBOX_ID:migrate
```

What occurs during a move:

- The primary pauses the sandbox, copies its memory and disk to the other
  host, and starts it there. On the test servers, this takes 3 to 7
  seconds.
- The sandbox keeps its ID, files, processes, preview URLs and secrets.
  Clients use the same URLs.
- During the move, requests for the sandbox wait. They continue when the
  move is complete.
- A running sandbox stays running. A paused sandbox stays paused.
- If the move fails, the sandbox stays on its first host and continues.
  The response is an error with `"retryable": true`.
- The event `sandbox.migrated` shows `from`, `to`, `was_running` and
  `duration_ms`.

> **NOTE:** You cannot drain the primary. Sandboxes move only between
> hosts with the same backend, kernel, base disk, Firecracker or runsc,
> egress CA and CPU model. Each worker uses the egress CA of the primary for this reason.

### Volumes on more than one host

The data of a volume is on one host. This host is the **home** of the
volume. `node` in `GET /v1/volumes/{name}` shows the home. `null` is the
primary.

- The primary puts a sandbox that mounts a volume on the home of the
  volume.
- If the home is full or draining, the primary copies the volume to a
  different host. It does this only if no sandbox uses the volume.
- If the volumes of a sandbox are on different hosts, the primary copies
  them to one host first.
- When a sandbox moves, its volumes move with it. A sandbox can move only
  if it is the only sandbox that uses its volumes. If not, the response is
  `409`.
- A volume moves only between hosts with the same backend.
- If the home of a volume is down, sandboxes cannot use the volume. The
  response is `503 node_unreachable`, or `503 volume_unavailable` when a
  cold sandbox starts. Try again when the host comes back.

- When you drain a worker with `{"migrate":true}`, the primary also
  copies the volumes of the worker to other hosts. The event
  `node.drained` shows `volumes_moved` and `volumes_failed`.

> **CAUTION:** Before you remove a worker, drain it. Make sure that
> `GET /v1/volumes` shows no volume with the `node` of the worker. If you
> remove a worker that is the home of a volume, you lose the data of the
> volume.

### Add an edge

An **edge** is a front door for your clients. It runs no sandboxes. It
sends each request to the correct host:

- Commands, terminals, files, `git:clone` and preview URLs go directly to
  the host of the sandbox. The primary is not in the path.
- All other requests go to the primary.

If the primary stops, commands, terminals, files and previews of running
sandboxes continue to operate through the edge. Other requests fail with
`503` until the primary starts again.

The edge does not need KVM or root. You can run it on the primary, on a
worker or on a different small host.

1. On the primary, make a join token, as in
   [step 3](#step-3-add-a-worker).

2. On the edge host, type:

   ```sh
   sudo /opt/spawnbox/bin/spawn-api edge \
     --primary https://PRIMARY_PRIVATE_IP:7443 \
     --join-token TOKEN \
     --primary-ca-sha256 CA_SHA256 \
     --data-dir /var/lib/spawnbox-edge \
     --listen 0.0.0.0:443 \
     --tls-cert /etc/spawnbox/api.crt --tls-key /etc/spawnbox/api.key \
     --preview-listen 0.0.0.0:8443 \
     --preview-tls-cert /etc/spawnbox/preview.crt \
     --preview-tls-key /etc/spawnbox/preview.key
   ```

   You can also set the token in `SPAWNBOX_JOIN_TOKEN`. Without the TLS
   options, the edge uses plain HTTP. The edge keeps its certificate in
   the data directory. When it starts again, it does not need a token.

3. Point your clients and your preview domain to the edge. Use the same
   API keys as before. The host that gets the request checks the key.

You can run more than one edge. Put them behind a TCP load balancer.

The edge gets the list of hosts and sandboxes from the primary each
second. Thus:

- For approximately 1 s after a sandbox moves, a request can go to the old
  host.
- If a worker starts again while the primary is stopped, the worker
  refuses requests from edges until the primary is available.

To remove an edge, use `DELETE /v1/nodes/NODE_ID`. After approximately
5 s, the edge refuses all requests with `403`.

### Remove a worker

1. On the primary, type:

   ```sh
   curl -s -H "$A" -X DELETE http://127.0.0.1:8080/v1/nodes/NODE_ID
   ```

   The primary marks the sandboxes of the worker as deleted. It does not
   send requests to the worker again.

2. On the worker, stop the service:

   ```sh
   sudo systemctl stop spawnbox
   ```

To add the same host again, remove `/var/lib/spawnbox/fleet/worker/` on
the worker. Then do [step 3](#step-3-add-a-worker) with a new token.

### Retire a worker safely

To stop a worker machine without losing sandboxes, retire it first. A
retired worker takes no new sandboxes and never takes them again. Use
this before you stop the machine for a spot interruption, an Auto Scaling
group scale-in or any other reason.

1. On the primary, type:

   ```sh
   curl -s -H "$A" -X POST http://127.0.0.1:8080/v1/nodes/NODE_ID:retire \
     -d '{"reason":"spot interruption"}'
   ```

   The primary moves the sandboxes of the worker to other hosts. With
   `{"migrate":false}`, it waits for them to end instead.

2. Get the worker until `retirement.state` is `ready_to_terminate`:

   ```sh
   curl -s -H "$A" http://127.0.0.1:8080/v1/nodes/NODE_ID
   ```

   `retirement.waiting_for` tells what the primary still waits for:
   `sandboxes`, `volumes`, `calls` (requests to the worker that are not
   done), `settle` (3 minutes after the retirement started) or
   `heartbeat` (a report from the worker after that time). If a sandbox
   cannot move, the state is `blocked`, and the primary tries again every
   minute.

3. Stop the machine. Then remove the worker:

   ```sh
   curl -s -H "$A" -X DELETE http://127.0.0.1:8080/v1/nodes/NODE_ID
   ```

You cannot undo a retirement. `:undrain` gives `409` while a worker
retires. Do not use `systemctl stop` or `SIGTERM` to drain a worker: the
worker stops, and its sandboxes are lost.

### Add and remove workers automatically

The primary can ask for workers when it is busy, and give them back when
it is idle. It does not know your cloud. It calls your hook: a program or
a webhook. The hook starts or stops a machine with the AWS CLI,
Terraform, Pulumi or any other tool.

How it decides:

- The load is the largest of the used slots, the used memory and the
  reserved memory, for the primary and the ready workers that are not
  drained. A host that is short of memory counts as full.
- If a create gets `503 no_capacity`, the primary asks for one more
  worker at once. It does not wait for `--autoscale-up-after-s`.
- If the load stays above `--autoscale-up-pct` for
  `--autoscale-up-after-s`, the primary asks for one more worker
  (`scale_up`).
- If there are fewer workers than `--autoscale-min-workers`, the primary
  asks for all the missing workers at once. To get ready for a known
  burst, raise the minimum before it starts.
- If the load stays below `--autoscale-down-pct` for
  `--autoscale-down-after-s`, the primary
  [retires](#retire-a-worker-safely) the worker with the fewest
  sandboxes. When it is `ready_to_terminate`, the primary calls the hook
  to stop the machine (`scale_down`), then removes the worker.
- Otherwise it asks for one worker at a time, and it never goes above
  `--autoscale-max-workers`. Retiring workers do not count. If the load
  goes up while a worker retires, the primary asks for a new worker.
- A new worker must join within 30 minutes. If none does, the primary
  calls the hook to stop the machine it asked for.
- If the hook fails, the primary sends the same request again after 5
  minutes. A new primary that takes over also sends the open `scale_up`
  requests again, because it cannot know if the hook ran. The request ID
  and the join token stay the same. **Your hook must start at most one
  machine for each request ID.** On AWS, use the ID as the client token
  of `run-instances`.

#### Use the AWS example

[`deploy/aws/terraform`](deploy/aws/terraform) has the parts for AWS:

- A launch template for workers: Ubuntu 24.04 with nested
  virtualization (C8i, M8i or R8i), and the metadata service only for
  the host itself (IMDSv2, hop limit 1).
- A security group: the primary calls workers on port 7444, and workers
  call the primary on port 7443.
- An instance profile for the primary. It can start workers only from
  the template, and stop only instances with the tag
  `spawnbox-fleet`.
- [`aws-hook.sh`](deploy/aws/terraform/aws-hook.sh): the hook. A new
  worker installs Spawnbox with the
  [install command](#step-4-install-spawnbox) and joins with its token.

1. Make the parts. Use private subnets in the VPC of the primary:

   ```sh
   cd deploy/aws/terraform
   terraform init
   terraform apply -var region=ap-south-1 \
     -var 'subnet_ids=["subnet-..."]' \
     -var primary_security_group_id=sg-... \
     -var primary_url=https://10.0.0.1:7443
   ```

2. Attach the instance profile `primary_instance_profile` to the
   primary. Install the AWS CLI on the primary.
3. On the primary, install the hook and its settings:

   ```sh
   sudo install -m 755 aws-hook.sh /etc/spawnbox/aws-hook.sh
   terraform output -raw hook_env | sudo tee /etc/spawnbox/aws-hook.env
   ```

4. Add these flags to `SPAWNBOX_ARGS` on the primary and restart:
   `--autoscale-hook /etc/spawnbox/aws-hook.sh --autoscale-max-workers 10`.

To change new workers, add these to `/etc/spawnbox/aws-hook.env`:

- `SPAWNBOX_WORKER_ARGS`: more flags for each worker, for example
  `"--max-sandboxes 64"`. The Terraform variable `worker_args` sets it.
- `SPAWNBOX_WORKER_SETUP`: path to a script on the primary. Each new
  worker runs it as root at boot, before Spawnbox is installed, for
  example to start a monitoring agent. It goes in the EC2 user data,
  which is at most 16 KB. Do not change it while a worker is still to
  join: a request sent again must have the same user data.

With Pulumi or another tool, make the same parts and use the same hook.
On Azure or GCP, change the `aws` commands in the hook.

#### Write your own hook

The primary runs the program with one argument, `scale_up` or
`scale_down`. Exit code `0` means success. The program can run for at
most 10 minutes. Its output goes to the log of the primary. It also gets
the request as JSON on stdin, and these environment variables:

| Variable | Action | Value |
|---|---|---|
| `SPAWNBOX_ACTION` | Both | `scale_up` or `scale_down` |
| `SPAWNBOX_REQUEST_ID` | Both | ID of the request, for example `scl_...`. The same request can come again. |
| `SPAWNBOX_JOIN_TOKEN` | `scale_up` | Join token for the new worker |
| `SPAWNBOX_PRIMARY_CA_SHA256` | `scale_up` | Value for `--primary-ca-sha256` |
| `SPAWNBOX_NODE_ID` | `scale_down` | ID of the worker to stop, or empty |
| `SPAWNBOX_NODE_URL` | `scale_down` | `--advertise` URL of the worker, or empty |
| `SPAWNBOX_NODE_SCALE_UP` | `scale_down` | ID of the `scale_up` request that made the worker, or empty |

A `scale_down` for a machine that is already gone must also exit `0`.

If no worker joins within 30 minutes of a `scale_up`, the primary sends a
`scale_down` with only `SPAWNBOX_NODE_SCALE_UP` set (the node's `id` and
`url` are `null` in the JSON), so the hook stops any machine it started
for that request.

To use a webhook, give a URL to `--autoscale-hook`, for example
`--autoscale-hook https://hooks.example.com/spawnbox`. The URL must use
`https`, or `http` to `localhost`. The primary sends a `POST` with this
JSON and waits for a `2xx` response for at most 60 seconds:

```json
{"action":"scale_up","id":"scl_...","reason":"load 82% for 120 s",
 "join":{"token":"sbj_...","ca_sha256":"...","expires_at":"2026-01-01T00:30:00.000Z"}}
{"action":"scale_down","id":"scl_...","reason":"load 12% for 1200 s",
 "node":{"id":"nod_...","url":"https://10.0.0.7:7444","scale_up":"scl_..."}}
```

With `--autoscale-secret` (or `SPAWNBOX_AUTOSCALE_SECRET`), each request
has the header `X-Spawnbox-Signature: sha256=<hex>`. The value is the
HMAC-SHA256 of the body with the secret.

#### Use your own autoscaler

Without `--autoscale-hook`, the primary does not start or stop machines,
but it still shows what an autoscaler needs. Your tool can read these and
start machines, then retire workers with `:retire` before it stops them:

- `GET /v1/nodes/autoscale`: the load, the number of workers in each
  state (`ready`, `suspect`, `down`, `draining`, `retiring`) and recent
  requests. With a hook, also the settings.
- The metrics `spawnbox_fleet_load`,
  `spawnbox_fleet_create_refused_total` and
  `spawnbox_fleet_retirements`. Refer to
  [See metrics in Prometheus](#see-metrics-in-prometheus).

To see the state, type:

```sh
curl -s -H "$A" http://127.0.0.1:8080/v1/nodes/autoscale
```

The events `autoscale.requested`, `autoscale.done`, `autoscale.failed`,
`node.retiring` and `node.retired` show each request and retirement.

## Back up and restore

`install.sh` installs `/opt/spawnbox/backup.sh` and a systemd timer,
`spawnbox-backup.timer`, that runs it each day on the primary. Workers
are not backed up: their state comes from the primary.

### What a backup contains

Each backup is one file, `spawnbox-<UTC time>.tar.gpg`. It is a tar
archive, encrypted with gpg (AES-256) under a passphrase. It contains:

- The database: a copy of `spawnbox.db` made with `sqlite3 .backup`, or,
  with `--database-url`, a `pg_dump` of the Postgres database. This has
  the tenants, keys, templates and their specs, sandbox records and start
  records, events, volumes records, the fleet and the encrypted secrets
  and env.
- `secrets.key` (or the `--secrets-key-file`). Without it, the secrets,
  the env of sandboxes and the CA keys in the database cannot be read.
- `session.key`, the egress CA and, on a fleet, the fleet CA. With the
  same fleet CA, the workers trust the restored primary.

A backup does not contain:

- Template builds. At the next start, the server builds the templates
  again from their specs. A template made with `:snapshot` cannot be
  built again; it works only if a [build store](#keep-builds-in-an-object-store)
  has its build.
- The memory and disk files of paused sandboxes. After a restore,
  persistent sandboxes become `cold` and start again at the next call;
  ephemeral paused sandboxes become `failed`.
- Volumes. Copy them yourself if you need them.
- `host-id`. A restored primary is a new host, so it fences the
  persistent sandboxes of the old one, as at a failover.

### The keys

> [!WARNING]
> `secrets.key` decrypts everything that Spawnbox encrypts in the
> database. Never keep a plain copy of `secrets.key` in the same place as
> a database dump. `backup.sh` puts both in one encrypted file, so that
> they are never stored in plain.

- `install.sh` makes a random passphrase in
  `/etc/spawnbox/backup.passphrase` (mode `0600`). **Copy it now to a safe
  place that is not this host and not the backup target**, such as a
  password manager. Without the passphrase, the backups cannot be read.
  If you lose the host, you need the passphrase and a backup.
- The passphrase is used only to read and write backups. To change it,
  write a new one into the file. Older backups still need the old one.
- Keep `/etc/spawnbox/spawnbox.env` too, or know its flags. It is not in
  the backup.

### Settings

Set these in `/etc/spawnbox/backup.env`. `install.sh` writes it once and
keeps it on upgrade.

| Setting | Default | Meaning |
| --- | --- | --- |
| `SPAWNBOX_BACKUP_TARGET` | `/var/backups/spawnbox` | A directory, or `s3://bucket/prefix`. S3 needs the `aws` CLI and credentials, for example an instance role. |
| `SPAWNBOX_BACKUP_KEEP` | `14` | How many backups to keep at the target. Older ones are deleted after each backup that works. |
| `SPAWNBOX_BACKUP_PASSPHRASE_FILE` | `/etc/spawnbox/backup.passphrase` | The passphrase |
| `SPAWNBOX_BACKUP_METRICS_FILE` | None | A node exporter textfile. After each backup that works, the script writes `spawnbox_backup_last_success_timestamp_seconds` to it, for the `SpawnboxBackupMissing` alert. |

The script reads `--data-dir`, `--database-url`, `--database-ca-file` and
`--secrets-key-file` from `SPAWNBOX_ARGS` in `/etc/spawnbox/spawnbox.env`.
A backup to a local directory does not help if you lose the host's disk.
Use S3, or copy the directory to another place.

The server can run during a backup. A Postgres backup needs `pg_dump` of
the server's major version or newer; `install.sh` installs
`postgresql-client` when `--database-url` is set.

```sh
sudo systemctl start spawnbox-backup         # make a backup now
sudo journalctl -u spawnbox-backup           # see the result
sudo /opt/spawnbox/backup.sh --list          # list the backups
systemctl list-timers spawnbox-backup.timer  # see when the next one runs
```

### Restore a backup

1. Install Spawnbox on the host with the same flags as before, for
   example the same `--database-url`. The new server makes an empty
   database and a new `secrets.key`; the restore replaces them.
2. Put the passphrase in `/etc/spawnbox/backup.passphrase` (mode `0600`).
   If the backups are in S3, set `SPAWNBOX_BACKUP_TARGET` in
   `/etc/spawnbox/backup.env`.
3. Stop the server:

   ```sh
   sudo systemctl stop spawnbox
   ```

4. Restore the newest backup, or a file or URL:

   ```sh
   sudo /opt/spawnbox/backup.sh --restore latest --force
   sudo /opt/spawnbox/backup.sh --restore s3://my-bucket/spawnbox/spawnbox-20260101T030000Z.tar.gpg --force
   ```

   The script decrypts and checks the whole backup before it changes
   anything. Without `--force`, it does not replace a SQLite database,
   a Postgres database that has tables, or files that are different. With
   `--force`, it keeps the old files as `<file>.pre-restore` and replaces
   the Postgres tables in one transaction. The Postgres database must
   exist.

5. The script then runs `spawn-api check-data`. It counts the tenants,
   keys, templates, secrets and sandboxes, and decrypts each secret, each
   sandbox env and each CA key with the restored `secrets.key`. It fails
   if one cannot be decrypted. You can run it yourself at any time:

   ```sh
   sudo /opt/spawnbox/bin/spawn-api check-data --data-dir /var/lib/spawnbox
   ```

   Add `--database-url` for Postgres. It changes nothing: it opens SQLite
   read-only and Postgres in read-only transactions, and does not upgrade
   the schema. It fails if the database's schema version is not the one
   this `spawn-api` writes; check with the binary that wrote the data, or
   start the matching server once to upgrade it.

6. Start the server, and check it:

   ```sh
   sudo systemctl start spawnbox
   spawnbox doctor
   ```

On a fleet, restore only the primary. The workers connect to it again,
because the fleet CA is the same. Sandboxes and nodes that changed after
the backup was made are as they were at the backup. Check
`GET /v1/nodes` and the events after the restore.

## API reference

Each `/v1` request must have the header `Authorization: Bearer <key>`.
Spawnbox keeps only the SHA-256 hash of each key. An error response has
this format: `{"error": {"code", "message", "request_id", "retryable"}}`.

### Errors

| Code | HTTP status | Retryable | Meaning |
| --- | --- | --- | --- |
| `invalid_request` | 400 | No | A field is missing or wrong. |
| `unauthorized` | 401 | No | The key is missing, wrong or revoked. |
| `forbidden` | 403 | No | The key does not have the scope for this call. |
| `not_found` | 404 | No | The sandbox, template or other resource does not exist. |
| `conflict` | 409 | No | The resource is not in a state that allows this call, or the name is already used. |
| `protected_env` | 409 | No | A snapshot would show env values of the sandbox. |
| `build_failed` | 409 | No | A build that the sandbox needs could not be made. The same error is given for 5 minutes. |
| `quota_exceeded` | 429 | Yes | A tenant quota is full. Try again after other sandboxes end. |
| `no_capacity` | 503 | Yes | No host has room. The response has `Retry-After: 30`. |
| `node_unreachable` | 503 | Yes | The host of the sandbox cannot be reached. |
| `volume_unavailable` | 503 | Yes | The only copy of a volume is on a host that cannot be reached. |
| `rebuilding` | 503 | Yes | A build that the sandbox needs is being made. |
| `sandbox_cold` | 503 | Yes | A worker stopped the sandbox, and the primary starts it again. |
| `internal` | 500 | Yes | An unexpected error. The server log has the cause with the `request_id`. |

`retryable` in the response has the same value. Repeat a retryable call
after a short wait, with backoff.

### Sandbox states

| State | Meaning | Next states |
| --- | --- | --- |
| `starting` | The VM starts, for a create, a fork or a cold start. | `running`; `failed` if the start fails; `deleted` if it is deleted meanwhile; `cold` for a persistent sandbox |
| `running` | The VM runs. | `paused`, `deleted`; `cold` (persistent) or `failed`/`deleted` (ephemeral) when the VM is lost |
| `paused` | Memory and disk are saved in `<data-dir>/paused/<id>`, and the VM is stopped. | `running` at a resume; `deleted`; `cold` (persistent) or `failed` (ephemeral) if the files cannot be used |
| `cold` | Persistent only. No VM and no saved memory. The start record (template build, env, secrets, network rules, volumes, services, ports) is kept. | `starting` at the next exec, file, terminal, clone, preview or resume call; `deleted` |
| `failed` | The sandbox could not start or lost its VM. It ends. | None |
| `deleted` | The sandbox was deleted, expired or lost. It ends. | None |

`failed` and `deleted` are final. These events show the changes:

| Change | Event | Reason |
| --- | --- | --- |
| A create, fork or cold start ends | `sandbox.created`, `sandbox.forked`, `sandbox.cold_started` | |
| Pause and resume | `sandbox.paused`, `sandbox.resumed` | `memory_pressure` for a pause to free memory |
| An ephemeral sandbox loses its VM, or a server restart finds it running | `sandbox.lost` | The state is `failed` or `deleted`. |
| The timeout ends | `sandbox.expired` | |
| A persistent sandbox becomes `cold` | `sandbox.cold` | `server_restarted`, `shutdown` (the server stopped before it could pause), `vm_exited`, `pages_lost`, `pause_failed`, `froze_while_saving`, `resume_failed`, `guest_too_old`, `paused_files_missing`, `capacity` (no room for its idle pause), `start_unfinished`, `gone_from_node`, `node_reported` |
| The primary fences a lost host, or a standby takes over | `node.fenced`, then `sandbox.cold` for each persistent sandbox of the host | `fenced` with `proof` (`operator`, `autoscaler`, `self_fence`), or `failover` |
| A host stops its copy of a persistent sandbox | `sandbox.fenced` | `self_fenced` or `lease_lost` (the host fenced itself), `stale_generation` (a newer copy exists), `resume_fenced` |
| A cold start uses a new build | `sandbox.rebuilt` | `missing`, `outdated`, `guest_too_old` |
| A move to another host | `sandbox.migrated` | |

Each cold start adds 1 to `generation`. A host stops a copy of a sandbox
from an older generation. Refer to [Fence lost hosts](#fence-lost-hosts).

A template build is `queued`, `building`, `ready` or `failed`. A ready
build becomes `outdated` when the kernel, base disk or runtime of the host
changes, and `removed` when a newer build replaces it or its template is
deleted. The files of `outdated` and `removed` builds are deleted.

### Sandboxes

- `POST /v1/sandboxes` creates a sandbox. Fields: `template` (default
  `base`), `timeout_s`, `idle_pause_s`, `env`, `labels`, `egress`,
  `secrets`, `volumes`, `persistent`, `services`. Org keys can also send
  `tenant`.
- `"persistent": true` keeps the sandbox until it is deleted. Do not send
  `timeout_s`. `idle_pause_s` must be more than 0 (default 600). On a
  fleet, the primary runs it. Refer to
  [Keep a sandbox until you delete it](#keep-a-sandbox-until-you-delete-it).
- The create response has `timings_ms` and `started_from`. The value of
  `started_from` is `warm_pool` or `build`.
- For a token or password that the sandbox sends in an HTTP header, use a
  secret with `env`, not `env`. The sandbox then sees only a placeholder,
  and the value never enters the VM. Refer to [Secrets](#secrets).
- Responses, events and logs never show env values.
- Each host adds up the `memory_mib` of its running sandboxes. A create,
  fork or resume that goes over `--memory-overcommit-pct` of the host
  memory (default 150) gives `503 no_capacity` with `Retry-After: 30`.
  A primary first tries the other hosts. Paused sandboxes do not count.
- When free host memory drops below `--memory-pressure-pct` (default 10)
  percent, or processes wait for memory that share of the time, the host
  pauses the sandbox with no running call that was used least recently,
  one at a time, and refuses creates and resumes with `503 no_capacity`
  until memory is fine again. The `sandbox.paused` event has the reason
  `memory_pressure`. The next call resumes the sandbox as usual.
- A Firecracker guest gives the pages it frees back to the host, so a
  sandbox uses only the memory it needs now. Templates built before this
  are rebuilt once.
- `GET /v1/sandboxes` lists sandboxes. Org keys can add `?tenant=`.
- `GET /v1/sandboxes/{id}` gets one sandbox. It has `persistent`,
  `generation` (1, plus 1 for each cold start), `cold_starts` and
  `last_cold_start_at`. It never shows env values. A persistent sandbox
  has no `expires_at`.
- States: `starting`, `running`, `paused`, `cold`, `deleted`, `failed`.
  Only persistent sandboxes become `cold`.
- `DELETE /v1/sandboxes/{id}` deletes a sandbox. A `cold` sandbox, or one
  that is starting again, is deleted at once. A start that ends after the
  delete stops its VM.
- Spawnbox deletes a sandbox when its `timeout_s` ends. The maximum is
  `--max-timeout-s`. Time in the paused state is not counted.
- `POST /v1/sandboxes/{id}:pause` saves the memory and disk in
  `<data-dir>/paused/<id>` and stops the VM.
- `POST /v1/sandboxes/{id}:resume` starts the VM again. For a `cold`
  sandbox, it boots a new VM from the template build.
- A cold start is given 120 seconds. Calls that come during a start wait
  for it. If it fails or takes longer, the sandbox stays `cold` and the
  next call tries again.
- If the sandbox is already in the requested state, pause and resume do
  nothing.
- A paused sandbox shows `"state": "paused"` and `paused_at`.
- Paused sandboxes stay after a server restart. Spawnbox deletes them
  after `--paused-retention-s` (default 7 days). Persistent sandboxes are
  not deleted.
- Spawnbox encrypts the env of paused and persistent sandboxes on disk
  with `--secrets-key-file`. The env of the sandbox and of all its
  services is one ChaCha20-Poly1305 value, bound to the tenant and the
  sandbox ID. A value cannot be moved to another variable, service or
  sandbox. At start, Spawnbox encrypts env that an earlier version kept
  in another form. On SQLite, the first start after the upgrade also
  compacts the database file, to clear the plain copies.
- If `secrets.key` cannot read the stored env of a sandbox, the server
  does not start. Usually the key is not the one that encrypted it; put
  back the right key. With `--allow-unreadable-env` the server starts,
  and leaves those sandboxes and their files as they are, so a later
  start with the right key resumes them. This helps only when the key
  reads everything else: `secrets.key` also encrypts the egress CA key,
  the stored secrets and, with Postgres, the files that primaries share.
  With a different key, the server still stops at those. Use the flag
  when the key is right but the env of some sandboxes cannot be read,
  for example rows that were damaged or copied from another
  installation.
- Memory files and disks are not encrypted. Put `<data-dir>` on an
  encrypted disk; `spawnbox doctor` warns when it is not.
- On Firecracker, a pause writes only the memory that changed since the
  sandbox was started or resumed. Spawnbox then merges it with the earlier
  memory in the background; a resume or a move waits for that merge. The
  first pause after a fork, a failed pause or a lazy (UFFD) restore writes
  all the memory. On the test server a full pause took approximately 0.7 s,
  and up to 12 s while earlier pauses were still being written.
- `POST /v1/sandboxes/{id}:fork` starts copies of a running sandbox on its
  host. Field: `count`, 1 to 16 (default 1).
  - The response is `201` with `sandboxes` (the copies that started) and
    `failed` (the number that did not start).
  - Each copy gets the memory, processes and files of the sandbox. It also
    gets its template, labels, env, secrets, network rules and the time
    that remains before its timeout.
  - Each copy gets its own ID, hostname and random numbers. Its env is
    encrypted again for its own ID.
  - Each copy counts against the quotas of the tenant.
  - On the test server, 10 copies take approximately 0.7 s.
- `POST /v1/sandboxes/{id}:snapshot` saves a running sandbox as a new
  template. Field: `name`.
  - The response is `201` with `template`, `build` and `spec`.
  - The template is in the tenant of the sandbox. Its `env` is the env of
    its template. Secrets are not saved. Add them again when you create a
    sandbox from the template.
  - A sandbox created with `env`, or with a service that has `env`, gives
    `409 protected_env`, because the template would show the values. Use
    secrets for these values, or put them in the template spec.
  - The template has a `snapshot` field. You cannot rebuild the template.
  - Without a build store, sandboxes from the template start only on the
    host of the original sandbox. With a build store, a host with the same
    fingerprint and CPU model can get the files from the store.
  - On the test server, a snapshot takes approximately 0.4 s.
- Fork and snapshot stop the sandbox for the time of the save. They do not
  operate on a paused sandbox or on a sandbox with volumes.

### Commands

- `POST /v1/sandboxes/{id}/exec` runs a command. Fields: `cmd`, `cwd`,
  `env`, `user`, `timeout_s`, `stdin` (maximum 1 MiB).
- The JSON response has these fields:
  - `stdout` and `stderr`, maximum 1 MiB each. The `stdout_truncated` and
    `stderr_truncated` flags show if output was cut.
  - `exit_code`, `signal` and `timed_out`.
  - `duration_ms` and `exec_id`.
- With the header `Accept: text/event-stream`, the response is a stream of
  `stdout`, `stderr` and `exit` events. If you close the stream, Spawnbox
  stops the command.
- The request ends when the command ends. A background process that the
  command started can continue.
- Environment variables come from the template, then the sandbox, then
  the command. A later value replaces an earlier value.

### Files

- `GET /v1/sandboxes/{id}/files?path=` gets the contents of a file, or a
  JSON list for a directory.
- `PUT` writes the request body to the file. Spawnbox creates the parent
  directories. It replaces the file only after it receives the full body.
- `DELETE` deletes a file. To delete a directory, add `recursive=true`.
- A relative path starts at `/workspace`.
- Spawnbox does file operations as `user`, unless you set `user=`. Usual
  file permissions apply.

### Terminals

- `GET /v1/sandboxes/{id}/pty?cols=&rows=&user=&cwd=&cmd=` opens a
  WebSocket. It runs `bash -l`, or `cmd`, on a real terminal.
- Binary frames carry terminal data in the two directions.
- To change the terminal size, send the text frame
  `{"type":"resize","cols","rows"}`.
- At the end, the server sends
  `{"type":"exit","exit_code","signal","duration_ms"}`.
- If you close the WebSocket, Spawnbox stops the shell.
- A browser can use a session token with the `terminal` audience
  instead of an API key: add `session_token=<token>` to the query.

### Browser session tokens

- `POST /v1/sandboxes/{id}/session-tokens` makes a token for one
  sandbox. Fields:
  - `audience` (required): `terminal` or `preview`.
  - `port`: the published port that a `preview` token opens. It is
    required for `preview`, and not allowed for `terminal`.
  - `ttl_s`: 1 to 900, default 900.
- The response has `token` and `expires_at`. The key must have
  `sandboxes:write`. A missing or bad `audience` or `port` gives
  `400 invalid_request`.
- The token is a JWT (HS256) with an `aud` claim. A `terminal` token
  opens only the terminal of that sandbox. A `preview` token opens only
  the `private` preview URL of that port. A token does not work on other
  API calls.
- The token stops at `expires_at`, or when the key that made it is
  revoked.
- Each new token records a `sandbox.session_token_created` event, with
  its `audience`.
- Spawnbox signs tokens with `<data-dir>/session.key`. The primary sends
  this key to the workers. If you delete the file, all tokens stop.

### Git

- `POST /v1/sandboxes/{id}/git:clone` clones a repository. Fields: `url`
  (`https://` or `http://`), `path` (default `/workspace/<repo>`),
  `branch`, `depth`, `user`, `timeout_s`.
- The response has `path`, `commit`, `branch` and `duration_ms`.
- A `git_https` secret on the sandbox gives access to private
  repositories. The token does not go into the sandbox.

### Templates

- `POST /v1/templates` creates a template and starts a build. Fields:
  - `name`.
  - `setup`: commands that run as root, with network access.
  - `warmup`: commands that run as `user` immediately before the
    snapshot. Background processes that they start continue in each
    sandbox.
  - `env`.
  - `resources`: `vcpus`, `memory_mib`, `disk_gib`.
  - `min_warm`: the minimum number of warm VMs that each host keeps for
    this template, 0 to 16. The default is 0. Refer to
    [Warm pools](#warm-pools).
  - `base`: a container image to start from, for example
    `node:22-bookworm-slim`. If you do not set it, the template starts
    from the Debian base. Refer to
    [Start a template from a container image](#start-a-template-from-a-container-image).
  - `registry_secrets`: names of held secrets that Spawnbox uses only to
    get `base`. A maximum of 4.
- The response is `202` with the template and its build.
- `GET /v1/templates` lists templates. `GET` and
  `DELETE /v1/templates/{name}` get and delete one template.
- `GET /v1/templates/{name}/builds/{build_id}` gets the state, the error
  and the end of the build log.
- You cannot change or delete the `base` template.
- If you save a template again, Spawnbox starts a new build. Until the new
  build is ready, sandboxes use the last ready build. If you change only
  `min_warm`, Spawnbox does not start a new build.
- If a template has no ready build, a create request gives `409`.
- Builds stay after a restart. Spawnbox builds again only when the kernel,
  base disk or Firecracker version changes.
- Spawnbox runs a maximum of `--max-builds` builds at the same time.

### Services

- `services` in `POST /v1/sandboxes` is a list of up to 8 services. Each
  has these fields:
  - `name`: 1 to 63 of `a-z`, `0-9` and `-`. It cannot start with `-`.
    Each name must be different.
  - `command`: the program and its arguments. It cannot be empty.
  - `cwd` (optional): an absolute path.
  - `env` (optional): it cannot set the CA variables, such as
    `SSL_CERT_FILE`, or the variable of a secret of the sandbox.
  - `port` (optional): 1 to 65535. Each port must be different.
  - `access` (optional, needs `port`): `private` (default), `token` or
    `public`.
  - `health` (optional, needs `port`): `{"http": "/path"}` or
    `{"tcp": true}`, with `interval_s` (1 to 3600, default 10) and
    `failures` (1 to 100, default 3).
  - `restart` (optional): `always` (default) or `on-failure`.
- A wrong value gives `400 invalid_argument`. A template without support
  for services gives `409 conflict`.
- `GET /v1/sandboxes/{id}/services` gives the state of each service:
  `{"services": [{"name", "state", "pid", "restarts", "last_exit",
  "started_at"}]}`.
  - `state` is `starting` (until the first good health check),
    `healthy`, `unhealthy`, `backoff` (it waits to start again) or
    `stopped`.
  - `last_exit` is `{"code": 1}`, `{"signal": 9}` or `null`.
- `POST /v1/sandboxes/{id}/services/{name}:restart` stops a service and
  starts it again. The response is `204`. An unknown name gives `404`.
- `GET /v1/sandboxes/{id}/services/{name}/logs` gives the last 1 MiB of
  output as text. With `?follow=true`, the response is a stream of
  `output` events (`{"text": "..."}`) that continues with new output.
- A stop sends `SIGTERM` to the process group of the service, and
  `SIGKILL` after 5 s.
- These calls resume a paused or `cold` sandbox, and count as activity.
  The work of a service in the VM does not keep the sandbox awake.
- Spawnbox never shows the env values of a service. It encrypts the
  services of paused and persistent sandboxes on disk, in one value with
  the env of the sandbox.
- A fork copies the services and their processes. A snapshot template
  does not keep the list of services.

### Preview URLs

- `POST /v1/sandboxes/{id}/ports` publishes a port and gives its URL.
  Fields: `port`, `access`, `ttl_s`.
- `GET` lists the published ports.
- `DELETE /v1/sandboxes/{id}/ports/{port}` removes a published port.
- `access` has three values:
  - `token` (default): the URL contains a token. The token stops after
    `ttl_s` (default 24 hours). At the first visit, it becomes a cookie.
  - `public`: all persons with the URL can open it.
  - `private`: the request must have the API key in `Authorization`, or
    a `preview` session token for the port. Add the token to the URL as
    `?spawnbox_session=<token>`. At the first visit, it becomes a cookie.
    Spawnbox removes this cookie before the request goes to the app.
- For each `access`, Spawnbox removes these from a request before it goes
  to the app: the `spawnbox_session` and `spawnbox_preview` cookies, the
  `spawnbox_session` query parameter, and an `Authorization` header with a
  Spawnbox API key (`Bearer sbx_...`) or a session token that this
  install made. On `public` and `token` ports, other `Authorization`
  values go to the app, so an app can use its own logins. On `private`
  ports, Spawnbox removes all `Authorization` values.
- Spawnbox serves previews on `--preview-listen` at `--preview-url`. It
  finds the sandbox from the host name.
- HTTP/1.1 and WebSockets are supported.
- A request to the port of a service waits up to 30 s until the service
  is healthy. Then it gives `503`.

### Network access (egress)

- Each TCP connection from a sandbox goes through the egress proxy.
  Spawnbox records each connection.
- Spawnbox always blocks these addresses:
  - private and link-local addresses, which include cloud metadata
  - loopback addresses
  - the addresses of the host
  - port 25 (SMTP)
- A policy has this format:
  `{"mode": "allow_all" | "allowlist" | "deny_all", "allow": [...], "deny": [...]}`.
  A pattern is a host name or `*.example.com`.
  - `allowlist` checks the TLS SNI or the HTTP `Host` name. It allows only
    ports 80 and 443.
  - `deny` is checked by name too: the TLS SNI, the HTTP `Host` name or
    the DNS query. Thus, when any policy has a `deny` list, `allow_all`
    refuses a TCP connection without a name on any port, for example to a
    bare address or TLS without SNI. It also drops UDP (except DNS) and
    ICMP. Without a `deny` list, `allow_all` allows these.
    An address written as a name, such as `Host: 93.184.215.14` or
    `0x5db8d70e`, counts as no name.
  - `deny` blocks names, not addresses. Spawnbox does not compare the
    address that an allowed name resolves to with the addresses of denied
    names. A sandbox that can use a name whose DNS it controls, such as a
    wildcard DNS service that answers `1-2-3-4.example` with `1.2.3.4`,
    can reach the address of a denied host. Thus, a `deny` list stops
    mistakes and casual use, not a determined program. Use `allowlist`
    when that matters.
  - A name check sees only the name that the client sends in clear text.
    A server that hosts many names, such as a CDN, can serve a denied
    name behind an allowed one (domain fronting or TLS Encrypted Client
    Hello). Use `allowlist` when that matters.
  - `deny_all` also blocks DNS.
- Each DNS query from a sandbox goes to the DNS forwarder of Spawnbox,
  for all DNS server addresses. The forwarder sends the query to `--dns`
  and records the name, the type, the result and the addresses.
  - When the policy does not allow a name, the answer is `REFUSED`.
- Optional speed limits, in megabits per second, from 1 to 100000:
  - `max_egress_mbps`: the data that the sandbox sends.
  - `max_ingress_mbps`: the data that the sandbox receives.

  For example:
  `{"mode": "allow_all", "max_egress_mbps": 20, "max_ingress_mbps": 100}`.
  The limits also apply after a resume.
- Spawnbox applies three policies: `--egress-policy` of the server, the
  `egress` of the tenant and the `egress` of the sandbox. The strictest
  policy wins. For speed limits, the lowest limit wins.

### Secrets

- `POST /v1/secrets` saves a secret. Fields: `name`, `type`
  (`http_header` or `git_https`), `value`, `allowed_hosts`, `env`,
  `header`, `format`, `username`.
- `GET`, `PATCH` and `DELETE /v1/secrets/{name}` get, change and delete a
  secret. They never show the value.
- Spawnbox encrypts each value with ChaCha20-Poly1305. The key is in
  `<data-dir>/secrets.key`, or in `--secrets-key-file`.
- Use a secret for each value that a sandbox sends in an HTTP header. With
  `env`, the sandbox gets a placeholder in that variable, and the proxy
  puts the value in the request. Code in the sandbox cannot read or leak
  the value.

  > **CAUTION:** Make a backup copy of `secrets.key`. Without this file,
  > you cannot read your secrets.

- For HTTPS requests to `allowed_hosts`, the proxy puts the value in the
  header of the secret. The default header is `Authorization: Bearer`.
  `git_https` uses Basic authentication.
- After a `PATCH`, the next request uses the new value.
- A `PATCH` that adds to `allowed_hosts` or changes `header` or `format`
  must also send `value`. Without it, the response is
  `400 value_required`, so a key that can change a secret cannot send its
  stored value to a new host. A `PATCH` that only removes hosts does not
  need `value`.
- The `secret.updated` and `secret.rotated` events show `allowed_hosts`.
  When the hosts change, they also show `previous_allowed_hosts`. They
  never show the value.
- Sandboxes trust the CA of the proxy. `SSL_CERT_FILE`,
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` point
  to the system certificate bundle.

### Volumes

- `POST /v1/volumes` creates a volume. Fields: `name`, `size_gib` (1 to
  1024, default 10), `tenant`. A name has 1 to 63 characters: `a-z`,
  `0-9` and `-`. It cannot start with `-`.
- `GET /v1/volumes` lists volumes. `GET /v1/volumes/{name}` gets one
  volume. The response shows `size_gib`, `backend`, `node` and `mounts`:
  the sandboxes that use the volume.
- `DELETE /v1/volumes/{name}` deletes a volume and its data. If a sandbox
  uses the volume, the response is `409`. Delete the sandbox first.
- To mount volumes, add `volumes` to `POST /v1/sandboxes`. Each item has
  `volume`, `path` and `read_only` (default `false`).
- `path` is an absolute path, for example `/data`. It cannot be `/`, or
  in `/proc`, `/sys`, `/dev`, `/run` or `/spawn`. Two paths cannot be one
  in the other.
- Spawnbox makes the disk of a volume when a sandbox mounts it the first
  time. The disk uses space on the host only for the data in it.
- Usage shows the full `size_gib` of each volume as disk use.

### Tenants and keys

- `POST /v1/tenants` creates a tenant. Fields: `id`, `name`, `quotas`,
  `egress`, `isolation`.
- `isolation` is `any` (default) or `microvm-only`. With `microvm-only`,
  the sandboxes of the tenant run only on Firecracker hosts. Refer to
  [Firecracker or gVisor](#firecracker-or-gvisor).
- `GET /v1/tenants` lists tenants. `GET`, `PATCH` and
  `DELETE /v1/tenants/{id}` get, change and delete one tenant. `GET` also
  shows the current usage.
- The `default` tenant always exists.
- You cannot delete a tenant that has sandboxes, templates or secrets. The
  response is `409`.
- When you delete a tenant, Spawnbox cancels its keys.
- There are two types of keys:
  - Org keys (`sbx_org_...`) can access all tenants. Older keys
    (`sbk_...`) are org keys.
  - Tenant keys (`sbx_tn_...`) can access only their tenant. For other
    tenants, the response is `404`.
- `POST /v1/keys` creates a key. Fields: `tenant`, `scopes`, `name`.
  Spawnbox shows the key only in this response.
- `GET /v1/keys` lists keys. `DELETE /v1/keys/{id}` cancels a key.
- Scopes: `sandboxes:read`, `sandboxes:write`, `templates:write`,
  `secrets:write`, `tenants:admin` (only org keys), `audit:read`,
  `usage:read`. A key without a scope list gets all the scopes that its
  type allows.
- A template or secret is for all tenants, or only for one tenant
  (`?tenant=`). If two have the same name, the tenant's own one wins.
- Quotas. The value `null` means no limit.

  | Quota | Default for a new tenant |
  | --- | --- |
  | `running_sandboxes` | 20 |
  | `running_vcpus` | 40 |
  | `running_memory_mib` | 80 GiB |
  | `max_session_s` | 24 hours |
  | `max_paused_retention_s` | 7 days |
  | `monthly_egress_bytes` | No limit |
  | `snapshot_storage_gib` | No limit |
  | `volume_storage_gib` | No limit |
  | `persistent_sandboxes` | 0 |

  The `default` tenant has no limits, except `persistent_sandboxes`.
  `persistent_sandboxes` counts persistent sandboxes in each state until
  they are deleted. If a request goes over a quota, the
  response is `429 quota_exceeded`.

### Events

- You can send the header `X-Spawnbox-Step: <id>` with each request, for
  example the ID of a tool call of your agent. You can also send a W3C
  `traceparent` header.
- The events from the request then have `step_id` and `trace_id`. Each
  event also has `tenant`, `sandbox` and `actor`.
- Event types:
  - `sandbox.created` (with `forked_from` for a copy), `.paused`,
    `.resumed`, `.forked`, `.snapshotted`, `.expired`, `.killed`, `.lost`,
    `.cold` (with `reason`), `.cold_started` (with `generation`, `build`
    and `duration_ms`), `.rebuilt` (with `from_build`, `to_build` and
    `reason`), `.fenced` (with `reason` and `generation`: a host
    stopped its copy), `.migrated`, `.session_token_created`
  - `node.joined`, `.up`, `.down`, `.draining`, `.drained`, `.undrained`,
    `.retiring`, `.retired`, `.removed`, `.fenced` (with `node` and
    `reason`), primary only
  - `exec.started`, `exec.finished` (with the last 64 KiB of output)
  - `pty.opened`, `pty.closed`
  - `service.started` (with `pid`), `service.exited` (with `exit`),
    `service.unhealthy` (with `failures`), `service.restarted` (with
    `restarts` and the `reason` `exit`, `unhealthy` or `request`). Each
    has `name`.
  - `file.written` (with the SHA-256 hash), `file.deleted`
  - `port.published`, `port.unpublished`
  - `net.connection`, `net.blocked`
  - `net.dns` (with `name`, `type`, `verdict`, `rcode`, `answers` and
    `duration_ms`)
  - `secret.injected` (without the value)
  - `volume.created`, `volume.deleted`
  - changes to tenants, keys, secrets and templates, such as
    `template.saved` and `template.deleted`
  - `autoscale.requested`, `.done`, `.failed` (primary only)
- `GET /v1/events` and `GET /v1/sandboxes/{id}/events` get events. These
  are the filters: `tenant`, `sandbox`, `step_id`, `type`, `since`,
  `until`. The type `exec.*` gets all the `exec` events.
- Use `limit` (maximum 1000) and `cursor` to get more pages.
- `follow=true` streams new events as server-sent events. After a
  disconnection, send `Last-Event-ID` to continue.
- The key must have the scope `audit:read`.
- `--otlp-endpoint` also sends the events to OpenTelemetry as OTLP/HTTP
  log records.
- `--otlp-endpoint` also sends traces. Each create and each command is
  one trace. A create has the spans `fetch_build`, `volumes`, `claim`,
  `restore` and `fixups`. A command has the spans `open` and `start`. On
  a primary, the span `sandbox.place` contains one `node` span for each
  host that it tries.
- If a request has a `traceparent` header, its trace contains the
  Spawnbox spans. The events of the request have the same `trace_id`.
- Spawnbox keeps events for `--events-retention-s` (default 7 days).

### Warm pools

A warm VM is a sandbox that Spawnbox restored before a request came. Its
vCPUs are paused. A create takes a warm VM, starts its vCPUs and gives it a
new clock, random seed and hostname.

- Spawnbox keeps a pool for each template build and network mode. The
  network mode comes from the egress policies: `allow_all`, `allowlist` or
  `deny_all`.
- The target size of a pool is the number of creates in the last 30
  seconds. The `base` pool for the server's egress policy has a minimum of
  `--warm-pool-min`. A template with `min_warm` has that minimum. A pool
  with no creates and no minimum falls to zero.
- The `min_warm` pool of a template uses the egress policy of the
  template's tenant (`allow_all` for org-wide templates). A sandbox with a
  narrower egress policy uses a different pool.
- In a fleet, each host keeps `min_warm` warm VMs.
- Warm VMs use a maximum of `--warm-pool-memory-pct` of the host memory.
  They do not use the last `--max-builds` free slots. If a create or resume
  has no free slot, Spawnbox stops a warm VM.
- Warm VMs are not counted in quotas or usage. Spawnbox counts them when a
  create takes them.
- `GET /v1/warm-pools` shows each pool: `template`, `build`, `network`,
  `ready`, `filling`, `target`, `hits` and `misses`. The key must have the
  scope `tenants:admin`.

### Nodes

These calls operate only on a primary. The key must have the scope
`tenants:admin`.

| Call | Function |
| --- | --- |
| `POST /v1/nodes/tokens` | Make a join token. Optional body: `{"ttl_s": 3600}`, from 60 to 604800. The response has `token`, `expires_at` and `ca_sha256`. |
| `GET /v1/nodes` | List the workers and edges that are not removed |
| `GET /v1/nodes/autoscale` | Get the load, the workers in each state and the autoscaler requests. Refer to [Add and remove workers automatically](#add-and-remove-workers-automatically). |
| `GET /v1/nodes/{id}` | Get one worker or edge |
| `DELETE /v1/nodes/{id}` | Remove a worker or an edge. The sandboxes of a worker are marked deleted. |
| `POST /v1/nodes/{id}:drain` | Put no new sandboxes on the worker. You cannot drain an edge. With the body `{"migrate":true}`, also move its sandboxes to other hosts. Gives `202` when it moves sandboxes. |
| `POST /v1/nodes/{id}:undrain` | Put new sandboxes on the worker again. Gives `409` if the worker retires. |
| `POST /v1/nodes/{id}:retire` | Retire the worker before you stop its machine. Optional body: `{"migrate":true,"reason":"..."}`. Gives `202`. Refer to [Retire a worker safely](#retire-a-worker-safely). |
| `POST /v1/nodes/{id}:fenced` | Tell the primary that the host of a `down` or removed worker is off. Its persistent sandboxes become `cold`. Optional body: `{"reason":"..."}`. The response has `sandboxes_cold`. Gives `409` if the worker is not `down` or removed. Refer to [Fence lost hosts](#fence-lost-hosts). |
| `POST /v1/sandboxes/{id}:migrate` | Move one sandbox to a different host. Optional body: `{"node":"nod_..."}` or `{"node":"primary"}`. |

Each node has `id`, `kind` (`worker` or `edge`), `url`, `state` (`ready`, `suspect`, `down`),
`draining`, `last_seen`, `sandboxes`, `config_current`, `retirement` and `capacity`
(free slots, free memory, reserved memory and its limit, whether memory is
short, ready templates,
warm VMs, CPU model and `fingerprint`). Sandboxes move only between hosts with the same
`fingerprint` and CPU model. `retirement` is `null`, or has `id`,
`origin` (`api` or `autoscaler`), `state` (`draining`, `blocked`,
`ready_to_terminate` or `removed`), `migrate`, `reason`, `created_at`,
`ready_at`, `ended_at`, `failed_moves` and `waiting_for`.

Each sandbox has the field `node`: the ID of the worker that runs it, or
`null` for the primary.

### Usage

- `GET /v1/usage?from=&to=&group_by=sandbox` gives one row for each tenant
  and each UTC hour. With `group_by=sandbox`, it gives one row for each
  sandbox.
- The default range is the current month. The maximum range is 93 days.
- The key must have the scope `usage:read`.
- Each row has these fields:
  - `vcpu_s` and `mem_gib_s`: the reserved size while the sandbox runs. A
    paused sandbox uses no vCPU or memory.
  - `disk_gib_h`: the bytes that are on the disk of the host.
  - `egress_bytes`: the TCP bytes sent and received.
- Limits:
  - Spawnbox counts the bytes of a connection when the connection closes.
    Thus, an egress quota does not stop open connections.
  - In open mode, Spawnbox does not count UDP and ICMP.
  - Spawnbox does not measure the time when the server is stopped.

## Configuration

To change a setting:

1. On the host, open the settings file:

   ```sh
   sudo nano /etc/spawnbox/spawnbox.env
   ```

2. Add the flags to the `SPAWNBOX_ARGS` line.
3. Save the file.
4. Restart the service:

   ```sh
   sudo systemctl restart spawnbox
   ```

> **CAUTION:** A restart deletes running sandboxes. Paused sandboxes stay.
> Running persistent sandboxes pause, or become `cold`.

To see all the flags, type `/opt/spawnbox/bin/spawn-api serve --help`.

| Flag | Default | Function |
| --- | --- | --- |
| `--backend` | `auto` | `firecracker`, `gvisor` or `auto`. `auto` uses Firecracker if `/dev/kvm` opens, and gVisor if it does not. Refer to [Firecracker or gVisor](#firecracker-or-gvisor). |
| `--listen` | `127.0.0.1:8080` | API address |
| `--tls-cert`, `--tls-key` | None | HTTPS for the API (PEM files). Spawnbox reads the files again when they change. |
| `--preview-listen` | `127.0.0.1:8081` | Preview proxy address |
| `--preview-url` | `http://{label}.localhost:8081` | URL pattern for previews |
| `--preview-tls-cert`, `--preview-tls-key` | None | HTTPS for previews, usually a wildcard certificate |
| `--data-dir` | `/var/lib/spawnbox` | Database, builds, paused sandboxes and logs |
| `--max-sandboxes` | 50 | Maximum number of sandboxes that run at the same time |
| `--memory-overcommit-pct` | 150 | Percent of host memory that the `memory_mib` of running sandboxes can add up to. Over 100 fits more sandboxes that do not use all their memory. 100 means the host never gives out more memory than it has. |
| `--vcpus`, `--memory-mib`, `--upper-disk-gib` | 2, 1024, 20 | Size of `base`, and the default size for templates |
| `--max-timeout-s` | 86400 | Maximum `timeout_s` of a sandbox |
| `--memory-pressure-pct` | 10 | Pause idle sandboxes to disk and refuse new ones when free host memory is below this percent, or processes wait for memory (PSI) this percent of the time. `0` turns it off. |
| `--ksm` | off | Let the kernel merge equal memory pages across Firecracker VMs. Saves memory when sandboxes run the same programs, but a sandbox can learn what another holds by timing its writes. Use it only when all sandboxes trust each other. Needs Linux 6.7 or later. |
| `--pin-vcpus` | `auto` | Keep each Firecracker vCPU on one host CPU, spreading VMs over the least used CPUs. `auto` turns it on when the host is itself a VM. Under nested virtualization, VMs whose vCPUs move between CPUs can crash (`KVM_EXIT_FAIL_ENTRY` in the sandbox log) once many share each CPU. `on` or `off` overrides it. |
| `--idle-pause-s` | 600 | Pause a sandbox after this time without requests. `0` means never. |
| `--paused-retention-s` | 604800 | Delete paused sandboxes after this time. Persistent sandboxes are kept. |
| `--shutdown-pause-s` | 30 | On SIGTERM, time for running persistent sandboxes to pause. The ones that do not pause in this time stop and become `cold`. |
| `--max-builds` | 2 | Maximum number of template builds at the same time |
| `--egress-policy` | `{"mode":"allow_all"}` | Network policy for all sandboxes |
| `--dns` | `1.1.1.1` | DNS server that the DNS forwarder sends queries to |
| `--dns-port` | 15053 | Host port (UDP and TCP) of the DNS forwarder. Only sandboxes can connect to it. |
| `--secrets-key-file` | `<data-dir>/secrets.key` | Key that encrypts secrets |
| `--allow-unreadable-env` | Off | Start even if the secrets key cannot read the stored env of some sandboxes. Spawnbox leaves those sandboxes as they are. It does not help with a different key: the egress CA key and stored secrets need the right one. |
| `--database-url` | None | Keep the state in this Postgres database, not in SQLite. Primaries on the same database fail over. You can also use `SPAWNBOX_DATABASE_URL`. Refer to [Keep the API up when the primary stops](#keep-the-api-up-when-the-primary-stops). |
| `--database-ca-file` | None | PEM CA certificates for the TLS certificate of the database |
| `--import-sqlite` | None | On the first start, copy this SQLite database into the empty Postgres database |
| `--events-retention-s` | 604800 | Time to keep events. `0` means always. |
| `--events-output-bytes` | 65536 | Bytes of output kept in `exec.finished` |
| `--warm-pool-memory-pct` | 10 | Percent of host memory for warm VMs. `0` turns warm pools off. |
| `--warm-pool-min` | 1 | Minimum number of warm VMs for `base` |
| `--build-store` | None | Object store for builds: `s3://bucket/prefix` or `file:///path`. Refer to [Keep builds in an object store](#keep-builds-in-an-object-store). |
| `--build-cache-gib` | 0 | Maximum disk for builds on the host. `0` means no limit. Needs `--build-store`. |
| `--otlp-endpoint` | None | OpenTelemetry collector for events and traces. You can also use `OTEL_EXPORTER_OTLP_ENDPOINT`. |
| `--metrics-listen` | None | Address for Prometheus metrics at `/metrics`, for example `127.0.0.1:9464`. It has no authentication. Refer to [See metrics in Prometheus](#see-metrics-in-prometheus). |
| `--fleet-listen` | None | Make this host a primary. Workers connect to this address. Refer to [Use more than one host](#use-more-than-one-host). |
| `--primary` | None | Make this host a worker of the primary at this URL, for example `https://10.0.0.1:7443`. For primaries that fail over, give each URL, separated by commas. |
| `--node-listen` | None | Worker: address for requests from the primary |
| `--advertise` | None | Worker: URL of `--node-listen` for the primary, for example `https://10.0.0.2:7444` |
| `--join-token` | None | Worker: token from `POST /v1/nodes/tokens`. You can also use `SPAWNBOX_JOIN_TOKEN`. Necessary only for the first start. |
| `--primary-ca-sha256` | None | Worker: `ca_sha256` from the same response. Necessary only for the first start. |
| `--self-fence` | Off | Worker: stop persistent VMs after `--fence-after-s` without the primary. Use it on every worker. A leader always stops them when it loses its lease. Refer to [Fence lost hosts](#fence-lost-hosts). |
| `--fence-after-s` | 60 | Seconds without the primary before a worker with `--self-fence` stops its persistent VMs. A new leader waits this time plus `--fence-margin-s` before the old leader's persistent sandboxes become `cold`. |
| `--fence-margin-s` | 30 | Primary: seconds added to the fence time of a worker before its persistent sandboxes become `cold` |
| `--autoscale-hook` | None | Primary: program (absolute path) or webhook URL that adds and removes workers. Refer to [Add and remove workers automatically](#add-and-remove-workers-automatically). |
| `--autoscale-secret` | None | Key to sign webhook requests. You can also use `SPAWNBOX_AUTOSCALE_SECRET`. |
| `--autoscale-min-workers` | 0 | Minimum number of workers |
| `--autoscale-max-workers` | 10 | Maximum number of workers |
| `--autoscale-up-pct` | 70 | Add a worker when the load is above this percent |
| `--autoscale-up-after-s` | 120 | Seconds the load must stay high |
| `--autoscale-down-pct` | 30 | Remove a worker when the load is below this percent |
| `--autoscale-down-after-s` | 1200 | Seconds the load must stay low |

To show previews on the internet:

1. Point a wildcard DNS name, for example `*.preview.example.com`, to the
   host.
2. Add these flags:
   `--preview-listen 0.0.0.0:8081 --preview-url https://{label}.preview.example.com`.
3. Keep `--listen` on `127.0.0.1`, or use `--tls-cert` and `--tls-key`.

Use a registrable domain only for previews, such as
`*.example-preview.com`, not a name under the domain of your own site.
An app in a sandbox can set cookies for its parent domains. Under your
own domain, it could set cookies that your site reads. Previews of
different sandboxes can also set cookies for each other. To stop that,
add the preview domain to the [Public Suffix List](https://publicsuffix.org/).

## Troubleshooting

Type these commands on the host.

| Problem | Cause | Action |
| --- | --- | --- |
| The log shows `sandboxes run in gvisor`, but you want Firecracker | Spawnbox cannot open `/dev/kvm` | Type `spawnbox doctor`. Use a bare-metal server, or turn on nested virtualization. |
| Spawnbox does not start, and the log shows `--backend firecracker needs /dev/kvm` | You set `--backend firecracker` on a host without KVM | Remove `--backend firecracker`, or use a host with KVM. |
| A create gives `503 no_capacity` with `the memory of this host is reserved by other sandboxes` | The running sandboxes reserve `--memory-overcommit-pct` of the host memory | Delete or pause sandboxes, add a worker, or use smaller templates. |
| A create gives `503 no_capacity` with `this host is short of memory` | Free host memory is below `--memory-pressure-pct`; the host is pausing idle sandboxes | Wait and try again, add a worker, or give the sandboxes less memory. |
| A create gives `503 no_capacity` for a `microvm-only` tenant | No Firecracker host has space | Add a Firecracker host, or set `isolation` of the tenant to `any`. |
| The installer stops with `only Debian and Ubuntu are supported` | Wrong operating system | Use Ubuntu 22.04 or later, or Debian 12 or later. |
| `curl .../healthz` shows `Connection refused` | The service is not running | Type `sudo systemctl status spawnbox`. Then read the log with `sudo journalctl -u spawnbox -n 50`. |
| A request gives `401 unauthorized` | The key is wrong or missing | Make sure that `$A` contains `Authorization: Bearer` and your full key. |
| A request gives `429 quota_exceeded` | The tenant is at a quota limit | Delete or pause sandboxes, or increase the quota with `PATCH /v1/tenants/{id}`. |
| A create request gives `409` | The template build is not ready | Wait until `latest_build.state` is `ready`. |
| A snapshot gives `409 protected_env` | The sandbox was created with `env` values, which the template would show | Use secrets for the values, or create the sandbox without `env`. |
| The server stops at start with `cannot read the stored env of ...` | `secrets.key` is not the key that encrypted them, or their rows are damaged | Put back the earlier `secrets.key`, or set `--secrets-key-file`, and restart. If the key is right, add `--allow-unreadable-env` to start without those sandboxes; they stay as they are. |
| You are not sure that `secrets.key` reads the database, for example after you moved or restored it | | Stop the server and type `sudo /opt/spawnbox/bin/spawn-api check-data` (add `--database-url` for Postgres). It decrypts each secret, sandbox env and CA key, and tells which ones fail. |
| `spawnbox-backup.service` fails | The passphrase file is missing, the target cannot be written, or `pg_dump` is older than the database server | Read `sudo journalctl -u spawnbox-backup`. Refer to [Back up and restore](#back-up-and-restore). |
| The server stops at start with `downgrades are not supported` | An earlier release runs on a database that a newer release changed | Install the newer release again, or restore the backup from before the upgrade. |
| A move gives `no host has the same backend, kernel, base disk, Firecracker or runsc, egress CA and CPU model` | The hosts have different backends, files or CPUs | Compare `fingerprint`, `backend` and `cpu` in `GET /v1/nodes`. Sandboxes cannot move between Firecracker and gVisor hosts. Copy `/opt/spawnbox/vmlinux` and `/opt/spawnbox/rootfs.ext4` from the primary to the worker, then restart the worker. |
| A request gives `503 node_unreachable` | The worker that runs the sandbox does not answer | On the primary, look at the worker with `GET /v1/nodes`. On the worker, type `sudo systemctl status spawnbox`. |
| A request for a persistent sandbox gives `503 node_unreachable` for a long time | Its worker is `down`, and no proof says that its VM is stopped | Bring the worker back, or stop its machine and call `POST /v1/nodes/{id}:fenced`. Refer to [Fence lost hosts](#fence-lost-hosts). |
| A request for a cold sandbox gives `503 volume_unavailable` | The only copy of its volume is on a host that is `down` | Bring the host back. |
| A request for a cold sandbox gives `503 rebuilding` | This host is building the sandbox's template spec again, because it cannot use the recorded build | Try again in a minute. Refer to [Upgrades and old builds](#upgrades-and-old-builds). |
| A request gives `503 sandbox_cold` | The sandbox's worker found it `cold`, and the primary did not learn it in time to start it again | Try again. Refer to [Upgrades and old builds](#upgrades-and-old-builds). |
| A request for a cold sandbox gives `409 build_failed` | The sandbox's template spec cannot be built on this host now, for example a setup command fails | Read the error. Fix what the setup needs, such as network access, then try again after 5 minutes. |
| A worker stops with `the join token is unknown, used or expired` | The token was used or is older than one hour | Make a new token on the primary. |
| A worker log shows `not a node of this fleet` | The worker was removed | Remove `/var/lib/spawnbox/fleet/worker/` and add the worker again with a new token. |

To check the host in more detail, type this command:

```sh
spawnbox doctor
```

`doctor` checks cgroup v2, and shows the backend that the host uses:
Firecracker if KVM operates, or gVisor if it does not. Exit code `0`
means that no check failed.

`doctor` also gives `WARN` when `--data-dir` (default `/var/lib/spawnbox`)
is not on a dm-crypt or LUKS disk. Memory files and disks of sandboxes are
not encrypted. On AWS, the encryption of an EBS volume cannot be seen from
the instance, so `doctor` says that it cannot tell. Check the volume in
the EC2 console. Instance store disks are encrypted by AWS.

To remove Spawnbox, type `sudo /opt/spawnbox/install.sh --uninstall`. This
keeps your data. To remove the data too, type
`sudo /opt/spawnbox/install.sh --purge`.

## How Spawnbox works

Each sandbox is a Firecracker microVM. Spawnbox restores it from the
memory snapshot of a template. Each VM has its own jail, cgroup and
network namespace. A small agent in each VM talks to the host through
vsock. On a host without KVM, each sandbox is a gVisor container. The
agent then talks to the host through a private TCP link. All TCP traffic from the sandboxes goes through one egress proxy.
This proxy applies the network policy and adds the secrets.

For diagrams and more data, read **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Development

Spawnbox is a Rust workspace. Install Rust with
[rustup](https://rustup.rs). The file `rust-toolchain.toml` sets the Rust
version.

Type these commands in the repository directory. They operate on macOS
and Linux:

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The VM, network and API code compiles only on Linux. Thus, also run
Clippy on Linux. You can write code on macOS, but you cannot run VMs on
macOS.

### Tests with real VMs

You must have a Linux x86_64 host with KVM that you use only for tests.
On the host, type:

```sh
scripts/m0.sh          # boot, snapshot and restore times, and clone isolation
scripts/m1-smoke.sh    # the full API, with a restart, a crash and HTTPS
```

- The two scripts use `sudo`. They remove all the items that they create.
- They use the kernel, the base disk and Firecracker in
  `~/.cache/spawnbox/artifacts`. `scripts/build-artifacts.sh` makes these
  files.

> **CAUTION:** Do not run `scripts/m1-smoke.sh` while the installed
> service runs. The two use the same firewall table. First, type
> `sudo systemctl stop spawnbox`.

To run the server without the installer:

```sh
a=~/.cache/spawnbox/artifacts
scripts/build-artifacts.sh $a
cargo build --release --locked -p spawn-api
sudo target/release/spawn-api create-key --data-dir /var/lib/spawnbox
sudo target/release/spawn-api serve --data-dir /var/lib/spawnbox \
  --firecracker $a/bin/firecracker --jailer $a/bin/jailer \
  --kernel $a/vmlinux --rootfs $a/rootfs.ext4
```

### Repository layout

| Path | Contents |
| --- | --- |
| `crates/spawn-api` | The HTTP API server (`spawn-api serve`) |
| `crates/spawn-node` | Builds, restores, pauses and connects VMs on one host |
| `crates/spawn-egress` | The egress proxy: policy, records and secrets |
| `crates/spawn-guest` | The agent that runs as PID 1 in each VM |
| `crates/spawn-proto` | The gRPC contract between the host and the guest |
| `crates/spawn-bench` | The boot and restore benchmark |
| `crates/spawnbox-cli` | The `spawnbox` CLI |
| `guest/` | The guest kernel settings and the Debian base image, with Node.js and Python |
| `templates/` | Ready-made template files for coding agent CLIs |
| `install.sh` | The one-line installer: downloads a release (or the code) and runs `deploy/install.sh` |
| `deploy/install.sh` | The installer for one server, from a release bundle or the code |
| `deploy/backup.sh` | Encrypted backups and restores. Refer to [Back up and restore](#back-up-and-restore). |
| `deploy/prometheus/` | Prometheus alert rules and what to do for each alert |
| `.github/workflows/release.yml` | Builds the release bundle for each `v*` tag |
| `scripts/` | Build scripts and end-to-end tests |

## Contributing

We welcome contributions. First, read [CONTRIBUTING.md](CONTRIBUTING.md).
Then do these steps:

1. For a large change, open an issue first.
2. Keep each change small.
3. Run fmt, Clippy and the tests in [Development](#development).
4. If you change the VM, network or API code, run `scripts/m1-smoke.sh`
   on a KVM host. If you change `spawn-node` or the guest, also run
   `scripts/m0.sh`.
5. Add tests for the behavior that you change.
6. If the available functions change, update this README.

> **WARNING:** Do not use real credentials or personal data in tests.

Good first tasks: the TypeScript or Python SDK, the CLI, an MCP server,
and examples for agent frameworks.

If you find a security problem, do not open a public issue. Read
[SECURITY.md](SECURITY.md) to send a private report.

## License

The Spawnbox code has the [Apache-2.0](LICENSE) license. Dependencies,
guest kernels and base images keep their own licenses.

Spawnbox is open source and you run it on your own servers. There is no
hosted service and no paid plan.

## Links

- Website: [spawnbox.tulipfarm.ai](https://spawnbox.tulipfarm.ai)
- Source: [github.com/TulipFarm/spawnbox](https://github.com/TulipFarm/spawnbox)
- Releases: [github.com/TulipFarm/spawnbox/releases](https://github.com/TulipFarm/spawnbox/releases)
- Issues: [github.com/TulipFarm/spawnbox/issues](https://github.com/TulipFarm/spawnbox/issues)
- X: [@TulipFarmAI](https://x.com/TulipFarmAI)
- LinkedIn: [linkedin.com/company/tulipfarmai](https://linkedin.com/company/tulipfarmai)
- YouTube: [youtube.com/@tulipfarmai](https://youtube.com/@tulipfarmai)
- Made by the [TulipFarm](https://tulipfarm.ai) team

<div align="center">
<br>

If Spawnbox helps you, give it a ⭐ on GitHub. It helps other people find it.

</div>
