# Security

Spawnbox runs code that you do not trust. A problem in its isolation,
network control, secrets or API keys can affect every sandbox on a host.

## Report a problem

Do not open a public issue, discussion or pull request.

1. Go to the [Security tab](https://github.com/TulipFarm/spawnbox/security)
   of this repository.
2. Click **Report a vulnerability**.
3. Tell us:
   - the version or commit that you used,
   - the backend (Firecracker or gVisor) and the host operating system,
   - the steps to show the problem,
   - what an attacker can do with it.

We reply within 5 working days. We tell you when we have a fix, and we
give you credit in the advisory if you want it.

## Supported versions

Spawnbox is in early development. We fix security problems only on the
`main` branch.

## Scope

These are in scope:

- A sandbox that gets out of its microVM or gVisor container
- A sandbox that reads or changes another sandbox, the host or the API
- A sandbox that connects to hosts that its network rules do not allow
- A secret value that gets into a sandbox
- An API key or browser token that gives more access than it should
- One tenant that sees or changes the data of a different tenant

Problems in Firecracker, gVisor, the Linux kernel or other dependencies
go to those projects. Tell us too if Spawnbox makes the problem worse.

## Deploy safely

- Serve previews on a registrable domain that you use only for previews.
  An app in a sandbox can set cookies for its parent domains, so under
  your own domain it could set cookies for your site. Previews of
  different sandboxes can set cookies for each other unless the preview
  domain is on the [Public Suffix List](https://publicsuffix.org/).
- Protect a worker as you protect the primary. A worker holds every API
  key hash and the key that signs browser session tokens, so root on a
  worker can make session tokens for any sandbox of the fleet.
