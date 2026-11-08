# Project scope

Spawnbox is an open-source, self-hosted project. Spawnbox's own code uses
Apache-2.0; third-party code retains its own licenses. Do not introduce
private components, paid tiers, managed hosting, or a hosted control plane
as a requirement.

A possible future company is not part of the current implementation plan.
Keep Firecracker as the default runtime target and gVisor as the planned
fallback. The initial runtime target is Linux x86_64.

# Development

- Do not describe planned features as implemented.
- Keep the README's current capabilities and limitations accurate.
- Use the pinned Rust toolchain and the existing Cargo workspace.
- Choose the latest stable Rust and dependency releases when adding or updating
  tooling. Pin the toolchain and commit the lockfile; avoid prereleases unless
  explicitly requested.
- Run formatting, Clippy and focused tests for changed behavior.
- Run only one test process at a time.
- Real Firecracker tests require a dedicated Linux KVM host. Never substitute
  mocked checks for evidence of a successful VM boot.
- Never run untrusted sandbox workloads on a personal or production machine.
