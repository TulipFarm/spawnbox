# Contributing

Spawnbox is in M2. Keep changes small and tied to
the [technical spec](docs/spec.md). The spec describes planned behavior;
the README describes what is implemented.

## Local checks

Run these commands from the repository root before submitting a change:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The guest agent ships as a static musl binary. If you change it, also run:

```sh
cargo clippy -p spawn-guest --all-targets --locked --target x86_64-unknown-linux-musl -- -D warnings
```

`spawn-api`, `spawn-node` and the `spawn-egress` proxy only build their VM
and network code on Linux, so lint them on Linux too. If you change them,
run `scripts/m1-smoke.sh` on a KVM host with internet access (its egress
checks reach example.com, postman-echo.com, httpbin.org and github.com); if
you change `spawn-node` or the guest, also run `scripts/m0.sh`. If you
change `deploy/install.sh`, run it on a test host, run it again (upgrade),
then run it with `--uninstall` and `--purge`. Do not run the smoke test
while the installed service runs: they share the host's nftables table.
The smoke test needs `openssl` for its HTTPS checks.

Add focused tests for changed behavior. Do not treat a macOS test pass or a
successful `doctor` run as proof that Firecracker works. Real VM tests must
run on a dedicated Linux KVM host and clean up only resources they created.

Never use production credentials or personal data in sandbox tests.
Do not add private infrastructure, secrets, or paid-service dependencies.

Unless explicitly stated otherwise, contributions to Spawnbox's own code
are provided under the project's Apache-2.0 license.
