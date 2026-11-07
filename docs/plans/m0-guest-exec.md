# M0: guest agent, exec over vsock, clone entropy

Goal: prove the core sandbox loop on a Linux KVM host before building the API.

## Scope

- `spawn-proto`: protobuf definitions for the host-guest protocol, compiled
  in pure Rust (no `protoc` install needed).
- `spawn-guest`: static musl binary, runs as PID 1 in the VM.
  - Mounts `/proc`, `/sys`, `/dev`, `/dev/pts`, `/dev/shm`, `/run`, `/tmp`.
  - Starts the agent as a child process and reaps orphaned processes.
  - gRPC server on vsock port 1024 with:
    - `Health.Hello`: protocol version handshake.
    - `Identity.Apply`: wall clock, host entropy (`RNDADDENTROPY`), hostname.
    - `Process.Exec`: run `bash -lc <cmd>`, stream stdout and stderr, then the
      exit result.
- `spawn-bench`: host-side tool that drives Firecracker directly.
  - Build a template: boot, wait for the agent, pause, full snapshot.
  - Restore N times; time each step up to the first exec output.
  - Restore 10 clones from one memory file at once; check random bytes and
    SSH keys differ in every clone.
- Debian base image build script with `spawn-guest` as init.

## Not in this step

- Jailer, networking, upper disk and overlay root, `uid 1000` user.
- Building our own guest kernel. The Firecracker CI kernel is used for now.
- `spawn-node`, the API, warm pools.

## Done when

- Unit tests pass on macOS and Linux; Linux-only code compiles for Linux.
- On the KVM test host: 20 restores answer an exec over vsock, with timings.
- 10 concurrent clones from one memory file all report different random bytes
  and different SSH keys.
