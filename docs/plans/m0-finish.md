# Plan: finish M0

Goal: run the M0 check on a safer, more usable VM, built from our own kernel.

## Scope

1. **Guest kernel.** Build Linux 6.18 LTS (the newest long-term line that
   Firecracker v1.17 tests) from Firecracker's guest config, plus the options in
   `guest/kernel/spawnbox.config`. The build fails if a required option is off.
2. **Jailer.** Every VM runs under the Firecracker jailer: its own chroot,
   its own unprivileged uid and gid, and a cgroup v2 group with CPU and memory
   limits. `spawn-bench` runs as root to set this up.
3. **Writable root.** The base disk stays read-only and shared. Each VM gets a
   sparse 20 GiB upper disk; the guest builds an overlay root from both. With
   no upper disk the guest uses memory (tmpfs) for the upper layer.
4. **User.** Commands run as `user` (uid 1000) with passwordless `sudo`, in
   `/workspace`, unless the request asks for another user.
5. **Network.** Each VM gets its own network namespace with the same guest
   address (`172.16.0.2/30`). Traffic leaves through host NAT. Cloud metadata,
   private ranges, the host itself and SMTP are blocked. DNS goes to one
   configurable resolver.

## Not in this step

- `spawn-egress`, the per-node DNS resolver, and egress policy.
- Network and disk rate limits.
- `Files`, `Pty`, stdin, and background processes.
- Our own netlink code: the bench calls `ip` and `nft`.

## Done when

- The kernel builds from pinned sources and boots.
- `scripts/m0.sh` runs every VM under the jailer and passes on the KVM host.
- Every clone: runs commands as `user`, can write to `/` with `sudo`, reaches
  the internet, cannot reach cloud metadata, and has unique random state.
- No VM processes, jails, namespaces, cgroups or firewall tables remain after
  the run.
