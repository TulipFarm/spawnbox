# Benchmark

Spawnbox's result on the Better-Auth task from
[hpc-sandbox-benchmarks](https://github.com/starslingdev/hpc-sandbox-benchmarks), with the scripts
and raw results needed to check or repeat it.

## Result

The task clones the [better-auth](https://github.com/better-auth/better-auth) repo, installs it,
builds it, and runs its lint and type checks inside a 4 vCPU, 8 GiB sandbox. The score is the sum
of each step's median over 12 runs. Lower is better.

| Rank | Provider | Total |
| ---: | --- | ---: |
| 1 | Brezel | 118.1 s |
| **2** | **Spawnbox** | **131.1 s** |
| 3 | boat | 135.8 s |
| 4 | Namespace | 150.5 s |
| 5 | Daytona (VM) | 156.6 s |
| 6 | Modal (VM) | 180.8 s |

| Step, median s | Brezel | Spawnbox | boat |
| --- | ---: | ---: | ---: |
| Build | 42.2 | 47.2 | 47.7 |
| Typecheck | 27.6 | 30.6 | 29.9 |
| Lint types | 20.6 | 24.5 | 23.3 |
| Cold install | 8.1 | 8.4 | 13.7 |
| Lint deps (Knip) | 6.9 | 7.5 | 7.5 |
| Lint spell | 4.9 | 5.3 | 5.3 |
| Lint (Biome) | 2.2 | 2.4 | 2.3 |
| Lint format | 2.0 | 2.1 | 2.2 |
| Lint packages | 1.8 | 2.0 | 2.4 |
| Git clone | 1.9 | 1.1 | 1.7 |

## How it was measured

- **Spawnbox:** release v0.1.13 with `--huge-pages`, self-hosted on one AWS
  `m8azn.metal-12xl` (AMD EPYC 9R05, up to 5 GHz, 48 cores) in `us-east-1`,
  14 Nov 2026. One sandbox ran at a time.
- **Other providers:** the suite's published run `37073680030` of 3 Oct 2026, on each provider's
  own hardware. The machines differ, so this compares setups, not only software.
- Only the Better-Auth task was rerun. Spawnbox's results on the suite's other tasks are not part
  of this result.

## Runs left out

Two problems hit the run. Their result files are kept in
[`results/2026-11-14-better-auth/excluded`](results/2026-11-14-better-auth/excluded):

- **`service-restart`:** Ubuntu's automatic upgrades updated libc during replicate 7 and restarted
  services, Spawnbox included. Spawnbox stopped its sandboxes on shutdown, so that replicate failed.
  `host-setup.sh` now stops automatic upgrades before a run.
- **`overlapped`:** a rerun script didn't wait for the main loop, so replicates 7, 10 and 11 ran
  while another replicate was running (totals 131.2, 132.3 and 134.4 s). All three were rerun alone.

The 12 replicates in [`results/2026-11-14-better-auth`](results/2026-11-14-better-auth) each ran
alone. Their totals were 130.1 to 135.0 s. `aggregate.json` is the suite's own aggregate of them.

## Run it yourself

Use a dedicated Linux x86_64 host with `/dev/kvm`. Don't use a personal or production machine.

1. Copy [`host-setup.sh`](host-setup.sh) and [`run-better-auth.sh`](run-better-auth.sh) to the
   host.
2. Run `host-setup.sh`. It installs Spawnbox, turns on huge pages, builds the benchmark template
   and checks out the benchmark repo with the Spawnbox provider. Set `SPAWNBOX_VERSION`,
   `HUGE_PAGES` or `BENCH_REF` to change its defaults.
3. In `tmux`, run `run-better-auth.sh <run-id>`. Each replicate takes about 7 minutes, and the
   script prints each step's median and the total at the end.

The Spawnbox provider is in
[starslingdev/hpc-sandbox-benchmarks#709](https://github.com/starslingdev/hpc-sandbox-benchmarks/pull/709).
Until that merges, `host-setup.sh` checks out the same change from
[TulipFarm/hpc-sandbox-benchmarks](https://github.com/TulipFarm/hpc-sandbox-benchmarks/tree/add-spawnbox-provider).
[`patches/spawnbox-provider.patch`](patches/spawnbox-provider.patch) is that change as a patch.
[`patches/chart-highlight.patch`](patches/chart-highlight.patch) is a local change to the suite's
chart renderer that highlights one provider when `HIGHLIGHT_PROVIDER` is set.
