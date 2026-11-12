# Spawnbox alerts

[`spawnbox-alerts.yml`](spawnbox-alerts.yml) has Prometheus alert rules for
Spawnbox. The metrics are in the
[README](../../README.md#see-metrics-in-prometheus).

## Set up

1. Start each server with `--metrics-listen` on a private address, such as
   `10.0.0.5:9464`.
2. Scrape each host with `job="spawnbox"`. A standby primary does not
   listen on any port until it becomes the leader. Do not scrape standbys
   under `job="spawnbox"`, or `SpawnboxDown` fires for them.

   ```yaml
   scrape_configs:
     - job_name: spawnbox
       static_configs:
         - targets: ["10.0.0.5:9464", "10.0.0.6:9464"]
   rule_files:
     - spawnbox-alerts.yml
   ```

3. For `SpawnboxBackupMissing`, set `SPAWNBOX_BACKUP_METRICS_FILE` in
   `/etc/spawnbox/backup.env` to a file in the textfile directory of the
   node exporter, for example
   `/var/lib/prometheus/node-exporter/spawnbox-backup.prom`. Refer to
   [Back up and restore](../../README.md#back-up-and-restore).
4. Check the rules:

   ```sh
   promtool check rules deploy/prometheus/spawnbox-alerts.yml
   ```

The thresholds are starting points. Change them to fit your load. Each
alert has a `severity` label: `critical` needs action now, `warning` needs
action today, and `info` needs a look.

To find the sandboxes and calls behind an alert, read the events
(`GET /v1/events`) and the server log (`journalctl -u spawnbox`). Each error
response and log line has a request ID.

## Availability

### SpawnboxDown (critical)

**Meaning.** A host has not answered a scrape for 2 minutes.
**Likely cause.** The server stopped or crashed, the host is down, or a
firewall blocks the metrics port.
**First response.** Run `systemctl status spawnbox` and
`journalctl -u spawnbox -n 200` on the host. On a primary, check that a
standby took over. On a worker, the primary marks it `suspect`, then
`down`.

### SpawnboxMetricsMissing (critical)

**Meaning.** No host with `job="spawnbox"` answers.
**Likely cause.** All servers are down, or the scrape configuration lost
the targets.
**First response.** Call `GET /v1/health` on the primary. If it answers,
fix the scrape configuration. If not, treat it as an outage of the
primary.

### SpawnboxRestartLoop (critical)

**Meaning.** The server on a host started 3 or more times in 30 minutes
(`spawnbox_start_time_seconds` changed).
**Likely cause.** A crash at startup or under load, an out-of-memory kill,
or a bad setting that systemd restarts again and again.
**First response.** Read `journalctl -u spawnbox -b` for the panic or the
error before each start, and `dmesg` for an out-of-memory kill. Each crash
makes running ephemeral sandboxes `deleted` and persistent ones `cold`.

## Creates

### SpawnboxCreateErrors (critical)

**Meaning.** More than 5% of creates on a host fail with a server-side
error: `internal`, `node_unreachable`, `volume_unavailable` or
`build_failed` (`spawnbox_creates_total`).
**Likely cause.** A full disk, a broken template build, a worker that
cannot be reached, or a bug.
**First response.** Group `spawnbox_creates_total` by `result` to see the
code. Find a failed create in the log by its request ID. Check the disk
and the fleet alerts.

### SpawnboxInternalErrors (warning)

**Meaning.** Calls of any kind give `500 internal` at more than 0.1 per
second.
**Likely cause.** A database error, a full disk, a VM that does not start
or a bug.
**First response.** Search the log for `internal`. Each one has its
request ID and cause.

### SpawnboxCreateSlow (warning)

**Meaning.** The 95th percentile of create time is above 2 seconds.
**Likely cause.** Warm pools are empty, so creates restore from the build;
the host is short of memory or disk I/O; or builds come from the build
store (`path="cold"`).
**First response.** Look at `spawnbox_create_seconds` by `path` and
`spawnbox_create_step_seconds` by `step`, and at `SpawnboxWarmPoolEmpty`.

## Cold starts

A cold start starts a `cold` persistent sandbox again from its start
record.

### SpawnboxColdStartFailures (warning)

**Meaning.** Cold starts failed (`spawnbox_cold_starts_total` with an error
`result`).
**Likely cause.** `build_failed`: the template spec cannot be built again.
`no_capacity`: no host has room. `volume_unavailable` or
`node_unreachable`: the host with a volume is lost. `internal`: read the
log.
**First response.** The sandboxes stay `cold`, and each call tries again.
For `build_failed`, see `SpawnboxBuildFailed`. For capacity, see
[Capacity](#capacity).

### SpawnboxColdStartSlow (warning)

**Meaning.** The 95th percentile of cold start time is above 60 seconds.
**Likely cause.** Cold starts need a new build (see
`SpawnboxSandboxRebuilds`), or services in the sandboxes start slowly.
**First response.** Check `spawnbox_sandbox_rebuilds_total` and the
`sandbox.rebuilt` events. Calls may give `503 rebuilding` meanwhile.

### SpawnboxColdStartsHigh (info)

**Meaning.** More than 100 cold starts on a host in an hour.
**Likely cause.** Persistent sandboxes lose their memory often: crashes,
failed pauses, a full `snapshot_storage_gib` quota or fencing.
**First response.** Group the `sandbox.cold` events by `reason`.

### SpawnboxSandboxRebuilds (info)

**Meaning.** Cold starts used a new build of the template spec
(`spawnbox_sandbox_rebuilds_total`), because the recorded build was
`missing`, `outdated` or had a guest that is `guest_too_old`.
**Likely cause.** An upgrade, a leader failover to a host without the
build, or removed builds.
**First response.** Usually none: this is expected after an upgrade. If it
does not stop, check that the build store works and that hosts keep their
builds.

### SpawnboxBuildFailed (warning)

**Meaning.** Calls gave `409 build_failed`.
**Likely cause.** A template spec that does not build any more, for
example a package that went away, or no egress for the build.
**First response.** Read the error in the response or the log. Fix the
template and build it again. The same error is given for 5 minutes, then
the next call builds again.

## Services

### SpawnboxServiceRestartsHigh (warning)

**Meaning.** Services in sandboxes restarted more than 20 times in 10
minutes because they exited or failed their health check.
**Likely cause.** A service command that crashes, or a health check that
is wrong.
**First response.** Find the sandboxes in the `service.restarted` and
`service.unhealthy` events, and read `/var/log/spawnbox/<name>.log` in
them. This is usually a problem of the tenant, not of the host.

## Fencing

Refer to [Fence lost hosts](../../README.md#fence-lost-hosts).

### SpawnboxSelfFenced (critical)

**Meaning.** A host stopped its persistent sandboxes because it lost the
primary or its lease (`spawnbox_self_fences_total`).
**Likely cause.** A network partition between the worker and the primary,
or a primary that was down too long.
**First response.** Check the network from the host to the primary and to
the database. The sandboxes become `cold` and start again on the next
call.

### SpawnboxSandboxesFencedCold (warning)

**Meaning.** The primary made persistent sandboxes of a lost host `cold`
(`spawnbox_fenced_cold_total`), by proof: `operator`, `autoscaler`,
`self_fence` or `failover`.
**Likely cause.** A worker was lost, or the primary failed over.
**First response.** Find the host in the `node.fenced` event. Bring it back
or remove it. Its sandboxes start again on the next call.

### SpawnboxStaleCopies (warning)

**Meaning.** A host deleted copies of persistent sandboxes from an older
generation (`spawnbox_stale_copies_total`).
**Likely cause.** A fenced host came back. This is the guard working: the
newer copy is kept.
**First response.** Confirm that the host was fenced before. If not, read
the log.

### SpawnboxWorkerDown (critical)

**Meaning.** The primary marks a worker `down`.
**Likely cause.** The host or its server is down, or the network is cut.
**First response.** Check the host. Its ephemeral sandboxes are lost. Fence
it to start its persistent sandboxes elsewhere.

### SpawnboxWorkerSuspect (warning)

**Meaning.** A worker has been `suspect` for 10 minutes.
**Likely cause.** Missed heartbeats: a slow or partly cut network, or an
overloaded host.
**First response.** Check the network between the primary and the worker,
and the load of the worker.

### SpawnboxLeaderChanged (warning)

**Meaning.** `spawnbox_leader_term` had more than one `holder` (host ID)
in the last 15 minutes: a standby took over as the primary. A primary that
restarts and takes the lease again gets a new term but keeps its holder,
so it does not fire this alert.
**Likely cause.** The old primary crashed, lost the database or was
stopped.
**First response.** Find out why the old primary stopped. Workers fence
and reconnect. Persistent sandboxes of the old primary become `cold`.

### SpawnboxTwoLeaders (critical)

**Meaning.** More than one host reports a leader term for 2 minutes.
**Likely cause.** An old primary that does not know it lost its lease, or a
scrape of a stale host.
**First response.** Check `spawnbox_leader_term` of each host. Stop the one
with the lower term. The lease and generations keep it from writing.

## Capacity

### SpawnboxNoCapacity (warning)

**Meaning.** Calls gave `503 no_capacity` for 10 minutes.
**Likely cause.** All hosts are full: slots, memory or the isolation that a
tenant needs.
**First response.** Check `spawnbox_fleet_create_refused_total` by
`reason` and `spawnbox_node_committed_ratio`. Add hosts, or delete
sandboxes that are not needed.

### SpawnboxSlotsNearlyFull (warning)

**Meaning.** More than 90% of the sandbox slots of a host are in use.
**First response.** Add hosts, or raise `--max-sandboxes` if the host has
memory for it.

### SpawnboxFleetLoadHigh (warning)

**Meaning.** The load of the fleet is above 85%.
**First response.** Add workers before creates give `no_capacity`.

### SpawnboxWarmPoolEmpty (warning)

**Meaning.** A warm pool has had no ready VM for 10 minutes.
**Likely cause.** Creates use VMs faster than the pool fills, or the pool
cannot fill: short of memory, or a broken build.
**First response.** Check `spawnbox_warm_pool_misses_total` and the log
for warm pool errors. Raise `min_warm` of the template, or add memory.

### SpawnboxRetirementBlocked (warning)

**Meaning.** A worker has been `blocked` from retirement for 30 minutes.
**Likely cause.** It has sandboxes or volumes that cannot move, such as a
volume's only copy.
**First response.** Get the worker (`GET /v1/nodes/NODE_ID`) and read
`retirement.waiting_for`. Move or delete what blocks it.

## Resources

### SpawnboxDataDirFilling (warning), SpawnboxDataDirFull (critical)

**Meaning.** The file system of the data directory has less than 10% or 5%
free (`spawnbox_data_dir_available_bytes`).
**Likely cause.** Paused sandboxes, builds, volumes or logs.
**First response.** Run `du -sh /var/lib/spawnbox/*`. Delete unused
templates and old builds, lower `--paused-retention-s`, or grow the disk. Do not
delete files under `/var/lib/spawnbox` by hand.

### SpawnboxDataDirFillsSoon (warning)

**Meaning.** At the rate of the last hour, the data directory fills within
6 hours.
**First response.** As for `SpawnboxDataDirFilling`. Find what grows fast,
for example one tenant's volumes.

### SpawnboxMemoryPressure (warning), SpawnboxMemoryCritical (critical)

**Meaning.** More than 90% or 97% of host memory is in use.
**Likely cause.** Many running sandboxes, a high `--memory-overcommit-pct`,
or sandboxes that use all their memory.
**First response.** The host pauses idle sandboxes under memory pressure.
Lower `--memory-overcommit-pct`, add hosts, or pause or delete sandboxes.

## Backups

### SpawnboxBackupMissing (warning)

**Meaning.** No backup worked for 2 days.
**Likely cause.** The timer is off, the target is full or cannot be
reached, the passphrase file is missing, or `pg_dump` is older than the
database server.
**First response.** Run `systemctl status spawnbox-backup` and
`journalctl -u spawnbox-backup`. Start one with
`systemctl start spawnbox-backup`.
