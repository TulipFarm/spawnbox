use std::collections::{BTreeMap, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use spawn_node::firecracker::{Host, Limits};
use spawn_node::net::{self, HostNet, NetMode};
use spawn_node::{
    Build, Node, Recipe, Restored, Slot, TEMPLATE_INDEX, Vm, absolute, guest, new_identity,
};
use tokio::task::JoinSet;
use tonic::transport::Channel;

use crate::stats;

const RANDOM_CMD: &str = "head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n'";
const SSH_KEY_CMD: &str = "rm -f /tmp/k /tmp/k.pub && ssh-keygen -q -t ed25519 -N '' -f /tmp/k \
     && ssh-keygen -lf /tmp/k.pub | cut -d' ' -f2";
const WRITE_CMD: &str = "sudo touch /usr/local/spawnbox-write-test && echo ok";
const INTERNET_CMD: &str =
    "curl -sS -o /dev/null -w '%{http_code}' --max-time 10 https://deb.debian.org/debian/";
const METADATA_CMD: &str = "curl -s --max-time 3 -o /dev/null http://169.254.169.254/latest/meta-data/ \
     && echo reachable || echo blocked";

#[derive(clap::Args)]
pub struct Args {
    /// Path to the Firecracker binary.
    #[arg(long)]
    firecracker: PathBuf,
    /// Path to the jailer binary from the same Firecracker release.
    #[arg(long)]
    jailer: PathBuf,
    /// Path to the uncompressed guest kernel (vmlinux).
    #[arg(long)]
    kernel: PathBuf,
    /// Path to the ext4 base disk with spawn-guest installed.
    #[arg(long)]
    rootfs: PathBuf,
    /// Directory for builds, jails and logs.
    #[arg(long)]
    work_dir: PathBuf,
    /// Number of timed restores.
    #[arg(long, default_value_t = 20)]
    runs: u32,
    /// Number of clones restored at the same time for the checks.
    #[arg(long, default_value_t = 10)]
    clones: u32,
    #[arg(long, default_value_t = 2)]
    vcpus: u8,
    #[arg(long, default_value_t = 1024)]
    memory_mib: u32,
    /// Logical size of each VM's writable disk.
    #[arg(long, default_value_t = 20)]
    upper_disk_gib: u32,
    /// DNS resolver that guest DNS requests are sent to.
    #[arg(long, default_value_t = Ipv4Addr::new(1, 1, 1, 1))]
    dns: Ipv4Addr,
}

pub async fn run(args: Args) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        bail!("run as root: it creates jails, cgroups, network namespaces and firewall rules");
    }
    if args.runs == 0 || args.clones < 2 {
        bail!("--runs must be at least 1 and --clones at least 2");
    }
    tokio::fs::create_dir_all(&args.work_dir).await?;
    let work = args.work_dir.canonicalize()?;
    let host = Host {
        jailer: absolute(&args.jailer)?,
        firecracker: absolute(&args.firecracker)?,
        jails: work.join("jails"),
        logs: work.join("logs"),
    };
    net::remove_stale_namespaces().await?;
    host.remove_all().await;
    host.setup()?;
    let host_net = HostNet::setup(args.dns, None).await?;

    let result = run_checks(&args, host, &work).await;

    host_net.teardown().await;
    let report = result?;
    let path = work.join("m0-results.json");
    tokio::fs::write(&path, serde_json::to_vec_pretty(&report)?).await?;
    println!("wrote {}", path.display());
    if report["clones"]["pass"] != json!(true) {
        bail!("clone checks failed");
    }
    Ok(())
}

async fn run_checks(args: &Args, host: Host, work: &Path) -> Result<Value> {
    let node = Node {
        host: host.clone(),
        runsc: None,
        dns: args.dns,
    };
    let recipe = Recipe {
        setup: Vec::new(),
        warmup: Vec::new(),
        env: BTreeMap::new(),
        limits: Limits {
            vcpus: args.vcpus,
            memory_mib: args.memory_mib,
        },
        disk_gib: args.upper_disk_gib,
        net: NetMode::Open,
        ca: None,
        base: None,
        record_pages: false,
    };

    let result = async {
        let slot = Slot {
            id: "template",
            index: TEMPLATE_INDEX,
        };
        let (build, t) = node
            .build_template(
                &work.join("build"),
                &args.kernel,
                &args.rootfs,
                &recipe,
                &slot,
                &mut std::io::stdout(),
            )
            .await?;
        let ctx = Arc::new(Ctx { node, build });
        let template = json!({
            "agent_version": t.agent_version,
            "boot_to_agent_ms": t.boot_to_agent_ms,
            "snapshot_create_ms": t.snapshot_create_ms,
            "upper_disk_used_kib": t.upper_disk_used_kib,
        });
        println!("template: {template}");
        let restores = timed_restores(&ctx, args.runs).await?;
        println!("restores: {restores}");
        let clones = check_clones(&ctx, args.runs + 1, args.clones).await?;
        println!("clones: {clones}");
        anyhow::Ok(json!({ "template": template, "restores": restores, "clones": clones }))
    }
    .await;

    // Anything left by a failed step: VMs were killed when dropped.
    let _ = net::remove_stale_namespaces().await;
    host.remove_all().await;
    result
}

/// What every restore needs.
struct Ctx {
    node: Node,
    build: Build,
}

/// Milliseconds per step. `prepare` and `disk_copy` are measured from the
/// start; the rest from starting the jailer, after preparation.
#[derive(Default)]
struct Steps {
    prepare: f64,
    disk_copy: f64,
    spawn: f64,
    load: f64,
    hello: f64,
    apply: f64,
    first_output: f64,
    total: f64,
}

async fn restore(ctx: &Ctx, id: &str, index: u32) -> Result<(Vm, Channel, Instant, Steps)> {
    let Restored {
        vm,
        channel,
        started,
        steps: s,
    } = ctx
        .node
        .restore(&ctx.build, id, index, NetMode::Open, &[])
        .await?;
    let steps = Steps {
        prepare: s.prepare,
        disk_copy: s.disk_copy,
        spawn: s.spawn,
        load: s.load,
        hello: s.hello,
        ..Steps::default()
    };
    Ok((vm, channel, started, steps))
}

async fn timed_restores(ctx: &Ctx, runs: u32) -> Result<Value> {
    let mut all = Vec::new();
    for run in 0..runs {
        let id = format!("restore-{run}");
        let (vm, channel, start, mut steps) = restore(ctx, &id, 1 + run).await?;
        guest::apply(&channel, new_identity(&id)?).await?;
        steps.apply = ms(start.elapsed());
        let before_exec = start.elapsed();
        let output = guest::exec(&channel, "echo ready").await?;
        steps.first_output = ms(before_exec + output.first_output.context("no output")?);
        steps.total = ms(start.elapsed());
        drop(channel);
        vm.stop().await;
        all.push(steps);
    }
    let summarize = |pick: fn(&Steps) -> f64| {
        let samples: Vec<f64> = all.iter().map(pick).collect();
        json!({ "p50": stats::percentile(&samples, 50.0), "p95": stats::percentile(&samples, 95.0) })
    };
    Ok(json!({
        "runs": runs,
        "prepare_jail_disk_and_network_ms": summarize(|s| s.prepare),
        "upper_disk_copy_ms": summarize(|s| s.disk_copy),
        "after_prepare": {
            "jailer_to_api_ready_ms": summarize(|s| s.spawn),
            "load_and_resume_ms": summarize(|s| s.load),
            "agent_hello_ms": summarize(|s| s.hello),
            "apply_identity_ms": summarize(|s| s.apply),
            "first_output_ms": summarize(|s| s.first_output),
            "total_ms": summarize(|s| s.total),
        },
    }))
}

struct CloneProbe {
    random_before: String,
    random_after: String,
    ssh_key: String,
    user: String,
    root_fs: String,
    sudo_write: String,
    http_status: String,
    metadata: String,
    host: String,
}

async fn probe_clone(ctx: &Ctx, id: String, index: u32) -> Result<CloneProbe> {
    let (vm, channel, _, _) = restore(ctx, &id, index).await?;
    let out = async |cmd: &str| guest::exec(&channel, cmd).await.map(|o| o.stdout);
    let random_before = out(RANDOM_CMD).await?;
    guest::apply(&channel, new_identity(&id)?).await?;
    let host_cmd = format!(
        "timeout 3 bash -c 'echo > /dev/tcp/{}/22' 2>/dev/null && echo reachable || echo blocked",
        vm.host_ip()
    );
    let probe = CloneProbe {
        random_before,
        random_after: out(RANDOM_CMD).await?,
        ssh_key: out(SSH_KEY_CMD).await?,
        user: out("id -un").await?,
        root_fs: out("findmnt -no FSTYPE /").await?,
        sudo_write: out(WRITE_CMD).await?,
        http_status: out(INTERNET_CMD).await?,
        metadata: out(METADATA_CMD).await?,
        host: out(&host_cmd).await?,
    };
    drop(channel);
    vm.stop().await;
    Ok(probe)
}

async fn check_clones(ctx: &Arc<Ctx>, first_index: u32, count: u32) -> Result<Value> {
    let mut tasks = JoinSet::new();
    for clone in 0..count {
        let ctx = Arc::clone(ctx);
        tasks.spawn(async move {
            probe_clone(&ctx, format!("clone-{clone}"), first_index + clone).await
        });
    }
    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result??);
    }
    let unique =
        |pick: fn(&CloneProbe) -> &str| results.iter().map(pick).collect::<HashSet<_>>().len();
    let all = |test: fn(&CloneProbe) -> bool| results.iter().filter(|p| test(p)).count();
    let n = count as usize;
    let mut report = json!({
        "count": count,
        "unique_random_before_apply": unique(|p| &p.random_before),
        "unique_random_after_apply": unique(|p| &p.random_after),
        "unique_ssh_keys": unique(|p| &p.ssh_key),
        "runs_as_user": all(|p| p.user == "user"),
        "overlay_root": all(|p| p.root_fs == "overlay"),
        "sudo_write_to_root": all(|p| p.sudo_write == "ok"),
        "internet_ok": all(|p| p.http_status.starts_with('2') || p.http_status.starts_with('3')),
        "metadata_blocked": all(|p| p.metadata == "blocked"),
        "host_blocked": all(|p| p.host == "blocked"),
    });
    // Every check must hold for every clone. Random bytes before `Apply` are
    // reported but not required: that depends on the kernel's VMGenID support.
    let pass = report.as_object().is_some_and(|fields| {
        fields
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "count" | "unique_random_before_apply"))
            .all(|(_, value)| value == &json!(n))
    });
    report["pass"] = json!(pass);
    Ok(report)
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}
