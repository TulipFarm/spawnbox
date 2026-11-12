//! Prometheus metrics in the text format, served on `--metrics-listen`.
//!
//! Counters and histograms are kept in one process-wide registry as events
//! happen. Gauges (sandboxes, slots, memory, warm pools) are read when
//! Prometheus scrapes. Every metric is about the host that serves it.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard};

use crate::model::ApiError;

/// Upper bounds of the histogram buckets, in seconds.
const BUCKETS: [f64; 14] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 300.0,
];

/// Name, type and help of every metric, in the order they are written.
const METRICS: &[(&str, &str, &str)] = &[
    (
        "spawnbox_create_seconds",
        "histogram",
        "Time to create a sandbox on this host, by path (warm, cached or cold) and backend.",
    ),
    (
        "spawnbox_create_step_seconds",
        "histogram",
        "Time of each create step on this host: prepare, restore or fixups.",
    ),
    (
        "spawnbox_creates_total",
        "counter",
        "Create calls this host answered, by result: ok or the error code.",
    ),
    (
        "spawnbox_cold_starts_total",
        "counter",
        "Cold starts of persistent sandboxes on this host, by result: ok or the error code.",
    ),
    (
        "spawnbox_cold_start_seconds",
        "histogram",
        "Time of each cold start of a persistent sandbox on this host that worked.",
    ),
    (
        "spawnbox_api_errors_total",
        "counter",
        "API error responses, by error code.",
    ),
    (
        "spawnbox_egress_connections_total",
        "counter",
        "Outbound connections through the egress proxy, by verdict.",
    ),
    (
        "spawnbox_dns_queries_total",
        "counter",
        "DNS queries from sandboxes and template builds, by verdict.",
    ),
    (
        "spawnbox_sandboxes",
        "gauge",
        "Sandboxes on this host that have not ended, by state.",
    ),
    (
        "spawnbox_node_committed_ratio",
        "gauge",
        "Part of this host's slots or memory in use (0 to 1).",
    ),
    (
        "spawnbox_warm_pool_ready",
        "gauge",
        "Warm VMs ready, by template, build and network.",
    ),
    (
        "spawnbox_service_restarts_total",
        "counter",
        "Restarts of services in sandboxes, by reason: exit, unhealthy or request.",
    ),
    (
        "spawnbox_warm_pool_hits_total",
        "counter",
        "Creates that took a warm VM, by build.",
    ),
    (
        "spawnbox_warm_pool_misses_total",
        "counter",
        "Creates that found no warm VM, by build.",
    ),
    (
        "spawnbox_fleet_nodes",
        "gauge",
        "Workers known to the primary, by state.",
    ),
    (
        "spawnbox_fleet_load",
        "gauge",
        "Part of the slots or memory in use over the primary and its ready workers that are not draining (0 to 1).",
    ),
    (
        "spawnbox_fleet_create_refused_total",
        "counter",
        "Creates the primary refused because no host had room, by reason.",
    ),
    (
        "spawnbox_self_fences_total",
        "counter",
        "Times this host stopped its persistent sandboxes because it lost the primary or the leader lease, by reason.",
    ),
    (
        "spawnbox_fenced_cold_total",
        "counter",
        "Persistent sandboxes of a lost worker made cold once its copies were known to be stopped, by proof.",
    ),
    (
        "spawnbox_stale_copies_total",
        "counter",
        "Copies of persistent sandboxes destroyed on this host because a newer generation runs elsewhere.",
    ),
    (
        "spawnbox_sandbox_rebuilds_total",
        "counter",
        "Cold starts of persistent sandboxes whose recorded build could not be used here, so their template spec was built again or an equal build was taken, by reason.",
    ),
    (
        "spawnbox_fleet_retirements",
        "gauge",
        "Workers being retired, by state: draining, blocked or ready_to_terminate.",
    ),
    (
        "spawnbox_leader_term",
        "gauge",
        "With --database-url: the term of the leader lease this primary holds. It grows each time a primary takes the lease.",
    ),
    (
        "spawnbox_data_dir_available_bytes",
        "gauge",
        "Bytes free for the server on the file system of the data directory.",
    ),
    (
        "spawnbox_data_dir_size_bytes",
        "gauge",
        "Size in bytes of the file system of the data directory.",
    ),
    (
        "spawnbox_start_time_seconds",
        "gauge",
        "When this server process started, in seconds since the Unix epoch.",
    ),
];

pub type Labels = Vec<(&'static str, String)>;

struct Histogram {
    /// Count per bucket (not cumulative), then the +Inf bucket.
    counts: [u64; BUCKETS.len() + 1],
    sum: f64,
}

struct Registry {
    counters: BTreeMap<(&'static str, Labels), u64>,
    histograms: BTreeMap<(&'static str, Labels), Histogram>,
}

pub struct Metrics(Mutex<Registry>);

static REGISTRY: Metrics = Metrics::new();

impl Metrics {
    const fn new() -> Self {
        Self(Mutex::new(Registry {
            counters: BTreeMap::new(),
            histograms: BTreeMap::new(),
        }))
    }

    fn registry(&self) -> MutexGuard<'_, Registry> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn inc(&self, name: &'static str, labels: Labels) {
        let mut registry = self.registry();
        *registry.counters.entry((name, labels)).or_default() += 1;
    }

    /// Counts a call by its `result` label: `ok`, or its error code.
    pub fn inc_result<T>(&self, name: &'static str, outcome: &Result<T, ApiError>) {
        let result = match outcome {
            Ok(_) => "ok",
            Err(error) => error.code.as_str(),
        };
        self.inc(name, vec![("result", result.into())]);
    }

    pub fn observe(&self, name: &'static str, labels: Labels, seconds: f64) {
        let mut registry = self.registry();
        let histogram = registry
            .histograms
            .entry((name, labels))
            .or_insert_with(|| Histogram {
                counts: [0; BUCKETS.len() + 1],
                sum: 0.0,
            });
        let bucket = BUCKETS
            .iter()
            .position(|le| seconds <= *le)
            .unwrap_or(BUCKETS.len());
        histogram.counts[bucket] += 1;
        histogram.sum += seconds;
    }

    /// The text exposition of the registry and `samples`, read now. Each
    /// sample is a metric name, labels and value.
    pub fn render(&self, samples: &[(&'static str, Labels, f64)]) -> String {
        let registry = self.registry();
        let mut out = String::new();
        for (name, kind, help) in METRICS {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} {kind}");
            for ((_, labels), value) in registry.counters.iter().filter(|((n, _), _)| n == name) {
                let _ = writeln!(out, "{name}{} {value}", labels_text(labels, None));
            }
            for ((_, labels), h) in registry.histograms.iter().filter(|((n, _), _)| n == name) {
                let mut cumulative = 0;
                for (i, le) in BUCKETS.iter().enumerate() {
                    cumulative += h.counts[i];
                    let le = le.to_string();
                    let _ = writeln!(
                        out,
                        "{name}_bucket{} {cumulative}",
                        labels_text(labels, Some(&le))
                    );
                }
                cumulative += h.counts[BUCKETS.len()];
                let _ = writeln!(
                    out,
                    "{name}_bucket{} {cumulative}",
                    labels_text(labels, Some("+Inf"))
                );
                let _ = writeln!(out, "{name}_sum{} {}", labels_text(labels, None), h.sum);
                let _ = writeln!(
                    out,
                    "{name}_count{} {cumulative}",
                    labels_text(labels, None)
                );
            }
            for (_, labels, value) in samples.iter().filter(|(n, _, _)| n == name) {
                let _ = writeln!(out, "{name}{} {value}", labels_text(labels, None));
            }
        }
        out
    }
}

/// `{a="1",b="2"}`, with `le` last if given; empty with no labels.
fn labels_text(labels: &Labels, le: Option<&str>) -> String {
    let mut parts: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
        .collect();
    if let Some(le) = le {
        parts.push(format!("le=\"{le}\""));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("{{{}}}", parts.join(","))
    }
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

pub fn inc(name: &'static str, labels: Labels) {
    REGISTRY.inc(name, labels);
}

pub fn inc_result<T>(name: &'static str, outcome: &Result<T, ApiError>) {
    REGISTRY.inc_result(name, outcome);
}

pub fn observe(name: &'static str, labels: Labels, seconds: f64) {
    REGISTRY.observe(name, labels, seconds);
}

pub fn render(samples: &[(&'static str, Labels, f64)]) -> String {
    REGISTRY.render(samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_counters_histograms_and_samples() {
        let metrics = Metrics::new();
        metrics.inc(
            "spawnbox_api_errors_total",
            vec![("code", "not_found".into())],
        );
        metrics.inc(
            "spawnbox_api_errors_total",
            vec![("code", "not_found".into())],
        );
        let labels = || vec![("path", "warm".into()), ("backend", "firecracker".into())];
        metrics.observe("spawnbox_create_seconds", labels(), 0.008);
        metrics.observe("spawnbox_create_seconds", labels(), 0.07);
        metrics.observe("spawnbox_create_seconds", labels(), 1000.0);
        let out = metrics.render(&[(
            "spawnbox_sandboxes",
            vec![("state", "run\"ning".into())],
            3.0,
        )]);
        assert!(out.contains("# TYPE spawnbox_api_errors_total counter\n"));
        assert!(out.contains("spawnbox_api_errors_total{code=\"not_found\"} 2\n"));
        assert!(out.contains(
            "spawnbox_create_seconds_bucket{path=\"warm\",backend=\"firecracker\",le=\"0.005\"} 0\n"
        ));
        assert!(out.contains(
            "spawnbox_create_seconds_bucket{path=\"warm\",backend=\"firecracker\",le=\"0.01\"} 1\n"
        ));
        assert!(out.contains(
            "spawnbox_create_seconds_bucket{path=\"warm\",backend=\"firecracker\",le=\"300\"} 2\n"
        ));
        assert!(out.contains(
            "spawnbox_create_seconds_bucket{path=\"warm\",backend=\"firecracker\",le=\"+Inf\"} 3\n"
        ));
        assert!(
            out.contains(
                "spawnbox_create_seconds_count{path=\"warm\",backend=\"firecracker\"} 3\n"
            )
        );
        assert!(out.contains("spawnbox_sandboxes{state=\"run\\\"ning\"} 3\n"));
    }
    #[test]
    fn counts_results_by_error_code() {
        use crate::model::{ApiError, Code};
        let metrics = Metrics::new();
        metrics.inc_result("spawnbox_creates_total", &Ok::<(), ApiError>(()));
        metrics.inc_result("spawnbox_creates_total", &Ok::<(), ApiError>(()));
        let refused: Result<(), _> = Err(ApiError::new(Code::NoCapacity, "full"));
        metrics.inc_result("spawnbox_creates_total", &refused);
        let out = metrics.render(&[]);
        assert!(out.contains("spawnbox_creates_total{result=\"ok\"} 2\n"));
        assert!(out.contains("spawnbox_creates_total{result=\"no_capacity\"} 1\n"));
    }

    /// Every metric the alert rules use is one the server exports, or the
    /// one the backup script writes.
    #[test]
    fn alert_rules_use_known_metrics() {
        let rules = include_str!("../../../deploy/prometheus/spawnbox-alerts.yml");
        let backup = include_str!("../../../deploy/backup.sh");
        let mut used = 0;
        for word in rules.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            if !word.starts_with("spawnbox_") {
                continue;
            }
            used += 1;
            let base = ["_bucket", "_count", "_sum"]
                .iter()
                .find_map(|suffix| word.strip_suffix(suffix))
                .filter(|base| {
                    METRICS
                        .iter()
                        .any(|(name, kind, _)| name == base && *kind == "histogram")
                })
                .unwrap_or(word);
            assert!(
                METRICS.iter().any(|(name, _, _)| *name == base) || backup.contains(base),
                "{word} is not exported"
            );
        }
        assert!(used > 20);
        let docs = include_str!("../../../deploy/prometheus/README.md");
        for line in rules.lines() {
            if let Some(alert) = line.trim().strip_prefix("- alert: ") {
                assert!(
                    docs.contains(&format!("### {alert}"))
                        || docs.contains(&format!(", {alert} (")),
                    "{alert} is not documented"
                );
            }
        }
    }
}
