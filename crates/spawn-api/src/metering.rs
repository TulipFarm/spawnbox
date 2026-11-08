//! Usage metering: what each sandbox reserved, stored and sent, per tenant,
//! sandbox and UTC hour.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use serde::Serialize;
use time::{OffsetDateTime, Time};

use crate::db::Db;

pub const HOUR_MS: i64 = 3_600_000;
const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

/// Usage in one period.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, serde::Deserialize)]
pub struct Totals {
    pub vcpu_s: f64,
    pub mem_gib_s: f64,
    pub disk_gib_h: f64,
    pub egress_bytes: u64,
}

impl Totals {
    pub fn add(&mut self, other: &Self) {
        self.vcpu_s += other.vcpu_s;
        self.mem_gib_s += other.mem_gib_s;
        self.disk_gib_h += other.disk_gib_h;
        self.egress_bytes = self.egress_bytes.saturating_add(other.egress_bytes);
    }
}

/// What a sandbox holds while in one state.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Rate {
    pub vcpus: u8,
    pub memory_mib: u32,
    pub disk_bytes: u64,
}

/// One row of `usage_hourly`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
pub struct Key {
    pub tenant: String,
    pub sandbox: String,
    /// Unix ms at the start of the UTC hour.
    pub hour: i64,
}

/// Collects usage in memory until `flush` adds it to the database.
pub struct Meter {
    db: Db,
    pending: Mutex<HashMap<Key, Totals>>,
}

impl Meter {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            pending: Mutex::default(),
        }
    }

    fn pending(&self) -> MutexGuard<'_, HashMap<Key, Totals>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Counts a sandbox holding `rate` from `from_ms` to `to_ms`.
    pub fn charge(&self, tenant: &str, sandbox: &str, from_ms: i64, to_ms: i64, rate: Rate) {
        let mut pending = self.pending();
        for (hour, ms) in split(from_ms, to_ms) {
            let seconds = ms as f64 / 1000.0;
            let disk_gib = rate.disk_bytes as f64 / GIB;
            let totals = pending
                .entry(Key {
                    tenant: tenant.to_owned(),
                    sandbox: sandbox.to_owned(),
                    hour,
                })
                .or_default();
            totals.vcpu_s += f64::from(rate.vcpus) * seconds;
            totals.mem_gib_s += f64::from(rate.memory_mib) / 1024.0 * seconds;
            totals.disk_gib_h += disk_gib * seconds / 3600.0;
        }
    }

    /// Counts egress bytes in the hour of `at_ms`.
    pub fn egress(&self, tenant: &str, sandbox: &str, bytes: u64, at_ms: i64) {
        let mut pending = self.pending();
        let totals = pending
            .entry(Key {
                tenant: tenant.to_owned(),
                sandbox: sandbox.to_owned(),
                hour: hour_start(at_ms),
            })
            .or_default();
        totals.egress_bytes = totals.egress_bytes.saturating_add(bytes);
    }

    /// Adds what was collected to the database. On failure, keeps it for
    /// the next try.
    pub fn flush(&self) -> crate::db::Result<()> {
        let rows = std::mem::take(&mut *self.pending());
        if rows.is_empty() {
            return Ok(());
        }
        self.db.add_usage(&rows).inspect_err(|_| {
            let mut pending = self.pending();
            for (key, totals) in rows {
                pending.entry(key).or_default().add(&totals);
            }
        })
    }

    /// `tenant`'s egress bytes this UTC month, written or not.
    pub fn month_egress(&self, tenant: &str, now_ms: i64) -> crate::db::Result<u64> {
        let since = month_start(now_ms);
        let stored = self.db.egress_since(tenant, since)?;
        let pending: u64 = self
            .pending()
            .iter()
            .filter(|(key, _)| key.tenant == tenant && key.hour >= since)
            .map(|(_, totals)| totals.egress_bytes)
            .sum();
        Ok(stored.saturating_add(pending))
    }
}

/// Unix ms at the start of the UTC hour holding `ms`.
pub fn hour_start(ms: i64) -> i64 {
    ms.div_euclid(HOUR_MS) * HOUR_MS
}

/// Unix ms at the start of the UTC month holding `ms`.
pub fn month_start(ms: i64) -> i64 {
    OffsetDateTime::from_unix_timestamp(ms.div_euclid(1000))
        .ok()
        .and_then(|t| t.replace_day(1).ok())
        .map_or(0, |t| {
            t.replace_time(Time::MIDNIGHT).unix_timestamp() * 1000
        })
}

/// Splits `from_ms..to_ms` at hour boundaries: each hour's start and the ms
/// in it.
fn split(from_ms: i64, to_ms: i64) -> Vec<(i64, i64)> {
    let mut parts = Vec::new();
    let mut at = from_ms;
    while at < to_ms {
        let hour = hour_start(at);
        let end = (hour + HOUR_MS).min(to_ms);
        parts.push((hour, end - at));
        at = end;
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: i64 = HOUR_MS;

    #[test]
    fn splits_at_hours() {
        assert_eq!(split(5, 5), vec![]);
        assert_eq!(split(10, 3), vec![]);
        assert_eq!(split(H + 10, H + 20), vec![(H, 10)]);
        assert_eq!(
            split(H - 100, 3 * H + 50),
            vec![(0, 100), (H, H), (2 * H, H), (3 * H, 50)]
        );
    }

    #[test]
    fn month_starts_at_midnight_on_the_first() {
        // 2026-11-04T10:25:14Z
        let ms = 1_793_787_914_000;
        // 2026-11-01T00:00:00Z
        assert_eq!(month_start(ms), 1_793_491_200_000);
        assert_eq!(month_start(1_793_491_200_000), 1_793_491_200_000);
    }

    #[test]
    fn charges_rates_per_hour_and_flushes() {
        let db = Db::memory().unwrap();
        let meter = Meter::new(db.clone());
        let rate = Rate {
            vcpus: 2,
            memory_mib: 512,
            disk_bytes: 1 << 30,
        };
        meter.charge("acme", "sbx_a", H - 1000, H + 2000, rate);
        meter.egress("acme", "sbx_a", 300, H + 5);
        meter.flush().unwrap();
        // Flushing again adds to the stored rows.
        meter.charge("acme", "sbx_a", H + 2000, H + 3000, rate);
        meter.egress("other", "sbx_b", 7, H);
        meter.flush().unwrap();

        let rows = db.list_usage(None, 0, 2 * H, true).unwrap();
        assert_eq!(rows.len(), 3);
        let (first, second) = (&rows[0], &rows[1]);
        assert_eq!((first.hour, first.tenant.as_str()), (0, "acme"));
        assert!((first.totals.vcpu_s - 2.0).abs() < 1e-9);
        assert!((first.totals.mem_gib_s - 0.5).abs() < 1e-9);
        assert!((first.totals.disk_gib_h - 1.0 / 3600.0).abs() < 1e-12);
        assert_eq!(second.hour, H);
        assert_eq!(second.sandbox.as_deref(), Some("sbx_a"));
        assert!((second.totals.vcpu_s - 6.0).abs() < 1e-9);
        assert_eq!(second.totals.egress_bytes, 300);

        let acme = db.list_usage(Some("acme"), H, 2 * H, false).unwrap();
        assert_eq!(acme.len(), 1);
        assert_eq!(acme[0].sandbox, None);
        assert_eq!(meter.month_egress("acme", H).unwrap(), 300);
        meter.egress("acme", "sbx_a", 5, H);
        assert_eq!(meter.month_egress("acme", H).unwrap(), 305);
    }
}
