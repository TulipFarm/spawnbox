//! Events: what happened to which sandbox, caused by which call and agent
//! step. The types, filters and step tracking here are plain data; the
//! writer, live feed and OTLP export are in `hub`.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::model::{ApiError, rfc3339_ms};

/// Longest `X-Spawnbox-Step` value.
pub const MAX_STEP: usize = 256;
/// `actor` of what the server does by itself: expiry, idle pause, recovery.
pub const SYSTEM: &str = "system";

/// The W3C trace context of the call that caused an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    /// 32 lowercase hex digits.
    pub trace_id: String,
    /// 16 lowercase hex digits: the caller's span.
    pub span_id: String,
    pub sampled: bool,
}

impl Trace {
    /// Parses a `traceparent` header. Anything invalid is ignored, as the
    /// W3C spec asks.
    pub fn parse(header: &str) -> Option<Self> {
        let mut parts = header.trim().split('-');
        let (version, trace_id, span_id, flags) =
            (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        let hex = |s: &str, len: usize| {
            s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        };
        let zero = |s: &str| s.bytes().all(|b| b == b'0');
        let valid = hex(version, 2)
            && version != "ff"
            // Version 00 has exactly four fields; later ones may add more.
            && (version != "00" || parts.next().is_none())
            && hex(trace_id, 32)
            && !zero(trace_id)
            && hex(span_id, 16)
            && !zero(span_id)
            && hex(flags, 2);
        valid.then(|| Self {
            trace_id: trace_id.to_owned(),
            span_id: span_id.to_owned(),
            sampled: u8::from_str_radix(flags, 16).is_ok_and(|f| f & 1 == 1),
        })
    }
}

/// Who and what caused an event.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Origin {
    pub actor: Option<String>,
    pub step: Option<String>,
    pub trace: Option<Trace>,
}

impl Origin {
    pub fn system() -> Self {
        Self {
            actor: Some(SYSTEM.to_owned()),
            ..Self::default()
        }
    }

    /// The origin of an API call by key `actor` with these header values.
    pub fn of_call(
        actor: &str,
        step: Option<&str>,
        traceparent: Option<&str>,
    ) -> Result<Self, ApiError> {
        let step = match step {
            None => None,
            Some(step)
                if (1..=MAX_STEP).contains(&step.len())
                    && step.bytes().all(|b| b.is_ascii_graphic()) =>
            {
                Some(step.to_owned())
            }
            Some(_) => {
                return Err(ApiError::invalid(format!(
                    "X-Spawnbox-Step must be 1 to {MAX_STEP} visible ASCII characters"
                )));
            }
        };
        Ok(Self {
            actor: Some(actor.to_owned()),
            step,
            trace: traceparent.and_then(Trace::parse),
        })
    }
}

/// An event before it is stored.
#[derive(Clone, Debug)]
pub struct NewEvent {
    /// Unix ms.
    pub ts: i64,
    pub kind: &'static str,
    pub tenant: Option<String>,
    pub sandbox: Option<String>,
    pub step_id: Option<String>,
    pub trace: Option<Trace>,
    pub actor: Option<String>,
    pub attrs: Value,
}

impl NewEvent {
    pub fn new(
        kind: &'static str,
        origin: &Origin,
        tenant: Option<&str>,
        sandbox: Option<&str>,
        attrs: Value,
        ts: i64,
    ) -> Self {
        Self {
            ts,
            kind,
            tenant: tenant.map(str::to_owned),
            sandbox: sandbox.map(str::to_owned),
            step_id: origin.step.clone(),
            trace: origin.trace.clone(),
            actor: origin.actor.clone(),
            attrs,
        }
    }
}

/// A stored event.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Event {
    /// Grows with every event. The cursor for lists and feeds.
    pub id: i64,
    pub ts: i64,
    pub tenant: Option<String>,
    pub sandbox: Option<String>,
    pub step_id: Option<String>,
    pub trace_id: Option<String>,
    pub actor: Option<String>,
    pub kind: String,
    pub attrs: Value,
}

impl Event {
    pub fn stored(id: i64, new: NewEvent) -> Self {
        Self {
            id,
            ts: new.ts,
            tenant: new.tenant,
            sandbox: new.sandbox,
            step_id: new.step_id,
            trace_id: new.trace.map(|t| t.trace_id),
            actor: new.actor,
            kind: new.kind.to_owned(),
            attrs: new.attrs,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id.to_string(),
            "ts": rfc3339_ms(self.ts),
            "tenant": self.tenant,
            "sandbox": self.sandbox,
            "step_id": self.step_id,
            "trace_id": self.trace_id,
            "actor": self.actor,
            "type": self.kind,
            "attrs": self.attrs,
        })
    }
}

/// Which events a query or feed returns. Every set field must match.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    pub tenant: Option<String>,
    pub sandbox: Option<String>,
    pub step_id: Option<String>,
    /// Exact types, or groups as `exec.` (from `exec.*`). Empty: all.
    pub types: Vec<String>,
    /// Unix ms, inclusive.
    pub since: Option<i64>,
    /// Unix ms, exclusive.
    pub until: Option<i64>,
}

impl Filter {
    /// Parses a comma list of types and `group.*` patterns.
    pub fn parse_types(text: &str) -> Result<Vec<String>, ApiError> {
        let mut types = Vec::new();
        for item in text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let name = item.strip_suffix('*').unwrap_or(item);
            let valid = name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_')
                && (item.ends_with(".*") || !item.contains('*'));
            if !valid {
                return Err(ApiError::invalid(format!(
                    "type {item:?} must be an event type like exec.finished or a group like exec.*"
                )));
            }
            types.push(name.to_owned());
        }
        Ok(types)
    }

    pub fn type_matches(&self, kind: &str) -> bool {
        self.types.is_empty()
            || self.types.iter().any(|t| {
                if t.ends_with('.') {
                    kind.starts_with(t.as_str())
                } else {
                    kind == t
                }
            })
    }

    pub fn matches(&self, event: &Event) -> bool {
        let same = |want: &Option<String>, have: &Option<String>| {
            want.as_ref().is_none_or(|w| have.as_ref() == Some(w))
        };
        same(&self.tenant, &event.tenant)
            && same(&self.sandbox, &event.sandbox)
            && same(&self.step_id, &event.step_id)
            && self.type_matches(&event.kind)
            && self.since.is_none_or(|s| event.ts >= s)
            && self.until.is_none_or(|u| event.ts < u)
    }
}

/// The last `max` bytes of a stream.
#[derive(Debug, Default)]
pub struct Tail {
    max: usize,
    buffer: Vec<u8>,
    pub total: u64,
}

impl Tail {
    pub fn new(max: usize) -> Self {
        Self {
            max,
            buffer: Vec::new(),
            total: 0,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.total += bytes.len() as u64;
        if self.max == 0 {
            return;
        }
        if bytes.len() >= self.max {
            self.buffer.clear();
            self.buffer
                .extend_from_slice(&bytes[bytes.len() - self.max..]);
        } else {
            self.buffer.extend_from_slice(bytes);
            let extra = self.buffer.len().saturating_sub(self.max);
            self.buffer.drain(..extra);
        }
    }

    /// The kept bytes as text. A character cut at the start is dropped.
    pub fn text(&self) -> String {
        let cut = if self.total > self.buffer.len() as u64 {
            self.buffer
                .iter()
                .take(3)
                .take_while(|b| (**b & 0xC0) == 0x80)
                .count()
        } else {
            0
        };
        String::from_utf8_lossy(&self.buffer[cut..]).into_owned()
    }
}

/// The execs and terminals running in each sandbox and their steps, so
/// network events can be tagged with a step when that is unambiguous.
#[derive(Debug, Default)]
pub struct Active {
    next: u64,
    running: HashMap<String, Vec<Entry>>,
}

#[derive(Debug)]
struct Entry {
    token: u64,
    step: Option<String>,
    trace: Option<Trace>,
}

impl Active {
    /// Returns a token for `end`.
    pub fn begin(&mut self, sandbox: &str, origin: &Origin) -> u64 {
        self.next += 1;
        self.running
            .entry(sandbox.to_owned())
            .or_default()
            .push(Entry {
                token: self.next,
                step: origin.step.clone(),
                trace: origin.trace.clone(),
            });
        self.next
    }

    pub fn end(&mut self, sandbox: &str, token: u64) {
        if let Some(list) = self.running.get_mut(sandbox) {
            list.retain(|entry| entry.token != token);
            if list.is_empty() {
                self.running.remove(sandbox);
            }
        }
    }

    /// The step and trace every running exec and terminal in `sandbox`
    /// shares. `None` if nothing runs, or they differ, or one has none.
    pub fn current(&self, sandbox: &str) -> Origin {
        let Some(list) = self.running.get(sandbox) else {
            return Origin::default();
        };
        let step = list[0]
            .step
            .clone()
            .filter(|step| list.iter().all(|e| e.step.as_ref() == Some(step)));
        let trace = step.as_ref().and_then(|_| {
            list[0]
                .trace
                .clone()
                .filter(|trace| list.iter().all(|e| e.trace.as_ref() == Some(trace)))
        });
        Origin {
            actor: None,
            step,
            trace,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn parses_traceparent() {
        let trace = Trace::parse(PARENT).unwrap();
        assert_eq!(trace.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(trace.span_id, "00f067aa0ba902b7");
        assert!(trace.sampled);
        for bad in [
            "",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-x",
        ] {
            assert_eq!(Trace::parse(bad), None, "{bad}");
        }
        assert!(
            Trace::parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00-x").is_some()
        );
    }

    #[test]
    fn checks_step_length() {
        let origin = Origin::of_call("key_a", Some("run_1/step_2"), Some(PARENT)).unwrap();
        assert_eq!(origin.step.as_deref(), Some("run_1/step_2"));
        assert!(origin.trace.is_some());
        assert!(Origin::of_call("key_a", Some(""), None).is_err());
        assert!(Origin::of_call("key_a", Some(&"s".repeat(MAX_STEP + 1)), None).is_err());
        assert_eq!(
            Origin::of_call("key_a", None, Some("junk")).unwrap().trace,
            None
        );
    }

    #[test]
    fn filters_by_type_group() {
        let filter = Filter {
            types: Filter::parse_types("exec.*, file.written").unwrap(),
            ..Filter::default()
        };
        assert!(filter.type_matches("exec.finished"));
        assert!(filter.type_matches("file.written"));
        assert!(!filter.type_matches("file.deleted"));
        assert!(!filter.type_matches("executor"));
        assert!(Filter::parse_types("exec*").is_err());
        assert!(Filter::parse_types("Exec.started").is_err());
        assert!(Filter::default().type_matches("anything"));
    }

    #[test]
    fn matches_events() {
        let event = Event {
            id: 1,
            ts: 100,
            tenant: Some("acme".into()),
            sandbox: Some("sbx_1".into()),
            step_id: None,
            trace_id: None,
            actor: None,
            kind: "net.connection".into(),
            attrs: json!({}),
        };
        let mut filter = Filter {
            tenant: Some("acme".into()),
            since: Some(100),
            until: Some(101),
            ..Filter::default()
        };
        assert!(filter.matches(&event));
        filter.step_id = Some("s".into());
        assert!(!filter.matches(&event));
        filter.step_id = None;
        filter.tenant = Some("beta".into());
        assert!(!filter.matches(&event));
    }

    #[test]
    fn keeps_the_tail() {
        let mut tail = Tail::new(4);
        tail.push(b"ab");
        tail.push(b"cdef");
        assert_eq!(tail.text(), "cdef");
        tail.push(b"0123456");
        assert_eq!(tail.text(), "3456");
        assert_eq!(tail.total, 13);
        let mut cut = Tail::new(3);
        cut.push("xé!".as_bytes());
        assert_eq!(cut.text(), "é!");
        let mut cut = Tail::new(3);
        cut.push("éé".as_bytes());
        assert_eq!(cut.text(), "é", "a cut character is dropped");
        let mut off = Tail::new(0);
        off.push(b"abc");
        assert_eq!((off.text().as_str(), off.total), ("", 3));
    }

    #[test]
    fn tags_only_unambiguous_steps() {
        let mut active = Active::default();
        let step = |s: &str| Origin {
            step: Some(s.into()),
            ..Origin::default()
        };
        assert_eq!(active.current("sbx_1").step, None);
        let a = active.begin("sbx_1", &step("one"));
        assert_eq!(active.current("sbx_1").step.as_deref(), Some("one"));
        let b = active.begin("sbx_1", &step("one"));
        assert_eq!(active.current("sbx_1").step.as_deref(), Some("one"));
        let c = active.begin("sbx_1", &step("two"));
        assert_eq!(active.current("sbx_1").step, None);
        active.end("sbx_1", c);
        let d = active.begin("sbx_1", &Origin::default());
        assert_eq!(active.current("sbx_1").step, None);
        for token in [a, b, d] {
            active.end("sbx_1", token);
        }
        assert!(active.running.is_empty());
    }
}
