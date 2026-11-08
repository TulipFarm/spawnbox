//! The event hub: one writer task stores events in batches, sends them to
//! OTLP and to live feeds. Calls only queue events, so they never wait on
//! the database.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::response::sse;
use opentelemetry::KeyValue;
use serde_json::{Value, json};
use spawn_egress::Activity;
use spawn_proto::guest::v1::ExecExit;
use spawn_proto::guest::v1::exec_event::Event as GuestEvent;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_stream::wrappers::ReceiverStream;

use crate::db::Db;
use crate::events::{Active, Event, Filter, NewEvent, Origin, Tail};
use crate::metrics;
use crate::otlp::Otlp;
use crate::runtime::now_ms;
use crate::traces::Traced;

/// Events waiting to be stored. More are dropped and counted.
const QUEUE: usize = 10_000;
/// Most events stored in one transaction.
const BATCH: usize = 500;
/// Live events a slow feed may fall behind before it reads from the
/// database again.
const FEED: usize = 4096;
/// Events per database page when a feed catches up.
const PAGE: usize = 500;
const PRUNE_BATCH: usize = 5000;

enum Msg {
    Event(NewEvent),
    /// A worker's events, stored once each. Replies with the newest of its
    /// event IDs stored here.
    Remote {
        node: String,
        events: Vec<Event>,
        reply: oneshot::Sender<crate::db::Result<i64>>,
    },
    /// Stores everything queued before it, then stops the writer.
    Close(oneshot::Sender<()>),
}

pub struct Hub {
    db: Db,
    queue: mpsc::Sender<Msg>,
    feed: broadcast::Sender<Arc<Event>>,
    dropped: AtomicU64,
    active: Mutex<Active>,
    /// The origin of each open egress connection when it opened.
    connections: Mutex<HashMap<u64, Origin>>,
    /// Bytes of stdout and stderr kept in `exec.finished`.
    output_bytes: usize,
    stopping: watch::Sender<bool>,
}

impl Hub {
    pub fn start(db: Db, otlp: Option<Otlp>, output_bytes: usize) -> Arc<Self> {
        let (queue, rx) = mpsc::channel(QUEUE);
        let (feed, _) = broadcast::channel(FEED);
        let hub = Arc::new(Self {
            db: db.clone(),
            queue,
            feed: feed.clone(),
            dropped: AtomicU64::new(0),
            active: Mutex::default(),
            connections: Mutex::default(),
            output_bytes,
            stopping: watch::Sender::new(false),
        });
        tokio::spawn(write(db, rx, feed, otlp.map(Arc::new)));
        hub
    }

    pub fn emit(&self, event: NewEvent) {
        if self.queue.try_send(Msg::Event(event)).is_err() {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                eprintln!("events: queue full or closed; {dropped} events dropped so far");
            }
        }
    }

    /// Records an event that happens now.
    pub fn record(
        &self,
        kind: &'static str,
        origin: &Origin,
        tenant: Option<&str>,
        sandbox: Option<&str>,
        attrs: Value,
    ) {
        self.emit(NewEvent::new(
            kind,
            origin,
            tenant,
            sandbox,
            attrs,
            now_ms(),
        ));
    }

    /// Ends live feeds, so they do not hold the server open.
    pub fn stop_feeds(&self) {
        self.stopping.send_replace(true);
    }

    /// Ends live feeds, stores what is queued and sends the rest to OTLP.
    /// Events after this are dropped.
    pub async fn close(&self) {
        self.stop_feeds();
        let (tx, rx) = oneshot::channel();
        if self.queue.send(Msg::Close(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }

    /// Deletes events older than `before` (Unix ms) in batches.
    pub async fn prune(&self, before: i64) {
        loop {
            match self.db.prune_events(before, PRUNE_BATCH) {
                Ok(n) if n == PRUNE_BATCH => tokio::task::yield_now().await,
                Ok(_) => return,
                Err(err) => {
                    eprintln!("events: prune: {err}");
                    return;
                }
            }
        }
    }

    /// Marks an exec or terminal as running in `sandbox` until the guard
    /// drops, so network events can carry its step.
    pub fn begin(self: &Arc<Self>, sandbox: &str, origin: &Origin) -> Running {
        let token = lock(&self.active).begin(sandbox, origin);
        Running {
            hub: Arc::clone(self),
            sandbox: sandbox.to_owned(),
            token,
        }
    }

    /// Records what the egress proxy did.
    pub fn egress(&self, activity: Activity) {
        let sandbox = match &activity {
            Activity::Opened { sandbox, .. }
            | Activity::Connection { sandbox, .. }
            | Activity::Request { sandbox, .. }
            | Activity::Dns { sandbox, .. } => sandbox,
        };
        if let Activity::Connection { verdict, .. } = &activity {
            metrics::inc(
                "spawnbox_egress_connections_total",
                vec![("verdict", (*verdict).into())],
            );
        }
        if let Activity::Dns { verdict, .. } = &activity {
            metrics::inc(
                "spawnbox_dns_queries_total",
                vec![("verdict", (*verdict).into())],
            );
        }
        // Template builds also go through the proxy; only sandboxes have
        // events.
        if !sandbox.starts_with("sbx_") {
            return;
        }
        let origin = lock(&self.active).current(sandbox);
        match activity {
            Activity::Opened { id, .. } => {
                lock(&self.connections).insert(id, origin);
            }
            Activity::Connection {
                id,
                sandbox,
                tenant,
                dst,
                host,
                verdict,
                reason,
                up,
                down,
                ms,
            } => {
                let (kind, attrs) = if verdict == "deny" {
                    (
                        "net.blocked",
                        json!({ "dst": dst.to_string(), "host": host, "reason": reason }),
                    )
                } else {
                    let mut attrs = json!({
                        "dst": dst.to_string(),
                        "host": host,
                        "verdict": verdict,
                        "bytes_up": up,
                        "bytes_down": down,
                        "duration_ms": ms,
                    });
                    if !reason.is_empty() {
                        attrs["reason"] = json!(reason);
                    }
                    ("net.connection", attrs)
                };
                // Only a step that ran from open to close made the
                // connection; a later step or a background process did not.
                let opened = lock(&self.connections).remove(&id).unwrap_or_default();
                let origin = if opened == origin {
                    origin
                } else {
                    Origin::default()
                };
                self.record(kind, &origin, tenant.as_deref(), Some(&sandbox), attrs);
            }
            Activity::Request {
                sandbox,
                tenant,
                host,
                method,
                status,
                secrets,
                refused,
            } => {
                if let Some(reason) = refused {
                    let attrs = json!({ "host": host, "method": method, "reason": reason });
                    self.record(
                        "net.blocked",
                        &origin,
                        tenant.as_deref(),
                        Some(&sandbox),
                        attrs,
                    );
                    return;
                }
                for (name, version) in secrets {
                    // Tenant secrets are stored as `tenant/name`.
                    let name = tenant
                        .as_deref()
                        .and_then(|t| name.strip_prefix(t)?.strip_prefix('/'))
                        .map_or_else(|| name.clone(), str::to_owned);
                    let attrs = json!({
                        "name": name,
                        "version": version,
                        "host": host,
                        "method": method,
                        "status": status,
                    });
                    self.record(
                        "secret.injected",
                        &origin,
                        tenant.as_deref(),
                        Some(&sandbox),
                        attrs,
                    );
                }
            }
            Activity::Dns {
                sandbox,
                tenant,
                name,
                qtype,
                verdict,
                rcode,
                answers,
                ms,
            } => {
                let attrs = json!({
                    "name": name,
                    "type": qtype,
                    "verdict": verdict,
                    "rcode": rcode,
                    "answers": answers,
                    "duration_ms": ms,
                });
                self.record("net.dns", &origin, tenant.as_deref(), Some(&sandbox), attrs);
            }
        }
    }

    /// Starts recording an exec. `exec.started` is stored now and
    /// `exec.finished` when the record drops.
    pub fn exec(
        self: &Arc<Self>,
        origin: &Origin,
        tenant: &str,
        sandbox: &str,
        attrs: Value,
        span: Traced,
    ) -> ExecLog {
        let id = crate::ids::new_id("ex").unwrap_or_default();
        let mut started = attrs;
        started["exec_id"] = json!(id);
        self.record("exec.started", origin, Some(tenant), Some(sandbox), started);
        ExecLog {
            running: self.begin(sandbox, origin),
            id,
            origin: origin.clone(),
            tenant: tenant.to_owned(),
            started: Instant::now(),
            stdout: Tail::new(self.output_bytes),
            stderr: Tail::new(self.output_bytes),
            exit: None,
            error: None,
            span,
        }
    }

    /// The live and stored events matching `filter` after ID `after`, as
    /// server-sent events. Ends when the client leaves or the server stops.
    pub fn follow(
        self: &Arc<Self>,
        filter: Filter,
        after: i64,
    ) -> ReceiverStream<Result<sse::Event, Infallible>> {
        let (tx, rx) = mpsc::channel(64);
        let hub = Arc::clone(self);
        tokio::spawn(async move {
            let mut live = hub.feed.subscribe();
            let mut stopping = hub.stopping.subscribe();
            let mut last = after;
            if !hub.catch_up(&filter, &mut last, &tx, &mut stopping).await {
                return;
            }
            loop {
                let event = tokio::select! {
                    event = live.recv() => event,
                    _ = stopping.wait_for(|s| *s) => return,
                    () = tx.closed() => return,
                };
                match event {
                    Ok(event) if event.id > last => {
                        last = event.id;
                        if filter.matches(&event) && !send(&tx, &mut stopping, &event).await {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if !hub.catch_up(&filter, &mut last, &tx, &mut stopping).await {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
        ReceiverStream::new(rx)
    }

    /// Sends stored events after `last`. Returns false if the client left
    /// or the server is stopping.
    async fn catch_up(
        &self,
        filter: &Filter,
        last: &mut i64,
        tx: &mpsc::Sender<Result<sse::Event, Infallible>>,
        stopping: &mut watch::Receiver<bool>,
    ) -> bool {
        loop {
            let (page, more) = match self.db.list_events(filter, *last, PAGE) {
                Ok(page) => page,
                Err(err) => {
                    eprintln!("events: follow: {err}");
                    return false;
                }
            };
            for event in &page {
                *last = event.id;
                if !send(tx, stopping, event).await {
                    return false;
                }
            }
            if !more {
                return true;
            }
        }
    }

    /// Stores a worker's events and sends the new ones to followers.
    /// Returns the newest of its event IDs stored here.
    pub async fn ingest(&self, node: &str, events: Vec<Event>) -> crate::db::Result<i64> {
        let (reply, rx) = oneshot::channel();
        let msg = Msg::Remote {
            node: node.to_owned(),
            events,
            reply,
        };
        if self.queue.send(msg).await.is_err() {
            return Err(crate::db::Error::Connection(
                "the database task stopped".into(),
            ));
        }
        rx.await.unwrap_or(Err(crate::db::Error::Connection(
            "the database task stopped".into(),
        )))
    }

    /// The newest stored event's ID.
    pub fn latest(&self) -> crate::db::Result<i64> {
        self.db.latest_event_id()
    }
}

/// Sends to a follower unless it left or the server is stopping, so a
/// slow reader cannot hold shutdown up.
async fn send(
    tx: &mpsc::Sender<Result<sse::Event, Infallible>>,
    stopping: &mut watch::Receiver<bool>,
    event: &Event,
) -> bool {
    tokio::select! {
        sent = tx.send(Ok(sse_event(event))) => sent.is_ok(),
        _ = stopping.wait_for(|s| *s) => false,
    }
}

fn sse_event(event: &Event) -> sse::Event {
    sse::Event::default()
        .id(event.id.to_string())
        .data(event.to_json().to_string())
}

async fn write(
    db: Db,
    mut rx: mpsc::Receiver<Msg>,
    feed: broadcast::Sender<Arc<Event>>,
    otlp: Option<Arc<Otlp>>,
) {
    let mut batch = Vec::new();
    let mut close = None;
    while close.is_none() {
        let Some(first) = rx.recv().await else {
            break;
        };
        let mut next = Some(first);
        while let Some(msg) = next.take() {
            match msg {
                Msg::Event(event) => batch.push(event),
                Msg::Remote {
                    node,
                    events,
                    reply,
                } => {
                    // Earlier local events first, so feed IDs keep rising.
                    store(&db, &mut batch, &feed, otlp.as_ref()).await;
                    let _ = reply.send(store_remote(&db, node, events, &feed).await);
                }
                Msg::Close(reply) => {
                    close = Some(reply);
                    break;
                }
            }
            if batch.len() < BATCH {
                next = rx.try_recv().ok();
            }
        }
        store(&db, &mut batch, &feed, otlp.as_ref()).await;
    }
    if let Some(otlp) = otlp {
        let _ = tokio::task::spawn_blocking(move || otlp.shutdown()).await;
    }
    if let Some(reply) = close {
        let _ = reply.send(());
    }
}

async fn store(
    db: &Db,
    batch: &mut Vec<NewEvent>,
    feed: &broadcast::Sender<Arc<Event>>,
    otlp: Option<&Arc<Otlp>>,
) {
    if batch.is_empty() {
        return;
    }
    let events = std::mem::take(batch);
    let db = db.clone();
    let stored = tokio::task::spawn_blocking(move || {
        let ids = db.insert_events(&events);
        (events, ids)
    })
    .await;
    match stored {
        Ok((events, Ok(ids))) => {
            for (id, event) in ids.into_iter().zip(events) {
                if let Some(otlp) = otlp {
                    otlp.export(id, &event);
                }
                let _ = feed.send(Arc::new(Event::stored(id, event)));
            }
        }
        Ok((events, Err(err))) => {
            eprintln!("events: store {} events: {err}", events.len());
        }
        Err(err) => eprintln!("events: store: {err}"),
    }
}

async fn store_remote(
    db: &Db,
    node: String,
    events: Vec<Event>,
    feed: &broadcast::Sender<Arc<Event>>,
) -> crate::db::Result<i64> {
    let db = db.clone();
    let stored = tokio::task::spawn_blocking(move || {
        let stored = db.insert_remote_events(&node, &events)?;
        Ok::<_, crate::db::Error>((stored, db.remote_event_cursor(&node)?))
    })
    .await
    .map_err(|_| crate::db::Error::Connection("the database task stopped".into()))??;
    let (stored, cursor) = stored;
    for event in stored {
        let _ = feed.send(Arc::new(event));
    }
    Ok(cursor)
}

/// An exec or terminal running in a sandbox.
pub struct Running {
    hub: Arc<Hub>,
    sandbox: String,
    token: u64,
}

impl Running {
    pub fn sandbox(&self) -> &str {
        &self.sandbox
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        lock(&self.hub.active).end(&self.sandbox, self.token);
    }
}

/// Watches one exec's output and stores `exec.finished` when dropped.
pub struct ExecLog {
    running: Running,
    id: String,
    origin: Origin,
    tenant: String,
    started: Instant,
    stdout: Tail,
    stderr: Tail,
    exit: Option<ExecExit>,
    error: Option<String>,
    span: Traced,
}

impl ExecLog {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn see(&mut self, event: &GuestEvent) {
        match event {
            GuestEvent::Stdout(bytes) => self.stdout.push(bytes),
            GuestEvent::Stderr(bytes) => self.stderr.push(bytes),
            GuestEvent::Exit(exit) => self.exit = Some(*exit),
        }
    }

    /// The guest connection failed.
    pub fn failed(&mut self, error: &str) {
        self.error = Some(error.to_owned());
    }
}

impl Drop for ExecLog {
    fn drop(&mut self) {
        let mut attrs = json!({
            "exec_id": self.id,
            "stdout_bytes": self.stdout.total,
            "stderr_bytes": self.stderr.total,
            "stdout_tail": self.stdout.text(),
            "stderr_tail": self.stderr.text(),
        });
        match &self.exit {
            Some(exit) => {
                attrs["exit_code"] = json!(exit.exit_code);
                attrs["signal"] = json!(exit.signal);
                attrs["timed_out"] = json!(exit.timed_out);
                attrs["duration_ms"] = json!(exit.duration_ms);
                if let Some(code) = exit.exit_code {
                    self.span
                        .attr(KeyValue::new("spawnbox.exit_code", i64::from(code)));
                }
                if exit.timed_out {
                    self.span.fail("timed out");
                }
            }
            None => {
                attrs["duration_ms"] =
                    json!(u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX));
                match &self.error {
                    Some(error) => {
                        attrs["error"] = json!(error);
                        self.span.fail(error.clone());
                    }
                    None => {
                        attrs["cancelled"] = json!(true);
                        self.span.attr(KeyValue::new("spawnbox.cancelled", true));
                    }
                }
            }
        }
        self.running.hub.record(
            "exec.finished",
            &self.origin,
            Some(&self.tenant),
            Some(self.running.sandbox()),
            attrs,
        );
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
