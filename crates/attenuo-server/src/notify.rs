//! The approval notifier (`[approvals.notify]`): tells a webhook the deployment owns that an
//! approval is waiting, and again when it was decided or expired, so an operator does not have
//! to watch the console.
//!
//! Where: [`NotifierHandle::pending`] is called by the pipeline after a new pending approval
//! and its `approval_request` record were written, and [`NotifierHandle::decided`] by the
//! approval routes after the decision and its `approval_grant` record were. Both build a
//! small JSON document, store it as one row of the lease store's `notice_outbox` table (one
//! local insert, never the network) and queue it. Delivery runs on the `[audit.sink]` queue
//! ([`crate::sink::Queue`], role [`QueueRole::ApprovalNotices`]): bounded, oldest dropped when
//! full, one background thread, jittered exponential backoff, and given up after
//! `max_attempts`. The queue's [`Settle`] hook ([`OutboxSettle`]) marks each row delivered or
//! given up, and records the attempts and the next try of a failed one. Expiry has no request
//! to hang on, so a watcher thread keeps the pending approvals by expiry time and, once one is
//! due, reads it from the lease store and queues `approval.expired` if it is still pending.
//!
//! Restarts: on start the rows still open (queued, or in flight, when the last process
//! stopped) are delivered again, oldest first, with their attempts so far. The delivery thread
//! reads them from the outbox a batch of at most `queue_capacity` at a time, whenever the
//! queue runs empty, so a backlog longer than the queue is delivered whole instead of being
//! dropped for lack of room (SR-93); a notice stored meanwhile is queued as usual and may go
//! out between two batches. And every approval still pending in the store is watched again,
//! so one that expired while the server was down gets its `approval.expired` at once. The notice id (`event_id`) is derived from the
//! approval id and the type ([`event_id_for`]) and is unique in the table, so finding such an
//! expiry a second time queues nothing. Rows delivered or given up are deleted
//! `outbox_retention_seconds` later by the watcher; an approval that expired longer ago than
//! that is not looked at on start, since its notice may already be gone from the table.
//!
//! Best effort: a notification can be late, dropped (counted in
//! `attenuo_approval_notify_dropped_total`) or delivered twice: after a retry whose answer was
//! lost, or when the process stopped between a delivery and the write marking it delivered.
//! The receiver deduplicates by `event_id`. Nothing here can change a decision, and a receiver
//! that is down or slow never holds up a request.
//!
//! The document carries no token and no arguments: only the call hash
//! (`ToolCall::call_hash`, SHA-256 over server, tool and arguments) stands for the call. Each
//! request is signed: `X-Attenuo-Signature: t=<unix seconds>,v1=<hex HMAC-SHA-256 of
//! "<t>.<body>">` under the secret in the environment variable `secret_env`
//! ([`signature`]).

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use attenuo_audit::{
    Approval, ApprovalState, LeaseStore, NewNotice, OutboxNotice, SqliteLeaseStore,
};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::{NotifySection, NOTIFY_SECRET_MIN_LEN};
use crate::metrics::Metrics;
use crate::sink::{
    Backoff, Deliver, Queue, QueueHandle, QueueItem, QueueRole, Settle, Settled, SinkLimits,
    SinkStatus,
};

/// The signature header: `t=<unix seconds>,v1=<hex HMAC-SHA-256 of "<t>.<body>">`.
pub const SIGNATURE_HEADER: &str = "x-attenuo-signature";
/// The event type (`approval.pending`, `approval.decided`, `approval.expired`).
pub const EVENT_HEADER: &str = "x-attenuo-event";
/// The event id, the same on every retry of one notification.
pub const EVENT_ID_HEADER: &str = "x-attenuo-event-id";

/// Most pending approvals the expiry watcher keeps. Beyond this an approval gets no
/// `approval.expired` notice, and the miss is counted as a drop.
pub const MAX_WATCHED: usize = 10_000;

/// How long after `expires_at` the watcher looks, so the store agrees it has expired.
const EXPIRY_GRACE: Duration = Duration::from_millis(250);

/// How often the watcher deletes outbox rows settled more than `outbox_retention_seconds` ago.
/// It also does so once at start.
pub const OUTBOX_PRUNE_PERIOD: Duration = Duration::from_secs(3600);

/// What happened to the approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    Pending,
    Decided,
    Expired,
}

impl NoticeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "approval.pending",
            Self::Decided => "approval.decided",
            Self::Expired => "approval.expired",
        }
    }

    /// The kind [`as_str`](Self::as_str) names.
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Pending, Self::Decided, Self::Expired]
            .into_iter()
            .find(|k| k.as_str() == s)
    }
}

/// The `event_id` of the `kind` notice of approval `approval_id`: a UUID (version 8, RFC 9562)
/// made of the first 16 bytes of SHA-256 over a label, the type and the approval id. An
/// approval gets at most one notice of each type, so this names the notice, and it is the
/// same on every attempt and after a restart.
pub fn event_id_for(kind: NoticeKind, approval_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"attenuo approval notice\0");
    h.update(kind.as_str().as_bytes());
    h.update(b"\0");
    h.update(approval_id.as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&h.finalize()[..16]);
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(b).to_string()
}

/// One notification, its body fixed when it was first queued.
#[derive(Debug, Clone)]
pub struct Notice {
    pub kind: NoticeKind,
    pub approval_id: String,
    /// The same on every attempt and after a restart ([`event_id_for`]).
    pub event_id: String,
    /// The JSON document, exactly as sent and signed.
    pub body: Vec<u8>,
    /// Its `notice_outbox` row; `None` when storing it failed (then it lives in memory only).
    pub row: Option<i64>,
    /// Failed attempts before it was queued (a row reloaded after a restart).
    pub attempts: u32,
}

impl Notice {
    pub fn new(kind: NoticeKind, a: &Approval) -> Self {
        let event_id = event_id_for(kind, &a.id);
        let body = serde_json::to_vec(&notice_json(kind, &event_id, a)).unwrap_or_default();
        Self {
            kind,
            approval_id: a.id.clone(),
            event_id,
            body,
            row: None,
            attempts: 0,
        }
    }

    /// A row of the outbox, as stored. `None` for a type this version does not know.
    pub fn from_outbox(r: OutboxNotice) -> Option<Self> {
        Some(Self {
            kind: NoticeKind::parse(&r.kind)?,
            approval_id: r.approval_id,
            event_id: r.event_id,
            body: r.body,
            row: Some(r.id),
            attempts: r.attempts,
        })
    }
}

impl QueueItem for Notice {
    fn log_id(&self) -> String {
        format!("{} {}", self.kind.as_str(), self.approval_id)
    }

    fn attempts(&self) -> u32 {
        self.attempts
    }
}

/// The queue's [`Settle`] hook: keeps each notice's outbox row in step with its delivery. A
/// write that fails is logged and leaves the row open, so it is delivered again after the
/// next restart (the receiver deduplicates by `event_id`).
///
/// It also hands the delivery thread the rows a restart left open (`Backlog`), a batch at a
/// time whenever the queue runs empty, so that none is dropped for lack of room (SR-93).
#[derive(Debug)]
pub struct OutboxSettle {
    store: Arc<SqliteLeaseStore>,
    metrics: Arc<Metrics>,
    backlog: Mutex<Backlog>,
}

/// The outbox rows open at start not yet handed to the queue: those with a row id in
/// `(after, through]`. `through` is the newest row open at start; a notice stored since has a
/// higher id and was queued when it was stored, so reading stops there and nothing is
/// delivered twice. Empty once `after >= through`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Backlog {
    after: i64,
    through: i64,
}

impl OutboxSettle {
    /// The next open rows of the backlog, oldest first, at most `room`. A row of a type this
    /// version does not know is skipped. A read that fails ends the backlog, logged: the rows
    /// left stay open for the next restart.
    fn next_backlog(&self, room: usize) -> Vec<Notice> {
        let mut b = self.backlog.lock().unwrap_or_else(|e| e.into_inner());
        while b.after < b.through && room > 0 {
            let rows = match self.store.outbox_open_between(b.after, b.through, room) {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!(error = %e, "[approvals.notify] could not read the outbox: notices stored before the restart and not yet queued are left until the next one");
                    b.after = b.through;
                    break;
                }
            };
            let Some(last) = rows.last() else {
                b.after = b.through;
                break;
            };
            b.after = last.id;
            let notices: Vec<Notice> = rows
                .into_iter()
                .filter_map(|row| {
                    let n = Notice::from_outbox(row);
                    if n.is_none() {
                        tracing::warn!("[approvals.notify] outbox row of an unknown type: skipped");
                    }
                    n
                })
                .collect();
            if !notices.is_empty() {
                return notices;
            }
        }
        Vec::new()
    }
}

impl Settle<Notice> for OutboxSettle {
    fn settled(&self, n: &Notice, how: Settled) {
        let Some(row) = n.row else {
            return;
        };
        let now = OffsetDateTime::now_utc();
        let closed = match how {
            Settled::Delivered => self.store.outbox_delivered(row, now),
            Settled::GaveUp { attempts } => self.store.outbox_given_up(row, attempts, now),
            Settled::Dropped => self.store.outbox_given_up(row, n.attempts, now),
            Settled::Retry { attempts, wait } => self
                .store
                .outbox_retry(row, attempts, now + wait)
                .map(|()| false),
        };
        match closed {
            Ok(true) => self.metrics.approval_notify_outbox_closed(),
            Ok(false) => {}
            Err(e) => tracing::warn!(
                notice = %n.log_id(),
                error = %e,
                "[approvals.notify] could not update the outbox row: it may be delivered again \
                 after a restart"
            ),
        }
    }

    fn refill(&self, room: usize) -> Vec<Notice> {
        self.next_backlog(room)
    }
}

/// Stores a notice in the outbox, then queues it. Shared by the handle and the watcher.
#[derive(Debug, Clone)]
struct Emitter {
    queue: QueueHandle<Notice>,
    store: Arc<SqliteLeaseStore>,
    metrics: Arc<Metrics>,
}

impl Emitter {
    fn emit(&self, mut n: Notice) {
        let new = NewNotice {
            event_id: &n.event_id,
            kind: n.kind.as_str(),
            approval_id: &n.approval_id,
            body: &n.body,
        };
        match self.store.outbox_insert(new, OffsetDateTime::now_utc()) {
            Ok(Some(row)) => {
                n.row = Some(row);
                self.metrics.approval_notify_outbox_opened();
            }
            // Stored before (an expiry found again after a restart): queued then, or done.
            Ok(None) => return,
            Err(e) => tracing::warn!(
                notice = %n.log_id(),
                error = %e,
                "[approvals.notify] could not store the notice in the outbox: queued in memory \
                 only, so a restart before it is delivered loses it"
            ),
        }
        self.queue.push(n);
    }
}

fn fmt(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

/// The JSON document for `a`. Only identifiers, names, times and the call hash: no token, no
/// argument values, no labels' content beyond the source tool names.
pub fn notice_json(kind: NoticeKind, event_id: &str, a: &Approval) -> Value {
    let user = &a.chain.originating_user;
    let mut v = json!({
        "type": kind.as_str(),
        "event_id": event_id,
        "approval_id": a.id,
        "decision_id": a.decision_id,
        "chain_id": a.chain_id,
        "server": a.server,
        "tool": a.tool,
        "call_hash": a.call_hash,
        "subject": user.subject,
        "issuer": user.issuer,
        "agent": a.chain.hops.last().map(|h| h.agent.0.as_str()),
        "chain_depth": a.chain.depth(),
        "requested_at": fmt(a.created_at),
        "expires_at": fmt(a.expires_at),
        "reason": reason_summary(a),
    });
    if kind == NoticeKind::Decided {
        let decision = match a.state {
            ApprovalState::Granted | ApprovalState::Consumed => "grant",
            _ => "decline",
        };
        v["decision"] = json!(decision);
        if let Some(p) = &a.approver {
            v["decided_by"] = json!({ "subject": p.subject, "by": p.method.by() });
        }
        if let Some(t) = a.decided_at {
            v["decided_at"] = json!(fmt(t));
        }
    }
    v
}

/// One line on why the call waits: the sources of the run's untrusted results, at most three
/// by name, and how many arguments matched one.
pub fn reason_summary(a: &Approval) -> String {
    let mut sources: Vec<&str> = Vec::new();
    for l in &a.labels {
        if !sources.contains(&l.source.as_str()) {
            sources.push(&l.source);
        }
    }
    let mut s = String::from("a policy asks for approval of this call");
    if !sources.is_empty() {
        let shown = sources
            .iter()
            .take(3)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str("; the run read untrusted results from ");
        s.push_str(&shown);
        if sources.len() > 3 {
            s.push_str(&format!(" and {} more", sources.len() - 3));
        }
    }
    match a.untrusted_args.len() {
        0 => {}
        1 => s.push_str("; 1 argument matches an untrusted result"),
        n => s.push_str(&format!("; {n} arguments match untrusted results")),
    }
    s
}

/// HMAC-SHA-256 of `msg` under `secret`, hex.
pub fn hmac_hex(secret: &[u8], msg: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    hex::encode(ring::hmac::sign(&key, msg).as_ref())
}

/// The [`SIGNATURE_HEADER`] value: `t=<timestamp>,v1=<hex HMAC-SHA-256 of "<timestamp>.<body>">`.
/// The timestamp is signed so that a receiver can refuse an old request replayed to it.
pub fn signature(secret: &[u8], timestamp: u64, body: &[u8]) -> String {
    let mut msg = format!("{timestamp}.").into_bytes();
    msg.extend_from_slice(body);
    format!("t={timestamp},v1={}", hmac_hex(secret, &msg))
}

/// `POST` each notice as JSON, signed.
pub struct WebhookNotify {
    client: reqwest::Client,
    url: String,
    /// For log lines: the URL's host only, since a path or query may carry a credential.
    host: String,
    headers: reqwest::header::HeaderMap,
    secret: Vec<u8>,
}

impl std::fmt::Debug for WebhookNotify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookNotify")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl WebhookNotify {
    /// `headers` are name and value pairs, already read from the environment.
    pub fn new(
        url: &str,
        headers: &[(String, String)],
        secret: Vec<u8>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let parsed = reqwest::Url::parse(url)?;
        let host = parsed.host_str().unwrap_or_default().to_string();
        let mut map = reqwest::header::HeaderMap::new();
        for (name, value) in headers {
            let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())?;
            let mut value = reqwest::header::HeaderValue::from_str(value).map_err(|_| {
                anyhow::anyhow!(
                    "[approvals.notify] headers: the value for {name} is not a valid header value"
                )
            })?;
            value.set_sensitive(true);
            map.insert(name, value);
        }
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            url: url.to_string(),
            host,
            headers: map,
            secret,
        })
    }
}

/// Whether notices to `url` would travel unencrypted to another host: an `http` URL (in any
/// letter case, as the URL parser reads the scheme) whose host is not `localhost` or a
/// loopback address (SR-96).
fn plain_http_off_loopback(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    let host = url.host_str().unwrap_or_default();
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = host.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|a| a.is_loopback());
    url.scheme() == "http" && !loopback
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[async_trait]
impl Deliver<Notice> for WebhookNotify {
    async fn deliver(&self, n: &Notice) -> Result<(), String> {
        let sig = signature(&self.secret, unix_now(), &n.body);
        let resp = self
            .client
            .post(&self.url)
            .headers(self.headers.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(EVENT_HEADER, n.kind.as_str())
            .header(EVENT_ID_HEADER, &n.event_id)
            .header(SIGNATURE_HEADER, sig)
            .body(n.body.clone())
            .send()
            .await
            // The URL is left out of the error: its path or query may hold a credential.
            .map_err(|e| format!("request to {} failed: {}", self.host, e.without_url()))?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("{} answered {status}", self.host))
        }
    }
}

/// Pending approvals by when they expire.
#[derive(Debug, Default)]
struct WatchState {
    due: BTreeSet<(Instant, String)>,
    at: HashMap<String, Instant>,
    stop: bool,
}

#[derive(Debug, Default)]
struct Watch {
    st: Mutex<WatchState>,
    wake: Condvar,
}

impl Watch {
    /// Look at `id` again at `when`. `false` when the watcher is full.
    fn add(&self, id: &str, when: Instant) -> bool {
        let mut st = self.st.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(old) = st.at.remove(id) {
            st.due.remove(&(old, id.to_string()));
        } else if st.at.len() >= MAX_WATCHED {
            return false;
        }
        st.at.insert(id.to_string(), when);
        st.due.insert((when, id.to_string()));
        drop(st);
        self.wake.notify_all();
        true
    }

    fn remove(&self, id: &str) {
        let mut st = self.st.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(old) = st.at.remove(id) {
            st.due.remove(&(old, id.to_string()));
        }
    }

    fn stop(&self) {
        self.st.lock().unwrap_or_else(|e| e.into_inner()).stop = true;
        self.wake.notify_all();
    }

    /// Wait for the next due id, or until `until`.
    fn next_due(&self, until: Instant) -> Next {
        let mut st = self.st.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if st.stop {
                return Next::Stop;
            }
            let now = Instant::now();
            let wake_at = match st.due.first().cloned() {
                Some((when, id)) if when <= now => {
                    st.due.remove(&(when, id.clone()));
                    st.at.remove(&id);
                    return Next::Due(id);
                }
                Some((when, _)) => when.min(until),
                None => until,
            };
            if wake_at <= now {
                return Next::Timeout;
            }
            st = self
                .wake
                .wait_timeout(st, wake_at - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

/// What [`Watch::next_due`] waited for.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    Due(String),
    Timeout,
    Stop,
}

/// When to look at an approval that expires at `expires_at`.
fn due_at(expires_at: OffsetDateTime) -> Instant {
    let left = expires_at - OffsetDateTime::now_utc();
    let left = Duration::try_from(left).unwrap_or(Duration::ZERO);
    Instant::now() + left + EXPIRY_GRACE
}

/// The producer end: what the pipeline and the approval routes call. Cheap to clone.
#[derive(Debug, Clone)]
pub struct NotifierHandle {
    emit: Emitter,
    watch: Arc<Watch>,
}

impl NotifierHandle {
    /// `a` was just stored as pending: store and queue `approval.pending`, and watch for its
    /// expiry. Writes one outbox row; never waits on the receiver.
    pub fn pending(&self, a: &Approval) {
        self.emit.emit(Notice::new(NoticeKind::Pending, a));
        if !self.watch.add(&a.id, due_at(a.expires_at)) {
            self.emit.metrics.approval_notify_dropped();
            tracing::warn!(
                approval = %a.id,
                max = MAX_WATCHED,
                "[approvals.notify] too many pending approvals watched: this one gets no \
                 approval.expired notice"
            );
        }
    }

    /// `a` was just granted or declined: store and queue `approval.decided`.
    pub fn decided(&self, a: &Approval) {
        self.watch.remove(&a.id);
        self.emit.emit(Notice::new(NoticeKind::Decided, a));
    }
}

/// A running notifier: the queue, its delivery thread and the expiry watcher.
#[derive(Debug)]
pub struct ApprovalNotifier {
    queue: Queue<Notice>,
    emit: Emitter,
    watch: Arc<Watch>,
    watcher: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl ApprovalNotifier {
    /// Validate `cfg`, read its secret and headers from the environment, and start. The
    /// error names a missing variable, never a value.
    pub fn start(
        cfg: &NotifySection,
        metrics: Arc<Metrics>,
        leases: Arc<SqliteLeaseStore>,
    ) -> anyhow::Result<Self> {
        cfg.validate()?;
        let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let secret = env(&cfg.secret_env).ok_or_else(|| {
            anyhow::anyhow!(
                "[approvals.notify] the signing secret is not set: put at least \
                 {NOTIFY_SECRET_MIN_LEN} bytes in the environment variable {}",
                cfg.secret_env
            )
        })?;
        if secret.len() < NOTIFY_SECRET_MIN_LEN {
            anyhow::bail!(
                "[approvals.notify] the signing secret in {} is shorter than \
                 {NOTIFY_SECRET_MIN_LEN} bytes",
                cfg.secret_env
            );
        }
        let mut headers = Vec::new();
        for (name, var) in &cfg.headers {
            let value = env(var).ok_or_else(|| {
                anyhow::anyhow!(
                    "[approvals.notify] headers: {name} names the environment variable {var}, \
                     which is not set"
                )
            })?;
            headers.push((name.clone(), value));
        }
        let deliver = WebhookNotify::new(
            &cfg.url,
            &headers,
            secret.into_bytes(),
            Duration::from_secs(cfg.timeout_seconds),
        )?;
        let host = deliver.host.clone();
        if plain_http_off_loopback(&cfg.url) {
            tracing::warn!(
                host = %host,
                "[approvals.notify] url is plain http to a host other than loopback: \
                 notifications travel unencrypted"
            );
        }
        let limits = SinkLimits {
            capacity: cfg.queue_capacity,
            max_lag: Duration::from_secs(cfg.max_lag_seconds),
            backoff: Backoff {
                initial: Duration::from_millis(cfg.initial_backoff_ms),
                max: Duration::from_secs(cfg.max_backoff_seconds),
            },
        };
        let retention = Duration::from_secs(cfg.outbox_retention_seconds);
        let n = Self::with_deliver(
            Box::new(deliver),
            limits,
            cfg.max_attempts,
            retention,
            metrics,
            leases,
        )?;
        tracing::info!(host = %host, capacity = cfg.queue_capacity, "[approvals.notify] notifying a webhook of approvals");
        Ok(n)
    }

    /// Start with any deliverer (tests). Hands the delivery thread the outbox rows still open
    /// and watches the approvals still pending (see the module docs), then returns.
    pub fn with_deliver(
        deliver: Box<dyn Deliver<Notice>>,
        limits: SinkLimits,
        max_attempts: u32,
        outbox_retention: Duration,
        metrics: Arc<Metrics>,
        store: Arc<SqliteLeaseStore>,
    ) -> anyhow::Result<Self> {
        let settle = OutboxSettle {
            store: store.clone(),
            metrics: metrics.clone(),
            backlog: Mutex::new(backlog_at_start(&store)),
        };
        let queue = Queue::start_with(
            deliver,
            limits,
            QueueRole::ApprovalNotices { max_attempts },
            metrics.clone(),
            Some(Box::new(settle)),
        )?;
        let emit = Emitter {
            queue: queue.handle(),
            store,
            metrics,
        };
        let watch = Arc::new(Watch::default());
        recover(&emit, &watch, outbox_retention);
        let (w, e) = (watch.clone(), emit.clone());
        let watcher = std::thread::Builder::new()
            .name("attenuo-approval-expiry".into())
            .spawn(move || watch_expiry(&w, &e, outbox_retention))?;
        Ok(Self {
            queue,
            emit,
            watch,
            watcher: Mutex::new(Some(watcher)),
        })
    }

    pub fn handle(&self) -> NotifierHandle {
        NotifierHandle {
            emit: self.emit.clone(),
            watch: self.watch.clone(),
        }
    }

    pub fn status(&self) -> SinkStatus {
        self.queue.status()
    }

    /// Stop watching, then deliver what is queued until `grace` has passed. Blocks.
    pub fn shutdown(&self, grace: Duration) {
        self.watch.stop();
        if let Some(t) = self.watcher.lock().ok().and_then(|mut t| t.take()) {
            let _ = t.join();
        }
        self.queue.shutdown(grace);
    }
}

impl Drop for ApprovalNotifier {
    fn drop(&mut self) {
        self.watch.stop();
    }
}

/// The outbox rows open at start, for [`OutboxSettle`] to hand to the queue a batch at a
/// time (SR-93). Read before the queue starts, so before any new notice is stored. A read that
/// fails is logged and leaves the backlog empty: those rows wait for the next restart.
fn backlog_at_start(store: &SqliteLeaseStore) -> Backlog {
    match store.outbox_last_open_id() {
        Ok(last) => Backlog {
            after: 0,
            through: last.unwrap_or(0),
        },
        Err(e) => {
            tracing::error!(error = %e, "[approvals.notify] could not read the outbox: notices stored before the restart are not delivered now");
            Backlog::default()
        }
    }
}

/// What a restart left, besides the open outbox rows (which the delivery thread reads in
/// batches, [`OutboxSettle`]): count those rows, and watch every approval still pending whose
/// expiry is within `retention` (the watcher queues `approval.expired` at once for one that
/// expired while the server was down). Errors are logged: the notifier starts anyway.
fn recover(emit: &Emitter, watch: &Watch, retention: Duration) {
    let store = &emit.store;
    match store.outbox_open_count() {
        Ok(n) => {
            emit.metrics.approval_notify_outbox_rows(n);
            if n > 0 {
                tracing::info!(
                    notices = n,
                    "[approvals.notify] delivering notices stored before the restart"
                );
            }
        }
        Err(e) => tracing::warn!(error = %e, "[approvals.notify] could not count the outbox"),
    }
    let oldest = OffsetDateTime::now_utc() - retention;
    match store.pending_approvals(MAX_WATCHED) {
        Ok(pending) => {
            for a in pending.iter().filter(|a| a.expires_at > oldest) {
                watch.add(&a.id, due_at(a.expires_at));
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "[approvals.notify] could not read the pending approvals: those waiting before the restart get no approval.expired notice")
        }
    }
}

/// Delete outbox rows settled longer than `retention` ago.
fn prune_outbox(emit: &Emitter, retention: Duration) {
    match emit
        .store
        .outbox_prune(OffsetDateTime::now_utc() - retention)
    {
        Ok(0) => {}
        Ok(n) => tracing::debug!(rows = n, "[approvals.notify] pruned the outbox"),
        Err(e) => tracing::warn!(error = %e, "[approvals.notify] pruning the outbox failed"),
    }
}

/// The expiry watcher: queue `approval.expired` for each watched approval still pending once
/// its expiry has passed, and prune the outbox every [`OUTBOX_PRUNE_PERIOD`].
fn watch_expiry(watch: &Watch, emit: &Emitter, retention: Duration) {
    let leases: &dyn LeaseStore = emit.store.as_ref();
    let metrics = &emit.metrics;
    let mut prune_at = Instant::now();
    loop {
        if Instant::now() >= prune_at {
            prune_outbox(emit, retention);
            prune_at = Instant::now() + OUTBOX_PRUNE_PERIOD;
        }
        let id = match watch.next_due(prune_at) {
            Next::Due(id) => id,
            Next::Timeout => continue,
            Next::Stop => return,
        };
        match leases.approval(&id) {
            Ok(Some(a)) if a.state == ApprovalState::Pending => {
                if a.is_expired(OffsetDateTime::now_utc()) {
                    emit.emit(Notice::new(NoticeKind::Expired, &a));
                } else {
                    // The clocks disagree by a little: look again.
                    watch.add(
                        &a.id,
                        due_at(a.expires_at).max(Instant::now() + EXPIRY_GRACE),
                    );
                }
            }
            // Decided, used, or gone (pruned, or dropped after a failed audit append).
            Ok(_) => {}
            Err(e) => {
                metrics.approval_notify_dropped();
                tracing::warn!(approval = %id, error = %e, "[approvals.notify] approval unreadable at its expiry: no approval.expired notice");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attenuo_audit::{ApprovalLabel, ApprovalMethod, Approver};
    use attenuo_core::{AgentId, Capability, DelegationChain, Hop, LeaseId, OriginatingUser};

    fn approval(state: ApprovalState) -> Approval {
        let t = OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap();
        let hop = |agent: &str, lease: &str| Hop {
            agent: AgentId::new(agent),
            capabilities: std::iter::once(Capability::new("github", "*")).collect(),
            lease: LeaseId::new(lease),
            expires_at: t + time::Duration::hours(1),
            issued_at: t,
        };
        let chain = DelegationChain {
            originating_user: OriginatingUser {
                subject: "alice".into(),
                issuer: "https://idp.example".into(),
                authenticated_at: t,
                attributes: Default::default(),
            },
            hops: vec![hop("planner", "l0"), hop("coder", "l1")],
        };
        Approval {
            id: "11111111-1111-4111-8111-111111111111".into(),
            chain_id: LeaseId::new("l0"),
            lease: LeaseId::new("l1"),
            call_hash: "ab".repeat(32),
            server: "github".into(),
            tool: "delete_repo".into(),
            arguments: json!({"repo": "alice/site", "token": "ghp_secret"}),
            labels: vec![
                ApprovalLabel {
                    source: "github/read_web".into(),
                    seq: 3,
                },
                ApprovalLabel {
                    source: "github/read_web".into(),
                    seq: 4,
                },
            ],
            untrusted_args: Vec::new(),
            decision_id: "22222222-2222-4222-8222-222222222222".into(),
            chain,
            created_at: t,
            expires_at: t + time::Duration::seconds(120),
            state,
            approver: None,
            decided_at: None,
            consumed_by: None,
            jkt: None,
        }
    }

    #[test]
    fn pending_notice_has_the_fields_and_no_arguments() {
        let a = approval(ApprovalState::Pending);
        let v = notice_json(NoticeKind::Pending, "e1", &a);
        assert_eq!(
            v,
            json!({
                "type": "approval.pending",
                "event_id": "e1",
                "approval_id": a.id,
                "decision_id": a.decision_id,
                "chain_id": "l0",
                "server": "github",
                "tool": "delete_repo",
                "call_hash": a.call_hash,
                "subject": "alice",
                "issuer": "https://idp.example",
                "agent": "coder",
                "chain_depth": 2,
                "requested_at": "2026-05-28T20:26:40Z",
                "expires_at": "2026-05-28T20:28:40Z",
                "reason": "a policy asks for approval of this call; the run read untrusted \
                           results from github/read_web",
            })
        );
        let body = String::from_utf8(Notice::new(NoticeKind::Pending, &a).body).unwrap();
        assert!(
            !body.contains("alice/site") && !body.contains("ghp_secret"),
            "{body}"
        );
        assert!(!body.contains("arguments"), "{body}");
    }

    #[test]
    fn decided_notice_names_the_decision_and_the_approver() {
        let mut a = approval(ApprovalState::Declined);
        a.approver = Some(Approver {
            subject: "urn:attenuo:admin".into(),
            method: ApprovalMethod::AdminToken,
        });
        a.decided_at = Some(a.created_at + time::Duration::seconds(5));
        let v = notice_json(NoticeKind::Decided, "e2", &a);
        assert_eq!(v["type"], "approval.decided");
        assert_eq!(v["decision"], "decline");
        assert_eq!(
            v["decided_by"],
            json!({"subject": "urn:attenuo:admin", "by": "operator"})
        );
        assert_eq!(v["decided_at"], "2026-05-28T20:26:45Z");
        a.state = ApprovalState::Granted;
        assert_eq!(
            notice_json(NoticeKind::Decided, "e3", &a)["decision"],
            "grant"
        );
        // Expired and pending notices carry no decision.
        let e = notice_json(NoticeKind::Expired, "e4", &a);
        assert_eq!(e["type"], "approval.expired");
        assert!(e.get("decision").is_none() && e.get("decided_by").is_none());
    }

    #[test]
    fn reason_lists_at_most_three_sources_and_counts_matched_arguments() {
        let mut a = approval(ApprovalState::Pending);
        a.labels.clear();
        assert_eq!(
            reason_summary(&a),
            "a policy asks for approval of this call"
        );
        a.labels = ["a/x", "b/y", "c/z", "d/w", "e/v"]
            .iter()
            .enumerate()
            .map(|(i, s)| ApprovalLabel {
                source: (*s).into(),
                seq: i as u64,
            })
            .collect();
        assert_eq!(
            reason_summary(&a),
            "a policy asks for approval of this call; the run read untrusted results from \
             a/x, b/y, c/z and 2 more"
        );
    }

    /// RFC 4231 test case 2, then the header built on it.
    #[test]
    fn signature_is_hmac_sha256_over_timestamp_dot_body() {
        assert_eq!(
            hmac_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let body = br#"{"type":"approval.pending"}"#;
        let sig = signature(b"Jefe", 1_780_000_000, body);
        let mut msg = b"1780000000.".to_vec();
        msg.extend_from_slice(body);
        assert_eq!(sig, format!("t=1780000000,v1={}", hmac_hex(b"Jefe", &msg)));
        assert_ne!(
            sig,
            signature(b"Jefe", 1_780_000_001, body),
            "the time is signed"
        );
        assert_ne!(sig, signature(b"other", 1_780_000_000, body));
    }

    #[test]
    fn event_id_is_a_stable_uuid_per_approval_and_type() {
        let a = event_id_for(NoticeKind::Pending, "a1");
        assert_eq!(a, event_id_for(NoticeKind::Pending, "a1"));
        assert_ne!(a, event_id_for(NoticeKind::Expired, "a1"));
        assert_ne!(a, event_id_for(NoticeKind::Pending, "a2"));
        let u = uuid::Uuid::parse_str(&a).unwrap();
        assert_eq!(u.get_version_num(), 8);
        assert_eq!(u.get_variant(), uuid::Variant::RFC4122);
        let n = Notice::new(NoticeKind::Pending, &approval(ApprovalState::Pending));
        let body: Value = serde_json::from_slice(&n.body).unwrap();
        assert_eq!(body["event_id"], n.event_id);
        for k in [
            NoticeKind::Pending,
            NoticeKind::Decided,
            NoticeKind::Expired,
        ] {
            assert_eq!(NoticeKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(NoticeKind::parse("approval.other"), None);
    }

    #[test]
    fn webhook_debug_shows_the_host_only() {
        let w = WebhookNotify::new(
            "https://hooks.example/p/very-secret-path?key=k",
            &[("authorization".into(), "Bearer s3cret".into())],
            b"x".repeat(32),
            Duration::from_secs(1),
        )
        .unwrap();
        let d = format!("{w:?}");
        assert!(d.contains("hooks.example"), "{d}");
        assert!(!d.contains("very-secret") && !d.contains("s3cret") && !d.contains("key=k"));
    }

    #[test]
    fn config_validation() {
        let mut c = NotifySection::new("https://hooks.example/attenuo");
        c.validate().unwrap();
        for bad in [
            "ftp://hooks.example/",
            "https://user:pw@hooks.example/",
            "https://hooks.example/#x",
            "not a url",
        ] {
            c.url = bad.into();
            assert!(c.validate().is_err(), "{bad}");
        }
        c.url = "https://hooks.example/".into();
        c.headers.insert("X-Attenuo-Signature".into(), "E".into());
        assert!(c.validate().is_err());
        c.headers.clear();
        c.headers.insert("content-type".into(), "E".into());
        assert!(c.validate().is_err());
        c.headers.clear();
        c.headers.insert("authorization".into(), String::new());
        assert!(c.validate().is_err());
        c.headers.clear();
        c.max_attempts = 0;
        assert!(c.validate().is_err());
    }

    /// SR-96: the plain-http warning reads the scheme as the URL parser does, so an upper-case
    /// `HTTP://` to another host is warned about too, and every loopback address is exempt.
    #[test]
    fn plain_http_to_another_host_is_detected_in_any_case_sr96() {
        for url in [
            "http://hooks.example/a",
            "HTTP://hooks.example/a",
            "Http://10.0.0.5:8080/",
            "http://[2001:db8::1]/",
        ] {
            assert!(plain_http_off_loopback(url), "{url}");
        }
        for url in [
            "https://hooks.example/a",
            "HTTPS://hooks.example/a",
            "http://localhost:9000/",
            "http://LOCALHOST/",
            "http://127.0.0.1/",
            "http://127.0.0.2:9/",
            "http://[::1]:9/",
        ] {
            assert!(!plain_http_off_loopback(url), "{url}");
        }
    }

    /// Records the event ids it delivers. While `hold` is set, the first delivery tells
    /// `started` and waits for `release`.
    #[derive(Default)]
    struct Recorder {
        got: Mutex<Vec<String>>,
        hold: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    }

    struct RecorderRef(Arc<Recorder>);

    #[async_trait]
    impl Deliver<Notice> for RecorderRef {
        async fn deliver(&self, n: &Notice) -> Result<(), String> {
            let hold = self.0.hold.lock().unwrap().take();
            if let Some((started, release)) = hold {
                started.send(()).unwrap();
                release.recv().unwrap();
            }
            self.0.got.lock().unwrap().push(n.event_id.clone());
            Ok(())
        }
    }

    fn wait_until(mut f: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(10);
        while !f() {
            assert!(Instant::now() < end, "timed out");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// A store with `n` open outbox rows, as a restart finds them: their event ids, in order.
    fn store_with_open_rows(n: usize) -> (Arc<SqliteLeaseStore>, Vec<String>) {
        let store = Arc::new(SqliteLeaseStore::open_in_memory().unwrap());
        let now = OffsetDateTime::now_utc();
        let mut events = Vec::new();
        for i in 0..n {
            let mut a = approval(ApprovalState::Pending);
            a.id = format!("00000000-0000-4000-8000-{i:012}");
            let notice = Notice::new(NoticeKind::Pending, &a);
            let new = NewNotice {
                event_id: &notice.event_id,
                kind: notice.kind.as_str(),
                approval_id: &notice.approval_id,
                body: &notice.body,
            };
            store.outbox_insert(new, now).unwrap().unwrap();
            events.push(notice.event_id);
        }
        // One already delivered before the restart: not sent again.
        let done = event_id_for(NoticeKind::Decided, "delivered-before");
        let row = store
            .outbox_insert(
                NewNotice {
                    event_id: &done,
                    kind: "approval.decided",
                    approval_id: "delivered-before",
                    body: b"{}",
                },
                now,
            )
            .unwrap()
            .unwrap();
        store.outbox_delivered(row, now).unwrap();
        (store, events)
    }

    fn start(
        store: &Arc<SqliteLeaseStore>,
        recorder: &Arc<Recorder>,
        capacity: usize,
    ) -> (ApprovalNotifier, Arc<Metrics>) {
        let metrics = Metrics::new();
        let limits = SinkLimits {
            capacity,
            max_lag: Duration::from_secs(3600),
            backoff: Backoff {
                initial: Duration::from_millis(1),
                max: Duration::from_millis(5),
            },
        };
        let n = ApprovalNotifier::with_deliver(
            Box::new(RecorderRef(recorder.clone())),
            limits,
            3,
            Duration::from_secs(3600),
            metrics.clone(),
            store.clone(),
        )
        .unwrap();
        (n, metrics)
    }

    /// SR-93: after a restart with more open rows than the queue holds, every row gets a
    /// delivery attempt, in order, and none is given up for lack of room.
    #[test]
    fn a_backlog_longer_than_the_queue_is_delivered_whole_and_in_order_sr93() {
        let (store, events) = store_with_open_rows(23);
        let recorder = Arc::new(Recorder::default());
        let (n, metrics) = start(&store, &recorder, 4);
        wait_until(|| recorder.got.lock().unwrap().len() >= events.len());
        n.shutdown(Duration::from_secs(5));
        assert_eq!(*recorder.got.lock().unwrap(), events);
        assert_eq!(store.outbox_open_count().unwrap(), 0);
        let text = metrics.render();
        assert!(
            text.contains("attenuo_approval_notify_dropped_total 0\n"),
            "{text}"
        );
        assert!(
            text.contains("attenuo_approval_notify_delivered_total 23\n"),
            "{text}"
        );
    }

    /// SR-93: a notice stored while the backlog drains is queued directly and delivered once:
    /// the backlog stops at the last row open at start, so the delivery thread never reads a
    /// later row from the outbox, not even one whose notice is stored but not queued yet (an
    /// `emit` between its insert and its push, stood in for here by a bare insert).
    #[test]
    fn a_notice_stored_while_the_backlog_drains_is_delivered_once_sr93() {
        let (store, events) = store_with_open_rows(10);
        let recorder = Arc::new(Recorder::default());
        let (started, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release) = std::sync::mpsc::channel();
        *recorder.hold.lock().unwrap() = Some((started, release));
        let (n, metrics) = start(&store, &recorder, 4);
        // The first backlog row is in flight, three more are queued.
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let mut fresh = approval(ApprovalState::Pending);
        fresh.id = "33333333-3333-4333-8333-333333333333".into();
        fresh.expires_at = OffsetDateTime::now_utc() + time::Duration::hours(1);
        n.handle().pending(&fresh);
        let fresh_event = event_id_for(NoticeKind::Pending, &fresh.id);
        let mid_emit = event_id_for(NoticeKind::Expired, &fresh.id);
        store
            .outbox_insert(
                NewNotice {
                    event_id: &mid_emit,
                    kind: "approval.expired",
                    approval_id: &fresh.id,
                    body: b"{}",
                },
                OffsetDateTime::now_utc(),
            )
            .unwrap()
            .unwrap();
        release_tx.send(()).unwrap();
        wait_until(|| recorder.got.lock().unwrap().len() > events.len());
        // Shutting down delivers anything still queued, so a second copy would show here.
        n.shutdown(Duration::from_secs(5));
        let got = recorder.got.lock().unwrap().clone();
        // The first batch, the fresh notice queued behind it, then the rest of the backlog.
        let mut want = events[..4].to_vec();
        want.push(fresh_event);
        want.extend_from_slice(&events[4..]);
        assert_eq!(got, want);
        // Only the row whose push is still to come is open: the backlog did not take it.
        assert!(store.outbox_open_id(&mid_emit).unwrap().is_some());
        assert_eq!(store.outbox_open_count().unwrap(), 1);
        assert!(metrics
            .render()
            .contains("attenuo_approval_notify_dropped_total 0\n"));
    }

    #[test]
    fn watch_returns_ids_in_expiry_order_and_forgets_removed_ones() {
        let w = Watch::default();
        let now = Instant::now();
        assert!(w.add("b", now + Duration::from_millis(20)));
        assert!(w.add("a", now));
        assert!(w.add("c", now + Duration::from_millis(10)));
        w.remove("c");
        let later = Instant::now() + Duration::from_secs(5);
        assert_eq!(w.next_due(later), Next::Due("a".into()));
        assert_eq!(w.next_due(later), Next::Due("b".into()));
        assert_eq!(w.next_due(Instant::now()), Next::Timeout);
        w.stop();
        assert_eq!(w.next_due(later), Next::Stop);
    }
}
