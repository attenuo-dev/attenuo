//! The checkpoint sink (`[audit.sink]`, SR-21): ships every signed audit checkpoint off the
//! host as soon as it is created.
//!
//! Why: a checkpoint is signed with the server's own issuer key. An attacker who holds the
//! host and that key can rewrite the SQLite log and sign new checkpoints over the rewritten
//! history; an export of it verifies against the JWKS. A copy that already left the host
//! cannot be rewritten, and `attenuo audit verify --file <export> --checkpoints <shipped>`
//! reports any checkpoint signed again after it was shipped
//! ([`attenuo_audit::cross_check`]).
//!
//! How: the log's `on_created` hook runs after the commit that wrote the checkpoint was synced
//! (SR-50) and calls [`SinkHandle::push`], which only queues. The queue is bounded
//! (`queue_capacity`); when it is full the oldest queued checkpoint is dropped, because every
//! later checkpoint covers the entries an earlier one does, and
//! `attenuo_audit_sink_dropped_total` counts it. A prune's anchor is never dropped (see
//! below). One background thread, with its own
//! single-threaded Tokio runtime, delivers the queue in order. A failed delivery is retried
//! with exponential backoff and full jitter between half and all of the delay (`initial_backoff_ms`
//! doubling up to `max_backoff_seconds`) until it succeeds; it is never skipped, so a sink
//! that keeps failing holds the queue until it fills. [`SinkHandle::status`] says the sink is
//! degraded (on `/readyz`) when the queue is full or the oldest undelivered checkpoint is older
//! than `max_lag_seconds`.
//!
//! Three deliverers: [`WebhookDeliver`] (`POST`, any 2xx), [`FileDeliver`] (append one JSON
//! line, `fsync`), and [`S3Deliver`] (`PUT` with AWS Signature Version 4, implemented here on
//! `ring` HMAC and `sha2`). The webhook and S3 clients check the receiver's certificate against
//! the built-in web PKI roots plus the CA certificates of `ca_pem_path`, read once at start;
//! the S3 credentials are read once at start too, and nothing refreshes them.
//!
//! A prune of the log (`[audit.retention]`, ADR-0015) ships its signed anchor through the same
//! queue, between the checkpoint before the prune record and the one after it, as a
//! [`ShippedAnchor`] envelope ([`Shipped::Anchor`]): one more webhook `POST`, file line or S3
//! object (`<prefix>anchor-<through_seq, 20 digits>-<first 16 hex of anchor_sha256>.json`).
//! [`SinkHandle::delivered_through`] is the highest checkpoint seq delivered since start,
//! which the prune's "sink caught up" guard reads. An anchor is never dropped from a full
//! queue ([`QueueItem::keep`]) and, like a checkpoint, never given up: a receiver that refuses
//! it holds every later checkpoint behind it, and the sink goes degraded. Each delivery is
//! told to [`CheckpointSink::on_anchor_delivered`] (the server records the anchor's
//! `shipped_at`), and the server queues again at start-up any anchor not delivered yet.
//!
//! The queue itself ([`Queue`]) is generic over what it carries, so the approval notifier
//! (`[approvals.notify]`) and the revocation notifier (`[leases.notify]`), both in
//! [`crate::notify`], run on the same code with their own metrics and one difference: a
//! notification is given up after `max_attempts` ([`QueueRole::give_up`]), where a checkpoint
//! never is.

use std::collections::VecDeque;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use attenuo_audit::{Anchor, Checkpoint, ShippedAnchor, ShippedCheckpoint};
use sha2::{Digest, Sha256};

use crate::config::{SinkKind, SinkSection, SINK_TOKEN_ENV};
use crate::metrics::Metrics;

/// What the checkpoint sink ships: a signed checkpoint, or the signed anchor of a prune.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shipped {
    /// A checkpoint, as [`ShippedCheckpoint`].
    Checkpoint(ShippedCheckpoint),
    /// A prune's anchor, as [`ShippedAnchor`].
    Anchor(ShippedAnchor),
}

impl Shipped {
    /// The canonical JSON bytes (the webhook body, the S3 object).
    pub fn to_canonical_json(&self) -> Vec<u8> {
        match self {
            Self::Checkpoint(c) => c.to_canonical_json(),
            Self::Anchor(a) => a.to_canonical_json(),
        }
    }

    /// One JSONL line, newline included (the file sink).
    pub fn to_line(&self) -> String {
        match self {
            Self::Checkpoint(c) => c.to_line(),
            Self::Anchor(a) => a.to_line(),
        }
    }

    /// The checkpoint, when this is one.
    pub fn checkpoint(&self) -> Option<&ShippedCheckpoint> {
        match self {
            Self::Checkpoint(c) => Some(c),
            Self::Anchor(_) => None,
        }
    }
}

/// Delivers one queued item (a shipped checkpoint or anchor unless named). `Err` is retried.
#[async_trait]
pub trait Deliver<T: Sync = Shipped>: Send + Sync {
    /// Deliver `item` once. `Err` carries the failure for the log and `last_error`; the queue
    /// retries after a backoff, or gives up as its [`QueueRole`] says.
    async fn deliver(&self, item: &T) -> Result<(), String>;
}

/// What a [`Queue`] carries.
pub trait QueueItem: Send + Sync + 'static {
    /// Names the item in log lines. Never secret.
    fn log_id(&self) -> String;

    /// Failed attempts made before the item was queued: an approval notice reloaded from the
    /// outbox after a restart. They count towards [`QueueRole::give_up`]. Default 0.
    fn attempts(&self) -> u32 {
        0
    }

    /// Never dropped from a full queue: a push onto a full queue drops the oldest item that
    /// is not kept instead, and when every queued item is kept the queue grows past its
    /// capacity. Default false.
    fn keep(&self) -> bool {
        false
    }
}

/// What became of a queued item, told to the queue's [`Settle`] hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// Delivered.
    Delivered,
    /// Attempt number `attempts` failed; the next one follows in `wait`.
    Retry {
        /// Failed attempts so far, this one and any made before the item was queued included.
        attempts: u32,
        /// Delay before the next attempt.
        wait: Duration,
    },
    /// Every attempt failed ([`QueueRole::give_up`]): dropped.
    GaveUp {
        /// Failed attempts in all, any made before the item was queued included.
        attempts: u32,
    },
    /// Dropped from a full queue before delivery.
    Dropped,
}

/// Told what became of each item, for a queue whose items are also kept elsewhere (the
/// approval notice outbox, [`crate::notify`]). Runs on the delivery thread, before the
/// delivered and failure counters move; [`Settled::Dropped`] runs on the thread that pushed.
/// Never called for an item left queued at shutdown: it stays wherever the hook keeps it.
pub trait Settle<T>: Send + Sync + std::fmt::Debug {
    /// How one attempt to deliver `item` ended, or that it was dropped from a full queue.
    fn settled(&self, item: &T, how: Settled);

    /// Items kept elsewhere that wait for room in the queue, oldest first, at most `room`
    /// (the approval notices a restart left open, SR-93). The delivery thread asks each time
    /// it finds the queue empty, outside the lock, for at most half the capacity (SR-98), and
    /// puts what it gets at the front, so they go before anything queued meanwhile. Default:
    /// none.
    fn refill(&self, room: usize) -> Vec<T> {
        let _ = room;
        Vec::new()
    }
}

impl QueueItem for Shipped {
    fn log_id(&self) -> String {
        match self {
            Self::Checkpoint(c) => format!("checkpoint seq {}", c.checkpoint.seq),
            Self::Anchor(a) => format!("anchor through seq {}", a.anchor.through_seq),
        }
    }

    /// A prune's anchor is the only copy off the host of where the log starts: it is never
    /// dropped (ADR-0015).
    fn keep(&self) -> bool {
        matches!(self, Self::Anchor(_))
    }
}

/// Which queue this is: where its log lines and metrics go, and whether it gives up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueRole {
    /// `[audit.sink]`: retried until delivered.
    Checkpoints,
    /// `[approvals.notify]`: given up after this many failed attempts (at least 1).
    ApprovalNotices {
        /// The `[approvals.notify]` attempt limit; 0 counts as 1.
        max_attempts: u32,
    },
    /// `[leases.notify]`: given up after this many failed attempts (at least 1).
    LeaseNotices {
        /// The `[leases.notify]` attempt limit; 0 counts as 1.
        max_attempts: u32,
    },
}

impl QueueRole {
    /// The config section, as log lines name it.
    pub fn section(self) -> &'static str {
        match self {
            Self::Checkpoints => "[audit.sink]",
            Self::ApprovalNotices { .. } => "[approvals.notify]",
            Self::LeaseNotices { .. } => "[leases.notify]",
        }
    }

    fn thread_name(self) -> &'static str {
        match self {
            Self::Checkpoints => "attenuo-ckpt-sink",
            Self::ApprovalNotices { .. } => "attenuo-approval-notify",
            Self::LeaseNotices { .. } => "attenuo-lease-notify",
        }
    }

    /// After how many failed attempts an item is dropped; `None` retries forever.
    pub fn give_up(self) -> Option<u32> {
        match self {
            Self::Checkpoints => None,
            Self::ApprovalNotices { max_attempts } | Self::LeaseNotices { max_attempts } => {
                Some(max_attempts.max(1))
            }
        }
    }

    /// The counters of a notifier's queue; `None` for the checkpoint sink.
    fn notify(self, m: &Metrics) -> Option<&crate::metrics::NotifyCounters> {
        match self {
            Self::Checkpoints => None,
            Self::ApprovalNotices { .. } => Some(m.approval_notify()),
            Self::LeaseNotices { .. } => Some(m.lease_notify()),
        }
    }

    fn delivered(self, m: &Metrics) {
        match self.notify(m) {
            None => m.audit_sink_delivered(),
            Some(n) => n.delivered(),
        }
    }

    fn failed(self, m: &Metrics) {
        match self.notify(m) {
            None => m.audit_sink_failure(),
            Some(n) => n.failure(),
        }
    }

    fn dropped(self, m: &Metrics) {
        match self.notify(m) {
            None => m.audit_sink_dropped(),
            Some(n) => n.dropped(),
        }
    }

    fn gauges(self, m: &Metrics, depth: u64, oldest: Option<SystemTime>) {
        match self.notify(m) {
            None => m.audit_sink_queue(depth, oldest),
            Some(n) => n.queue(depth),
        }
    }
}

/// Exponential backoff with jitter: attempt `n` (from 0) waits a uniformly random time
/// between half and all of `min(initial * 2^n, max)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// The ceiling of the first retry.
    pub initial: Duration,
    /// The most any retry waits.
    pub max: Duration,
}

impl Backoff {
    /// The ceiling for attempt `n`, before jitter.
    pub fn ceiling(&self, attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt.min(31)).unwrap_or(u32::MAX);
        self.initial.saturating_mul(factor).min(self.max)
    }

    /// The delay for attempt `n`, with `unit` in `[0, 1)` choosing where in
    /// `[ceiling/2, ceiling]` it lands.
    pub fn delay(&self, attempt: u32, unit: f64) -> Duration {
        let c = self.ceiling(attempt);
        let half = c / 2;
        half + (c - half).mul_f64(unit.clamp(0.0, 1.0))
    }
}

/// A cheap source of jitter (splitmix64); not for anything secret.
#[derive(Debug)]
struct Jitter(u64);

impl Jitter {
    fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            // The low 64 bits of the clock are the seed.
            .map_or(0, |d| {
                u64::try_from(d.as_nanos() & u128::from(u64::MAX)).unwrap_or_default()
            });
        Self(seed ^ u64::from(std::process::id()).rotate_left(32))
    }

    fn unit(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Queue limits and timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkLimits {
    /// Most items queued; pushing onto a full queue drops the oldest.
    pub capacity: usize,
    /// Lag (or failing time) past which [`SinkStatus::degraded`] is set.
    pub max_lag: Duration,
    /// Retry delays.
    pub backoff: Backoff,
}

impl SinkLimits {
    /// The limits `[audit.sink]` sets: `queue_capacity`, `max_lag_seconds`,
    /// `initial_backoff_ms`, `max_backoff_seconds`.
    pub fn from_config(cfg: &SinkSection) -> Self {
        Self {
            capacity: cfg.queue_capacity,
            max_lag: Duration::from_secs(cfg.max_lag_seconds),
            backoff: Backoff {
                initial: Duration::from_millis(cfg.initial_backoff_ms),
                max: Duration::from_secs(cfg.max_backoff_seconds),
            },
        }
    }
}

#[derive(Debug)]
struct Queued<T> {
    item: T,
    since: Instant,
    since_wall: SystemTime,
}

#[derive(Debug)]
struct State<T> {
    queue: VecDeque<Queued<T>>,
    /// The item being delivered, by when it was queued.
    in_flight: Option<(Instant, SystemTime)>,
    /// First failure since the last successful delivery; cleared on success.
    failing_since: Option<Instant>,
    last_error: Option<String>,
    /// Shutting down: deliver what is queued until this deadline, then stop.
    stop_at: Option<Instant>,
}

impl<T> Default for State<T> {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            in_flight: None,
            failing_since: None,
            last_error: None,
            stop_at: None,
        }
    }
}

#[derive(Debug)]
struct Shared<T> {
    state: Mutex<State<T>>,
    wake: Condvar,
    limits: SinkLimits,
    role: QueueRole,
    metrics: Arc<Metrics>,
    /// Told what became of each item, when set.
    settle: Option<Box<dyn Settle<T>>>,
    /// Test hook: delivered items, by count.
    delivered: AtomicU64,
}

impl<T> Shared<T> {
    fn settled(&self, item: &T, how: Settled) {
        if let Some(s) = &self.settle {
            s.settled(item, how);
        }
    }

    /// Ask the hook for waiting items: at most half the capacity, so that items pushed while
    /// the batch is delivered find room instead of pushing the batch out of a full queue (and
    /// the queue does not read as full the whole time a backlog drains, SR-98).
    fn refill(&self) -> Vec<T> {
        self.settle
            .as_ref()
            .map_or_else(Vec::new, |s| s.refill(refill_room(self.limits.capacity)))
    }

    fn oldest(st: &State<T>) -> Option<(Instant, SystemTime)> {
        st.in_flight
            .or_else(|| st.queue.front().map(|q| (q.since, q.since_wall)))
    }

    /// Refresh the depth and oldest-undelivered gauges. Call with the lock held.
    fn gauges(&self, st: &State<T>) {
        self.role.gauges(
            &self.metrics,
            st.queue.len() as u64,
            Self::oldest(st).map(|(_, wall)| wall),
        );
    }
}

/// Whether the sink keeps up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkStatus {
    /// Items waiting for delivery, not counting the one in flight.
    pub queued: usize,
    /// The queue's capacity ([`SinkLimits::capacity`]).
    pub capacity: usize,
    /// Age of the oldest item not yet delivered (zero when none).
    pub lag: Duration,
    /// How long deliveries have been failing (since the last success).
    pub failing_for: Option<Duration>,
    /// The error of the last failed attempt, cleared by a success.
    pub last_error: Option<String>,
    /// The queue is full, or `lag` (or `failing_for`) exceeds `max_lag_seconds`.
    pub degraded: bool,
}

/// The end of a [`Queue`] that producers push into. Cheap to clone.
#[derive(Debug)]
pub struct QueueHandle<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Clone for QueueHandle<T> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<T: QueueItem> QueueHandle<T> {
    /// Queue `item` for delivery. Never blocks on the network or on disk. When the queue is
    /// full the oldest queued item that is not [kept](QueueItem::keep) is dropped and
    /// counted.
    pub fn push(&self, item: T) {
        let Ok(mut st) = self.shared.state.lock() else {
            return;
        };
        let mut dropped = None;
        if st.queue.len() >= self.shared.limits.capacity {
            let oldest = st.queue.iter().position(|q| !q.item.keep());
            if let Some(old) = oldest.and_then(|i| st.queue.remove(i)) {
                self.shared.role.dropped(&self.shared.metrics);
                tracing::error!(
                    dropped = %old.item.log_id(),
                    capacity = self.shared.limits.capacity,
                    "{} queue full: dropped the oldest undelivered item",
                    self.shared.role.section()
                );
                dropped = Some(old.item);
            }
        }
        st.queue.push_back(Queued {
            item,
            since: Instant::now(),
            since_wall: SystemTime::now(),
        });
        self.shared.gauges(&st);
        drop(st);
        self.shared.wake.notify_all();
        if let Some(old) = dropped {
            self.shared.settled(&old, Settled::Dropped);
        }
    }

    /// How the queue is keeping up now.
    pub fn status(&self) -> SinkStatus {
        self.status_at(Instant::now())
    }

    fn status_at(&self, now: Instant) -> SinkStatus {
        let st = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        let limits = self.shared.limits;
        let lag = Shared::<T>::oldest(&st)
            .map_or(Duration::ZERO, |(t, _)| now.saturating_duration_since(t));
        let failing_for = st.failing_since.map(|t| now.saturating_duration_since(t));
        let full = st.queue.len() >= limits.capacity;
        let degraded =
            full || lag > limits.max_lag || failing_for.is_some_and(|f| f > limits.max_lag);
        SinkStatus {
            queued: st.queue.len(),
            capacity: limits.capacity,
            lag,
            failing_for,
            last_error: st.last_error.clone(),
            degraded,
        }
    }

    /// Items delivered since start.
    pub fn delivered(&self) -> u64 {
        self.shared.delivered.load(Ordering::Relaxed)
    }
}

/// A running queue: its items plus the delivery thread. Dropping it stops the thread without
/// waiting; [`shutdown`](Self::shutdown) gives queued items a grace period first.
#[derive(Debug)]
pub struct Queue<T> {
    handle: QueueHandle<T>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl<T: QueueItem> Queue<T> {
    /// Start delivering with `deliver`.
    ///
    /// # Errors
    ///
    /// As [`start_with`](Self::start_with).
    pub fn start(
        deliver: Box<dyn Deliver<T>>,
        limits: SinkLimits,
        role: QueueRole,
        metrics: Arc<Metrics>,
    ) -> anyhow::Result<Self> {
        Self::start_with(deliver, limits, role, metrics, None)
    }

    /// [`start`](Self::start), telling `settle` what became of each item.
    ///
    /// # Errors
    ///
    /// When the delivery thread cannot be spawned.
    pub fn start_with(
        deliver: Box<dyn Deliver<T>>,
        limits: SinkLimits,
        role: QueueRole,
        metrics: Arc<Metrics>,
        settle: Option<Box<dyn Settle<T>>>,
    ) -> anyhow::Result<Self> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
            limits,
            role,
            metrics,
            settle,
            delivered: AtomicU64::new(0),
        });
        let worker = shared.clone();
        let thread = std::thread::Builder::new()
            .name(role.thread_name().into())
            .spawn(move || run(worker, deliver))?;
        Ok(Self {
            handle: QueueHandle { shared },
            thread: Mutex::new(Some(thread)),
        })
    }

    /// A producer end of this queue.
    pub fn handle(&self) -> QueueHandle<T> {
        self.handle.clone()
    }

    /// How the queue is keeping up now.
    pub fn status(&self) -> SinkStatus {
        self.handle.status()
    }

    /// Stop after delivering what is queued, giving up at `grace`. Blocks (call it from a
    /// blocking context); a request already in flight can add its timeout.
    pub fn shutdown(&self, grace: Duration) {
        self.stop(Instant::now() + grace);
        let thread = self.thread.lock().ok().and_then(|mut t| t.take());
        if let Some(t) = thread {
            let _ = t.join();
        }
    }

    fn stop(&self, at: Instant) {
        if let Ok(mut st) = self.handle.shared.state.lock() {
            st.stop_at = Some(st.stop_at.map_or(at, |s| s.min(at)));
        }
        self.handle.shared.wake.notify_all();
    }
}

impl<T> Drop for Queue<T> {
    fn drop(&mut self) {
        if let Ok(mut st) = self.handle.shared.state.lock() {
            let now = Instant::now();
            st.stop_at = Some(st.stop_at.map_or(now, |s| s.min(now)));
        }
        self.handle.shared.wake.notify_all();
    }
}

/// The queue end the log's hook pushes into. Cheap to clone.
#[derive(Debug, Clone)]
pub struct SinkHandle {
    queue: QueueHandle<Shipped>,
    public_url: Option<String>,
    delivered_through: Arc<AtomicU64>,
    anchors: Arc<AnchorTracking>,
}

/// Told of each anchor the sink delivered ([`CheckpointSink::on_anchor_delivered`]).
type AnchorDelivered = Box<dyn Fn(&Anchor) + Send + Sync>;

/// What became of the anchors pushed: the ones queued and not yet delivered, and who to tell
/// of a delivery (the audit log, which records `shipped_at`).
#[derive(Default)]
struct AnchorTracking {
    pending: Mutex<std::collections::BTreeSet<u64>>,
    on_delivered: std::sync::OnceLock<AnchorDelivered>,
}

impl std::fmt::Debug for AnchorTracking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorTracking")
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

impl AnchorTracking {
    fn delivered(&self, a: &Anchor) {
        if let Ok(mut p) = self.pending.lock() {
            p.remove(&a.through_seq);
        }
        if let Some(f) = self.on_delivered.get() {
            f(a);
        }
    }
}

impl SinkHandle {
    /// Queue `cp` for delivery. Never blocks on the network or on disk.
    pub fn push(&self, cp: &Checkpoint) {
        self.queue.push(Shipped::Checkpoint(ShippedCheckpoint::new(
            cp,
            self.public_url.clone(),
        )));
    }

    /// Queue a prune's anchor for delivery, unless it is queued already and not yet
    /// delivered. Never blocks on the network or on disk, and the anchor is never dropped
    /// from a full queue ([`QueueItem::keep`]). True when it was queued now.
    pub fn push_anchor(&self, a: &Anchor) -> bool {
        let fresh = self
            .anchors
            .pending
            .lock()
            .map_or(true, |mut p| p.insert(a.through_seq));
        if fresh {
            self.queue.push(Shipped::Anchor(ShippedAnchor::new(
                a,
                self.public_url.clone(),
            )));
        }
        fresh
    }

    /// The anchor through `through_seq` is queued and not yet delivered.
    pub fn anchor_pending(&self, through_seq: u64) -> bool {
        self.anchors
            .pending
            .lock()
            .is_ok_and(|p| p.contains(&through_seq))
    }

    /// The highest checkpoint seq delivered since start; `None` before the first. The prune's
    /// "sink caught up" guard reads it (ADR-0015).
    pub fn delivered_through(&self) -> Option<u64> {
        match self.delivered_through.load(Ordering::Acquire) {
            0 => None,
            n => Some(n),
        }
    }

    /// How the sink is keeping up now.
    pub fn status(&self) -> SinkStatus {
        self.queue.status()
    }

    #[cfg(test)]
    fn status_at(&self, now: Instant) -> SinkStatus {
        self.queue.status_at(now)
    }

    /// Checkpoints delivered since start.
    pub fn delivered(&self) -> u64 {
        self.queue.delivered()
    }
}

/// A running sink: the queue plus its delivery thread. Dropping it stops the thread without
/// waiting; [`shutdown`](Self::shutdown) gives queued checkpoints a grace period first.
#[derive(Debug)]
pub struct CheckpointSink {
    queue: Queue<Shipped>,
    public_url: Option<String>,
    kind: SinkKind,
    delivered_through: Arc<AtomicU64>,
    anchors: Arc<AnchorTracking>,
}

/// Wraps the configured deliverer to keep the highest checkpoint seq delivered, and to tell
/// of each anchor delivered.
struct Tracked {
    inner: Box<dyn Deliver>,
    delivered_through: Arc<AtomicU64>,
    anchors: Arc<AnchorTracking>,
}

#[async_trait]
impl Deliver for Tracked {
    async fn deliver(&self, item: &Shipped) -> Result<(), String> {
        self.inner.deliver(item).await?;
        match item {
            Shipped::Checkpoint(c) => {
                self.delivered_through
                    .fetch_max(c.checkpoint.seq, Ordering::AcqRel);
            }
            Shipped::Anchor(a) => self.anchors.delivered(&a.anchor),
        }
        Ok(())
    }
}

impl CheckpointSink {
    /// Validate `cfg` and start delivering.
    ///
    /// # Errors
    ///
    /// When `cfg` does not validate, when `ca_pem_path` cannot be read or holds no usable CA
    /// certificate, when the webhook or S3 client cannot be built, when an S3 sink
    /// has no access key id or secret access key (in the config or `AWS_ACCESS_KEY_ID` and
    /// `AWS_SECRET_ACCESS_KEY`), when a file sink's path cannot be opened for appending, or as
    /// [`with_deliver`](Self::with_deliver).
    pub fn start(
        cfg: &SinkSection,
        public_url: Option<String>,
        metrics: Arc<Metrics>,
    ) -> anyhow::Result<Self> {
        cfg.validate()?;
        let timeout = Duration::from_secs(cfg.timeout_seconds);
        let roots = sink_roots(cfg)?;
        let deliver: Box<dyn Deliver> = match cfg.kind {
            SinkKind::Webhook => Box::new(WebhookDeliver::new(
                cfg.url.clone().unwrap_or_default(),
                cfg.bearer_token
                    .clone()
                    .or_else(|| std::env::var(SINK_TOKEN_ENV).ok().filter(|t| !t.is_empty())),
                timeout,
                &roots,
            )?),
            SinkKind::File => Box::new(FileDeliver::new(cfg.path.clone().unwrap_or_default())?),
            SinkKind::S3 => Box::new(S3Deliver::from_config(cfg, timeout, &roots)?),
        };
        let mut sink =
            Self::with_deliver(deliver, SinkLimits::from_config(cfg), public_url, metrics)?;
        sink.kind = cfg.kind;
        tracing::info!(kind = %cfg.kind, capacity = cfg.queue_capacity, "[audit.sink] shipping checkpoints off the host");
        Ok(sink)
    }

    /// Start with any deliverer (tests).
    ///
    /// # Errors
    ///
    /// When the delivery thread cannot be spawned.
    pub fn with_deliver(
        deliver: Box<dyn Deliver>,
        limits: SinkLimits,
        public_url: Option<String>,
        metrics: Arc<Metrics>,
    ) -> anyhow::Result<Self> {
        let delivered_through = Arc::new(AtomicU64::new(0));
        let anchors = Arc::new(AnchorTracking::default());
        let deliver = Box::new(Tracked {
            inner: deliver,
            delivered_through: delivered_through.clone(),
            anchors: anchors.clone(),
        });
        Ok(Self {
            queue: Queue::start(deliver, limits, QueueRole::Checkpoints, metrics)?,
            public_url,
            kind: SinkKind::Webhook,
            delivered_through,
            anchors,
        })
    }

    /// A producer end for the audit log's checkpoint hook.
    pub fn handle(&self) -> SinkHandle {
        SinkHandle {
            queue: self.queue.handle(),
            public_url: self.public_url.clone(),
            delivered_through: self.delivered_through.clone(),
            anchors: self.anchors.clone(),
        }
    }

    /// Run `f` on the delivery thread after each anchor is delivered (the server records
    /// `shipped_at` with it). Set once; a second call is ignored.
    pub fn on_anchor_delivered(&self, f: impl Fn(&Anchor) + Send + Sync + 'static) {
        let _ = self.anchors.on_delivered.set(Box::new(f));
    }

    /// The anchor through `through_seq` is queued and not yet delivered.
    pub fn anchor_pending(&self, through_seq: u64) -> bool {
        self.handle().anchor_pending(through_seq)
    }

    /// The highest checkpoint seq delivered since start ([`SinkHandle::delivered_through`]).
    pub fn delivered_through(&self) -> Option<u64> {
        match self.delivered_through.load(Ordering::Acquire) {
            0 => None,
            n => Some(n),
        }
    }

    /// The configured kind (`webhook`, `file` or `s3`).
    pub fn kind(&self) -> SinkKind {
        self.kind
    }

    /// How the sink is keeping up now, which `/readyz` reports.
    pub fn status(&self) -> SinkStatus {
        self.queue.status()
    }

    /// Stop after delivering what is queued, giving up at `grace`. Blocks (call it from a
    /// blocking context); a request already in flight can add its timeout.
    pub fn shutdown(&self, grace: Duration) {
        self.queue.shutdown(grace);
    }
}

/// How many waiting items [`Settle::refill`] is asked for at a time: half the queue, at least
/// one (SR-98).
fn refill_room(capacity: usize) -> usize {
    (capacity / 2).max(1)
}

/// The delivery thread.
fn run<T: QueueItem>(shared: Arc<Shared<T>>, deliver: Box<dyn Deliver<T>>) {
    let section = shared.role.section();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "{section} cannot start its runtime; nothing will be delivered");
            return;
        }
    };
    let mut jitter = Jitter::new();
    loop {
        // Next item, or stop.
        let item = {
            let mut st = shared.state.lock().unwrap_or_else(|e| e.into_inner());
            // Asked the hook for waiting items since the last wake-up.
            let mut refilled = false;
            loop {
                let stopping = st.stop_at.is_some_and(|t| Instant::now() >= t);
                if stopping {
                    if !st.queue.is_empty() {
                        tracing::error!(
                            undelivered = st.queue.len(),
                            "{section} stopping with items not delivered"
                        );
                    }
                    return;
                }
                if let Some(q) = st.queue.pop_front() {
                    st.in_flight = Some((q.since, q.since_wall));
                    break q;
                }
                if st.stop_at.is_some() {
                    return; // stopping and nothing left
                }
                if !refilled {
                    // Empty: take the next items waiting elsewhere, if any (SR-93). Outside
                    // the lock, since the hook may read from disk.
                    refilled = true;
                    drop(st);
                    let more = shared.refill();
                    st = shared.state.lock().unwrap_or_else(|e| e.into_inner());
                    if !more.is_empty() {
                        let (since, since_wall) = (Instant::now(), SystemTime::now());
                        for item in more.into_iter().rev() {
                            st.queue.push_front(Queued {
                                item,
                                since,
                                since_wall,
                            });
                        }
                        shared.gauges(&st);
                    }
                    continue;
                }
                st = shared.wake.wait(st).unwrap_or_else(|e| e.into_inner());
                refilled = false;
            }
        };
        let mut attempt = item.item.attempts();
        loop {
            let result = rt.block_on(deliver.deliver(&item.item));
            // Tell the hook first, outside the lock: it may write to disk.
            let wait = match &result {
                Ok(()) => {
                    shared.settled(&item.item, Settled::Delivered);
                    Duration::ZERO
                }
                Err(_) => {
                    let attempts = attempt.saturating_add(1);
                    if shared.role.give_up().is_some_and(|n| attempts >= n) {
                        shared.settled(&item.item, Settled::GaveUp { attempts });
                        Duration::ZERO
                    } else {
                        let wait = shared.limits.backoff.delay(attempts - 1, jitter.unit());
                        shared.settled(&item.item, Settled::Retry { attempts, wait });
                        wait
                    }
                }
            };
            let mut st = shared.state.lock().unwrap_or_else(|e| e.into_inner());
            match result {
                Ok(()) => {
                    st.in_flight = None;
                    st.failing_since = None;
                    st.last_error = None;
                    shared.gauges(&st);
                    shared.delivered.fetch_add(1, Ordering::Relaxed);
                    shared.role.delivered(&shared.metrics);
                    break;
                }
                Err(e) => {
                    shared.role.failed(&shared.metrics);
                    st.failing_since.get_or_insert_with(Instant::now);
                    attempt = attempt.saturating_add(1);
                    if shared.role.give_up().is_some_and(|n| attempt >= n) {
                        // Given up: counted as dropped. `failing_since` stays until a later
                        // delivery succeeds, so a receiver that stays down still degrades.
                        tracing::error!(
                            item = %item.item.log_id(),
                            attempts = attempt,
                            error = %e,
                            "{section} delivery failed on every attempt; dropped"
                        );
                        st.last_error = Some(e);
                        st.in_flight = None;
                        shared.role.dropped(&shared.metrics);
                        shared.gauges(&st);
                        break;
                    }
                    tracing::warn!(
                        item = %item.item.log_id(),
                        attempt = attempt - 1,
                        error = %e,
                        "{section} delivery failed; retrying"
                    );
                    st.last_error = Some(e);
                    let until = Instant::now() + wait;
                    // Sleep, but wake for a shutdown whose deadline has passed.
                    loop {
                        let now = Instant::now();
                        if st.stop_at.is_some_and(|t| now >= t) {
                            tracing::error!(
                                item = %item.item.log_id(),
                                undelivered = st.queue.len() + 1,
                                "{section} stopping with items not delivered"
                            );
                            return;
                        }
                        if now >= until {
                            break;
                        }
                        let mut d = until - now;
                        if let Some(t) = st.stop_at {
                            d = d.min(t.saturating_duration_since(now));
                        }
                        st = shared
                            .wake
                            .wait_timeout(st, d)
                            .unwrap_or_else(|e| e.into_inner())
                            .0;
                    }
                }
            }
        }
    }
}

/// The extra CA certificates of `[audit.sink] ca_pem_path` (none when unset), read once.
///
/// # Errors
///
/// The file cannot be read or holds no PEM certificate; the message names the key and path.
fn sink_roots(cfg: &SinkSection) -> anyhow::Result<Vec<reqwest::Certificate>> {
    let Some(path) = cfg.ca_pem_path.as_deref() else {
        return Ok(Vec::new());
    };
    let fail = |e: String| {
        anyhow::anyhow!(
            "[audit.sink] ca_pem_path {:?}: {e}",
            path.display().to_string()
        )
    };
    let roots = crate::idp::jwks::read_ca_pem(path).map_err(fail)?;
    // Build once here so a certificate that is not a usable trust anchor fails at start,
    // naming the file, and not as a client-build error without it.
    sink_client(Duration::from_secs(1), &roots).map_err(|e| {
        fail(format!(
            "a certificate cannot be used as a trust anchor ({})",
            crate::idp::jwks::error_chain(&e)
        ))
    })?;
    let endpoint = cfg.url.as_deref().or(cfg.endpoint.as_deref());
    if endpoint.is_some_and(|u| u.starts_with("http://")) {
        tracing::warn!(
            "[audit.sink] ca_pem_path is set but the sink's URL is http://: the CA is not used \
             and requests are not encrypted"
        );
    }
    Ok(roots)
}

/// The HTTP client of a webhook or S3 sink: `timeout` per request, no redirects followed, and
/// the built-in web PKI roots plus `extra_roots` (`ca_pem_path`) trusted.
fn sink_client(
    timeout: Duration,
    extra_roots: &[reqwest::Certificate],
) -> reqwest::Result<reqwest::Client> {
    extra_roots
        .iter()
        .fold(
            reqwest::Client::builder()
                .timeout(timeout)
                .redirect(reqwest::redirect::Policy::none()),
            |b, c| b.add_root_certificate(c.clone()),
        )
        .build()
}

/// A failed request as the sink logs it: reqwest's error without the URL (its query may hold
/// a credential, SR-94), followed by its causes, so a TLS failure names itself (`invalid peer
/// certificate: UnknownIssuer`) and is not only `error sending request`.
fn request_failed(e: reqwest::Error) -> String {
    format!(
        "request failed: {}",
        crate::idp::jwks::error_chain(&e.without_url())
    )
}

/// `POST` the shipped checkpoint as JSON.
#[derive(Debug)]
pub struct WebhookDeliver {
    client: reqwest::Client,
    url: String,
    bearer: Option<String>,
}

impl WebhookDeliver {
    /// A webhook deliverer for `url`, with `bearer` as `Authorization: Bearer` when set. Each
    /// request times out after `timeout`; redirects are not followed. `extra_roots` are
    /// trusted in addition to the built-in web PKI roots.
    ///
    /// # Errors
    ///
    /// The HTTP client cannot be built.
    pub fn new(
        url: String,
        bearer: Option<String>,
        timeout: Duration,
        extra_roots: &[reqwest::Certificate],
    ) -> anyhow::Result<Self> {
        let client = sink_client(timeout, extra_roots)?;
        Ok(Self {
            client,
            url,
            bearer,
        })
    }
}

#[async_trait]
impl Deliver for WebhookDeliver {
    async fn deliver(&self, s: &Shipped) -> Result<(), String> {
        let req = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        let mut req = match s {
            Shipped::Checkpoint(c) => req
                .header("x-attenuo-checkpoint-seq", c.checkpoint.seq.to_string())
                .header("x-attenuo-checkpoint-sha256", &c.checkpoint_sha256),
            Shipped::Anchor(a) => req
                .header(
                    "x-attenuo-anchor-through-seq",
                    a.anchor.through_seq.to_string(),
                )
                .header("x-attenuo-anchor-sha256", &a.anchor_sha256),
        }
        .body(s.to_canonical_json());
        if let Some(t) = &self.bearer {
            req = req.bearer_auth(t);
        }
        // The URL is left out of the error: its query may hold a credential (SR-94).
        let resp = req.send().await.map_err(request_failed)?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("receiver answered {status}"))
        }
    }
}

/// Append one JSON line per checkpoint and sync it.
#[derive(Debug)]
pub struct FileDeliver {
    path: PathBuf,
}

impl FileDeliver {
    /// A sink appending to `path`, checked at startup.
    ///
    /// # Errors
    ///
    /// When `path` cannot be opened for appending (missing directory, no permission); the message
    /// names the path.
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        open_append(&path)
            .map_err(|e| anyhow::anyhow!("[audit.sink] path {}: {e}", path.display()))?;
        Ok(Self { path })
    }
}

fn open_append(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

#[async_trait]
impl Deliver for FileDeliver {
    async fn deliver(&self, s: &Shipped) -> Result<(), String> {
        // Opened per line, so an operator's rotation (rename, new file) is picked up.
        let write = || -> std::io::Result<()> {
            let mut f = open_append(&self.path)?;
            f.write_all(s.to_line().as_bytes())?;
            f.sync_data()
        };
        write().map_err(|e| format!("{}: {e}", self.path.display()))
    }
}

/// Credentials for [`S3Deliver`].
#[derive(Clone)]
pub struct S3Credentials {
    /// AWS access key id.
    pub access_key_id: String,
    /// AWS secret access key. Left out of `Debug`.
    pub secret_access_key: String,
    /// STS session token, sent as `x-amz-security-token` when set. Left out of `Debug`.
    pub session_token: Option<String>,
}

impl std::fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Credentials")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

/// `PUT` each checkpoint as `<endpoint>/<bucket>/<prefix><seq>-<sha16>.json`, signed with
/// AWS Signature Version 4.
#[derive(Debug)]
pub struct S3Deliver {
    client: reqwest::Client,
    endpoint: String,
    bucket: String,
    region: String,
    prefix: String,
    creds: S3Credentials,
}

impl S3Deliver {
    fn from_config(
        cfg: &SinkSection,
        timeout: Duration,
        extra_roots: &[reqwest::Certificate],
    ) -> anyhow::Result<Self> {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let access_key_id = cfg
            .access_key_id
            .clone()
            .or_else(|| env("AWS_ACCESS_KEY_ID"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "[audit.sink] kind = \"s3\" needs access_key_id (or AWS_ACCESS_KEY_ID)"
                )
            })?;
        let secret_access_key = cfg
            .secret_access_key
            .clone()
            .or_else(|| env("AWS_SECRET_ACCESS_KEY"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "[audit.sink] kind = \"s3\" needs secret_access_key (or AWS_SECRET_ACCESS_KEY)"
                )
            })?;
        Self::new(
            cfg.endpoint.clone().unwrap_or_default(),
            cfg.bucket.clone().unwrap_or_default(),
            cfg.region.clone().unwrap_or_else(|| "us-east-1".into()),
            cfg.prefix
                .clone()
                .unwrap_or_else(|| "attenuo/checkpoints/".into()),
            S3Credentials {
                access_key_id,
                secret_access_key,
                session_token: cfg
                    .session_token
                    .clone()
                    .or_else(|| env("AWS_SESSION_TOKEN")),
            },
            timeout,
            extra_roots,
        )
    }

    /// An S3 deliverer for `bucket` at `endpoint` (a trailing `/` is dropped), naming objects
    /// under `prefix`. Each request times out after `timeout`; redirects are not followed.
    /// `extra_roots` are trusted in addition to the built-in web PKI roots. The credentials
    /// are kept as given: nothing refreshes them (temporary ones need a restart).
    ///
    /// # Errors
    ///
    /// The HTTP client cannot be built, or `endpoint` is not a base URL with a host as the
    /// URL parser reads it (`check_s3_endpoint`).
    pub fn new(
        endpoint: String,
        bucket: String,
        region: String,
        prefix: String,
        creds: S3Credentials,
        timeout: Duration,
        extra_roots: &[reqwest::Certificate],
    ) -> anyhow::Result<Self> {
        check_s3_endpoint(&endpoint).map_err(|e| anyhow::anyhow!("S3 endpoint {e}"))?;
        let client = sink_client(timeout, extra_roots)?;
        Ok(Self {
            client,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            bucket,
            region,
            prefix,
            creds,
        })
    }

    /// The object key for `s`: `<prefix><seq>-<sha16>.json` for a checkpoint,
    /// `<prefix>anchor-<through_seq>-<sha16>.json` for an anchor (seqs in 20 digits).
    pub fn key(&self, s: &Shipped) -> String {
        let short = |h: &str| h[..16.min(h.len())].to_string();
        match s {
            Shipped::Checkpoint(c) => format!(
                "{}{:020}-{}.json",
                self.prefix,
                c.checkpoint.seq,
                short(&c.checkpoint_sha256)
            ),
            Shipped::Anchor(a) => format!(
                "{}anchor-{:020}-{}.json",
                self.prefix,
                a.anchor.through_seq,
                short(&a.anchor_sha256)
            ),
        }
    }
}

#[async_trait]
impl Deliver for S3Deliver {
    async fn deliver(&self, s: &Shipped) -> Result<(), String> {
        let body = s.to_canonical_json();
        let path = format!(
            "/{}/{}",
            uri_encode(&self.bucket, true),
            uri_encode(&self.key(s), false)
        );
        let url = format!("{}{}", self.endpoint, path);
        let amz_date = amz_date(SystemTime::now());
        let digest = Sha256::digest(&body);
        let payload_hash = hex::encode(digest);
        let headers = s3_put_headers(
            signed_host(&self.endpoint),
            &digest,
            &amz_date,
            self.creds.session_token.as_deref(),
        );
        let auth = sigv4_authorization(&SigV4Request {
            method: "PUT",
            canonical_uri: &path,
            canonical_query: "",
            headers: &headers,
            payload_sha256: &payload_hash,
            region: &self.region,
            service: "s3",
            amz_date: &amz_date,
            creds: &self.creds,
        });
        let mut req = self
            .client
            .put(&url)
            .body(body)
            .header("authorization", auth);
        for (k, v) in &headers {
            if k != "host" {
                req = req.header(k.as_str(), v.as_str());
            }
        }
        let resp = req.send().await.map_err(request_failed)?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            match s3_error_code(resp).await {
                Some(code) => Err(format!("S3 answered {status} ({code})")),
                None => Err(format!("S3 answered {status}")),
            }
        }
    }
}

/// Most bytes of an S3 error answer read to find its `<Code>`.
const S3_ERROR_BODY_MAX: usize = 4096;

/// The `<Code>` of an S3 error answer (`SignatureDoesNotMatch`, `ExpiredToken`,
/// `InvalidTokenId`, `AccessDenied`, ...), which tells a wrong secret from an expired session
/// token where the status alone (403) does not. At most [`S3_ERROR_BODY_MAX`] bytes are read;
/// a code that is not a short run of ASCII letters and digits is not reported, so the store
/// cannot put arbitrary text in the log.
async fn s3_error_code(mut resp: reqwest::Response) -> Option<String> {
    let mut body = Vec::new();
    while body.len() < S3_ERROR_BODY_MAX {
        match resp.chunk().await {
            Ok(Some(c)) => body.extend_from_slice(&c),
            _ => break,
        }
    }
    body.truncate(S3_ERROR_BODY_MAX);
    s3_error_code_of(&body)
}

fn s3_error_code_of(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let start = text.find("<Code>")? + "<Code>".len();
    let len = text[start..].find("</Code>")?;
    let code = &text[start..start + len];
    (!code.is_empty() && code.len() <= 64 && code.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| code.to_string())
}

/// The headers of the sink's PutObject, every one of them signed: `content-type`, `host`,
/// `x-amz-checksum-sha256` (base64 of the body's SHA-256), `x-amz-content-sha256` (its hex),
/// `x-amz-date`, `x-amz-sdk-checksum-algorithm` (`SHA256`) and, with STS credentials,
/// `x-amz-security-token`.
///
/// The checksum pair is what an upload into an Object Lock bucket with a retention period
/// needs: AWS's PutObject reference says "The `Content-MD5` or `x-amz-sdk-checksum-algorithm`
/// header is required", and that `x-amz-sdk-checksum-algorithm` must come with the matching
/// `x-amz-checksum-<algorithm>` header, here `x-amz-checksum-sha256`, "the Base64 encoded,
/// 256-bit SHA256 digest of the object". S3 also checks the body against it (`BadDigest` on
/// a mismatch). SHA-256 because the sink computes it already; no MD5 is needed.
fn s3_put_headers(
    host: String,
    body_sha256: &[u8],
    amz_date: &str,
    session_token: Option<&str>,
) -> Vec<(String, String)> {
    use base64::Engine as _;
    let mut headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("host".to_string(), host),
        (
            "x-amz-checksum-sha256".to_string(),
            base64::engine::general_purpose::STANDARD.encode(body_sha256),
        ),
        ("x-amz-content-sha256".to_string(), hex::encode(body_sha256)),
        ("x-amz-date".to_string(), amz_date.to_string()),
        (
            "x-amz-sdk-checksum-algorithm".to_string(),
            "SHA256".to_string(),
        ),
    ];
    if let Some(t) = session_token {
        headers.push(("x-amz-security-token".to_string(), t.to_string()));
    }
    headers
}

/// Is `endpoint` an S3 base URL as the HTTP client reads it (SR-119)? It must parse, have a
/// host, and have no path (`/` at most), query or fragment. Without a host, the request URL
/// `<endpoint>/<bucket>/<key>` is `http:///<bucket>/<key>`, which the URL parser reads with
/// the bucket as its host. A backslash, whitespace or a control character is refused: the
/// parser reads `\` as `/` and drops tabs and line breaks.
///
/// # Errors
///
/// A message, after the endpoint (callers name it), saying what is wrong.
pub(crate) fn check_s3_endpoint(endpoint: &str) -> Result<(), String> {
    // The parser reads `\` as `/` and drops tabs and line breaks, so the string the request
    // URL is built from would not be the URL sent (as for `derive = "host"`, SR-56).
    if endpoint
        .chars()
        .any(|c| c == '\\' || c.is_whitespace() || c.is_control())
    {
        return Err("holds a backslash, whitespace or a control character".into());
    }
    let url = reqwest::Url::parse(endpoint).map_err(|e| format!("is not a URL ({e})"))?;
    if url.host_str().is_none_or(str::is_empty) {
        return Err("has no host".into());
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(format!(
            "must be a base URL without a path, query or fragment (the HTTP client reads it as \
             path {:?}; requests are path-style: <endpoint>/<bucket>/<key>)",
            url.path()
        ));
    }
    Ok(())
}

/// The `host` header value SigV4 signs for `endpoint`: what the HTTP client sends, so the
/// host as the URL parser normalizes it (lowercased) and the port only when it is not the
/// scheme's default (`http://s3:80` sends `Host: s3`). Signing the endpoint as written made
/// S3 answer 403 for an endpoint with an explicit default port.
fn signed_host(endpoint: &str) -> String {
    match reqwest::Url::parse(endpoint) {
        Ok(url) => match (url.host_str(), url.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_string(),
            (None, _) => String::new(),
        },
        Err(_) => endpoint
            .split_once("://")
            .map_or("", |(_, h)| h)
            .to_string(),
    }
}

/// `YYYYMMDD'T'HHMMSS'Z'` in UTC.
pub fn amz_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let dt = i64::try_from(secs)
        .ok()
        .and_then(|s| time::OffsetDateTime::from_unix_timestamp(s).ok())
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

/// RFC 3986 percent-encoding as SigV4 wants it: unreserved characters kept, everything else
/// `%XX` (uppercase); `/` kept unless `encode_slash`.
pub fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// What SigV4 signs.
pub struct SigV4Request<'a> {
    /// HTTP method, for example `PUT`.
    pub method: &'a str,
    /// Already encoded with [`uri_encode`].
    pub canonical_uri: &'a str,
    /// Canonical query string, already encoded and sorted; empty when there is none.
    pub canonical_query: &'a str,
    /// Lowercase names; every header listed here is signed.
    pub headers: &'a [(String, String)],
    /// Hex SHA-256 of the request body.
    pub payload_sha256: &'a str,
    /// AWS region, for example `us-east-1`.
    pub region: &'a str,
    /// AWS service name, for example `s3`.
    pub service: &'a str,
    /// Request time as `YYYYMMDD'T'HHMMSS'Z'` (the `x-amz-date` header); its first eight
    /// characters are the scope date.
    pub amz_date: &'a str,
    /// The signing credentials.
    pub creds: &'a S3Credentials,
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::sign(&k, data).as_ref().to_vec()
}

/// The SigV4 canonical request of `r` and its signed-header list: headers lowercased, values
/// with runs of whitespace folded to one space, sorted by name.
fn sigv4_canonical_request(r: &SigV4Request<'_>) -> (String, String) {
    let mut headers: Vec<(String, String)> = r
        .headers
        .iter()
        .map(|(k, v)| {
            let v = v.split_whitespace().collect::<Vec<_>>().join(" ");
            (k.to_ascii_lowercase(), v)
        })
        .collect();
    headers.sort();
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        r.method,
        r.canonical_uri,
        r.canonical_query,
        canonical_headers,
        signed_headers,
        r.payload_sha256
    );
    (canonical_request, signed_headers)
}

/// The `Authorization` header value for `r` (AWS Signature Version 4, header form).
pub fn sigv4_authorization(r: &SigV4Request<'_>) -> String {
    let (canonical_request, signed_headers) = sigv4_canonical_request(r);
    let date = &r.amz_date[..8];
    let scope = format!("{date}/{}/{}/aws4_request", r.region, r.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        r.amz_date,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac(
        format!("AWS4{}", r.creds.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac(&k_date, r.region.as_bytes());
    let k_service = hmac(&k_region, r.service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        r.creds.access_key_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn cp(seq: u64) -> Checkpoint {
        Checkpoint {
            seq,
            head_hash: format!("{seq:064x}"),
            at: "2026-10-23T00:00:00Z".into(),
            kid: "k1".into(),
            signature: "sig".into(),
        }
    }

    fn limits(capacity: usize, max_lag: Duration) -> SinkLimits {
        SinkLimits {
            capacity,
            max_lag,
            backoff: Backoff {
                initial: Duration::from_millis(1),
                max: Duration::from_millis(5),
            },
        }
    }

    /// Fails while `fail` is set; records what it delivered.
    #[derive(Default)]
    struct Fake {
        fail: std::sync::atomic::AtomicBool,
        attempts: AtomicUsize,
        got: Mutex<Vec<u64>>,
    }

    struct FakeRef(Arc<Fake>);

    #[async_trait]
    impl Deliver for FakeRef {
        async fn deliver(&self, s: &Shipped) -> Result<(), String> {
            self.0.attempts.fetch_add(1, Ordering::SeqCst);
            if self.0.fail.load(Ordering::SeqCst) {
                return Err("down".into());
            }
            // A checkpoint by its seq, an anchor by 1000 plus its boundary.
            let n = match s {
                Shipped::Checkpoint(c) => c.checkpoint.seq,
                Shipped::Anchor(a) => 1000 + a.anchor.through_seq,
            };
            self.0.got.lock().unwrap().push(n);
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

    #[test]
    fn backoff_doubles_caps_and_jitters_within_half_to_full() {
        let b = Backoff {
            initial: Duration::from_millis(500),
            max: Duration::from_secs(60),
        };
        assert_eq!(b.ceiling(0), Duration::from_millis(500));
        assert_eq!(b.ceiling(1), Duration::from_secs(1));
        assert_eq!(b.ceiling(3), Duration::from_secs(4));
        assert_eq!(b.ceiling(7), Duration::from_secs(60));
        assert_eq!(b.ceiling(u32::MAX), Duration::from_secs(60));
        assert_eq!(b.delay(1, 0.0), Duration::from_millis(500));
        assert_eq!(b.delay(1, 1.0), Duration::from_secs(1));
        let mut j = Jitter::new();
        let mut distinct = std::collections::BTreeSet::new();
        for _ in 0..200 {
            let u = j.unit();
            assert!((0.0..1.0).contains(&u));
            let d = b.delay(2, u);
            assert!(d >= Duration::from_secs(1) && d <= Duration::from_secs(2));
            distinct.insert(d);
        }
        assert!(distinct.len() > 100, "jitter spreads the delays");
    }

    #[test]
    fn delivers_in_order_and_retries_until_the_sink_recovers() {
        let fake = Arc::new(Fake::default());
        fake.fail.store(true, Ordering::SeqCst);
        let metrics = Metrics::new();
        let sink = CheckpointSink::with_deliver(
            Box::new(FakeRef(fake.clone())),
            limits(16, Duration::from_secs(60)),
            Some("https://ob.example".into()),
            metrics.clone(),
        )
        .unwrap();
        let h = sink.handle();
        for s in 1..=3 {
            h.push(&cp(s));
        }
        wait_until(|| fake.attempts.load(Ordering::SeqCst) >= 4);
        assert!(h.status().failing_for.is_some());
        assert_eq!(h.status().last_error.as_deref(), Some("down"));
        fake.fail.store(false, Ordering::SeqCst);
        wait_until(|| h.delivered() == 3);
        assert_eq!(*fake.got.lock().unwrap(), vec![1, 2, 3]);
        let st = h.status();
        assert_eq!(
            (st.queued, st.lag, st.failing_for, st.degraded),
            (0, Duration::ZERO, None, false)
        );
        let text = metrics.render();
        assert!(text.contains("attenuo_audit_sink_delivered_total 3\n"));
        assert!(!text.contains("attenuo_audit_sink_failures_total 0\n"));
        assert!(text.contains("attenuo_audit_sink_queue_depth 0\n"));
        sink.shutdown(Duration::from_secs(1));
    }

    fn anchor(through: u64) -> Anchor {
        Anchor {
            through_seq: through,
            through_hash: format!("{through:064x}"),
            prune_seq: through + 16,
            prune_entry_hash: "ab".repeat(32),
            previous_through_seq: None,
            archive_sha256: None,
            at: "2026-10-23T00:00:00Z".into(),
            kid: "k1".into(),
            signature: "sig".into(),
        }
    }

    /// A prune's anchor goes through the same queue; `delivered_through` is the highest
    /// checkpoint seq delivered, which an anchor does not move.
    #[test]
    fn anchors_are_shipped_and_delivered_through_tracks_checkpoints() {
        let fake = Arc::new(Fake::default());
        let sink = CheckpointSink::with_deliver(
            Box::new(FakeRef(fake.clone())),
            limits(16, Duration::from_secs(60)),
            None,
            Metrics::new(),
        )
        .unwrap();
        let h = sink.handle();
        assert_eq!(h.delivered_through(), None);
        h.push(&cp(30));
        h.push_anchor(&anchor(20));
        h.push(&cp(31));
        wait_until(|| h.delivered() == 3);
        assert_eq!(*fake.got.lock().unwrap(), vec![30, 1020, 31]);
        assert_eq!(h.delivered_through(), Some(31));
        assert_eq!(sink.delivered_through(), Some(31));
        sink.shutdown(Duration::from_secs(1));
    }

    /// An anchor is never dropped from a full queue: the oldest checkpoint goes instead, and
    /// with only anchors queued the queue grows past its capacity. Delivery is told to the
    /// hook, and an anchor queued and not yet delivered is not queued twice.
    #[test]
    fn a_full_queue_keeps_the_anchor() {
        let fake = Arc::new(Fake::default());
        fake.fail.store(true, Ordering::SeqCst);
        let metrics = Metrics::new();
        let sink = CheckpointSink::with_deliver(
            Box::new(FakeRef(fake.clone())),
            limits(2, Duration::from_secs(3600)),
            None,
            metrics.clone(),
        )
        .unwrap();
        let delivered: Arc<Mutex<Vec<u64>>> = Arc::default();
        let seen = delivered.clone();
        sink.on_anchor_delivered(move |a| seen.lock().unwrap().push(a.through_seq));
        let h = sink.handle();
        h.push(&cp(1));
        wait_until(|| fake.attempts.load(Ordering::SeqCst) >= 1);
        // Seq 1 is in flight; the anchor is the oldest queued, then 2..=5 come.
        assert!(h.push_anchor(&anchor(20)));
        assert!(!h.push_anchor(&anchor(20)), "queued already");
        assert!(sink.anchor_pending(20));
        for s in 2..=5 {
            h.push(&cp(s));
        }
        assert_eq!(h.status().queued, 2);
        // Checkpoints 2, 3 and 4 were dropped; 5 goes for the next anchor, and with only
        // anchors queued the queue grows past its capacity rather than dropping one.
        assert!(h.push_anchor(&anchor(30)));
        assert!(h.push_anchor(&anchor(40)));
        assert_eq!(h.status().queued, 3);
        fake.fail.store(false, Ordering::SeqCst);
        wait_until(|| h.delivered() == 4);
        assert_eq!(*fake.got.lock().unwrap(), vec![1, 1020, 1030, 1040]);
        assert_eq!(*delivered.lock().unwrap(), vec![20, 30, 40]);
        assert!(!sink.anchor_pending(20));
        // Delivered: it can be queued again (a repeated prune of an anchor not yet recorded).
        assert!(h.push_anchor(&anchor(20)));
        assert!(metrics
            .render()
            .contains("attenuo_audit_sink_dropped_total 4\n"));
        sink.shutdown(Duration::from_secs(1));
    }

    /// The file sink writes an anchor as one more line, which `parse_shipped` skips and
    /// `parse_shipped_anchors` reads; S3 names it apart from the checkpoints.
    #[test]
    fn an_anchor_is_one_more_file_line_and_its_own_s3_object() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ckpt.jsonl");
        let d = FileDeliver::new(path.clone()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let a = Shipped::Anchor(ShippedAnchor::new(&anchor(20), None));
        for item in [
            Shipped::Checkpoint(ShippedCheckpoint::new(&cp(30), None)),
            a.clone(),
            Shipped::Checkpoint(ShippedCheckpoint::new(&cp(36), None)),
        ] {
            rt.block_on(d.deliver(&item)).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let cps = attenuo_audit::parse_shipped(&text).unwrap();
        assert_eq!(
            cps.iter().map(|c| c.checkpoint.seq).collect::<Vec<_>>(),
            [30, 36]
        );
        let anchors = attenuo_audit::parse_shipped_anchors(&text).unwrap();
        assert_eq!(anchors.len(), 1);
        assert_eq!((anchors[0].0, &anchors[0].1.anchor), (2, &anchor(20)));
        let s3 = S3Deliver::new(
            "http://127.0.0.1:9000".into(),
            "b".into(),
            "us-east-1".into(),
            "p/".into(),
            example_creds(),
            Duration::from_secs(1),
            &[],
        )
        .unwrap();
        let Shipped::Anchor(shipped) = &a else {
            unreachable!()
        };
        assert_eq!(
            s3.key(&a),
            format!("p/anchor-{:020}-{}.json", 20, &shipped.anchor_sha256[..16])
        );
        assert!(s3
            .key(&Shipped::Checkpoint(ShippedCheckpoint::new(&cp(30), None)))
            .starts_with("p/00000000000000000030-"));
    }

    #[test]
    fn a_full_queue_drops_the_oldest_counts_it_and_degrades() {
        let fake = Arc::new(Fake::default());
        fake.fail.store(true, Ordering::SeqCst);
        let metrics = Metrics::new();
        let sink = CheckpointSink::with_deliver(
            Box::new(FakeRef(fake.clone())),
            limits(2, Duration::from_secs(3600)),
            None,
            metrics.clone(),
        )
        .unwrap();
        let h = sink.handle();
        h.push(&cp(1));
        // Seq 1 is in flight (failing); 2 and 3 fill the queue; 4 and 5 push out 2 and 3.
        wait_until(|| fake.attempts.load(Ordering::SeqCst) >= 1);
        for s in 2..=5 {
            h.push(&cp(s));
        }
        let st = h.status();
        assert_eq!((st.queued, st.capacity), (2, 2));
        assert!(st.degraded, "a full queue is degraded");
        assert!(metrics
            .render()
            .contains("attenuo_audit_sink_dropped_total 2\n"));
        assert!(metrics
            .render()
            .contains("attenuo_audit_sink_queue_depth 2\n"));
        fake.fail.store(false, Ordering::SeqCst);
        wait_until(|| h.delivered() == 3);
        assert_eq!(*fake.got.lock().unwrap(), vec![1, 4, 5]);
        assert!(!h.status().degraded);
        sink.shutdown(Duration::from_secs(1));
    }

    #[test]
    fn degraded_once_failing_or_lagging_longer_than_max_lag() {
        let fake = Arc::new(Fake::default());
        fake.fail.store(true, Ordering::SeqCst);
        let sink = CheckpointSink::with_deliver(
            Box::new(FakeRef(fake.clone())),
            limits(100, Duration::from_millis(50)),
            None,
            Metrics::new(),
        )
        .unwrap();
        let h = sink.handle();
        assert!(!h.status().degraded, "idle is healthy");
        h.push(&cp(1));
        wait_until(|| fake.attempts.load(Ordering::SeqCst) >= 1);
        let now = Instant::now();
        assert!(
            !h.status_at(now).degraded,
            "a fresh failure is not yet degraded"
        );
        let later = h.status_at(now + Duration::from_millis(200));
        assert!(later.degraded);
        assert!(later.lag >= Duration::from_millis(200));
        assert!(later.failing_for.unwrap() > Duration::from_millis(50));
        fake.fail.store(false, Ordering::SeqCst);
        wait_until(|| h.delivered() == 1);
        assert!(
            !h.status_at(Instant::now() + Duration::from_secs(10))
                .degraded
        );
        drop(sink);
    }

    #[test]
    fn shutdown_gives_up_after_the_grace_period() {
        let fake = Arc::new(Fake::default());
        fake.fail.store(true, Ordering::SeqCst);
        let sink = CheckpointSink::with_deliver(
            Box::new(FakeRef(fake.clone())),
            SinkLimits {
                capacity: 4,
                max_lag: Duration::from_secs(1),
                backoff: Backoff {
                    initial: Duration::from_secs(30),
                    max: Duration::from_secs(30),
                },
            },
            None,
            Metrics::new(),
        )
        .unwrap();
        sink.handle().push(&cp(1));
        wait_until(|| fake.attempts.load(Ordering::SeqCst) >= 1);
        let started = Instant::now();
        sink.shutdown(Duration::from_millis(50));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a 30 s backoff does not hold up shutdown"
        );
    }

    #[derive(Debug)]
    struct Item(u64);

    impl QueueItem for Item {
        fn log_id(&self) -> String {
            format!("item {}", self.0)
        }
    }

    #[async_trait]
    impl Deliver<Item> for FakeRef {
        async fn deliver(&self, i: &Item) -> Result<(), String> {
            self.0.attempts.fetch_add(1, Ordering::SeqCst);
            if self.0.fail.load(Ordering::SeqCst) {
                return Err("down".into());
            }
            self.0.got.lock().unwrap().push(i.0);
            Ok(())
        }
    }

    /// The approval notifier's role: an item is dropped after `max_attempts`, counted under
    /// its own metrics, and the next one is delivered; the checkpoint series stay at zero.
    #[test]
    fn a_notice_queue_gives_up_after_max_attempts_and_moves_on() {
        let fake = Arc::new(Fake::default());
        fake.fail.store(true, Ordering::SeqCst);
        let metrics = Metrics::new();
        let q = Queue::start(
            Box::new(FakeRef(fake.clone())) as Box<dyn Deliver<Item>>,
            limits(16, Duration::from_secs(3600)),
            QueueRole::ApprovalNotices { max_attempts: 3 },
            metrics.clone(),
        )
        .unwrap();
        let h = q.handle();
        h.push(Item(1));
        h.push(Item(2));
        wait_until(|| {
            metrics
                .render()
                .contains("attenuo_approval_notify_dropped_total 2\n")
        });
        assert_eq!(fake.attempts.load(Ordering::SeqCst), 6);
        let st = h.status();
        assert_eq!(st.queued, 0);
        assert!(
            st.failing_for.is_some(),
            "still failing until a delivery succeeds"
        );
        fake.fail.store(false, Ordering::SeqCst);
        h.push(Item(3));
        wait_until(|| h.delivered() == 1);
        assert_eq!(*fake.got.lock().unwrap(), vec![3]);
        assert_eq!(h.status().failing_for, None);
        let text = metrics.render();
        assert!(text.contains("attenuo_approval_notify_failures_total 6\n"));
        assert!(text.contains("attenuo_approval_notify_delivered_total 1\n"));
        assert!(text.contains("attenuo_audit_sink_failures_total 0\n"));
        assert!(text.contains("attenuo_audit_sink_dropped_total 0\n"));
        q.shutdown(Duration::from_secs(1));
    }

    /// SR-94: a failed delivery's error, which `/readyz` and the retry log line print, names
    /// neither the sink URL's query (it may carry a credential) nor its path.
    #[test]
    fn a_failed_webhook_delivery_does_not_log_the_url_sr94() {
        let d = WebhookDeliver::new(
            "http://127.0.0.1:1/ingest/path-marker?token=secret-marker".into(),
            None,
            Duration::from_secs(2),
            &[],
        )
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(d.deliver(&Shipped::Checkpoint(ShippedCheckpoint::new(&cp(1), None))))
            .unwrap_err();
        assert!(err.starts_with("request failed"), "{err}");
        assert!(
            !err.contains("secret-marker") && !err.contains("path-marker"),
            "{err}"
        );
    }

    #[test]
    fn file_sink_appends_canonical_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ckpt.jsonl");
        let d = FileDeliver::new(path.clone()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for s in [1, 2] {
            rt.block_on(d.deliver(&Shipped::Checkpoint(ShippedCheckpoint::new(&cp(s), None))))
                .unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines = attenuo_audit::parse_shipped(&text).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].checkpoint, cp(2));
        assert!(FileDeliver::new(dir.path().join("no/such/dir/x.jsonl")).is_err());
    }

    fn example_creds() -> S3Credentials {
        S3Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    /// AWS's published example "GET Object" (Signature Version 4, header form, S3 docs
    /// "Examples of signature calculations").
    #[test]
    fn sigv4_matches_the_aws_get_object_example() {
        let empty = hex::encode(Sha256::digest(b""));
        let headers = vec![
            (
                "host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("range".to_string(), "bytes=0-9".to_string()),
            ("x-amz-content-sha256".to_string(), empty.clone()),
            ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
        ];
        let auth = sigv4_authorization(&SigV4Request {
            method: "GET",
            canonical_uri: "/test.txt",
            canonical_query: "",
            headers: &headers,
            payload_sha256: &empty,
            region: "us-east-1",
            service: "s3",
            amz_date: "20130524T000000Z",
            creds: &example_creds(),
        });
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// AWS's published example "PUT Object".
    #[test]
    fn sigv4_matches_the_aws_put_object_example() {
        let body_hash = hex::encode(Sha256::digest(b"Welcome to Amazon S3."));
        let headers = vec![
            (
                "date".to_string(),
                "Fri, 24 May 2013 00:00:00 GMT".to_string(),
            ),
            (
                "host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("x-amz-content-sha256".to_string(), body_hash.clone()),
            ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
            (
                "x-amz-storage-class".to_string(),
                "REDUCED_REDUNDANCY".to_string(),
            ),
        ];
        let auth = sigv4_authorization(&SigV4Request {
            method: "PUT",
            canonical_uri: &format!("/{}", uri_encode("test$file.text", false)),
            canonical_query: "",
            headers: &headers,
            payload_sha256: &body_hash,
            region: "us-east-1",
            service: "s3",
            amz_date: "20130524T000000Z",
            creds: &example_creds(),
        });
        assert!(
            auth.ends_with(
                "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
            ),
            "{auth}"
        );
    }

    /// The sink's PutObject carries the checksum headers an Object Lock bucket asks for
    /// (`x-amz-sdk-checksum-algorithm` with `x-amz-checksum-sha256`), and both are signed, in
    /// the canonical (sorted) order.
    #[test]
    fn the_put_object_canonical_request_signs_the_checksum_headers() {
        let body = b"Welcome to Amazon S3.";
        let digest = Sha256::digest(body);
        let headers = s3_put_headers(
            "127.0.0.1:9000".into(),
            &digest,
            "20130524T000000Z",
            Some("session-token"),
        );
        let payload_sha256 = hex::encode(digest);
        let r = SigV4Request {
            method: "PUT",
            canonical_uri: "/bucket/checkpoints/key.json",
            canonical_query: "",
            headers: &headers,
            payload_sha256: &payload_sha256,
            region: "us-east-1",
            service: "s3",
            amz_date: "20130524T000000Z",
            creds: &example_creds(),
        };
        let (canonical, signed) = sigv4_canonical_request(&r);
        let hex_hash = "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072";
        assert_eq!(hex::encode(digest), hex_hash);
        let b64 = "RM591nyVng01JP+sF3Hfu6h9K2tLTpnkIDSouAP4sHI=";
        assert_eq!(
            canonical,
            format!(
                "PUT\n/bucket/checkpoints/key.json\n\n\
                 content-type:application/json\n\
                 host:127.0.0.1:9000\n\
                 x-amz-checksum-sha256:{b64}\n\
                 x-amz-content-sha256:{hex_hash}\n\
                 x-amz-date:20130524T000000Z\n\
                 x-amz-sdk-checksum-algorithm:SHA256\n\
                 x-amz-security-token:session-token\n\n\
                 content-type;host;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date;\
                 x-amz-sdk-checksum-algorithm;x-amz-security-token\n\
                 {hex_hash}"
            )
        );
        assert_eq!(
            signed,
            "content-type;host;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date;\
             x-amz-sdk-checksum-algorithm;x-amz-security-token"
        );
        // The checksum is the standard (padded) base64 of the same SHA-256 as the hex.
        use base64::Engine as _;
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap(),
            digest.to_vec()
        );
        // Without STS credentials there is no token header, and the rest is unchanged.
        let plain = s3_put_headers("h".into(), &digest, "20130524T000000Z", None);
        assert_eq!(plain.len(), headers.len() - 1);
        assert!(plain.iter().all(|(k, _)| k != "x-amz-security-token"));
    }

    /// The signed `host` is the one reqwest sends: a default port (`:80` for http, `:443` for
    /// https) is not sent, so it must not be signed, or S3 answers 403 SignatureDoesNotMatch
    /// (seen against MinIO at `http://127.0.0.1:80`); the host is sent lowercased.
    #[test]
    fn signed_host_is_the_host_header_sent() {
        assert_eq!(signed_host("http://127.0.0.1:9000"), "127.0.0.1:9000");
        assert_eq!(signed_host("http://127.0.0.1:80"), "127.0.0.1");
        assert_eq!(
            signed_host("https://s3.eu-west-1.amazonaws.com:443"),
            "s3.eu-west-1.amazonaws.com"
        );
        assert_eq!(signed_host("http://minio:443"), "minio:443");
        assert_eq!(signed_host("https://S3.Example.com"), "s3.example.com");
        assert_eq!(signed_host("http://[::1]:9000"), "[::1]:9000");
        for endpoint in [
            "http://127.0.0.1:80",
            "https://S3.Example.com:443",
            "http://[::1]:9000",
            "http://minio:9000",
        ] {
            let url = reqwest::Url::parse(&format!("{endpoint}/bucket/key")).unwrap();
            let sent = match url.port() {
                Some(p) => format!("{}:{p}", url.host_str().unwrap()),
                None => url.host_str().unwrap().to_string(),
            };
            assert_eq!(signed_host(endpoint), sent, "{endpoint}");
        }
    }

    #[test]
    fn amz_date_and_uri_encoding() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_369_353_600);
        assert_eq!(amz_date(t), "20130524T000000Z");
        assert_eq!(uri_encode("a b/c~d$", false), "a%20b/c~d%24");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
    }

    #[test]
    fn config_validation_names_missing_and_foreign_fields() {
        let mut c = SinkSection::new(SinkKind::Webhook);
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("needs `url`"));
        c.url = Some("ftp://x".into());
        assert!(c.validate().is_err());
        c.url = Some("https://hooks.example/ckpt".into());
        c.validate().unwrap();
        c.path = Some("/x".into());
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not use path"));
        let mut s3 = SinkSection::new(SinkKind::S3);
        s3.endpoint = Some("https://s3.example/extra".into());
        s3.bucket = Some("b".into());
        assert!(s3
            .validate()
            .unwrap_err()
            .to_string()
            .contains("without a path"));
        s3.endpoint = Some("http://127.0.0.1:9000".into());
        s3.validate().unwrap();
        for ok in [
            "http://127.0.0.1:9000/",
            "https://s3.eu-west-1.amazonaws.com",
            "http://[::1]:9000",
            "https://S3.Example.com:443",
        ] {
            s3.endpoint = Some(ok.into());
            s3.validate().unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        let mut f = SinkSection::new(SinkKind::File);
        f.path = Some("/x".into());
        f.queue_capacity = 0;
        assert!(f.validate().is_err());
    }

    /// SR-119: an endpoint the URL parser reads with no host (`http://`), or with a path the
    /// string check missed (a backslash, which WHATWG reads as `/`), is refused at start. With
    /// `http://` the request URL `http:///<bucket>/<key>` parses with the bucket as its host,
    /// so the PUT, its signature and any session token went to whatever the bucket names, and
    /// the signed host (`""`) was not the one sent.
    #[test]
    fn an_s3_endpoint_the_url_parser_reads_differently_is_refused_sr119() {
        // What the parser does with the request URL such an endpoint makes.
        let u = reqwest::Url::parse("http:///evil.example/attenuo/checkpoints/k.json").unwrap();
        assert_eq!(u.host_str(), Some("evil.example"));
        let mut s3 = SinkSection::new(SinkKind::S3);
        s3.bucket = Some("evil.example".into());
        for bad in [
            "http://",
            "https://",
            "http:///",
            "http://minio:9000\\evil",
            "https://s3.example\\",
            "http://minio:9000\t",
        ] {
            s3.endpoint = Some(bad.into());
            let e = s3.validate().unwrap_err().to_string();
            assert!(e.contains("[audit.sink] endpoint"), "{bad}: {e}");
        }
        for bad in ["http://", "https://minio:9000\\evil"] {
            let e = S3Deliver::new(
                bad.into(),
                "evil.example".into(),
                "us-east-1".into(),
                "p/".into(),
                example_creds(),
                Duration::from_secs(1),
                &[],
            )
            .unwrap_err()
            .to_string();
            assert!(e.contains("endpoint"), "{bad}: {e}");
        }
        S3Deliver::new(
            "http://127.0.0.1:9000/".into(),
            "b".into(),
            "us-east-1".into(),
            "p/".into(),
            example_creds(),
            Duration::from_secs(1),
            &[],
        )
        .unwrap();
    }

    /// The `<Code>` of an S3 error answer is reported; anything that is not a short ASCII
    /// word is not, so a store cannot put its own text in the log.
    #[test]
    fn the_s3_error_code_is_read_from_the_answer() {
        let xml = |code: &str| {
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code>\
                 <Message>m</Message></Error>"
            )
        };
        for code in ["ExpiredToken", "InvalidTokenId", "SignatureDoesNotMatch"] {
            assert_eq!(
                s3_error_code_of(xml(code).as_bytes()).as_deref(),
                Some(code)
            );
        }
        for bad in ["", "two words", "x\nforged log line", &"A".repeat(65)] {
            assert_eq!(s3_error_code_of(xml(bad).as_bytes()), None, "{bad:?}");
        }
        assert_eq!(s3_error_code_of(b"<html>Forbidden</html>"), None);
        assert_eq!(s3_error_code_of(&[0xff, 0xfe]), None);
    }
}
