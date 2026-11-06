//! Prometheus metrics: hand-rolled counters and histograms, plus the text exposition writer.
//!
//! No dependency: a few atomics and two small maps behind mutexes. Label values come from
//! fixed sets (reason codes, route templates, status codes, limit kinds, approver kinds), so
//! cardinality stays bounded: nothing is labelled by lease, user, run or argument value.
//! The endpoint lives on its own listener (`[metrics] listen`), never on the proxy port.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use attenuo_audit::WalStats;
use attenuo_core::{LimitKind, OutputLabel};
use attenuo_proxy::guard::STREAM_END_TOOL;
use attenuo_proxy::records::is_lease_refusal_tool;
use attenuo_proxy::{Stage, StreamEndCause};
use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

/// Upper bounds (seconds) of the `authorize_duration_seconds` buckets.
pub const BUCKETS: [f64; 11] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
];

/// Upper bounds (seconds) of the `proxy_stage_seconds` buckets: 1 us to 1 s, five per decade,
/// fine enough to read a median off stages that take a few microseconds.
pub const STAGE_BUCKETS: [f64; 31] = [
    1e-6, 2e-6, 3e-6, 5e-6, 7e-6, 1e-5, 2e-5, 3e-5, 5e-5, 7e-5, 1e-4, 2e-4, 3e-4, 5e-4, 7e-4, 1e-3,
    2e-3, 3e-3, 5e-3, 7e-3, 1e-2, 2e-2, 3e-2, 5e-2, 7e-2, 0.1, 0.2, 0.3, 0.5, 0.7, 1.0,
];

const PREFIX: &str = "attenuo";

/// The `kind` label values of the run-limit series, in index order (see [`kind_index`]).
const LIMIT_KINDS: [LimitKind; 4] = [
    LimitKind::Calls,
    LimitKind::Sum,
    LimitKind::CallsPer,
    LimitKind::Distinct,
];

fn kind_index(kind: LimitKind) -> usize {
    match kind {
        LimitKind::Calls => 0,
        LimitKind::Sum => 1,
        LimitKind::CallsPer => 2,
        LimitKind::Distinct => 3,
    }
}

/// The `by` label values of the approval series, in index order.
const APPROVER_KINDS: [&str; 2] = ["user", "operator"];

fn approver_index(by: &str) -> Option<usize> {
    APPROVER_KINDS.iter().position(|k| *k == by)
}

/// Where a decision met an exhausted run limit (the `at` label of
/// `budget_exhausted_total`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExhaustedAt {
    /// The limit check before Cedar, on the counters as read.
    Check = 0,
    /// The store's re-check in the charge transaction: a concurrent call of the run spent the
    /// budget after this one read it.
    Charge = 1,
}

/// Who returned a run-limit charge (the `source` label of `budget_refunds_total`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundSource {
    /// `POST /admin/budgets/refund`.
    Operator = 0,
    /// The pipeline, because the allowed decision's record could not be written.
    AuditError = 1,
}

/// Reads the WAL checkpointer's counters at render time (see [`Metrics::set_wal_source`]).
struct WalSource(Box<dyn Fn() -> Option<WalStats> + Send + Sync>);

impl std::fmt::Debug for WalSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WalSource")
    }
}

/// All server metrics. Cheap to share: clone the `Arc`.
#[derive(Debug)]
pub struct Metrics {
    /// (decision, reason) -> count
    decisions: Mutex<BTreeMap<(String, String), u64>>,
    /// (route, status) -> count
    http: Mutex<BTreeMap<(String, u16), u64>>,
    tokens_root: AtomicU64,
    tokens_exchange: AtomicU64,
    leases_revoked: AtomicU64,
    /// Session bindings deleted by retention (`[leases] session_retention_seconds`).
    lease_sessions_pruned: AtomicU64,
    /// Leases deleted by retention (`[leases] retention_seconds`).
    leases_pruned: AtomicU64,
    /// Run state deleted by retention (`[leases] run_state_retention_seconds`), by
    /// [`RUN_STATE_KINDS`].
    run_state_pruned: [AtomicU64; 4],
    audit_append_errors: AtomicU64,
    audit_checkpoints: AtomicU64,
    /// `[audit.sink]` (SR-21): checkpoints delivered, delivery attempts that failed,
    /// checkpoints dropped from a full queue, the queue depth, and when the oldest undelivered
    /// checkpoint was queued (unix seconds, 0 when none).
    audit_sink_delivered: AtomicU64,
    audit_sink_failures: AtomicU64,
    audit_sink_dropped: AtomicU64,
    audit_sink_queue_depth: AtomicU64,
    audit_sink_oldest_unix: AtomicU64,
    /// `[approvals.notify]`: notifications delivered, delivery attempts that failed,
    /// notifications dropped (queue full, every attempt failed, or too many approvals waiting
    /// for their expiry), and the queue depth.
    approval_notify_delivered: AtomicU64,
    approval_notify_failures: AtomicU64,
    approval_notify_dropped: AtomicU64,
    approval_notify_queue_depth: AtomicU64,
    approval_notify_outbox_rows: AtomicU64,
    /// Time to decide one tool call.
    authorize: Histogram,
    /// Time for one audit append, lock wait and commit included.
    audit_append: Histogram,
    /// Per-stage time of proxied calls, indexed by [`Stage::index`].
    stages: [Histogram; Stage::ALL.len()],
    /// Unix time of the newest signed audit checkpoint this process wrote, 0 before the first.
    audit_checkpoint_last_unix: AtomicU64,
    /// Run limits (ADR-0010), by [`kind_index`]: limit counters charged by allowed calls,
    /// and `budget_exhausted` decisions by where the limit was met ([`ExhaustedAt`]).
    budget_charges: [AtomicU64; 4],
    budget_exhausted: [[AtomicU64; 2]; 4],
    /// Charges returned, by [`RefundSource`].
    budget_refunds: [AtomicU64; 2],
    /// Approvals (ADR-0009): pending approvals stored, decided by (outcome granted/declined,
    /// approver kind), consumed by approver kind, and refused because they had expired.
    approvals_created: AtomicU64,
    approvals_decided: [[AtomicU64; 2]; 2],
    approvals_consumed: [AtomicU64; 2],
    approvals_expired: AtomicU64,
    /// Output labelling (ADR-0009): results recorded, by label (trusted, untrusted), and
    /// decisions on calls whose arguments matched the run's span index (calls the server
    /// matches: destructive ones, or every call when a policy reads argument taint), by
    /// decision (allow, deny).
    results_recorded: [AtomicU64; 2],
    taint_matches: [AtomicU64; 2],
    /// SR-55: time to acquire a run's lock, observed once per guarded decision (its count is
    /// the guarded decisions).
    run_lock_wait: Histogram,
    /// The background WAL checkpointer of the audit store, when there is one.
    wal: OnceLock<WalSource>,
    /// `GET` listen streams ended, by [`StreamEndCause::index`].
    streams_ended: [AtomicU64; StreamEndCause::ALL.len()],
    /// `stream.end` records not written, by [`StreamEndCause::index`] of the reason (only the
    /// [`StreamEndCause::RECORDED`] ones, which lead the list).
    stream_end_suppressed: [AtomicU64; StreamEndCause::RECORDED.len()],
    /// Lease-refusal records of undecided requests not written, by (tool, index of the
    /// reason). Tools come from a fixed set ([`is_lease_refusal_tool`]), so the map stays
    /// small; a series appears once counted.
    lease_refusal_suppressed: Mutex<BTreeMap<(String, usize), u64>>,
    /// `tools/list` entries the list screen hid (ADR-0011), by [`LIST_HIDE_REASONS`] index.
    list_entries_hidden: [AtomicU64; LIST_HIDE_REASONS.len()],
}

/// The reasons of `proxy_list_entries_hidden_total`, the list screen's hide reasons.
pub const LIST_HIDE_REASONS: [&str; 3] = [
    attenuo_policy::HIDE_POLICY,
    attenuo_policy::HIDE_NOT_IN_CATALOG,
    attenuo_policy::HIDE_INVALID_NAME,
];

impl Default for Metrics {
    fn default() -> Self {
        Self {
            decisions: Mutex::default(),
            http: Mutex::default(),
            tokens_root: AtomicU64::default(),
            tokens_exchange: AtomicU64::default(),
            leases_revoked: AtomicU64::default(),
            lease_sessions_pruned: AtomicU64::default(),
            leases_pruned: AtomicU64::default(),
            run_state_pruned: Default::default(),
            audit_append_errors: AtomicU64::default(),
            audit_checkpoints: AtomicU64::default(),
            audit_sink_delivered: AtomicU64::default(),
            audit_sink_failures: AtomicU64::default(),
            audit_sink_dropped: AtomicU64::default(),
            audit_sink_queue_depth: AtomicU64::default(),
            audit_sink_oldest_unix: AtomicU64::default(),
            approval_notify_delivered: AtomicU64::default(),
            approval_notify_failures: AtomicU64::default(),
            approval_notify_dropped: AtomicU64::default(),
            approval_notify_queue_depth: AtomicU64::default(),
            approval_notify_outbox_rows: AtomicU64::default(),
            authorize: Histogram::new(&BUCKETS),
            audit_append: Histogram::new(&BUCKETS),
            stages: std::array::from_fn(|_| Histogram::new(&STAGE_BUCKETS)),
            audit_checkpoint_last_unix: AtomicU64::default(),
            budget_charges: Default::default(),
            budget_exhausted: Default::default(),
            budget_refunds: Default::default(),
            approvals_created: AtomicU64::default(),
            approvals_decided: Default::default(),
            approvals_consumed: Default::default(),
            approvals_expired: AtomicU64::default(),
            results_recorded: Default::default(),
            taint_matches: Default::default(),
            run_lock_wait: Histogram::new(&STAGE_BUCKETS),
            wal: OnceLock::new(),
            streams_ended: Default::default(),
            stream_end_suppressed: Default::default(),
            lease_refusal_suppressed: Mutex::default(),
            list_entries_hidden: Default::default(),
        }
    }
}

/// A fixed-bucket histogram.
#[derive(Debug)]
struct Histogram {
    /// Upper bounds, ascending.
    bounds: &'static [f64],
    /// Non-cumulative per-bucket counts; the last slot is `+Inf`.
    buckets: Box<[AtomicU64]>,
    nanos: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn new(bounds: &'static [f64]) -> Self {
        Self {
            bounds,
            buckets: (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect(),
            nanos: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        let i = self
            .bounds
            .iter()
            .position(|b| secs <= *b)
            .unwrap_or(self.bounds.len());
        self.buckets[i].fetch_add(1, Ordering::Relaxed);
        let nanos = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        self.nanos.fetch_add(nanos, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String, name: &str, help: &str) {
        header_lines(out, name, help, "histogram");
        self.render_samples(out, name, "");
    }

    /// The `_bucket`, `_sum` and `_count` lines. `labels` is empty or `key="value",` pairs,
    /// each followed by a comma, placed before `le`.
    fn render_samples(&self, out: &mut String, name: &str, labels: &str) {
        let mut cumulative = 0;
        for (i, bound) in self.bounds.iter().enumerate() {
            cumulative += self.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{PREFIX}_{name}_bucket{{{labels}le=\"{bound}\"}} {cumulative}"
            );
        }
        cumulative += self.buckets[self.bounds.len()].load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "{PREFIX}_{name}_bucket{{{labels}le=\"+Inf\"}} {cumulative}"
        );
        let braced = labels
            .strip_suffix(',')
            .map(|l| format!("{{{l}}}"))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "{PREFIX}_{name}_sum{braced} {}",
            self.nanos.load(Ordering::Relaxed) as f64 / 1e9
        );
        let _ = writeln!(
            out,
            "{PREFIX}_{name}_count{braced} {}",
            self.count.load(Ordering::Relaxed)
        );
    }
}

/// Which kind of token was issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// A hop-0 token: IdP intake or the dev root mint (`kind="root"`).
    Root,
    /// A token exchanged from a parent (`kind="exchange"`).
    Exchange,
}

impl Metrics {
    /// A fresh set of metrics with every counter at zero, shared by the pipeline, the routes
    /// and the background tasks of one server.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Count one decision record (`decision` is `allow` or `deny`): a pipeline decision or a
    /// recorded proxy refusal.
    pub fn decision(&self, decision: &str, reason: &str) {
        if let Ok(mut m) = self.decisions.lock() {
            *m.entry((decision.to_string(), reason.to_string()))
                .or_default() += 1;
        }
    }

    /// Count one issued token in `tokens_issued_total`.
    pub fn token_issued(&self, kind: TokenKind) {
        let c = match kind {
            TokenKind::Root => &self.tokens_root,
            TokenKind::Exchange => &self.tokens_exchange,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// Count leases that changed to revoked.
    pub fn leases_revoked(&self, n: u64) {
        self.leases_revoked.fetch_add(n, Ordering::Relaxed);
    }

    /// Count session bindings deleted by retention.
    pub fn lease_sessions_pruned(&self, n: u64) {
        self.lease_sessions_pruned.fetch_add(n, Ordering::Relaxed);
    }

    /// Count leases deleted by retention.
    pub fn leases_pruned(&self, n: u64) {
        self.leases_pruned.fetch_add(n, Ordering::Relaxed);
    }

    /// Count run state deleted by retention: counters, charge-log entries, approvals.
    pub fn run_state_pruned(&self, counters: u64, charges: u64, approvals: u64) {
        for (c, n) in self
            .run_state_pruned
            .iter()
            .zip([counters, charges, approvals])
        {
            c.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Count per-user window rows (windows and their charges) deleted by
    /// `[leases] user_window_retention_seconds`, as `run_state_pruned_total{kind="user_window"}`.
    pub fn user_windows_pruned(&self, n: u64) {
        self.run_state_pruned[3].fetch_add(n, Ordering::Relaxed);
    }

    /// Count one failed audit append (`audit_append_errors_total`).
    pub fn audit_append_error(&self) {
        self.audit_append_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one HTTP response by route template (`unmatched` for none) and status code.
    pub fn http_request(&self, route: &str, status: u16) {
        if let Ok(mut m) = self.http.lock() {
            *m.entry((route.to_string(), status)).or_default() += 1;
        }
    }

    /// Record how long one authorization decision took.
    pub fn observe_authorize(&self, d: Duration) {
        self.authorize.observe(d);
    }

    /// Record how long one audit append took, from asking for the store's lock to the commit
    /// (failed appends included).
    pub fn observe_audit_append(&self, d: Duration) {
        self.audit_append.observe(d);
    }

    /// Run an audit append and record its duration.
    pub fn time_audit_append<R>(&self, append: impl FnOnce() -> R) -> R {
        let started = std::time::Instant::now();
        let out = append();
        self.observe_audit_append(started.elapsed());
        out
    }

    /// Record how long one stage of a proxied call took (see [`Stage`]).
    pub fn observe_stage(&self, stage: Stage, d: Duration) {
        self.stages[stage.index()].observe(d);
    }

    /// Count one signed audit checkpoint, written now.
    pub fn audit_checkpoint(&self) {
        self.audit_checkpoints.fetch_add(1, Ordering::Relaxed);
        self.audit_checkpoint_last_unix
            .store(unix_secs(std::time::SystemTime::now()), Ordering::Relaxed);
    }

    /// Read the audit store's WAL checkpointer through `source` at every render. Set once;
    /// later calls are ignored. `source` returns `None` when no checkpointer runs, and the WAL
    /// series are then left out.
    pub fn set_wal_source(&self, source: impl Fn() -> Option<WalStats> + Send + Sync + 'static) {
        let _ = self.wal.set(WalSource(Box::new(source)));
    }

    /// Count one run-limit counter charged by an allowed call (ADR-0010).
    pub fn budget_charged(&self, kind: LimitKind) {
        self.budget_charges[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    /// Count one `budget_exhausted` decision: the limit kind that was hit and where.
    pub fn budget_exhausted(&self, kind: LimitKind, at: ExhaustedAt) {
        self.budget_exhausted[kind_index(kind)][at as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Count one decision's charge returned to the run-limit counters.
    pub fn budget_refunded(&self, source: RefundSource) {
        self.budget_refunds[source as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Count one pending approval stored (a repeated gated call that finds the pending one
    /// does not count).
    pub fn approval_created(&self) {
        self.approvals_created.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one approval granted or declined, by `by` (`user` or `operator`; anything else
    /// is not counted).
    pub fn approval_decided(&self, granted: bool, by: &str) {
        if let Some(i) = approver_index(by) {
            self.approvals_decided[usize::from(!granted)][i].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count one granted approval consumed by an allowed call, by who granted it.
    pub fn approval_consumed(&self, by: &str) {
        if let Some(i) = approver_index(by) {
            self.approvals_consumed[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count one attempt to decide or use an approval that had expired (expiry is not a
    /// state: an approval that lapses unseen is not counted).
    pub fn approval_expired(&self) {
        self.approvals_expired.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one tool result recorded, by its output label.
    pub fn result_recorded(&self, label: OutputLabel) {
        let i = usize::from(label == OutputLabel::Untrusted);
        self.results_recorded[i].fetch_add(1, Ordering::Relaxed);
    }

    /// Count one decision on a call with an argument that matched the run's span index (or
    /// could not be checked against it); see `Pipeline::arg_taint` for which calls are matched.
    pub fn taint_match(&self, allowed: bool) {
        self.taint_matches[usize::from(!allowed)].fetch_add(1, Ordering::Relaxed);
    }

    /// Record how long a guarded decision waited for its run's lock (SR-55).
    pub fn observe_run_lock_wait(&self, d: Duration) {
        self.run_lock_wait.observe(d);
    }

    /// Count one checkpoint delivered by `[audit.sink]`.
    pub fn audit_sink_delivered(&self) {
        self.audit_sink_delivered.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one failed delivery attempt (it is retried).
    pub fn audit_sink_failure(&self) {
        self.audit_sink_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one checkpoint dropped from a full sink queue.
    pub fn audit_sink_dropped(&self) {
        self.audit_sink_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Set the sink queue gauges: queued checkpoints, and when the oldest undelivered one
    /// (queued or in flight) was queued.
    pub fn audit_sink_queue(&self, depth: u64, oldest: Option<std::time::SystemTime>) {
        self.audit_sink_queue_depth.store(depth, Ordering::Relaxed);
        self.audit_sink_oldest_unix
            .store(oldest.map_or(0, unix_secs), Ordering::Relaxed);
    }

    /// Count one approval notification delivered by `[approvals.notify]`.
    pub fn approval_notify_delivered(&self) {
        self.approval_notify_delivered
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Count one failed notification delivery attempt.
    pub fn approval_notify_failure(&self) {
        self.approval_notify_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Count one approval notification that will not be delivered.
    pub fn approval_notify_dropped(&self) {
        self.approval_notify_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Set the notification queue depth gauge.
    pub fn approval_notify_queue(&self, depth: u64) {
        self.approval_notify_queue_depth
            .store(depth, Ordering::Relaxed);
    }

    /// Set the open outbox rows gauge (at start, from the table).
    pub fn approval_notify_outbox_rows(&self, rows: u64) {
        self.approval_notify_outbox_rows
            .store(rows, Ordering::Relaxed);
    }

    /// One notice stored in the outbox.
    pub fn approval_notify_outbox_opened(&self) {
        self.approval_notify_outbox_rows
            .fetch_add(1, Ordering::Relaxed);
    }

    /// One outbox row marked delivered or given up.
    pub fn approval_notify_outbox_closed(&self) {
        // A compare-and-swap loop that stops at zero (`fetch_update` is deprecated on newer
        // toolchains, `try_update` is too new for the MSRV).
        let rows = &self.approval_notify_outbox_rows;
        let mut n = rows.load(Ordering::Relaxed);
        while n > 0 {
            match rows.compare_exchange_weak(n, n - 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(now) => n = now,
            }
        }
    }

    /// Prometheus text exposition format (version 0.0.4).
    pub fn render(&self) -> String {
        let mut out = String::new();
        header_lines(
            &mut out,
            "decisions_total",
            "Decision records by outcome and reason code: pipeline decisions (MCP proxy and \
             AuthZEN), requests the proxy refused and recorded before a decision, \
             streams the proxy ended on revocation or expiry, and \
             refused token exchanges and lease renewals whose token verified. \
             Unauthenticated requests \
             are not counted.",
            "counter",
        );
        if let Ok(m) = self.decisions.lock() {
            for ((decision, reason), n) in m.iter() {
                let _ = writeln!(
                    out,
                    "{PREFIX}_decisions_total{{decision=\"{}\",reason=\"{}\"}} {n}",
                    escape(decision),
                    escape(reason)
                );
            }
        }
        header_lines(
            &mut out,
            "tokens_issued_total",
            "Delegation tokens issued, by kind.",
            "counter",
        );
        for (kind, c) in [
            ("root", &self.tokens_root),
            ("exchange", &self.tokens_exchange),
        ] {
            let _ = writeln!(
                out,
                "{PREFIX}_tokens_issued_total{{kind=\"{kind}\"}} {}",
                c.load(Ordering::Relaxed)
            );
        }
        simple_counter(
            &mut out,
            "leases_revoked_total",
            "Leases moved to revoked, including cascaded descendants.",
            &self.leases_revoked,
        );
        simple_counter(
            &mut out,
            "lease_sessions_pruned_total",
            "Session bindings (revoke by session) deleted because their chain was revoked or \
             expired longer ago than the retention period.",
            &self.lease_sessions_pruned,
        );
        simple_counter(
            &mut out,
            "leases_pruned_total",
            "Leases deleted from the registry because every lease of their chain was revoked or \
             expired longer ago than the retention period.",
            &self.leases_pruned,
        );
        header_lines(
            &mut out,
            "run_state_pruned_total",
            "Run-limit counters, charge-log entries and approvals deleted because their run's \
             leases were gone from the registry and the state was older than the retention \
             period, and per-user window rows deleted once their window had ended longer ago \
             than its retention.",
            "counter",
        );
        for (kind, c) in RUN_STATE_KINDS.iter().zip(&self.run_state_pruned) {
            let _ = writeln!(
                out,
                "{PREFIX}_run_state_pruned_total{{kind=\"{kind}\"}} {}",
                c.load(Ordering::Relaxed)
            );
        }
        simple_counter(
            &mut out,
            "audit_append_errors_total",
            "Audit log appends that failed.",
            &self.audit_append_errors,
        );
        simple_counter(
            &mut out,
            "audit_checkpoints_total",
            "Signed audit checkpoints written.",
            &self.audit_checkpoints,
        );
        simple_gauge(
            &mut out,
            "audit_checkpoint_last_timestamp_seconds",
            "Unix time the newest signed audit checkpoint was written by this process; 0 when \
             none.",
            &self.audit_checkpoint_last_unix,
        );
        if let Some(stats) = self.wal.get().and_then(|w| (w.0)()) {
            render_wal(&mut out, &stats);
        }
        simple_counter(
            &mut out,
            "audit_sink_delivered_total",
            "Signed audit checkpoints delivered off the host by [audit.sink].",
            &self.audit_sink_delivered,
        );
        simple_counter(
            &mut out,
            "audit_sink_failures_total",
            "Checkpoint deliveries by [audit.sink] that failed and will be retried.",
            &self.audit_sink_failures,
        );
        simple_counter(
            &mut out,
            "audit_sink_dropped_total",
            "Checkpoints dropped from a full [audit.sink] queue before delivery.",
            &self.audit_sink_dropped,
        );
        simple_gauge(
            &mut out,
            "audit_sink_queue_depth",
            "Checkpoints waiting in the [audit.sink] queue.",
            &self.audit_sink_queue_depth,
        );
        simple_gauge(
            &mut out,
            "audit_sink_oldest_undelivered_timestamp_seconds",
            "Unix time the oldest undelivered checkpoint was queued; 0 when none.",
            &self.audit_sink_oldest_unix,
        );
        simple_counter(
            &mut out,
            "approval_notify_delivered_total",
            "Approval notifications delivered by [approvals.notify].",
            &self.approval_notify_delivered,
        );
        simple_counter(
            &mut out,
            "approval_notify_failures_total",
            "Approval notification deliveries that failed (retried until max_attempts).",
            &self.approval_notify_failures,
        );
        simple_counter(
            &mut out,
            "approval_notify_dropped_total",
            "Approval notifications not delivered: queue full, every attempt failed, or too \
             many approvals waiting for their expiry.",
            &self.approval_notify_dropped,
        );
        simple_gauge(
            &mut out,
            "approval_notify_queue_depth",
            "Approval notifications waiting in the [approvals.notify] queue.",
            &self.approval_notify_queue_depth,
        );
        simple_gauge(
            &mut out,
            "approval_notify_outbox_rows",
            "Approval notifications stored in the outbox and not yet delivered or given up.",
            &self.approval_notify_outbox_rows,
        );
        header_lines(
            &mut out,
            "http_requests_total",
            "HTTP requests by route template and status.",
            "counter",
        );
        if let Ok(m) = self.http.lock() {
            for ((route, status), n) in m.iter() {
                let _ = writeln!(
                    out,
                    "{PREFIX}_http_requests_total{{route=\"{}\",status=\"{status}\"}} {n}",
                    escape(route)
                );
            }
        }
        self.authorize.render(
            &mut out,
            "authorize_duration_seconds",
            "Time to decide one tool call (leases, labels, run limits, run lock, approval, \
             policy, charge, audit append).",
        );
        self.audit_append.render(
            &mut out,
            "audit_append_duration_seconds",
            "Time for one audit log append, including waiting for the store's lock.",
        );
        header_lines(
            &mut out,
            "proxy_stage_seconds",
            "Time spent in each stage of a proxied call (token verification, lease check, \
             policy, audit append, blocking-pool hop, upstream round trip, response handling, \
             total).",
            "histogram",
        );
        for stage in Stage::ALL {
            self.stages[stage.index()].render_samples(
                &mut out,
                "proxy_stage_seconds",
                &format!("stage=\"{}\",", stage.as_str()),
            );
        }
        self.render_limits_approvals_labels(&mut out);
        self.run_lock_wait.render(
            &mut out,
            "run_lock_wait_seconds",
            "Time a decision waited for its delegation run's lock (SR-55); only decisions whose \
             policy input includes run limits or run usage take it.",
        );
        self.render_stream_ends(&mut out);
        self.render_list_screen(&mut out);
        out
    }

    fn render_limits_approvals_labels(&self, out: &mut String) {
        header_lines(
            out,
            "budget_charges_total",
            "Run-limit counters charged by allowed calls, by limit kind (one per matching \
             limit in every hop).",
            "counter",
        );
        for kind in LIMIT_KINDS {
            let n = self.budget_charges[kind_index(kind)].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{PREFIX}_budget_charges_total{{kind=\"{}\"}} {n}",
                kind.as_str()
            );
        }
        header_lines(
            out,
            "budget_exhausted_total",
            "Calls denied with budget_exhausted, by the limit kind hit and where: check (the \
             counters as read) or charge (spent by a concurrent call of the run).",
            "counter",
        );
        for kind in LIMIT_KINDS {
            for (at, name) in ["check", "charge"].iter().enumerate() {
                let n = self.budget_exhausted[kind_index(kind)][at].load(Ordering::Relaxed);
                let _ = writeln!(
                    out,
                    "{PREFIX}_budget_exhausted_total{{kind=\"{}\",at=\"{name}\"}} {n}",
                    kind.as_str()
                );
            }
        }
        header_lines(
            out,
            "budget_refunds_total",
            "Decisions whose run-limit charge was returned, by source: operator (POST \
             /admin/budgets/refund) or audit_error (the decision could not be recorded).",
            "counter",
        );
        for (i, source) in ["operator", "audit_error"].iter().enumerate() {
            let n = self.budget_refunds[i].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{PREFIX}_budget_refunds_total{{source=\"{source}\"}} {n}"
            );
        }
        simple_counter(
            out,
            "approvals_created_total",
            "Pending approvals stored for approval_required calls.",
            &self.approvals_created,
        );
        header_lines(
            out,
            "approvals_decided_total",
            "Approvals granted or declined, by outcome and approver kind.",
            "counter",
        );
        for (o, outcome) in ["granted", "declined"].iter().enumerate() {
            for (i, by) in APPROVER_KINDS.iter().enumerate() {
                let n = self.approvals_decided[o][i].load(Ordering::Relaxed);
                let _ = writeln!(
                    out,
                    "{PREFIX}_approvals_decided_total{{outcome=\"{outcome}\",by=\"{by}\"}} {n}"
                );
            }
        }
        header_lines(
            out,
            "approvals_consumed_total",
            "Granted approvals spent by the allowed call they were for, by approver kind.",
            "counter",
        );
        for (i, by) in APPROVER_KINDS.iter().enumerate() {
            let n = self.approvals_consumed[i].load(Ordering::Relaxed);
            let _ = writeln!(out, "{PREFIX}_approvals_consumed_total{{by=\"{by}\"}} {n}");
        }
        simple_counter(
            out,
            "approvals_expired_total",
            "Attempts to grant, decline or present an approval that had expired.",
            &self.approvals_expired,
        );
        header_lines(
            out,
            "results_recorded_total",
            "Tool results recorded after an allowed call, by output label; untrusted ones \
             label the run.",
            "counter",
        );
        for (i, label) in ["trusted", "untrusted"].iter().enumerate() {
            let n = self.results_recorded[i].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{PREFIX}_results_recorded_total{{label=\"{label}\"}} {n}"
            );
        }
        header_lines(
            out,
            "taint_matches_total",
            "Decisions on calls with an argument found in the run's untrusted results (or not \
             checkable), by decision.",
            "counter",
        );
        for (i, decision) in ["allow", "deny"].iter().enumerate() {
            let n = self.taint_matches[i].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{PREFIX}_taint_matches_total{{decision=\"{decision}\"}} {n}"
            );
        }
    }
}

/// The WAL checkpointer's series.
fn render_wal(out: &mut String, s: &WalStats) {
    header_lines(
        out,
        "audit_wal_checkpoints_total",
        "Background WAL checkpoint rounds, by result: complete (nothing left in the WAL), \
         incomplete (frames left behind) or error.",
        "counter",
    );
    for (result, n) in [
        ("complete", s.rounds_complete),
        ("incomplete", s.rounds_incomplete),
        ("error", s.round_errors),
    ] {
        let _ = writeln!(
            out,
            "{PREFIX}_audit_wal_checkpoints_total{{result=\"{result}\"}} {n}"
        );
    }
    let counter = |out: &mut String, name: &str, help: &str, n: u64| {
        header_lines(out, name, help, "counter");
        let _ = writeln!(out, "{PREFIX}_{name} {n}");
    };
    counter(
        out,
        "audit_wal_locked_passes_total",
        "WAL catch-up passes run holding the store's lock (each pauses appends briefly).",
        s.locked_passes,
    );
    counter(
        out,
        "audit_wal_backstops_total",
        "WAL checkpoints the audit writer ran itself because the WAL outgrew the backstop.",
        s.backstops,
    );
    header_lines(
        out,
        "audit_wal_presyncs_total",
        "Syncs run off the request path: wal (ahead of a signed checkpoint) or db (before a \
         locked pass).",
        "counter",
    );
    for (file, n) in [("wal", s.wal_presyncs), ("db", s.db_presyncs)] {
        let _ = writeln!(
            out,
            "{PREFIX}_audit_wal_presyncs_total{{file=\"{file}\"}} {n}"
        );
    }
    let gauge = |out: &mut String, name: &str, help: &str, n: u64| {
        header_lines(out, name, help, "gauge");
        let _ = writeln!(out, "{PREFIX}_{name} {n}");
    };
    gauge(
        out,
        "audit_wal_frames",
        "Frames in the WAL at the last checkpoint pass.",
        s.wal_frames,
    );
    gauge(
        out,
        "audit_wal_last_complete_timestamp_seconds",
        "Unix time the last complete WAL checkpoint round finished; 0 before the first.",
        s.last_complete_unix,
    );
}

/// Unix seconds, at least 1 (0 is the gauges' "none").
fn unix_secs(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().max(1))
}

fn header_lines(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {PREFIX}_{name} {help}");
    let _ = writeln!(out, "# TYPE {PREFIX}_{name} {kind}");
}

/// The `kind` label values of `run_state_pruned_total`, in [`Metrics::run_state_pruned`]'s
/// argument order, then `user_window` ([`Metrics::user_windows_pruned`]).
pub const RUN_STATE_KINDS: [&str; 4] = ["counters", "charges", "approvals", "user_window"];

fn simple_counter(out: &mut String, name: &str, help: &str, c: &AtomicU64) {
    header_lines(out, name, help, "counter");
    let _ = writeln!(out, "{PREFIX}_{name} {}", c.load(Ordering::Relaxed));
}

fn simple_gauge(out: &mut String, name: &str, help: &str, c: &AtomicU64) {
    header_lines(out, name, help, "gauge");
    let _ = writeln!(out, "{PREFIX}_{name} {}", c.load(Ordering::Relaxed));
}

/// Escape a label value: backslash, double quote and newline.
fn escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Check `text` against the Prometheus text exposition format 0.0.4, as far as the server
/// uses it: `# HELP` and `# TYPE` lines, one `# TYPE` per family placed before its samples,
/// valid metric and label names, quoted label values with only `\\`, `\"` and `\n`
/// escapes, no repeated series, a numeric value on every sample, and histogram samples only
/// as `_bucket` (with `le`), `_sum` and `_count`. `Err` names the first offending line. For
/// tests.
#[doc(hidden)]
pub fn check_text_format(text: &str) -> Result<(), String> {
    use std::collections::{BTreeSet, HashMap};
    fn valid_name(n: &str, colon: bool) -> bool {
        let mut chars = n.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || (colon && c == ':'))
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || (colon && c == ':'))
    }
    let mut types: HashMap<String, String> = HashMap::new();
    let mut helps: BTreeSet<String> = BTreeSet::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    if !text.is_empty() && !text.ends_with('\n') {
        return Err("the text does not end with a newline".into());
    }
    for (i, line) in text.lines().enumerate() {
        let bad = |why: &str| Err(format!("line {}: {why}: {line}", i + 1));
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# ") {
            let mut parts = rest.splitn(3, ' ');
            let (kw, name, tail) = (parts.next(), parts.next(), parts.next());
            let Some(name) = name.filter(|n| valid_name(n, true)) else {
                return bad("bad metric name in a comment");
            };
            match kw {
                Some("HELP") => {
                    if !helps.insert(name.to_string()) {
                        return bad("second HELP for a family");
                    }
                }
                Some("TYPE") => {
                    let kind = tail.unwrap_or_default();
                    if !["counter", "gauge", "histogram", "summary", "untyped"].contains(&kind) {
                        return bad("unknown type");
                    }
                    if types.insert(name.to_string(), kind.to_string()).is_some() {
                        return bad("second TYPE for a family");
                    }
                }
                _ => {}
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let (series, value) = match line.rsplit_once(' ') {
            Some(v) => v,
            None => return bad("no value"),
        };
        if value.parse::<f64>().is_err() && !["+Inf", "-Inf", "NaN"].contains(&value) {
            return bad("value is not a number");
        }
        let (name, labels) = match series.split_once('{') {
            Some((n, l)) => match l.strip_suffix('}') {
                Some(l) => (n, l),
                None => return bad("unclosed label set"),
            },
            None => (series, ""),
        };
        if !valid_name(name, true) {
            return bad("bad metric name");
        }
        let mut label_names = Vec::new();
        let mut rest = labels;
        while !rest.is_empty() {
            let Some((lname, after)) = rest.split_once("=\"") else {
                return bad("label without a quoted value");
            };
            if !valid_name(lname, false) || label_names.contains(&lname) {
                return bad("bad or repeated label name");
            }
            label_names.push(lname);
            let mut end = None;
            let mut escaped = false;
            for (j, c) in after.char_indices() {
                match (escaped, c) {
                    (true, '\\' | '"' | 'n') => escaped = false,
                    (true, _) => return bad("bad escape in a label value"),
                    (false, '\\') => escaped = true,
                    (false, '"') => {
                        end = Some(j);
                        break;
                    }
                    (false, _) => {}
                }
            }
            let Some(end) = end else {
                return bad("unterminated label value");
            };
            rest = &after[end + 1..];
            if let Some(r) = rest.strip_prefix(',') {
                rest = r;
            } else if !rest.is_empty() {
                return bad("labels not separated by commas");
            }
        }
        let family = match types.get(name) {
            Some(_) => name,
            None => {
                let base = ["_bucket", "_sum", "_count"]
                    .iter()
                    .find_map(|s| name.strip_suffix(s))
                    .filter(|b| types.get(*b).is_some_and(|t| t == "histogram"));
                match base {
                    Some(b) => b,
                    None => return bad("sample before its TYPE line"),
                }
            }
        };
        if types[family] == "histogram" {
            if name == family {
                return bad("histogram sample without _bucket, _sum or _count");
            }
            if name.ends_with("_bucket") != label_names.contains(&"le") {
                return bad("le belongs on _bucket samples only");
            }
        }
        if !seen.insert(series.to_string()) {
            return bad("repeated series");
        }
    }
    Ok(())
}

/// A router serving `GET /metrics` for `metrics`. Mount it on its own listener.
pub fn router(metrics: Arc<Metrics>) -> Router {
    Router::new()
        .route("/metrics", get(handler))
        .with_state(metrics)
}

async fn handler(State(metrics): State<Arc<Metrics>>) -> Response {
    let mut res = metrics.render().into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    res
}

/// Middleware counting every response by matched route template and status.
pub async fn track_http(State(metrics): State<Arc<Metrics>>, req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_string(), |p| p.as_str().to_string());
    let res = next.run(req).await;
    metrics.http_request(&route, res.status().as_u16());
    res
}

/// The proxy's listen-stream endings and the `stream.end` records it did not write.
impl Metrics {
    /// Count one `GET` listen stream that ended, by cause.
    pub fn stream_ended(&self, cause: StreamEndCause) {
        self.streams_ended[cause.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Count one audit record not written because an earlier one of the same chain, tool and
    /// reason stands for it: a `stream.end` of a listen stream, or a lease refusal of an
    /// undecided request (a tool of [`is_lease_refusal_tool`]), with a recorded reason.
    /// Anything else is ignored, so the label set stays fixed.
    pub fn record_suppressed(&self, tool: &str, reason: StreamEndCause) {
        if !StreamEndCause::RECORDED.contains(&reason) {
            return;
        }
        if tool == STREAM_END_TOOL {
            self.stream_end_suppressed[reason.index()].fetch_add(1, Ordering::Relaxed);
        } else if is_lease_refusal_tool(tool) {
            if let Ok(mut map) = self.lease_refusal_suppressed.lock() {
                *map.entry((tool.to_owned(), reason.index())).or_default() += 1;
            }
        }
    }

    /// Count one `tools/list` entry the list screen hid, by its reason (one of
    /// [`LIST_HIDE_REASONS`]; anything else is ignored, so the label set stays fixed).
    pub fn list_entry_hidden(&self, reason: &str) {
        if let Some(i) = LIST_HIDE_REASONS.iter().position(|r| *r == reason) {
            self.list_entries_hidden[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    fn render_list_screen(&self, out: &mut String) {
        header_lines(
            out,
            "proxy_list_entries_hidden_total",
            "tools/list entries the list screen hid ([proxy] list_filter = \"policy\", \
             ADR-0011), by reason: policy (no call could be allowed), not_in_catalog \
             (unknown_tools = \"deny\"), invalid_name. Not audited: nothing was decided.",
            "counter",
        );
        for (i, reason) in LIST_HIDE_REASONS.iter().enumerate() {
            let n = self.list_entries_hidden[i].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{PREFIX}_proxy_list_entries_hidden_total{{reason=\"{reason}\"}} {n}"
            );
        }
    }

    fn render_stream_ends(&self, out: &mut String) {
        header_lines(
            out,
            "proxy_streams_ended_total",
            "GET listen streams the proxy relayed that ended, by cause: the re-check cut them \
             (token_expired, lease_*, recheck_*), the client went away (client_disconnect), \
             or the upstream finished or broke them (upstream_eof, upstream_error). Each \
             stream is counted once.",
            "counter",
        );
        for cause in StreamEndCause::ALL {
            let n = self.streams_ended[cause.index()].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{PREFIX}_proxy_streams_ended_total{{cause=\"{}\"}} {n}",
                cause.as_str()
            );
        }
        header_lines(
            out,
            "audit_records_suppressed_total",
            "Audit records not written because an earlier record of the same delegation \
             chain, tool and reason, less than [proxy] record_window_seconds older (default \
             60), stands for them: stream.end records of GET listen streams, and lease \
             refusals of undecided requests (initialize, the list methods, notifications, GET, \
             DELETE; these series appear once counted). Tool-call decisions, token exchanges \
             and renewals are never bounded.",
            "counter",
        );
        for reason in StreamEndCause::RECORDED {
            let n = self.stream_end_suppressed[reason.index()].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{PREFIX}_audit_records_suppressed_total{{tool=\"{STREAM_END_TOOL}\",reason=\"{}\"}} {n}",
                reason.as_str()
            );
        }
        if let Ok(map) = self.lease_refusal_suppressed.lock() {
            for ((tool, reason), n) in map.iter() {
                let reason = StreamEndCause::RECORDED[*reason].as_str();
                let _ = writeln!(
                    out,
                    "{PREFIX}_audit_records_suppressed_total{{tool=\"{tool}\",reason=\"{reason}\"}} {n}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_counters_and_histogram() {
        let m = Metrics::new();
        m.decision("allow", "policy_permit");
        m.decision("allow", "policy_permit");
        m.decision("deny", "lease \"x\"");
        m.token_issued(TokenKind::Root);
        m.leases_revoked(3);
        m.audit_append_error();
        m.http_request("/token", 200);
        m.observe_authorize(Duration::from_micros(200));
        m.observe_authorize(Duration::from_millis(30));
        m.observe_authorize(Duration::from_secs(5));
        let text = m.render();
        assert!(text
            .contains("attenuo_decisions_total{decision=\"allow\",reason=\"policy_permit\"} 2\n"));
        assert!(text.contains("reason=\"lease \\\"x\\\"\"} 1\n"));
        assert!(text.contains("attenuo_tokens_issued_total{kind=\"root\"} 1\n"));
        assert!(text.contains("attenuo_tokens_issued_total{kind=\"exchange\"} 0\n"));
        assert!(text.contains("attenuo_leases_revoked_total 3\n"));
        assert!(text.contains("attenuo_lease_sessions_pruned_total 0\n"));
        assert!(text.contains("attenuo_leases_pruned_total 0\n"));
        for kind in RUN_STATE_KINDS {
            assert!(text.contains(&format!(
                "attenuo_run_state_pruned_total{{kind=\"{kind}\"}} 0\n"
            )));
        }
        m.run_state_pruned(1, 2, 3);
        let text = m.render();
        assert!(text.contains("attenuo_run_state_pruned_total{kind=\"counters\"} 1\n"));
        assert!(text.contains("attenuo_run_state_pruned_total{kind=\"charges\"} 2\n"));
        assert!(text.contains("attenuo_run_state_pruned_total{kind=\"approvals\"} 3\n"));
        assert!(text.contains("attenuo_audit_append_errors_total 1\n"));
        assert!(text.contains("attenuo_http_requests_total{route=\"/token\",status=\"200\"} 1\n"));
        assert!(text.contains("authorize_duration_seconds_bucket{le=\"0.0005\"} 1\n"));
        assert!(text.contains("authorize_duration_seconds_bucket{le=\"0.05\"} 2\n"));
        assert!(text.contains("authorize_duration_seconds_bucket{le=\"+Inf\"} 3\n"));
        assert!(text.contains("authorize_duration_seconds_count 3\n"));
        assert!(text.contains("# TYPE attenuo_authorize_duration_seconds histogram\n"));
    }

    #[test]
    fn renders_audit_append_histogram_and_checkpoint_counter() {
        let m = Metrics::new();
        let text = m.render();
        assert!(text.contains("# TYPE attenuo_audit_append_duration_seconds histogram\n"));
        assert!(text.contains("attenuo_audit_append_duration_seconds_count 0\n"));
        assert!(text.contains("# TYPE attenuo_audit_checkpoints_total counter\n"));
        assert!(text.contains("attenuo_audit_checkpoints_total 0\n"));

        m.observe_audit_append(Duration::from_micros(300));
        m.observe_audit_append(Duration::from_millis(7));
        let slow = m.time_audit_append(|| {
            std::thread::sleep(Duration::from_millis(30));
            "done"
        });
        assert_eq!(slow, "done");
        m.audit_checkpoint();
        m.audit_checkpoint();
        let text = m.render();
        assert!(text.contains("audit_append_duration_seconds_bucket{le=\"0.0005\"} 1\n"));
        assert!(text.contains("audit_append_duration_seconds_bucket{le=\"0.01\"} 2\n"));
        assert!(text.contains("audit_append_duration_seconds_bucket{le=\"+Inf\"} 3\n"));
        assert!(text.contains("audit_append_duration_seconds_count 3\n"));
        assert!(text.contains("attenuo_audit_checkpoints_total 2\n"));
        // The two histograms are independent.
        assert!(text.contains("attenuo_authorize_duration_seconds_count 0\n"));
    }

    #[test]
    fn renders_limits_approvals_labels_and_run_lock() {
        let m = Metrics::new();
        let text = m.render();
        check_text_format(&text).unwrap();
        // Every fixed label combination is there at zero before anything happens.
        for kind in ["calls", "sum", "calls_per", "distinct"] {
            assert!(text.contains(&format!(
                "attenuo_budget_charges_total{{kind=\"{kind}\"}} 0\n"
            )));
            for at in ["check", "charge"] {
                assert!(text.contains(&format!(
                    "attenuo_budget_exhausted_total{{kind=\"{kind}\",at=\"{at}\"}} 0\n"
                )));
            }
        }
        assert!(text
            .contains("attenuo_approvals_decided_total{outcome=\"declined\",by=\"operator\"} 0\n"));
        assert!(text.contains("attenuo_run_lock_wait_seconds_count 0\n"));
        assert!(text.contains("attenuo_audit_checkpoint_last_timestamp_seconds 0\n"));
        // No WAL source, no WAL series.
        assert!(!text.contains("audit_wal_"));

        m.budget_charged(LimitKind::Calls);
        m.budget_charged(LimitKind::Calls);
        m.budget_charged(LimitKind::Distinct);
        m.budget_exhausted(LimitKind::Sum, ExhaustedAt::Check);
        m.budget_exhausted(LimitKind::CallsPer, ExhaustedAt::Charge);
        m.budget_refunded(RefundSource::Operator);
        m.budget_refunded(RefundSource::AuditError);
        m.budget_refunded(RefundSource::AuditError);
        m.approval_created();
        m.approval_decided(true, "user");
        m.approval_decided(false, "operator");
        m.approval_decided(true, "somebody"); // not a known kind: not counted
        m.approval_consumed("user");
        m.approval_expired();
        m.result_recorded(OutputLabel::Untrusted);
        m.result_recorded(OutputLabel::Trusted);
        m.result_recorded(OutputLabel::Untrusted);
        m.taint_match(false);
        m.observe_run_lock_wait(Duration::from_micros(3));
        m.observe_run_lock_wait(Duration::from_millis(4));
        m.audit_checkpoint();
        m.set_wal_source(|| {
            Some(WalStats {
                rounds_complete: 5,
                rounds_incomplete: 1,
                wal_presyncs: 2,
                last_complete_unix: 1_790_000_000,
                wal_frames: 12,
                ..WalStats::default()
            })
        });
        let text = m.render();
        check_text_format(&text).unwrap();
        for line in [
            "attenuo_budget_charges_total{kind=\"calls\"} 2",
            "attenuo_budget_charges_total{kind=\"distinct\"} 1",
            "attenuo_budget_charges_total{kind=\"sum\"} 0",
            "attenuo_budget_exhausted_total{kind=\"sum\",at=\"check\"} 1",
            "attenuo_budget_exhausted_total{kind=\"calls_per\",at=\"charge\"} 1",
            "attenuo_budget_refunds_total{source=\"operator\"} 1",
            "attenuo_budget_refunds_total{source=\"audit_error\"} 2",
            "attenuo_approvals_created_total 1",
            "attenuo_approvals_decided_total{outcome=\"granted\",by=\"user\"} 1",
            "attenuo_approvals_decided_total{outcome=\"granted\",by=\"operator\"} 0",
            "attenuo_approvals_decided_total{outcome=\"declined\",by=\"operator\"} 1",
            "attenuo_approvals_consumed_total{by=\"user\"} 1",
            "attenuo_approvals_expired_total 1",
            "attenuo_results_recorded_total{label=\"untrusted\"} 2",
            "attenuo_results_recorded_total{label=\"trusted\"} 1",
            "attenuo_taint_matches_total{decision=\"deny\"} 1",
            "attenuo_taint_matches_total{decision=\"allow\"} 0",
            "attenuo_run_lock_wait_seconds_bucket{le=\"0.000003\"} 1",
            "attenuo_run_lock_wait_seconds_bucket{le=\"+Inf\"} 2",
            "attenuo_run_lock_wait_seconds_count 2",
            "attenuo_audit_wal_checkpoints_total{result=\"complete\"} 5",
            "attenuo_audit_wal_checkpoints_total{result=\"incomplete\"} 1",
            "attenuo_audit_wal_checkpoints_total{result=\"error\"} 0",
            "attenuo_audit_wal_presyncs_total{file=\"wal\"} 2",
            "attenuo_audit_wal_presyncs_total{file=\"db\"} 0",
            "attenuo_audit_wal_locked_passes_total 0",
            "attenuo_audit_wal_backstops_total 0",
            "attenuo_audit_wal_frames 12",
            "attenuo_audit_wal_last_complete_timestamp_seconds 1790000000",
        ] {
            assert!(text.contains(&format!("{line}\n")), "{line}\n{text}");
        }
        assert!(!text.contains("attenuo_audit_checkpoint_last_timestamp_seconds 0\n"));
    }

    #[test]
    fn text_format_check_rejects_malformed_output() {
        let ok = "# HELP attenuo_x_total X.\n# TYPE attenuo_x_total counter\nattenuo_x_total{a=\"q\\\"\"} 1\n";
        check_text_format(ok).unwrap();
        for bad in [
            "attenuo_x_total 1\n",                                  // no TYPE
            "# TYPE attenuo_x counter\nattenuo_x{a=\"1\"} one\n",   // value
            "# TYPE attenuo_x counter\nattenuo_x{a=1} 1\n",         // unquoted
            "# TYPE attenuo_x counter\nattenuo_x 1\nattenuo_x 2\n", // repeated
            "# TYPE attenuo_x counter\n# TYPE attenuo_x counter\n", // two TYPEs
            "# TYPE attenuo_h histogram\nattenuo_h 1\n",            // bare histogram
            "# TYPE attenuo_h histogram\nattenuo_h_bucket 1\n",     // no le
            "# TYPE attenuo_x counter\nattenuo_x{a=\"\\t\"} 1\n",   // bad escape
            "# TYPE attenuo_x counter\nattenuo_x 1",                // no newline
        ] {
            assert!(check_text_format(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn renders_stage_histograms_with_labels() {
        let m = Metrics::new();
        m.observe_stage(Stage::Policy, Duration::from_micros(12));
        m.observe_stage(Stage::Policy, Duration::from_micros(40));
        m.observe_stage(Stage::Upstream, Duration::from_millis(2));
        let text = m.render();
        assert!(text.contains("# TYPE attenuo_proxy_stage_seconds histogram\n"));
        assert!(text
            .contains("attenuo_proxy_stage_seconds_bucket{stage=\"policy\",le=\"0.00002\"} 1\n"));
        assert!(
            text.contains("attenuo_proxy_stage_seconds_bucket{stage=\"policy\",le=\"+Inf\"} 2\n")
        );
        assert!(text.contains("attenuo_proxy_stage_seconds_count{stage=\"policy\"} 2\n"));
        assert!(text.contains("attenuo_proxy_stage_seconds_sum{stage=\"policy\"} 0.000052\n"));
        assert!(text.contains("attenuo_proxy_stage_seconds_count{stage=\"upstream\"} 1\n"));
        // Every stage is rendered, observed or not, and only one TYPE line is written.
        for s in Stage::ALL {
            let line = format!(
                "attenuo_proxy_stage_seconds_count{{stage=\"{}\"}} ",
                s.as_str()
            );
            assert!(text.contains(&line), "{line}");
        }
        assert_eq!(
            text.matches("# TYPE attenuo_proxy_stage_seconds").count(),
            1
        );
        // The older histograms keep their label-free form.
        assert!(text.contains("attenuo_authorize_duration_seconds_bucket{le=\"+Inf\"} 0\n"));
        assert!(text.contains("attenuo_authorize_duration_seconds_sum 0\n"));
    }

    #[test]
    fn stream_ends_and_suppressed_records_have_fixed_labels() {
        let m = Metrics::new();
        m.stream_ended(StreamEndCause::TokenExpired);
        m.stream_ended(StreamEndCause::ClientDisconnect);
        m.stream_ended(StreamEndCause::ClientDisconnect);
        m.record_suppressed(STREAM_END_TOOL, StreamEndCause::TokenExpired);
        // Not a bounded record: ignored, no new label.
        m.record_suppressed("tools/call", StreamEndCause::TokenExpired);
        m.record_suppressed("lease.renew", StreamEndCause::LeaseRevoked);
        m.record_suppressed(STREAM_END_TOOL, StreamEndCause::UpstreamEof);
        m.record_suppressed("initialize", StreamEndCause::ClientDisconnect);
        let text = m.render();
        assert!(text.contains("# TYPE attenuo_proxy_streams_ended_total counter\n"));
        assert!(text.contains("attenuo_proxy_streams_ended_total{cause=\"token_expired\"} 1\n"));
        assert!(text.contains("attenuo_proxy_streams_ended_total{cause=\"client_disconnect\"} 2\n"));
        for c in StreamEndCause::ALL {
            let line = format!(
                "attenuo_proxy_streams_ended_total{{cause=\"{}\"}} ",
                c.as_str()
            );
            assert_eq!(text.matches(&line).count(), 1, "{line}");
        }
        assert!(text.contains(
            "attenuo_audit_records_suppressed_total{tool=\"stream.end\",reason=\"token_expired\"} 1\n"
        ));
        assert_eq!(
            text.matches("attenuo_audit_records_suppressed_total{")
                .count(),
            StreamEndCause::RECORDED.len()
        );
        assert!(!text.contains("tools/call"));
        assert!(!text.contains("lease.renew"));
        assert!(!text.contains("reason=\"upstream_eof\""));
        assert!(!text.contains("reason=\"client_disconnect\""));
    }

    #[test]
    fn suppressed_lease_refusals_appear_once_counted() {
        let m = Metrics::new();
        let text = m.render();
        assert!(!text.contains("tool=\"initialize\""));
        m.record_suppressed("initialize", StreamEndCause::LeaseRevoked);
        m.record_suppressed("initialize", StreamEndCause::LeaseRevoked);
        m.record_suppressed("http.GET", StreamEndCause::LeaseExpired);
        m.record_suppressed("http.GET", StreamEndCause::LeaseOther);
        // Request text never becomes a label.
        m.record_suppressed("vendor/x", StreamEndCause::LeaseRevoked);
        let text = m.render();
        assert!(text.contains(
            "attenuo_audit_records_suppressed_total{tool=\"initialize\",reason=\"lease_revoked\"} 2\n"
        ));
        assert!(text.contains(
            "attenuo_audit_records_suppressed_total{tool=\"http.GET\",reason=\"lease_expired\"} 1\n"
        ));
        assert!(text.contains(
            "attenuo_audit_records_suppressed_total{tool=\"http.GET\",reason=\"lease_other\"} 1\n"
        ));
        assert!(!text.contains("vendor/x"));
        assert_eq!(
            text.matches("attenuo_audit_records_suppressed_total{")
                .count(),
            StreamEndCause::RECORDED.len() + 3
        );
        assert_eq!(
            text.matches("# TYPE attenuo_audit_records_suppressed_total counter\n")
                .count(),
            1
        );
    }
}
