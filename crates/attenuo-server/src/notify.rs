//! The two notifiers: the approval notifier (`[approvals.notify]`) tells a webhook the
//! deployment owns that an approval is waiting, and again when it was decided or expired, so an
//! operator does not have to watch the console; the revocation notifier (`[leases.notify]`)
//! tells a webhook that leases were revoked, so an enforcement point outside the server learns
//! of it without asking. Both run on the same code ([`NoticeStream`] says which one a notice
//! belongs to) and differ only in what they send and when.
//!
//! Where: [`NotifierHandle::pending`] is called by the pipeline after a new pending approval
//! and its `approval_request` record were written, and [`NotifierHandle::decided`] by the
//! approval routes after the decision and its `approval_grant` record were.
//! [`LeaseNotifier::revoked`] is called by the two revocation routes after the revocation and
//! its `lease_revoke` record were written, once per request that revoked at least one lease.
//! Each builds a small JSON document, stores it as one row of the lease store's
//! `notice_outbox` table (one local insert, never the network) and queues it. Delivery runs
//! on the `[audit.sink]` queue ([`crate::sink::Queue`], role [`QueueRole::ApprovalNotices`]
//! or [`QueueRole::LeaseNotices`]): bounded, oldest dropped when full, one background thread
//! per notifier, jittered exponential backoff, and given up after `max_attempts`. The queue's
//! [`Settle`] hook ([`OutboxSettle`]) marks each row delivered or given up, and records the
//! attempts and the next try of a failed one. Approval expiry has no request to hang on, so a
//! watcher thread keeps the pending approvals by expiry time and, once one is due, reads it
//! from the lease store and queues `approval.expired` if it is still pending. A lease that
//! expires sends nothing: the enforcement point already knows its `exp`.
//!
//! The two notifiers share the outbox table and keep apart by the namespace of the row's type
//! (`approval.` or `lease.`, [`NoticeStream::kind_prefix`]): each reads, counts and prunes only
//! its own rows, so each has its own backlog, gauge and retention.
//!
//! Restarts: on start the rows still open (queued, or in flight, when the last process
//! stopped) are delivered again, oldest first, with their attempts so far. The delivery thread
//! reads them from the outbox a batch of at most half of `queue_capacity` at a time, whenever
//! the queue runs empty (the other half is room, SR-98), so a backlog longer than the queue is
//! delivered whole instead of being dropped for lack of room (SR-93). Until it has caught up,
//! a notice stored meanwhile is not queued: it waits in the outbox and is read there behind
//! every row stored before it, so the notices of one approval go out in the order they were
//! stored (`approval.pending` before its `approval.expired` or `approval.decided`) across a
//! restart too. Once a read of the outbox finds nothing left, notices are queued as they are
//! stored again. And every approval still pending in the store is watched again,
//! so one that expired while the server was down gets its `approval.expired` at once, behind
//! its `approval.pending` if that was still in the outbox. The notice id (`event_id`) is derived from the
//! approval id and the type ([`event_id_for`]) and is unique in the table, so finding such an
//! expiry a second time queues nothing. Rows delivered or given up are deleted
//! `outbox_retention_seconds` later by the watcher; an approval that expired longer ago than
//! that is not looked at on start, since its notice may already be gone from the table.
//!
//! Best effort: a notification can be late, dropped (counted in
//! `attenuo_approval_notify_dropped_total` or `attenuo_lease_notify_dropped_total`) or
//! delivered twice: after a retry whose answer was lost, or when the process stopped between a
//! delivery and the write marking it delivered. The receiver deduplicates by `event_id`.
//! Nothing here can change a decision or a revocation, and a receiver that is down or slow
//! never holds up a request. A `lease.revoked` notice is a hint: the revocation is in force
//! in the server whether or not it arrives, and an enforcement point that must be sure still
//! asks.
//!
//! The documents carry no token and no arguments: an approval notice has only the call hash
//! (`ToolCall::call_hash`, SHA-256 over server, tool and arguments) to stand for the call, a
//! revocation notice only lease ids, names and times. Each request is signed:
//! `X-Attenuo-Signature: t=<unix seconds>,v1=<hex HMAC-SHA-256 of "<t>.<body>">` under the
//! secret in the environment variable `secret_env` ([`signature`]).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use attenuo_audit::{
    Approval, ApprovalState, ApprovalStore, NewNotice, OutboxNotice, SqliteLeaseStore,
};
use attenuo_core::{Clock, LeaseId};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::{
    ForApprovals, LeaseNotifySection, NotifySection, NotifyTarget, NOTIFY_SECRET_MIN_LEN,
};
use crate::metrics::{Metrics, NotifyCounters};
use crate::sink::{
    Backoff, Deliver, Queue, QueueHandle, QueueItem, QueueRole, Settle, Settled, SinkLimits,
    SinkStatus,
};

/// The signature header: `t=<unix seconds>,v1=<hex HMAC-SHA-256 of "<t>.<body>">`.
pub const SIGNATURE_HEADER: &str = "x-attenuo-signature";
/// The event type (`approval.pending`, `approval.decided`, `approval.expired`,
/// `lease.revoked`).
pub const EVENT_HEADER: &str = "x-attenuo-event";
/// The event id, the same on every retry of one notification.
pub const EVENT_ID_HEADER: &str = "x-attenuo-event-id";

/// Most pending approvals the expiry watcher keeps. Beyond this an approval gets no
/// `approval.expired` notice, and the miss is counted as a drop.
pub const MAX_WATCHED: usize = 10_000;

/// Most lease ids a `lease.revoked` notice lists in `lease_ids`, and so in `chain_ids`. A
/// selector revocation that matched more top leases than this sets `truncated`. 100 ids keep
/// the body under about 8 KB; a receiver that needs every lease reads the tree from the admin
/// API, or treats each chain it knows of the user as dead.
pub const MAX_LEASE_NOTICE_IDS: usize = 100;

/// How long after `expires_at` the watcher looks, so the store agrees it has expired.
const EXPIRY_GRACE: Duration = Duration::from_millis(250);

/// How often the watcher deletes outbox rows settled more than `outbox_retention_seconds` ago.
/// It also does so once at start.
pub const OUTBOX_PRUNE_PERIOD: Duration = Duration::from_secs(3600);

/// Which notifier a notice belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeStream {
    /// `[approvals.notify]`: `approval.*` notices.
    Approvals,
    /// `[leases.notify]`: `lease.*` notices.
    Leases,
}

impl NoticeStream {
    /// The config section, as log lines name it.
    pub fn section(self) -> &'static str {
        match self {
            Self::Approvals => "[approvals.notify]",
            Self::Leases => "[leases.notify]",
        }
    }

    /// The start of the type of every notice of this notifier, which is how its rows of the
    /// shared outbox table are told apart from the other's.
    pub fn kind_prefix(self) -> &'static str {
        match self {
            Self::Approvals => "approval.",
            Self::Leases => "lease.",
        }
    }

    fn role(self, max_attempts: u32) -> QueueRole {
        match self {
            Self::Approvals => QueueRole::ApprovalNotices { max_attempts },
            Self::Leases => QueueRole::LeaseNotices { max_attempts },
        }
    }

    fn counters(self, m: &Metrics) -> &NotifyCounters {
        match self {
            Self::Approvals => m.approval_notify(),
            Self::Leases => m.lease_notify(),
        }
    }
}

/// What a notice tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    /// The call was gated and its approval is waiting (`approval.pending`).
    Pending,
    /// The approval was granted or declined (`approval.decided`).
    Decided,
    /// The approval expired undecided (`approval.expired`).
    Expired,
    /// A revocation request revoked at least one lease (`lease.revoked`).
    LeaseRevoked,
}

impl NoticeKind {
    /// The event type, as sent in [`EVENT_HEADER`] and the body's `type`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "approval.pending",
            Self::Decided => "approval.decided",
            Self::Expired => "approval.expired",
            Self::LeaseRevoked => "lease.revoked",
        }
    }

    /// The kind [`as_str`](Self::as_str) names.
    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::Pending,
            Self::Decided,
            Self::Expired,
            Self::LeaseRevoked,
        ]
        .into_iter()
        .find(|k| k.as_str() == s)
    }

    /// The notifier that sends this kind.
    pub fn stream(self) -> NoticeStream {
        match self {
            Self::Pending | Self::Decided | Self::Expired => NoticeStream::Approvals,
            Self::LeaseRevoked => NoticeStream::Leases,
        }
    }
}

/// The `event_id` of the `kind` notice about `id`: a UUID (version 8, RFC 9562) made of the
/// first 16 bytes of SHA-256 over a label, the type and the id. For an approval notice `id` is
/// the approval id: an approval gets at most one notice of each type. For `lease.revoked` it
/// is [`LeaseRevocation::event_key`], the id of the revocation's `lease_revoke` audit record:
/// one notice per revocation request. Either way this names the notice, and it is the same on
/// every attempt and after a restart.
pub fn event_id_for(kind: NoticeKind, id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(match kind.stream() {
        NoticeStream::Approvals => b"attenuo approval notice\0".as_slice(),
        NoticeStream::Leases => b"attenuo lease notice\0".as_slice(),
    });
    h.update(kind.as_str().as_bytes());
    h.update(b"\0");
    h.update(id.as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&h.finalize()[..16]);
    b[6] = (b[6] & 0x0f) | 0x80;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(b).to_string()
}

/// One notification, its body fixed when it was first queued.
#[derive(Debug, Clone)]
pub struct Notice {
    /// What the notice tells.
    pub kind: NoticeKind,
    /// What it is about: the approval's id, or for `lease.revoked` the first lease the
    /// revocation named. Kept in the outbox row and named in log lines.
    pub about: String,
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
    /// The notice of `kind` for approval `a`, its body built and fixed now; not yet stored.
    pub fn new(kind: NoticeKind, a: &Approval) -> Self {
        let event_id = event_id_for(kind, &a.id);
        let body = serde_json::to_vec(&notice_json(kind, &event_id, a)).unwrap_or_default();
        Self {
            kind,
            about: a.id.clone(),
            event_id,
            body,
            row: None,
            attempts: 0,
        }
    }

    /// The `lease.revoked` notice of revocation `r`, its body built and fixed now; not yet
    /// stored.
    pub fn lease_revoked(r: &LeaseRevocation) -> Self {
        let kind = NoticeKind::LeaseRevoked;
        let event_id = event_id_for(kind, &r.event_key());
        let body = serde_json::to_vec(&lease_notice_json(&event_id, r)).unwrap_or_default();
        Self {
            kind,
            about: r.lease_ids.first().map(|l| l.0.clone()).unwrap_or_default(),
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
            about: r.approval_id,
            event_id: r.event_id,
            body: r.body,
            row: Some(r.id),
            attempts: r.attempts,
        })
    }
}

impl QueueItem for Notice {
    fn log_id(&self) -> String {
        format!("{} {}", self.kind.as_str(), self.about)
    }

    fn attempts(&self) -> u32 {
        self.attempts
    }
}

/// The queue's [`Settle`] hook: keeps each notice's outbox row in step with its delivery. A
/// write that fails is logged and leaves the row open, so it is delivered again after the
/// next restart (the receiver deduplicates by `event_id`).
///
/// It also hands the delivery thread the rows a restart left open, and those stored while it
/// works through them (`Backlog`), a batch at a time whenever the queue runs empty, so that
/// none is dropped for lack of room (SR-93) and they go out in the order they were stored.
/// It reads only the rows of its own notifier ([`NoticeStream::kind_prefix`]).
#[derive(Debug)]
pub struct OutboxSettle {
    stream: NoticeStream,
    store: Arc<SqliteLeaseStore>,
    metrics: Arc<Metrics>,
    backlog: Arc<Backlog>,
    clock: Arc<dyn Clock>,
}

/// The outbox rows not yet handed to the queue after a restart: the open ones with a row id
/// above `after`, the last row handed. While `draining`, [`Emitter::emit`] stores a new notice
/// without queuing it, so the delivery thread reads it from the outbox behind every row stored
/// before it; the first read that finds no row (or fails) clears `draining`, and from then on
/// notices are queued when stored and the outbox is not read again. `draining` changes only
/// with `after` locked, and `emit` decides with it locked too, so a notice is either read from
/// the outbox or queued, never both and never neither.
///
/// A notice stored during the drain gets a row id above `after`: SQLite gives a new row an id
/// above every id in the table, and the row `after` names is the last of the batch being
/// delivered, which stays open (so unpruned) until that batch is through; the next read
/// follows as soon as the queue runs empty. The other notifier's rows in the same table do
/// not change this: they only take ids in between, which this notifier's reads skip.
#[derive(Debug, Default)]
struct Backlog {
    after: Mutex<i64>,
    draining: AtomicBool,
}

impl Backlog {
    fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, i64> {
        self.after.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl OutboxSettle {
    /// The next open rows of the backlog, oldest first, at most `room`. A row of a type this
    /// version does not know is skipped. A read that finds nothing ends the backlog; one that
    /// fails ends it too, logged, and the rows left stay open for the next restart.
    fn next_backlog(&self, room: usize) -> Vec<Notice> {
        let section = self.stream.section();
        let prefix = self.stream.kind_prefix();
        let mut after = self.backlog.lock();
        while self.backlog.is_draining() && room > 0 {
            let rows = match self
                .store
                .outbox_open_between_of(prefix, *after, i64::MAX, room)
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!(error = %e, "{section} could not read the outbox: notices stored before the restart and not yet queued are left until the next one");
                    self.backlog.draining.store(false, Ordering::Release);
                    break;
                }
            };
            let Some(last) = rows.last() else {
                self.backlog.draining.store(false, Ordering::Release);
                break;
            };
            *after = last.id;
            let notices: Vec<Notice> = rows
                .into_iter()
                .filter_map(|row| {
                    let n = Notice::from_outbox(row);
                    if n.is_none() {
                        tracing::warn!("{section} outbox row of an unknown type: skipped");
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
        let now = self.clock.now_utc();
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
            Ok(true) => self.stream.counters(&self.metrics).outbox_closed(),
            Ok(false) => {}
            Err(e) => tracing::warn!(
                notice = %n.log_id(),
                error = %e,
                "{} could not update the outbox row: it may be delivered again after a restart",
                self.stream.section()
            ),
        }
    }

    fn refill(&self, room: usize) -> Vec<Notice> {
        self.next_backlog(room)
    }
}

/// Stores a notice in the outbox, then queues it (or, while a restart's backlog drains, leaves
/// it to be read from the outbox in its turn, [`Backlog`]). Shared by the handle and the
/// watcher.
#[derive(Debug, Clone)]
struct Emitter {
    stream: NoticeStream,
    queue: QueueHandle<Notice>,
    store: Arc<SqliteLeaseStore>,
    metrics: Arc<Metrics>,
    clock: Arc<dyn Clock>,
    backlog: Arc<Backlog>,
}

impl Emitter {
    fn emit(&self, mut n: Notice) {
        if self.backlog.is_draining() {
            let after = self.backlog.lock();
            // Looked at again with the backlog locked: the drain may have ended meanwhile.
            if self.backlog.is_draining() {
                if !self.store(&mut n) {
                    return;
                }
                if n.row.is_some() {
                    // Stored: the delivery thread reads it behind the rows before it.
                    return;
                }
                // Not stored, so the backlog cannot read it: queued now, in memory only.
                drop(after);
                self.queue.push(n);
                return;
            }
        }
        if self.store(&mut n) {
            self.queue.push(n);
        }
    }

    /// Store `n` in the outbox and set its row. `false` when it was stored before (an expiry
    /// found again after a restart: queued then, or done), so there is nothing to queue.
    fn store(&self, n: &mut Notice) -> bool {
        let new = NewNotice {
            event_id: &n.event_id,
            kind: n.kind.as_str(),
            approval_id: &n.about,
            body: &n.body,
        };
        match self.store.outbox_insert(new, self.clock.now_utc()) {
            Ok(Some(row)) => {
                n.row = Some(row);
                self.counters().outbox_opened();
            }
            // Stored before (an expiry found again after a restart): queued then, or done.
            Ok(None) => return false,
            Err(e) => tracing::warn!(
                notice = %n.log_id(),
                error = %e,
                "{} could not store the notice in the outbox: queued in memory only, so a \
                 restart before it is delivered loses it",
                self.stream.section()
            ),
        }
        true
    }

    fn counters(&self) -> &NotifyCounters {
        self.stream.counters(&self.metrics)
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

/// What a `lease.revoked` notice says about one revocation request: the top leases of what it
/// revoked, their chains, and the facts its `lease_revoke` audit record holds. Built by the
/// revocation routes ([`LeaseRevocation::tops`]) after the revocation and its record were
/// written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRevocation {
    /// The tops of what was revoked, at most [`MAX_LEASE_NOTICE_IDS`]: for
    /// `POST /admin/leases/{id}/revoke` the lease named, for `POST /admin/leases/revoke` each
    /// matched lease whose parent this request did not revoke too (ordered by id). Every lease
    /// the request revoked is one of these or descends from one.
    pub lease_ids: Vec<LeaseId>,
    /// The chain (root lease) of each of `lease_ids`, each once, in the same order.
    pub chain_ids: Vec<LeaseId>,
    /// More top leases matched than `lease_ids` lists.
    pub truncated: bool,
    /// The selector of `POST /admin/leases/revoke`, as its response and audit record show it
    /// (`{"user": ...}`, `{"chain_id": ...}`, `{"session_tag": ..., "chain_ids": [...]}`); `None`
    /// for a revocation of one lease by id.
    pub selector: Option<Value>,
    /// How many leases changed from unrevoked to revoked, descendants included.
    pub revoked: u64,
    /// The reason stored with the revocation.
    pub reason: String,
    /// When the leases were revoked: the `at` of the audit record.
    pub revoked_at: OffsetDateTime,
    /// The id of the `lease_revoke` audit record; `None` when it could not be written (the
    /// revocation stands, and the notice is still sent).
    pub audit_record_id: Option<uuid::Uuid>,
    /// The operator's name (`admin` for `[admin] token`).
    pub by: String,
    /// The operator's subject, as the audit record's `originating_subject` has it.
    pub by_subject: String,
}

impl LeaseRevocation {
    /// What names this revocation for [`event_id_for`]: the audit record id, unique per
    /// request; without a record, the top leases and the revocation time, which one request
    /// fixes and another cannot repeat (a revoked lease is not revoked again).
    pub fn event_key(&self) -> String {
        match &self.audit_record_id {
            Some(id) => id.to_string(),
            None => {
                let leases: Vec<&str> = self.lease_ids.iter().map(|l| l.0.as_str()).collect();
                format!(
                    "{}@{}",
                    leases.join(","),
                    self.revoked_at.unix_timestamp_nanos()
                )
            }
        }
    }

    /// The top leases of a revocation that changed `revoked` and matched `matched` (both as
    /// the store returned them; `matched` ordered by id), with their chains, read from
    /// `store`. A matched lease is a top when its parent is not among `revoked`: then no
    /// other match of this request covers it. At most [`MAX_LEASE_NOTICE_IDS`] are listed;
    /// the walk stops as soon as one more is found, and sets `truncated`. A lease or chain
    /// that cannot be read is logged and left out; nothing here fails the revocation.
    pub fn tops(
        store: &SqliteLeaseStore,
        matched: &[LeaseId],
        revoked: &[LeaseId],
    ) -> (Vec<LeaseId>, Vec<LeaseId>, bool) {
        let changed: HashSet<&LeaseId> = revoked.iter().collect();
        let mut tops = Vec::new();
        let mut truncated = false;
        for m in matched {
            let parent = match store.get(m) {
                Ok(row) => row.and_then(|r| r.parent),
                Err(e) => {
                    tracing::warn!(lease = %m.0, error = %e, "[leases.notify] could not read a revoked lease: left out of the notice");
                    continue;
                }
            };
            if parent.is_some_and(|p| changed.contains(&p)) {
                continue;
            }
            if tops.len() == MAX_LEASE_NOTICE_IDS {
                truncated = true;
                break;
            }
            tops.push(m.clone());
        }
        let mut chains: Vec<LeaseId> = Vec::new();
        for t in &tops {
            if let Some(root) = chain_root(store, t) {
                if !chains.contains(&root) {
                    chains.push(root);
                }
            }
        }
        (tops, chains, truncated)
    }
}

/// The root of the chain `lease` belongs to: its topmost ancestor, which is the audit
/// records' `chain_id`. `None` when a row cannot be read (logged).
fn chain_root(store: &SqliteLeaseStore, lease: &LeaseId) -> Option<LeaseId> {
    let mut at = lease.clone();
    let mut seen = HashSet::from([at.clone()]);
    loop {
        match store.get(&at) {
            Ok(Some(row)) => match row.parent {
                // A cycle no real tree has: stop where it closes.
                Some(p) if seen.insert(p.clone()) => at = p,
                _ => return Some(at),
            },
            // A parent the store no longer knows: the topmost lease reached.
            Ok(None) => return Some(at),
            Err(e) => {
                tracing::warn!(lease = %lease.0, error = %e, "[leases.notify] could not read a lease's chain: left out of the notice");
                return None;
            }
        }
    }
}

/// The `lease.revoked` document for `r`. Only lease ids, the selector as the audit record
/// shows it, a count, the reason, a time, the record id and the operator: no token, no
/// secret, no raw session id.
pub fn lease_notice_json(event_id: &str, r: &LeaseRevocation) -> Value {
    json!({
        "type": NoticeKind::LeaseRevoked.as_str(),
        "event_id": event_id,
        "lease_ids": r.lease_ids,
        "chain_ids": r.chain_ids,
        "truncated": r.truncated,
        "selector": r.selector,
        "revoked": r.revoked,
        "reason": r.reason,
        "revoked_at": fmt(r.revoked_at),
        "audit_record_id": r.audit_record_id,
        "by": r.by,
        "by_subject": r.by_subject,
    })
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
    /// `headers` are name and value pairs, already read from the environment. For
    /// `[approvals.notify]`; [`new_for`](Self::new_for) names another section in its errors.
    ///
    /// # Errors
    ///
    /// When `url` does not parse, when a header name or value is not valid in HTTP, or when the
    /// HTTP client cannot be built (its TLS backend fails to start).
    pub fn new(
        url: &str,
        headers: &[(String, String)],
        secret: Vec<u8>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        Self::new_for(NoticeStream::Approvals, url, headers, secret, timeout)
    }

    /// [`new`](Self::new) for the notifier `stream`, whose section its errors name.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub fn new_for(
        stream: NoticeStream,
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
                    "{} headers: the value for {name} is not a valid header value",
                    stream.section()
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

/// The deliverer and queue limits `cfg` sets for the notifier `stream`, its secret and header
/// values read from the environment. Shared by both notifiers, so both start, and fail to
/// start, the same way.
///
/// # Errors
///
/// When `cfg` does not validate, when the signing secret's variable is unset or holds fewer
/// than `NOTIFY_SECRET_MIN_LEN` bytes, when a header's variable is unset, or when the webhook
/// client cannot be built ([`WebhookNotify::new`]). The message names the section and the
/// variable, never its value.
fn webhook_from_config<K: NotifyTarget>(
    stream: NoticeStream,
    cfg: &NotifySection<K>,
) -> anyhow::Result<(WebhookNotify, SinkLimits)> {
    cfg.validate()?;
    let section = stream.section();
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let secret = env(&cfg.secret_env).ok_or_else(|| {
        anyhow::anyhow!(
            "{section} the signing secret is not set: put at least \
             {NOTIFY_SECRET_MIN_LEN} bytes in the environment variable {}",
            cfg.secret_env
        )
    })?;
    if secret.len() < NOTIFY_SECRET_MIN_LEN {
        anyhow::bail!(
            "{section} the signing secret in {} is shorter than {NOTIFY_SECRET_MIN_LEN} bytes",
            cfg.secret_env
        );
    }
    let mut headers = Vec::new();
    for (name, var) in &cfg.headers {
        let value = env(var).ok_or_else(|| {
            anyhow::anyhow!(
                "{section} headers: {name} names the environment variable {var}, which is not set"
            )
        })?;
        headers.push((name.clone(), value));
    }
    let deliver = WebhookNotify::new_for(
        stream,
        &cfg.url,
        &headers,
        secret.into_bytes(),
        Duration::from_secs(cfg.timeout_seconds),
    )?;
    if plain_http_off_loopback(&cfg.url) {
        tracing::warn!(
            host = %deliver.host,
            "{section} url is plain http to a host other than loopback: notifications travel \
             unencrypted"
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
    Ok((deliver, limits))
}

/// One notifier's delivery: its queue, with the outbox hook, and the emitter that stores and
/// queues its notices. Started with the backlog a restart left (see the module docs).
#[derive(Debug)]
struct Channel {
    queue: Queue<Notice>,
    emit: Emitter,
}

impl Channel {
    fn start(
        stream: NoticeStream,
        deliver: Box<dyn Deliver<Notice>>,
        limits: SinkLimits,
        max_attempts: u32,
        metrics: Arc<Metrics>,
        store: Arc<SqliteLeaseStore>,
        clock: Arc<dyn Clock>,
    ) -> anyhow::Result<Self> {
        let backlog = Arc::new(backlog_at_start(stream, &store));
        let settle = OutboxSettle {
            stream,
            store: store.clone(),
            metrics: metrics.clone(),
            backlog: backlog.clone(),
            clock: clock.clone(),
        };
        let queue = Queue::start_with(
            deliver,
            limits,
            stream.role(max_attempts),
            metrics.clone(),
            Some(Box::new(settle)),
        )?;
        let emit = Emitter {
            stream,
            queue: queue.handle(),
            store,
            metrics,
            clock,
            backlog,
        };
        count_open(&emit);
        Ok(Self { queue, emit })
    }
}

/// Pending approvals by when they expire.
#[derive(Debug, Default)]
struct WatchState {
    due: BTreeSet<(Instant, String)>,
    at: HashMap<String, Instant>,
    stop: bool,
}

/// The watched approvals, on `clock`: due times are its [`Clock::now`] instants. The
/// revocation notifier uses one with nothing in it, for its pruning loop and its stop.
#[derive(Debug)]
struct Watch {
    st: Mutex<WatchState>,
    wake: Condvar,
    clock: Arc<dyn Clock>,
}

impl Watch {
    fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            st: Mutex::default(),
            wake: Condvar::new(),
            clock,
        }
    }

    /// When to look at an approval that expires at `expires_at`.
    fn due_at(&self, expires_at: OffsetDateTime) -> Instant {
        let left = expires_at - self.clock.now_utc();
        let left = Duration::try_from(left).unwrap_or(Duration::ZERO);
        self.clock.now() + left + EXPIRY_GRACE
    }

    /// Wake [`next_due`](Self::next_due) to read the clock again. Taking the lock first
    /// means a watcher that read the clock before it moved is already waiting, so it is woken.
    fn poke(&self) {
        drop(self.st.lock().unwrap_or_else(|e| e.into_inner()));
        self.wake.notify_all();
    }

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
            let now = self.clock.now();
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
        if !self.watch.add(&a.id, self.watch.due_at(a.expires_at)) {
            self.emit.counters().dropped();
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
    /// Validate `cfg`, read its secret and headers from the environment, and start.
    ///
    /// # Errors
    ///
    /// When `cfg` does not validate, when the signing secret's variable is unset or holds fewer
    /// than `NOTIFY_SECRET_MIN_LEN` bytes, when a header's variable is unset, when the webhook
    /// client cannot be built ([`WebhookNotify::new`]), or as [`with_deliver`](Self::with_deliver).
    /// The message names the variable, never its value.
    pub fn start(
        cfg: &NotifySection<ForApprovals>,
        metrics: Arc<Metrics>,
        leases: Arc<SqliteLeaseStore>,
        clock: Arc<dyn Clock>,
    ) -> anyhow::Result<Self> {
        let (deliver, limits) = webhook_from_config(NoticeStream::Approvals, cfg)?;
        let host = deliver.host.clone();
        let retention = Duration::from_secs(cfg.outbox_retention_seconds);
        let n = Self::with_deliver(
            Box::new(deliver),
            limits,
            cfg.max_attempts,
            retention,
            metrics,
            leases,
            clock,
        )?;
        tracing::info!(host = %host, capacity = cfg.queue_capacity, "[approvals.notify] notifying a webhook of approvals");
        Ok(n)
    }

    /// Start with any deliverer (tests). Hands the delivery thread the outbox rows still open
    /// and watches the approvals still pending (see the module docs), then returns.
    ///
    /// # Errors
    ///
    /// When the delivery thread or the expiry watcher thread cannot be spawned.
    pub fn with_deliver(
        deliver: Box<dyn Deliver<Notice>>,
        limits: SinkLimits,
        max_attempts: u32,
        outbox_retention: Duration,
        metrics: Arc<Metrics>,
        store: Arc<SqliteLeaseStore>,
        clock: Arc<dyn Clock>,
    ) -> anyhow::Result<Self> {
        let Channel { queue, emit } = Channel::start(
            NoticeStream::Approvals,
            deliver,
            limits,
            max_attempts,
            metrics,
            store,
            clock.clone(),
        )?;
        let watch = Arc::new(Watch::new(clock));
        watch_pending(&emit, &watch, outbox_retention);
        let (w, e) = (watch.clone(), emit.clone());
        let watcher = std::thread::Builder::new()
            .name("attenuo-approval-expiry".into())
            .spawn(move || maintain(&w, &e, outbox_retention, expire_if_pending))?;
        Ok(Self {
            queue,
            emit,
            watch,
            watcher: Mutex::new(Some(watcher)),
        })
    }

    /// A producer end for the pipeline and the approval routes.
    pub fn handle(&self) -> NotifierHandle {
        NotifierHandle {
            emit: self.emit.clone(),
            watch: self.watch.clone(),
        }
    }

    /// Queue depth, lag and failures of delivery, which `/readyz` reports.
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

    /// Have the expiry watcher read its clock again now. For tests that move a
    /// [`attenuo_core::ManualClock`] forward: the watcher otherwise sleeps until the next
    /// expiry as the real time goes, so a jump of the clock is seen only then.
    pub fn clock_advanced(&self) {
        self.watch.poke();
    }

    /// Whether the delivery thread is still reading a restart's backlog from the outbox.
    #[cfg(test)]
    fn draining(&self) -> bool {
        self.emit.backlog.is_draining()
    }
}

impl Drop for ApprovalNotifier {
    fn drop(&mut self) {
        self.watch.stop();
    }
}

/// A running revocation notifier (`[leases.notify]`): the queue, its delivery thread and a
/// thread that prunes its outbox rows. The revocation routes call [`revoked`](Self::revoked).
#[derive(Debug)]
pub struct LeaseNotifier {
    queue: Queue<Notice>,
    emit: Emitter,
    /// Never holds an id: its loop prunes the outbox and stops with it.
    watch: Arc<Watch>,
    pruner: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl LeaseNotifier {
    /// Validate `cfg`, read its secret and headers from the environment, and start, as
    /// [`ApprovalNotifier::start`] does.
    ///
    /// # Errors
    ///
    /// As [`ApprovalNotifier::start`], the messages naming `[leases.notify]`.
    pub fn start(
        cfg: &LeaseNotifySection,
        metrics: Arc<Metrics>,
        leases: Arc<SqliteLeaseStore>,
        clock: Arc<dyn Clock>,
    ) -> anyhow::Result<Self> {
        let (deliver, limits) = webhook_from_config(NoticeStream::Leases, cfg)?;
        let host = deliver.host.clone();
        let retention = Duration::from_secs(cfg.outbox_retention_seconds);
        let n = Self::with_deliver(
            Box::new(deliver),
            limits,
            cfg.max_attempts,
            retention,
            metrics,
            leases,
            clock,
        )?;
        tracing::info!(host = %host, capacity = cfg.queue_capacity, "[leases.notify] notifying a webhook of lease revocations");
        Ok(n)
    }

    /// Start with any deliverer (tests). Hands the delivery thread the outbox rows of this
    /// notifier still open, then returns.
    ///
    /// # Errors
    ///
    /// When the delivery thread or the pruning thread cannot be spawned.
    pub fn with_deliver(
        deliver: Box<dyn Deliver<Notice>>,
        limits: SinkLimits,
        max_attempts: u32,
        outbox_retention: Duration,
        metrics: Arc<Metrics>,
        store: Arc<SqliteLeaseStore>,
        clock: Arc<dyn Clock>,
    ) -> anyhow::Result<Self> {
        let Channel { queue, emit } = Channel::start(
            NoticeStream::Leases,
            deliver,
            limits,
            max_attempts,
            metrics,
            store,
            clock.clone(),
        )?;
        let watch = Arc::new(Watch::new(clock));
        let (w, e) = (watch.clone(), emit.clone());
        let pruner = std::thread::Builder::new()
            .name("attenuo-lease-notify-prune".into())
            .spawn(move || maintain(&w, &e, outbox_retention, |_, _, _| {}))?;
        Ok(Self {
            queue,
            emit,
            watch,
            pruner: Mutex::new(Some(pruner)),
        })
    }

    /// The revocation `r` was just written, with its audit record: store and queue its
    /// `lease.revoked` notice. Writes one outbox row; never waits on the receiver. A
    /// revocation that changed nothing is not one to tell (`r.revoked` is 0): nothing is sent.
    pub fn revoked(&self, r: &LeaseRevocation) {
        if r.revoked == 0 {
            return;
        }
        self.emit.emit(Notice::lease_revoked(r));
    }

    /// Queue depth, lag and failures of delivery, which `/readyz` reports.
    pub fn status(&self) -> SinkStatus {
        self.queue.status()
    }

    /// Stop pruning, then deliver what is queued until `grace` has passed. Blocks.
    pub fn shutdown(&self, grace: Duration) {
        self.watch.stop();
        if let Some(t) = self.pruner.lock().ok().and_then(|mut t| t.take()) {
            let _ = t.join();
        }
        self.queue.shutdown(grace);
    }
}

impl Drop for LeaseNotifier {
    fn drop(&mut self) {
        self.watch.stop();
    }
}

/// Whether a restart left outbox rows of `stream` open, for [`OutboxSettle`] to hand to the
/// queue a batch at a time (SR-93), with new notices waiting behind them ([`Backlog`]). Read
/// before the queue starts, so before any new notice is stored. A read that fails is logged
/// and leaves the backlog empty: those rows wait for the next restart.
fn backlog_at_start(stream: NoticeStream, store: &SqliteLeaseStore) -> Backlog {
    let draining = match store.outbox_last_open_id_of(stream.kind_prefix()) {
        Ok(last) => last.is_some(),
        Err(e) => {
            tracing::error!(error = %e, "{} could not read the outbox: notices stored before the restart are not delivered now", stream.section());
            false
        }
    };
    Backlog {
        after: Mutex::new(0),
        draining: AtomicBool::new(draining),
    }
}

/// Count the outbox rows of the notifier a restart left open (the delivery thread reads them
/// in batches, [`OutboxSettle`]). An error is logged: the notifier starts anyway.
fn count_open(emit: &Emitter) {
    let section = emit.stream.section();
    match emit.store.outbox_open_count_of(emit.stream.kind_prefix()) {
        Ok(n) => {
            emit.counters().outbox_rows(n);
            if n > 0 {
                tracing::info!(
                    notices = n,
                    "{section} delivering notices stored before the restart"
                );
            }
        }
        Err(e) => tracing::warn!(error = %e, "{section} could not count the outbox"),
    }
}

/// What a restart left besides the open outbox rows: watch every approval still pending whose
/// expiry is within `retention` (the watcher queues `approval.expired` at once for one that
/// expired while the server was down). Errors are logged: the notifier starts anyway.
fn watch_pending(emit: &Emitter, watch: &Watch, retention: Duration) {
    let oldest = emit.clock.now_utc() - retention;
    match emit.store.pending_approvals(MAX_WATCHED) {
        Ok(pending) => {
            for a in pending.iter().filter(|a| a.expires_at > oldest) {
                watch.add(&a.id, watch.due_at(a.expires_at));
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "[approvals.notify] could not read the pending approvals: those waiting before the restart get no approval.expired notice")
        }
    }
}

/// Delete this notifier's outbox rows settled longer than `retention` ago.
fn prune_outbox(emit: &Emitter, retention: Duration) {
    let section = emit.stream.section();
    match emit
        .store
        .outbox_prune_of(emit.stream.kind_prefix(), emit.clock.now_utc() - retention)
    {
        Ok(0) => {}
        Ok(n) => tracing::debug!(rows = n, "{section} pruned the outbox"),
        Err(e) => tracing::warn!(error = %e, "{section} pruning the outbox failed"),
    }
}

/// A notifier's background loop: prune its outbox every [`OUTBOX_PRUNE_PERIOD`] (and once at
/// start), and hand each id of `watch` that comes due to `on_due`, until stopped.
fn maintain(
    watch: &Watch,
    emit: &Emitter,
    retention: Duration,
    on_due: impl Fn(&Watch, &Emitter, String),
) {
    let clock = &emit.clock;
    let mut prune_at = clock.now();
    loop {
        if clock.now() >= prune_at {
            prune_outbox(emit, retention);
            prune_at = clock.now() + OUTBOX_PRUNE_PERIOD;
        }
        match watch.next_due(prune_at) {
            Next::Due(id) => on_due(watch, emit, id),
            Next::Timeout => {}
            Next::Stop => return,
        }
    }
}

/// The expiry watcher's step for a due approval: queue `approval.expired` if it is still
/// pending once its expiry has passed.
fn expire_if_pending(watch: &Watch, emit: &Emitter, id: String) {
    let leases: &dyn ApprovalStore = emit.store.as_ref();
    let clock = &emit.clock;
    match leases.approval(&id) {
        Ok(Some(a)) if a.state == ApprovalState::Pending => {
            if a.is_expired(clock.now_utc()) {
                emit.emit(Notice::new(NoticeKind::Expired, &a));
            } else {
                // The clocks disagree by a little: look again.
                watch.add(
                    &a.id,
                    watch.due_at(a.expires_at).max(clock.now() + EXPIRY_GRACE),
                );
            }
        }
        // Decided, used, or gone (pruned, or dropped after a failed audit append).
        Ok(_) => {}
        Err(e) => {
            emit.counters().dropped();
            tracing::warn!(approval = %id, error = %e, "[approvals.notify] approval unreadable at its expiry: no approval.expired notice");
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
                approval_id: &notice.about,
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
            attenuo_core::clock::system_clock(),
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

    /// SR-93: a notice stored while the backlog drains is delivered once, read from the outbox
    /// behind the rows stored before it, and so is a row stored there by any other path then
    /// (a bare insert here). Once the delivery thread has caught up, a notice is queued when it
    /// is stored and the outbox is not read again: a row that is stored but never queued (an
    /// `emit` cut off between its insert and its push, stood in for by a bare insert) stays
    /// open for the next restart instead of being delivered twice.
    #[test]
    fn a_notice_stored_while_the_backlog_drains_is_delivered_once_sr93() {
        let (store, events) = store_with_open_rows(10);
        let recorder = Arc::new(Recorder::default());
        let (started, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release) = std::sync::mpsc::channel();
        *recorder.hold.lock().unwrap() = Some((started, release));
        let (n, metrics) = start(&store, &recorder, 4);
        // The first backlog row is in flight, the other one of its batch is queued.
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(n.draining());
        let mut fresh = approval(ApprovalState::Pending);
        fresh.id = "33333333-3333-4333-8333-333333333333".into();
        fresh.expires_at = OffsetDateTime::now_utc() + time::Duration::hours(1);
        n.handle().pending(&fresh);
        // Stored, not queued: only the rest of the first batch is in the queue.
        assert_eq!(n.status().queued, 1);
        let fresh_event = event_id_for(NoticeKind::Pending, &fresh.id);
        let insert = |event: &str, kind: &str| {
            store
                .outbox_insert(
                    NewNotice {
                        event_id: event,
                        kind,
                        approval_id: &fresh.id,
                        body: b"{}",
                    },
                    OffsetDateTime::now_utc(),
                )
                .unwrap()
                .unwrap()
        };
        let mid_drain = event_id_for(NoticeKind::Expired, &fresh.id);
        insert(&mid_drain, "approval.expired");
        release_tx.send(()).unwrap();
        wait_until(|| !n.draining());
        // Caught up: queued as stored, and a bare insert is not read any more.
        let mut later = approval(ApprovalState::Pending);
        later.id = "55555555-5555-4555-8555-555555555555".into();
        later.expires_at = OffsetDateTime::now_utc() + time::Duration::hours(1);
        n.handle().pending(&later);
        let later_event = event_id_for(NoticeKind::Pending, &later.id);
        let never_pushed = event_id_for(NoticeKind::Decided, &fresh.id);
        insert(&never_pushed, "approval.decided");
        wait_until(|| recorder.got.lock().unwrap().len() > events.len() + 2);
        // Shutting down delivers anything still queued, so a second copy would show here.
        n.shutdown(Duration::from_secs(5));
        let got = recorder.got.lock().unwrap().clone();
        // The backlog in the order it was stored, the two notices stored during the drain
        // behind it, then the one queued once the drain was over.
        let mut want = events.clone();
        want.extend([fresh_event, mid_drain, later_event]);
        assert_eq!(got, want);
        // Only the row whose push never came is open: the outbox was not read again.
        assert!(store.outbox_open_id(&never_pushed).unwrap().is_some());
        assert_eq!(store.outbox_open_count().unwrap(), 1);
        assert!(metrics
            .render()
            .contains("attenuo_approval_notify_dropped_total 0\n"));
    }

    /// The notices of one approval go out in the order they were stored across a restart: an
    /// `approval.expired` (or `approval.decided`) stored while that approval's
    /// `approval.pending` is still unread in the outbox goes out after it, not before. Before
    /// the fix the new notice was queued at once and could overtake the backlog, which a
    /// receiver saw as an expiry of an approval it had never heard of.
    #[test]
    fn a_notice_stored_during_the_drain_never_overtakes_its_approvals_pending_one() {
        let (store, events) = store_with_open_rows(10);
        let recorder = Arc::new(Recorder::default());
        let (started, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release) = std::sync::mpsc::channel();
        *recorder.hold.lock().unwrap() = Some((started, release));
        let (n, metrics) = start(&store, &recorder, 4);
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        // Rows 1 and 2 are in the first batch; row 6's approval is still unread. It expires,
        // and another is decided.
        let mut expired = approval(ApprovalState::Pending);
        expired.id = "00000000-0000-4000-8000-000000000006".into();
        let mut decided = approval(ApprovalState::Granted);
        decided.id = "00000000-0000-4000-8000-000000000008".into();
        n.emit.emit(Notice::new(NoticeKind::Expired, &expired));
        n.handle().decided(&decided);
        release_tx.send(()).unwrap();
        wait_until(|| recorder.got.lock().unwrap().len() >= events.len() + 2);
        n.shutdown(Duration::from_secs(5));
        let got = recorder.got.lock().unwrap().clone();
        let mut want = events.clone();
        want.push(event_id_for(NoticeKind::Expired, &expired.id));
        want.push(event_id_for(NoticeKind::Decided, &decided.id));
        assert_eq!(got, want);
        let pos = |e: &str| got.iter().position(|g| g == e).unwrap();
        assert!(pos(&events[6]) < pos(&want[events.len()]));
        assert!(pos(&events[8]) < pos(&want[events.len() + 1]));
        assert_eq!(store.outbox_open_count().unwrap(), 0);
        assert!(metrics
            .render()
            .contains("attenuo_approval_notify_dropped_total 0\n"));
    }

    /// SR-98: a backlog batch leaves room in the queue, and nothing that arrives while it is
    /// delivered pushes any of it out: with the batch as large as the queue, the second new
    /// notice dropped a backlog row (given up without one attempt), and the queue read as full
    /// on `/readyz` for the whole backlog. New notices now wait in the outbox behind the
    /// backlog, so they take no room in the queue while it drains.
    #[test]
    fn notices_queued_while_a_backlog_batch_drains_drop_none_of_it_sr98() {
        let (store, events) = store_with_open_rows(10);
        let recorder = Arc::new(Recorder::default());
        let (started, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release) = std::sync::mpsc::channel();
        *recorder.hold.lock().unwrap() = Some((started, release));
        let (n, metrics) = start(&store, &recorder, 4);
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        // The first backlog row is in flight and the rest of its batch is queued.
        let st = n.status();
        assert!(st.queued < st.capacity, "{st:?}");
        assert!(!st.degraded, "{st:?}");
        let mut fresh_events = Vec::new();
        for i in 0..2 {
            let mut fresh = approval(ApprovalState::Pending);
            fresh.id = format!("44444444-4444-4444-8444-{i:012}");
            fresh.expires_at = OffsetDateTime::now_utc() + time::Duration::hours(1);
            n.handle().pending(&fresh);
            fresh_events.push(event_id_for(NoticeKind::Pending, &fresh.id));
        }
        let st = n.status();
        assert!(st.queued < st.capacity, "{st:?}");
        release_tx.send(()).unwrap();
        // Every row is closed once it is delivered, or given up when a full queue drops it.
        wait_until(|| store.outbox_open_count().unwrap() == 0);
        n.shutdown(Duration::from_secs(5));
        let got = recorder.got.lock().unwrap().clone();
        // The backlog, then the new notices, in the order they were stored.
        let mut want = events.clone();
        want.extend(fresh_events);
        assert_eq!(got, want);
        assert_eq!(store.outbox_open_count().unwrap(), 0);
        assert!(metrics
            .render()
            .contains("attenuo_approval_notify_dropped_total 0\n"));
    }

    #[test]
    fn watch_returns_ids_in_expiry_order_and_forgets_removed_ones() {
        let clock = attenuo_core::ManualClock::new();
        let w = Watch::new(clock.clone());
        let now = clock.now();
        assert!(w.add("b", now + Duration::from_secs(20)));
        assert!(w.add("a", now));
        assert!(w.add("c", now + Duration::from_secs(10)));
        w.remove("c");
        let later = now + Duration::from_secs(3600);
        assert_eq!(w.next_due(later), Next::Due("a".into()));
        // "b" is not due yet; step the clock to it instead of waiting.
        assert_eq!(w.next_due(clock.now()), Next::Timeout);
        clock.advance(Duration::from_secs(20));
        assert_eq!(w.next_due(later), Next::Due("b".into()));
        assert_eq!(w.next_due(clock.now()), Next::Timeout);
        w.stop();
        assert_eq!(w.next_due(later), Next::Stop);
    }

    fn revocation() -> LeaseRevocation {
        LeaseRevocation {
            lease_ids: vec![LeaseId::new("l1")],
            chain_ids: vec![LeaseId::new("l0")],
            truncated: false,
            selector: None,
            revoked: 3,
            reason: "revoked by alice".into(),
            revoked_at: OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap(),
            audit_record_id: Some(
                uuid::Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap(),
            ),
            by: "alice".into(),
            by_subject: "urn:attenuo:admin:alice".into(),
        }
    }

    #[test]
    fn lease_notice_has_the_fields_and_nothing_else() {
        let r = revocation();
        assert_eq!(
            lease_notice_json("e1", &r),
            json!({
                "type": "lease.revoked",
                "event_id": "e1",
                "lease_ids": ["l1"],
                "chain_ids": ["l0"],
                "truncated": false,
                "selector": null,
                "revoked": 3,
                "reason": "revoked by alice",
                "revoked_at": "2026-05-28T20:26:40Z",
                "audit_record_id": "33333333-3333-4333-8333-333333333333",
                "by": "alice",
                "by_subject": "urn:attenuo:admin:alice",
            })
        );
        let mut sel = r.clone();
        sel.selector = Some(json!({"user": "bob"}));
        sel.audit_record_id = None;
        let v = lease_notice_json("e2", &sel);
        assert_eq!(v["selector"], json!({"user": "bob"}));
        assert_eq!(v["audit_record_id"], Value::Null);
        let n = Notice::lease_revoked(&r);
        assert_eq!(n.kind, NoticeKind::LeaseRevoked);
        assert_eq!(n.about, "l1");
        assert_eq!(n.log_id(), "lease.revoked l1");
        let body: Value = serde_json::from_slice(&n.body).unwrap();
        assert_eq!(body["event_id"], n.event_id);
    }

    #[test]
    fn lease_event_id_is_stable_per_revocation_and_apart_from_approval_ids() {
        let r = revocation();
        let id = Notice::lease_revoked(&r).event_id;
        assert_eq!(id, Notice::lease_revoked(&r).event_id, "stable");
        assert_eq!(
            id,
            event_id_for(
                NoticeKind::LeaseRevoked,
                "33333333-3333-4333-8333-333333333333"
            ),
            "derived from the audit record id"
        );
        let u = uuid::Uuid::parse_str(&id).unwrap();
        assert_eq!(u.get_version_num(), 8);
        // Another request, another record: another id. Same key, approval type: another id.
        let mut other = r.clone();
        other.audit_record_id = Some(uuid::Uuid::new_v4());
        assert_ne!(id, Notice::lease_revoked(&other).event_id);
        for k in [
            NoticeKind::Pending,
            NoticeKind::Decided,
            NoticeKind::Expired,
        ] {
            assert_ne!(id, event_id_for(k, "33333333-3333-4333-8333-333333333333"));
            assert_eq!(k.stream(), NoticeStream::Approvals);
        }
        // Without a record: the top leases and the time, still stable.
        let mut unrecorded = r.clone();
        unrecorded.audit_record_id = None;
        assert_eq!(unrecorded.event_key(), "l1@1780000000000000000");
        assert_eq!(
            Notice::lease_revoked(&unrecorded).event_id,
            Notice::lease_revoked(&unrecorded).event_id
        );
        assert_eq!(
            NoticeKind::parse("lease.revoked"),
            Some(NoticeKind::LeaseRevoked)
        );
        assert_eq!(NoticeKind::LeaseRevoked.stream(), NoticeStream::Leases);
        assert_eq!(NoticeStream::Leases.kind_prefix(), "lease.");
    }

    /// A store with the chain `r > a > (a1, a2)` and `r > b`, and a second chain `s`.
    fn tree() -> SqliteLeaseStore {
        use attenuo_audit::LeaseRegistry;
        let store = SqliteLeaseStore::open_in_memory().unwrap();
        let exp = OffsetDateTime::now_utc() + time::Duration::hours(1);
        for (id, parent) in [
            ("r", None),
            ("a", Some("r")),
            ("a1", Some("a")),
            ("a2", Some("a")),
            ("b", Some("r")),
            ("s", None),
        ] {
            store
                .register(&LeaseId::new(id), parent.map(LeaseId::new).as_ref(), exp)
                .unwrap();
        }
        store
    }

    fn ids(v: &[&str]) -> Vec<LeaseId> {
        v.iter().map(|s| LeaseId::new(*s)).collect()
    }

    /// The tops of a revocation are the matches whose parent it did not revoke, and their
    /// chains are named once each.
    #[test]
    fn tops_are_the_matches_not_covered_by_another_and_name_their_chains() {
        let store = tree();
        // By id: the lease named, whatever was revoked under it.
        let (tops, chains, cut) = LeaseRevocation::tops(&store, &ids(&["a"]), &[]);
        assert_eq!((tops, chains, cut), (ids(&["a"]), ids(&["r"]), false));
        // A user selector matching a, a1 and s: a1 is under a, so a and s are the tops.
        let (tops, chains, cut) = LeaseRevocation::tops(
            &store,
            &ids(&["a", "a1", "s"]),
            &ids(&["a", "a1", "s", "a2"]),
        );
        assert_eq!(
            (tops, chains, cut),
            (ids(&["a", "s"]), ids(&["r", "s"]), false)
        );
        // Two matches of one chain whose parent was revoked before: both tops, one chain.
        let (tops, chains, _) =
            LeaseRevocation::tops(&store, &ids(&["a1", "a2"]), &ids(&["a1", "a2"]));
        assert_eq!((tops, chains), (ids(&["a1", "a2"]), ids(&["r"])));
        // An unknown lease is a top of its own chain.
        let (tops, chains, _) = LeaseRevocation::tops(&store, &ids(&["gone"]), &[]);
        assert_eq!((tops, chains), (ids(&["gone"]), ids(&["gone"])));
    }

    #[test]
    fn tops_are_cut_at_the_cap_and_say_so() {
        use attenuo_audit::LeaseRegistry;
        let store = SqliteLeaseStore::open_in_memory().unwrap();
        let exp = OffsetDateTime::now_utc() + time::Duration::hours(1);
        let roots: Vec<LeaseId> = (0..MAX_LEASE_NOTICE_IDS + 5)
            .map(|i| LeaseId::new(format!("root-{i:04}")))
            .collect();
        for r in &roots {
            store.register(r, None, exp).unwrap();
        }
        let (tops, chains, cut) = LeaseRevocation::tops(&store, &roots, &roots);
        assert!(cut);
        assert_eq!(tops.len(), MAX_LEASE_NOTICE_IDS);
        assert_eq!(tops, roots[..MAX_LEASE_NOTICE_IDS].to_vec());
        assert_eq!(chains, tops);
        let (tops, _, cut) = LeaseRevocation::tops(&store, &roots[..MAX_LEASE_NOTICE_IDS], &roots);
        assert_eq!((tops.len(), cut), (MAX_LEASE_NOTICE_IDS, false));
    }

    #[test]
    fn lease_config_validation_names_its_section_and_its_secret() {
        let mut c = LeaseNotifySection::with_url("https://hooks.example/revoked");
        c.validate().unwrap();
        assert_eq!(c.secret_env, "ATTENUO_LEASE_NOTIFY_SECRET");
        assert_eq!(c.section(), "[leases.notify]");
        for bad in ["ftp://hooks.example/", "https://user:pw@hooks.example/"] {
            c.url = bad.into();
            let e = c.validate().unwrap_err().to_string();
            assert!(e.starts_with("[leases.notify] url"), "{e}");
        }
        c.url = "https://hooks.example/".into();
        c.headers.insert("X-Attenuo-Event".into(), "E".into());
        assert!(c.validate().is_err());
        c.headers.clear();
        c.queue_capacity = 0;
        let e = c.validate().unwrap_err().to_string();
        assert!(e.starts_with("[leases.notify] queue_capacity"), "{e}");
        c.queue_capacity = 1;
        c.outbox_retention_seconds = 0;
        assert!(c.validate().is_err());
        // The approval section keeps its own default and name.
        let a = NotifySection::new("https://hooks.example/");
        assert_eq!(a.secret_env, "ATTENUO_APPROVAL_NOTIFY_SECRET");
        assert_eq!(a.section(), "[approvals.notify]");
    }

    /// The two notifiers share the outbox and keep apart: each delivers only its own backlog
    /// after a restart, counts only its own rows, and a revocation that changed nothing sends
    /// nothing.
    #[test]
    fn each_notifier_delivers_only_its_own_rows_from_a_shared_outbox() {
        let (store, approval_events) = store_with_open_rows(3);
        let r = revocation();
        let lease_notice = Notice::lease_revoked(&r);
        let now = OffsetDateTime::now_utc();
        store
            .outbox_insert(
                NewNotice {
                    event_id: &lease_notice.event_id,
                    kind: lease_notice.kind.as_str(),
                    approval_id: &lease_notice.about,
                    body: &lease_notice.body,
                },
                now,
            )
            .unwrap()
            .unwrap();
        let limits = SinkLimits {
            capacity: 8,
            max_lag: Duration::from_secs(3600),
            backoff: Backoff {
                initial: Duration::from_millis(1),
                max: Duration::from_millis(5),
            },
        };
        let metrics = Metrics::new();
        let leases_got = Arc::new(Recorder::default());
        let ln = LeaseNotifier::with_deliver(
            Box::new(RecorderRef(leases_got.clone())),
            limits,
            3,
            Duration::from_secs(3600),
            metrics.clone(),
            store.clone(),
            attenuo_core::clock::system_clock(),
        )
        .unwrap();
        wait_until(|| !leases_got.got.lock().unwrap().is_empty());
        // Changed nothing: nothing to tell.
        let mut nothing = r.clone();
        nothing.revoked = 0;
        nothing.audit_record_id = Some(uuid::Uuid::new_v4());
        ln.revoked(&nothing);
        // A fresh revocation is queued as stored.
        let mut fresh = r.clone();
        fresh.audit_record_id = Some(uuid::Uuid::new_v4());
        ln.revoked(&fresh);
        wait_until(|| leases_got.got.lock().unwrap().len() == 2);
        ln.shutdown(Duration::from_secs(5));
        assert_eq!(
            *leases_got.got.lock().unwrap(),
            vec![
                lease_notice.event_id.clone(),
                Notice::lease_revoked(&fresh).event_id
            ]
        );
        // The approval rows were left alone.
        assert_eq!(store.outbox_open_count_of("approval.").unwrap(), 3);
        assert_eq!(store.outbox_open_count_of("lease.").unwrap(), 0);
        let text = metrics.render();
        assert!(
            text.contains("attenuo_lease_notify_delivered_total 2\n"),
            "{text}"
        );
        assert!(
            text.contains("attenuo_lease_notify_outbox_rows 0\n"),
            "{text}"
        );
        assert!(
            text.contains("attenuo_approval_notify_delivered_total 0\n"),
            "{text}"
        );
        // And the approval notifier, started on the same store, delivers only its own.
        let approvals_got = Arc::new(Recorder::default());
        let (an, _) = start(&store, &approvals_got, 8);
        wait_until(|| approvals_got.got.lock().unwrap().len() >= approval_events.len());
        an.shutdown(Duration::from_secs(5));
        assert_eq!(*approvals_got.got.lock().unwrap(), approval_events);
        assert_eq!(store.outbox_open_count().unwrap(), 0);
    }
}
