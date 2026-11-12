use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use attenuo_audit::{
    AuditEntry, AuditError, Durability, MemoryAudit, MemoryLeaseStore, SqliteAudit,
    SqliteLeaseStore, VerifyReport,
};
use attenuo_audit::{AuditSink, LeaseStore};
use attenuo_core::limits::{
    REASON_BUDGET_ERROR, REASON_BUDGET_EXHAUSTED, REASON_LIMIT_ARG_INVALID,
};
use attenuo_core::{AgentId, Capability, CapabilitySet, LeaseId, Limits, OriginatingUser};
use attenuo_core::{DecisionRecord, DelegationChain, LimitKind, ToolCall};
use attenuo_policy::PolicyEngineBuilder;
use attenuo_policy::{BudgetContext, UsageContext};
use serde_json::json;
use serde_json::Value;
use std::sync::{Arc, RwLock};
use time::Duration;
use time::OffsetDateTime;

/// A memory log whose appends can be made to fail.
#[derive(Default)]
struct FlakyAudit {
    inner: MemoryAudit,
    fail: AtomicBool,
}

impl AuditSink for FlakyAudit {
    fn append(&self, record: DecisionRecord) -> Result<AuditEntry, AuditError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AuditError::Storage("disk full".into()));
        }
        self.inner.append(record)
    }
    fn head(&self) -> Result<Option<AuditEntry>, AuditError> {
        self.inner.head()
    }
    fn range(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        self.inner.range(from_seq, limit)
    }
    fn verify_chain(&self) -> Result<VerifyReport, AuditError> {
        self.inner.verify_chain()
    }
}

const POLICY: &str = r#"
permit(principal, action, resource);
@id("no_big_payments")
forbid(principal, action == Action::"bank/send", resource)
when { context.input has amount && context.input.amount > 1000 };
"#;

fn chain(limits: Limits, now: OffsetDateTime) -> DelegationChain {
    DelegationChain::root(
        OriginatingUser {
            subject: "alice".into(),
            issuer: "idp".into(),
            authenticated_at: now,
            attributes: Default::default(),
        },
        AgentId::new("planner"),
        CapabilitySet::from_iter([Capability::new("bank", "send").with_limits(limits)]),
        now,
        Duration::hours(1),
        LeaseId::new("l1"),
    )
    .unwrap()
}

fn pipeline(leases: Arc<dyn LeaseStore>, audit: Arc<dyn AuditSink>) -> Pipeline {
    let engine = PolicyEngineBuilder::new()
        .with_catalog(attenuo_policy::ToolCatalog::new().with(
            "bank",
            "send",
            attenuo_policy::ToolAttrs::new().with_input("amount", attenuo_policy::ArgType::Long),
        ))
        .with_policies_str(POLICY)
        // These tests are about limits, and one about the worst-case usage of an
        // unreadable store: keep usage although `POLICY` does not read it.
        .with_track_usage(attenuo_policy::TrackUsage::Always)
        .build()
        .unwrap();
    Pipeline::new(Arc::new(RwLock::new(engine)), leases, audit)
}

fn send(amount: Value) -> ToolCall {
    ToolCall::new("bank", "send", json!({ "to": "emma", "amount": amount }))
}

/// `record_rejection_checked` says whether the rejection reached the log; the proxy opens
/// a record window only when it did (SR-81). `record_rejection` returns an id either way.
#[test]
fn a_failed_rejection_append_is_reported_sr81() {
    let now = OffsetDateTime::now_utc();
    let audit = Arc::new(FlakyAudit::default());
    let p = pipeline(Arc::new(MemoryLeaseStore::new()), audit.clone());
    let chain = chain(Limits::default(), now);
    let call = ToolCall::new("github", "initialize", json!({}));
    audit.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        p.record_rejection_checked(&chain, &call, "lease_revoked", now),
        None
    );
    let unwritten = p.record_rejection(&chain, &call, "lease_revoked", now);
    assert_eq!(audit.inner.len().unwrap(), 0);
    audit.fail.store(false, Ordering::SeqCst);
    let id = p
        .record_rejection_checked(&chain, &call, "lease_revoked", now)
        .expect("written");
    assert_ne!(id, unwritten);
    let entries = audit.inner.snapshot().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].record.id, id);
}

#[test]
fn charges_allowed_calls_and_records_what_was_left() {
    let now = OffsetDateTime::now_utc();
    let leases = Arc::new(MemoryLeaseStore::new());
    leases
        .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
        .unwrap();
    let audit = Arc::new(MemoryAudit::new());
    let p = pipeline(leases, audit.clone());
    let c = chain(Limits::default().with_calls(2).with_sum("amount", 50), now);

    let d = p.decide(&c, &send(json!(40)), now);
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(
        d.budget.calls_remaining, 2,
        "Cedar sees the figures before the call"
    );
    assert_eq!(d.budget.amount_remaining, 50);
    let record = &audit.snapshot().unwrap()[0].record;
    let charged = record.budget.as_ref().unwrap();
    assert_eq!(
        charged
            .charged
            .iter()
            .map(|c| (c.kind, c.used_after, c.max))
            .collect::<Vec<_>>(),
        vec![(LimitKind::Calls, 1, 2), (LimitKind::Sum, 40, 50)]
    );

    // 20 more would take the sum to 60: refused before Cedar, with the limit named.
    let d = p.decide(&c, &send(json!(20)), now);
    assert_eq!(d.reason, REASON_BUDGET_EXHAUSTED);
    let hit = d.limit.unwrap();
    assert_eq!(
        (hit.kind, hit.max, hit.used, hit.hop),
        (LimitKind::Sum, 50, 40, 0)
    );
    assert_eq!(hit.to_json()["arg"], "amount");
    assert!(audit.snapshot().unwrap()[1].record.budget.is_none());
    // 10 still fits.
    assert!(p.decide(&c, &send(json!(10)), now).is_allow());
}

#[test]
fn denied_call_is_not_charged() {
    let now = OffsetDateTime::now_utc();
    let leases = Arc::new(MemoryLeaseStore::new());
    leases
        .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
        .unwrap();
    let p = pipeline(leases.clone(), Arc::new(MemoryAudit::new()));
    let c = chain(Limits::default().with_calls(1), now);
    // Cedar forbids it: nothing is spent, so the next permitted call still has its budget.
    let d = p.decide(&c, &send(json!(5000)), now);
    assert_eq!(d.reason, attenuo_policy::REASON_POLICY_DENY);
    assert!(d.charged.is_none());
    assert!(p.decide(&c, &send(json!(5)), now).is_allow());
    assert_eq!(
        p.decide(&c, &send(json!(5)), now).reason,
        REASON_BUDGET_EXHAUSTED
    );
}

#[test]
fn negative_or_string_amount_is_refused() {
    let now = OffsetDateTime::now_utc();
    let leases = Arc::new(MemoryLeaseStore::new());
    leases
        .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
        .unwrap();
    let p = pipeline(leases, Arc::new(MemoryAudit::new()));
    let c = chain(Limits::default().with_sum("amount", 5000), now);
    for amount in [json!("1500"), json!(-1200), json!(1.5)] {
        let d = p.decide(&c, &send(amount.clone()), now);
        assert_eq!(d.reason, REASON_LIMIT_ARG_INVALID, "{amount}");
        assert!(d.budget.limited);
    }
}

#[test]
fn charge_and_audit_append_commit_together() {
    let now = OffsetDateTime::now_utc();
    let leases = Arc::new(MemoryLeaseStore::new());
    leases
        .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
        .unwrap();
    let audit = Arc::new(FlakyAudit::default());
    let p = pipeline(leases.clone(), audit.clone());
    let c = chain(Limits::default().with_calls(1), now);
    audit.fail.store(true, Ordering::SeqCst);
    let d = p.decide(&c, &send(json!(1)), now);
    assert_eq!(d.reason, REASON_AUDIT_ERROR);
    // The charge was refunded: the call that can be recorded gets the budget.
    audit.fail.store(false, Ordering::SeqCst);
    assert!(p.decide(&c, &send(json!(1)), now).is_allow());
    assert_eq!(
        p.decide(&c, &send(json!(1)), now).reason,
        REASON_BUDGET_EXHAUSTED
    );
    // On /metrics: two charges (the refunded one and the recorded one), one refund by
    // the pipeline, one exhaustion at the check.
    let text = p.metrics().render();
    for line in [
        "attenuo_budget_charges_total{kind=\"calls\"} 2\n",
        "attenuo_budget_refunds_total{source=\"audit_error\"} 1\n",
        "attenuo_budget_refunds_total{source=\"operator\"} 0\n",
        "attenuo_budget_exhausted_total{kind=\"calls\",at=\"check\"} 1\n",
        "attenuo_budget_exhausted_total{kind=\"calls\",at=\"charge\"} 0\n",
        "attenuo_decisions_total{decision=\"deny\",reason=\"audit_error\"} 1\n",
    ] {
        assert!(text.contains(line), "{line}{text}");
    }
}

/// A SQLite log that notes which append each decision used, and can be made to fail.
struct SpyAudit {
    inner: SqliteAudit,
    fail: AtomicBool,
    calls: std::sync::Mutex<Vec<&'static str>>,
}

impl SpyAudit {
    fn new(inner: SqliteAudit) -> Self {
        Self {
            inner,
            fail: AtomicBool::new(false),
            calls: Default::default(),
        }
    }

    fn take_calls(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }

    fn note(&self, what: &'static str) -> Result<(), AuditError> {
        self.calls.lock().unwrap().push(what);
        if self.fail.load(Ordering::SeqCst) {
            return Err(AuditError::Storage("disk full".into()));
        }
        Ok(())
    }
}

impl AuditSink for SpyAudit {
    fn append(&self, record: DecisionRecord) -> Result<AuditEntry, AuditError> {
        self.note("append")?;
        self.inner.append(record)
    }
    fn append_synced(&self, record: DecisionRecord) -> Result<AuditEntry, AuditError> {
        self.note("append_synced")?;
        self.inner.append_synced(record)
    }
    fn sync_file(&self) -> Option<&std::path::Path> {
        self.inner.sync_file()
    }
    fn head(&self) -> Result<Option<AuditEntry>, AuditError> {
        self.inner.head()
    }
    fn range(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        self.inner.range(from_seq, limit)
    }
    fn verify_chain(&self) -> Result<VerifyReport, AuditError> {
        self.inner.verify_chain()
    }
}

/// A log and a lease store at `durability`, the lease store in the log's file or, with
/// `apart`, in a file of its own.
fn file_stores(
    dir: &tempfile::TempDir,
    durability: Durability,
    apart: bool,
    now: OffsetDateTime,
) -> (Arc<SqliteLeaseStore>, Arc<SpyAudit>) {
    let path = dir.path().join("audit.db");
    let audit = SqliteAudit::open_with(&path, durability).unwrap();
    let lease_path = if apart {
        dir.path().join("leases.db")
    } else {
        path
    };
    let leases = SqliteLeaseStore::open_with(lease_path, durability).unwrap();
    leases
        .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
        .unwrap();
    (Arc::new(leases), Arc::new(SpyAudit::new(audit)))
}

/// Lease store and log in one file at `normal`: an allowed call that charges a `sum`
/// limit appends its decision with `append_synced` (the sync that makes the charge
/// durable); a `calls`-only charge, an unlimited call and a refused one append as before.
#[test]
fn sum_charge_is_synced_by_the_decision_append_on_a_shared_file() {
    let now = OffsetDateTime::now_utc();
    let dir = tempfile::tempdir().unwrap();
    let (leases, audit) = file_stores(&dir, Durability::Normal, false, now);
    let p = pipeline(leases.clone(), audit.clone());
    assert!(p.charge_sync_on_append);

    let sum = chain(Limits::default().with_sum("amount", 50), now);
    let d = p.decide(&sum, &send(json!(40)), now);
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(audit.take_calls(), ["append_synced"]);
    // Over the limit: nothing charged, nothing to sync.
    let d = p.decide(&sum, &send(json!(20)), now);
    assert_eq!(d.reason, REASON_BUDGET_EXHAUSTED);
    let calls = chain(Limits::default().with_calls(5), now);
    assert!(p.decide(&calls, &send(json!(1)), now).is_allow());
    let free = chain(Limits::default(), now);
    assert!(p.decide(&free, &send(json!(1)), now).is_allow());
    assert_eq!(audit.take_calls(), ["append", "append", "append"]);
    // The first decision's record carries what it charged.
    let first = &audit.range(1, 1).unwrap()[0].record;
    assert_eq!(first.budget.as_ref().unwrap().charged[0].used_after, 40);
    assert!(audit.verify_chain().unwrap().ok);
}

/// Where the log's sync would not cover the lease store (another file) or every commit is
/// synced anyway (`full`), the charge syncs itself as before and the append is plain.
#[test]
fn sum_charge_syncs_itself_when_the_append_cannot_cover_it() {
    let now = OffsetDateTime::now_utc();
    for (durability, apart, defers) in [
        (Durability::Normal, true, false),
        (Durability::Full, false, true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (leases, audit) = file_stores(&dir, durability, apart, now);
        let p = pipeline(leases, audit.clone());
        assert_eq!(p.charge_sync_on_append, defers, "{durability}");
        let sum = chain(Limits::default().with_sum("amount", 50), now);
        assert!(p.decide(&sum, &send(json!(40)), now).is_allow());
        assert_eq!(audit.take_calls(), ["append"], "{durability} apart={apart}");
    }
}

/// A deferred `sum` charge whose synced append fails is refunded, as any charge is: the
/// call is denied with `audit_error` and the budget is whole for the next call.
#[test]
fn deferred_sum_charge_is_refunded_when_the_synced_append_fails() {
    let now = OffsetDateTime::now_utc();
    let dir = tempfile::tempdir().unwrap();
    let (leases, audit) = file_stores(&dir, Durability::Normal, false, now);
    let p = pipeline(leases.clone(), audit.clone());
    let c = chain(Limits::default().with_sum("amount", 50), now);
    audit.fail.store(true, Ordering::SeqCst);
    let d = p.decide(&c, &send(json!(50)), now);
    assert_eq!(d.reason, REASON_AUDIT_ERROR);
    assert_eq!(audit.take_calls(), ["append_synced"]);
    audit.fail.store(false, Ordering::SeqCst);
    assert!(p.decide(&c, &send(json!(50)), now).is_allow());
    assert_eq!(
        p.decide(&c, &send(json!(1)), now).reason,
        REASON_BUDGET_EXHAUSTED
    );
}

#[test]
fn unreadable_counters_deny() {
    let now = OffsetDateTime::now_utc();
    let leases = Arc::new(SqliteLeaseStore::open_in_memory().unwrap());
    leases
        .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
        .unwrap();
    leases
        .with_connection(|c| Ok(c.execute_batch("DROP TABLE budget_counters")?))
        .unwrap();
    let p = pipeline(leases, Arc::new(MemoryAudit::new()));
    let d = p.decide(
        &chain(Limits::default().with_calls(5), now),
        &send(json!(1)),
        now,
    );
    assert_eq!(d.reason, REASON_BUDGET_ERROR);
    assert!(
        d.diagnostics.iter().any(|m| m.contains("unreadable")),
        "{d:?}"
    );
    // A call no limit applies to is not refused: its tool is destructive, so the policy
    // sees the worst-case run usage and decides (this one permits everything).
    let free = chain(Limits::default(), now);
    let d = p.decide(&free, &send(json!(1)), now);
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(d.usage, Some(UNREADABLE_USAGE));
    assert!(
        d.diagnostics
            .iter()
            .any(|m| m.contains("run usage unreadable")),
        "{d:?}"
    );
}

/// The seam of the admin dry run: counters stated as a store would hold them give the view
/// a store holding them gives (figures, limit hit, usage), through the same code.
#[test]
fn stated_counters_give_the_view_a_store_holding_them_gives() {
    let now = OffsetDateTime::now_utc();
    let leases = Arc::new(MemoryLeaseStore::new());
    leases
        .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
        .unwrap();
    let p = pipeline(leases, Arc::new(MemoryAudit::new()));
    let c = chain(
        Limits::default()
            .with_calls(3)
            .with_sum("amount", 50)
            .with_calls_per("to", 2)
            .with_distinct("to", 2),
        now,
    );
    assert!(p.decide(&c, &send(json!(40)), now).is_allow());

    for amount in [5, 20] {
        let call = send(json!(amount));
        let stored = p.budget_view(&c, &call);
        let stated = StatedBudget {
            calls_remaining: Some(2),
            amount_remaining: Some(10),
            destination_new: Some(false),
            limits: vec![
                StatedLimit {
                    hop: 0,
                    kind: LimitKind::CallsPer,
                    arg: Some("to".into()),
                    max: Some(2),
                    used: 1,
                },
                StatedLimit {
                    hop: 0,
                    kind: LimitKind::Distinct,
                    arg: Some("to".into()),
                    max: None,
                    used: 1,
                },
            ],
            usage: UsageContext {
                calls: 1,
                ..UsageContext::default()
            },
            ..StatedBudget::default()
        };
        assert_eq!(stated.unmatched(&stored.charges), None);
        let from_stated = p.budget_view_from(&c, &call, CounterSource::Stated(&stated));
        assert_eq!(from_stated, stored, "amount {amount}");
    }
    let over = p.budget_view(&c, &send(json!(20)));
    assert_eq!(over.hit.as_ref().map(|h| h.kind), Some(LimitKind::Sum));
    assert_eq!(
        over.context.refusal.as_ref().map(|r| r.reason.as_str()),
        Some(REASON_BUDGET_EXHAUSTED)
    );
}

/// A stated run never reads the store: with the counter table gone, the store read fails
/// closed while the stated one decides, and a spent stated limit is `budget_exhausted`
/// with the live diagnostic.
#[test]
fn stated_counters_never_read_the_store() {
    let now = OffsetDateTime::now_utc();
    let leases = Arc::new(SqliteLeaseStore::open_in_memory().unwrap());
    leases
        .with_connection(|c| Ok(c.execute_batch("DROP TABLE budget_counters")?))
        .unwrap();
    let p = pipeline(leases, Arc::new(MemoryAudit::new()));
    let c = chain(Limits::default().with_calls(5), now);
    let call = send(json!(1));
    let stored = p.budget_view(&c, &call);
    assert_eq!(
        stored.context.refusal.map(|r| r.reason),
        Some(REASON_BUDGET_ERROR.to_string())
    );

    let fresh = StatedBudget::default();
    let v = p.budget_view_from(&c, &call, CounterSource::Stated(&fresh));
    assert_eq!(v.context.refusal, None);
    assert_eq!(v.context.calls_remaining, 5);
    assert_eq!(v.usage, Some(UsageContext::default()));

    let spent = StatedBudget {
        calls_remaining: Some(0),
        ..StatedBudget::default()
    };
    let v = p.budget_view_from(&c, &call, CounterSource::Stated(&spent));
    let refusal = v.context.refusal.unwrap();
    assert_eq!(refusal.reason, REASON_BUDGET_EXHAUSTED);
    assert_eq!(
        refusal.detail,
        "limit `calls` of hop 0 would be exceeded: max 5, used 5"
    );
    assert_eq!(v.context.calls_remaining, 0);
}

#[test]
fn stated_entries_must_name_a_matching_limit_and_unlimited_figures_pass_through() {
    let now = OffsetDateTime::now_utc();
    let p = pipeline(
        Arc::new(MemoryLeaseStore::new()),
        Arc::new(MemoryAudit::new()),
    );
    let c = chain(Limits::default().with_calls(5), now);
    let stated = StatedBudget {
        limits: vec![StatedLimit {
            hop: 0,
            kind: LimitKind::Sum,
            arg: Some("amount".into()),
            max: None,
            used: 1,
        }],
        ..StatedBudget::default()
    };
    let v = p.budget_view_from(&c, &send(json!(1)), CounterSource::Stated(&stated));
    assert_eq!(
        stated.unmatched(&v.charges).as_deref(),
        Some(
            "`limits[0]` (hop 0, `sum` on `amount`) names no limit of the chain that \
             matches the call"
        )
    );

    let figures = StatedBudget {
        calls_remaining: Some(1),
        ..StatedBudget::default()
    };
    assert_eq!(
        figures.unlimited_context(),
        BudgetContext {
            limited: true,
            calls_remaining: 1,
            ..BudgetContext::default()
        }
    );
    let off = StatedBudget {
        limited: Some(false),
        ..StatedBudget::default()
    };
    assert_eq!(off.unlimited_context(), BudgetContext::default());
}

/// A stuck audit writer (audit A-3; here a thread holds the log's connection, as a write stuck
/// on a hung disk would) fails the decision closed with `audit_error` within the append
/// timeout, instead of blocking the caller for as long as the disk hangs. Once the writer is
/// free, decisions are allowed again.
#[test]
fn a_stuck_audit_writer_denies_within_the_append_timeout() {
    let now = OffsetDateTime::now_utc();
    let leases = Arc::new(SqliteLeaseStore::open_in_memory().unwrap());
    leases
        .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
        .unwrap();
    let audit = Arc::new(
        SqliteAudit::open_in_memory()
            .unwrap()
            .with_append_limits(16, std::time::Duration::from_millis(200)),
    );
    let p = pipeline(leases, audit.clone());
    let c = chain(Limits::default(), now);
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = {
        let audit = audit.clone();
        std::thread::spawn(move || {
            audit
                .with_connection(|_| {
                    held_tx.send(()).unwrap();
                    let _ = release_rx.recv();
                    Ok(())
                })
                .unwrap();
        })
    };
    held_rx.recv().unwrap();
    let started = std::time::Instant::now();
    let d = p.decide(&c, &send(json!(1)), now);
    assert_eq!(d.reason, REASON_AUDIT_ERROR);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(audit.append_stats().timeouts, 1);
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    assert!(p.decide(&c, &send(json!(1)), now).is_allow());
    assert!(audit.verify_chain().unwrap().ok);
}
