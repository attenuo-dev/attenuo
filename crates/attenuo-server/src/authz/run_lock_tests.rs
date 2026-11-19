//! SR-55: a policy over run usage (or budget figures) is evaluated on figures read before
//! the call is charged. Without a per-run lock, concurrent calls of one run all read the
//! same figures and all pass a rule that should stop the second.

use super::*;
use attenuo_audit::{Approval, ChargeOutcome, RunLabel};
use attenuo_audit::{ApprovalStore, LeaseRegistry, RunLimits, RunState, StoreRetention};
use attenuo_audit::{
    Approver, AuditError, CounterSummary, HopLimit, LeaseStatus, MemoryAudit, MemoryLeaseStore,
    SpanHit,
};
use attenuo_core::fingerprint::Fingerprint;
use attenuo_core::limits::REASON_BUDGET_EXHAUSTED;
use attenuo_core::{AgentId, Capability, CapabilitySet, Limits, OriginatingUser};
use attenuo_core::{Charge, DelegationChain, LeaseId, LimitKind, ToolCall, WindowCharge};
use attenuo_policy::{ArgType, PolicyEngineBuilder, ToolAttrs, ToolCatalog};
use serde_json::json;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::sync::{Barrier, Condvar};
use time::Duration;
use time::OffsetDateTime;

/// A lease store whose budget reads wait (up to a bound) for a second reader, so two
/// concurrent decisions both read before either charges unless something serialises them.
struct Rendezvous {
    inner: MemoryLeaseStore,
    readers: Mutex<usize>,
    window_readers: Mutex<usize>,
    arrived: Condvar,
    /// Budget reads see empty counters, as if another process had not charged yet; only
    /// the store's charge transaction sees what was spent.
    stale: std::sync::atomic::AtomicBool,
    /// Per-user windows cannot be read or charged (a store that lost them).
    no_windows: std::sync::atomic::AtomicBool,
}

impl LeaseRegistry for Rendezvous {
    fn register(
        &self,
        l: &LeaseId,
        p: Option<&LeaseId>,
        e: OffsetDateTime,
    ) -> Result<(), AuditError> {
        self.inner.register(l, p, e)
    }

    fn revoke(&self, l: &LeaseId, r: &str, n: OffsetDateTime) -> Result<u64, AuditError> {
        self.inner.revoke(l, r, n)
    }

    fn renew(&self, l: &LeaseId, e: OffsetDateTime, n: OffsetDateTime) -> Result<(), AuditError> {
        self.inner.renew(l, e, n)
    }

    fn is_active(&self, l: &LeaseId, n: OffsetDateTime) -> Result<bool, AuditError> {
        self.inner.is_active(l, n)
    }

    fn bind(&self, l: &LeaseId, b: &str) -> Result<(), AuditError> {
        self.inner.bind(l, b)
    }

    fn binding(&self, l: &LeaseId) -> Result<Option<String>, AuditError> {
        self.inner.binding(l)
    }

    fn record_subject(&self, l: &LeaseId, s: &str) -> Result<(), AuditError> {
        self.inner.record_subject(l, s)
    }

    fn subject(&self, l: &LeaseId) -> Result<Option<String>, AuditError> {
        self.inner.subject(l)
    }

    fn record_originating_user(&self, l: &LeaseId, i: &str, s: &str) -> Result<(), AuditError> {
        self.inner.record_originating_user(l, i, s)
    }

    fn originating_user(&self, l: &LeaseId) -> Result<Option<(String, String)>, AuditError> {
        self.inner.originating_user(l)
    }

    fn preview_selected(
        &self,
        s: &attenuo_audit::LeaseSelector,
    ) -> Result<attenuo_audit::SelectorRevocation, AuditError> {
        self.inner.preview_selected(s)
    }

    fn revoke_selected(
        &self,
        s: &attenuo_audit::LeaseSelector,
        r: &str,
        n: OffsetDateTime,
    ) -> Result<attenuo_audit::SelectorRevocation, AuditError> {
        self.inner.revoke_selected(s, r, n)
    }

    fn check_all(&self, l: &[&LeaseId], n: OffsetDateTime) -> Result<LeaseStatus, AuditError> {
        self.inner.check_all(l, n)
    }
}

impl RunState for Rendezvous {
    fn record_session(
        &self,
        s: &str,
        v: &str,
        c: &LeaseId,
        n: OffsetDateTime,
    ) -> Result<bool, AuditError> {
        self.inner.record_session(s, v, c, n)
    }

    fn sessions(&self, s: &str) -> Result<Vec<attenuo_audit::SessionBinding>, AuditError> {
        self.inner.sessions(s)
    }

    fn add_label(&self, c: &LeaseId, l: &RunLabel) -> Result<(), AuditError> {
        self.inner.add_label(c, l)
    }

    fn labels(&self, c: &LeaseId) -> Result<Vec<RunLabel>, AuditError> {
        self.inner.labels(c)
    }

    fn add_spans(&self, c: &LeaseId, s: u64, f: &[Fingerprint]) -> Result<(), AuditError> {
        self.inner.add_spans(c, s, f)
    }

    fn find_spans(&self, c: &LeaseId, f: &[Fingerprint]) -> Result<Vec<SpanHit>, AuditError> {
        self.inner.find_spans(c, f)
    }
}

impl ApprovalStore for Rendezvous {
    fn create_approval(&self, a: &Approval) -> Result<(Approval, bool), AuditError> {
        self.inner.create_approval(a)
    }

    fn approval(&self, id: &str) -> Result<Option<Approval>, AuditError> {
        self.inner.approval(id)
    }

    fn approvals(
        &self,
        c: Option<&LeaseId>,
        s: Option<attenuo_audit::ApprovalState>,
        b: Option<u64>,
        n: usize,
    ) -> Result<Vec<(u64, Approval)>, AuditError> {
        self.inner.approvals(c, s, b, n)
    }

    fn decide_approval(
        &self,
        id: &str,
        g: bool,
        a: &Approver,
        n: OffsetDateTime,
    ) -> Result<Approval, AuditError> {
        self.inner.decide_approval(id, g, a, n)
    }

    fn take_approval(
        &self,
        c: &LeaseId,
        l: &LeaseId,
        h: &str,
        d: &str,
        n: OffsetDateTime,
    ) -> Result<Option<Approval>, AuditError> {
        self.inner.take_approval(c, l, h, d, n)
    }

    fn take_approval_by_id(
        &self,
        id: &str,
        c: &LeaseId,
        l: &LeaseId,
        h: &str,
        d: &str,
        n: OffsetDateTime,
    ) -> Result<Option<Approval>, AuditError> {
        self.inner.take_approval_by_id(id, c, l, h, d, n)
    }

    fn restore_approval(&self, id: &str, d: &str) -> Result<(), AuditError> {
        self.inner.restore_approval(id, d)
    }

    fn remove_approval(&self, id: &str) -> Result<(), AuditError> {
        self.inner.remove_approval(id)
    }
}

impl RunLimits for Rendezvous {
    fn budget_used(&self, c: &[Charge]) -> Result<Vec<u64>, AuditError> {
        if self.stale.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(vec![0; c.len()]);
        }
        let mut readers = self.readers.lock().unwrap();
        *readers += 1;
        self.arrived.notify_all();
        let (readers, _) = self
            .arrived
            .wait_timeout_while(readers, std::time::Duration::from_millis(300), |r| *r < 2)
            .unwrap();
        drop(readers);
        self.inner.budget_used(c)
    }

    fn charge(
        &self,
        d: &str,
        c: &[Charge],
        at: OffsetDateTime,
    ) -> Result<ChargeOutcome, AuditError> {
        self.inner.charge(d, c, at)
    }

    fn refund(&self, d: &str, at: OffsetDateTime) -> Result<u64, AuditError> {
        self.inner.refund(d, at)
    }

    fn window_used(&self, w: &[WindowCharge]) -> Result<Vec<u64>, AuditError> {
        if self.no_windows.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(AuditError::Storage("windows lost".into()));
        }
        // Wait for a second reader, as `budget_used` does: two runs of one user both read
        // their windows before either charges unless the user lock serialises them.
        let mut readers = self.window_readers.lock().unwrap();
        *readers += 1;
        self.arrived.notify_all();
        let (readers, _) = self
            .arrived
            .wait_timeout_while(readers, std::time::Duration::from_millis(300), |r| *r < 2)
            .unwrap();
        drop(readers);
        self.inner.window_used(w)
    }

    fn charge_windowed(
        &self,
        d: &str,
        c: &[Charge],
        w: &[WindowCharge],
        at: OffsetDateTime,
        defer: bool,
    ) -> Result<(ChargeOutcome, bool), AuditError> {
        if self.no_windows.load(std::sync::atomic::Ordering::SeqCst) && !w.is_empty() {
            return Err(AuditError::Storage("windows lost".into()));
        }
        self.inner.charge_windowed(d, c, w, at, defer)
    }

    fn record_hop_limits(&self, l: &LeaseId, h: &[HopLimit]) -> Result<(), AuditError> {
        self.inner.record_hop_limits(l, h)
    }

    fn hop_limits(&self, l: &LeaseId) -> Result<Option<Vec<HopLimit>>, AuditError> {
        self.inner.hop_limits(l)
    }

    fn budget_summary(&self, l: &LeaseId) -> Result<Vec<CounterSummary>, AuditError> {
        self.inner.budget_summary(l)
    }
}

impl StoreRetention for Rendezvous {
    fn prune_sessions(
        &self,
        n: OffsetDateTime,
        r: time::Duration,
        m: usize,
    ) -> Result<attenuo_audit::SessionPrune, AuditError> {
        self.inner.prune_sessions(n, r, m)
    }

    fn prune_leases(
        &self,
        n: OffsetDateTime,
        r: time::Duration,
        m: usize,
    ) -> Result<attenuo_audit::LeasePrune, AuditError> {
        self.inner.prune_leases(n, r, m)
    }

    fn prune_run_state(
        &self,
        n: OffsetDateTime,
        r: time::Duration,
        m: usize,
    ) -> Result<attenuo_audit::RunStatePrune, AuditError> {
        self.inner.prune_run_state(n, r, m)
    }
}

fn run(policies: &str, limits: Limits) -> (Arc<Pipeline>, DelegationChain, OffsetDateTime) {
    run_with(policies, limits, false)
}

fn run_with(
    policies: &str,
    limits: Limits,
    stale: bool,
) -> (Arc<Pipeline>, DelegationChain, OffsetDateTime) {
    let (p, chain, now, _) = runs_with(policies, limits, stale, false);
    (p, chain, now)
}

/// As [`run_with`], plus a second run (`l2`) of the same user; with `no_windows`, per-user
/// windows cannot be read.
fn runs_with(
    policies: &str,
    limits: Limits,
    stale: bool,
    no_windows: bool,
) -> (
    Arc<Pipeline>,
    DelegationChain,
    OffsetDateTime,
    DelegationChain,
) {
    let now = OffsetDateTime::now_utc();
    let leases = Arc::new(Rendezvous {
        inner: MemoryLeaseStore::new(),
        readers: Mutex::new(0),
        window_readers: Mutex::new(0),
        arrived: Condvar::new(),
        stale: stale.into(),
        no_windows: no_windows.into(),
    });
    for l in ["l1", "l2"] {
        leases
            .register(&LeaseId::new(l), None, now + Duration::hours(1))
            .unwrap();
    }
    let attrs = ToolAttrs::new()
        .with_input("amount", ArgType::Long)
        .with_amount("amount");
    let engine = PolicyEngineBuilder::new()
        .with_catalog(ToolCatalog::new().with("bank", "send", attrs))
        .with_policies_str(policies)
        .build()
        .unwrap();
    let pipeline = Pipeline::new(
        Arc::new(SharedPolicy::new(engine)),
        leases,
        Arc::new(MemoryAudit::new()),
    );
    let root = |lease: &str| {
        DelegationChain::root(
            OriginatingUser {
                subject: "alice".into(),
                issuer: "idp".into(),
                authenticated_at: now,
                attributes: Default::default(),
            },
            AgentId::new("planner"),
            CapabilitySet::from_iter([Capability::new("bank", "send").with_limits(limits.clone())]),
            now,
            Duration::hours(1),
            LeaseId::new(lease),
        )
        .unwrap()
    };
    (Arc::new(pipeline), root("l1"), now, root("l2"))
}

/// Two payments of one run, sent at the same moment.
fn pay_twice_at_once(
    p: &Arc<Pipeline>,
    chain: &DelegationChain,
    now: OffsetDateTime,
) -> Vec<PipelineDecision> {
    pay_at_once(p, [chain, chain], now)
}

/// One payment from each of two chains, sent at the same moment.
fn pay_at_once(
    p: &Arc<Pipeline>,
    chains: [&DelegationChain; 2],
    now: OffsetDateTime,
) -> Vec<PipelineDecision> {
    let start = Arc::new(Barrier::new(2));
    let threads: Vec<_> = chains
        .into_iter()
        .map(|chain| {
            let (p, chain, start) = (p.clone(), chain.clone(), start.clone());
            std::thread::spawn(move || {
                start.wait();
                let call = ToolCall::new("bank", "send", json!({"amount": 1500}));
                p.decide(&chain, &call, now)
            })
        })
        .collect();
    threads.into_iter().map(|t| t.join().unwrap()).collect()
}

#[test]
fn concurrent_calls_cannot_both_pass_a_run_usage_cap_sr55() {
    // The shipped example's "hard" cap: a run never sends more than 2000 in total.
    let (p, chain, now) = run(
        r#"
permit(principal, action, resource);
@id("run_spend_cap_2000")
forbid (principal, action == Action::"bank/send", resource)
when { context.input has amount && context.usage.amount + context.input.amount > 2000 };
"#,
        Limits::default(),
    );
    let out = pay_twice_at_once(&p, &chain, now);
    assert_eq!(out.iter().filter(|d| d.is_allow()).count(), 1, "{out:#?}");
    let denied = out.iter().find(|d| !d.is_allow()).unwrap();
    assert_eq!(denied.reason, attenuo_policy::REASON_POLICY_DENY);
    assert_eq!(denied.usage.map(|u| u.amount), Some(1500));
}

#[test]
fn concurrent_calls_cannot_both_pass_a_budget_rule_sr55() {
    // A policy over `context.budget`, which the store's charge does not re-check.
    let (p, chain, now) = run(
        r#"
permit(principal, action, resource);
@id("last_call_needs_an_approval")
@obligation("approval")
forbid (principal, action == Action::"bank/send", resource)
when { context.budget.calls_remaining <= 1 && !context.approval.present };
"#,
        Limits::default().with_calls(2),
    );
    let out = pay_twice_at_once(&p, &chain, now);
    let reasons: BTreeSet<&str> = out.iter().map(|d| d.reason.as_str()).collect();
    assert_eq!(
        reasons,
        BTreeSet::from([
            attenuo_policy::REASON_POLICY_ALLOW,
            attenuo_policy::REASON_APPROVAL_REQUIRED
        ]),
        "{out:#?}"
    );
}

/// The run lock is timed for every guarded decision, and a limit met only in the store's
/// charge transaction (the read saw room) is counted at `charge`, not `check`.
#[test]
fn metrics_time_the_run_lock_and_tell_a_charge_time_exhaustion() {
    let (p, chain, now) = run_with(
        "permit(principal, action, resource);",
        Limits::default().with_calls(1),
        true,
    );
    let call = ToolCall::new("bank", "send", json!({"amount": 1}));
    assert!(p.decide(&chain, &call, now).is_allow());
    let d = p.decide(&chain, &call, now);
    assert_eq!(d.reason, REASON_BUDGET_EXHAUSTED);
    assert_eq!(d.limit.as_ref().map(|l| l.kind), Some(LimitKind::Calls));
    let text = p.metrics().render();
    crate::metrics::check_text_format(&text).unwrap();
    for line in [
        "attenuo_budget_exhausted_total{kind=\"calls\",at=\"charge\"} 1\n",
        "attenuo_budget_exhausted_total{kind=\"calls\",at=\"check\"} 0\n",
        "attenuo_budget_charges_total{kind=\"calls\"} 1\n",
        "attenuo_run_lock_wait_seconds_count 2\n",
        "attenuo_run_lock_wait_seconds_bucket{le=\"+Inf\"} 2\n",
    ] {
        assert!(text.contains(line), "{line}{text}");
    }
    // A decision whose leases are not live never takes the lock.
    let dead = p.decide(&chain, &call, now + Duration::hours(2));
    assert_eq!(dead.reason, REASON_LEASE_EXPIRED);
    assert!(p
        .metrics()
        .render()
        .contains("attenuo_run_lock_wait_seconds_count 2\n"));
}

/// A user's daily cap over every run (run limits phase 3).
const USER_DAILY_CAP: &str = r#"
permit(principal, action, resource);
@id("user_daily_spend_cap_2000")
forbid (principal, action == Action::"bank/send", resource)
when { context.input has amount && context.usage.user_window.day.amount + context.input.amount > 2000 };
"#;

/// Two runs of one user hold different run stripes, so only the user stripe, taken after the
/// run's, keeps them from both reading the same window figure and both passing the cap.
#[test]
fn concurrent_runs_of_one_user_cannot_both_pass_a_window_cap() {
    let (p, a, now, b) = runs_with(USER_DAILY_CAP, Limits::default(), false, false);
    let stripe = |c: &DelegationChain| {
        let d =
            attenuo_core::digest::sha256_bytes(attenuo_core::chain_id_of(c).unwrap().as_bytes());
        usize::from_str_radix(&d[..8], 16).unwrap() % super::pipeline::RUN_LOCK_STRIPES_FOR_TESTS
    };
    assert_ne!(
        stripe(&a),
        stripe(&b),
        "the two runs must not share a run stripe"
    );
    let out = pay_at_once(&p, [&a, &b], now);
    assert_eq!(out.iter().filter(|d| d.is_allow()).count(), 1, "{out:#?}");
    let denied = out.iter().find(|d| !d.is_allow()).unwrap();
    assert_eq!(denied.reason, attenuo_policy::REASON_POLICY_DENY);
    assert_eq!(denied.usage.map(|u| u.user_window.day.amount), Some(1500));
    // The run's own usage is the other run's business: zero here.
    assert_eq!(denied.usage.map(|u| u.amount), Some(0));
    // Only the day kind is kept: the hour reads zero.
    assert_eq!(denied.usage.map(|u| u.user_window.hour.amount), Some(0));
    // Both decisions waited on the lock once.
    assert!(p
        .metrics()
        .render()
        .contains("attenuo_run_lock_wait_seconds_count 2\n"));
}

/// A window the store cannot read is the worst case: the amount rule overflows and denies,
/// with a diagnostic, and the call is not charged.
#[test]
fn an_unreadable_window_is_the_worst_case() {
    let (p, a, now, _) = runs_with(USER_DAILY_CAP, Limits::default(), false, true);
    let call = ToolCall::new("bank", "send", json!({"amount": 1}));
    let d = p.decide(&a, &call, now);
    assert!(!d.is_allow(), "{d:#?}");
    assert_eq!(
        d.usage.map(|u| u.user_window.day),
        Some(crate::authz::UNREADABLE_WINDOW)
    );
    assert!(
        d.diagnostics
            .iter()
            .any(|m| m.contains("per-user windows unreadable, worst case assumed")),
        "{:?}",
        d.diagnostics
    );
    // A count rule refuses too.
    let (p, a, now, _) = runs_with(
        "permit(principal, action, resource);\n\
         forbid (principal, action == Action::\"bank/send\", resource) \
         when { context.usage.user_window.hour.calls >= 5 };",
        Limits::default(),
        false,
        true,
    );
    assert_eq!(
        p.decide(&a, &call, now).reason,
        attenuo_policy::REASON_POLICY_DENY
    );
}

/// Sequentially, the second run sees what the first charged, and the record says so.
#[test]
fn a_new_run_does_not_reset_the_users_window() {
    let (p, a, now, b) = runs_with(USER_DAILY_CAP, Limits::default(), false, false);
    let call = ToolCall::new("bank", "send", json!({"amount": 1500}));
    assert!(p.decide(&a, &call, now).is_allow());
    let d = p.decide(&b, &call, now);
    assert_eq!(d.reason, attenuo_policy::REASON_POLICY_DENY, "{d:#?}");
    let small = ToolCall::new("bank", "send", json!({"amount": 500}));
    let d = p.decide(&b, &small, now);
    assert!(d.is_allow(), "{d:#?}");
    let w = d.usage.unwrap().user_window.day;
    assert_eq!((w.calls, w.amount), (1, 1500));
}
