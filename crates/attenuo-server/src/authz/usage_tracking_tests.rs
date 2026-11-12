//! Run usage is kept only when it can matter ([`PolicyEngine::tracks_usage`]): a policy
//! set that does not read `context.usage`, with no catalog `amount` or `destination`,
//! writes no usage counter and records no `usage`.

use super::*;
use attenuo_audit::{AuditSink, LeaseStore};
use attenuo_audit::{MemoryAudit, SqliteLeaseStore};
use attenuo_core::{AgentId, Capability, CapabilitySet, OriginatingUser};
use attenuo_core::{DelegationChain, LeaseId, ToolCall};
use attenuo_policy::UsageContext;
use attenuo_policy::{ArgType, PolicyEngineBuilder, ToolAttrs, ToolCatalog, TrackUsage};
use serde_json::json;
use std::sync::Arc;
use time::Duration;
use time::OffsetDateTime;

const PLAIN: &str = r#"
permit(principal, action, resource);
@id("no_big_payments")
forbid(principal, action == Action::"bank/send", resource)
when { context.input has amount && context.input.amount > 1000 };
"#;

const READS_USAGE: &str = r#"
permit(principal, action, resource);
@id("cap_run_calls")
forbid(principal, action == Action::"bank/send", resource)
when { context.usage.calls >= 2 };
"#;

struct Setup {
    pipeline: Pipeline,
    leases: Arc<SqliteLeaseStore>,
    audit: Arc<MemoryAudit>,
    chain: DelegationChain,
    now: OffsetDateTime,
}

fn setup(policies: &str, amount: bool, track: TrackUsage) -> Setup {
    let now = OffsetDateTime::now_utc();
    let leases = Arc::new(SqliteLeaseStore::open_in_memory().unwrap());
    leases
        .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
        .unwrap();
    let mut attrs = ToolAttrs::new().with_input("amount", ArgType::Long);
    if amount {
        attrs = attrs.with_amount("amount");
    }
    let engine = PolicyEngineBuilder::new()
        .with_catalog(ToolCatalog::new().with("bank", "send", attrs))
        .with_policies_str(policies)
        .with_track_usage(track)
        .build()
        .unwrap();
    let audit = Arc::new(MemoryAudit::new());
    let pipeline = Pipeline::new(
        Arc::new(SharedPolicy::new(engine)),
        leases.clone(),
        audit.clone(),
    );
    let chain = DelegationChain::root(
        OriginatingUser {
            subject: "alice".into(),
            issuer: "idp".into(),
            authenticated_at: now,
            attributes: Default::default(),
        },
        AgentId::new("planner"),
        CapabilitySet::from_iter([Capability::new("bank", "send")]),
        now,
        Duration::hours(1),
        LeaseId::new("l1"),
    )
    .unwrap();
    Setup {
        pipeline,
        leases,
        audit,
        chain,
        now,
    }
}

impl Setup {
    fn pay(&self) -> PipelineDecision {
        let call = ToolCall::new("bank", "send", json!({ "amount": 5 }));
        self.pipeline.decide(&self.chain, &call, self.now)
    }

    /// The run-usage counters in the store.
    fn usage_rows(&self) -> i64 {
        self.leases
            .with_connection(|c| {
                Ok(c.query_row(
                    "SELECT count(*) FROM budget_counters WHERE kind LIKE 'usage_%'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap()
    }

    fn tracks(&self) -> bool {
        self.pipeline.policy().snapshot().tracks_usage()
    }

    fn last_record_has_usage(&self) -> bool {
        let entries = self.audit.range(0, 1000).unwrap();
        entries.last().unwrap().record.usage.is_some()
    }
}

#[test]
fn a_policy_set_that_cannot_read_usage_writes_none() {
    let s = setup(PLAIN, false, TrackUsage::Auto);
    assert!(!s.tracks());
    for _ in 0..3 {
        let d = s.pay();
        assert!(d.is_allow(), "{d:?}");
        assert_eq!(d.usage, None);
        assert!(d.charged.is_none());
        assert!(!s.last_record_has_usage());
    }
    assert_eq!(s.usage_rows(), 0);
}

#[test]
fn a_policy_that_reads_usage_turns_it_on() {
    let s = setup(READS_USAGE, false, TrackUsage::Auto);
    assert!(s.tracks());
    assert_eq!(s.pay().usage, Some(UsageContext::default()));
    assert!(s.last_record_has_usage());
    assert!(s.pay().is_allow());
    // The third sees two calls and is refused by the policy.
    let d = s.pay();
    assert!(!d.is_allow(), "{d:?}");
    assert_eq!(d.usage.map(|u| u.calls), Some(2));
    assert!(s.usage_rows() > 0);
}

#[test]
fn a_catalog_amount_turns_it_on() {
    let s = setup(PLAIN, true, TrackUsage::Auto);
    assert!(s.tracks());
    s.pay();
    let d = s.pay();
    assert_eq!(
        d.usage,
        Some(UsageContext {
            calls: 1,
            amount: 5,
            destination_seen: false,
            ..Default::default()
        })
    );
    assert!(s.usage_rows() > 0);
}

#[test]
fn track_usage_true_forces_it() {
    let s = setup(PLAIN, false, TrackUsage::Always);
    assert!(s.tracks());
    s.pay();
    assert_eq!(s.pay().usage.map(|u| u.calls), Some(1));
    assert!(s.usage_rows() > 0);
}

#[test]
fn reload_flips_it() {
    let s = setup(PLAIN, false, TrackUsage::Auto);
    s.pay();
    assert_eq!(s.usage_rows(), 0);
    s.pipeline.policy().swap(Arc::new(
        s.pipeline
            .policy_snapshot()
            .with_policies_reloaded(READS_USAGE)
            .unwrap(),
    ));
    assert!(s.tracks());
    // Usage counts from the reload on: the call before it was not kept.
    assert_eq!(s.pay().usage, Some(UsageContext::default()));
    assert_eq!(s.pay().usage.map(|u| u.calls), Some(1));
    let rows = s.usage_rows();
    assert!(rows > 0);
    s.pipeline.policy().swap(Arc::new(
        s.pipeline
            .policy_snapshot()
            .with_policies_reloaded(PLAIN)
            .unwrap(),
    ));
    assert!(!s.tracks());
    assert_eq!(s.pay().usage, None);
    assert!(!s.last_record_has_usage());
    assert_eq!(s.usage_rows(), rows, "no usage written after the reload");
}

/// Generation A: its only permit reads `context.usage`, so run usage is kept.
const GEN_A: &str = r#"
@id("gen_a_permit")
permit(principal, action, resource) when { context.usage.calls >= 0 };
"#;

/// Generation B: disjoint ids, and nothing reads usage, so none is kept.
const GEN_B: &str = r#"
@id("gen_b_permit")
permit(principal, action, resource);
"#;

/// Whether `d` was decided by one generation throughout: the run-state stage (whether usage
/// was read) and the policy stage (which permit allowed it) agree.
fn one_generation(d: &PipelineDecision) -> bool {
    match d.policy_ids.as_slice() {
        [id] if id == "gen_a_permit" => d.usage.is_some(),
        [id] if id == "gen_b_permit" => d.usage.is_none(),
        _ => false,
    }
}

fn reload(p: &Pipeline, text: &str) {
    p.policy().swap(Arc::new(
        p.policy_snapshot().with_policies_reloaded(text).unwrap(),
    ));
}

/// A-8: a reload that lands between the stages of a decision does not reach it; the decision
/// finishes on the policy set it started with, and the next one uses the new set.
#[test]
fn a_reload_mid_decision_does_not_mix_policy_sets() {
    let s = setup(GEN_A, false, TrackUsage::Auto);
    let target = Arc::new(
        s.pipeline
            .policy_snapshot()
            .with_policies_reloaded(GEN_B)
            .unwrap(),
    );
    let shared = Arc::clone(s.pipeline.policy());
    *s.pipeline.mid_decision_hook.lock().unwrap() = Some(Box::new(move || {
        shared.swap(Arc::clone(&target));
    }));
    let d = s.pay();
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(d.policy_ids, ["gen_a_permit"]);
    assert!(
        d.usage.is_some(),
        "the run-state stage and the policy stage saw generation A"
    );
    assert!(s.last_record_has_usage());
    *s.pipeline.mid_decision_hook.lock().unwrap() = None;
    let d = s.pay();
    assert_eq!(d.policy_ids, ["gen_b_permit"]);
    assert!(d.usage.is_none());
}

/// A-8, raced: decisions on four threads while another reloads between two policy sets with
/// disjoint ids as fast as it can. Every decision comes from one set.
#[test]
fn reloads_racing_decisions_never_yield_a_mixed_decision() {
    let s = setup(GEN_A, false, TrackUsage::Auto);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let (seen_a, seen_b) = std::thread::scope(|scope| {
        let reloader = scope.spawn(|| {
            let mut n = 0u32;
            while !stop.load(std::sync::atomic::Ordering::Acquire) {
                reload(&s.pipeline, if n.is_multiple_of(2) { GEN_B } else { GEN_A });
                n += 1;
            }
            n
        });
        let deciders: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    // Stops the reloader when an assertion below fails, so a failure fails
                    // the test instead of hanging it.
                    struct StopOnPanic<'a>(&'a std::sync::atomic::AtomicBool);
                    impl Drop for StopOnPanic<'_> {
                        fn drop(&mut self) {
                            if std::thread::panicking() {
                                self.0.store(true, std::sync::atomic::Ordering::Release);
                            }
                        }
                    }
                    let _stop = StopOnPanic(&stop);
                    let (mut a, mut b) = (0, 0);
                    for _ in 0..150 {
                        let d = s.pay();
                        assert!(d.is_allow() && one_generation(&d), "mixed: {d:?}");
                        if d.usage.is_some() {
                            a += 1;
                        } else {
                            b += 1;
                        }
                    }
                    (a, b)
                })
            })
            .collect();
        let counts: Vec<(u32, u32)> = deciders.into_iter().map(|d| d.join().unwrap()).collect();
        stop.store(true, std::sync::atomic::Ordering::Release);
        assert!(reloader.join().unwrap() > 1, "the reloader ran");
        counts.iter().fold((0, 0), |(a, b), (x, y)| (a + x, b + y))
    });
    // The records agree with the answers: one generation each.
    for e in s.audit.range(0, 10_000).unwrap() {
        let r = &e.record;
        let ok = match r.policy_ids.as_slice() {
            [id] if id == "gen_a_permit" => r.usage.is_some(),
            [id] if id == "gen_b_permit" => r.usage.is_none(),
            _ => false,
        };
        assert!(ok, "record {} mixes generations: {r:?}", e.seq);
    }
    assert_eq!(seen_a + seen_b, 600);
}
