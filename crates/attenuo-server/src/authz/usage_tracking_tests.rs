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
use std::sync::{Arc, RwLock};
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
    let pipeline = Pipeline::new(Arc::new(RwLock::new(engine)), leases.clone(), audit.clone());
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
        self.pipeline.policy().read().unwrap().tracks_usage()
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
    s.pipeline
        .policy()
        .write()
        .unwrap()
        .reload_policies_str(READS_USAGE)
        .unwrap();
    assert!(s.tracks());
    // Usage counts from the reload on: the call before it was not kept.
    assert_eq!(s.pay().usage, Some(UsageContext::default()));
    assert_eq!(s.pay().usage.map(|u| u.calls), Some(1));
    let rows = s.usage_rows();
    assert!(rows > 0);
    s.pipeline
        .policy()
        .write()
        .unwrap()
        .reload_policies_str(PLAIN)
        .unwrap();
    assert!(!s.tracks());
    assert_eq!(s.pay().usage, None);
    assert!(!s.last_record_has_usage());
    assert_eq!(s.usage_rows(), rows, "no usage written after the reload");
}
