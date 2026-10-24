//! Run limits in the policy engine (ADR-0010): the always-present `context.budget` attributes
//! and the refusal the server sets, which denies in the capability stage, before Cedar.

use std::path::Path;

use attenuo_core::limits::{REASON_BUDGET_ERROR, REASON_BUDGET_EXHAUSTED};
use attenuo_core::{AgentId, Capability, CapabilitySet, DelegationChain, LeaseId, OriginatingUser};
use attenuo_core::{Decision, ToolCall};
use attenuo_policy::testing::TestFile;
use attenuo_policy::{
    ApprovalContext, BudgetContext, BudgetRefusal, CallLabels, PolicyEngineBuilder, ToolAttrs,
    ToolCatalog, REASON_CAPABILITY_DENIED, REASON_POLICY_ALLOW, REASON_POLICY_DENY,
};
use serde_json::json;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

fn now() -> OffsetDateTime {
    datetime!(2026-10-24 09:00 UTC)
}

fn chain() -> DelegationChain {
    DelegationChain::root(
        OriginatingUser {
            subject: "alice".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: now() - Duration::minutes(1),
            attributes: Default::default(),
        },
        AgentId::new("assistant"),
        CapabilitySet::from_iter([Capability::new("bank", "send")]),
        now(),
        Duration::hours(1),
        LeaseId::new("run-1"),
    )
    .unwrap()
}

fn engine(policies: &str) -> attenuo_policy::PolicyEngine {
    PolicyEngineBuilder::new()
        .with_catalog(
            ToolCatalog::new()
                .with("bank", "send", ToolAttrs::new())
                .with("bank", "other", ToolAttrs::new()),
        )
        .with_policies_str(policies)
        .build()
        .unwrap()
}

/// Every attribute is present with its default when no limit applies, so a policy needs no
/// `has` guard, and the figures the server computes reach Cedar.
#[test]
fn budget_attributes_are_always_present() {
    let e = engine(
        r#"
@id("defaults")
permit (principal, action, resource)
when {
  !context.budget.limited &&
  context.budget.calls_remaining == 9223372036854775807 &&
  context.budget.amount_remaining == 9223372036854775807 &&
  context.budget.destination_new
};
@id("figures")
permit (principal, action, resource)
when {
  context.budget.limited &&
  context.budget.calls_remaining == 2 &&
  context.budget.amount_remaining == 40 &&
  !context.budget.destination_new
};
"#,
    );
    let call = ToolCall::new("bank", "send", json!({"amount": 1}));
    let o = e.authorize(&chain(), &call, now());
    assert_eq!(o.reason, REASON_POLICY_ALLOW);
    assert_eq!(o.policy_ids, vec!["defaults".to_string()]);
    let labels = CallLabels {
        budget: BudgetContext {
            limited: true,
            calls_remaining: 2,
            amount_remaining: 40,
            destination_new: false,
            refusal: None,
        },
        ..Default::default()
    };
    let o = e.authorize_labelled(&chain(), &call, &labels, now());
    assert_eq!(o.reason, REASON_POLICY_ALLOW);
    assert_eq!(o.policy_ids, vec!["figures".to_string()]);
}

/// A token limit is hard: the refusal wins over every permit and any approval, and the
/// capability check still comes first.
#[test]
fn token_budget_cannot_be_approved_past() {
    let e = engine("@id(\"all\") permit (principal, action, resource);");
    let refused = |reason: &str| CallLabels {
        approval: ApprovalContext::by("user"),
        budget: BudgetContext {
            limited: true,
            calls_remaining: 0,
            refusal: Some(BudgetRefusal {
                reason: reason.into(),
                detail: "limit `calls` of hop 0: max 1, used 1".into(),
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    let call = ToolCall::new("bank", "send", json!({}));
    for reason in [REASON_BUDGET_EXHAUSTED, REASON_BUDGET_ERROR] {
        let o = e.authorize_labelled(&chain(), &call, &refused(reason), now());
        assert_eq!(o.decision, Decision::Deny);
        assert_eq!(o.reason, reason);
        assert!(o.policy_ids.is_empty(), "decided before Cedar");
    }
    let outside = ToolCall::new("bank", "other", json!({}));
    let o = e.authorize_labelled(&chain(), &outside, &refused(REASON_BUDGET_EXHAUSTED), now());
    assert_eq!(o.reason, REASON_CAPABILITY_DENIED);
    // And a plain forbid reading the figures still works as a policy deny.
    let e = engine(
        "@id(\"all\") permit (principal, action, resource);\n\
         @id(\"low\") forbid (principal, action, resource) when { context.budget.amount_remaining < 10 };",
    );
    let low = CallLabels {
        budget: BudgetContext {
            limited: true,
            amount_remaining: 5,
            ..Default::default()
        },
        ..Default::default()
    };
    assert_eq!(
        e.authorize_labelled(&chain(), &call, &low, now()).reason,
        REASON_POLICY_DENY
    );
}

#[test]
fn shipped_run_limit_policies_pass_their_tests() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policies/run-limits_test.yaml");
    let report = TestFile::load(&path).unwrap().run().unwrap();
    for case in &report.cases {
        assert!(
            case.passed,
            "{}: {:?} {:?}",
            case.name, case.failures, case.error
        );
    }
    assert!(report.cases.len() >= 7);
}
