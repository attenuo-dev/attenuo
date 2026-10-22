#![allow(dead_code)]

use std::collections::BTreeMap;

use onbehalf_core::chain::DEFAULT_MAX_DEPTH;
use onbehalf_core::{
    AgentId, Capability, CapabilitySet, Decision, DecisionRecord, DelegationChain, LeaseId,
    OriginatingUser, ToolCall,
};
use serde_json::json;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

pub fn t0() -> OffsetDateTime {
    datetime!(2026-10-22 21:00 UTC)
}

pub fn user(subject: &str) -> OriginatingUser {
    OriginatingUser {
        subject: subject.into(),
        issuer: "https://idp.example".into(),
        authenticated_at: t0(),
        attributes: BTreeMap::new(),
    }
}

/// A two-hop chain for `subject` with leases `l1` -> `l2`.
pub fn chain(subject: &str, leases: (&str, &str)) -> DelegationChain {
    let root = DelegationChain::root(
        user(subject),
        AgentId::new("agent:planner"),
        CapabilitySet::from_iter(vec![Capability::new("github", "*")]),
        t0(),
        Duration::hours(1),
        LeaseId::new(leases.0),
    )
    .unwrap();
    root.extend(
        AgentId::new("agent:coder"),
        CapabilitySet::from_iter(vec![Capability::new("github", "create_issue")]),
        t0(),
        Duration::minutes(30),
        LeaseId::new(leases.1),
        DEFAULT_MAX_DEPTH,
    )
    .unwrap()
}

pub fn record_for(chain: &DelegationChain, i: usize, decision: Decision) -> DecisionRecord {
    let call = ToolCall::new(
        "github",
        "create_issue",
        json!({"repo": "acme/x", "title": format!("issue {i}")}),
    )
    .with_session(format!("sess-{}", i % 3));
    let reason = if decision.is_allow() {
        "policy_allow"
    } else {
        "policy_deny"
    };
    DecisionRecord::new(
        t0() + Duration::seconds(i as i64),
        decision,
        reason,
        chain,
        &call,
        vec![format!("policy-{}", i % 2)],
    )
}

pub fn record(i: usize) -> DecisionRecord {
    let c = chain("user:mudit", ("l1", "l2"));
    record_for(
        &c,
        i,
        if i % 2 == 0 {
            Decision::Allow
        } else {
            Decision::Deny
        },
    )
}
