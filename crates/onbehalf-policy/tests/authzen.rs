//! AuthZEN mapping: request and response round-trips, wire format, and serving an AuthZEN
//! request through the engine.

use onbehalf_core::{
    AgentId, Capability, CapabilitySet, Decision, DelegationChain, LeaseId, OriginatingUser,
    ToolCall,
};
use onbehalf_policy::authzen::{
    from_outcome, to_chain_and_call, to_outcome, to_request, EvaluationRequest, EvaluationResponse,
};
use onbehalf_policy::{
    ArgType, Outcome, PolicyEngineBuilder, PolicyError, ToolAttrs, ToolCatalog, REASON_POLICY_ALLOW,
};
use serde_json::json;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

fn now() -> OffsetDateTime {
    datetime!(2026-10-22 21:00 UTC)
}

fn chain() -> DelegationChain {
    let user = OriginatingUser {
        subject: "alice".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: now() - Duration::minutes(5),
        attributes: [("mfa".to_string(), json!(true))].into_iter().collect(),
    };
    DelegationChain::root(
        user,
        AgentId::new("coder"),
        CapabilitySet::from_iter([Capability::new("github", "*")]),
        now(),
        Duration::hours(1),
        LeaseId::new("l1"),
    )
    .unwrap()
}

fn call() -> ToolCall {
    ToolCall::new(
        "github",
        "create_issue",
        json!({"repo": "acme/api", "title": "x"}),
    )
    .with_session("s1")
}

#[test]
fn request_round_trips_through_json() {
    let (chain, call) = (chain(), call());
    let req = to_request(&chain, &call);
    assert_eq!(req.subject.r#type, "agent");
    assert_eq!(req.subject.id, "coder");
    assert_eq!(req.action.name, "create_issue");
    assert_eq!(req.resource.r#type, "tool");
    assert_eq!(req.resource.id, "github/create_issue");

    let wire = serde_json::to_value(&req).unwrap();
    // AuthZEN field names, not Rust ones.
    assert_eq!(wire["subject"]["type"], "agent");
    assert_eq!(wire["resource"]["type"], "tool");
    assert_eq!(wire["action"]["properties"]["server"], "github");
    assert_eq!(wire["context"]["input"]["repo"], "acme/api");
    assert_eq!(wire["context"]["session_id"], "s1");

    let back: EvaluationRequest = serde_json::from_value(wire).unwrap();
    assert_eq!(back, req);
    let (chain2, call2) = to_chain_and_call(&back).unwrap();
    assert_eq!(chain2, chain);
    assert_eq!(call2, call);
    assert_eq!(chain2.digest(), chain.digest());
}

#[test]
fn request_without_chain_or_with_wrong_subject_is_rejected() {
    let mut req = to_request(&chain(), &call());
    req.subject.properties = None;
    assert!(matches!(
        to_chain_and_call(&req),
        Err(PolicyError::Parse(_))
    ));

    let mut req = to_request(&chain(), &call());
    req.subject.id = "someone-else".into();
    assert!(matches!(
        to_chain_and_call(&req),
        Err(PolicyError::Parse(_))
    ));

    let mut req = to_request(&chain(), &call());
    req.subject.r#type = "user".into();
    assert!(matches!(
        to_chain_and_call(&req),
        Err(PolicyError::Parse(_))
    ));
}

#[test]
fn server_falls_back_to_resource_id() {
    let mut req = to_request(&chain(), &call());
    req.action.properties = None;
    req.resource.properties = None;
    let (_, call) = to_chain_and_call(&req).unwrap();
    assert_eq!(call.server, "github");
    assert_eq!(call.tool, "create_issue");
}

#[test]
fn outcome_round_trips_through_response() {
    let outcome = Outcome {
        decision: Decision::Deny,
        reason: "policy_deny".into(),
        policy_ids: vec!["forbid_deep_chains".into()],
        diagnostics: vec!["note".into()],
    };
    let resp = from_outcome(&outcome);
    assert!(!resp.decision);
    let wire = serde_json::to_value(&resp).unwrap();
    assert_eq!(wire["decision"], false);
    assert_eq!(wire["context"]["reason"], "policy_deny");
    assert_eq!(wire["context"]["policy_ids"][0], "forbid_deep_chains");
    let back: EvaluationResponse = serde_json::from_value(wire).unwrap();
    assert_eq!(to_outcome(&back), outcome);

    // A bare response still maps to a sane outcome.
    let bare: EvaluationResponse = serde_json::from_value(json!({"decision": true})).unwrap();
    let o = to_outcome(&bare);
    assert_eq!(o.decision, Decision::Allow);
    assert!(o.reason.is_empty() && o.policy_ids.is_empty());
}

#[test]
fn engine_serves_authzen_requests() {
    let engine = PolicyEngineBuilder::new()
        .with_catalog(ToolCatalog::new().with(
            "github",
            "create_issue",
            ToolAttrs::new().with_input("repo", ArgType::String),
        ))
        .with_policies_str(
            r#"@id("acme") permit(principal, action == Action::"github/create_issue", resource)
               when { context.input has repo && context.input.repo like "acme/*" };"#,
        )
        .build()
        .unwrap();
    let req = to_request(&chain(), &call());
    let resp = engine.evaluate(&req, now()).unwrap();
    assert!(resp.decision);
    let ctx = resp.context.unwrap();
    assert_eq!(ctx["reason"], REASON_POLICY_ALLOW);
    assert_eq!(ctx["policy_ids"], json!(["acme"]));

    let direct = engine.authorize(&chain(), &call(), now());
    assert_eq!(direct.decision, Decision::Allow);
}
