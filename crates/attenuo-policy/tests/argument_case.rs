//! An argument name that differs only in case from a name the decision reads is refused
//! (`argument_case_mismatch`, the remainder of SR-133): an upstream that matches names without
//! regard to case (Go's `encoding/json`) reads `Path` as `path`, which every check saw absent.

use attenuo_core::{
    AgentId, ArgConstraint, ArgLimit, Capability, CapabilitySet, Decision, DelegationChain, Derive,
    LeaseId, Limits, OriginatingUser, ToolCall,
};
use attenuo_policy::{
    ArgLabels, ArgType, CallLabels, PolicyEngine, PolicyEngineBuilder, ToolAttrs, ToolCatalog,
    UnknownTools, REASON_ARGUMENT_CASE_MISMATCH, REASON_CAPABILITY_DENIED, REASON_POLICY_DENY,
};
use serde_json::{json, Value};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

fn now() -> OffsetDateTime {
    datetime!(2026-11-15 12:00 UTC)
}

fn chain(caps: Vec<Capability>) -> DelegationChain {
    DelegationChain::root(
        OriginatingUser {
            subject: "alice".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: now() - Duration::minutes(5),
            attributes: Default::default(),
        },
        AgentId::new("coder"),
        CapabilitySet::from_iter(caps),
        now(),
        Duration::hours(1),
        LeaseId::new("l1"),
    )
    .unwrap()
}

fn wide() -> DelegationChain {
    chain(vec![Capability::new("fs", "*")])
}

fn engine(attrs: ToolAttrs, policies: &str) -> PolicyEngine {
    PolicyEngineBuilder::new()
        .with_catalog(ToolCatalog::new().with("fs", "read_file", attrs))
        .with_policies_str(policies)
        .build()
        .unwrap()
}

const PERMIT: &str = "permit(principal, action, resource);";

fn call(args: Value) -> ToolCall {
    ToolCall::new("fs", "read_file", args)
}

fn reason(e: &PolicyEngine, c: &DelegationChain, args: Value) -> String {
    e.authorize(c, &call(args), now()).reason
}

/// (1) A constraint on `path`, of every operator: `Path` alone is refused for its case. The
/// claim the pass 19 note makes is checked too: without the argument at all, every operator
/// refuses it as absent (`capability_denied`), so a constraint was never "nothing to check".
#[test]
fn a_constraint_on_path_refuses_path_in_another_case() {
    let e = engine(ToolAttrs::new(), PERMIT);
    for c in [
        ArgConstraint::Equals(json!("/w/a")),
        ArgConstraint::OneOf(vec![json!("/w/a")]),
        ArgConstraint::Prefix("/w/".into()),
        ArgConstraint::path_prefix("/w").unwrap(),
        ArgConstraint::range(Some(0), Some(10)).unwrap(),
    ] {
        let ch = chain(vec![
            Capability::new("fs", "read_file").with_constraint("path", c.clone())
        ]);
        assert_eq!(
            reason(&e, &ch, json!({"Path": "/etc/passwd"})),
            REASON_ARGUMENT_CASE_MISMATCH,
            "{c:?}"
        );
        assert_eq!(
            reason(&e, &ch, json!({})),
            REASON_CAPABILITY_DENIED,
            "{c:?}"
        );
        assert_eq!(
            reason(&e, &ch, json!({"other": 1})),
            REASON_CAPABILITY_DENIED,
            "{c:?}"
        );
        assert_eq!(
            reason(&e, &ch, json!({"path": null})),
            REASON_CAPABILITY_DENIED
        );
    }
}

/// (2) A forbid that reads `context.input.path` behind `has` did not fire on `Path`.
#[test]
fn a_forbid_behind_has_cannot_be_dodged_by_case() {
    let policies = r#"permit(principal, action, resource);
        @id("no-etc")
        forbid(principal, action, resource) when {
          context.input has path && context.input.path like "/etc/*" };"#;
    let e = engine(
        ToolAttrs::new().with_input("path", ArgType::String),
        policies,
    );
    let ch = wide();
    assert_eq!(
        reason(&e, &ch, json!({"path": "/etc/passwd"})),
        REASON_POLICY_DENY
    );
    assert_eq!(
        reason(&e, &ch, json!({"Path": "/etc/passwd"})),
        REASON_ARGUMENT_CASE_MISMATCH
    );
    // Undeclared in the catalog: the guarded read still loads and runs, and is still known.
    let e = engine(ToolAttrs::new(), policies);
    assert_eq!(
        reason(&e, &ch, json!({"path": "/etc/passwd"})),
        REASON_POLICY_DENY
    );
    let out = e.authorize(&ch, &call(json!({"PATH": "/etc/passwd"})), now());
    assert_eq!(out.reason, REASON_ARGUMENT_CASE_MISMATCH);
    assert_eq!(out.decision, Decision::Deny);
    assert!(
        out.diagnostics[0].contains("\"PATH\"") && out.diagnostics[0].contains("\"path\""),
        "{:?}",
        out.diagnostics
    );
    assert!(!out.diagnostics[0].contains("passwd"), "never the value");
    // `context.input["path"]` is the same read.
    let e = engine(
        ToolAttrs::new(),
        r#"permit(principal, action, resource);
           forbid(principal, action, resource) when {
             context.input has path && context.input["path"] == "/x" };"#,
    );
    assert_eq!(
        reason(&e, &ch, json!({"pAth": "/x"})),
        REASON_ARGUMENT_CASE_MISMATCH
    );
    // A policy scoped to another tool is still read: the names are collected from every
    // policy, not per action.
    let e = PolicyEngineBuilder::new()
        .with_catalog(
            ToolCatalog::new()
                .with("fs", "read_file", ToolAttrs::new())
                .with(
                    "fs",
                    "write_file",
                    ToolAttrs::new().with_input("path", ArgType::String),
                ),
        )
        .with_policies_str(
            r#"permit(principal, action, resource);
               forbid(principal, action == Action::"fs/write_file", resource) when {
                 context.input has path && context.input.path like "/etc/*" };"#,
        )
        .build()
        .unwrap();
    assert_eq!(
        reason(&e, &ch, json!({"Path": "/x"})),
        REASON_ARGUMENT_CASE_MISMATCH
    );
}

/// (3, policy side) A policy that names an argument in `context.untrusted_args` matched no
/// argument `Path`; the name is read from the policy, and an outbound input from the catalog.
#[test]
fn names_compared_with_untrusted_args_and_outbound_inputs_are_known() {
    let e = engine(
        ToolAttrs::new(),
        r#"permit(principal, action, resource);
           forbid(principal, action, resource) when { context.untrusted_args.contains("path") };"#,
    );
    let ch = wide();
    let tainted = |arg: &str| CallLabels {
        args: ArgLabels::from_args([arg]),
        ..CallLabels::default()
    };
    let out = e.authorize_labelled(&ch, &call(json!({"path": "x"})), &tainted("path"), now());
    assert_eq!(out.reason, REASON_POLICY_DENY);
    let out = e.authorize_labelled(&ch, &call(json!({"Path": "x"})), &tainted("Path"), now());
    assert_eq!(out.reason, REASON_ARGUMENT_CASE_MISMATCH);
    // Reversed and as a set.
    let e = engine(
        ToolAttrs::new(),
        r#"permit(principal, action, resource);
           forbid(principal, action, resource) when {
             ["url", "body"].containsAny(context.untrusted_args) };"#,
    );
    assert_eq!(
        reason(&e, &ch, json!({"URL": "x"})),
        REASON_ARGUMENT_CASE_MISMATCH
    );
    assert_eq!(
        reason(&e, &ch, json!({"Body": "x"})),
        REASON_ARGUMENT_CASE_MISMATCH
    );

    // `context.untrusted_outbound` is computed from the catalog's outbound names.
    let e = engine(
        ToolAttrs::new().with_outbound("url#host"),
        r#"permit(principal, action, resource);
           forbid(principal, action, resource) when { context.untrusted_outbound };"#,
    );
    let out = e.authorize_labelled(
        &ch,
        &call(json!({"url": "https://e.x"})),
        &tainted("url"),
        now(),
    );
    assert_eq!(out.reason, REASON_POLICY_DENY);
    let out = e.authorize_labelled(
        &ch,
        &call(json!({"Url": "https://e.x"})),
        &tainted("Url"),
        now(),
    );
    assert_eq!(out.reason, REASON_ARGUMENT_CASE_MISMATCH);
}

/// (4, policy side) A run limit's argument is known; the server's limit stage is tested in
/// attenuo-server.
#[test]
fn a_limit_argument_is_known_at_every_hop() {
    let e = engine(ToolAttrs::new(), PERMIT);
    for limits in [
        Limits::default().with_sum("amount", 100),
        Limits::default().with_distinct("to", 3),
        Limits::default().with_calls_per("to", 3),
        Limits {
            distinct: Some(ArgLimit::new("url", 3).derived(Derive::Host)),
            ..Limits::default()
        },
    ] {
        let arg = [&limits.sum, &limits.distinct, &limits.calls_per]
            .into_iter()
            .flatten()
            .next()
            .unwrap()
            .arg
            .to_uppercase();
        // The limit on the root hop, a narrower hop after it without one.
        let ch = chain(vec![Capability::new("fs", "*").with_limits(limits.clone())])
            .extend(
                AgentId::new("sub"),
                CapabilitySet::from_iter([
                    Capability::new("fs", "read_file").with_limits(limits.clone())
                ]),
                now(),
                Duration::minutes(5),
                LeaseId::new("l2"),
                8,
            )
            .unwrap();
        assert_eq!(
            reason(&e, &ch, json!({ arg.clone(): 5 })),
            REASON_ARGUMENT_CASE_MISMATCH,
            "{limits:?}"
        );
    }
}

/// (5) Derived values: `#host` of a catalog destination or outbound input, and the run usage
/// `amount`, all read the named argument.
#[test]
fn catalog_derived_names_are_known() {
    let ch = wide();
    for attrs in [
        ToolAttrs::new().with_destination("url#host"),
        ToolAttrs::new().with_outbound("url#host"),
        ToolAttrs::new().with_outbound("url"),
    ] {
        let e = engine(attrs.clone(), PERMIT);
        assert_eq!(
            reason(&e, &ch, json!({"URL": "https://evil.example/"})),
            REASON_ARGUMENT_CASE_MISMATCH,
            "{attrs:?}"
        );
        assert!(e
            .authorize(&ch, &call(json!({"url": "https://ok.example/"})), now())
            .decision
            .is_allow());
    }
    let e = engine(
        ToolAttrs::new()
            .with_amount("amount")
            .with_input("amount", ArgType::Long),
        PERMIT,
    );
    assert_eq!(
        reason(&e, &ch, json!({"Amount": 5000})),
        REASON_ARGUMENT_CASE_MISMATCH
    );
}

/// (6) The catalog type check skipped `Count` (an undeclared argument); a `decimal` input too.
#[test]
fn declared_inputs_are_known() {
    let e = engine(
        ToolAttrs::new()
            .with_input("count", ArgType::Long)
            .with_input("price", ArgType::Decimal),
        PERMIT,
    );
    let ch = wide();
    assert_eq!(
        reason(&e, &ch, json!({"count": "x"})),
        attenuo_policy::REASON_INPUT_TYPE_MISMATCH
    );
    assert_eq!(
        reason(&e, &ch, json!({"Count": "x"})),
        REASON_ARGUMENT_CASE_MISMATCH
    );
    assert_eq!(
        reason(&e, &ch, json!({"PRICE": 1.234567})),
        REASON_ARGUMENT_CASE_MISMATCH
    );
}

/// Go folds the long s to `s` and the Kelvin sign to `k`: both are refused as `ask` and `key`.
#[test]
fn unicode_folds_are_refused() {
    let e = engine(
        ToolAttrs::new()
            .with_input("ask", ArgType::String)
            .with_input("key", ArgType::String),
        PERMIT,
    );
    let ch = wide();
    assert_eq!(
        reason(&e, &ch, json!({"a\u{17f}k": "x"})),
        REASON_ARGUMENT_CASE_MISMATCH
    );
    assert_eq!(
        reason(&e, &ch, json!({"\u{212a}ey": "x"})),
        REASON_ARGUMENT_CASE_MISMATCH
    );
}

/// Exact names, unrelated names and nested names pass; a tool nothing is known about passes
/// whatever the case, as before (this case cannot be closed without the tool's schema).
#[test]
fn exact_unrelated_nested_and_unknown_names_pass() {
    let policies = r#"permit(principal, action, resource);
        forbid(principal, action, resource) when {
          context.input has path && context.input.path like "/etc/*" };"#;
    let e = engine(
        ToolAttrs::new().with_input("path", ArgType::String),
        policies,
    );
    let ch = chain(vec![Capability::new("fs", "read_file")
        .with_constraint("mode", ArgConstraint::OneOf(vec![json!("r")]))]);
    for ok in [
        json!({"path": "/w/a", "mode": "r"}),
        json!({"path": "/w/a", "mode": "r", "Other": 1, "MODEL": 2}),
        // Below the top level nothing reads a name.
        json!({"path": "/w/a", "mode": "r", "filter": {"Path": "/etc/passwd"}}),
    ] {
        assert!(
            e.authorize(&ch, &call(ok.clone()), now())
                .decision
                .is_allow(),
            "{ok}"
        );
    }
    assert_eq!(
        reason(&e, &ch, json!({"path": "/w", "Mode": "r"})),
        REASON_ARGUMENT_CASE_MISMATCH
    );

    // Nothing known: no catalog entry, no constraint, no policy reading the name.
    let open = PolicyEngineBuilder::new()
        .with_unknown_tools(UnknownTools::Allow)
        .with_policies_str(PERMIT)
        .build()
        .unwrap();
    let ch = chain(vec![Capability::new("other", "*")]);
    let out = open.authorize(
        &ch,
        &ToolCall::new("other", "tool", json!({"Path": "/etc/passwd"})),
        now(),
    );
    assert!(out.decision.is_allow(), "{out:?}");
}

/// An exact name of the tool's own passes although a policy for another tool reads a name
/// that differs from it only in case; two names of its own in different cases refuse both.
#[test]
fn own_exact_names_win_over_other_tools_names() {
    let e = PolicyEngineBuilder::new()
        .with_catalog(
            ToolCatalog::new()
                .with(
                    "fs",
                    "read_file",
                    ToolAttrs::new().with_input("Path", ArgType::String),
                )
                .with(
                    "fs",
                    "write_file",
                    ToolAttrs::new().with_input("path", ArgType::String),
                ),
        )
        .with_policies_str(
            r#"permit(principal, action, resource);
               forbid(principal, action == Action::"fs/write_file", resource) when {
                 context.input has path && context.input.path like "/etc/*" };"#,
        )
        .build()
        .unwrap();
    let ch = wide();
    assert!(e
        .authorize(&ch, &call(json!({"Path": "/x"})), now())
        .decision
        .is_allow());
    assert_eq!(
        reason(&e, &ch, json!({"path": "/x"})),
        REASON_ARGUMENT_CASE_MISMATCH
    );
    // A capability on `path` beside the catalog's `Path`: neither spelling is one name.
    let ch = chain(vec![Capability::new("fs", "read_file")
        .with_constraint("path", ArgConstraint::Prefix("/".into()))]);
    assert_eq!(
        reason(&e, &ch, json!({"Path": "/x"})),
        REASON_ARGUMENT_CASE_MISMATCH
    );
}

/// A reload reads the new policies' names.
#[test]
fn a_reload_reads_the_new_names() {
    let e = engine(ToolAttrs::new(), PERMIT);
    let ch = wide();
    assert!(e
        .authorize(&ch, &call(json!({"Path": "/x"})), now())
        .decision
        .is_allow());
    let e = e
        .with_policies_reloaded(
            r#"permit(principal, action, resource);
               forbid(principal, action, resource) when {
                 context.input has path && context.input.path == "/x" };"#,
        )
        .unwrap();
    assert_eq!(
        reason(&e, &ch, json!({"Path": "/x"})),
        REASON_ARGUMENT_CASE_MISMATCH
    );
}
