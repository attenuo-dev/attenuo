//! Integration tests for the policy decision point: capability stage, every starter policy,
//! load-time errors, fail-closed behaviour, and the over-privileged-token scenario.

use std::collections::BTreeMap;

use onbehalf_core::chain::DEFAULT_MAX_DEPTH;
use onbehalf_core::{
    AgentId, Capability, CapabilitySet, Decision, DelegationChain, LeaseId, OriginatingUser,
    ToolCall,
};
use onbehalf_policy::{
    ArgType, PolicyEngine, PolicyEngineBuilder, PolicyError, ToolAttrs, ToolCatalog, UnknownTools,
    DEFAULT_POLICIES, REASON_CAPABILITY_DENIED, REASON_POLICY_ALLOW, REASON_POLICY_DENY,
    REASON_POLICY_ERROR, REASON_TOOL_NOT_IN_CATALOG,
};
use serde_json::{json, Value};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

fn now() -> OffsetDateTime {
    datetime!(2026-10-22 21:00 UTC)
}

fn user_with(attrs: &[(&str, Value)]) -> OriginatingUser {
    OriginatingUser {
        subject: "alice".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: now() - Duration::minutes(5),
        attributes: attrs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    }
}

fn user() -> OriginatingUser {
    user_with(&[("mfa", json!(true))])
}

fn caps(v: Vec<Capability>) -> CapabilitySet {
    CapabilitySet::from_iter(v)
}

fn chain_for(user: OriginatingUser, agent: &str, caps: CapabilitySet) -> DelegationChain {
    DelegationChain::root(
        user,
        AgentId::new(agent),
        caps,
        now(),
        Duration::hours(1),
        LeaseId::new("l1"),
    )
    .unwrap()
}

fn chain() -> DelegationChain {
    chain_for(user(), "coder", caps(vec![Capability::new("github", "*")]))
}

/// Extend a chain `n` times with the same wide capability, giving depth `1 + n`.
fn deepen(chain: DelegationChain, n: usize) -> DelegationChain {
    let mut c = chain;
    for i in 0..n {
        c = c
            .extend(
                AgentId::new(format!("sub{i}")),
                caps(vec![Capability::new("github", "*")]),
                now(),
                Duration::minutes(10),
                LeaseId::new(format!("l{}", i + 2)),
                DEFAULT_MAX_DEPTH,
            )
            .unwrap();
    }
    c
}

fn catalog() -> ToolCatalog {
    ToolCatalog::new()
        .with(
            "github",
            "read_file",
            ToolAttrs::new()
                .readonly(true)
                .with_input("repo", ArgType::String)
                .with_input("path", ArgType::String),
        )
        .with("github", "list_issues", ToolAttrs::new().readonly(true))
        .with(
            "github",
            "create_issue",
            ToolAttrs::new()
                .with_input("repo", ArgType::String)
                .with_input("title", ArgType::String),
        )
        .with(
            "github",
            "delete_repo",
            ToolAttrs::new()
                .sensitive(true)
                .with_input("repo", ArgType::String),
        )
        .with(
            "github",
            "set_limit",
            ToolAttrs::new().with_input("count", ArgType::Long),
        )
}

fn engine_with(policies: &str) -> PolicyEngine {
    PolicyEngineBuilder::new()
        .with_catalog(catalog())
        .with_policies_str(policies)
        .build()
        .expect("policies load")
}

fn default_engine() -> PolicyEngine {
    engine_with(DEFAULT_POLICIES)
}

fn call(tool: &str, args: Value) -> ToolCall {
    ToolCall::new("github", tool, args)
}

// ---------------------------------------------------------------------------------------
// Stage 1: capabilities
// ---------------------------------------------------------------------------------------

#[test]
fn capability_stage_denies_before_cedar() {
    // A policy that permits everything must not rescue a call the chain never delegated.
    let engine = engine_with(r#"@id("all") permit(principal, action, resource);"#);
    let narrow = chain_for(
        user(),
        "coder",
        caps(vec![Capability::new("github", "read_*")]),
    );
    let out = engine.authorize(
        &narrow,
        &call("create_issue", json!({"repo": "acme/api"})),
        now(),
    );
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(out.reason, REASON_CAPABILITY_DENIED);
    assert!(
        out.policy_ids.is_empty(),
        "Cedar must not have run: {:?}",
        out.policy_ids
    );
    assert!(out.diagnostics[0].contains("github:read_*"));

    // The same call within capabilities reaches Cedar and is allowed by the permit-all.
    let out = engine.authorize(
        &narrow,
        &call("read_file", json!({"repo": "acme/api"})),
        now(),
    );
    assert_eq!(out.decision, Decision::Allow);
    assert_eq!(out.policy_ids, vec!["all"]);
}

#[test]
fn capability_argument_constraints_are_enforced_before_cedar() {
    use onbehalf_core::ArgConstraint;
    let engine = engine_with(r#"@id("all") permit(principal, action, resource);"#);
    let constrained = chain_for(
        user(),
        "coder",
        caps(vec![Capability::new("github", "create_issue")
            .with_constraint(
                "repo",
                ArgConstraint::Prefix("acme/".into()),
            )]),
    );
    let out = engine.authorize(
        &constrained,
        &call("create_issue", json!({"repo": "evil/x"})),
        now(),
    );
    assert_eq!(out.reason, REASON_CAPABILITY_DENIED);
    let out = engine.authorize(
        &constrained,
        &call("create_issue", json!({"repo": "acme/x"})),
        now(),
    );
    assert_eq!(out.reason, REASON_POLICY_ALLOW);
}

// ---------------------------------------------------------------------------------------
// Stage 2: the starter policies, one by one
// ---------------------------------------------------------------------------------------

#[test]
fn readonly_tools_are_permitted_and_others_denied_by_default() {
    let engine = default_engine();
    let out = engine.authorize(
        &chain(),
        &call("read_file", json!({"repo": "acme/api", "path": "README"})),
        now(),
    );
    assert_eq!(out.decision, Decision::Allow);
    assert_eq!(out.reason, REASON_POLICY_ALLOW);
    assert_eq!(out.policy_ids, vec!["permit_readonly_tools"]);

    let out = engine.authorize(&chain(), &call("list_issues", json!({})), now());
    assert_eq!(out.decision, Decision::Allow);

    // A tool the catalog does not know is denied before Cedar runs (SR-12).
    let out = engine.authorize(&chain(), &call("run_workflow", json!({})), now());
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(out.reason, REASON_TOOL_NOT_IN_CATALOG);
    assert!(out.policy_ids.is_empty());
}

/// SR-12: an uncatalogued tool used to be evaluated as neither readonly nor sensitive, so every
/// `forbid ... when { resource.sensitive }` failed open for it.
#[test]
fn unknown_tools_are_denied_by_default_or_treated_as_sensitive() {
    let policies = r#"@id("allow_all") permit(principal, action, resource);
        @id("mfa_for_sensitive")
        forbid(principal, action, resource)
        when { resource.sensitive && !(context.originating_user.attributes has mfa &&
                                       context.originating_user.attributes.mfa == true) };"#;
    let build = |mode: Option<UnknownTools>| {
        let b = PolicyEngineBuilder::new()
            .with_catalog(catalog())
            .with_policies_str(policies);
        match mode {
            Some(m) => b.with_unknown_tools(m),
            None => b,
        }
        .build()
        .unwrap()
    };
    let delete_org = call("delete_org", json!({}));
    // Default: deny, with a reason of its own, even though a broad permit matches.
    let engine = build(None);
    assert_eq!(engine.unknown_tools(), UnknownTools::Deny);
    let o = engine.authorize(&chain(), &delete_org, now());
    assert_eq!(o.reason, REASON_TOOL_NOT_IN_CATALOG, "{o:?}");
    assert!(o.diagnostics[0].contains("github:delete_org"));
    // A case variant of a catalogued tool is a different, unknown tool.
    let o = engine.authorize(&chain(), &call("Read_File", json!({})), now());
    assert_eq!(o.reason, REASON_TOOL_NOT_IN_CATALOG);
    // Catalogued tools are unaffected.
    assert!(engine
        .authorize(&chain(), &call("list_issues", json!({})), now())
        .decision
        .is_allow());
    // Sensitive: the MFA forbid now applies to the unknown tool.
    let no_mfa = chain_for(
        user_with(&[("mfa", json!(false))]),
        "coder",
        caps(vec![Capability::new("github", "*")]),
    );
    let o = build(Some(UnknownTools::Sensitive)).authorize(&no_mfa, &delete_org, now());
    assert_eq!(o.reason, REASON_POLICY_DENY, "{o:?}");
    assert_eq!(o.policy_ids, vec!["mfa_for_sensitive"]);
    // Allow: the old behaviour, default attributes.
    let o = build(Some(UnknownTools::Allow)).authorize(&no_mfa, &delete_org, now());
    assert!(o.decision.is_allow(), "{o:?}");
}

#[test]
fn create_issue_argument_rule_allows_acme_and_denies_others() {
    let engine = default_engine();
    let out = engine.authorize(
        &chain(),
        &call("create_issue", json!({"repo": "acme/api", "title": "bug"})),
        now(),
    );
    assert_eq!(out.decision, Decision::Allow);
    assert_eq!(out.policy_ids, vec!["permit_create_issue_in_acme"]);

    let out = engine.authorize(
        &chain(),
        &call("create_issue", json!({"repo": "evil/x", "title": "bug"})),
        now(),
    );
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(out.reason, REASON_POLICY_DENY);
    assert!(out.policy_ids.is_empty());

    // `like` is anchored: a repo that merely contains "acme/" is not in the org.
    let out = engine.authorize(
        &chain(),
        &call("create_issue", json!({"repo": "evil/acme/api"})),
        now(),
    );
    assert_eq!(out.decision, Decision::Deny);
}

#[test]
fn create_issue_with_missing_argument_is_denied() {
    let engine = default_engine();
    let out = engine.authorize(
        &chain(),
        &call("create_issue", json!({"title": "no repo"})),
        now(),
    );
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(out.reason, REASON_POLICY_DENY);
    assert!(
        out.diagnostics.is_empty(),
        "a missing optional argument is not an error"
    );

    // An explicit null is the same as absent.
    let out = engine.authorize(
        &chain(),
        &call("create_issue", json!({"repo": null})),
        now(),
    );
    assert_eq!(out.decision, Decision::Deny);
}

#[test]
fn deep_chains_are_forbidden() {
    let engine = default_engine();
    let depth3 = deepen(chain(), 2);
    assert_eq!(depth3.depth(), 3);
    let out = engine.authorize(
        &depth3,
        &call("read_file", json!({"repo": "acme/api"})),
        now(),
    );
    assert_eq!(out.decision, Decision::Allow);

    let depth4 = deepen(chain(), 3);
    assert_eq!(depth4.depth(), 4);
    let out = engine.authorize(
        &depth4,
        &call("read_file", json!({"repo": "acme/api"})),
        now(),
    );
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(out.reason, REASON_POLICY_DENY);
    assert_eq!(out.policy_ids, vec!["forbid_deep_chains"]);
}

#[test]
fn sensitive_tools_require_mfa() {
    // Add a permit for delete_repo so the only thing standing in the way is the MFA forbid.
    let policies = format!(
        "{DEFAULT_POLICIES}\n@id(\"permit_delete\") permit(principal, action == Action::\"delete_repo\", resource);"
    );
    let engine = engine_with(&policies);
    let call = call("delete_repo", json!({"repo": "acme/old"}));

    let with_mfa = chain_for(
        user_with(&[("mfa", json!(true))]),
        "coder",
        caps(vec![Capability::new("github", "*")]),
    );
    let out = engine.authorize(&with_mfa, &call, now());
    assert_eq!(out.decision, Decision::Allow);
    assert_eq!(out.policy_ids, vec!["permit_delete"]);

    let no_mfa = chain_for(
        user_with(&[("mfa", json!(false))]),
        "coder",
        caps(vec![Capability::new("github", "*")]),
    );
    let out = engine.authorize(&no_mfa, &call, now());
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(out.reason, REASON_POLICY_DENY);
    assert_eq!(out.policy_ids, vec!["forbid_sensitive_without_mfa"]);

    let unknown_mfa = chain_for(
        user_with(&[]),
        "coder",
        caps(vec![Capability::new("github", "*")]),
    );
    let out = engine.authorize(&unknown_mfa, &call, now());
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(out.policy_ids, vec!["forbid_sensitive_without_mfa"]);

    // Non-sensitive tools do not care about MFA.
    let out = engine.authorize(
        &no_mfa,
        &ToolCall::new("github", "read_file", json!({})),
        now(),
    );
    assert_eq!(out.decision, Decision::Allow);
}

#[test]
fn forbid_wins_over_permit_and_both_ids_are_reported_appropriately() {
    let engine = engine_with(
        r#"
        @id("p") permit(principal, action, resource);
        @id("f") forbid(principal, action == Action::"delete_repo", resource);
        "#,
    );
    let out = engine.authorize(&chain(), &call("delete_repo", json!({})), now());
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(out.policy_ids, vec!["f"]);
    let out = engine.authorize(&chain(), &call("read_file", json!({})), now());
    assert_eq!(out.decision, Decision::Allow);
    assert_eq!(out.policy_ids, vec!["p"]);
}

// ---------------------------------------------------------------------------------------
// Entities and context details
// ---------------------------------------------------------------------------------------

#[test]
fn principal_hierarchy_user_and_agents() {
    let engine = engine_with(
        r#"
        @id("alice_only") permit(principal in User::"alice", action, resource);
        @id("under_planner") forbid(principal in Agent::"planner", action == Action::"delete_repo", resource);
        "#,
    );
    let planner = chain_for(
        user(),
        "planner",
        caps(vec![Capability::new("github", "*")]),
    );
    let coder = planner
        .extend(
            AgentId::new("coder"),
            caps(vec![Capability::new("github", "*")]),
            now(),
            Duration::minutes(5),
            LeaseId::new("l2"),
            DEFAULT_MAX_DEPTH,
        )
        .unwrap();
    let out = engine.authorize(&coder, &call("read_file", json!({})), now());
    assert_eq!(out.decision, Decision::Allow);
    assert_eq!(out.policy_ids, vec!["alice_only"]);
    // coder acts under planner, so planner's forbid reaches it
    let out = engine.authorize(&coder, &call("delete_repo", json!({})), now());
    assert_eq!(out.policy_ids, vec!["under_planner"]);

    let mut bob = user();
    bob.subject = "bob".into();
    let bob_chain = chain_for(bob, "coder", caps(vec![Capability::new("github", "*")]));
    let out = engine.authorize(&bob_chain, &call("read_file", json!({})), now());
    assert_eq!(out.decision, Decision::Deny);
}

#[test]
fn context_exposes_chain_session_time_and_resource_hierarchy() {
    let engine = engine_with(
        r#"
        @id("session") permit(principal, action, resource)
        when { context has session_id && context.session_id == "s1" && context.now_unix > 0 };
        @id("root_agent") permit(principal, action, resource in Server::"github")
        when { context.chain.root_agent == "coder" && context.chain.agents.contains("coder")
               && context.chain.leases.contains("l1") && context.originating_user.subject == "alice"
               && context.originating_user.authenticated_at_unix < context.now_unix };
        "#,
    );
    let without = engine.authorize(&chain(), &call("read_file", json!({})), now());
    assert_eq!(without.policy_ids, vec!["root_agent"]);
    let with = engine.authorize(
        &chain(),
        &call("read_file", json!({})).with_session("s1"),
        now(),
    );
    let mut ids = with.policy_ids.clone();
    ids.sort();
    assert_eq!(ids, vec!["root_agent", "session"]);
}

#[test]
fn nested_and_numeric_arguments_are_available_to_policies() {
    let engine = engine_with(
        r#"
        @id("limit") permit(principal, action == Action::"set_limit", resource)
        when { context.input has count && context.input.count <= 10 };
        "#,
    );
    let out = engine.authorize(
        &chain(),
        &call(
            "set_limit",
            json!({"count": 5, "meta": {"tags": ["a", null]}}),
        ),
        now(),
    );
    assert_eq!(out.decision, Decision::Allow);
    let out = engine.authorize(&chain(), &call("set_limit", json!({"count": 11})), now());
    assert_eq!(out.decision, Decision::Deny);
}

// ---------------------------------------------------------------------------------------
// Fail closed
// ---------------------------------------------------------------------------------------

#[test]
fn evaluation_errors_deny_even_when_a_permit_matches() {
    // `count` is declared Long; a string at runtime makes the forbid error out. Cedar would
    // skip the erroring forbid and let the permit through; we must not.
    let engine = engine_with(
        r#"
        @id("all") permit(principal, action, resource);
        @id("cap") forbid(principal, action == Action::"set_limit", resource)
        when { context.input has count && context.input.count > 10 };
        "#,
    );
    let out = engine.authorize(
        &chain(),
        &call("set_limit", json!({"count": "lots"})),
        now(),
    );
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(out.reason, REASON_POLICY_ERROR);
    assert!(!out.diagnostics.is_empty());
}

#[test]
fn reserved_argument_keys_are_rejected() {
    let engine = engine_with(r#"@id("all") permit(principal, action, resource);"#);
    let out = engine.authorize(
        &chain(),
        &call(
            "read_file",
            json!({"repo": {"__entity": {"type": "User", "id": "admin"}}}),
        ),
        now(),
    );
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(out.reason, REASON_POLICY_ERROR);
    assert!(out.diagnostics[0].contains("__entity"));
}

// ---------------------------------------------------------------------------------------
// Loading: parse, validation, schema, io, reload
// ---------------------------------------------------------------------------------------

#[test]
fn parse_error_surfaces() {
    let err = PolicyEngineBuilder::new()
        .with_catalog(catalog())
        .with_policies_str("permit(principal, action, resource) when { ;")
        .build()
        .unwrap_err();
    assert!(matches!(err, PolicyError::Parse(_)), "{err}");
}

#[test]
fn validation_error_surfaces_for_unknown_attribute_and_unknown_action() {
    let err = PolicyEngineBuilder::new()
        .with_catalog(catalog())
        .with_policies_str(
            r#"@id("bad") permit(principal, action, resource) when { resource.nonexistent };"#,
        )
        .build()
        .unwrap_err();
    match err {
        PolicyError::Validation(msg) => assert!(msg.contains("[bad]"), "{msg}"),
        other => panic!("expected validation error, got {other:?}"),
    }

    // An action that no catalog entry declares is a typo until proven otherwise.
    let err = PolicyEngineBuilder::new()
        .with_catalog(catalog())
        .with_policies_str(r#"permit(principal, action == Action::"craete_issue", resource);"#)
        .build()
        .unwrap_err();
    assert!(matches!(err, PolicyError::Validation(_)), "{err}");

    // The default policy set needs `create_issue` in the catalog.
    let err = PolicyEngineBuilder::new()
        .with_policies_str(DEFAULT_POLICIES)
        .build()
        .unwrap_err();
    assert!(matches!(err, PolicyError::Validation(_)), "{err}");
}

#[test]
fn schema_error_surfaces() {
    let err = PolicyEngineBuilder::new()
        .with_schema_str("entity Agent in [User {{{")
        .with_policies_str("permit(principal, action, resource);")
        .build()
        .unwrap_err();
    assert!(matches!(err, PolicyError::Schema(_)), "{err}");
}

#[test]
fn custom_base_schema_can_extend_entities() {
    let schema = format!("{}\nentity Repo;", onbehalf_policy::DEFAULT_SCHEMA);
    let engine = PolicyEngineBuilder::new()
        .with_schema_str(&schema)
        .with_catalog(catalog())
        .with_policies_str(
            r#"@id("x") permit(principal, action, resource) when { resource.readonly };"#,
        )
        .build()
        .unwrap();
    assert!(engine.schema_text().contains("entity Repo;"));
    assert_eq!(engine.policy_ids(), vec!["x"]);
}

#[test]
fn io_error_surfaces_from_missing_policy_file() {
    let err = PolicyEngineBuilder::new()
        .with_policies_file("/definitely/not/here.cedar")
        .build()
        .unwrap_err();
    assert!(matches!(err, PolicyError::Io(_)), "{err}");
}

#[test]
fn shipped_default_policy_file_loads_from_disk() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/policies/default.cedar");
    let engine = PolicyEngineBuilder::new()
        .with_catalog(catalog())
        .with_policies_file(path)
        .build()
        .unwrap();
    assert_eq!(
        engine.policy_ids(),
        vec![
            "forbid_deep_chains",
            "forbid_sensitive_without_mfa",
            "permit_create_issue_in_acme",
            "permit_readonly_tools",
        ]
    );
    assert!(
        engine.validation_warnings().is_empty(),
        "{:?}",
        engine.validation_warnings()
    );
}

#[test]
fn duplicate_policy_ids_are_rejected() {
    let err = PolicyEngineBuilder::new()
        .with_catalog(catalog())
        .with_policies_str(
            r#"@id("same") permit(principal, action, resource);
               @id("same") forbid(principal, action, resource);"#,
        )
        .build()
        .unwrap_err();
    assert!(matches!(err, PolicyError::Parse(_)), "{err}");
}

#[test]
fn reload_replaces_policies_and_keeps_old_ones_on_error() {
    let mut engine = engine_with(r#"@id("all") permit(principal, action, resource);"#);
    let c = call("read_file", json!({}));
    assert_eq!(
        engine.authorize(&chain(), &c, now()).decision,
        Decision::Allow
    );

    let err =
        engine.reload_policies_str("forbid(principal, action, resource) when { resource.nope };");
    assert!(matches!(err, Err(PolicyError::Validation(_))));
    assert_eq!(
        engine.authorize(&chain(), &c, now()).decision,
        Decision::Allow,
        "old policies stay"
    );

    engine
        .reload_policies_str(r#"@id("none") forbid(principal, action, resource);"#)
        .unwrap();
    let out = engine.authorize(&chain(), &c, now());
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(out.policy_ids, vec!["none"]);
}

// ---------------------------------------------------------------------------------------
// Scenario: the GitHub MCP over-privileged token
// ---------------------------------------------------------------------------------------

/// Alice's GitHub token can read every repo she can see. The `coder` agent holds a broad
/// `github:*` capability because that is what the token grants. Policy narrows it to her
/// public repositories, so a prompt-injected "read alice/private-salaries" is refused even
/// though the token itself would have served it.
#[test]
fn github_mcp_over_privileged_token_is_narrowed_by_policy() {
    let engine = engine_with(
        r#"
        @id("public_repos_only")
        permit(principal in User::"alice", action, resource in Server::"github")
        when { context.input has repo && context.input.repo like "alice/public-*" };
        "#,
    );
    let coder = chain_for(user(), "coder", caps(vec![Capability::new("github", "*")]));

    let private = call(
        "read_file",
        json!({"repo": "alice/private-salaries", "path": "2026.csv"}),
    );
    let out = engine.authorize(&coder, &private, now());
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(out.reason, REASON_POLICY_DENY);
    assert!(out.policy_ids.is_empty());

    let public = call(
        "read_file",
        json!({"repo": "alice/public-site", "path": "index.html"}),
    );
    let out = engine.authorize(&coder, &public, now());
    assert_eq!(out.decision, Decision::Allow);
    assert_eq!(out.policy_ids, vec!["public_repos_only"]);

    // The write side is narrowed just the same: the token could, the policy will not.
    let out = engine.authorize(
        &coder,
        &call("delete_repo", json!({"repo": "alice/private-salaries"})),
        now(),
    );
    assert_eq!(out.decision, Decision::Deny);
}

// ---- Regression tests from the 2026-10-22 security review --------------------------------

/// SR-04: `action in Action::"invoke"` is the documented way to target every tool. The action
/// hierarchy was missing from the entity store, so such a `forbid` silently never matched.
#[test]
fn forbid_on_generic_invoke_action_applies_to_every_tool() {
    let engine = PolicyEngineBuilder::new()
        .with_catalog(catalog())
        // Evaluate uncatalogued tools too, to show the forbid reaches them.
        .with_unknown_tools(UnknownTools::Allow)
        .with_policies_str(
            r#"@id("allow_all") permit(principal, action, resource);
               @id("no_dangerous_flag")
               forbid(principal, action in Action::"invoke", resource)
               when { context.input has dangerous };"#,
        )
        .build()
        .unwrap();
    for tool in ["read_file", "not_in_catalog", "invoke"] {
        let call = ToolCall::new("github", tool, json!({"dangerous": true}));
        let o = engine.authorize(&chain(), &call, now());
        assert_eq!(o.reason, REASON_POLICY_DENY, "{tool}: {o:?}");
        assert_eq!(o.policy_ids, vec!["no_dangerous_flag"], "{tool}");
        let ok = ToolCall::new("github", tool, json!({}));
        assert!(
            engine.authorize(&chain(), &ok, now()).decision.is_allow(),
            "{tool}"
        );
    }
    // and a permit scoped the same way matches too
    let engine = PolicyEngineBuilder::new()
        .with_catalog(catalog())
        .with_policies_str(r#"permit(principal, action in Action::"invoke", resource);"#)
        .build()
        .unwrap();
    let call = ToolCall::new("github", "read_file", json!({}));
    assert!(engine.authorize(&chain(), &call, now()).decision.is_allow());
}

/// SR-05: `0.0` used to become the Cedar decimal `0.0000`, which is not `== 0`, so an
/// equality `forbid` on a Long could be bypassed by sending the same JSON value as a float.
#[test]
fn integral_floats_are_longs_so_equality_forbids_hold() {
    let engine = PolicyEngineBuilder::new()
        .with_catalog(catalog())
        .with_policies_str(
            r#"permit(principal, action, resource);
               @id("no_zero_limit")
               forbid(principal, action, resource)
               when { context.input has limit && context.input.limit == 0 };"#,
        )
        .build()
        .unwrap();
    for v in [json!(0), json!(0.0), json!(-0.0)] {
        let call = ToolCall::new("github", "read_file", json!({ "limit": v }));
        let o = engine.authorize(&chain(), &call, now());
        assert_eq!(o.reason, REASON_POLICY_DENY, "{v}: {o:?}");
    }
    let call = ToolCall::new("github", "read_file", json!({ "limit": 0.5 }));
    assert!(engine.authorize(&chain(), &call, now()).decision.is_allow());
}

// ---------------------------------------------------------------------------------------------
// Extra user attributes declared in the schema
// ---------------------------------------------------------------------------------------------

const GROUP_POLICY: &str = r#"
@id("eng_reads")
permit(principal, action == Action::"read_file", resource)
when {
    context.originating_user.attributes has groups &&
    context.originating_user.attributes.groups.contains("eng") &&
    context.originating_user.attributes has department &&
    context.originating_user.attributes.department == "platform"
};
"#;

#[test]
fn undeclared_user_attribute_warns_and_declared_one_validates_and_matches() {
    let call = ToolCall::new("github", "read_file", json!({"repo": "a/b", "path": "x"}));
    let eng_user = || {
        user_with(&[
            ("groups", json!(["eng", "oncall"])),
            ("department", json!("platform")),
        ])
    };

    // `groups` is not one of the built-in attributes, so the validator reports the policy as
    // impossible. (Evaluation is schema-free, so it would still run; the warning is what tells
    // the operator the schema does not know the attribute.)
    let undeclared = PolicyEngineBuilder::new()
        .with_catalog(catalog())
        .with_policies_str(GROUP_POLICY)
        .build()
        .unwrap();
    assert!(
        undeclared
            .validation_warnings()
            .iter()
            .any(|w| w.contains("eng_reads")),
        "expected an impossible-policy warning, got {:?}",
        undeclared.validation_warnings()
    );

    let engine = PolicyEngineBuilder::new()
        .with_catalog(catalog())
        .with_user_attr("groups", "set<string>".parse().unwrap())
        .with_user_attr("department", ArgType::String)
        .with_policies_str(GROUP_POLICY)
        .build()
        .expect("declared attributes validate");
    assert!(engine.validation_warnings().is_empty());
    let c = chain_for(
        eng_user(),
        "coder",
        caps(vec![Capability::new("github", "*")]),
    );
    let out = engine.authorize(&c, &call, now());
    assert_eq!(out.decision, Decision::Allow, "{out:?}");
    assert_eq!(out.policy_ids, vec!["eng_reads"]);

    let wrong_group = user_with(&[
        ("groups", json!(["sales"])),
        ("department", json!("platform")),
    ]);
    let c = chain_for(
        wrong_group,
        "coder",
        caps(vec![Capability::new("github", "*")]),
    );
    assert_eq!(engine.authorize(&c, &call, now()).decision, Decision::Deny);

    // No groups at all: the `has` guard keeps it a clean deny, not an evaluation error.
    let c = chain_for(user(), "coder", caps(vec![Capability::new("github", "*")]));
    let out = engine.authorize(&c, &call, now());
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(out.reason, REASON_POLICY_DENY);
}

#[test]
fn arg_type_notation_parses() {
    assert_eq!("string".parse::<ArgType>().unwrap(), ArgType::String);
    assert_eq!(" Long ".parse::<ArgType>().unwrap(), ArgType::Long);
    assert_eq!("bool".parse::<ArgType>().unwrap(), ArgType::Bool);
    assert_eq!(
        "set<string>".parse::<ArgType>().unwrap(),
        ArgType::Set(Box::new(ArgType::String))
    );
    assert_eq!(
        "set<set<long>>".parse::<ArgType>().unwrap(),
        ArgType::Set(Box::new(ArgType::Set(Box::new(ArgType::Long))))
    );
    for bad in ["", "str", "set<>", "set<nope>", "set<string", "record"] {
        assert!(bad.parse::<ArgType>().is_err(), "{bad}");
    }
}
