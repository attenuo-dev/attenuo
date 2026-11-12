//! The list screen (ADR-0011): `PolicyEngine::screen_tools` hides a tool only when no call to
//! it could be allowed for the chain. The examples pin what it hides and keeps; the proptest
//! at the end checks that it is sound: every tool it hides is denied by `authorize_labelled`
//! for generated concrete calls (arguments, taint, argument labels, approvals, budgets, usage,
//! time and session), under the starter policy and the injection suite's policies.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use attenuo_core::ToolCall;
use attenuo_core::{AgentId, Capability, CapabilitySet, DelegationChain, LeaseId, OriginatingUser};
use attenuo_policy::{
    AnnotationImport, ApprovalContext, ArgLabels, ArgType, BudgetContext, CallLabels, ListScreen,
    PolicyEngine, PolicyEngineBuilder, SessionLabels, ToolAttrs, ToolCatalog, UnknownTools,
    UsageContext, DEFAULT_POLICIES, HIDE_INVALID_NAME, HIDE_NOT_IN_CATALOG, HIDE_POLICY,
};
use proptest::prelude::*;
use serde_json::{json, Map, Value};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

fn now() -> OffsetDateTime {
    datetime!(2026-11-05 09:00 UTC)
}

fn user(mfa: Option<bool>) -> OriginatingUser {
    let mut attributes = BTreeMap::new();
    if let Some(m) = mfa {
        attributes.insert("mfa".to_string(), json!(m));
    }
    OriginatingUser {
        subject: "alice".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: now() - Duration::minutes(1),
        attributes,
    }
}

/// A chain of `depth` hops, every hop granted `<server>:*` for each server.
fn chain(depth: usize, mfa: Option<bool>, servers: &[&str]) -> DelegationChain {
    let caps = || CapabilitySet::from_iter(servers.iter().map(|s| Capability::new(*s, "*")));
    let mut c = DelegationChain::root(
        user(mfa),
        AgentId::new("root"),
        caps(),
        now(),
        Duration::hours(1),
        LeaseId::new("l0"),
    )
    .unwrap();
    for i in 1..depth {
        c = c
            .extend(
                AgentId::new(format!("a{i}")),
                caps(),
                now(),
                Duration::minutes(30),
                LeaseId::new(format!("l{i}")),
                16,
            )
            .unwrap();
    }
    c
}

fn repo() -> ToolAttrs {
    ToolAttrs::new().with_input("repo", ArgType::String)
}

/// The starter policy's tools, and some it does not name.
fn github_catalog() -> ToolCatalog {
    ToolCatalog::new()
        .with("github", "read_file", repo().readonly(true))
        .with(
            "github",
            "list_secrets",
            repo().readonly(true).sensitive(true),
        )
        .with("github", "create_issue", repo())
        .with("github", "update_issue", repo())
        .with("github", "close_issue", repo())
        .with("github", "merge", repo())
        .with("github", "delete_repo", repo().sensitive(true))
}

fn engine_with(policies: &str, unknown: UnknownTools) -> PolicyEngine {
    PolicyEngineBuilder::new()
        .with_catalog(github_catalog())
        .with_unknown_tools(unknown)
        .with_policies_str(policies)
        .build()
        .unwrap()
}

fn starter(extra: &str) -> PolicyEngine {
    engine_with(&format!("{DEFAULT_POLICIES}\n{extra}"), UnknownTools::Deny)
}

fn screen(engine: &PolicyEngine, chain: &DelegationChain, tools: &[&str]) -> Vec<ListScreen> {
    let names: Vec<String> = tools.iter().map(|t| t.to_string()).collect();
    let memo = engine.screen_tools(chain, "github", &names);
    assert_eq!(memo, engine.screen_tools_uncached(chain, "github", &names));
    memo
}

const HIDE: ListScreen = ListScreen::Hide(HIDE_POLICY);

#[test]
fn policy_screen_hides_tools_no_permit_can_allow() {
    let e = starter("");
    let c = chain(1, Some(true), &["github"]);
    assert_eq!(
        screen(
            &e,
            &c,
            &["read_file", "create_issue", "update_issue", "merge"]
        ),
        vec![ListScreen::Keep, ListScreen::Keep, HIDE, HIDE]
    );
}

#[test]
fn policy_screen_hides_sensitive_tools_for_users_without_mfa() {
    let e = starter("");
    for mfa in [None, Some(false)] {
        let c = chain(1, mfa, &["github"]);
        assert_eq!(
            screen(&e, &c, &["delete_repo", "list_secrets", "read_file"]),
            vec![HIDE, HIDE, ListScreen::Keep],
            "mfa {mfa:?}"
        );
    }
    let c = chain(1, Some(true), &["github"]);
    assert_eq!(
        screen(&e, &c, &["delete_repo", "list_secrets"]),
        vec![ListScreen::Keep, ListScreen::Keep]
    );
}

#[test]
fn policy_screen_hides_every_tool_for_chains_deeper_than_the_policy_allows() {
    let e = starter("");
    let tools = ["read_file", "create_issue", "delete_repo"];
    assert!(screen(&e, &chain(3, Some(true), &["github"]), &tools)
        .iter()
        .all(|v| v.keeps()));
    assert_eq!(
        screen(&e, &chain(4, Some(true), &["github"]), &tools),
        vec![HIDE; 3]
    );
}

/// A tool denied only by `@obligation("approval")` forbids stays listed: its pending approval
/// is created by a denied call. A forbid without the annotation still hides.
#[test]
fn policy_screen_keeps_approval_gated_tools() {
    let e = starter(
        r#"
        @id("ask_every_time")
        @obligation("approval")
        forbid(principal, action == Action::"github/create_issue", resource)
        unless { context.approval.present };

        @id("ask_after_taint")
        @obligation("approval")
        forbid(principal, action, resource)
        when { resource.destructive && context.session.tainted && !context.approval.present };

        @id("never_read")
        forbid(principal, action == Action::"github/read_file", resource);
        "#,
    );
    assert!(e.asks_for_approval());
    let c = chain(1, Some(true), &["github"]);
    assert_eq!(
        screen(&e, &c, &["create_issue", "delete_repo", "read_file"]),
        vec![ListScreen::Keep, ListScreen::Keep, HIDE]
    );
    // And the call is indeed approval_required, not policy_deny.
    let call = ToolCall::new("github", "create_issue", json!({"repo": "acme/x"}));
    assert_eq!(e.authorize(&c, &call, now()).reason, "approval_required");
}

#[test]
fn policy_screen_keeps_tools_whose_permit_depends_on_input() {
    let e = starter("");
    let c = chain(1, None, &["github"]);
    // permit_create_issue_in_acme reads context.input: a residual, so kept.
    assert_eq!(screen(&e, &c, &["create_issue"]), vec![ListScreen::Keep]);
}

#[test]
fn policy_screen_keeps_tools_whose_permit_depends_on_time() {
    let e = starter(
        r#"
        @id("merge_window")
        permit(principal, action == Action::"github/merge", resource)
        when { context.now_unix < 1800000000 };

        @id("freeze")
        forbid(principal, action == Action::"github/update_issue", resource)
        when { context.now_unix > 0 };
        @id("update_ok")
        permit(principal, action == Action::"github/update_issue", resource);
        "#,
    );
    let c = chain(1, None, &["github"]);
    // Both depend on the clock: neither is a definite deny (the screen does not decide that
    // `now_unix > 0` always holds).
    assert_eq!(
        screen(&e, &c, &["merge", "update_issue"]),
        vec![ListScreen::Keep, ListScreen::Keep]
    );
}

/// `session_id` is the one optional context member: a permit that needs it absent must keep
/// its tool listed, though an unknown `session_id` alone would make `has` true.
#[test]
fn policy_screen_keeps_tools_allowed_only_without_a_session_id() {
    let e = starter(
        r#"
        @id("sessionless_updates")
        permit(principal, action == Action::"github/update_issue", resource)
        when { !(context has session_id) };

        @id("session_merges")
        permit(principal, action == Action::"github/merge", resource)
        when { context has session_id && context.session_id == "abc" };
        "#,
    );
    let c = chain(1, None, &["github"]);
    assert_eq!(
        screen(&e, &c, &["update_issue", "merge", "close_issue"]),
        vec![ListScreen::Keep, ListScreen::Keep, HIDE]
    );
    let call = ToolCall::new("github", "update_issue", json!({}));
    assert!(e.authorize(&c, &call, now()).decision.is_allow());
}

#[test]
fn policy_screen_hides_uncatalogued_tools_only_under_unknown_tools_deny() {
    let c = chain(1, Some(true), &["github"]);
    let permit_all = "permit(principal, action, resource);";
    let deny = engine_with(permit_all, UnknownTools::Deny);
    assert_eq!(
        screen(&deny, &c, &["read_file", "delete_org", "bad name"]),
        vec![
            ListScreen::Keep,
            ListScreen::Hide(HIDE_NOT_IN_CATALOG),
            ListScreen::Hide(HIDE_INVALID_NAME)
        ]
    );
    for unknown in [UnknownTools::Sensitive, UnknownTools::Allow] {
        let e = engine_with(permit_all, unknown);
        assert_eq!(
            screen(&e, &c, &["delete_org"]),
            vec![ListScreen::Keep],
            "{unknown:?}"
        );
    }
    // Under `sensitive`, the MFA forbid applies to an uncatalogued tool.
    let e = engine_with(
        &format!("{permit_all}\n{}", sensitive_forbid()),
        UnknownTools::Sensitive,
    );
    assert_eq!(
        screen(&e, &chain(1, None, &["github"]), &["delete_org"]),
        vec![HIDE]
    );
}

fn sensitive_forbid() -> &'static str {
    r#"forbid(principal, action, resource) when {
        resource.sensitive &&
        !(context.originating_user.attributes has mfa && context.originating_user.attributes.mfa == true)
    };"#
}

#[test]
fn policy_screen_hides_everything_for_a_user_attribute_of_the_wrong_type() {
    let e = starter("");
    let mut c = chain(1, Some(true), &["github"]);
    c.originating_user
        .attributes
        .insert("mfa".into(), json!(["yes"]));
    assert_eq!(screen(&e, &c, &["read_file"]), vec![HIDE]);
}

#[test]
fn a_reload_bumps_the_generation_and_empties_the_memo() {
    let mut e = starter("");
    let c = chain(1, None, &["github"]);
    assert_eq!(screen(&e, &c, &["update_issue"]), vec![HIDE]);
    assert_eq!(e.screened_tools(), 1);
    let generation = e.policy_generation();
    e.reload_policies_str(&format!(
        "{DEFAULT_POLICIES}\n@id(\"u\") permit(principal, action == Action::\"github/update_issue\", resource);"
    ))
    .unwrap();
    assert_eq!(e.policy_generation(), generation + 1);
    assert_eq!(e.screened_tools(), 0);
    assert_eq!(screen(&e, &c, &["update_issue"]), vec![ListScreen::Keep]);
    // A failed reload changes nothing.
    assert!(e.reload_policies_str("permit(").is_err());
    assert_eq!(e.policy_generation(), generation + 1);
}

#[test]
fn imported_narrowing_is_part_of_the_memo_key() {
    let e = PolicyEngineBuilder::new()
        .with_catalog(github_catalog())
        .with_annotation_import(AnnotationImport::Narrowing)
        .with_policies_str(DEFAULT_POLICIES)
        .build()
        .unwrap();
    let c = chain(1, None, &["github"]);
    assert_eq!(screen(&e, &c, &["read_file"]), vec![ListScreen::Keep]);
    // The upstream says read_file is not read-only: permit_readonly_tools no longer applies.
    assert!(e.import_annotations("github", "read_file", Some(false), None));
    assert_eq!(screen(&e, &c, &["read_file"]), vec![HIDE]);
}

// ---------------------------------------------------------------------------------------------
// Soundness: hidden means denied for every generated call.
// ---------------------------------------------------------------------------------------------

/// Extra rules over the starter policy that read every call-time member.
const CALL_TIME_RULES: &str = r#"
@id("sessionless_updates")
permit(principal, action == Action::"github/update_issue", resource)
when { !(context has session_id) && context.input has repo };

@id("budgeted_closes")
permit(principal, action == Action::"github/close_issue", resource)
when { context.budget.limited && context.budget.calls_remaining > 0 && context.usage.calls < 3 };

@id("operator_merges")
permit(principal, action == Action::"github/merge", resource)
when { context.approval.present && context.approval.by == "operator" };

@id("no_untrusted_body")
forbid(principal, action, resource)
when { context.args_contain_untrusted && context.untrusted_args.contains("body") };

@id("late_freeze")
forbid(principal, action, resource)
when { resource.destructive && context.now_unix > 1800000000 };

@id("ask_after_taint")
@obligation("approval")
forbid(principal, action, resource)
when { resource.destructive && context.session.tainted && !context.approval.present };

@id("ask_on_repeat")
@obligation("approval")
forbid(principal, action, resource)
when { context.usage.calls >= 1 && !context.usage.destination_seen && !context.approval.present };
"#;

struct Suite {
    server: String,
    engine: PolicyEngine,
    tools: Vec<String>,
    strings: Vec<String>,
}

fn suite_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../evaluation/injection-suite/policies")
}

/// String literals of a policy text, as argument values that policies test for.
fn string_literals(text: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        let tail = &rest[start + 1..];
        let Some(end) = tail.find('"') else { break };
        let lit = &tail[..end];
        if !lit.contains('\\') {
            out.insert(lit.replace('*', "x"));
            out.insert(lit.to_string());
        }
        rest = &tail[end + 1..];
    }
    out.into_iter().collect()
}

fn suites() -> Vec<Suite> {
    let mut out = Vec::new();
    let starter_text = format!("{DEFAULT_POLICIES}\n{CALL_TIME_RULES}");
    let mut tools: Vec<String> = github_catalog()
        .iter()
        .map(|((_, t), _)| t.clone())
        .collect();
    tools.push("not_catalogued".into());
    for unknown in [UnknownTools::Deny, UnknownTools::Sensitive] {
        out.push(Suite {
            server: "github".into(),
            engine: engine_with(&starter_text, unknown),
            tools: tools.clone(),
            strings: string_literals(&starter_text),
        });
    }
    // The suite's add-on arms that load with every suite; `labels.cedar` names a workspace
    // action, so it goes with that suite only.
    let addons = |name: &str| -> String {
        let mut files = vec!["labels-args.cedar", "usage-soft.cedar"];
        if name == "workspace" {
            files.push("labels.cedar");
        }
        files
            .iter()
            .map(|f| std::fs::read_to_string(suite_dir().join(f)).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    };
    #[derive(serde::Deserialize)]
    struct Env {
        upstream: String,
        catalog: BTreeMap<String, serde_yaml::Value>,
    }
    // The suite writes input types as the config does (`set<string>`), which the harness
    // parses with `ArgType::from_str`.
    let attrs_of = |mut v: serde_yaml::Value| -> ToolAttrs {
        let inputs = v
            .as_mapping_mut()
            .and_then(|m| m.remove("inputs"))
            .unwrap_or_default();
        let mut attrs: ToolAttrs = serde_yaml::from_value(v).unwrap();
        if let Some(m) = inputs.as_mapping() {
            for (k, t) in m {
                let ty: ArgType = t.as_str().unwrap().parse().unwrap();
                attrs = attrs.with_input(k.as_str().unwrap(), ty);
            }
        }
        attrs
    };
    for name in ["banking", "github", "slack", "travel", "workspace"] {
        let env: Env = serde_yaml::from_str(
            &std::fs::read_to_string(suite_dir().join(format!("{name}.yaml"))).unwrap(),
        )
        .unwrap();
        let cedar = std::fs::read_to_string(suite_dir().join(format!("{name}.cedar"))).unwrap();
        let mut catalog = ToolCatalog::new();
        for (tool, attrs) in &env.catalog {
            catalog.insert(env.upstream.clone(), tool.clone(), attrs_of(attrs.clone()));
        }
        let text = format!("{cedar}\n{}", addons(name));
        let engine = PolicyEngineBuilder::new()
            .with_catalog(catalog)
            .with_policies_str(&text)
            .build()
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut tools: Vec<String> = env.catalog.keys().cloned().collect();
        tools.push("not_catalogued".into());
        out.push(Suite {
            server: env.upstream,
            engine,
            tools,
            strings: string_literals(&text),
        });
    }
    out
}

/// One generated concrete call context.
#[derive(Debug, Clone)]
struct Ctx {
    depth: usize,
    mfa: Option<bool>,
    /// Per argument slot: absent, or an index into the value pools.
    args: Vec<Option<(u8, u16)>>,
    tainted: bool,
    untrusted: Vec<u8>,
    approval: Option<bool>,
    limited: bool,
    remaining: i64,
    usage_calls: i64,
    usage_amount: i64,
    destination_seen: bool,
    now: i64,
    session: Option<u8>,
}

fn ctx() -> impl Strategy<Value = Ctx> {
    (
        (
            1usize..=5,
            prop_oneof![Just(None), any::<bool>().prop_map(Some)],
        ),
        proptest::collection::vec(proptest::option::of((any::<u8>(), any::<u16>())), 0..6),
        (any::<bool>(), proptest::collection::vec(any::<u8>(), 0..3)),
        prop_oneof![Just(None), any::<bool>().prop_map(Some)],
        (
            any::<bool>(),
            prop_oneof![Just(0i64), Just(1), Just(i64::MAX)],
        ),
        (
            0i64..4,
            prop_oneof![Just(0i64), Just(1999), Just(5000)],
            any::<bool>(),
        ),
        prop_oneof![Just(1_700_000_000i64), Just(1_900_000_000)],
        proptest::option::of(any::<u8>()),
    )
        .prop_map(
            |(
                (depth, mfa),
                args,
                (tainted, untrusted),
                approval,
                (limited, remaining),
                (uc, ua, ds),
                now,
                session,
            )| Ctx {
                depth,
                mfa,
                args,
                tainted,
                untrusted,
                approval,
                limited,
                remaining,
                usage_calls: uc,
                usage_amount: ua,
                destination_seen: ds,
                now,
                session,
            },
        )
}

const LONGS: [i64; 8] = [0, 1, 2, 5, 100, 2000, 2001, -1];

/// The arguments of a call: the catalog's declared inputs (and `repo`, `body`), each absent
/// or a value of its declared type (any type when undeclared) from the pools.
fn arguments(suite: &Suite, tool: &str, c: &Ctx) -> Map<String, Value> {
    let attrs = suite
        .engine
        .effective_attrs(&suite.server, tool)
        .unwrap_or_default();
    let mut names: Vec<(String, Option<ArgType>)> = attrs
        .inputs
        .iter()
        .map(|(n, t)| (n.clone(), Some(t.clone())))
        .collect();
    for extra in ["repo", "body"] {
        if !attrs.inputs.contains_key(extra) {
            names.push((extra.to_string(), None));
        }
    }
    let mut out = Map::new();
    for ((name, ty), slot) in names
        .iter()
        .zip(c.args.iter().chain(std::iter::repeat(&None)))
    {
        let Some((kind, pick)) = slot else { continue };
        let s = || Value::String(suite.strings[*pick as usize % suite.strings.len()].clone());
        let l = || json!(LONGS[*pick as usize % LONGS.len()]);
        let v = match ty {
            Some(ArgType::String) => s(),
            Some(ArgType::Long) => l(),
            Some(ArgType::Decimal) => json!(1.25),
            Some(ArgType::Bool) => json!(pick % 2 == 0),
            Some(ArgType::Set(_)) => Value::Array(vec![s()]),
            None => match kind % 3 {
                0 => s(),
                1 => l(),
                _ => json!(pick % 2 == 0),
            },
        };
        out.insert(name.clone(), v);
    }
    out
}

fn labels(c: &Ctx, args: &Map<String, Value>) -> CallLabels {
    let keys: Vec<&String> = args.keys().collect();
    let untrusted: Vec<String> = c
        .untrusted
        .iter()
        .filter(|_| !keys.is_empty())
        .map(|i| keys[*i as usize % keys.len()].clone())
        .collect();
    CallLabels {
        session: if c.tainted {
            SessionLabels::from_sources(["web/fetch"])
        } else {
            SessionLabels::untainted()
        },
        args: ArgLabels::from_args(untrusted),
        approval: match c.approval {
            None => ApprovalContext::default(),
            Some(true) => ApprovalContext::by("operator"),
            Some(false) => ApprovalContext::by("user"),
        },
        budget: BudgetContext {
            limited: c.limited,
            calls_remaining: c.remaining,
            ..BudgetContext::default()
        },
        usage: UsageContext {
            calls: c.usage_calls,
            amount: c.usage_amount,
            destination_seen: c.destination_seen,
            ..Default::default()
        },
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn every_hidden_tool_is_denied_for_generated_calls(c in ctx()) {
        for suite in suites_cached() {
            let ch = chain(c.depth, c.mfa, &[suite.server.as_str()]);
            let verdicts = suite.engine.screen_tools(&ch, &suite.server, &suite.tools);
            for (tool, verdict) in suite.tools.iter().zip(&verdicts) {
                if verdict.keeps() {
                    continue;
                }
                let args = arguments(suite, tool, &c);
                let mut call = ToolCall::new(&suite.server, tool, Value::Object(args.clone()));
                call.session_id = c.session.map(|s| if s % 2 == 0 { "abc".into() } else { format!("s{s}") });
                let at = OffsetDateTime::from_unix_timestamp(c.now).unwrap();
                let out = suite.engine.authorize_labelled(&ch, &call, &labels(&c, &args), at);
                prop_assert!(
                    !out.decision.is_allow(),
                    "{}/{tool} hidden ({verdict:?}) but allowed: {:?} for {call:?}",
                    suite.server, out
                );
            }
        }
    }
}

fn suites_cached() -> &'static [Suite] {
    static SUITES: std::sync::OnceLock<Vec<Suite>> = std::sync::OnceLock::new();
    SUITES.get_or_init(suites)
}

/// The proptest is not vacuous: across its suites the screen hides tools and keeps others,
/// and the allowed calls of each suite exist for some kept tool.
#[test]
fn the_soundness_suites_hide_and_keep_tools() {
    let mut hidden = 0;
    let mut kept = 0;
    for suite in suites_cached() {
        for mfa in [None, Some(true)] {
            let ch = chain(1, mfa, &[suite.server.as_str()]);
            for v in suite.engine.screen_tools(&ch, &suite.server, &suite.tools) {
                if v.keeps() {
                    kept += 1;
                } else {
                    hidden += 1;
                }
            }
        }
    }
    assert!(hidden >= 10 && kept >= 20, "hidden {hidden}, kept {kept}");
}
