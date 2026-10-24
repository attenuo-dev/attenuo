//! The policy engine on arbitrary tool-call arguments and originating-user attributes: the
//! JSON-to-Cedar context translation (depth, numbers at the i64 edges, floats, strings with
//! control characters, `__`-prefixed keys) and the catalog's declared-type checks. The engine
//! must never panic and must always return one of its documented reasons; an allow must have
//! passed the capability and catalog stages. Also runs the AuthZEN entry point
//! (`PolicyEngine::evaluate`) on arbitrary JSON.
#![no_main]

use std::sync::OnceLock;

use arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use attenuo_core::{
    AgentId, Capability, CapabilitySet, Decision, DelegationChain, LeaseId, OriginatingUser,
    ToolCall,
};
use attenuo_fuzz::{edge_string, json_value};
use attenuo_policy::{
    ArgType, PolicyEngine, PolicyEngineBuilder, ToolAttrs, ToolCatalog, UnknownTools,
    DEFAULT_POLICIES,
};
use serde_json::{Map, Value};
use time::Duration;

const EXTRA_POLICIES: &str = r#"
@id("forbid_zero")
forbid(principal, action == Action::"github/create_issue", resource)
when { context.input has n && context.input.n == 0 };

@id("permit_tagged")
permit(principal, action == Action::"github/create_issue", resource)
when { context.input has tags && context.input.tags.contains("ok") };

@id("forbid_suspended")
forbid(principal, action, resource)
when { context.originating_user.attributes has tenant &&
       context.originating_user.attributes.tenant == "suspended" };
"#;

const ARGS: &[&str] = &[
    "repo", "n", "flag", "tags", "path", "__entity", "__extn", "",
];
const TOOLS: &[&str] = &["create_issue", "read_file", "delete_repo", "unknown", "a/b"];
const ATTRS: &[&str] = &["mfa", "roles", "tenant", "email", "level", "__expr"];

fn engines() -> &'static [PolicyEngine] {
    static E: OnceLock<Vec<PolicyEngine>> = OnceLock::new();
    E.get_or_init(|| {
        let catalog = ToolCatalog::new()
            .with(
                "github",
                "create_issue",
                ToolAttrs::new()
                    .with_input("repo", ArgType::String)
                    .with_input("n", ArgType::Long)
                    .with_input("flag", ArgType::Bool)
                    .with_input("tags", ArgType::Set(Box::new(ArgType::String))),
            )
            .with("github", "read_file", ToolAttrs::new().readonly(true))
            .with("github", "delete_repo", ToolAttrs::new().sensitive(true));
        [
            UnknownTools::Deny,
            UnknownTools::Sensitive,
            UnknownTools::Allow,
        ]
        .into_iter()
        .map(|unknown| {
            PolicyEngineBuilder::new()
                .with_policies_str(DEFAULT_POLICIES)
                .with_policies_str(EXTRA_POLICIES)
                .with_catalog(catalog.clone())
                .with_user_attr("level", ArgType::Long)
                .with_unknown_tools(unknown)
                .build()
                .expect("fuzz engine builds")
        })
        .collect()
    })
}

#[derive(Debug)]
struct Input {
    engine: usize,
    attributes: Map<String, Value>,
    server: String,
    tool: String,
    arguments: Map<String, Value>,
    session: Option<String>,
    authzen: Option<Vec<u8>>,
}

fn key(u: &mut Unstructured<'_>, list: &[&str]) -> Result<String> {
    if u.ratio(1u8, 5u8)? {
        edge_string(u)
    } else {
        Ok((*u.choose(list)?).to_string())
    }
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut attributes = Map::new();
        for _ in 0..u.int_in_range(0usize..=4)? {
            attributes.insert(key(u, ATTRS)?, json_value(u, 4)?);
        }
        let mut arguments = Map::new();
        for _ in 0..u.int_in_range(0usize..=5)? {
            arguments.insert(key(u, ARGS)?, json_value(u, 6)?);
        }
        Ok(Input {
            engine: u.int_in_range(0usize..=2)?,
            attributes,
            server: if u.ratio(1u8, 8u8)? {
                edge_string(u)?
            } else {
                "github".into()
            },
            tool: key(u, TOOLS)?,
            arguments,
            session: if u.arbitrary()? {
                Some(edge_string(u)?)
            } else {
                None
            },
            authzen: if u.ratio(1u8, 6u8)? {
                Some(u.arbitrary()?)
            } else {
                None
            },
        })
    }
}

const REASONS: &[&str] = &[
    attenuo_policy::REASON_INVALID_NAME,
    attenuo_policy::REASON_CAPABILITY_DENIED,
    attenuo_policy::REASON_TOOL_NOT_IN_CATALOG,
    attenuo_policy::REASON_ATTRIBUTE_TYPE_MISMATCH,
    attenuo_policy::REASON_INPUT_TYPE_MISMATCH,
    attenuo_policy::REASON_POLICY_ALLOW,
    attenuo_policy::REASON_POLICY_DENY,
    attenuo_policy::REASON_POLICY_ERROR,
];

fuzz_target!(|input: Input| {
    let f = attenuo_fuzz::fixture();
    let engine = &engines()[input.engine];
    let user = OriginatingUser {
        subject: "user:mudit".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: f.now,
        attributes: input.attributes.into_iter().collect(),
    };
    let chain = DelegationChain::root(
        user,
        AgentId::new("agent:planner"),
        CapabilitySet::from_iter([
            Capability::new("github", "*"),
            Capability::new("*", "read_*"),
        ]),
        f.now,
        Duration::minutes(10),
        LeaseId::new("lease-1"),
    )
    .expect("fixed chain is valid");
    let mut call = ToolCall::new(input.server, input.tool, Value::Object(input.arguments));
    if let Some(s) = input.session {
        call = call.with_session(s);
    }
    let out = engine.authorize(&chain, &call, f.now);
    assert!(
        REASONS.contains(&out.reason.as_str()),
        "unknown reason {}",
        out.reason
    );
    if out.decision == Decision::Allow {
        assert_eq!(out.reason, attenuo_policy::REASON_POLICY_ALLOW);
        assert!(call.check_names().is_ok());
        assert!(chain.effective_capabilities().unwrap().permits(&call));
    }
    // Deterministic.
    assert_eq!(engine.authorize(&chain, &call, f.now), out);

    if let Some(bytes) = input.authzen {
        if let Ok(req) =
            serde_json::from_slice::<attenuo_policy::authzen::EvaluationRequest>(&bytes)
        {
            let _ = engine.evaluate(&req, f.now);
        }
    }
});
