//! The Cedar usage walker (`attenuo_policy::policies_read_usage`) on random policies that
//! parse. Saying "nobody reads usage" for a policy that does is the dangerous direction: the
//! server then stops keeping `context.usage` and the policy sees zeros.
//!
//! Policies come from a small Cedar grammar that knows, per generated expression, whether it
//! names `context.usage` directly (`context.usage`, `context["usage"]`, `context has usage`,
//! `context has usage.calls`): a reference grep over the generated AST. Raw text is tried too.
//! Two oracles:
//!
//! - **syntactic**: a policy whose AST names `context.usage` must be reported as reading it;
//! - **semantic**: if two requests that differ only in `context.usage` get different answers
//!   (decision, determining policies or errors), the policy reads usage, so the walker must
//!   say so, whatever the spelling.
#![no_main]

use std::str::FromStr;
use std::sync::OnceLock;

use arbitrary::{Arbitrary, Result, Unstructured};
use attenuo_policy::policies_read_usage;
use cedar_policy::{Authorizer, Context, Entities, EntityUid, PolicySet, Request, Response};
use libfuzzer_sys::fuzz_target;
use serde_json::json;

/// A generated expression and whether it names `context.usage` directly.
struct Expr {
    text: String,
    usage: bool,
}

fn e(text: impl Into<String>, usage: bool) -> Expr {
    Expr {
        text: text.into(),
        usage,
    }
}

const ATTRS: &[&str] = &["usage", "input", "budget", "Usage", "usage_", "calls"];
const USAGE_FIELDS: &[&str] = &["calls", "amount", "destination_seen", "nope"];

fn context_access(u: &mut Unstructured<'_>) -> Result<Expr> {
    let attr = *u.choose(ATTRS)?;
    let is_usage = attr == "usage";
    Ok(match u.int_in_range(0u8..=9)? {
        0 => e(format!("context.{attr}"), is_usage),
        1 => e(format!("context[\"{attr}\"]"), is_usage),
        2 => e(format!("context has {attr}"), is_usage),
        3 => e(format!("context has \"{attr}\""), is_usage),
        4 => {
            let f = *u.choose(USAGE_FIELDS)?;
            e(format!("context has {attr}.{f}"), is_usage)
        }
        5 => {
            let f = *u.choose(USAGE_FIELDS)?;
            e(format!("context.{attr}.{f}"), is_usage)
        }
        6 => {
            let f = *u.choose(USAGE_FIELDS)?;
            e(format!("context[\"{attr}\"][\"{f}\"]"), is_usage)
        }
        7 => e("context", false),
        // Unicode escapes spell the same attribute.
        8 => e("context[\"\\u{75}sage\"]", true),
        _ => e(
            format!("(if true then context else {{\"{attr}\": 1}}).{attr}"),
            false,
        ),
    })
}

fn leaf(u: &mut Unstructured<'_>) -> Result<Expr> {
    Ok(match u.int_in_range(0u8..=8)? {
        0 | 1 | 2 => context_access(u)?,
        3 => e(if u.arbitrary()? { "true" } else { "false" }, false),
        4 => e(format!("{}", u.int_in_range(-3i64..=3)?), false),
        5 => e(
            format!("\"{}\"", *u.choose(&["usage", "context.usage", "", "a"])?),
            false,
        ),
        6 => e("resource.destructive", false),
        7 => e("principal", false),
        _ => e("{\"usage\": {\"calls\": 1}}", false),
    })
}

fn expr(u: &mut Unstructured<'_>, depth: u32) -> Result<Expr> {
    if depth == 0 || u.ratio(1u8, 3u8)? {
        return leaf(u);
    }
    let a = expr(u, depth - 1)?;
    Ok(match u.int_in_range(0u8..=13)? {
        0 => {
            let b = expr(u, depth - 1)?;
            e(format!("({} && {})", a.text, b.text), a.usage || b.usage)
        }
        1 => {
            let b = expr(u, depth - 1)?;
            e(format!("({} || {})", a.text, b.text), a.usage || b.usage)
        }
        2 => e(format!("!({})", a.text), a.usage),
        3 => {
            let (b, c) = (expr(u, depth - 1)?, expr(u, depth - 1)?);
            e(
                format!("(if {} then {} else {})", a.text, b.text, c.text),
                a.usage || b.usage || c.usage,
            )
        }
        4 => {
            let b = expr(u, depth - 1)?;
            let op = *u.choose(&["==", "!=", "<", "<=", ">", ">="])?;
            e(format!("({} {op} {})", a.text, b.text), a.usage || b.usage)
        }
        5 => {
            let f = *u.choose(USAGE_FIELDS)?;
            e(format!("({}).{f}", a.text), a.usage)
        }
        6 => {
            let f = *u.choose(ATTRS)?;
            e(format!("({}) has {f}", a.text), a.usage)
        }
        7 => {
            let b = expr(u, depth - 1)?;
            e(format!("[{}, {}]", a.text, b.text), a.usage || b.usage)
        }
        8 => {
            let k = *u.choose(ATTRS)?;
            e(format!("{{\"{k}\": {}}}", a.text), a.usage)
        }
        9 => {
            let b = expr(u, depth - 1)?;
            e(
                format!("({}).contains({})", a.text, b.text),
                a.usage || b.usage,
            )
        }
        10 => e(format!("({}) like \"*s*\"", a.text), a.usage),
        11 => {
            let b = expr(u, depth - 1)?;
            e(format!("({} + {})", a.text, b.text), a.usage || b.usage)
        }
        12 => e(format!("({}) is Tool", a.text), a.usage),
        _ => {
            let b = expr(u, depth - 1)?;
            e(
                format!("({}).getTag({})", a.text, b.text),
                a.usage || b.usage,
            )
        }
    })
}

#[derive(Debug)]
struct Input {
    text: String,
    /// Whether the generated AST names `context.usage` (unknown for raw text).
    reference: Option<bool>,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        if u.ratio(1u8, 8u8)? {
            return Ok(Input {
                text: u.arbitrary()?,
                reference: None,
            });
        }
        let mut text = String::new();
        let mut usage = false;
        for i in 0..u.int_in_range(1usize..=3)? {
            let effect = *u.choose(&["permit", "forbid"])?;
            let scope = *u.choose(&[
                "principal, action, resource",
                "principal == ?principal, action, resource",
                "principal, action == Action::\"bank/send\", resource",
                "principal, action, resource is Tool",
            ])?;
            text.push_str(&format!("@id(\"p{i}\")\n{effect}({scope})"));
            for _ in 0..u.int_in_range(0usize..=2)? {
                let kw = *u.choose(&["when", "unless"])?;
                let x = expr(u, 4)?;
                usage |= x.usage;
                text.push_str(&format!(" {kw} {{ {} }}", x.text));
            }
            text.push_str(";\n");
        }
        Ok(Input {
            text,
            reference: Some(usage),
        })
    }
}

struct World {
    entities: Entities,
    principal: EntityUid,
    action: EntityUid,
    resource: EntityUid,
}

fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        let entities = Entities::from_json_value(
            json!([
                {"uid": {"type": "Agent", "id": "planner"}, "attrs": {}, "parents": []},
                {"uid": {"type": "Tool", "id": "bank/send"},
                 "attrs": {"destructive": true}, "parents": [], "tags": {"usage": 1}},
            ]),
            None,
        )
        .expect("entities");
        World {
            entities,
            principal: EntityUid::from_str(r#"Agent::"planner""#).unwrap(),
            action: EntityUid::from_str(r#"Action::"bank/send""#).unwrap(),
            resource: EntityUid::from_str(r#"Tool::"bank/send""#).unwrap(),
        }
    })
}

/// The usage records the semantic oracle compares (the server always sends one).
fn usages() -> [serde_json::Value; 3] {
    [
        json!({"calls": 0, "amount": 0, "destination_seen": false}),
        json!({"calls": 3, "amount": 1000, "destination_seen": true}),
        json!({"calls": 1, "amount": -5, "destination_seen": false}),
    ]
}

fn answer(policies: &PolicySet, usage: &serde_json::Value) -> String {
    let w = world();
    let context = Context::from_json_value(
        json!({"usage": usage, "input": {"amount": 5, "to": "a"}, "budget": {"limited": false}}),
        None,
    )
    .expect("context");
    let request = Request::new(
        w.principal.clone(),
        w.action.clone(),
        w.resource.clone(),
        context,
        None,
    )
    .expect("request");
    let r: Response = Authorizer::new().is_authorized(&request, policies, &w.entities);
    let mut reasons: Vec<String> = r.diagnostics().reason().map(|p| p.to_string()).collect();
    reasons.sort();
    let mut errors: Vec<String> = r.diagnostics().errors().map(|e| e.to_string()).collect();
    errors.sort();
    format!("{:?} {reasons:?} {errors:?}", r.decision())
}

fuzz_target!(|input: Input| {
    let Ok(policies) = PolicySet::from_str(&input.text) else {
        return;
    };
    let reads = policies_read_usage(&policies);
    if input.reference == Some(true) {
        assert!(
            reads,
            "policy names context.usage but the walker says nobody reads it:\n{}",
            input.text
        );
    }
    // Templates are not evaluated (they need linking); the static policies are.
    let answers: Vec<String> = usages().iter().map(|u| answer(&policies, u)).collect();
    if answers.windows(2).any(|w| w[0] != w[1]) {
        assert!(
            reads,
            "the answer depends on context.usage but the walker says nobody reads it:\n{}\n{answers:#?}",
            input.text
        );
    }
});
