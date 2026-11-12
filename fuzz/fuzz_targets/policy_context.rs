//! The policy engine on arbitrary tool-call arguments and originating-user attributes: the
//! JSON-to-Cedar context translation (depth, numbers at the i64 edges, floats, strings with
//! control characters, `__`-prefixed keys) and the catalog's declared-type checks. The engine
//! must never panic and must always return one of its documented reasons; an allow must have
//! passed the capability and catalog stages. Also runs the AuthZEN entry point
//! (`PolicyEngine::evaluate`) on arbitrary JSON.
//!
//! `github/create_issue` declares every input type, `decimal` and `set<decimal>` included, and
//! its outcome is predicted by an oracle written here: a wrong user attribute gives
//! `attribute_type_mismatch`, then a wrong input gives `input_type_mismatch`, and anything else
//! reaches Cedar. The decimal oracle reads the number as the upstream is sent it (re-encoded by
//! `serde_json`, SR-95) and works on exact digits, so the `dec_` policies that compare it with
//! `lessThan`, `greaterThan`, `lessThanOrEqual`, `greaterThanOrEqual` and set membership must
//! match exactly when the oracle says they do. Decimal arguments are generated as JSON text:
//! many fractional digits, huge magnitudes, negative zero, exponents, very long digit strings,
//! and the same text as a string.
#![no_main]

use std::sync::OnceLock;

use arbitrary::{Arbitrary, Result, Unstructured};
use attenuo_core::{
    AgentId, Capability, CapabilitySet, Decision, DelegationChain, LeaseId, OriginatingUser,
    ToolCall,
};
use attenuo_fuzz::{edge_string, json_value};
use attenuo_policy::{
    ArgType, PolicyEngine, PolicyEngineBuilder, ToolAttrs, ToolCatalog, UnknownTools,
    DEFAULT_POLICIES,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Number, Value};
use time::Duration;

const EXTRA_POLICIES: &str = r#"
@id("forbid_zero")
forbid(principal, action == Action::"github/create_issue", resource)
when { context.input has n && context.input.n == 0 };

@id("permit_tagged")
permit(principal, action == Action::"github/create_issue", resource)
when { context.input has tags && context.input.tags.contains("ok") };

@id("dec_forbid_over")
forbid(principal, action == Action::"github/create_issue", resource)
when { context.input has amount && context.input.amount.greaterThan(decimal("1000.0")) };

@id("dec_forbid_under")
forbid(principal, action == Action::"github/create_issue", resource)
when { context.input has amount && context.input.amount.lessThan(decimal("-1000.0")) };

@id("dec_permit_small")
permit(principal, action == Action::"github/create_issue", resource)
when { context.input has amount &&
       context.input.amount.greaterThanOrEqual(decimal("0.0")) &&
       context.input.amount.lessThanOrEqual(decimal("100.0")) };

@id("dec_forbid_listed")
forbid(principal, action == Action::"github/create_issue", resource)
when { context.input has amount &&
       [decimal("0.1"), decimal("-0.0001"), decimal("922337203685477.0")]
           .contains(context.input.amount) };

@id("dec_forbid_fee")
forbid(principal, action == Action::"github/create_issue", resource)
when { context.input has fees && context.input.fees.contains(decimal("13.37")) };

@id("forbid_suspended")
forbid(principal, action, resource)
when { context.originating_user.attributes has tenant &&
       context.originating_user.attributes.tenant == "suspended" };
"#;

const ARGS: &[&str] = &[
    "repo", "n", "flag", "tags", "amount", "fees", "path", "__entity", "__extn", "",
];
const TOOLS: &[&str] = &["create_issue", "read_file", "delete_repo", "unknown", "a/b"];
const ATTRS: &[&str] = &["mfa", "roles", "tenant", "email", "level", "__expr"];

fn engines() -> &'static [PolicyEngine] {
    static E: OnceLock<Vec<PolicyEngine>> = OnceLock::new();
    E.get_or_init(|| {
        // `decimal` is a catalog input type only.
        for ty in [ArgType::Decimal, ArgType::Set(Box::new(ArgType::Decimal))] {
            assert!(PolicyEngineBuilder::new()
                .with_user_attr("amount", ty)
                .build()
                .is_err());
        }
        let catalog = ToolCatalog::new()
            .with(
                "github",
                "create_issue",
                ToolAttrs::new()
                    .with_input("repo", ArgType::String)
                    .with_input("n", ArgType::Long)
                    .with_input("flag", ArgType::Bool)
                    .with_input("tags", ArgType::Set(Box::new(ArgType::String)))
                    .with_input("amount", ArgType::Decimal)
                    .with_input("fees", ArgType::Set(Box::new(ArgType::Decimal))),
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

/// Decimal texts at the edges: Cedar's range, the 4-digit limit, negative zero, and numbers
/// with more digits than a double holds (SR-95).
const EDGE_DECIMALS: &[&str] = &[
    "0",
    "-0",
    "0.0",
    "-0.0",
    "-0e0",
    "0.1",
    "0.10000000000000001",
    "0.1000",
    "0.00001",
    "-0.0001",
    "0.0001",
    "1e-4",
    "1E-5",
    "1e3",
    "1e15",
    "1e16",
    "1e300",
    "1e-300",
    "5e-324",
    "13.37",
    "13.3700",
    "13.37000000000001",
    "100",
    "100.0",
    "100.00001",
    "1000",
    "1000.0001",
    "999.9999",
    "-1000",
    "-1000.0001",
    "-999.99999",
    "1000000000000.00001",
    "12345678901.234500001",
    "99999999999.99999",
    "922337203685477",
    "922337203685477.0",
    "922337203685477.5807",
    "922337203685478",
    "-922337203685477",
    "-922337203685477.5808",
    "9223372036854775807",
    "-9223372036854775808",
    "18446744073709551615",
    "18446744073709551616",
    "1.7976931348623157e308",
];

fn digits(u: &mut Unstructured<'_>, max: usize) -> Result<String> {
    let n = u.int_in_range(0usize..=max)?;
    (0..n)
        .map(|_| u.int_in_range(b'0'..=b'9').map(char::from))
        .collect()
}

/// JSON number text for a decimal argument, valid JSON or not.
fn decimal_text(u: &mut Unstructured<'_>) -> Result<String> {
    let sign = if u.arbitrary()? { "-" } else { "" };
    Ok(match u.int_in_range(0u8..=6)? {
        0 | 1 => (*u.choose(EDGE_DECIMALS)?).to_string(),
        2 => {
            let int = digits(u, 18)?;
            let frac = digits(u, 9)?;
            let int = if int.is_empty() { "0".into() } else { int };
            let mut t = format!("{sign}{int}");
            if !frac.is_empty() {
                t.push('.');
                t.push_str(&frac);
            }
            if u.ratio(1u8, 4u8)? {
                t.push_str(&format!("e{}", u.int_in_range(-30i32..=30)?));
            }
            t
        }
        // Very long digit strings, whole or fractional.
        3 => {
            let int = digits(u, 400)?;
            let int = if int.is_empty() { "1".into() } else { int };
            let frac = digits(u, 400)?;
            if frac.is_empty() {
                format!("{sign}{int}")
            } else {
                format!("{sign}{int}.{frac}")
            }
        }
        // Next to a comparison bound, with 4 or 5 fractional digits.
        4 => {
            let base = *u.choose(&[0i64, 13, 100, 999, 1000, 922_337_203_685_476])?;
            if u.arbitrary()? {
                format!("{sign}{base}.{:04}", u.int_in_range(0u32..=9999)?)
            } else {
                format!("{sign}{base}.{:05}", u.int_in_range(0u32..=99999)?)
            }
        }
        5 => u.arbitrary::<f64>()?.to_string(),
        _ => u.arbitrary::<i64>()?.to_string(),
    })
}

/// A decimal argument: usually a JSON number parsed from [`decimal_text`] (as the proxy parses
/// a request body), sometimes the same text as a string, or any JSON value.
fn decimal_value(u: &mut Unstructured<'_>) -> Result<Value> {
    Ok(match u.int_in_range(0u8..=9)? {
        0 => Value::String(decimal_text(u)?),
        1 => json_value(u, 2)?,
        2 => Value::Null,
        _ => {
            let text = decimal_text(u)?;
            match serde_json::from_str::<Value>(&text) {
                Ok(v) => v,
                Err(_) => Value::String(text),
            }
        }
    })
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
        if u.ratio(3u8, 4u8)? {
            arguments.insert("amount".into(), decimal_value(u)?);
        }
        if u.ratio(1u8, 2u8)? {
            let fees = if u.ratio(1u8, 8u8)? {
                decimal_value(u)?
            } else {
                let n = u.int_in_range(0usize..=5)?;
                Value::Array((0..n).map(|_| decimal_value(u)).collect::<Result<_>>()?)
            };
            arguments.insert("fees".into(), fees);
        }
        Ok(Input {
            engine: u.int_in_range(0usize..=2)?,
            attributes,
            server: if u.ratio(1u8, 8u8)? {
                edge_string(u)?
            } else {
                "github".into()
            },
            tool: if u.arbitrary()? {
                "create_issue".into()
            } else {
                key(u, TOOLS)?
            },
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

/// Cedar's decimal range, times 10^4: `decimal_text` refuses a magnitude above 922337203685477.
const DECIMAL_MAX_SCALED: i128 = 922_337_203_685_477 * 10_000;

/// The exact value of a JSON number text times 10^4, when it has at most 4 fractional digits
/// (trailing zeros aside) and a magnitude of at most 922337203685477; `None` otherwise. Works
/// on the digits, so nothing is rounded.
fn decimal_oracle(text: &str) -> Option<i128> {
    let (neg, rest) = match text.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, text),
    };
    let (mant, exp) = match rest.find(['e', 'E']) {
        Some(i) => (&rest[..i], rest[i + 1..].parse::<i64>().ok()?),
        None => (rest, 0),
    };
    let (int, frac) = mant.split_once('.').unwrap_or((mant, ""));
    let all = format!("{int}{frac}");
    assert!(
        all.bytes().all(|b| b.is_ascii_digit()),
        "odd number text {text}"
    );
    let all = all.trim_start_matches('0');
    if all.is_empty() {
        return Some(0);
    }
    let trimmed = all.trim_end_matches('0');
    // value = trimmed * 10^scale
    let scale = exp - frac.len() as i64 + (all.len() - trimmed.len()) as i64;
    if scale < -4 || trimmed.len() as i64 + scale + 4 > 20 {
        return None;
    }
    let mut v: i128 = trimmed.parse().ok()?;
    for _ in 0..scale + 4 {
        v *= 10;
    }
    (v <= DECIMAL_MAX_SCALED).then_some(if neg { -v } else { v })
}

/// A `decimal` argument as the oracle reads it: the text the upstream is sent.
fn as_decimal(v: &Value) -> Option<i128> {
    match v {
        Value::Number(n) => decimal_oracle(&serde_json::to_string(n).unwrap()),
        _ => None,
    }
}

fn whole_long(n: &Number) -> bool {
    n.as_i64().is_some()
        || n.as_f64()
            .is_some_and(|f| f.is_finite() && f.fract() == 0.0 && f.abs() <= 922_337_203_685_477.0)
}

/// Every declared `create_issue` input is absent, `null` or of its type.
fn inputs_ok(args: &std::collections::BTreeMap<String, Value>) -> bool {
    let ok =
        |name: &str, f: &dyn Fn(&Value) -> bool| args.get(name).is_none_or(|v| v.is_null() || f(v));
    let set = |f: fn(&Value) -> bool| {
        move |v: &Value| {
            v.as_array()
                .is_some_and(|a| a.iter().all(|i| i.is_null() || f(i)))
        }
    };
    ok("repo", &|v| v.is_string())
        && ok("n", &|v| v.as_number().is_some_and(whole_long))
        && ok("flag", &|v| v.is_boolean())
        && ok("tags", &set(|i| i.is_string()))
        && ok("amount", &|v| as_decimal(v).is_some())
        && ok("fees", &set(|i| as_decimal(i).is_some()))
}

fn sorted(mut o: attenuo_policy::Outcome) -> attenuo_policy::Outcome {
    o.policy_ids.sort_unstable();
    o.diagnostics.sort_unstable();
    o
}

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
    if call.server == "github" && call.tool == "create_issue" {
        check_create_issue(&chain, &call, &out);
    }
    // Deterministic, up to the order of `policy_ids` and `diagnostics`: Cedar returns the
    // determining policies and the errors as hash sets, so two forbids that both match can come
    // back in either order from one call to the next (found by this target once `amount` could
    // match two `dec_` forbids at once).
    assert_eq!(sorted(engine.authorize(&chain, &call, f.now)), sorted(out));

    if let Some(bytes) = input.authzen {
        if let Ok(req) =
            serde_json::from_slice::<attenuo_policy::authzen::EvaluationRequest>(&bytes)
        {
            let _ = engine.evaluate(&req, f.now);
        }
    }
});

/// The `create_issue` outcome against the oracle: the stage that denies, and which `dec_`
/// policies decided.
fn check_create_issue(chain: &DelegationChain, call: &ToolCall, out: &attenuo_policy::Outcome) {
    // The default schema's user attributes plus `level`; a set's elements may not be `null`
    // here, unlike in call arguments.
    let attrs = &chain.originating_user.attributes;
    let attr = |name: &str, f: &dyn Fn(&Value) -> bool| {
        attrs.get(name).is_none_or(|v| v.is_null() || f(v))
    };
    let attrs_ok = attr("mfa", &|v| v.is_boolean())
        && attr("roles", &|v| {
            v.as_array().is_some_and(|a| a.iter().all(Value::is_string))
        })
        && attr("tenant", &|v| v.is_string())
        && attr("email", &|v| v.is_string())
        && attr("level", &|v| v.as_i64().is_some());
    if !attrs_ok {
        assert_eq!(
            out.reason,
            attenuo_policy::REASON_ATTRIBUTE_TYPE_MISMATCH,
            "{out:?}"
        );
        return;
    }
    if !inputs_ok(&call.arguments) {
        assert_eq!(
            out.reason,
            attenuo_policy::REASON_INPUT_TYPE_MISMATCH,
            "{out:?}"
        );
        return;
    }
    assert!(
        [
            attenuo_policy::REASON_POLICY_ALLOW,
            attenuo_policy::REASON_POLICY_DENY,
            attenuo_policy::REASON_POLICY_ERROR,
        ]
        .contains(&out.reason.as_str()),
        "typed inputs must reach Cedar: {out:?}"
    );
    // The type check is what keeps the decimal methods from raising a type error.
    assert!(
        !out.diagnostics.iter().any(|d| d.contains("dec_")),
        "a dec_ policy errored on checked inputs: {out:?} {:?}",
        call.arguments
    );
    if out.reason == attenuo_policy::REASON_POLICY_ERROR {
        return;
    }
    let amount = call.arguments.get("amount").and_then(as_decimal);
    let fees: Vec<i128> = call
        .arguments
        .get("fees")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(as_decimal).collect())
        .unwrap_or_default();
    let mut want: Vec<&str> = Vec::new();
    if let Some(a) = amount {
        if a > 1000 * 10_000 {
            want.push("dec_forbid_over");
        }
        if a < -1000 * 10_000 {
            want.push("dec_forbid_under");
        }
        if [1_000, -1, DECIMAL_MAX_SCALED].contains(&a) {
            want.push("dec_forbid_listed");
        }
    }
    if fees.contains(&133_700) {
        want.push("dec_forbid_fee");
    }
    want.sort_unstable();
    let small = amount.is_some_and(|a| (0..=100 * 10_000).contains(&a));
    let mut got: Vec<&str> = out
        .policy_ids
        .iter()
        .map(String::as_str)
        .filter(|id| id.starts_with("dec_") && *id != "dec_permit_small")
        .collect();
    got.sort_unstable();
    if out.decision == Decision::Allow {
        assert!(
            want.is_empty(),
            "allowed past {want:?}: {:?}",
            call.arguments
        );
        assert_eq!(
            out.policy_ids.iter().any(|id| id == "dec_permit_small"),
            small,
            "dec_permit_small: {:?} {out:?}",
            call.arguments
        );
    } else {
        assert_eq!(got, want, "{:?} {out:?}", call.arguments);
    }
}
