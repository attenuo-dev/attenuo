//! Run limits (`attenuo_core::limits`) on attacker-shaped input: a child token's `limits`
//! (deserialisation, `validate`, `narrows`, `clamp_to`), and the charges a call's arguments
//! produce (`charges_for`, `usage_charges`), with nested lists, huge numbers, floats, strings
//! with control characters, URL-ish strings for `Derive::Host` and lists around
//! `MAX_COUNTED_VALUES`. Also checks the canonical JSON every counted value is keyed by.
//!
//! Properties beyond "no panic":
//!
//! - a deserialised `Limits` round-trips through JSON; a valid one has every `max` at most
//!   `MAX_LIMIT` and argument names without control characters or `#`;
//! - `narrows` is reflexive; `clamp_to` is idempotent, never widens a child that already
//!   narrows, and narrows the parent whenever the two count the same arguments;
//! - every charge carries its limit's `max`; a `sum` charge is `amount_of` the argument; a
//!   limit counts at most `MAX_COUNTED_VALUES` values per call, each once, each canonical
//!   JSON; a `LimitArgError` names an argument that really is missing or unusable;
//! - `usage_charges` starts with one `calls` charge, has distinct destination values, at most
//!   `MAX_COUNTED_VALUES` of them, and never fails;
//! - a derived host is non-empty, lowercase, without characters URL parsers disagree on, comes
//!   from a URL of a special scheme (`https`, `http`, ...) or from a bare host (no scheme, or a
//!   "scheme" followed by a port, read as `http://` plus the string) only, and counting it
//!   again gives the same host;
//! - canonical JSON is a fixpoint (parse and canonicalise again gives the same bytes) and
//!   `jcs::value_eq` agrees with byte equality of the canonical forms.
#![no_main]

use std::collections::{BTreeMap, BTreeSet};

use arbitrary::{Arbitrary, Result, Unstructured};
use attenuo_core::limits::{
    amount_of, charges_for, usage_charges, LimitArgError, MAX_COUNTED_VALUES, MAX_LIMIT,
};
use attenuo_core::{
    jcs, AgentId, ArgConstraint, ArgLimit, Capability, CapabilitySet, Charge, DelegationChain,
    Derive, Hop, LeaseId, LimitKind, Limits, OriginatingUser, ToolCall,
};
use attenuo_fuzz::{edge_number, edge_string, json_value};
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Map, Value};
use time::Duration;

const ARGS: &[&str] = &["amount", "to", "url", "n", ""];

/// Strings that stress `Derive::Host`: hosts URL parsers disagree on, IDNA, IPs, dots.
const URLS: &[&str] = &[
    "https://a.example/x",
    "https://A.EXAMPLE./y?q=1",
    "https://a.example../",
    "https://a.example\\@b.example/",
    "https://user:pw@a.example:8443/",
    "https://[::1]/",
    "https://[::ffff:127.0.0.1]/",
    "http://127.1/",
    "http://0x7f.1/",
    "https://xn--nxasmq6b.example/",
    "https://ÉXAMPLE.com/",
    "https://exa%6dple.com/",
    "https://a.example%2F@b.example/",
    "https://a.example#@b.example/",
    "https://a.example?@b.example/",
    "https://.example/",
    "https://./",
    "https://../",
    "file:///etc/passwd",
    "file://host/x",
    "mailto:a@b.example",
    "data:text/plain,x",
    "a.example/x",
    "www.true-informations.com",
    "localhost:8080",
    "a.example:443/x",
    "a.example:99999",
    "good.example@evil.example",
    "a.example:x@b.example",
    "a.example:80@b.example",
    "javascript:alert(1)",
    "tel:911",
    "http:8080",
    "//a.example/x",
    "https:a.example",
    "https:/a.example",
    "https:\\\\a.example",
    "HTTPS://a.example",
    "ftp://a.example",
    "ws://a.example",
    "foo://a.example",
    "ssh://a.ex%61mple/",
    "git://\u{3b2}\u{3cc}\u{3bb}\u{3bf}\u{3c2}/",
    "https://a.example\u{3002}com/",
    "https://a\u{ad}.example/",
    "https://a\u{200b}.example/",
    "https://\u{ff41}.example/",
];

fn url_string(u: &mut Unstructured<'_>) -> Result<String> {
    Ok(match u.int_in_range(0u8..=5)? {
        0..=2 => (*u.choose(URLS)?).to_string(),
        3 => format!("https://{}/", edge_string(u)?),
        4 => format!("{}{}", u.choose(URLS)?, edge_string(u)?),
        _ => edge_string(u)?,
    })
}

/// An argument value: a JSON value, a URL, an amount, or a list near `MAX_COUNTED_VALUES`.
fn arg_value(u: &mut Unstructured<'_>) -> Result<Value> {
    Ok(match u.int_in_range(0u8..=7)? {
        0 | 1 => json_value(u, 4)?,
        2 => Value::String(url_string(u)?),
        3 => edge_number(u)?,
        4 => {
            let n = u.int_in_range(0usize..=8)?;
            Value::Array(
                (0..n)
                    .map(|_| -> Result<Value> {
                        Ok(match u.int_in_range(0u8..=2)? {
                            0 => Value::String(url_string(u)?),
                            1 => edge_number(u)?,
                            _ => json_value(u, 2)?,
                        })
                    })
                    .collect::<Result<_>>()?,
            )
        }
        5 => {
            // Around the boundary, distinct or repeated elements.
            let n = MAX_COUNTED_VALUES - 2 + u.int_in_range(0usize..=4)?;
            let distinct = u.arbitrary::<bool>()?;
            Value::Array(
                (0..n)
                    .map(|i| {
                        if distinct {
                            json!(format!("https://h{i}.example/"))
                        } else {
                            json!(format!("https://h{}.example/", i % 3))
                        }
                    })
                    .collect(),
            )
        }
        6 => json!(u.int_in_range(0u64..=20)?),
        _ => Value::Null,
    })
}

fn arg_name(u: &mut Unstructured<'_>) -> Result<String> {
    if u.ratio(1u8, 6u8)? {
        edge_string(u)
    } else {
        Ok((*u.choose(ARGS)?).to_string())
    }
}

fn max(u: &mut Unstructured<'_>) -> Result<u64> {
    Ok(match u.int_in_range(0u8..=5)? {
        0 => MAX_LIMIT,
        1 => MAX_LIMIT + u.int_in_range(0u64..=2)?,
        2 => u64::MAX,
        _ => u.int_in_range(0u64..=5)?,
    })
}

fn arg_limit(u: &mut Unstructured<'_>) -> Result<ArgLimit> {
    let l = ArgLimit::new(arg_name(u)?, max(u)?);
    Ok(if u.arbitrary()? {
        l.derived(Derive::Host)
    } else {
        l
    })
}

fn limits(u: &mut Unstructured<'_>) -> Result<Limits> {
    Ok(Limits {
        calls: if u.arbitrary()? { Some(max(u)?) } else { None },
        sum: if u.arbitrary()? {
            Some(arg_limit(u)?)
        } else {
            None
        },
        calls_per: if u.arbitrary()? {
            Some(arg_limit(u)?)
        } else {
            None
        },
        distinct: if u.arbitrary()? {
            Some(arg_limit(u)?)
        } else {
            None
        },
    })
}

/// A `limits` object as a child token could spell it: known members with odd values, unknown
/// members, wrong types.
fn limits_json(u: &mut Unstructured<'_>) -> Result<Value> {
    let mut m = Map::new();
    for _ in 0..u.int_in_range(0usize..=5)? {
        let key = *u.choose(&[
            "calls",
            "sum",
            "calls_per",
            "distinct",
            "Calls",
            "max",
            "derive",
            "",
        ])?;
        let v = match u.int_in_range(0u8..=4)? {
            0 => edge_number(u)?,
            1 => {
                let mut l = Map::new();
                for _ in 0..u.int_in_range(0usize..=4)? {
                    let k = *u.choose(&["arg", "max", "derive", "extra"])?;
                    let v = match k {
                        "arg" => Value::String(arg_name(u)?),
                        "max" => edge_number(u)?,
                        "derive" => json!(*u.choose(&["host", "Host", "path", ""])?),
                        _ => json_value(u, 1)?,
                    };
                    l.insert(k.into(), v);
                }
                Value::Object(l)
            }
            _ => json_value(u, 2)?,
        };
        m.insert(key.into(), v);
    }
    Ok(Value::Object(m))
}

fn constraint(u: &mut Unstructured<'_>) -> Result<ArgConstraint> {
    Ok(match u.int_in_range(0u8..=3)? {
        0 => ArgConstraint::Equals(arg_value(u)?),
        1 => ArgConstraint::OneOf(
            (0..u.int_in_range(0usize..=3)?)
                .map(|_| arg_value(u))
                .collect::<Result<_>>()?,
        ),
        2 => ArgConstraint::Prefix(edge_string(u)?),
        _ => {
            let mut bound = || -> Result<Option<i64>> {
                Ok(if u.arbitrary()? {
                    Some(u.int_in_range(-2i64..=40)?)
                } else {
                    None
                })
            };
            ArgConstraint::Range {
                min: bound()?,
                max: bound()?,
            }
        }
    })
}

fn capability(u: &mut Unstructured<'_>) -> Result<Capability> {
    let mut c = Capability::new(
        *u.choose(&["bank", "*", "b*"])?,
        *u.choose(&["send", "*", "s*", "other"])?,
    )
    .with_limits(limits(u)?);
    if u.ratio(1u8, 4u8)? {
        c = c.with_constraint(arg_name(u)?, constraint(u)?);
    }
    Ok(c)
}

#[derive(Debug)]
struct Input {
    raw_limits: Value,
    parent: Limits,
    child: Limits,
    hops: Vec<Vec<Capability>>,
    arguments: Map<String, Value>,
    tool: String,
    amount_arg: Option<String>,
    destination_arg: Option<String>,
    host_probe: String,
    pair: (Value, Value),
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut arguments = Map::new();
        for _ in 0..u.int_in_range(0usize..=5)? {
            arguments.insert(arg_name(u)?, arg_value(u)?);
        }
        let a = arg_value(u)?;
        let b = if u.arbitrary()? {
            mutate(u, &a)?
        } else {
            arg_value(u)?
        };
        Ok(Input {
            raw_limits: limits_json(u)?,
            parent: limits(u)?,
            child: limits(u)?,
            hops: (0..u.int_in_range(1usize..=3)?)
                .map(|_| {
                    (0..u.int_in_range(0usize..=3)?)
                        .map(|_| capability(u))
                        .collect::<Result<_>>()
                })
                .collect::<Result<_>>()?,
            arguments,
            tool: (*u.choose(&["send", "other", "send/x", ""])?).to_string(),
            amount_arg: if u.arbitrary()? {
                Some(arg_name(u)?)
            } else {
                None
            },
            destination_arg: if u.arbitrary()? {
                Some(match u.int_in_range(0u8..=2)? {
                    0 => format!("{}#host", arg_name(u)?),
                    1 => format!("{}#{}", arg_name(u)?, edge_string(u)?),
                    _ => arg_name(u)?,
                })
            } else {
                None
            },
            host_probe: url_string(u)?,
            pair: (a, b),
        })
    }
}

/// A value close to `v`: a number respelled, an element dropped or doubled, a string changed
/// in one character, members reordered.
fn mutate(u: &mut Unstructured<'_>, v: &Value) -> Result<Value> {
    Ok(match v {
        Value::Number(n) => match u.int_in_range(0u8..=3)? {
            0 => n
                .as_f64()
                .and_then(serde_json::Number::from_f64)
                .map(Value::Number)
                .unwrap_or(Value::Null),
            1 => n
                .as_u64()
                .map(|x| json!(x.wrapping_add(1)))
                .unwrap_or_else(|| v.clone()),
            2 => n
                .as_f64()
                .and_then(|f| serde_json::Number::from_f64(-f))
                .map(Value::Number)
                .unwrap_or(Value::Null),
            _ => edge_number(u)?,
        },
        Value::String(s) => {
            let mut s = s.clone();
            match u.int_in_range(0u8..=2)? {
                0 => s.push(*u.choose(&['.', ' ', '\u{0}', '/', 'A'])?),
                1 => s = s.to_uppercase(),
                _ => {
                    s.pop();
                }
            }
            Value::String(s)
        }
        Value::Array(items) => {
            let mut items = items.clone();
            match u.int_in_range(0u8..=2)? {
                0 if !items.is_empty() => {
                    let i = u.choose_index(items.len())?;
                    let x = items[i].clone();
                    items.push(x);
                }
                1 if !items.is_empty() => {
                    items.pop();
                }
                _ => items.reverse(),
            }
            Value::Array(items)
        }
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, x) in m.iter().rev() {
                out.insert(k.clone(), x.clone());
            }
            if u.arbitrary()? {
                if let Some((k, x)) = m.iter().next() {
                    out.insert(k.clone(), mutate(u, x)?);
                }
            }
            Value::Object(out)
        }
        other => other.clone(),
    })
}

fn canonical(v: &Value) -> Vec<u8> {
    jcs::to_vec(v).expect("a JSON value always has a canonical form")
}

fn check_canonical(bytes: &[u8]) {
    let back: Value = serde_json::from_slice(bytes).expect("canonical JSON parses");
    assert_eq!(canonical(&back), bytes, "canonical JSON is not a fixpoint");
}

/// The properties of every derived host: non-empty, lowercase, no separator.
fn check_host_shape(host: &str) {
    assert!(!host.is_empty());
    assert_eq!(host, host.to_ascii_lowercase());
    assert!(
        !host.ends_with('.'),
        "derived host {host:?} keeps a trailing dot"
    );
    assert!(
        !host.chars().any(|c| c == '\\'
            || c.is_whitespace()
            || c.is_control()
            || c == '/'
            || c == '@'),
        "derived host {host:?} holds a separator"
    );
}

/// The schemes whose hosts WHATWG parses as domains or IP addresses.
const SPECIAL: &[&str] = &["http", "https", "ws", "wss", "ftp", "file"];

/// `host` was derived from `source`. Only a special scheme has a host: any other scheme has
/// an opaque host, which WHATWG neither percent-decodes nor maps through IDNA (FZ2-2). A
/// string with no scheme is a bare host, the host of `http://` plus the string; so is one whose
/// "scheme" is followed by a port (`localhost:8080`). Counting the host again gives the same
/// host: one destination, one spelling.
fn check_host(host: &str, source: &str) {
    check_host_shape(host);
    let (scheme, rest) = source.split_once(':').unwrap_or_default();
    let is_scheme = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c));
    let special = is_scheme && SPECIAL.contains(&scheme.to_ascii_lowercase().as_str());
    if !special {
        let port = rest.split(['/', '?', '#']).next().unwrap_or_default();
        assert!(
            !is_scheme || (!port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())),
            "{source:?} has a host ({host:?}) under a non-special scheme"
        );
        let bare = Derive::Host.apply(&Value::String(format!("http://{source}")));
        assert_eq!(
            bare.as_deref(),
            Some(host),
            "bare host {source:?} is not the host of http://{source}"
        );
    }
    let again = Derive::Host.apply(&Value::String(format!("https://{host}/")));
    assert_eq!(
        again.as_deref(),
        Some(host),
        "host {host:?} (from {source:?}) counts as another host when used again"
    );
}

/// Check the host of every string in every argument (each element of a list).
fn check_hosts_of(arguments: &BTreeMap<String, Value>) {
    for v in arguments.values() {
        let items: Vec<&Value> = match v {
            Value::Array(a) => a.iter().collect(),
            other => vec![other],
        };
        for item in items {
            if let (Some(source), Some(host)) = (item.as_str(), Derive::Host.apply(item)) {
                check_host(&host, source);
            }
        }
    }
}

fn chain(hops: &[Vec<Capability>]) -> DelegationChain {
    let f = attenuo_fuzz::fixture();
    let user = OriginatingUser {
        subject: "user:mudit".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: f.now,
        attributes: BTreeMap::new(),
    };
    DelegationChain {
        originating_user: user,
        hops: hops
            .iter()
            .enumerate()
            .map(|(i, caps)| Hop {
                agent: AgentId::new(format!("agent:{i}")),
                capabilities: CapabilitySet(caps.iter().cloned().collect()),
                issued_at: f.now,
                expires_at: f.now + Duration::minutes(10),
                lease: LeaseId::new(format!("lease-{i}")),
            })
            .collect(),
    }
}

/// Do `child` and `parent` limit the same kind on different arguments (or derivations)?
fn target_mismatch(child: &Limits, parent: &Limits) -> bool {
    let differ = |c: &Option<ArgLimit>, p: &Option<ArgLimit>, derive: bool| match (c, p) {
        (Some(c), Some(p)) => c.arg != p.arg || (derive && c.derive != p.derive),
        _ => false,
    };
    differ(&child.sum, &parent.sum, false)
        || differ(&child.calls_per, &parent.calls_per, true)
        || differ(&child.distinct, &parent.distinct, true)
}

fn check_charges(chain: &DelegationChain, call: &ToolCall, charges: &[Charge]) {
    let mut seen: BTreeMap<(usize, usize, LimitKind), BTreeSet<Vec<u8>>> = BTreeMap::new();
    for c in charges {
        let hop = &chain.hops[c.hop];
        let cap = hop
            .capabilities
            .iter()
            .nth(c.cap)
            .expect("charge names a capability");
        assert!(
            cap.permits(call),
            "charged a capability that does not permit the call"
        );
        assert_eq!(c.lease, hop.lease);
        assert!(!c.usage);
        let l = &cap.limits;
        match c.kind {
            LimitKind::Calls => {
                assert_eq!(Some(c.max), l.calls);
                assert_eq!(c.amount, 1);
                assert!(c.value.is_none() && c.arg.is_none());
            }
            LimitKind::Sum => {
                let s = l.sum.as_ref().expect("sum charge without a sum limit");
                assert_eq!(c.max, s.max);
                let v = call
                    .arguments
                    .get(&s.arg)
                    .expect("charged a missing amount");
                assert_eq!(Some(c.amount), amount_of(v));
                assert!(c.amount <= MAX_LIMIT);
                assert!(c.value.is_none());
            }
            LimitKind::CallsPer | LimitKind::Distinct => {
                let al = if c.kind == LimitKind::CallsPer {
                    &l.calls_per
                } else {
                    &l.distinct
                };
                let al = al.as_ref().expect("per-value charge without its limit");
                assert_eq!(c.max, al.max);
                assert_eq!(c.amount, 1);
                assert_eq!(c.arg.as_deref(), Some(al.counted().as_str()));
                let value = c.value.as_ref().expect("per-value charge without a value");
                check_canonical(value);
                if al.derive.is_some() {
                    let host: Value = serde_json::from_slice(value).unwrap();
                    check_host_shape(host.as_str().expect("a derived value is a string"));
                }
                let set = seen.entry((c.hop, c.cap, c.kind)).or_default();
                assert!(set.insert(value.clone()), "a value was counted twice");
                assert!(set.len() <= MAX_COUNTED_VALUES);
            }
        }
    }
}

fn check_arg_error(chain: &DelegationChain, call: &ToolCall, e: &LimitArgError) {
    // Some matching limit of that hop counts that argument, and it is unusable.
    let hop = &chain.hops[e.hop];
    let explained = hop.capabilities.iter().any(|cap| {
        if !cap.permits(call) {
            return false;
        }
        let l = &cap.limits;
        let al = match e.kind {
            LimitKind::Sum => &l.sum,
            LimitKind::CallsPer => &l.calls_per,
            LimitKind::Distinct => &l.distinct,
            LimitKind::Calls => return false,
        };
        let Some(al) = al else { return false };
        if al.counted() != e.arg && al.arg != e.arg {
            return false;
        }
        match call.arguments.get(&al.arg).filter(|v| !v.is_null()) {
            None => true,
            Some(v) if e.kind == LimitKind::Sum => amount_of(v).is_none(),
            Some(v) => {
                let items: Vec<&Value> = match v {
                    Value::Array(a) => a.iter().collect(),
                    other => vec![other],
                };
                items.len() > MAX_COUNTED_VALUES
                    || al
                        .derive
                        .is_some_and(|d| items.iter().any(|x| d.apply(x).is_none()))
            }
        }
    });
    assert!(explained, "limit_arg_invalid without a cause: {e}");
}

/// Does `v` survive a JSON round trip? Tool arguments arrive as JSON text, which `serde_json`
/// parses at most 128 levels deep; deeper generated values are not reachable.
fn reachable(v: &Value) -> bool {
    serde_json::from_slice::<Value>(&serde_json::to_vec(v).unwrap()).is_ok()
}

fuzz_target!(|input: Input| {
    let args = Value::Object(input.arguments.clone());
    if !reachable(&args) || !reachable(&input.pair.0) || !reachable(&input.pair.1) {
        return;
    }
    // 1. Deserialisation and validation of a child's `limits`.
    if let Ok(l) = serde_json::from_value::<Limits>(input.raw_limits.clone()) {
        let back: Limits =
            serde_json::from_value(serde_json::to_value(&l).unwrap()).expect("round trip");
        assert_eq!(back, l);
        let cap = Capability::new("bank", "send").with_limits(l.clone());
        if cap.validate_limits().is_ok() {
            assert!(l.calls.is_none_or(|c| c <= MAX_LIMIT));
            for al in [&l.sum, &l.calls_per, &l.distinct].into_iter().flatten() {
                assert!(al.max <= MAX_LIMIT);
                assert!(!al.arg.is_empty());
                assert!(!al.arg.chars().any(|c| c.is_control() || c == '#'));
            }
            assert!(l.sum.as_ref().is_none_or(|s| s.derive.is_none()));
        }
    }

    // 2. Narrowing and clamping.
    let (parent, child) = (&input.parent, &input.child);
    assert!(parent.narrows(parent) && child.narrows(child));
    let clamped = Limits::clamp_to(child, parent);
    assert_eq!(
        Limits::clamp_to(&clamped, parent),
        clamped,
        "clamp_to is not idempotent"
    );
    if child.narrows(parent) {
        // It may still lower a figure the child's `calls` already bounds; it never widens.
        assert!(
            clamped.narrows(child) && clamped.narrows(parent),
            "clamp_to widened a child that already narrows: {child:?} -> {clamped:?}"
        );
    }
    if !target_mismatch(child, parent) {
        assert!(
            clamped.narrows(parent),
            "clamped limits do not narrow the parent: {child:?} -> {clamped:?} under {parent:?}"
        );
    }

    // 3. Charges of a call against a chain of limited capabilities.
    let chain = chain(&input.hops);
    let call = ToolCall::new("bank", input.tool.clone(), Value::Object(input.arguments));
    check_hosts_of(&call.arguments);
    match charges_for(&chain, &call) {
        Ok(charges) => check_charges(&chain, &call, &charges),
        Err(e) => check_arg_error(&chain, &call, &e),
    }

    // 4. Run usage never fails and bounds its destinations.
    let run = LeaseId::new("run-1");
    let usage = usage_charges(
        &run,
        &call,
        input.amount_arg.as_deref(),
        input.destination_arg.as_deref(),
    );
    assert!(!usage.is_empty() && usage[0].kind == LimitKind::Calls && usage[0].amount == 1);
    assert!(usage
        .iter()
        .all(|c| c.usage && c.max == MAX_LIMIT && c.lease == run));
    let dests: Vec<&Vec<u8>> = usage
        .iter()
        .filter(|c| c.kind == LimitKind::CallsPer)
        .map(|c| c.value.as_ref().expect("destination has a value"))
        .collect();
    assert!(dests.len() <= MAX_COUNTED_VALUES);
    assert_eq!(
        dests.iter().collect::<BTreeSet<_>>().len(),
        dests.len(),
        "a destination was counted twice in one call"
    );
    for d in dests {
        check_canonical(d);
    }

    // 5. Host derivation on an arbitrary string.
    if let Some(host) = Derive::Host.apply(&Value::String(input.host_probe.clone())) {
        check_host(&host, &input.host_probe);
    }

    // 6. Canonical JSON and its equality.
    let (a, b) = &input.pair;
    let (ca, cb) = (canonical(a), canonical(b));
    check_canonical(&ca);
    assert_eq!(
        jcs::value_eq(a, b),
        ca == cb,
        "value_eq disagrees with canonical bytes: {a} vs {b}"
    );
});
