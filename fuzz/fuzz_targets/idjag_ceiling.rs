//! The ID-JAG ceiling (`[idps.id_jag_ceiling]`, `idp/ceiling.rs`) and the hop-0 narrowing
//! under it (`idp/intake.rs` `narrow`), through the `fuzzing` feature of attenuo-server, which
//! wraps the server's own functions. Generated: a ceiling config (`resources` and `scopes`
//! over small capability sets, some with limits), a root grant (some capabilities limited),
//! the ID-JAG's claims (`scope` strings with repeats and odd whitespace, `resource` as a
//! string or an array with repeats and non-strings, `authorization_details` with the right
//! and the wrong `type`, capabilities with and without limits, malformed members) and a
//! request. Half the inputs are shaped (and every short one, since exhausted input picks the
//! shaped branch): a broad grant, a valid config, the `scope` and `authorization_details`
//! claims both present, the details built under the `scopes` entries the claim names and told
//! apart by an argument nothing else constrains, and a request of one capability per named one
//! or two per named one. Without that, a request that passes every check with a limited step
//! between was too rare for a property to see a planted bug within minutes.
//!
//! Properties beyond "no panic":
//!
//! 1. A config `from_config` accepts is built whole: under the grant `*:*`, each `scopes`
//!    token alone gives exactly the capabilities it maps to, and each `resources` value alone
//!    gives `<server>:*` for each server it maps to. (A refused config is an `Err` and nothing
//!    else, which the types already say.)
//! 2. The ceiling is within the grant: every ceiling capability is covered by one grant
//!    capability, limits included (`covers` checks the limits too), and by every recorded step.
//! 3. A claim with repeated or reordered values gives the same ceiling as its distinct set
//!    (SR-129): `scope` tokens deduplicated and sorted, a `resource` array reduced to its
//!    distinct strings, `authorization_details` entries and capabilities reversed (not
//!    repeated: more than 256 capability objects name nothing on purpose, SR-123). SR-129
//!    itself was a cost bug, which equal answers do not show, so the target also counts the
//!    heap allocations of `apply` on both claims: the repeated claim may cost at most a few
//!    more (the token list grows, log-many times) than the distinct one.
//! 4. Every `limited_steps` entry holds a limited capability and is within the grant.
//! 5. When narrowing succeeds, every result capability is covered by the grant, by the final
//!    ceiling and by every recorded step. For each of those three, as each is checked by the
//!    server (the grant over the request, the final ceiling over the request as the grant left
//!    it, each step over the result), no limited capability is the chosen parent (the first
//!    that covers with its limits, else the first that covers the calls, as in
//!    `capability_attenuate_root`, from `attenuo_fuzz::caps`'s reference) of two distinct
//!    result capabilities. The result is also the reference attenuation's.
//! 6. A budget, in a mode where no two limited capabilities of the grant and the used `scopes`
//!    entries overlap and no capability without limits overlaps one of the same side (the
//!    grant's limited capabilities are on servers `g0` and `g1`, which no other grant
//!    capability and no limited `scopes` capability names; the `scopes` limited capabilities
//!    are on `s0` and `s1`, which no other `scopes` capability names; each limited one is on
//!    its own exact `server:tool`; `authorization_details` carries no limits). Each limited
//!    capability `S` of the grant, and of a `scopes` entry the `scope` claim names, is then the
//!    only source of limits for the calls it covers, and the sum over result capabilities
//!    whose calls `S` covers of their `calls` (and of their `sum` on `S`'s argument) is at
//!    most `S`'s figure. This is stronger than 5 where it holds: it is stated against the
//!    configured sources, not the intermediate sets, so it holds whatever path `meet` copies a
//!    limit along. `calls_per` and `distinct` are left out: a per-value bound is not additive.
//!    Outside the mode it does not hold today, by design or by SR-128 (below).
//! 7. Narrowing does not depend on the order in which the request lists its capabilities: the
//!    same set, or the same error code.
//!
//! Not covered: SR-128 (security review pass 17), a known open gap. Overlapping limited
//! capabilities of one grant entry, or of one ceiling, are not combined at hop 0: a requested
//! capability takes its limits from one of them and is not charged by the other. Property 5 is
//! stated per chosen parent, which is what the code promises, and property 6 only where no two
//! limited capabilities overlap, so that gap is not reported.
#![no_main]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use arbitrary::{Arbitrary, Result, Unstructured};
use attenuo_core::{ArgConstraint, ArgLimit, Capability, CapabilitySet, Limits};
use attenuo_fuzz::caps::{
    attenuate_indexed_ref, capability, caps, constraint, covers_calls_ref, limits, set_covers_ref,
    ARGS,
};
use attenuo_server::config::{CapSpec, IdJagCeilingConfig};
use attenuo_server::fuzzing::{narrow, Applied, IdJagCeiling};
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Map, Value};

/// Counts allocations while [`COUNTING`] is set (libFuzzer runs inputs on one thread).
struct Counting;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn counted<T>(f: impl FnOnce() -> T) -> (T, usize) {
    ALLOCS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let out = f();
    COUNTING.store(false, Ordering::Relaxed);
    (out, ALLOCS.load(Ordering::Relaxed))
}

/// What a repeated claim may cost over its distinct set: growing the list of each of the two
/// claims' tokens (`collect` doubles, so at most 64 times for any length) and slack.
const REPEAT_ALLOC_SLACK: usize = 64 + 16;

const RES_KEYS: &[&str] = &["r1", "r2", "https://a.example/", " r1", "", " "];
const SCOPE_KEYS: &[&str] = &["s1", "s2", "read", "write", "", "a b", "x\u{a0}"];
/// Claim tokens: the keys, unmapped ones, and keys joined by a character that is whitespace
/// to `char::is_whitespace` but not to `split_ascii_whitespace`.
const CLAIM_TOKENS: &[&str] = &["s1", "s2", "read", "write", "zz", "S1", "s1\u{b}s2"];
const SEPARATORS: &[&str] = &[" ", "  ", "\t", "\n", "\r\n", "\u{c}", "\u{a0}", "\u{b}"];
/// Server names a `scopes` capability may have (`*`, or a valid exact name), and some it may
/// not.
const SCOPE_SERVERS: &[&str] = &["*", "a", "ab", "abc", "b", "A", "a*", "r/x"];
const RES_SERVERS: &[&str] = &["a", "ab", "b", "A", "g0", "s0", "", "a/b"];

// The disjoint mode (property 6).
const G_SERVERS: &[&str] = &["g0", "g1"];
const S_SERVERS: &[&str] = &["s0", "s1"];
const LIM_TOOLS: &[&str] = &["t0", "t1"];
/// Servers of grant capabilities without limits in the disjoint mode: never `g*`.
const G_FREE_SERVERS: &[&str] = &["a", "ab", "a*", "s0", "s1", "s*", "*a"];
/// Servers of `scopes` capabilities without limits in the disjoint mode: never `s*`.
const S_FREE_SERVERS: &[&str] = &["a", "ab", "g0", "g1"];

#[derive(Debug)]
struct Input {
    disjoint: bool,
    grant: CapabilitySet,
    cfg: IdJagCeilingConfig,
    claims: Map<String, Value>,
    request: Vec<Capability>,
    order: Vec<usize>,
}

fn valid(c: &Capability) -> bool {
    c.validate().is_ok() && c.validate_limits().is_ok() && c.validate_size().is_ok()
}

/// Limits with at least one of `calls` and `sum`, so the capability is a budget source.
fn some_limits(u: &mut Unstructured<'_>) -> Result<Limits> {
    let mut l = limits(u)?;
    if l.calls.is_none() && l.sum.is_none() {
        if u.arbitrary()? {
            l.calls = Some(u.int_in_range(0u64..=3)?);
        } else {
            l.sum = Some(ArgLimit::new(*u.choose(ARGS)?, u.int_in_range(0u64..=3)?));
        }
    }
    Ok(l)
}

/// `c`, sometimes narrowed by a constraint, another tool or other limits: the shapes that
/// share a parent.
fn variant(u: &mut Unstructured<'_>, c: &Capability, with_limits: bool) -> Result<Capability> {
    let mut c = c.clone();
    match u.int_in_range(0u8..=3)? {
        0 => {}
        1 if with_limits => c.limits = limits(u)?,
        1 | 2 => {
            c.constraints
                .insert((*u.choose(ARGS)?).to_string(), constraint(u, 12)?);
        }
        _ => c.tool = attenuo_fuzz::caps::name(u)?,
    }
    if !with_limits {
        c.limits = Limits::default();
    }
    Ok(c)
}

fn free_capability(u: &mut Unstructured<'_>, servers: &[&str]) -> Result<Capability> {
    let mut c = capability(u, 12)?;
    c.server = (*u.choose(servers)?).to_string();
    if u.ratio(1u8, 2u8)? {
        c.tool = (*u.choose(LIM_TOOLS)?).to_string();
    }
    c.limits = Limits::default();
    Ok(c)
}

/// One capability per distinct `server:tool` of `servers` × [`LIM_TOOLS`], each limited.
fn limited_pool(
    u: &mut Unstructured<'_>,
    servers: &[&str],
    at_least_one: bool,
) -> Result<Vec<Capability>> {
    let mut out = Vec::new();
    for s in servers {
        for t in LIM_TOOLS {
            let first = s == &servers[0] && t == &LIM_TOOLS[0];
            if (at_least_one && first) || u.arbitrary()? {
                let mut c = Capability::new(*s, *t);
                if u.ratio(1u8, 3u8)? {
                    c.constraints
                        .insert((*u.choose(ARGS)?).to_string(), constraint(u, 12)?);
                }
                c.limits = some_limits(u)?;
                out.push(c);
            }
        }
    }
    Ok(out)
}

fn spec(u: &mut Unstructured<'_>, c: Capability) -> Result<CapSpec> {
    Ok(
        if c.constraints.is_empty() && c.limits.is_empty() && u.ratio(1u8, 3u8)? {
            CapSpec::Short(format!("{}:{}", c.server, c.tool))
        } else {
            CapSpec::Full(c)
        },
    )
}

fn capability_object(u: &mut Unstructured<'_>, c: &Capability) -> Result<Value> {
    let mut v = serde_json::to_value(c).unwrap_or(Value::Null);
    if let Some(obj) = v.as_object_mut() {
        // Arm 0, which exhausted input picks, leaves the object well formed.
        match u.int_in_range(0u8..=11)? {
            8 => {
                obj.insert("extra".into(), json!(1));
            }
            9 => {
                obj.remove("tool");
            }
            10 => {
                obj.insert("server".into(), json!(5));
            }
            11 => {
                obj.insert("limits".into(), json!({"calls": "x"}));
            }
            _ => {}
        }
    }
    Ok(v)
}

fn scope_claim(u: &mut Unstructured<'_>, keys: &[String], shaped: bool) -> Result<Value> {
    let mut s = String::new();
    if u.ratio(1u8, 4u8)? {
        s.push_str(u.choose(SEPARATORS)?);
    }
    let mut tokens = Vec::new();
    for _ in 0..u.int_in_range(usize::from(shaped)..=4)? {
        if !keys.is_empty() && u.ratio(2u8, 3u8)? {
            tokens.push(keys[u.choose_index(keys.len())?].as_str());
        } else {
            tokens.push(*u.choose(CLAIM_TOKENS)?);
        }
    }
    // Many repeats now and then (SR-129).
    let repeat = if u.ratio(1u8, 5u8)? {
        u.int_in_range(2usize..=400)?
    } else {
        1
    };
    for _ in 0..repeat {
        for t in &tokens {
            s.push_str(t);
            let sep = if u.ratio(1u8, 3u8).unwrap_or(false) {
                u.choose(SEPARATORS).unwrap_or(&" ")
            } else {
                " "
            };
            s.push_str(sep);
        }
    }
    Ok(Value::String(s))
}

fn resource_claim(u: &mut Unstructured<'_>) -> Result<Value> {
    let pick = |u: &mut Unstructured<'_>| -> Result<Value> {
        Ok(match u.int_in_range(0u8..=9)? {
            0 => json!(1),
            1 => Value::Null,
            2 => json!(["r1"]),
            3 => json!({"r": "r1"}),
            _ => Value::String((*u.choose(RES_KEYS)?).to_string()),
        })
    };
    Ok(if u.ratio(1u8, 3u8)? {
        Value::String((*u.choose(RES_KEYS)?).to_string())
    } else {
        let mut items = Vec::new();
        for _ in 0..u.int_in_range(0..=4)? {
            items.push(pick(u)?);
        }
        let repeat = if u.ratio(1u8, 5u8)? {
            u.int_in_range(2usize..=200)?
        } else {
            1
        };
        Value::Array((0..repeat).flat_map(|_| items.iter().cloned()).collect())
    })
}

/// `named` receives the capabilities generated, so the request can ask for them: two of them
/// under one limited capability of an earlier step is the shape of SR-127.
fn details_claim(
    u: &mut Unstructured<'_>,
    scope_pool: &[Capability],
    pool: &[Capability],
    disjoint: bool,
    shaped: bool,
    named: &mut Vec<Capability>,
) -> Result<Value> {
    let mut entries = Vec::new();
    for _ in 0..u.int_in_range(usize::from(shaped)..=3)? {
        let kind = match if shaped { 0 } else { u.int_in_range(0u8..=7)? } {
            5 => json!("other"),
            6 => json!(5),
            7 => Value::Null,
            _ => json!(attenuo_token::AUTHORIZATION_DETAILS_TYPE),
        };
        let mut objects = Vec::new();
        // Shaped: several capabilities, which exhausted input leaves at 4.
        let n = if shaped {
            4 - u.int_in_range(0..=2)?
        } else {
            u.int_in_range(0..=4)?
        };
        for k in 0..n {
            let from_scope = !scope_pool.is_empty() && u.ratio(2u8, 3u8)?;
            let mut c = if from_scope {
                let i = u.choose_index(scope_pool.len())?;
                variant(u, &scope_pool[i], true)?
            } else if !pool.is_empty() && u.ratio(2u8, 3u8)? {
                let i = u.choose_index(pool.len())?;
                variant(u, &pool[i], true)?
            } else {
                capability(u, 12)?
            };
            if disjoint || u.arbitrary()? {
                c.limits = Limits::default();
            }
            // Shaped: tell the capabilities apart by an argument nothing else constrains, so
            // several stay under one capability of the scope step.
            if shaped && u.ratio(1u8, 2u8)? {
                c.constraints
                    .insert("k".into(), ArgConstraint::Equals(Value::from(k)));
            }
            objects.push(capability_object(u, &c)?);
            named.push(c);
        }
        let mut entry = Map::new();
        if !kind.is_null() {
            entry.insert("type".into(), kind);
        }
        entry.insert(
            "capabilities".into(),
            if !shaped && u.ratio(1u8, 10u8)? {
                json!("not an array")
            } else {
                Value::Array(objects)
            },
        );
        entries.push(Value::Object(entry));
    }
    Ok(Value::Array(entries))
}

/// A claim: mostly well formed, sometimes `null` or of the wrong type, `None` when absent.
fn claim(
    u: &mut Unstructured<'_>,
    good: impl FnOnce(&mut Unstructured<'_>) -> Result<Value>,
) -> Result<Option<Value>> {
    Ok(match u.int_in_range(0u8..=11)? {
        0..=5 => Some(good(u)?),
        6 => Some(Value::Null),
        7 => Some(attenuo_fuzz::json_value(u, 2)?),
        _ => None,
    })
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let disjoint = u.ratio(1u8, 3u8)?;
        // Shaped: a broad grant, a valid config and the `scope` and `authorization_details`
        // claims present and well formed, so the ceiling steps and their limits are reached
        // (SR-127); the details stay generated.
        // `ratio` is true on exhausted input, so short inputs are shaped.
        let shaped = u.ratio(1u8, 2u8)?;

        // The grant, as the server would accept it at start.
        let mut grant: Vec<Capability> = if disjoint {
            let mut g = limited_pool(u, G_SERVERS, false)?;
            for _ in 0..u.int_in_range(0..=3)? {
                g.push(free_capability(u, G_FREE_SERVERS)?);
            }
            g
        } else {
            let mut g = caps(u, 4, 12)?;
            if u.arbitrary()? {
                g.push(Capability::new("*", "*").with_limits(limits(u)?));
            }
            g
        };
        if shaped {
            grant.push(if disjoint {
                Capability::new("s*", "*")
            } else {
                Capability::new("*", "*")
            });
        }
        grant.retain(valid);
        let mut grant: CapabilitySet = grant.into_iter().collect();
        if grant.validate_size().is_err() {
            grant = CapabilitySet::new();
        }

        // The ceiling config.
        let mut cfg = IdJagCeilingConfig::default();
        for _ in 0..u.int_in_range(0..=3)? {
            let key = (*u.choose(RES_KEYS)?).to_string();
            let mut servers = Vec::new();
            for _ in 0..u.int_in_range(0..=3)? {
                servers.push((*u.choose(RES_SERVERS)?).to_string());
            }
            if shaped || u.ratio(9u8, 10u8)? {
                servers.retain(|s| attenuo_server::config::check_server_name(s).is_ok());
                if servers.is_empty() {
                    servers.push("a".into());
                }
            }
            cfg.resources.insert(key, servers);
        }
        let grant_list: Vec<Capability> = grant.iter().cloned().collect();
        let s_pool = if disjoint {
            limited_pool(u, S_SERVERS, shaped)?
        } else {
            Vec::new()
        };
        for _ in 0..u.int_in_range(usize::from(shaped)..=3)? {
            let mut key = (*u.choose(SCOPE_KEYS)?).to_string();
            if (shaped || u.ratio(9u8, 10u8)?)
                && (key.is_empty() || key.chars().any(char::is_whitespace))
            {
                key = "s1".into();
            }
            let mut specs = Vec::new();
            for _ in 0..u.int_in_range(1..=3)? {
                let c = if disjoint {
                    if !s_pool.is_empty() && u.ratio(2u8, 3u8)? {
                        s_pool[u.choose_index(s_pool.len())?].clone()
                    } else {
                        free_capability(u, S_FREE_SERVERS)?
                    }
                } else if !grant_list.is_empty() && u.arbitrary()? {
                    let i = u.choose_index(grant_list.len())?;
                    let mut c = variant(u, &grant_list[i], true)?;
                    if shaped {
                        c.limits = some_limits(u)?;
                    } else if u.arbitrary()? {
                        c.limits = limits(u)?;
                    }
                    c
                } else {
                    let mut c = capability(u, 12)?;
                    c.server = (*u.choose(SCOPE_SERVERS)?).to_string();
                    c
                };
                specs.push(spec(u, c)?);
            }
            if shaped {
                specs.retain(|s| {
                    s.to_capability()
                        .is_ok_and(|c| valid(&c) && c.server != "a*")
                });
                if specs.is_empty() {
                    specs.push(CapSpec::Short("a:*".into()));
                }
            } else if u.ratio(1u8, 20u8)? {
                specs.clear();
            }
            cfg.scopes.insert(key, specs);
        }

        // The claims.
        let mut scope_pool: Vec<Capability> = s_pool.clone();
        for specs in cfg.scopes.values() {
            scope_pool.extend(specs.iter().filter_map(|s| s.to_capability().ok()));
        }
        let mut pool: Vec<Capability> = grant_list.clone();
        pool.extend(scope_pool.iter().cloned());
        let mut named = Vec::new();
        let mut claims = Map::new();
        let resource = if !shaped {
            claim(u, resource_claim)?
        } else if !cfg.resources.is_empty() && u.arbitrary()? {
            let keys: Vec<&String> = cfg.resources.keys().collect();
            Some(Value::String(keys[u.choose_index(keys.len())?].clone()))
        } else {
            None
        };
        if let Some(v) = resource {
            claims.insert("resource".into(), v);
        }
        let keys: Vec<String> = cfg.scopes.keys().cloned().collect();
        let scope = if shaped {
            Some(scope_claim(u, &keys, true)?)
        } else {
            claim(u, |u| scope_claim(u, &keys, false))?
        };
        // The capabilities of the `scopes` entries the claim names: shaped details are
        // built under them.
        let in_scope: Vec<Capability> = match &scope {
            Some(Value::String(s)) => s
                .split_ascii_whitespace()
                .filter_map(|t| cfg.scopes.get(t))
                .flatten()
                .filter_map(|spec| spec.to_capability().ok())
                .collect(),
            _ => Vec::new(),
        };
        if let Some(v) = scope {
            claims.insert("scope".into(), v);
        }
        let details = if shaped {
            let base = if in_scope.is_empty() {
                &scope_pool
            } else {
                &in_scope
            };
            Some(details_claim(u, base, &pool, disjoint, true, &mut named)?)
        } else {
            claim(u, |u| {
                details_claim(u, &scope_pool, &pool, disjoint, false, &mut named)
            })?
        };
        if let Some(v) = details {
            claims.insert("authorization_details".into(), v);
        }
        if u.ratio(1u8, 8u8)? {
            claims.insert("sub".into(), json!("user"));
        }

        // The request: mostly narrowed capabilities from everything above.
        let mut request = Vec::new();
        let n = if shaped {
            4 - u.int_in_range(0..=3)?
        } else {
            u.int_in_range(0..=4)?
        };
        for k in 0..n {
            if !named.is_empty() && u.ratio(2u8, 3u8)? {
                // Shaped: one capability per named one (their parents differ in the final
                // ceiling, SR-127), or two per named one told apart by an argument nothing
                // else constrains (one parent, SR-121).
                let (i, pair) = match u.int_in_range(0u8..=2)? {
                    0 if shaped => (k % named.len(), false),
                    1 if shaped => ((k / 2) % named.len(), true),
                    _ => (u.choose_index(named.len())?, false),
                };
                let mut c = variant(u, &named[i], true)?;
                if pair {
                    c.constraints
                        .insert("j".into(), ArgConstraint::Equals(Value::from(k)));
                }
                request.push(c);
            } else if !pool.is_empty() && u.ratio(3u8, 4u8)? {
                let base = pool[u.choose_index(pool.len())?].clone();
                request.push(variant(u, &base, true)?);
            } else {
                request.push(capability(u, 12)?);
            }
        }
        let mut order: Vec<usize> = (0..request.len()).collect();
        for i in (1..order.len()).rev() {
            let j = u.int_in_range(0..=i)?;
            order.swap(i, j);
        }
        Ok(Input {
            disjoint,
            grant,
            cfg,
            claims,
            request,
            order,
        })
    }
}

/// The claims with every repeat dropped and values reordered (property 3).
fn distinct(claims: &Map<String, Value>) -> Map<String, Value> {
    let mut out = claims.clone();
    if let Some(Value::String(s)) = out.get("scope") {
        let tokens: BTreeSet<&str> = s.split_ascii_whitespace().collect();
        let joined = tokens.into_iter().collect::<Vec<_>>().join(" ");
        out.insert("scope".into(), Value::String(joined));
    }
    if let Some(Value::Array(items)) = out.get("resource") {
        let values: BTreeSet<&str> = items.iter().filter_map(Value::as_str).collect();
        let values: Vec<Value> = values.into_iter().rev().map(Value::from).collect();
        out.insert("resource".into(), Value::Array(values));
    }
    if let Some(Value::Array(entries)) = out.get("authorization_details") {
        let reversed: Vec<Value> = entries
            .iter()
            .rev()
            .map(|e| {
                let mut e = e.clone();
                if let Some(Value::Array(caps)) = e.get_mut("capabilities") {
                    caps.reverse();
                }
                e
            })
            .collect();
        out.insert("authorization_details".into(), Value::Array(reversed));
    }
    out
}

type Narrowed = std::result::Result<CapabilitySet, (String, Option<&'static str>)>;

fn narrowed(
    grant: &CapabilitySet,
    ceiling: Option<&IdJagCeiling>,
    claims: &Map<String, Value>,
    requested: &CapabilitySet,
) -> Narrowed {
    narrow(grant, ceiling, claims, requested).map_err(|e| (e.code, e.description))
}

/// The server's request body limit.
const MAX_BODY: usize = 2 << 20;

/// The length of `value` as JSON, without building the text.
fn json_len(value: &impl serde::Serialize) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut n = Count(0);
    let _ = serde_json::to_writer(&mut n, value);
    n.0
}

fn has_limits(set: &CapabilitySet) -> bool {
    set.iter().any(|c| !c.limits.is_empty())
}

/// Property 5 for one set `parent` checked over `input`: the `(parent index, child)` of each
/// capability of `input`, mapped to the result capabilities each child stands for by `to_result`.
/// No limited capability of `parent` may be the chosen parent of two distinct ones.
fn one_result_per_limited_parent(
    what: &str,
    parent: &CapabilitySet,
    input: &CapabilitySet,
    to_result: &dyn Fn(&Capability) -> Vec<Capability>,
) {
    let steps = attenuate_indexed_ref(parent, input)
        .unwrap_or_else(|e| panic!("{what}: the reference refuses what the server accepted: {e}"));
    let parents: Vec<&Capability> = parent.iter().collect();
    let mut by_parent: BTreeMap<usize, BTreeSet<Capability>> = BTreeMap::new();
    for (i, _, child) in &steps {
        if !parents[*i].limits.is_empty() {
            by_parent.entry(*i).or_default().extend(to_result(child));
        }
    }
    for (i, results) in by_parent {
        assert!(
            results.len() <= 1,
            "{what}: limited capability {} is the parent of {} result capabilities: {results:?}",
            parents[i].display(),
            results.len()
        );
    }
}

fn check_built(ceiling: &IdJagCeiling, cfg: &IdJagCeilingConfig) {
    let all: CapabilitySet = std::iter::once(Capability::new("*", "*")).collect();
    for (token, specs) in &cfg.scopes {
        let want: CapabilitySet = specs
            .iter()
            .map(|s| s.to_capability().expect("accepted"))
            .collect();
        let mut claims = Map::new();
        claims.insert("scope".into(), Value::String(token.clone()));
        let got = ceiling.apply(&all, &claims);
        assert_eq!(got.capabilities, want, "scope `{token}` not built whole");
    }
    for (resource, servers) in &cfg.resources {
        let want: CapabilitySet = servers.iter().map(|s| Capability::new(s, "*")).collect();
        let mut claims = Map::new();
        claims.insert("resource".into(), Value::String(resource.clone()));
        let got = ceiling.apply(&all, &claims);
        assert_eq!(
            got.capabilities, want,
            "resource `{resource}` not built whole"
        );
    }
}

/// Property 6: the limited capabilities of the grant and of the `scopes` entries the claim
/// names, the only sources of limits in the disjoint mode.
fn sources(
    grant: &CapabilitySet,
    cfg: &IdJagCeilingConfig,
    claims: &Map<String, Value>,
) -> Vec<Capability> {
    let mut out: Vec<Capability> = grant
        .iter()
        .filter(|c| !c.limits.is_empty())
        .cloned()
        .collect();
    if let Some(Value::String(s)) = claims.get("scope") {
        let tokens: BTreeSet<&str> = s.split_ascii_whitespace().collect();
        for t in tokens {
            for spec in cfg.scopes.get(t).into_iter().flatten() {
                let c = spec.to_capability().expect("accepted");
                if !c.limits.is_empty() {
                    out.push(c);
                }
            }
        }
    }
    out
}

fn check_budgets(sources: &[Capability], result: &CapabilitySet) {
    for s in sources {
        let under: Vec<&Capability> = result.iter().filter(|r| covers_calls_ref(s, r)).collect();
        if let Some(max) = s.limits.calls {
            let total: Option<u128> = under.iter().map(|r| r.limits.calls.map(u128::from)).sum();
            assert!(
                total.is_some_and(|t| t <= u128::from(max)),
                "calls {max} of {} spent {total:?} by {under:?}",
                s.display()
            );
        }
        if let Some(p) = &s.limits.sum {
            let total: Option<u128> = under
                .iter()
                .map(|r| {
                    r.limits
                        .sum
                        .as_ref()
                        .filter(|c| c.arg == p.arg)
                        .map(|c| u128::from(c.max))
                })
                .sum();
            assert!(
                total.is_some_and(|t| t <= u128::from(p.max)),
                "sum {} of {} spent {total:?} by {under:?}",
                p.max,
                s.display()
            );
        }
    }
}

fuzz_target!(|input: Input| {
    let Input {
        disjoint,
        grant,
        cfg,
        claims,
        request,
        order,
    } = input;
    let requested: CapabilitySet = request.iter().cloned().collect();
    // The request and the claims reach the server in one token request body, which it refuses
    // over 2 MiB: larger ones (the shared JSON generator can make a `one_of` of tens of MB)
    // only spend the run's time.
    if json_len(&requested) + json_len(&claims) > MAX_BODY {
        return;
    }

    // 1. From the config, whole or not at all.
    let Ok(ceiling) = IdJagCeiling::from_config(&cfg) else {
        return;
    };
    check_built(&ceiling, &cfg);

    // 2. and 4. The ceiling and its steps, within the grant.
    let (applied, cost): (Applied, usize) = counted(|| ceiling.apply(&grant, &claims));
    assert!(
        grant.covers(&applied.capabilities) && set_covers_ref(&grant, &applied.capabilities),
        "ceiling not within the grant"
    );
    for step in &applied.limited_steps {
        assert!(has_limits(step), "a recorded step holds no limit");
        assert!(grant.covers(step), "a recorded step not within the grant");
        assert!(
            step.covers(&applied.capabilities),
            "the ceiling not within a recorded step"
        );
    }

    // 3. Repeats and order of claim values.
    let plain = distinct(&claims);
    let (again, plain_cost) = counted(|| ceiling.apply(&grant, &plain));
    assert_eq!(
        applied, again,
        "repeated or reordered claim values changed the ceiling"
    );
    assert!(
        cost <= plain_cost + REPEAT_ALLOC_SLACK,
        "repeated claim values cost {cost} allocations, their distinct set {plain_cost}"
    );

    // 5. The narrowing.
    let result = narrowed(&grant, Some(&ceiling), &claims, &requested);
    if let Ok(out) = &result {
        assert!(grant.covers(out), "result not within the grant");
        assert!(
            applied.capabilities.covers(out),
            "result not within the ceiling"
        );
        for step in &applied.limited_steps {
            assert!(step.covers(out), "result not within a recorded step");
        }
        let capabilities = grant
            .attenuate_root(&requested)
            .expect("narrowing passed the grant");
        let under_ceiling = attenuate_indexed_ref(&applied.capabilities, &capabilities)
            .expect("passed the ceiling");
        let reference: CapabilitySet = under_ceiling.iter().map(|(_, _, r)| r.clone()).collect();
        assert_eq!(&reference, out, "the reference narrows to another set");
        let result_of = |c: &Capability| -> Vec<Capability> {
            under_ceiling
                .iter()
                .filter(|(_, from, _)| *from == c)
                .map(|(_, _, r)| r.clone())
                .collect()
        };
        one_result_per_limited_parent("grant", &grant, &requested, &result_of);
        one_result_per_limited_parent("ceiling", &applied.capabilities, &capabilities, &|r| {
            vec![r.clone()]
        });
        for step in &applied.limited_steps {
            one_result_per_limited_parent("step", step, out, &|r| vec![r.clone()]);
        }

        // 6. Budgets, where no two limited capabilities overlap.
        if disjoint {
            check_budgets(&sources(&grant, &cfg, &claims), out);
        }
    }

    // 3. again, through the narrowing; 7. the order of the request.
    assert_eq!(
        narrowed(&grant, Some(&ceiling), &plain, &requested),
        result,
        "repeated or reordered claim values changed the narrowing"
    );
    let reordered: CapabilitySet = order.iter().map(|&i| request[i].clone()).collect();
    assert_eq!(
        narrowed(&grant, Some(&ceiling), &claims, &reordered),
        result,
        "the request's order changed the narrowing"
    );
});
