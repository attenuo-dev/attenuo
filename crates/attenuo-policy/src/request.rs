//! Translation of a `(DelegationChain, ToolCall)` pair into a Cedar request: the entity store
//! and the context record. The shape is documented at the crate root.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock, Mutex};

use attenuo_core::{DelegationChain, ToolCall};
use cedar_policy::{
    Context, Entities, EntityId, EntityTypeName, EntityUid, Request, RestrictedExpression,
};
use serde_json::{json, Map, Value};
use time::OffsetDateTime;

use crate::catalog::{ArgType, ToolAttrs};
use crate::schema::GENERIC_ACTION;
use crate::CallLabels;

/// Largest magnitude a Cedar `decimal` can hold.
// Cedar decimal range is +/-922337203685477.5807; stay a little inside it.
const DECIMAL_MAX: f64 = 922_337_203_685_477.0;

/// A float read as a Cedar `Long`: a finite whole number of magnitude at most [`DECIMAL_MAX`]
/// (RFC-0001 section 5), so `5.0` is `5` and `-1.0` is `-1`. NaN, the infinities, fractions
/// (`5.5`) and larger magnitudes (`1e300`) are not a `Long`. [`to_cedar_json`] and the
/// declared-type check both read numbers through this, so they cannot disagree.
fn whole_long(f: f64) -> Option<i64> {
    if !(f.is_finite() && f.fract() == 0.0 && f.abs() <= DECIMAL_MAX) {
        return None;
    }
    // Whole and |f| <= DECIMAL_MAX < 2^53, so the cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    Some(f as i64)
}

/// Something in the call or chain that cannot be expressed to Cedar safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TranslationError(pub String);

impl std::fmt::Display for TranslationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Convert arbitrary JSON into JSON that Cedar's schema-less parser accepts and that cannot
/// smuggle in entity references or extension values.
///
/// - `null` has no Cedar equivalent: object members that are `null` are dropped (policies test
///   presence with `has`), `null` array elements are dropped.
/// - Integers become `Long`; integers that do not fit in `i64` become strings.
/// - Floats with no fractional part (`5.0`) become `Long`, like integers.
/// - Other floats become `decimal` when representable (four fractional digits), otherwise strings.
/// - Object keys beginning with `__` are rejected, because Cedar interprets `__entity`,
///   `__extn` and `__expr` as escapes. Accepting them would let a caller forge an entity
///   reference inside `context.input`.
pub(crate) fn to_cedar_json(value: &Value, path: &str) -> Result<Value, TranslationError> {
    Ok(match value {
        Value::Null => Value::Null,
        Value::Bool(b) => Value::Bool(*b),
        Value::String(s) => Value::String(s.clone()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                json!(i)
            } else if let Some(f) = n.as_f64() {
                if let Some(i) = whole_long(f) {
                    // JSON has one number type: `0.0` is the value `0` to most consumers
                    // (JavaScript, Python's `==`), so it must be the Cedar `Long` 0 too.
                    // Otherwise `forbid ... when { context.input.n == 0 }` is bypassed by
                    // sending `0.0`.
                    json!(i)
                } else if f.is_finite() && f.abs() <= DECIMAL_MAX {
                    json!({ "__extn": { "fn": "decimal", "arg": format!("{f:.4}") } })
                } else {
                    Value::String(n.to_string())
                }
            } else {
                Value::String(n.to_string())
            }
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                let v = to_cedar_json(item, &format!("{path}[{i}]"))?;
                if !v.is_null() {
                    out.push(v);
                }
            }
            Value::Array(out)
        }
        Value::Object(members) => {
            let mut out = Map::with_capacity(members.len());
            for (k, v) in members {
                if k.starts_with("__") {
                    return Err(TranslationError(format!(
                        "{path}.{k}: keys beginning with `__` are reserved by Cedar"
                    )));
                }
                let v = to_cedar_json(v, &format!("{path}.{k}"))?;
                if !v.is_null() {
                    out.insert(k.clone(), v);
                }
            }
            Value::Object(out)
        }
    })
}

fn object_from<'a>(
    map: impl IntoIterator<Item = (&'a String, &'a Value)>,
    path: &str,
) -> Result<Value, TranslationError> {
    let mut out = Map::new();
    for (k, v) in map {
        if k.starts_with("__") {
            return Err(TranslationError(format!(
                "{path}.{k}: keys beginning with `__` are reserved by Cedar"
            )));
        }
        let v = to_cedar_json(v, &format!("{path}.{k}"))?;
        if !v.is_null() {
            out.insert(k.clone(), v);
        }
    }
    Ok(Value::Object(out))
}

/// A JSON number as the argument of Cedar's `decimal()`, for an argument declared
/// [`ArgType::Decimal`]: its shortest decimal form, with `.0` added to a whole number, so `12.5`
/// is `"12.5"` and `100` is `"100.0"`. `None` when it has more than 4 fractional digits or a
/// magnitude above [`DECIMAL_MAX`] (Cedar's range); nothing is rounded here. A JSON number is
/// a double here (serde_json's `float_roundtrip` is on), and Rust's `Display` for `f64` is the
/// shortest form that reads back as the same double, never in exponent notation, so the digits
/// are the ones the caller wrote, trailing zeros aside, as long as a double can hold them
/// (15 significant digits always fit). A number written with more digits than that was
/// already rounded to the nearest double when the JSON was parsed, and that double's shortest
/// form can have fewer fractional digits than were sent: `0.10000000000000001` is the double
/// `0.1`, `1000000000000.00001` the double `1000000000000.0`, and both are accepted. Cedar and
/// the upstream still see the same number, because the proxy forwards the arguments
/// re-encoded from the same parsed value (SR-95).
pub(crate) fn decimal_text(n: &serde_json::Number) -> Option<String> {
    let text = if let Some(i) = n.as_i64() {
        // Integers above 2^53 have no exact double; read them as integers.
        if i.unsigned_abs() > 922_337_203_685_477 {
            return None;
        }
        i.to_string()
    } else {
        let f = n.as_f64()?;
        if !(f.is_finite() && f.abs() <= DECIMAL_MAX) {
            return None;
        }
        // `-0.0` displays as `-0`.
        if f == 0.0 {
            "0".to_string()
        } else {
            f.to_string()
        }
    };
    match text.split_once('.') {
        None => Some(format!("{text}.0")),
        Some((_, frac)) if (1..=4).contains(&frac.len()) => Some(text),
        Some(_) => None,
    }
}

/// `value` as Cedar JSON when the catalog declares its type: a [`ArgType::Decimal`] number (or
/// each element of a set of them) becomes `decimal(...)` through [`decimal_text`] rather than a
/// `Long` or a rounded decimal; everything else is [`to_cedar_json`]. Run after
/// [`check_tool_inputs`], so a number that is not a decimal is an error only if that check
/// was skipped.
fn typed_cedar_json(value: &Value, ty: &ArgType, path: &str) -> Result<Value, TranslationError> {
    match (ty, value) {
        (ArgType::Decimal, Value::Number(n)) => {
            let arg = decimal_text(n).ok_or_else(|| {
                TranslationError(format!("{path}: number {n} is not a Cedar decimal"))
            })?;
            Ok(json!({ "__extn": { "fn": "decimal", "arg": arg } }))
        }
        (ArgType::Set(inner), Value::Array(items)) if inner.contains_decimal() => {
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                let v = typed_cedar_json(item, inner, &format!("{path}[{i}]"))?;
                if !v.is_null() {
                    out.push(v);
                }
            }
            Ok(Value::Array(out))
        }
        _ => to_cedar_json(value, path),
    }
}

/// `context.input`: the call's arguments, each through [`typed_cedar_json`] when `declared`
/// gives its type and [`to_cedar_json`] otherwise, `null`s dropped, `__` keys refused.
fn input_object(
    arguments: &BTreeMap<String, Value>,
    declared: &BTreeMap<String, ArgType>,
) -> Result<Value, TranslationError> {
    let mut out = Map::new();
    for (k, v) in arguments {
        if k.starts_with("__") {
            return Err(TranslationError(format!(
                "input.{k}: keys beginning with `__` are reserved by Cedar"
            )));
        }
        let path = format!("input.{k}");
        let v = match declared.get(k) {
            Some(ty) => typed_cedar_json(v, ty, &path)?,
            None => to_cedar_json(v, &path)?,
        };
        if !v.is_null() {
            out.insert(k.clone(), v);
        }
    }
    Ok(Value::Object(out))
}

fn matches_type(value: &Value, ty: &ArgType) -> bool {
    match (ty, value) {
        (ArgType::String, Value::String(_)) | (ArgType::Bool, Value::Bool(_)) => true,
        (ArgType::Long, Value::Number(n)) => n.is_i64(),
        (ArgType::Set(inner), Value::Array(items)) => items.iter().all(|i| matches_type(i, inner)),
        _ => false,
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_i64() => "long",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Check every declared attribute that is present against its declared type. Absent and
/// `null` attributes are fine (policies test presence with `has`); a present value of another
/// type is an error. No coercion: a single-element list is not a string.
pub(crate) fn check_user_attributes(
    user: &attenuo_core::OriginatingUser,
    declared: &BTreeMap<String, ArgType>,
) -> Result<(), String> {
    for (name, ty) in declared {
        let Some(value) = user.attributes.get(name) else {
            continue;
        };
        if value.is_null() || matches_type(value, ty) {
            continue;
        }
        return Err(format!(
            "originating_user.attributes.{name}: expected {}, got {}",
            ty.cedar(),
            type_name(value)
        ));
    }
    Ok(())
}

/// Does a call argument have its declared type, read as Cedar will see it after
/// [`to_cedar_json`]? Integers, and floats with no fractional part within range, are `Long`;
/// `null` elements of a list are dropped. Anything else, an integer where a string is declared,
/// a fraction or an out-of-range number where a long is, a single value where a set is, is a
/// mismatch. Nothing is coerced.
fn input_matches(value: &Value, ty: &ArgType) -> bool {
    match (ty, value) {
        (ArgType::String, Value::String(_)) | (ArgType::Bool, Value::Bool(_)) => true,
        (ArgType::Long, Value::Number(n)) => {
            n.is_i64() || n.as_f64().and_then(whole_long).is_some()
        }
        (ArgType::Decimal, Value::Number(n)) => decimal_text(n).is_some(),
        (ArgType::Set(inner), Value::Array(items)) => {
            items.iter().all(|i| i.is_null() || input_matches(i, inner))
        }
        _ => false,
    }
}

/// Check every argument the catalog declares a type for and the call carries, before Cedar.
/// Absent and `null` arguments are fine (policies test presence with `has`); undeclared
/// arguments are not checked and reach Cedar as they are. Without the check a wrongly typed
/// argument reaches Cedar, where a policy that reads it raises a type error (`policy_error`)
/// and one that does not lets it through to the upstream unread.
pub(crate) fn check_tool_inputs(
    arguments: &BTreeMap<String, Value>,
    declared: &BTreeMap<String, ArgType>,
) -> Result<(), String> {
    for (name, ty) in declared {
        let Some(value) = arguments.get(name) else {
            continue;
        };
        if value.is_null() || input_matches(value, ty) {
            continue;
        }
        let got = match (ty, value) {
            (ArgType::Decimal, Value::Number(_)) => {
                "a number with more than 4 fractional digits or out of range"
            }
            _ => type_name(value),
        };
        return Err(format!("input.{name}: expected {}, got {got}", ty.shown()));
    }
    Ok(())
}

/// The fixed entity type names a request refers to, parsed once rather than per request.
static AGENT: LazyLock<EntityTypeName> = LazyLock::new(|| entity_type("Agent"));
static ACTION: LazyLock<EntityTypeName> = LazyLock::new(|| entity_type("Action"));
static TOOL: LazyLock<EntityTypeName> = LazyLock::new(|| entity_type("Tool"));
static SERVER: LazyLock<EntityTypeName> = LazyLock::new(|| entity_type("Server"));

fn entity_type(ty: &str) -> EntityTypeName {
    ty.parse().expect("entity type names used here are valid")
}

pub(crate) fn uid(ty: &EntityTypeName, id: &str) -> EntityUid {
    EntityUid::from_type_name_and_id(ty.clone(), EntityId::new(id))
}

/// Resource id for a call: `<server>/<tool>`.
pub(crate) fn tool_id(call: &ToolCall) -> String {
    format!("{}/{}", call.server, call.tool)
}

fn uid_json(ty: &str, id: &str) -> Value {
    json!({ "type": ty, "id": id })
}

/// Calls whose request parts [`RequestCache`] keeps.
pub(crate) const REQUEST_CACHE_CAPACITY: usize = 4096;

/// Everything the cached parts were built from: the originating user, each hop's agent and
/// lease, the call's server and tool, and the tool attributes the engine resolved for it. A
/// cache hit requires all of it to be equal, so a hash collision is only a miss.
#[derive(Debug, PartialEq)]
struct PartsKey {
    subject: String,
    issuer: String,
    authenticated_at: OffsetDateTime,
    attributes: BTreeMap<String, Value>,
    hops: Vec<(String, String)>,
    server: String,
    tool: String,
    readonly: bool,
    sensitive: bool,
    destructive: bool,
}

impl PartsKey {
    fn new(chain: &DelegationChain, call: &ToolCall, attrs: &ToolAttrs) -> Self {
        let user = &chain.originating_user;
        Self {
            subject: user.subject.clone(),
            issuer: user.issuer.clone(),
            authenticated_at: user.authenticated_at,
            attributes: user.attributes.clone(),
            hops: chain
                .hops
                .iter()
                .map(|h| (h.agent.0.clone(), h.lease.0.clone()))
                .collect(),
            server: call.server.clone(),
            tool: call.tool.clone(),
            readonly: attrs.readonly,
            sensitive: attrs.sensitive,
            destructive: attrs.is_destructive(),
        }
    }

    fn matches(&self, chain: &DelegationChain, call: &ToolCall, attrs: &ToolAttrs) -> bool {
        let user = &chain.originating_user;
        self.subject == user.subject
            && self.issuer == user.issuer
            && self.authenticated_at == user.authenticated_at
            && self.server == call.server
            && self.tool == call.tool
            && self.readonly == attrs.readonly
            && self.sensitive == attrs.sensitive
            && self.destructive == attrs.is_destructive()
            && self.hops.len() == chain.hops.len()
            && self
                .hops
                .iter()
                .zip(&chain.hops)
                .all(|((agent, lease), h)| *agent == h.agent.0 && *lease == h.lease.0)
            && self.attributes == user.attributes
    }

    /// Bucket for `(chain, call)`. Attribute values are left out (JSON values do not hash);
    /// they are compared on a hit like everything else.
    fn fingerprint(chain: &DelegationChain, call: &ToolCall) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        let user = &chain.originating_user;
        user.subject.hash(&mut h);
        user.issuer.hash(&mut h);
        user.authenticated_at.hash(&mut h);
        for hop in &chain.hops {
            hop.agent.0.hash(&mut h);
            hop.lease.0.hash(&mut h);
        }
        call.server.hash(&mut h);
        call.tool.hash(&mut h);
        h.finish()
    }
}

/// The parts of a Cedar request that do not change from one call to the next for the same
/// chain and tool: the principal, action and resource, the entity store (user, agents,
/// server, tool, actions) and the `originating_user` and `chain` context records. Only
/// `context.input`, `context.session_id`, `context.now_unix` and the output-labelling members
/// (`session`, `args_contain_untrusted`, `untrusted_args`, `approval`) and the run-limit
/// members (`budget`, `usage`) are built per call.
#[derive(Debug)]
pub(crate) struct RequestParts {
    key: PartsKey,
    principal: EntityUid,
    action: EntityUid,
    resource: EntityUid,
    originating_user: RestrictedExpression,
    chain: RestrictedExpression,
    pub(crate) entities: Entities,
}

/// The `originating_user` and `chain` context records, which depend on the chain only.
fn fixed_records(
    chain: &DelegationChain,
) -> Result<(RestrictedExpression, RestrictedExpression), TranslationError> {
    let user = &chain.originating_user;
    let user_attributes = object_from(user.attributes.iter(), "originating_user.attributes")?;
    let agents: Vec<String> = chain.hops.iter().map(|h| h.agent.to_string()).collect();
    let leases: Vec<String> = chain.hops.iter().map(|h| h.lease.0.clone()).collect();
    let root_agent = agents.first().cloned().unwrap_or_default();

    // ---- context: the records that depend on the chain only ----
    let fixed = json!({
        "originating_user": {
            "subject": user.subject,
            "issuer": user.issuer,
            "attributes": user_attributes,
            "authenticated_at_unix": user.authenticated_at.unix_timestamp(),
        },
        "chain": {
            "depth": chain.depth(),
            "agents": agents,
            "root_agent": root_agent,
            "leases": leases,
        },
    });
    let mut originating_user = None;
    let mut chain_record = None;
    for (k, v) in Context::from_json_value(fixed, None)
        .map_err(|e| TranslationError(format!("context: {e}")))?
    {
        match k.as_str() {
            "originating_user" => originating_user = Some(v),
            "chain" => chain_record = Some(v),
            _ => {}
        }
    }
    match (originating_user, chain_record) {
        (Some(u), Some(c)) => Ok((u, c)),
        _ => Err(TranslationError("context: missing record".into())),
    }
}

impl RequestParts {
    /// Translate the chain and tool. This is the JSON translation the engine has always
    /// used; its output is reused by [`RequestParts::request`] for every call it matches.
    pub(crate) fn build(
        chain: &DelegationChain,
        call: &ToolCall,
        attrs: &ToolAttrs,
        legacy_bare_actions: bool,
    ) -> Result<Self, TranslationError> {
        let action = crate::schema::action_id(&call.server, &call.tool, legacy_bare_actions);
        let agent = chain
            .current_agent()
            .ok_or_else(|| TranslationError("delegation chain has no hops".into()))?;
        let (originating_user, chain_record) = fixed_records(chain)?;

        Ok(Self {
            key: PartsKey::new(chain, call, attrs),
            principal: uid(&AGENT, &agent.0),
            action: uid(&ACTION, &action),
            resource: uid(&TOOL, &tool_id(call)),
            originating_user,
            chain: chain_record,
            entities: entities(chain, call, attrs, &action)?,
        })
    }

    /// The Cedar request for `call` at `now`, with the per-call context members.
    /// `inputs` are the tool's declared argument types, which pick how a number is converted
    /// ([`ArgType::Decimal`]).
    pub(crate) fn request(
        &self,
        call: &ToolCall,
        inputs: &BTreeMap<String, ArgType>,
        labels: &CallLabels,
        now: OffsetDateTime,
    ) -> Result<Request, TranslationError> {
        let input = input_object(&call.arguments, inputs)?;
        let mut pairs = Vec::with_capacity(10);
        pairs.push(("input".to_string(), restricted(&input)?));
        pairs.push((
            "originating_user".to_string(),
            self.originating_user.clone(),
        ));
        pairs.push(("chain".to_string(), self.chain.clone()));
        if let Some(sid) = &call.session_id {
            pairs.push((
                "session_id".to_string(),
                RestrictedExpression::new_string(sid.clone()),
            ));
        }
        pairs.push((
            "now_unix".to_string(),
            RestrictedExpression::new_long(now.unix_timestamp()),
        ));
        pairs.extend(label_pairs(labels)?);
        let context =
            Context::from_pairs(pairs).map_err(|e| TranslationError(format!("context: {e}")))?;
        Request::new(
            self.principal.clone(),
            self.action.clone(),
            self.resource.clone(),
            context,
            None,
        )
        .map_err(|e| TranslationError(e.to_string()))
    }
}

/// The output-labelling members of the context (ADR-0009), always present:
/// `session: {tainted, tainted_by}`, `args_contain_untrusted` and `untrusted_args` (the
/// arguments that matched the run's span index, phase 2), and `approval: {present, by}` (a
/// granted approval the call consumed, if any); and the run-limit member (ADR-0010),
/// `budget: {limited, calls_remaining, amount_remaining, destination_new}`, and run usage,
/// `usage: {calls, amount, destination_seen, user_window: {hour, day}}`.
fn label_pairs(
    labels: &CallLabels,
) -> Result<Vec<(String, RestrictedExpression)>, TranslationError> {
    let record = |pairs: Vec<(String, RestrictedExpression)>| {
        RestrictedExpression::new_record(pairs)
            .map_err(|e| TranslationError(format!("context: {e}")))
    };
    let session = record(vec![
        (
            "tainted".to_string(),
            RestrictedExpression::new_bool(labels.session.tainted),
        ),
        (
            "tainted_by".to_string(),
            RestrictedExpression::new_set(
                labels
                    .session
                    .tainted_by
                    .iter()
                    .map(|s| RestrictedExpression::new_string(s.clone())),
            ),
        ),
    ])?;
    let approval = record(vec![
        (
            "present".to_string(),
            RestrictedExpression::new_bool(labels.approval.present),
        ),
        (
            "by".to_string(),
            RestrictedExpression::new_string(labels.approval.by.clone()),
        ),
    ])?;
    let b = &labels.budget;
    let budget = record(vec![
        (
            "limited".to_string(),
            RestrictedExpression::new_bool(b.limited),
        ),
        (
            "calls_remaining".to_string(),
            RestrictedExpression::new_long(b.calls_remaining),
        ),
        (
            "amount_remaining".to_string(),
            RestrictedExpression::new_long(b.amount_remaining),
        ),
        (
            "destination_new".to_string(),
            RestrictedExpression::new_bool(b.destination_new),
        ),
    ])?;
    let u = &labels.usage;
    let window = |w: &crate::WindowFigures| {
        record(vec![
            ("calls".to_string(), RestrictedExpression::new_long(w.calls)),
            (
                "amount".to_string(),
                RestrictedExpression::new_long(w.amount),
            ),
        ])
    };
    let user_window = record(vec![
        ("hour".to_string(), window(&u.user_window.hour)?),
        ("day".to_string(), window(&u.user_window.day)?),
    ])?;
    let usage = record(vec![
        ("calls".to_string(), RestrictedExpression::new_long(u.calls)),
        (
            "amount".to_string(),
            RestrictedExpression::new_long(u.amount),
        ),
        (
            "destination_seen".to_string(),
            RestrictedExpression::new_bool(u.destination_seen),
        ),
        ("user_window".to_string(), user_window),
    ])?;
    Ok(vec![
        ("session".to_string(), session),
        (
            "args_contain_untrusted".to_string(),
            RestrictedExpression::new_bool(labels.args.contain_untrusted),
        ),
        (
            "untrusted_args".to_string(),
            RestrictedExpression::new_set(
                labels
                    .args
                    .untrusted
                    .iter()
                    .map(|a| RestrictedExpression::new_string(a.clone())),
            ),
        ),
        ("approval".to_string(), approval),
        ("budget".to_string(), budget),
        ("usage".to_string(), usage),
    ])
}

/// The output-labelling members as JSON, for the one-pass reference translation.
#[cfg(test)]
fn label_json(labels: &CallLabels) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(
        "session".into(),
        json!({ "tainted": labels.session.tainted, "tainted_by": labels.session.tainted_by }),
    );
    m.insert(
        "args_contain_untrusted".into(),
        json!(labels.args.contain_untrusted),
    );
    m.insert("untrusted_args".into(), json!(labels.args.untrusted));
    m.insert(
        "approval".into(),
        json!({ "present": labels.approval.present, "by": labels.approval.by }),
    );
    m.insert(
        "budget".into(),
        json!({
            "limited": labels.budget.limited,
            "calls_remaining": labels.budget.calls_remaining,
            "amount_remaining": labels.budget.amount_remaining,
            "destination_new": labels.budget.destination_new,
        }),
    );
    m.insert(
        "usage".into(),
        json!({
            "calls": labels.usage.calls,
            "amount": labels.usage.amount,
            "destination_seen": labels.usage.destination_seen,
            "user_window": {
                "hour": {
                    "calls": labels.usage.user_window.hour.calls,
                    "amount": labels.usage.user_window.hour.amount,
                },
                "day": {
                    "calls": labels.usage.user_window.day.calls,
                    "amount": labels.usage.user_window.day.amount,
                },
            },
        }),
    );
    m
}

/// Convert the output of [`to_cedar_json`] into the expression Cedar's schema-less JSON
/// parser would build from it: strings, booleans, `Long`s, sets, records and the one
/// extension escape `to_cedar_json` emits (`decimal`). Anything else is an error, never a
/// guess. `tests::context_matches_the_json_translation` holds the two paths equal.
fn restricted(value: &Value) -> Result<RestrictedExpression, TranslationError> {
    Ok(match value {
        Value::Bool(b) => RestrictedExpression::new_bool(*b),
        Value::String(s) => RestrictedExpression::new_string(s.clone()),
        Value::Number(n) => match n.as_i64() {
            Some(i) => RestrictedExpression::new_long(i),
            None => {
                return Err(TranslationError(format!(
                    "context: number {n} is not a Long"
                )))
            }
        },
        Value::Array(items) => RestrictedExpression::new_set(
            items
                .iter()
                .map(restricted)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Value::Object(members) => {
            if let Some(Value::Object(extn)) = members.get("__extn") {
                return match (members.len(), extn.get("fn"), extn.get("arg")) {
                    (1, Some(Value::String(f)), Some(Value::String(arg))) if f == "decimal" => {
                        Ok(RestrictedExpression::new_decimal(arg))
                    }
                    _ => Err(TranslationError(
                        "context: unexpected extension escape".into(),
                    )),
                };
            }
            RestrictedExpression::new_record(
                members
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), restricted(v)?)))
                    .collect::<Result<Vec<_>, TranslationError>>()?,
            )
            .map_err(|e| TranslationError(format!("context: {e}")))?
        }
        Value::Null => return Err(TranslationError("context: unexpected null".into())),
    })
}

/// The entity store for one call (see the crate docs for the hierarchy).
fn entities(
    chain: &DelegationChain,
    call: &ToolCall,
    attrs: &ToolAttrs,
    action: &str,
) -> Result<Entities, TranslationError> {
    let user = &chain.originating_user;
    let mut entities = Vec::with_capacity(chain.hops.len() + 5);
    entities.push(json!({
        "uid": uid_json("User", &user.subject),
        "attrs": {
            "subject": user.subject,
            "issuer": user.issuer,
            "authenticated_at_unix": user.authenticated_at.unix_timestamp(),
            "attributes": user_attributes_value(&user.attributes)?,
        },
        "parents": [],
    }));
    for (i, hop) in chain.hops.iter().enumerate() {
        let mut parents = vec![uid_json("User", &user.subject)];
        if i > 0 {
            parents.push(uid_json("Agent", &chain.hops[i - 1].agent.0));
        }
        entities.push(json!({
            "uid": uid_json("Agent", &hop.agent.0),
            "attrs": { "id": hop.agent.0, "chain_depth": i + 1 },
            "parents": parents,
        }));
    }
    entities.push(json!({
        "uid": uid_json("Server", &call.server),
        "attrs": { "name": call.server },
        "parents": [],
    }));
    entities.push(json!({
        "uid": uid_json("Tool", &tool_id(call)),
        "attrs": {
            "server": call.server,
            "name": call.tool,
            "readonly": attrs.readonly,
            "sensitive": attrs.sensitive,
            "destructive": attrs.is_destructive(),
        },
        "parents": [uid_json("Server", &call.server)],
    }));
    // The action hierarchy. Evaluation is schema-free, so Cedar only knows that
    // `Action::"<server>/<tool>"` is `in Action::"invoke"` if the entity store says so; without
    // these entries `action in Action::"invoke"` is false and a `forbid` written that way never
    // fires.
    entities.push(json!({
        "uid": uid_json("Action", GENERIC_ACTION),
        "attrs": {},
        "parents": [],
    }));
    if action != GENERIC_ACTION {
        entities.push(json!({
            "uid": uid_json("Action", action),
            "attrs": {},
            "parents": [uid_json("Action", GENERIC_ACTION)],
        }));
    }
    Entities::from_json_value(Value::Array(entities), None)
        .map_err(|e| TranslationError(format!("entities: {e}")))
}

/// [`RequestParts`] by chain and tool, so the translation (about 90 percent of the Cedar
/// stage, nearly all of it Cedar parsing the entity and context JSON) runs once per chain
/// and tool rather than once per call.
///
/// Nothing in the parts depends on the time, the arguments, the session or the policies;
/// they depend on the chain, the call's server and tool, and the engine's catalog and
/// action-id mode, which are fixed for the life of a [`PolicyEngine`](crate::PolicyEngine)
/// (a catalog change builds a new engine, and with it an empty cache). The cache is cleared
/// on a policy reload all the same. Bounded: when full it is cleared, and the next calls
/// translate again.
#[derive(Debug)]
pub(crate) struct RequestCache {
    parts: Mutex<HashMap<u64, Arc<RequestParts>>>,
    capacity: usize,
}

impl RequestCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            parts: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    pub(crate) fn get_or_build(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        attrs: &ToolAttrs,
        legacy_bare_actions: bool,
    ) -> Result<Arc<RequestParts>, TranslationError> {
        let fingerprint = PartsKey::fingerprint(chain, call);
        if let Ok(parts) = self.parts.lock() {
            if let Some(hit) = parts.get(&fingerprint) {
                if hit.key.matches(chain, call, attrs) {
                    return Ok(Arc::clone(hit));
                }
            }
        }
        let built = Arc::new(RequestParts::build(
            chain,
            call,
            attrs,
            legacy_bare_actions,
        )?);
        if let Ok(mut parts) = self.parts.lock() {
            if parts.len() >= self.capacity && !parts.contains_key(&fingerprint) {
                parts.clear();
            }
            parts.insert(fingerprint, Arc::clone(&built));
        }
        Ok(built)
    }

    pub(crate) fn clear(&self) {
        if let Ok(mut parts) = self.parts.lock() {
            parts.clear();
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.parts.lock().map(|p| p.len()).unwrap_or(0)
    }
}

/// The context members a `tools/call` decision fills in from the call or the run, which a
/// list screen does not know (ADR-0011): each is a Cedar unknown of the same name. Every one
/// of them is always present in a call's context, so making its value unknown keeps
/// `context has <member>` true, as it is for every call. `session_id`, the one optional member,
/// is handled apart ([`ScreenBase::partial_request`]).
pub(crate) const SCREEN_UNKNOWNS: [&str; 8] = [
    "input",
    "now_unix",
    "session",
    "args_contain_untrusted",
    "untrusted_args",
    "approval",
    "budget",
    "usage",
];

/// The parts of a list screen's Cedar requests that depend on the chain and the server only,
/// built once per screened list: the principal, the `originating_user` and `chain` records,
/// and the entity store without the tool and its action (the user, every hop's agent, the
/// server and `Action::"invoke"`). The entities and records are the ones
/// [`RequestParts::build`] gives a call; [`ScreenBase::partial_request`] adds the tool.
#[derive(Debug)]
pub(crate) struct ScreenBase {
    server: String,
    principal: EntityUid,
    originating_user: RestrictedExpression,
    chain: RestrictedExpression,
    entities: Entities,
}

impl ScreenBase {
    pub(crate) fn build(chain: &DelegationChain, server: &str) -> Result<Self, TranslationError> {
        let agent = chain
            .current_agent()
            .ok_or_else(|| TranslationError("delegation chain has no hops".into()))?;
        let (originating_user, chain_record) = fixed_records(chain)?;
        let user = &chain.originating_user;
        let mut entities = Vec::with_capacity(chain.hops.len() + 3);
        entities.push(json!({
            "uid": uid_json("User", &user.subject),
            "attrs": {
                "subject": user.subject,
                "issuer": user.issuer,
                "authenticated_at_unix": user.authenticated_at.unix_timestamp(),
                "attributes": user_attributes_value(&user.attributes)?,
            },
            "parents": [],
        }));
        for (i, hop) in chain.hops.iter().enumerate() {
            let mut parents = vec![uid_json("User", &user.subject)];
            if i > 0 {
                parents.push(uid_json("Agent", &chain.hops[i - 1].agent.0));
            }
            entities.push(json!({
                "uid": uid_json("Agent", &hop.agent.0),
                "attrs": { "id": hop.agent.0, "chain_depth": i + 1 },
                "parents": parents,
            }));
        }
        entities.push(json!({
            "uid": uid_json("Server", server),
            "attrs": { "name": server },
            "parents": [],
        }));
        entities.push(json!({
            "uid": uid_json("Action", GENERIC_ACTION),
            "attrs": {},
            "parents": [],
        }));
        let entities = Entities::from_json_value(Value::Array(entities), None)
            .map_err(|e| TranslationError(format!("entities: {e}")))?;
        Ok(Self {
            server: server.to_owned(),
            principal: uid(&AGENT, &agent.0),
            originating_user,
            chain: chain_record,
            entities,
        })
    }

    /// The request and entity store for a call of `tool` with every member of
    /// [`SCREEN_UNKNOWNS`] unknown, and `session_id` an unknown when `with_session_id`,
    /// absent otherwise. The tool's entity and its action's are those
    /// [`RequestParts::build`] makes.
    pub(crate) fn partial_request(
        &self,
        tool: &str,
        attrs: &ToolAttrs,
        legacy_bare_actions: bool,
        with_session_id: bool,
    ) -> Result<(Request, Entities), TranslationError> {
        use cedar_policy::Entity;
        use std::collections::HashSet;

        let action = crate::schema::action_id(&self.server, tool, legacy_bare_actions);
        let resource_id = format!("{}/{tool}", self.server);
        let tool_entity = Entity::new(
            uid(&TOOL, &resource_id),
            HashMap::from([
                (
                    "server".to_string(),
                    RestrictedExpression::new_string(self.server.clone()),
                ),
                (
                    "name".to_string(),
                    RestrictedExpression::new_string(tool.to_owned()),
                ),
                (
                    "readonly".to_string(),
                    RestrictedExpression::new_bool(attrs.readonly),
                ),
                (
                    "sensitive".to_string(),
                    RestrictedExpression::new_bool(attrs.sensitive),
                ),
                (
                    "destructive".to_string(),
                    RestrictedExpression::new_bool(attrs.is_destructive()),
                ),
            ]),
            HashSet::from([uid(&SERVER, &self.server)]),
        )
        .map_err(|e| TranslationError(format!("entities: {e}")))?;
        let mut added = vec![tool_entity];
        if action != GENERIC_ACTION {
            added.push(Entity::new_no_attrs(
                uid(&ACTION, &action),
                HashSet::from([uid(&ACTION, GENERIC_ACTION)]),
            ));
        }
        let entities = self
            .entities
            .clone()
            .add_entities(added, None)
            .map_err(|e| TranslationError(format!("entities: {e}")))?;

        let mut pairs = Vec::with_capacity(SCREEN_UNKNOWNS.len() + 3);
        pairs.push((
            "originating_user".to_string(),
            self.originating_user.clone(),
        ));
        pairs.push(("chain".to_string(), self.chain.clone()));
        if with_session_id {
            pairs.push((
                "session_id".to_string(),
                RestrictedExpression::new_unknown("session_id"),
            ));
        }
        for name in SCREEN_UNKNOWNS {
            pairs.push((name.to_string(), RestrictedExpression::new_unknown(name)));
        }
        let context =
            Context::from_pairs(pairs).map_err(|e| TranslationError(format!("context: {e}")))?;
        let request = Request::new(
            self.principal.clone(),
            uid(&ACTION, &action),
            uid(&TOOL, &resource_id),
            context,
            None,
        )
        .map_err(|e| TranslationError(e.to_string()))?;
        Ok((request, entities))
    }
}

/// The Cedar request parts for one authorization, built in one pass: the translation before
/// [`RequestParts`], kept as the reference the cached path is tested against.
#[cfg(test)]
pub(crate) struct CedarRequest {
    pub principal: EntityUid,
    pub action: EntityUid,
    pub resource: EntityUid,
    pub context: Context,
    pub entities: Entities,
}

#[cfg(test)]
pub(crate) fn build(
    chain: &DelegationChain,
    call: &ToolCall,
    attrs: &ToolAttrs,
    labels: &CallLabels,
    now: OffsetDateTime,
    legacy_bare_actions: bool,
) -> Result<CedarRequest, TranslationError> {
    let action = crate::schema::action_id(&call.server, &call.tool, legacy_bare_actions);
    let agent = chain
        .current_agent()
        .ok_or_else(|| TranslationError("delegation chain has no hops".into()))?;
    let user = &chain.originating_user;
    let user_attributes = object_from(user.attributes.iter(), "originating_user.attributes")?;
    let input = object_from(call.arguments.iter(), "input")?;

    let agents: Vec<String> = chain.hops.iter().map(|h| h.agent.to_string()).collect();
    let leases: Vec<String> = chain.hops.iter().map(|h| h.lease.0.clone()).collect();
    let root_agent = agents.first().cloned().unwrap_or_default();

    // ---- context ----
    let mut context = Map::new();
    context.insert("input".into(), input);
    context.insert(
        "originating_user".into(),
        json!({
            "subject": user.subject,
            "issuer": user.issuer,
            "attributes": user_attributes,
            "authenticated_at_unix": user.authenticated_at.unix_timestamp(),
        }),
    );
    context.insert(
        "chain".into(),
        json!({
            "depth": chain.depth(),
            "agents": agents,
            "root_agent": root_agent,
            "leases": leases,
        }),
    );
    if let Some(sid) = &call.session_id {
        context.insert("session_id".into(), Value::String(sid.clone()));
    }
    context.insert("now_unix".into(), json!(now.unix_timestamp()));
    context.extend(label_json(labels));
    let context = Context::from_json_value(Value::Object(context), None)
        .map_err(|e| TranslationError(format!("context: {e}")))?;

    // ---- entities ----
    let mut entities = Vec::with_capacity(chain.hops.len() + 3);
    entities.push(json!({
        "uid": uid_json("User", &user.subject),
        "attrs": {
            "subject": user.subject,
            "issuer": user.issuer,
            "authenticated_at_unix": user.authenticated_at.unix_timestamp(),
            "attributes": user_attributes_value(&user.attributes)?,
        },
        "parents": [],
    }));
    for (i, hop) in chain.hops.iter().enumerate() {
        let mut parents = vec![uid_json("User", &user.subject)];
        if i > 0 {
            parents.push(uid_json("Agent", &chain.hops[i - 1].agent.0));
        }
        entities.push(json!({
            "uid": uid_json("Agent", &hop.agent.0),
            "attrs": { "id": hop.agent.0, "chain_depth": i + 1 },
            "parents": parents,
        }));
    }
    entities.push(json!({
        "uid": uid_json("Server", &call.server),
        "attrs": { "name": call.server },
        "parents": [],
    }));
    entities.push(json!({
        "uid": uid_json("Tool", &tool_id(call)),
        "attrs": {
            "server": call.server,
            "name": call.tool,
            "readonly": attrs.readonly,
            "sensitive": attrs.sensitive,
            "destructive": attrs.is_destructive(),
        },
        "parents": [uid_json("Server", &call.server)],
    }));
    // The action hierarchy. Evaluation is schema-free, so Cedar only knows that
    // `Action::"<server>/<tool>"` is `in Action::"invoke"` if the entity store says so; without
    // these entries `action in Action::"invoke"` is false and a `forbid` written that way never
    // fires.
    entities.push(json!({
        "uid": uid_json("Action", GENERIC_ACTION),
        "attrs": {},
        "parents": [],
    }));
    if action != GENERIC_ACTION {
        entities.push(json!({
            "uid": uid_json("Action", &action),
            "attrs": {},
            "parents": [uid_json("Action", GENERIC_ACTION)],
        }));
    }
    let entities = Entities::from_json_value(Value::Array(entities), None)
        .map_err(|e| TranslationError(format!("entities: {e}")))?;

    Ok(CedarRequest {
        principal: uid(&AGENT, &agent.0),
        action: uid(&ACTION, &action),
        resource: uid(&TOOL, &tool_id(call)),
        context,
        entities,
    })
}

fn user_attributes_value(attrs: &BTreeMap<String, Value>) -> Result<Value, TranslationError> {
    object_from(attrs.iter(), "originating_user.attributes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_are_a_long_only_when_whole_and_in_range() {
        assert_eq!(whole_long(f64::NAN), None);
        assert_eq!(whole_long(f64::INFINITY), None);
        assert_eq!(whole_long(f64::NEG_INFINITY), None);
        assert_eq!(whole_long(1e300), None);
        assert_eq!(whole_long(-1e300), None);
        assert_eq!(whole_long(DECIMAL_MAX + 1.0), None);
        assert_eq!(whole_long(-1.0), Some(-1));
        assert_eq!(whole_long(-0.0), Some(0));
        assert_eq!(whole_long(5.0), Some(5));
        assert_eq!(whole_long(5.5), None);
        assert_eq!(whole_long(DECIMAL_MAX), Some(922_337_203_685_477));

        // The translation and the declared-type check agree on every case JSON can carry
        // (JSON has no NaN or infinity).
        for (f, cedar) in [
            (1e300, json!("1e+300")),
            (-1.0, json!(-1)),
            (5.0, json!(5)),
            (
                5.5,
                json!({ "__extn": { "fn": "decimal", "arg": "5.5000" } }),
            ),
        ] {
            let v = json!(f);
            assert_eq!(to_cedar_json(&v, "input").unwrap(), cedar, "{f:e}");
            assert_eq!(
                input_matches(&v, &ArgType::Long),
                whole_long(f).is_some(),
                "{f:e}"
            );
        }
    }

    /// An undeclared fractional argument reaches Cedar as a `decimal` rounded to four
    /// fractional digits: `12.34567` is `12.3457`, and `0.00001` is `0.0000`, which equals 0.
    #[test]
    fn undeclared_fractions_reach_cedar_rounded_to_four_digits() {
        for (f, arg) in [
            (12.5, "12.5000"),
            (12.34567, "12.3457"),
            (0.00001, "0.0000"),
            (-0.5, "-0.5000"),
        ] {
            assert_eq!(
                to_cedar_json(&json!(f), "input").unwrap(),
                json!({ "__extn": { "fn": "decimal", "arg": arg } }),
                "{f}"
            );
        }
    }

    /// SR-95: a number written with more digits than a double holds is rounded by the JSON
    /// parse, before `decimal_text` sees it, so a sixth fractional digit can vanish rather than
    /// be refused. What Cedar compares is then the value the upstream is sent: the shortest
    /// form of the parsed double, which is also how the arguments are re-encoded.
    #[test]
    fn digits_beyond_a_double_are_rounded_by_the_parse_alike_for_cedar_and_upstream_sr95() {
        for (text, cedar) in [
            ("0.10000000000000001", "0.1"),
            ("1000000000000.00001", "1000000000000.0"),
            ("12345678901.234500001", "12345678901.2345"),
        ] {
            let v: Value = serde_json::from_str(text).unwrap();
            let Value::Number(n) = &v else { unreachable!() };
            assert_eq!(decimal_text(n).as_deref(), Some(cedar), "{text}");
            let forwarded = serde_json::to_string(&v).unwrap();
            assert_eq!(
                forwarded, cedar,
                "{text}: the upstream is sent what Cedar compares"
            );
        }
        // Within what a double holds, a fifth fractional digit is still refused.
        for text in ["99999999999.99999", "12345678901.23456", "0.00001"] {
            let n: serde_json::Number = serde_json::from_str(text).unwrap();
            assert_eq!(decimal_text(&n), None, "{text}");
        }
    }

    #[test]
    fn decimal_inputs_convert_without_rounding() {
        let n = |text: &str| -> serde_json::Number { serde_json::from_str(text).unwrap() };
        for (text, want) in [
            // Whole numbers, integer or float, get a `.0`.
            ("12", "12.0"),
            ("12.0", "12.0"),
            ("-3", "-3.0"),
            ("0", "0.0"),
            ("-0.0", "0.0"),
            ("1e3", "1000.0"),
            ("922337203685477", "922337203685477.0"),
            // Fractions keep the digits written, trailing zeros aside.
            ("12.5", "12.5"),
            ("12.50", "12.5"),
            ("0.1", "0.1"),
            ("19.99", "19.99"),
            ("0.0001", "0.0001"),
            ("-1234.5678", "-1234.5678"),
        ] {
            assert_eq!(decimal_text(&n(text)).as_deref(), Some(want), "{text}");
        }
        // More than 4 fractional digits, or beyond Cedar's range: refused, not rounded.
        for text in [
            "12.34567",
            "0.00001",
            "1e-7",
            "922337203685478",
            "1e300",
            "9223372036854775807",
            "18446744073709551615",
        ] {
            assert_eq!(decimal_text(&n(text)), None, "{text}");
        }

        let decl: BTreeMap<String, ArgType> = [
            ("amount".to_string(), ArgType::Decimal),
            ("fees".to_string(), ArgType::Set(Box::new(ArgType::Decimal))),
        ]
        .into_iter()
        .collect();
        let args = |v: Value| -> BTreeMap<String, Value> { serde_json::from_value(v).unwrap() };
        let ok = args(json!({"amount": 100, "fees": [0.5, null, 2], "note": 1.5}));
        check_tool_inputs(&ok, &decl).unwrap();
        assert_eq!(
            input_object(&ok, &decl).unwrap(),
            json!({
                "amount": { "__extn": { "fn": "decimal", "arg": "100.0" } },
                "fees": [
                    { "__extn": { "fn": "decimal", "arg": "0.5" } },
                    { "__extn": { "fn": "decimal", "arg": "2.0" } },
                ],
                // Undeclared: as before.
                "note": { "__extn": { "fn": "decimal", "arg": "1.5000" } },
            })
        );
        for (bad, why) in [
            (
                json!({"amount": 12.34567}),
                "input.amount: expected decimal, got a number with more than 4 fractional \
                 digits or out of range",
            ),
            (
                json!({"amount": "12.5"}),
                "input.amount: expected decimal, got string",
            ),
            (
                json!({"amount": true}),
                "input.amount: expected decimal, got bool",
            ),
            (
                json!({"fees": ["0.5"]}),
                "input.fees: expected Set<decimal>, got array",
            ),
        ] {
            assert_eq!(
                check_tool_inputs(&args(bad.clone()), &decl).unwrap_err(),
                why,
                "{bad}"
            );
        }
        // Were the check skipped, the translation would still refuse rather than round.
        assert!(input_object(&args(json!({"amount": 12.34567})), &decl).is_err());
    }

    #[test]
    fn nulls_are_dropped_and_numbers_mapped() {
        let v = json!({ "a": null, "b": [1, null, "x"], "c": 1.5, "d": 18446744073709551615u64 });
        let out = to_cedar_json(&v, "input").unwrap();
        assert_eq!(
            out,
            json!({
                "b": [1, "x"],
                "c": { "__extn": { "fn": "decimal", "arg": "1.5000" } },
                "d": "18446744073709551615"
            })
        );
    }

    fn user_with(attrs: Value) -> attenuo_core::OriginatingUser {
        attenuo_core::OriginatingUser {
            subject: "alice".into(),
            issuer: "https://idp".into(),
            authenticated_at: OffsetDateTime::now_utc(),
            attributes: attrs
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }

    #[test]
    fn declared_types_are_checked() {
        let decl = crate::schema::default_user_attrs();
        let ok = user_with(json!({"mfa": true, "roles": ["a"], "tenant": "t", "email": null}));
        assert!(check_user_attributes(&ok, &decl).is_ok());
        for bad in [
            json!({"mfa": "true"}),
            json!({"roles": "dev"}),
            json!({"roles": ["a", 1]}),
            json!({"tenant": ["t"]}),
            json!({"email": 5}),
            json!({"tenant": {"a": 1}}),
        ] {
            assert!(
                check_user_attributes(&user_with(bad.clone()), &decl).is_err(),
                "{bad}"
            );
        }
        let mut long = BTreeMap::new();
        long.insert("n".to_string(), ArgType::Long);
        assert!(check_user_attributes(&user_with(json!({"n": 3})), &long).is_ok());
        assert!(check_user_attributes(&user_with(json!({"n": 3.5})), &long).is_err());
        assert!(check_user_attributes(&user_with(json!({"n": "3"})), &long).is_err());
    }

    #[test]
    fn declared_input_types_are_checked_as_cedar_sees_them() {
        let decl: BTreeMap<String, ArgType> = [
            ("repo".to_string(), ArgType::String),
            ("n".to_string(), ArgType::Long),
            ("flag".to_string(), ArgType::Bool),
            ("tags".to_string(), ArgType::Set(Box::new(ArgType::String))),
        ]
        .into_iter()
        .collect();
        let args = |v: Value| -> BTreeMap<String, Value> {
            v.as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        for ok in [
            json!({}),
            json!({"repo": "acme/api", "n": 3, "flag": false, "tags": ["a", "b"]}),
            // Absent, null and undeclared arguments are not checked.
            json!({"repo": null, "n": null, "other": 42}),
            // Cedar sees these as Long, like `to_cedar_json` makes them.
            json!({"n": -7}),
            json!({"n": 5.0}),
            // Null list elements are dropped before Cedar.
            json!({"tags": ["a", null], "n": 0}),
            json!({"tags": []}),
        ] {
            assert!(check_tool_inputs(&args(ok.clone()), &decl).is_ok(), "{ok}");
        }
        for (bad, why) in [
            (json!({"repo": 42}), "input.repo: expected String, got long"),
            (
                json!({"repo": ["acme/api"]}),
                "input.repo: expected String, got array",
            ),
            (
                json!({"repo": {"a": 1}}),
                "input.repo: expected String, got object",
            ),
            (json!({"n": "3"}), "input.n: expected Long, got string"),
            (json!({"n": 3.5}), "input.n: expected Long, got number"),
            (json!({"n": u64::MAX}), "input.n: expected Long, got number"),
            (json!({"n": 1e300}), "input.n: expected Long, got number"),
            (
                json!({"flag": "true"}),
                "input.flag: expected Bool, got string",
            ),
            (
                json!({"tags": "a"}),
                "input.tags: expected Set<String>, got string",
            ),
            (
                json!({"tags": ["a", 1]}),
                "input.tags: expected Set<String>, got array",
            ),
        ] {
            assert_eq!(
                check_tool_inputs(&args(bad.clone()), &decl).unwrap_err(),
                why,
                "{bad}"
            );
        }
        // Nothing declared, nothing checked.
        let none = BTreeMap::new();
        assert!(check_tool_inputs(&args(json!({"repo": 42, "n": "x"})), &none).is_ok());
    }

    #[test]
    fn reserved_keys_are_rejected() {
        let v = json!({ "nested": { "__entity": { "type": "User", "id": "admin" } } });
        let err = to_cedar_json(&v, "input").unwrap_err();
        assert!(err.0.contains("input.nested.__entity"));
    }

    fn chain_of(depth: usize, attrs: Value) -> DelegationChain {
        use attenuo_core::chain::DEFAULT_MAX_DEPTH;
        use attenuo_core::{AgentId, Capability, CapabilitySet, LeaseId};
        let now = OffsetDateTime::from_unix_timestamp(1_760_000_000).unwrap();
        let caps = || CapabilitySet::from_iter([Capability::new("gh", "*")]);
        let mut chain = DelegationChain::root(
            user_with(attrs),
            AgentId::new("root"),
            caps(),
            now,
            time::Duration::hours(1),
            LeaseId::new("l0"),
        )
        .unwrap();
        for i in 1..depth {
            chain = chain
                .extend(
                    AgentId::new(format!("a{i}")),
                    caps(),
                    now,
                    time::Duration::minutes(10),
                    LeaseId::new(format!("l{i}")),
                    DEFAULT_MAX_DEPTH,
                )
                .unwrap();
        }
        chain
    }

    /// The cached path (`RequestParts::build` once, `request` per call) produces exactly the
    /// request and entities of the one-pass JSON translation, for every shape of argument
    /// and attribute the translation accepts.
    #[test]
    fn context_matches_the_json_translation() {
        let now = OffsetDateTime::from_unix_timestamp(1_760_000_100).unwrap();
        let user_attrs = [
            json!({}),
            json!({"mfa": true, "roles": ["dev", "ops"], "tenant": "acme", "email": null}),
            json!({"level": 2.5, "n": 7, "zero": 0.0, "nested": {"a": [1, null, {"b": "c"}]}}),
        ];
        let args = [
            json!({}),
            json!({"repo": "alice/public-docs", "path": "README.md"}),
            json!({"n": 0, "f": 0.0, "g": 1.5, "h": -2.25, "big": 18446744073709551615u64,
                   "tiny": 1e-9, "huge": 1e300, "neg": -5}),
            json!({"list": [1, "two", true, null, [3], {"k": "v"}], "empty": [], "obj": {}}),
            json!({"nested": {"deep": {"deeper": {"x": null, "y": "ünïcödé"}}}, "t": false}),
            json!({"type": "User", "id": "admin"}),
        ];
        for depth in [1usize, 3] {
            for attrs in &user_attrs {
                let chain = chain_of(depth, attrs.clone());
                for arguments in &args {
                    for session in [None, Some("abc123def456".to_string())] {
                        for (server, tool) in [("gh", "read_file"), ("gh", "resources/read")] {
                            let mut call = ToolCall::new(server, tool, arguments.clone());
                            call.session_id = session.clone();
                            let tool_attrs = ToolAttrs::new().readonly(true);
                            for (legacy, labels) in
                                [(false, CallLabels::default()), (true, tainted_labels())]
                            {
                                let reference =
                                    build(&chain, &call, &tool_attrs, &labels, now, legacy)
                                        .unwrap();
                                let parts = RequestParts::build(&chain, &call, &tool_attrs, legacy)
                                    .unwrap();
                                let request = parts
                                    .request(&call, &BTreeMap::new(), &labels, now)
                                    .unwrap();
                                let what = format!(
                                    "{depth} {attrs} {arguments} {session:?} {tool} {legacy}"
                                );
                                assert_eq!(request.context(), Some(&reference.context), "{what}");
                                assert_eq!(request.principal(), Some(&reference.principal));
                                assert_eq!(request.action(), Some(&reference.action));
                                assert_eq!(request.resource(), Some(&reference.resource));
                                assert_eq!(parts.entities, reference.entities, "{what}");
                            }
                        }
                    }
                }
            }
        }
    }

    fn tainted_labels() -> CallLabels {
        CallLabels {
            session: crate::SessionLabels::from_sources(["web/fetch", "mail/read"]),
            args: crate::ArgLabels::from_args(["body", "to"]),
            ..Default::default()
        }
    }

    #[test]
    fn translation_errors_are_the_same() {
        let now = OffsetDateTime::now_utc();
        let bad_user = chain_of(1, json!({"__entity": {"type": "User", "id": "admin"}}));
        let call = ToolCall::new("gh", "read_file", json!({}));
        let attrs = ToolAttrs::new();
        let labels = CallLabels::default();
        let reference = build(&bad_user, &call, &attrs, &labels, now, false)
            .err()
            .unwrap();
        let cached = RequestParts::build(&bad_user, &call, &attrs, false).unwrap_err();
        assert_eq!(cached, reference);

        let chain = chain_of(1, json!({}));
        let bad_call = ToolCall::new("gh", "read_file", json!({"a": {"__extn": {}}}));
        let reference = build(&chain, &bad_call, &attrs, &labels, now, false)
            .err()
            .unwrap();
        let parts = RequestParts::build(&chain, &bad_call, &attrs, false).unwrap();
        assert_eq!(
            parts
                .request(&bad_call, &BTreeMap::new(), &labels, now)
                .unwrap_err(),
            reference
        );
    }

    #[test]
    fn the_cache_matches_on_everything_it_was_built_from() {
        let cache = RequestCache::new(16);
        let attrs = ToolAttrs::new();
        let chain = chain_of(2, json!({"mfa": true}));
        let call = ToolCall::new("gh", "read_file", json!({}));
        let first = cache.get_or_build(&chain, &call, &attrs, false).unwrap();
        let again = cache.get_or_build(&chain, &call, &attrs, false).unwrap();
        assert!(Arc::ptr_eq(&first, &again), "same chain and tool: a hit");
        // Different arguments and time are per call: still a hit.
        let other_args = ToolCall::new("gh", "read_file", json!({"repo": "x"}));
        let hit = cache
            .get_or_build(&chain, &other_args, &attrs, false)
            .unwrap();
        assert!(Arc::ptr_eq(&first, &hit));

        // Same fingerprint, different attribute values: a miss that replaces the entry.
        let no_mfa = chain_of(2, json!({"mfa": false}));
        let miss = cache.get_or_build(&no_mfa, &call, &attrs, false).unwrap();
        assert!(!Arc::ptr_eq(&first, &miss));
        assert_eq!(miss.key.attributes.get("mfa"), Some(&json!(false)));

        // Different tool attributes: a miss.
        let sensitive = ToolAttrs::new().sensitive(true);
        let miss = cache
            .get_or_build(&no_mfa, &call, &sensitive, false)
            .unwrap();
        assert!(miss.key.sensitive);
        let additive = ToolAttrs::new().sensitive(true).destructive(false);
        let miss2 = cache
            .get_or_build(&no_mfa, &call, &additive, false)
            .unwrap();
        assert!(!Arc::ptr_eq(&miss, &miss2));
        assert!(!miss2.key.destructive);

        // Another depth, another tool: separate entries.
        cache
            .get_or_build(&chain_of(3, json!({})), &call, &attrs, false)
            .unwrap();
        cache
            .get_or_build(
                &chain,
                &ToolCall::new("gh", "write_file", json!({})),
                &attrs,
                false,
            )
            .unwrap();
        assert!(cache.len() >= 3);
    }

    #[test]
    fn the_cache_stays_bounded() {
        let cache = RequestCache::new(3);
        let attrs = ToolAttrs::new();
        let chain = chain_of(1, json!({}));
        for i in 0..20 {
            let call = ToolCall::new("gh", format!("t{i}"), json!({}));
            cache.get_or_build(&chain, &call, &attrs, false).unwrap();
            assert!(cache.len() <= 3);
        }
        cache.clear();
        assert_eq!(cache.len(), 0);
    }
}
