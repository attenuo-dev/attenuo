//! Translation of a `(DelegationChain, ToolCall)` pair into a Cedar request: the entity store
//! and the context record. The shape is documented at the crate root.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use cedar_policy::{
    Context, Entities, EntityId, EntityTypeName, EntityUid, Request, RestrictedExpression,
};
use onbehalf_core::{DelegationChain, ToolCall};
use serde_json::{json, Map, Value};
use time::OffsetDateTime;

use crate::catalog::{ArgType, ToolAttrs};
use crate::schema::GENERIC_ACTION;

/// Largest magnitude a Cedar `decimal` can hold.
// Cedar decimal range is +/-922337203685477.5807; stay a little inside it.
const DECIMAL_MAX: f64 = 922_337_203_685_477.0;

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
                if f.is_finite() && f.fract() == 0.0 && f.abs() <= DECIMAL_MAX {
                    // JSON has one number type: `0.0` is the value `0` to most consumers
                    // (JavaScript, Python's `==`), so it must be the Cedar `Long` 0 too.
                    // Otherwise `forbid ... when { context.input.n == 0 }` is bypassed by
                    // sending `0.0`. |f| <= DECIMAL_MAX < 2^63, so the cast is exact.
                    json!(f as i64)
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
    user: &onbehalf_core::OriginatingUser,
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

pub(crate) fn uid(ty: &str, id: &str) -> EntityUid {
    let ty: EntityTypeName = ty.parse().expect("entity type names used here are valid");
    EntityUid::from_type_name_and_id(ty, EntityId::new(id))
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
/// `context.input`, `context.session_id` and `context.now_unix` are built per call.
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
                "depth": chain.depth() as i64,
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
        let (Some(originating_user), Some(chain_record)) = (originating_user, chain_record) else {
            return Err(TranslationError("context: missing record".into()));
        };

        Ok(Self {
            key: PartsKey::new(chain, call, attrs),
            principal: uid("Agent", &agent.0),
            action: uid("Action", &action),
            resource: uid("Tool", &tool_id(call)),
            originating_user,
            chain: chain_record,
            entities: entities(chain, call, attrs, &action)?,
        })
    }

    /// The Cedar request for `call` at `now`, with the per-call context members.
    pub(crate) fn request(
        &self,
        call: &ToolCall,
        now: OffsetDateTime,
    ) -> Result<Request, TranslationError> {
        let input = object_from(call.arguments.iter(), "input")?;
        let mut pairs = Vec::with_capacity(5);
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
            "attrs": { "id": hop.agent.0, "chain_depth": (i + 1) as i64 },
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
            "depth": chain.depth() as i64,
            "agents": agents,
            "root_agent": root_agent,
            "leases": leases,
        }),
    );
    if let Some(sid) = &call.session_id {
        context.insert("session_id".into(), Value::String(sid.clone()));
    }
    context.insert("now_unix".into(), json!(now.unix_timestamp()));
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
            "attrs": { "id": hop.agent.0, "chain_depth": (i + 1) as i64 },
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
        principal: uid("Agent", &agent.0),
        action: uid("Action", &action),
        resource: uid("Tool", &tool_id(call)),
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

    fn user_with(attrs: Value) -> onbehalf_core::OriginatingUser {
        onbehalf_core::OriginatingUser {
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
    fn reserved_keys_are_rejected() {
        let v = json!({ "nested": { "__entity": { "type": "User", "id": "admin" } } });
        let err = to_cedar_json(&v, "input").unwrap_err();
        assert!(err.0.contains("input.nested.__entity"));
    }

    fn chain_of(depth: usize, attrs: Value) -> DelegationChain {
        use onbehalf_core::chain::DEFAULT_MAX_DEPTH;
        use onbehalf_core::{AgentId, Capability, CapabilitySet, LeaseId};
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
                            for legacy in [false, true] {
                                let reference =
                                    build(&chain, &call, &tool_attrs, now, legacy).unwrap();
                                let parts = RequestParts::build(&chain, &call, &tool_attrs, legacy)
                                    .unwrap();
                                let request = parts.request(&call, now).unwrap();
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

    #[test]
    fn translation_errors_are_the_same() {
        let now = OffsetDateTime::now_utc();
        let bad_user = chain_of(1, json!({"__entity": {"type": "User", "id": "admin"}}));
        let call = ToolCall::new("gh", "read_file", json!({}));
        let attrs = ToolAttrs::new();
        let reference = build(&bad_user, &call, &attrs, now, false).err().unwrap();
        let cached = RequestParts::build(&bad_user, &call, &attrs, false).unwrap_err();
        assert_eq!(cached, reference);

        let chain = chain_of(1, json!({}));
        let bad_call = ToolCall::new("gh", "read_file", json!({"a": {"__extn": {}}}));
        let reference = build(&chain, &bad_call, &attrs, now, false).err().unwrap();
        let parts = RequestParts::build(&chain, &bad_call, &attrs, false).unwrap();
        assert_eq!(parts.request(&bad_call, now).unwrap_err(), reference);
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
