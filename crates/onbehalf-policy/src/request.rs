//! Translation of a `(DelegationChain, ToolCall)` pair into a Cedar request: the entity store
//! and the context record. The shape is documented at the crate root.

use std::collections::BTreeMap;

use cedar_policy::{Context, Entities, EntityId, EntityTypeName, EntityUid};
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

/// The Cedar request parts for one authorization.
pub(crate) struct CedarRequest {
    pub principal: EntityUid,
    pub action: EntityUid,
    pub resource: EntityUid,
    pub context: Context,
    pub entities: Entities,
}

pub(crate) fn build(
    chain: &DelegationChain,
    call: &ToolCall,
    attrs: &ToolAttrs,
    now: OffsetDateTime,
) -> Result<CedarRequest, TranslationError> {
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
    // `Action::"<tool>"` is `in Action::"invoke"` if the entity store says so; without these
    // entries `action in Action::"invoke"` is false and a `forbid` written that way never fires.
    entities.push(json!({
        "uid": uid_json("Action", GENERIC_ACTION),
        "attrs": {},
        "parents": [],
    }));
    if call.tool != GENERIC_ACTION {
        entities.push(json!({
            "uid": uid_json("Action", &call.tool),
            "attrs": {},
            "parents": [uid_json("Action", GENERIC_ACTION)],
        }));
    }
    let entities = Entities::from_json_value(Value::Array(entities), None)
        .map_err(|e| TranslationError(format!("entities: {e}")))?;

    Ok(CedarRequest {
        principal: uid("Agent", &agent.0),
        action: uid("Action", &call.tool),
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
}
