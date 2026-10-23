//! OpenID AuthZEN 1.0 Authorization API types, so any policy enforcement point that speaks
//! AuthZEN can use attenuo as its policy decision point.
//!
//! Wire shape (`POST /access/v1/evaluation`):
//!
//! ```json
//! {
//!   "subject":  { "type": "agent", "id": "coder", "properties": { "chain": { ... } } },
//!   "action":   { "name": "create_issue", "properties": { "server": "github" } },
//!   "resource": { "type": "tool", "id": "github/create_issue",
//!                 "properties": { "server": "github", "tool": "create_issue" } },
//!   "context":  { "input": { "repo": "acme/api" }, "session_id": "s1" }
//! }
//! ```
//!
//! `subject.properties.chain` carries the whole serialized [`DelegationChain`], so the request
//! is self-contained and [`to_chain_and_call`] can rebuild the attenuo inputs exactly. The
//! response is `{ "decision": bool, "context": { "reason", "policy_ids", "diagnostics" } }`.

use attenuo_core::{Decision, DelegationChain, ToolCall};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{Outcome, PolicyError};

/// `subject.type` used for attenuo agents.
pub const SUBJECT_TYPE: &str = "agent";
/// `resource.type` used for tools.
pub const RESOURCE_TYPE: &str = "tool";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    #[serde(rename = "type")]
    pub r#type: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    #[serde(rename = "type")]
    pub r#type: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Value>,
}

/// AuthZEN evaluation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationRequest {
    pub subject: Subject,
    pub action: Action,
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

/// AuthZEN evaluation response. `context` carries the reason code, the determining policy ids
/// and any diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationResponse {
    pub decision: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

/// Map an attenuo `(chain, call)` pair to an AuthZEN request.
pub fn to_request(chain: &DelegationChain, call: &ToolCall) -> EvaluationRequest {
    let agent = chain
        .current_agent()
        .map(|a| a.0.clone())
        .unwrap_or_default();
    let mut context =
        json!({ "input": Value::Object(call.arguments.clone().into_iter().collect()) });
    if let Some(sid) = &call.session_id {
        context["session_id"] = Value::String(sid.clone());
    }
    EvaluationRequest {
        subject: Subject {
            r#type: SUBJECT_TYPE.to_string(),
            id: agent,
            properties: Some(json!({
                "chain": chain,
                "originating_user": chain.originating_user,
            })),
        },
        action: Action {
            name: call.tool.clone(),
            properties: Some(json!({ "server": call.server })),
        },
        resource: Resource {
            r#type: RESOURCE_TYPE.to_string(),
            id: format!("{}/{}", call.server, call.tool),
            properties: Some(json!({ "server": call.server, "tool": call.tool })),
        },
        context: Some(context),
    }
}

/// Rebuild the attenuo inputs from an AuthZEN request produced by [`to_request`] (or by any
/// PEP that follows the same conventions: `subject.properties.chain` holds the chain, the
/// server comes from `action.properties.server` or `resource.properties.server`, and
/// `context.input` holds the arguments).
pub fn to_chain_and_call(
    req: &EvaluationRequest,
) -> Result<(DelegationChain, ToolCall), PolicyError> {
    if req.subject.r#type != SUBJECT_TYPE {
        return Err(PolicyError::Parse(format!(
            "authzen: subject.type must be `{SUBJECT_TYPE}`, got `{}`",
            req.subject.r#type
        )));
    }
    let chain_value = req
        .subject
        .properties
        .as_ref()
        .and_then(|p| p.get("chain"))
        .ok_or_else(|| {
            PolicyError::Parse("authzen: subject.properties.chain is required".into())
        })?;
    let chain: DelegationChain = serde_json::from_value(chain_value.clone())
        .map_err(|e| PolicyError::Parse(format!("authzen: subject.properties.chain: {e}")))?;
    if chain.current_agent().map(|a| a.0.as_str()) != Some(req.subject.id.as_str()) {
        return Err(PolicyError::Parse(
            "authzen: subject.id does not match the chain's current agent".into(),
        ));
    }
    let server = req
        .action
        .properties
        .as_ref()
        .and_then(|p| p.get("server"))
        .or_else(|| {
            req.resource
                .properties
                .as_ref()
                .and_then(|p| p.get("server"))
        })
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            req.resource
                .id
                .strip_suffix(&format!("/{}", req.action.name))
                .map(str::to_string)
        })
        .ok_or_else(|| PolicyError::Parse("authzen: cannot determine the server".into()))?;
    let input = req
        .context
        .as_ref()
        .and_then(|c| c.get("input"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut call = ToolCall::new(server, req.action.name.clone(), input);
    if let Some(sid) = req
        .context
        .as_ref()
        .and_then(|c| c.get("session_id"))
        .and_then(Value::as_str)
    {
        call = call.with_session(sid);
    }
    Ok((chain, call))
}

/// Map an [`Outcome`] to an AuthZEN response.
pub fn from_outcome(o: &Outcome) -> EvaluationResponse {
    EvaluationResponse {
        decision: o.decision.is_allow(),
        context: Some(json!({
            "reason": o.reason,
            "policy_ids": o.policy_ids,
            "diagnostics": o.diagnostics,
        })),
    }
}

/// Map an AuthZEN response back to an [`Outcome`]. Missing context fields default to an empty
/// reason, no policy ids and no diagnostics.
pub fn to_outcome(r: &EvaluationResponse) -> Outcome {
    let get_strings = |key: &str| -> Vec<String> {
        r.context
            .as_ref()
            .and_then(|c| c.get(key))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    Outcome {
        decision: if r.decision {
            Decision::Allow
        } else {
            Decision::Deny
        },
        reason: r
            .context
            .as_ref()
            .and_then(|c| c.get("reason"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        policy_ids: get_strings("policy_ids"),
        diagnostics: get_strings("diagnostics"),
    }
}
