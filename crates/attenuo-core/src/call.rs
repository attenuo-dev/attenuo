//! A normalized tool invocation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::digest::sha256_json;

/// A tool call as seen by the enforcement point, independent of transport (MCP, A2A, HTTP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Logical server name the call is addressed to (e.g. `github`).
    pub server: String,
    /// Tool name (e.g. `create_issue`).
    pub tool: String,
    /// Arguments, keyed by name. A `BTreeMap` so digests are stable.
    #[serde(default)]
    pub arguments: BTreeMap<String, Value>,
    /// Caller-supplied session identifier, if any (used for session-scoped policy and leases).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The request proved possession of the key its token is bound to (a DPoP proof for a
    /// token with `cnf.jkt`, SR-24). Recorded in the audit log; not part of the policy input.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dpop_bound: bool,
}

impl ToolCall {
    /// Build a call from a JSON object of arguments. Non-object values become an empty map.
    pub fn new(server: impl Into<String>, tool: impl Into<String>, arguments: Value) -> Self {
        let arguments = match arguments {
            Value::Object(m) => m.into_iter().collect(),
            _ => BTreeMap::new(),
        };
        Self {
            server: server.into(),
            tool: tool.into(),
            arguments,
            session_id: None,
            dpop_bound: false,
        }
    }

    /// Mark whether the request carried a verified DPoP proof for a bound token.
    pub fn with_dpop_bound(mut self, bound: bool) -> Self {
        self.dpop_bound = bound;
        self
    }

    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Check `server` and `tool` against [`crate::names`]: a server name, and a call name (a
    /// tool name or an MCP method name such as `resources/read`).
    pub fn check_names(&self) -> Result<(), crate::names::NameError> {
        crate::names::check_server_name(&self.server)?;
        crate::names::check_call_name(&self.tool)
    }

    /// Stable digest of the arguments, for audit records (arguments themselves may be sensitive).
    pub fn arguments_digest(&self) -> String {
        sha256_json(&self.arguments)
    }
}
