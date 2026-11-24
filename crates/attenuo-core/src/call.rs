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
    /// The request showed the TLS client certificate its token is bound to (a token with
    /// `cnf.x5t#S256`, RFC 8705 §3). Recorded in the audit log; not part of the policy input.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cert_bound: bool,
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
            cert_bound: false,
        }
    }

    /// Mark whether the request carried a verified DPoP proof for a bound token.
    pub fn with_dpop_bound(mut self, bound: bool) -> Self {
        self.dpop_bound = bound;
        self
    }

    /// Mark whether the request showed the TLS client certificate its token is bound to.
    pub fn with_cert_bound(mut self, bound: bool) -> Self {
        self.cert_bound = bound;
        self
    }

    /// Set the MCP session id the call arrived on.
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Check `server` and `tool` against [`crate::names`]: a server name, and a call name (a
    /// tool name or an MCP method name such as `resources/read`).
    ///
    /// # Errors
    ///
    /// [`NameError`](crate::names::NameError) if `server` is not a valid server name (checked
    /// first) or `tool` is not a valid call name: empty, longer than
    /// [`MAX_NAME_LEN`](crate::names::MAX_NAME_LEN) bytes, or holding a character outside
    /// `[A-Za-z0-9_.-]` (or, in `tool`, an empty `/`-separated segment).
    pub fn check_names(&self) -> Result<(), crate::names::NameError> {
        crate::names::check_server_name(&self.server)?;
        crate::names::check_call_name(&self.tool)
    }

    /// Stable digest of the arguments, for audit records (arguments themselves may be sensitive).
    pub fn arguments_digest(&self) -> String {
        sha256_json(&self.arguments)
    }

    /// The hash an approval is bound to (ADR-0009): SHA-256, hex, of the RFC 8785 canonical
    /// JSON of `{"server", "tool", "arguments"}`. Any change to the server, the tool or one
    /// argument gives another hash; the session and the DPoP flag are not part of it.
    pub fn call_hash(&self) -> String {
        sha256_json(&serde_json::json!({
            "server": self.server,
            "tool": self.tool,
            "arguments": self.arguments,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_hash_covers_server_tool_and_arguments() {
        let call = ToolCall::new("mail", "send", serde_json::json!({"to": "bob", "n": 1}));
        // Canonical form: keys sorted, no whitespace.
        assert_eq!(
            call.call_hash(),
            crate::digest::sha256_bytes(
                br#"{"arguments":{"n":1,"to":"bob"},"server":"mail","tool":"send"}"#
            )
        );
        let same = ToolCall::new("mail", "send", serde_json::json!({"n": 1.0, "to": "bob"}));
        assert_eq!(call.call_hash(), same.call_hash());
        for other in [
            ToolCall::new("mail", "send", serde_json::json!({"to": "eve", "n": 1})),
            ToolCall::new("mail", "draft", serde_json::json!({"to": "bob", "n": 1})),
            ToolCall::new("mail2", "send", serde_json::json!({"to": "bob", "n": 1})),
        ] {
            assert_ne!(call.call_hash(), other.call_hash());
        }
        let tagged = call.clone().with_session("abc").with_dpop_bound(true);
        assert_eq!(call.call_hash(), tagged.call_hash());
    }
}
