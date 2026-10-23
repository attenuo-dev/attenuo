//! Minimal JSON-RPC 2.0 helpers. The proxy works on `serde_json::Value` so that messages it
//! does not understand are forwarded byte-for-byte rather than re-encoded through a schema.

use serde_json::{json, Value};
use uuid::Uuid;

/// Standard JSON-RPC parse error.
pub const CODE_PARSE_ERROR: i64 = -32700;
/// Standard JSON-RPC invalid request.
pub const CODE_INVALID_REQUEST: i64 = -32600;
/// Standard JSON-RPC invalid params.
pub const CODE_INVALID_PARAMS: i64 = -32602;
/// onbehalf: missing or invalid bearer token (sent with HTTP 401).
pub const CODE_UNAUTHORIZED: i64 = -32001;
/// onbehalf: the call was denied by policy.
pub const CODE_DENIED: i64 = -32003;
/// onbehalf: no upstream is configured under this name (sent with HTTP 404).
pub const CODE_UNKNOWN_SERVER: i64 = -32004;
/// onbehalf: the upstream could not be reached, or answered with something the proxy will not
/// relay (sent with HTTP 502).
pub const CODE_UPSTREAM: i64 = -32005;
/// onbehalf: the proxy is out of a bounded resource, such as session slots (sent with HTTP
/// 503).
pub const CODE_UNAVAILABLE: i64 = -32006;
/// onbehalf: this principal holds too many of a bounded resource, such as session slots (sent
/// with HTTP 429 and `Retry-After`; SR-49).
pub const CODE_TOO_MANY: i64 = -32007;

/// MCP method names the proxy understands.
pub const METHOD_TOOLS_CALL: &str = "tools/call";
pub const METHOD_TOOLS_LIST: &str = "tools/list";
pub const METHOD_RESOURCES_LIST: &str = "resources/list";
pub const METHOD_RESOURCES_TEMPLATES_LIST: &str = "resources/templates/list";
pub const METHOD_PROMPTS_LIST: &str = "prompts/list";
pub const METHOD_RESOURCES_READ: &str = "resources/read";
pub const METHOD_RESOURCES_SUBSCRIBE: &str = "resources/subscribe";
pub const METHOD_PROMPTS_GET: &str = "prompts/get";
pub const METHOD_COMPLETION_COMPLETE: &str = "completion/complete";

/// Methods forwarded without a per-call authorization decision. They are still authenticated
/// and lease-checked (`Authorizer::check_active`). Everything else that is not a notification
/// is authorized with `tool = method name`.
pub const PASSTHROUGH_METHODS: &[&str] = &[
    "initialize",
    "ping",
    METHOD_TOOLS_LIST,
    METHOD_RESOURCES_LIST,
    METHOD_RESOURCES_TEMPLATES_LIST,
    METHOD_PROMPTS_LIST,
    "logging/setLevel",
];

/// Is `method` forwarded without a per-call decision? True for [`PASSTHROUGH_METHODS`] and
/// every `notifications/*`.
pub fn is_passthrough_method(method: &str) -> bool {
    PASSTHROUGH_METHODS.contains(&method) || method.starts_with("notifications/")
}

/// Build a JSON-RPC error response.
pub fn error_response(
    id: Value,
    code: i64,
    message: impl Into<String>,
    data: Option<Value>,
) -> Value {
    let mut error = json!({ "code": code, "message": message.into() });
    if let Some(data) = data {
        error["data"] = data;
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": error })
}

/// The error response the proxy returns for a denied `tools/call`.
pub fn denied_response(id: Value, reason: &str, decision_id: Uuid) -> Value {
    error_response(
        id,
        CODE_DENIED,
        format!("onbehalf: denied: {reason}"),
        Some(json!({ "reason": reason, "decision_id": decision_id })),
    )
}

/// The `method` of a request or notification, if it has one.
pub fn method_of(msg: &Value) -> Option<&str> {
    msg.get("method").and_then(Value::as_str)
}

/// The `id` of a message, or `null` when it has none (a notification).
pub fn id_of(msg: &Value) -> Value {
    msg.get("id").cloned().unwrap_or(Value::Null)
}

/// Is this message a request (has an id), as opposed to a notification?
pub fn is_request(msg: &Value) -> bool {
    matches!(msg.get("id"), Some(v) if !v.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_response_shape() {
        let id = Uuid::nil();
        let v = denied_response(json!(7), "capability_denied", id);
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["error"]["code"], CODE_DENIED);
        assert_eq!(v["error"]["message"], "onbehalf: denied: capability_denied");
        assert_eq!(v["error"]["data"]["reason"], "capability_denied");
        assert_eq!(v["error"]["data"]["decision_id"], id.to_string());
    }

    #[test]
    fn passthrough_allowlist() {
        for m in PASSTHROUGH_METHODS {
            assert!(is_passthrough_method(m), "{m}");
        }
        assert!(is_passthrough_method("notifications/cancelled"));
        for m in [
            "tools/call",
            "resources/read",
            "resources/subscribe",
            "prompts/get",
            "completion/complete",
            "sampling/createMessage",
            "resources/unsubscribe",
            "notification/typo",
            "",
        ] {
            assert!(!is_passthrough_method(m), "{m}");
        }
    }

    #[test]
    fn notification_has_null_id() {
        let n = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        assert_eq!(id_of(&n), Value::Null);
        assert!(!is_request(&n));
        assert_eq!(method_of(&n), Some("notifications/initialized"));
        assert!(is_request(&json!({"id": 0, "method": "x"})));
    }
}
