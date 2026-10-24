//! `attenuo-proxy`: the policy enforcement point.
//!
//! An HTTP reverse proxy in front of one or more MCP servers speaking the Streamable HTTP
//! transport (JSON-RPC 2.0 over `POST`, responses as JSON or `text/event-stream`). Each upstream
//! is mounted at `/mcp/{server}`. For every request the proxy:
//!
//! 1. resolves the caller's `Authorization: Bearer <token>` into a [`DelegationChain`] through
//!    the pluggable [`Authorizer`] (missing or invalid token: HTTP 401, JSON-RPC error `-32001`);
//! 2. intercepts every request that can read data or cause an effect, asks the [`Authorizer`]
//!    for a decision, forwards allowed ones upstream unchanged and answers denied ones with
//!    JSON-RPC error `-32003` (`"attenuo: denied: <reason>"`, `data: {reason, decision_id}`);
//! 3. filters `tools/list`, `resources/list`, `resources/templates/list` and `prompts/list`
//!    results down to the entries the caller's effective capabilities could ever permit, using
//!    the same names the request mapping below uses (see [`filter::could_permit_tool`],
//!    [`filter::could_permit_resource`], [`filter::could_permit_prompt`]); `nextCursor` is
//!    passed through untouched;
//! 4. forwards the remaining allowlisted methods transparently, preserving `Mcp-Session-Id`.
//!    These, `tools/list` and `GET`/`DELETE` session requests are authenticated and
//!    lease-checked ([`Authorizer::check_active`]) first, so a revoked token gets `401` there
//!    too. That refusal is recorded through [`Authorizer::record_rejection`] (one record per
//!    request, tool = the allowlisted method or `http.<METHOD>`) and the `401` names the record;
//!    a token that does not verify is never recorded.
//! 5. binds every `Mcp-Session-Id` the upstream assigns to the principal it was assigned to
//!    (originating user and root lease) and refuses the id from anyone else: `403` with reason
//!    `session_mismatch`, recorded through [`Authorizer::record_rejection`]. An id the proxy
//!    does not know gets `404`, which tells an MCP client to start a new session. Decision
//!    records and logs carry a hash prefix of the id ([`session::session_tag`]), never the id.
//!    A request must carry at most one `Mcp-Session-Id`, visible ASCII only, or it gets `400`;
//!    only that checked value is forwarded. Upstream responses with more than one session id
//!    (or an invalid one) have the header removed and bind nothing (SR-27). See [`session`].
//!
//! 6. checks every `tools/call` name before asking for a decision (SR-25): it must be a valid
//!    tool name ([`attenuo_core::names`]: `[A-Za-z0-9_.-]`, at most 128 bytes, compared
//!    case-sensitively), or the call is denied with reason `invalid_name`; and, with
//!    [`ProxyConfig::require_listed_tools`] (default on), it must be a name the upstream
//!    returned from `tools/list` or one the authorizer's catalog knows
//!    ([`Authorizer::knows_tool`]), or the call is denied with reason `tool_not_listed`. So an
//!    upstream that resolves `Delete_Repo` to `delete_repo` cannot be used to step around a rule
//!    keyed on `delete_repo`. Both denials are recorded through
//!    [`Authorizer::record_rejection`]. See [`listed`].
//!
//! 7. bounds what it holds in memory (SR-36): request bodies over
//!    [`ProxyConfig::max_request_body_bytes`] (default 4 MiB) get `413`; an upstream body it
//!    must buffer (a JSON response to filter, one SSE event) over
//!    [`ProxyConfig::max_upstream_body_bytes`] (default 16 MiB) gets `502` (or ends the
//!    stream); and when every one of [`ProxyConfig::max_sessions`] session slots holds a live
//!    binding, a response that would bind a new session is replaced by `503` with reason
//!    `session_registry_full`. Expired bindings are reclaimed; live ones are never evicted.
//!    One principal (root lease) holds at most [`ProxyConfig::max_sessions_per_principal`]
//!    (default 64) live bindings; one more gets `429` with reason `too_many_sessions`, while
//!    other principals keep working (SR-49). Either way the session the upstream just created
//!    is deleted there with an MCP `DELETE`, best effort.
//!
//! 8. passes a `DPoP` proof (RFC 9449), with the method and path it must name, to
//!    [`Authorizer::authenticate_request`] (SR-24). A token bound to a key (`cnf.jkt`) is
//!    refused without a valid proof: `401` with reason `dpop_required` or
//!    `invalid_dpop_proof` and a `WWW-Authenticate: DPoP` challenge. Either
//!    `Authorization: Bearer <token>` or `Authorization: DPoP <token>` is accepted; the
//!    binding comes from the token. Decisions record whether the request was bound
//!    ([`attenuo_core::ToolCall::dpop_bound`]).
//!
//! 9. re-checks every response it streams (the `GET` listen stream, and a `POST` answered with
//!    a streamed body such as SSE) every [`ProxyConfig::stream_recheck`] (default 2 s) against
//!    the token's expiry and [`Authorizer::check_active`], and ends the stream at the first
//!    failure: an SSE stream after a final event carrying JSON-RPC error `-32001` with
//!    `data.reason` (`token_expired`, `lease_revoked`, ...), any other body with a transport
//!    error (SR-28). See [`guard`].
//!
//! 10. removes a signed approval token from `params._meta["dev.attenuo/approval"]`
//!     ([`auth::META_APPROVAL_KEY`]) of every message before it goes upstream (and `_meta`
//!     itself when nothing else is left in it), and hands the token to the decision in
//!     [`CallContext::approval_token`] (output labelling, ADR-0009). The key is removed before
//!     the [`ToolCall`](attenuo_core::ToolCall) is built, so it never reaches the arguments or
//!     the call hash. A value that is not a string gets `-32602`.
//!
//! Every authorized request's response carries an `X-Attenuo-Decision-Id` header with the
//! id(s) of the decision record(s) the authorizer produced, so a client can correlate a reply
//! with the audit log.
//!
//! The proxy times its own stages of a `POST` that carried a decided call (upstream round trip,
//! response handling, total; see [`Stage`]) and reports them through
//! [`Authorizer::observe_stage`] and a `tracing` debug event.
//!
//! # Method to `ToolCall` mapping
//!
//! The authorizer sees a [`ToolCall`](attenuo_core::ToolCall) with `server` = the `/mcp/{server}`
//! name and these fields. Capabilities and Cedar policies therefore name `resources/read` or
//! `prompts/get` exactly as they name a tool.
//!
//! | JSON-RPC method | `tool` | `arguments` |
//! |---|---|---|
//! | `tools/call` | `params.name` | `params.arguments` (or `{}`) |
//! | `resources/read` | `"resources/read"` | `{ "uri": params.uri }` |
//! | `resources/subscribe` | `"resources/subscribe"` | `{ "uri": params.uri }` |
//! | `prompts/get` | `"prompts/get"` | `{ "name": params.name, "arguments": params.arguments or {} }` |
//! | `completion/complete` | `"completion/complete"` | `params` as sent (`ref`, `argument`, `context`) |
//! | any other method not listed below | the method name | `params` as sent (or `{}`) |
//!
//! Not authorized per call (forwarded after authentication and a lease check):
//! `initialize`, `ping`, `tools/list`, `resources/list`, `resources/templates/list`,
//! `prompts/list`, `resources/unsubscribe`, `logging/setLevel`, and every `notifications/*`. A
//! message with no `method` (a client response to a server request) is forwarded after the
//! lease check. A failed lease check of any of them is recorded as a `deny` under the method's
//! name (or `http.POST`). `resources/unsubscribe` only gives something up, so it needs no
//! decision; `resources/subscribe` does.
//!
//! The default is deny: an unknown method (including `sampling/*`) is allowed only if a
//! capability and the policy permit a tool named after the method. A request missing the field the mapping needs (`name`, `uri`) is answered with
//! `-32602` and is not forwarded. `tools/call` and `prompts/get` with the same `name` stay
//! distinct because the latter's tool is `prompts/get`.
//!
//! # Limitations (v0)
//!
//! - List results are filtered in `application/json` bodies (single or batch) and in
//!   `text/event-stream` bodies, event by event ([`sse`]). A list request answered with any
//!   other content type, or with a body that does not parse, gets `502` instead of an
//!   unfiltered result. Denials inside a JSON-RPC batch whose remainder is answered over SSE
//!   are emitted as leading SSE `message` events on the same stream.
//! - The proxy does not add credentials for the upstream; the bearer token it receives is
//!   attenuo's, not the upstream's, and is never forwarded.
//! - On a server-to-client stream (the `GET` SSE channel, including one resumed with
//!   `Last-Event-ID`) the proxy did not see the requests, so a response there whose `result`
//!   holds a list array is filtered by its shape ([`filter::list_kinds_by_shape`]), answers to
//!   allowed calls are labelled ([`label`]), and everything else is relayed event by event and
//!   re-checked. A `GET` answered with anything but SSE is relayed as is (MCP allows only SSE
//!   or `405`). The client's replies to server requests are forwarded after a lease check, not
//!   authorized.
//! - Authentication is performed per HTTP request; there is no caching of resolved chains.
//!
//! [`DelegationChain`]: attenuo_core::DelegationChain

pub mod auth;
pub mod config;
pub mod filter;
pub mod guard;
pub mod jsonrpc;
pub mod label;
pub mod listed;
pub mod proxy;
pub mod session;
pub mod sse;
pub mod stage;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use auth::{
    ApprovalTicket, AuthDecision, AuthError, Authenticated, Authorizer, CallContext, RequestAuth,
    META_APPROVAL_KEY, REASON_APPROVAL_REQUIRED, REASON_LABEL_ERROR,
};
pub use config::{ProxyConfig, UpstreamConfig};
pub use proxy::{
    router, serve, DECISION_ID_HEADER, REASON_INVALID_NAME, REASON_REQUEST_TOO_LARGE,
    REASON_SESSION_MISMATCH, REASON_SESSION_REGISTRY_FULL, REASON_TOOL_NOT_LISTED,
    REASON_TOO_MANY_SESSIONS, REASON_UPSTREAM_BODY_TOO_LARGE,
};
pub use session::{SessionOwner, SessionRegistry};
pub use stage::Stage;
