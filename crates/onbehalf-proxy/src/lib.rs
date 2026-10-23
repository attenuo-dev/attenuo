//! `onbehalf-proxy`: the policy enforcement point.
//!
//! An HTTP reverse proxy in front of one or more MCP servers speaking the Streamable HTTP
//! transport (JSON-RPC 2.0 over `POST`, responses as JSON or `text/event-stream`). Each upstream
//! is mounted at `/mcp/{server}`. For every request the proxy:
//!
//! 1. resolves the caller's `Authorization: Bearer <token>` into a [`DelegationChain`] through
//!    the pluggable [`Authorizer`] (missing or invalid token: HTTP 401, JSON-RPC error `-32001`);
//! 2. intercepts every request that can read data or cause an effect, asks the [`Authorizer`]
//!    for a decision, forwards allowed ones upstream unchanged and answers denied ones with
//!    JSON-RPC error `-32003` (`"onbehalf: denied: <reason>"`, `data: {reason, decision_id}`);
//! 3. filters `tools/list`, `resources/list`, `resources/templates/list` and `prompts/list`
//!    results down to the entries the caller's effective capabilities could ever permit, using
//!    the same names the request mapping below uses (see [`filter::could_permit_tool`],
//!    [`filter::could_permit_resource`], [`filter::could_permit_prompt`]); `nextCursor` is
//!    passed through untouched;
//! 4. forwards the remaining allowlisted methods transparently, preserving `Mcp-Session-Id`.
//!    These, `tools/list` and `GET`/`DELETE` session requests are authenticated and
//!    lease-checked ([`Authorizer::check_active`]) first, so a revoked token gets `401` there
//!    too.
//! 5. binds every `Mcp-Session-Id` the upstream assigns to the principal it was assigned to
//!    (originating user and root lease) and refuses the id from anyone else: `403` with reason
//!    `session_mismatch`, recorded through [`Authorizer::record_rejection`]. An id the proxy
//!    does not know gets `404`, which tells an MCP client to start a new session. Decision
//!    records and logs carry a hash prefix of the id ([`session::session_tag`]), never the id.
//!    A request must carry at most one `Mcp-Session-Id`, visible ASCII only, or it gets `400`;
//!    only that checked value is forwarded. Upstream responses with more than one session id
//!    (or an invalid one) have the header removed and bind nothing (SR-27). See [`session`].
//!
//! Every authorized request's response carries an `X-Onbehalf-Decision-Id` header with the
//! id(s) of the decision record(s) the authorizer produced, so a client can correlate a reply
//! with the audit log.
//!
//! # Method to `ToolCall` mapping
//!
//! The authorizer sees a [`ToolCall`](onbehalf_core::ToolCall) with `server` = the `/mcp/{server}`
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
//! `prompts/list`, `logging/setLevel`, and every `notifications/*`. A message with no `method`
//! (a client response to a server request) is forwarded after the lease check.
//!
//! The default is deny: an unknown method (including `resources/unsubscribe` and
//! `sampling/*`) is allowed only if a capability and the policy permit a tool named after the
//! method. A request missing the field the mapping needs (`name`, `uri`) is answered with
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
//!   onbehalf's, not the upstream's, and is never forwarded.
//! - A server-to-client stream (the `GET` SSE channel, including a resumed one) is not
//!   inspected; the client's replies to
//!   server requests are forwarded after a lease check, not authorized.
//! - Authentication is performed per HTTP request; there is no caching of resolved chains.
//!
//! [`DelegationChain`]: onbehalf_core::DelegationChain

pub mod auth;
pub mod config;
pub mod filter;
pub mod jsonrpc;
pub mod proxy;
pub mod session;
pub mod sse;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use auth::{AuthDecision, AuthError, Authorizer};
pub use config::{ProxyConfig, UpstreamConfig};
pub use proxy::{router, serve, DECISION_ID_HEADER, REASON_SESSION_MISMATCH};
pub use session::{SessionOwner, SessionRegistry};
