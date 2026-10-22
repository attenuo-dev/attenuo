//! `onbehalf-proxy`: the policy enforcement point.
//!
//! An HTTP reverse proxy in front of one or more MCP servers speaking the Streamable HTTP
//! transport (JSON-RPC 2.0 over `POST`, responses as JSON or `text/event-stream`). Each upstream
//! is mounted at `/mcp/{server}`. For every request the proxy:
//!
//! 1. resolves the caller's `Authorization: Bearer <token>` into a [`DelegationChain`] through
//!    the pluggable [`Authorizer`] (missing or invalid token: HTTP 401, JSON-RPC error `-32001`);
//! 2. intercepts every `tools/call`, asks the [`Authorizer`] for a decision, forwards allowed
//!    calls upstream unchanged and answers denied ones with JSON-RPC error `-32003`
//!    (`"onbehalf: denied: <reason>"`, `data: {reason, decision_id}`);
//! 3. filters `tools/list` results down to the tools the caller's effective capabilities could
//!    ever permit by name (see [`filter::could_permit_tool`]);
//! 4. forwards everything else (`initialize`, `notifications/*`, `GET`/`DELETE` session
//!    requests) transparently, preserving `Mcp-Session-Id`.
//!
//! Every `tools/call` response carries an `X-Onbehalf-Decision-Id` header with the id(s) of the
//! decision record(s) the authorizer produced, so a client can correlate a reply with the audit
//! log.
//!
//! # Limitations (v0)
//!
//! - `tools/list` is only filtered when the upstream answers with `application/json`. If the
//!   upstream answers over SSE the response is passed through unfiltered and a warning is
//!   logged. Denials inside a JSON-RPC batch whose remainder is answered over SSE are emitted as
//!   leading SSE `message` events on the same stream.
//! - The proxy does not add credentials for the upstream; the bearer token it receives is
//!   onbehalf's, not the upstream's, and is never forwarded.
//! - Only `initialize`, `tools/list`, `tools/call` and notifications are understood. Other
//!   methods (`resources/*`, `prompts/*`, sampling) are forwarded without policy checks.
//! - Authentication is performed per HTTP request; there is no caching of resolved chains.
//!
//! [`DelegationChain`]: onbehalf_core::DelegationChain

pub mod auth;
pub mod config;
pub mod filter;
pub mod jsonrpc;
pub mod proxy;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use auth::{AuthDecision, AuthError, Authorizer};
pub use config::{ProxyConfig, UpstreamConfig};
pub use proxy::{router, serve, DECISION_ID_HEADER};
