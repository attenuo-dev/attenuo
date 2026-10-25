//! Proxy configuration.

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// One upstream MCP server, mounted at `/mcp/{name}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Logical server name. This is the `server` field of every [`attenuo_core::ToolCall`]
    /// derived from requests to this upstream, so it must match the server names used in
    /// capabilities (e.g. `github`).
    pub name: String,
    /// Full URL of the upstream's Streamable HTTP endpoint (e.g. `http://127.0.0.1:3001/mcp`).
    pub url: String,
}

impl UpstreamConfig {
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
        }
    }
}

/// Default for [`ProxyConfig::stream_recheck`].
pub const DEFAULT_STREAM_RECHECK: Duration = Duration::from_secs(2);
/// Default for [`ProxyConfig::max_upstream_body_bytes`]: 16 MiB.
pub const DEFAULT_MAX_UPSTREAM_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Default for [`ProxyConfig::max_request_body_bytes`]: 4 MiB.
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub upstreams: Vec<UpstreamConfig>,
    pub listen: SocketAddr,
    /// How often a long-lived response stream (the `GET` listen stream, or a `POST` answered
    /// with a streamed body such as SSE) is re-checked against lease state and token expiry.
    /// The stream is ended at the first failed check (SR-28). Default
    /// [`DEFAULT_STREAM_RECHECK`]; a zero value is treated as one millisecond.
    #[serde(default = "default_stream_recheck")]
    pub stream_recheck: Duration,
    /// Deny a `tools/call` (reason `tool_not_listed`) whose exact name the upstream never
    /// returned from `tools/list` and the authorizer's catalog does not know
    /// ([`crate::Authorizer::knows_tool`]). Default `true` (SR-25); see [`crate::listed`].
    #[serde(default = "default_true")]
    pub require_listed_tools: bool,
    /// Largest upstream body the proxy buffers: a JSON response it must filter or merge
    /// replies into, or one SSE event of a stream it relays. Larger gets `502` (or ends the
    /// stream) instead of unbounded memory (SR-36). Default
    /// [`DEFAULT_MAX_UPSTREAM_BODY_BYTES`].
    #[serde(default = "default_max_upstream_body_bytes")]
    pub max_upstream_body_bytes: usize,
    /// Largest client request body accepted; larger gets `413` (SR-36). Default
    /// [`DEFAULT_MAX_REQUEST_BODY_BYTES`].
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
    /// Idle lifetime of an `Mcp-Session-Id` binding. Default
    /// [`crate::session::DEFAULT_SESSION_TTL`].
    #[serde(default = "default_session_ttl")]
    pub session_ttl: Duration,
    /// Most live session bindings held. When every slot is live, a response that would bind a
    /// new session gets `503` with reason `session_registry_full` (SR-36). Default
    /// [`crate::session::DEFAULT_MAX_SESSIONS`].
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// Most live session bindings one principal (the chain's root lease) holds. One more gets
    /// `429` with reason `too_many_sessions`, and the session the upstream just opened is
    /// deleted there (SR-49). Default
    /// [`crate::session::DEFAULT_MAX_SESSIONS_PER_PRINCIPAL`].
    #[serde(default = "default_max_sessions_per_principal")]
    pub max_sessions_per_principal: usize,
    /// The window bounding repeated audit records ([`crate::records`]): after a record, further
    /// occurrences of the same delegation chain, tool name and reason within it are counted
    /// instead of recorded. One window for both bounded kinds, the `stream.end` records of
    /// `GET` listen streams and the lease refusals of undecided requests (each kind keeps its
    /// own table). Default [`crate::records::DEFAULT_RECORD_WINDOW`]; the server's
    /// `[proxy] record_window_seconds` sets it in whole seconds.
    #[serde(default = "default_record_window")]
    pub record_window: Duration,
    /// Most (chain, tool, reason) windows each bounded kind keeps open at once; a table full
    /// of open windows records rather than suppresses ([`crate::records::RecordWindow`]).
    /// Default [`crate::records::DEFAULT_RECORD_WINDOW_MAX_KEYS`].
    #[serde(default = "default_record_window_max_keys")]
    pub record_window_max_keys: usize,
}

fn default_record_window() -> Duration {
    crate::records::DEFAULT_RECORD_WINDOW
}

fn default_record_window_max_keys() -> usize {
    crate::records::DEFAULT_RECORD_WINDOW_MAX_KEYS
}

fn default_max_upstream_body_bytes() -> usize {
    DEFAULT_MAX_UPSTREAM_BODY_BYTES
}

fn default_max_request_body_bytes() -> usize {
    DEFAULT_MAX_REQUEST_BODY_BYTES
}

fn default_session_ttl() -> Duration {
    crate::session::DEFAULT_SESSION_TTL
}

fn default_max_sessions() -> usize {
    crate::session::DEFAULT_MAX_SESSIONS
}

fn default_max_sessions_per_principal() -> usize {
    crate::session::DEFAULT_MAX_SESSIONS_PER_PRINCIPAL
}

fn default_stream_recheck() -> Duration {
    DEFAULT_STREAM_RECHECK
}

fn default_true() -> bool {
    true
}

impl ProxyConfig {
    pub fn new(listen: SocketAddr, upstreams: Vec<UpstreamConfig>) -> Self {
        Self {
            upstreams,
            listen,
            stream_recheck: DEFAULT_STREAM_RECHECK,
            require_listed_tools: true,
            max_upstream_body_bytes: DEFAULT_MAX_UPSTREAM_BODY_BYTES,
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            session_ttl: crate::session::DEFAULT_SESSION_TTL,
            max_sessions: crate::session::DEFAULT_MAX_SESSIONS,
            max_sessions_per_principal: crate::session::DEFAULT_MAX_SESSIONS_PER_PRINCIPAL,
            record_window: crate::records::DEFAULT_RECORD_WINDOW,
            record_window_max_keys: crate::records::DEFAULT_RECORD_WINDOW_MAX_KEYS,
        }
    }

    /// Set [`ProxyConfig::record_window`] and [`ProxyConfig::record_window_max_keys`].
    pub fn with_record_window(mut self, window: Duration, max_keys: usize) -> Self {
        self.record_window = window;
        self.record_window_max_keys = max_keys;
        self
    }

    /// Set [`ProxyConfig::max_upstream_body_bytes`].
    pub fn with_max_upstream_body_bytes(mut self, bytes: usize) -> Self {
        self.max_upstream_body_bytes = bytes;
        self
    }

    /// Set [`ProxyConfig::max_request_body_bytes`].
    pub fn with_max_request_body_bytes(mut self, bytes: usize) -> Self {
        self.max_request_body_bytes = bytes;
        self
    }

    /// Set [`ProxyConfig::session_ttl`] and [`ProxyConfig::max_sessions`].
    pub fn with_sessions(mut self, ttl: Duration, max: usize) -> Self {
        self.session_ttl = ttl;
        self.max_sessions = max;
        self
    }

    /// Set [`ProxyConfig::max_sessions_per_principal`].
    pub fn with_max_sessions_per_principal(mut self, max: usize) -> Self {
        self.max_sessions_per_principal = max;
        self
    }

    /// Set [`ProxyConfig::require_listed_tools`].
    pub fn with_require_listed_tools(mut self, on: bool) -> Self {
        self.require_listed_tools = on;
        self
    }

    /// Set [`ProxyConfig::stream_recheck`].
    pub fn with_stream_recheck(mut self, interval: Duration) -> Self {
        self.stream_recheck = interval;
        self
    }
}
