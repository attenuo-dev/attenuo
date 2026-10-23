//! Proxy configuration.

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// One upstream MCP server, mounted at `/mcp/{name}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Logical server name. This is the `server` field of every [`onbehalf_core::ToolCall`]
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
        }
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
