//! Proxy configuration.

use std::net::SocketAddr;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub upstreams: Vec<UpstreamConfig>,
    pub listen: SocketAddr,
}

impl ProxyConfig {
    pub fn new(listen: SocketAddr, upstreams: Vec<UpstreamConfig>) -> Self {
        Self { upstreams, listen }
    }
}
