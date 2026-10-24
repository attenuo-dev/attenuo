//! New sessions are handed to `Authorizer::record_session` (revoke by session): once per
//! session the proxy binds, as a digest, and never for a caller that did not authenticate, a
//! revoked chain, or a session the proxy refused to bind.

use std::sync::Arc;

use attenuo_core::{Capability, LeaseId};
use attenuo_proxy::session::{session_digest, session_tag};
use attenuo_proxy::testing::{spawn_router, test_chain, FakeMcpServer, Spawned, StaticAuthorizer};
use attenuo_proxy::{router, ProxyConfig, UpstreamConfig};
use serde_json::{json, Value};

const SERVER: &str = "github";

struct Harness {
    authorizer: Arc<StaticAuthorizer>,
    proxy: Spawned,
    _up: Spawned,
}

impl Harness {
    async fn start(max_per_principal: usize) -> anyhow::Result<Self> {
        let upstream = FakeMcpServer::new(&["read_file"])
            .with_session_id("up")
            .with_fresh_session_ids(true);
        let up = upstream.spawn().await?;
        let authorizer = Arc::new(
            StaticAuthorizer::new()
                .with_chain(
                    "alice",
                    test_chain("user:alice", "agent:a", [Capability::new(SERVER, "*")]),
                )
                .with_chain(
                    "bob",
                    test_chain("user:bob", "agent:b", [Capability::new(SERVER, "*")]),
                ),
        );
        let cfg = ProxyConfig::new(
            "127.0.0.1:0".parse()?,
            vec![UpstreamConfig::new(SERVER, up.url("/mcp"))],
        )
        .with_max_sessions_per_principal(max_per_principal);
        let proxy = spawn_router(router(cfg, authorizer.clone())).await?;
        Ok(Self {
            authorizer,
            proxy,
            _up: up,
        })
    }

    /// POST `msg` as `bearer`: status and the `Mcp-Session-Id` of the response.
    async fn post(
        &self,
        bearer: &str,
        session: Option<&str>,
        msg: &Value,
    ) -> anyhow::Result<(u16, Option<String>)> {
        let mut req = reqwest::Client::new()
            .post(self.proxy.url(&format!("/mcp/{SERVER}")))
            .header("accept", "application/json, text/event-stream")
            .bearer_auth(bearer)
            .json(msg);
        if let Some(s) = session {
            req = req.header("mcp-session-id", s);
        }
        let resp = req.send().await?;
        let sid = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        Ok((resp.status().as_u16(), sid))
    }

    async fn initialize(&self, bearer: &str) -> anyhow::Result<(u16, Option<String>)> {
        let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "0"}}});
        self.post(bearer, None, &msg).await
    }
}

#[tokio::test]
async fn a_new_session_is_recorded_once_as_a_digest() -> anyhow::Result<()> {
    let h = Harness::start(64).await?;
    let (status, sid) = h.initialize("alice").await?;
    assert_eq!(status, 200);
    let sid = sid.expect("session id assigned");
    let digest = session_digest(&sid);
    assert_eq!(digest.len(), 64);
    assert!(
        digest.starts_with(&session_tag(&sid)),
        "the audit tag is its prefix"
    );
    assert_eq!(
        h.authorizer.recorded_sessions(),
        vec![(LeaseId::new("lease-agent:a"), SERVER.to_string(), digest)]
    );

    // Later requests on the session record nothing more.
    let ping = json!({"jsonrpc": "2.0", "id": 2, "method": "ping"});
    assert_eq!(h.post("alice", Some(&sid), &ping).await?.0, 200);
    assert_eq!(h.authorizer.recorded_sessions().len(), 1);

    // Bob's session is his own record.
    let (_, bob) = h.initialize("bob").await?;
    let got = h.authorizer.recorded_sessions();
    assert_eq!(got.len(), 2);
    assert_eq!(got[1].0, LeaseId::new("lease-agent:b"));
    assert_eq!(got[1].2, session_digest(&bob.expect("bob's session id")));
    Ok(())
}

/// SR-18: nothing is recorded for a token that does not verify or a revoked chain, and a
/// session the proxy refused to bind (SR-49) is not recorded either.
#[tokio::test]
async fn refused_callers_and_refused_sessions_are_not_recorded() -> anyhow::Result<()> {
    let h = Harness::start(1).await?;
    assert_eq!(h.initialize("nobody").await?.0, 401);
    assert!(h.authorizer.recorded_sessions().is_empty());

    assert_eq!(h.initialize("alice").await?.0, 200);
    let (status, sid) = h.initialize("alice").await?;
    assert_eq!((status, sid), (429, None));
    assert_eq!(h.authorizer.recorded_sessions().len(), 1);

    h.authorizer.revoke("bob");
    assert_eq!(h.initialize("bob").await?.0, 401);
    assert_eq!(h.authorizer.recorded_sessions().len(), 1);
    Ok(())
}
