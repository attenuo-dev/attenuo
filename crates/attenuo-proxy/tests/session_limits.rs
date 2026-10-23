//! SR-49 (`docs/research/security-review-2026-10-23-pass4.md`): a per-principal session cap,
//! and refused session bindings are deleted at the upstream.

use std::sync::Arc;
use std::time::Duration;

use attenuo_core::Capability;
use attenuo_proxy::jsonrpc::{CODE_TOO_MANY, CODE_UNAVAILABLE};
use attenuo_proxy::testing::{spawn_router, test_chain, FakeMcpServer, Spawned, StaticAuthorizer};
use attenuo_proxy::{
    router, ProxyConfig, UpstreamConfig, REASON_SESSION_REGISTRY_FULL, REASON_TOO_MANY_SESSIONS,
};
use serde_json::{json, Value};

const SERVER: &str = "github";

/// A proxy in front of a [`FakeMcpServer`] that opens a new session per `initialize`. Bearer
/// `alice` and `bob` are different principals (different root leases).
struct Harness {
    upstream: FakeMcpServer,
    proxy: Spawned,
    _up: Spawned,
}

/// Status, `Retry-After`, `Mcp-Session-Id` and body of a proxied response.
type Reply = (u16, Option<String>, Option<String>, Value);

fn initialize_msg() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
           "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                      "clientInfo": {"name": "t", "version": "0"}}})
}

impl Harness {
    async fn start(config: impl FnOnce(ProxyConfig) -> ProxyConfig) -> anyhow::Result<Self> {
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
        let cfg = config(ProxyConfig::new(
            "127.0.0.1:0".parse()?,
            vec![UpstreamConfig::new(SERVER, up.url("/mcp"))],
        ));
        let proxy = spawn_router(router(cfg, authorizer)).await?;
        Ok(Self {
            upstream,
            proxy,
            _up: up,
        })
    }

    async fn post(
        &self,
        bearer: &str,
        session: Option<&str>,
        msg: &Value,
    ) -> anyhow::Result<Reply> {
        let mut req = reqwest::Client::new()
            .post(self.proxy.url(&format!("/mcp/{SERVER}")))
            .header("accept", "application/json, text/event-stream")
            .bearer_auth(bearer)
            .json(msg);
        if let Some(s) = session {
            req = req.header("mcp-session-id", s);
        }
        let resp = req.send().await?;
        let header = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let (retry, sid) = (header("retry-after"), header("mcp-session-id"));
        let status = resp.status().as_u16();
        let body = resp.json().await.unwrap_or(Value::Null);
        Ok((status, retry, sid, body))
    }

    /// `initialize` as `bearer`: status, assigned session id, body.
    async fn initialize(&self, bearer: &str) -> anyhow::Result<(u16, Option<String>, Value)> {
        let (status, _, sid, body) = self.post(bearer, None, &initialize_msg()).await?;
        Ok((status, sid, body))
    }

    async fn ping(&self, bearer: &str, session: &str) -> anyhow::Result<u16> {
        let msg = json!({"jsonrpc": "2.0", "id": 2, "method": "ping"});
        Ok(self.post(bearer, Some(session), &msg).await?.0)
    }

    async fn delete(&self, bearer: &str, session: &str) -> anyhow::Result<u16> {
        Ok(reqwest::Client::new()
            .delete(self.proxy.url(&format!("/mcp/{SERVER}")))
            .bearer_auth(bearer)
            .header("mcp-session-id", session)
            .send()
            .await?
            .status()
            .as_u16())
    }
}

/// SR-49: one principal opening sessions in a loop hits its own cap (429 `too_many_sessions`,
/// `-32007`, `Retry-After`), keeps the sessions it has, and does not lock anyone else out.
#[tokio::test]
async fn one_principal_cannot_starve_another_sr49() -> anyhow::Result<()> {
    let h = Harness::start(|c| c.with_max_sessions_per_principal(2)).await?;
    let mut held = Vec::new();
    for _ in 0..2 {
        let (status, sid, body) = h.initialize("alice").await?;
        assert_eq!(status, 200, "{body}");
        held.push(sid.expect("session id assigned"));
    }
    for _ in 0..3 {
        let (status, retry, sid, body) = h.post("alice", None, &initialize_msg()).await?;
        assert_eq!(status, 429, "{body}");
        assert_eq!(retry.as_deref(), Some("30"));
        assert_eq!(sid, None, "the refused session id is not handed out");
        assert_eq!(body["error"]["code"], CODE_TOO_MANY);
        assert_eq!(body["error"]["data"]["reason"], REASON_TOO_MANY_SESSIONS);
    }
    // Bob is unaffected.
    let (status, sid, body) = h.initialize("bob").await?;
    assert_eq!(status, 200, "{body}");
    let bob = sid.expect("bob's session id");
    assert_eq!(h.ping("bob", &bob).await?, 200);
    // Alice's sessions still work.
    for sid in &held {
        assert_eq!(h.ping("alice", sid).await?, 200, "{sid}");
    }
    Ok(())
}

/// SR-49: a session the proxy refuses to bind is deleted at the upstream, both when the
/// principal is at its cap (429) and when the registry is full (503), so refused attempts do
/// not leak upstream sessions. Bound sessions are not touched.
#[tokio::test]
async fn refused_binds_delete_the_upstream_session_sr49() -> anyhow::Result<()> {
    // Principal cap.
    let h = Harness::start(|c| c.with_max_sessions_per_principal(1)).await?;
    let (status, kept, _) = h.initialize("alice").await?;
    assert_eq!((status, kept.as_deref()), (200, Some("up-1")));
    for _ in 0..2 {
        let (status, _, body) = h.initialize("alice").await?;
        assert_eq!(status, 429, "{body}");
    }
    assert_eq!(h.upstream.sessions_opened(), 3);
    assert_eq!(h.upstream.deleted_sessions(), vec!["up-2", "up-3"]);
    assert_eq!(h.ping("alice", "up-1").await?, 200);

    // Full registry.
    let h = Harness::start(|c| c.with_sessions(Duration::from_secs(3600), 1)).await?;
    let (status, _, _) = h.initialize("alice").await?;
    assert_eq!(status, 200);
    let (status, _, body) = h.initialize("bob").await?;
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["error"]["code"], CODE_UNAVAILABLE);
    assert_eq!(
        body["error"]["data"]["reason"],
        REASON_SESSION_REGISTRY_FULL
    );
    assert_eq!(h.upstream.deleted_sessions(), vec!["up-2"]);
    assert_eq!(h.ping("alice", "up-1").await?, 200);
    Ok(())
}

/// SR-49: only live bindings count. A session ended with `DELETE`, or idle past the TTL, frees
/// the principal's slot.
#[tokio::test]
async fn a_deleted_or_expired_binding_frees_the_slot_sr49() -> anyhow::Result<()> {
    let ttl = Duration::from_millis(1500);
    let h =
        Harness::start(|c| c.with_sessions(ttl, 100).with_max_sessions_per_principal(1)).await?;
    let (status, first, _) = h.initialize("alice").await?;
    assert_eq!(status, 200);
    let first = first.expect("session id");
    assert_eq!(h.initialize("alice").await?.0, 429);

    // Ending the session through the proxy frees the slot.
    assert_eq!(h.delete("alice", &first).await?, 200);
    let (status, second, body) = h.initialize("alice").await?;
    assert_eq!(status, 200, "{body}");
    assert_eq!(h.initialize("alice").await?.0, 429);

    // So does idling past the TTL.
    tokio::time::sleep(ttl + Duration::from_millis(200)).await;
    let (status, third, body) = h.initialize("alice").await?;
    assert_eq!(status, 200, "{body}");
    assert_ne!(second, third);
    assert_eq!(h.ping("alice", &second.expect("second")).await?, 404);
    Ok(())
}
