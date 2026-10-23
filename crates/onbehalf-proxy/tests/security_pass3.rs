//! Regression tests for findings of the 2026-10-23 security review, pass 3
//! (`docs/research/security-review-2026-10-23.md`).
//!
//! Both findings here are in `crates/onbehalf-proxy/src/proxy.rs`, which was being changed on
//! other branches during the review, so they are not fixed yet and the tests are `#[ignore]`d.
//! The report describes the fix for each; remove the `#[ignore]` when it lands.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use futures_util::StreamExt;
use onbehalf_core::Capability;
use onbehalf_proxy::testing::{spawn_router, test_chain, Spawned, StaticAuthorizer};
use onbehalf_proxy::{router, ProxyConfig, UpstreamConfig};
use serde_json::json;

const SERVER: &str = "github";

/// An upstream that hands out a fresh session id to every POST without one, records every
/// `Mcp-Session-Id` value it receives (all of them, per request), and answers `GET` with an
/// SSE stream that emits one event every 50 ms for as long as the connection stays open.
#[derive(Clone, Default)]
struct SessionUpstream {
    next: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Vec<Vec<u8>>>>>,
}

impl SessionUpstream {
    fn record(&self, headers: &HeaderMap) -> Vec<Vec<u8>> {
        let values: Vec<Vec<u8>> = headers
            .get_all("mcp-session-id")
            .iter()
            .map(|v| v.as_bytes().to_vec())
            .collect();
        self.seen.lock().unwrap().push(values.clone());
        values
    }

    /// Did any request reach the upstream carrying `sid` (in any of its session headers)?
    fn received(&self, sid: &str) -> bool {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .any(|values| values.iter().any(|v| v == sid.as_bytes()))
    }

    fn router(&self) -> Router {
        let (a, b) = (self.clone(), self.clone());
        Router::new().route(
            "/mcp",
            post(move |headers: HeaderMap| {
                let me = a.clone();
                async move {
                    let values = me.record(&headers);
                    let mut resp = (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/json")],
                        json!({"jsonrpc": "2.0", "id": 1, "result": {}}).to_string(),
                    )
                        .into_response();
                    if values.is_empty() {
                        let n = me.next.fetch_add(1, Ordering::SeqCst) + 1;
                        resp.headers_mut().insert(
                            "mcp-session-id",
                            HeaderValue::from_str(&format!("sess-{n}")).unwrap(),
                        );
                    }
                    resp
                }
            })
            .get(move |headers: HeaderMap| {
                let me = b.clone();
                async move {
                    me.record(&headers);
                    let events = futures_util::stream::unfold(0u64, |i| async move {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        let event = format!(
                            "event: message\ndata: {}\n\n",
                            json!({"jsonrpc": "2.0", "method": "notifications/message",
                                   "params": {"level": "info", "data": i}})
                        );
                        Some((Ok::<_, std::io::Error>(event), i + 1))
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .body(Body::from_stream(events))
                        .unwrap()
                }
            }),
        )
    }
}

async fn proxy_with(upstream: &Spawned, authorizer: Arc<StaticAuthorizer>) -> Spawned {
    let config = ProxyConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        vec![UpstreamConfig::new(SERVER, upstream.url("/mcp"))],
    );
    spawn_router(router(config, authorizer)).await.unwrap()
}

fn ping() -> String {
    json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string()
}

/// POST a ping as `bearer` with the given raw `Mcp-Session-Id` values (one header each).
async fn post_with_sessions(proxy: &Spawned, bearer: &str, sids: &[&[u8]]) -> reqwest::Response {
    let mut headers = reqwest::header::HeaderMap::new();
    for sid in sids {
        headers.append(
            "mcp-session-id",
            reqwest::header::HeaderValue::from_bytes(sid).unwrap(),
        );
    }
    reqwest::Client::new()
        .post(proxy.url(&format!("/mcp/{SERVER}")))
        .bearer_auth(bearer)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .headers(headers)
        .body(ping())
        .send()
        .await
        .unwrap()
}

/// SR-27: the session gate reads only the first `Mcp-Session-Id` value (and none at all when
/// that value is not visible ASCII), but every value is forwarded upstream. Bob can put his own
/// session (or a junk byte) first and alice's session second; an upstream that reads the last
/// header (or the first one it can decode) then serves bob inside alice's session.
#[tokio::test]
#[ignore = "SR-27: open, fix in crates/onbehalf-proxy/src/proxy.rs (see the 2026-10-23 report)"]
async fn a_second_session_header_cannot_smuggle_another_principals_session() {
    let upstream = SessionUpstream::default();
    let up = spawn_router(upstream.router()).await.unwrap();
    let caps = || [Capability::new(SERVER, "read_*")];
    let authorizer = Arc::new(
        StaticAuthorizer::new()
            .with_chain("alice", test_chain("user:alice", "agent:a", caps()))
            .with_chain("bob", test_chain("user:bob", "agent:b", caps())),
    );
    let proxy = proxy_with(&up, authorizer).await;

    // Each opens a session of their own.
    let alice_sid = post_with_sessions(&proxy, "alice", &[]).await.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let bob_sid = post_with_sessions(&proxy, "bob", &[]).await.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_ne!(alice_sid, bob_sid);

    // Bob's own session first, alice's second.
    let resp = post_with_sessions(&proxy, "bob", &[bob_sid.as_bytes(), alice_sid.as_bytes()]).await;
    let status = resp.status();
    // A byte that is not visible ASCII first, so the gate sees no session id at all.
    let resp2 = post_with_sessions(&proxy, "bob", &[b"\x80", alice_sid.as_bytes()]).await;
    let status2 = resp2.status();

    assert!(
        !upstream.received(&alice_sid),
        "alice's session id reached the upstream on bob's requests (statuses {status}, {status2})"
    );
    // The proxy should refuse an ambiguous or undecodable session header outright.
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(status2, StatusCode::BAD_REQUEST);
}

/// SR-28: the lease check for a `GET` listen stream (and for a `tools/call` answered over SSE)
/// happens once, when the stream opens. After the lease is revoked (or the token expires) the
/// proxy keeps relaying server-to-client messages for as long as the connection lives, so
/// in-flight revocation (P4) does not reach it.
#[tokio::test]
#[ignore = "SR-28: open, fix in crates/onbehalf-proxy/src/proxy.rs (see the 2026-10-23 report)"]
async fn revocation_ends_an_open_sse_stream() {
    let upstream = SessionUpstream::default();
    let up = spawn_router(upstream.router()).await.unwrap();
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain(
        "alice",
        test_chain("user:alice", "agent:a", [Capability::new(SERVER, "read_*")]),
    ));
    let proxy = proxy_with(&up, authorizer.clone()).await;
    let sid = post_with_sessions(&proxy, "alice", &[]).await.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();

    let resp = reqwest::Client::new()
        .get(proxy.url(&format!("/mcp/{SERVER}")))
        .bearer_auth("alice")
        .header("accept", "text/event-stream")
        .header("mcp-session-id", &sid)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut stream = resp.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("first event")
        .expect("stream open")
        .unwrap();
    assert!(String::from_utf8_lossy(&first).contains("notifications/message"));

    authorizer.revoke("alice");

    // The stream must end soon after the revocation. Five seconds leaves room for a periodic
    // re-check; today events keep coming until the client hangs up.
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(chunk) = stream.next().await {
            if chunk.is_err() {
                break;
            }
        }
    })
    .await;
    assert!(
        ended.is_ok(),
        "the SSE stream kept relaying events after the lease was revoked"
    );
}
