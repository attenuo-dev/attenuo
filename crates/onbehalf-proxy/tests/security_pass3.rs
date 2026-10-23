//! Regression tests for findings of the 2026-10-23 security review, pass 3
//! (`docs/research/security-review-2026-10-23.md`).
//!
//! Both findings here are in `crates/onbehalf-proxy/src/proxy.rs`: SR-27 (ambiguous
//! `Mcp-Session-Id` headers) and SR-28 (long-lived streams outliving revocation).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use futures_util::StreamExt;
use onbehalf_core::{AgentId, Capability, CapabilitySet, DelegationChain, LeaseId};
use onbehalf_proxy::testing::{spawn_router, test_chain, test_user, Spawned, StaticAuthorizer};
use onbehalf_proxy::{router, ProxyConfig, UpstreamConfig};
use serde_json::json;

const SERVER: &str = "github";

/// The stream re-check interval used in these tests (SR-28); production defaults to 2 s.
const RECHECK: Duration = Duration::from_millis(100);

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
            .delete({
                let me = self.clone();
                move |headers: HeaderMap| {
                    let me = me.clone();
                    async move {
                        me.record(&headers);
                        StatusCode::OK
                    }
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
    )
    .with_stream_recheck(RECHECK);
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

/// SR-27, `GET` and `DELETE`: the listen stream and session termination take the same single,
/// visible-ASCII session header as `POST`; anything else is refused before the upstream sees it.
#[tokio::test]
async fn get_and_delete_refuse_ambiguous_session_headers() {
    let upstream = SessionUpstream::default();
    let up = spawn_router(upstream.router()).await.unwrap();
    let caps = || [Capability::new(SERVER, "read_*")];
    let authorizer = Arc::new(
        StaticAuthorizer::new()
            .with_chain("alice", test_chain("user:alice", "agent:a", caps()))
            .with_chain("bob", test_chain("user:bob", "agent:b", caps())),
    );
    let proxy = proxy_with(&up, authorizer).await;
    let sid = |resp: reqwest::Response| {
        resp.headers()["mcp-session-id"]
            .to_str()
            .unwrap()
            .to_owned()
    };
    let alice_sid = sid(post_with_sessions(&proxy, "alice", &[]).await);
    let bob_sid = sid(post_with_sessions(&proxy, "bob", &[]).await);

    let client = reqwest::Client::new();
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        for sids in [
            &[bob_sid.as_bytes(), alice_sid.as_bytes()][..],
            &[b"\x80", alice_sid.as_bytes()][..],
            &[&b"\x80"[..]][..],
        ] {
            let mut headers = reqwest::header::HeaderMap::new();
            for s in sids {
                headers.append(
                    "mcp-session-id",
                    reqwest::header::HeaderValue::from_bytes(s).unwrap(),
                );
            }
            let resp = client
                .request(method.clone(), proxy.url(&format!("/mcp/{SERVER}")))
                .bearer_auth("bob")
                .header("accept", "text/event-stream")
                .headers(headers)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{method} {sids:?}");
        }
    }
    assert!(!upstream.received(&alice_sid));

    // A single, valid header still works, and is forwarded once.
    let resp = client
        .delete(proxy.url(&format!("/mcp/{SERVER}")))
        .bearer_auth("bob")
        .header("mcp-session-id", &bob_sid)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let seen = upstream.seen.lock().unwrap().clone();
    assert_eq!(seen.last().unwrap(), &vec![bob_sid.as_bytes().to_vec()]);
}

/// SR-27, response side: an upstream that sends two `Mcp-Session-Id` headers gets neither
/// bound, and the client sees none.
#[tokio::test]
async fn an_upstream_sending_two_session_ids_binds_neither() {
    let up = spawn_router(Router::new().route(
        "/mcp",
        post(|| async {
            let mut resp = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                json!({"jsonrpc": "2.0", "id": 1, "result": {}}).to_string(),
            )
                .into_response();
            for sid in ["sess-a", "sess-b"] {
                resp.headers_mut()
                    .append("mcp-session-id", HeaderValue::from_static(sid));
            }
            resp
        }),
    ))
    .await
    .unwrap();
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain(
        "alice",
        test_chain("user:alice", "agent:a", [Capability::new(SERVER, "read_*")]),
    ));
    let proxy = proxy_with(&up, authorizer).await;
    let resp = post_with_sessions(&proxy, "alice", &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get_all("mcp-session-id").iter().count(), 0);
    // Neither id was bound: using one is "unknown session".
    for sid in ["sess-a", "sess-b"] {
        let resp = post_with_sessions(&proxy, "alice", &[sid.as_bytes()]).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{sid}");
    }
}

/// SR-28: the lease check for a `GET` listen stream (and for a `tools/call` answered over SSE)
/// happens once, when the stream opens. After the lease is revoked (or the token expires) the
/// proxy keeps relaying server-to-client messages for as long as the connection lives, so
/// in-flight revocation (P4) does not reach it.
#[tokio::test]
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

/// Open a `GET` listen stream as `bearer` on a fresh session, and wait for its first event.
async fn open_listen_stream(
    proxy: &Spawned,
    bearer: &str,
) -> impl futures_util::Stream<Item = reqwest::Result<axum::body::Bytes>> {
    let sid = post_with_sessions(proxy, bearer, &[]).await.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let resp = reqwest::Client::new()
        .get(proxy.url(&format!("/mcp/{SERVER}")))
        .bearer_auth(bearer)
        .header("accept", "text/event-stream")
        .header("mcp-session-id", &sid)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut stream = Box::pin(resp.bytes_stream());
    let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("first event")
        .expect("stream open")
        .unwrap();
    assert!(String::from_utf8_lossy(&first).contains("notifications/message"));
    stream
}

/// Read `stream` to its end (or `limit`), returning everything received and how long it took.
async fn drain(
    mut stream: impl futures_util::Stream<Item = reqwest::Result<axum::body::Bytes>> + Unpin,
    limit: Duration,
) -> (String, Duration) {
    let start = std::time::Instant::now();
    let mut text = String::new();
    let ended = tokio::time::timeout(limit, async {
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(b) => text.push_str(&String::from_utf8_lossy(&b)),
                Err(_) => break,
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the stream was still open after {limit:?}");
    (text, start.elapsed())
}

/// The JSON-RPC payload of the last SSE event in `text`.
fn last_event(text: &str) -> serde_json::Value {
    let data = text
        .split("\n\n")
        .filter_map(|e| e.lines().find_map(|l| l.strip_prefix("data: ")))
        .last()
        .expect("an event");
    serde_json::from_str(data).unwrap()
}

/// SR-28: the stream ends within a few re-check intervals of the revocation, and its last
/// event says why.
#[tokio::test]
async fn a_revoked_listen_stream_ends_promptly_with_a_reason() {
    let upstream = SessionUpstream::default();
    let up = spawn_router(upstream.router()).await.unwrap();
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain(
        "alice",
        test_chain("user:alice", "agent:a", [Capability::new(SERVER, "read_*")]),
    ));
    let proxy = proxy_with(&up, authorizer.clone()).await;
    let stream = open_listen_stream(&proxy, "alice").await;

    authorizer.revoke("alice");
    let (text, took) = drain(stream, Duration::from_secs(5)).await;
    assert!(took < RECHECK * 10, "took {took:?}");
    let last = last_event(&text);
    assert_eq!(last["error"]["code"], -32001);
    assert_eq!(last["error"]["data"]["reason"], "lease_revoked");
}

/// SR-28: a listen stream does not outlive the token that opened it.
#[tokio::test]
async fn an_expired_tokens_listen_stream_ends() {
    let upstream = SessionUpstream::default();
    let up = spawn_router(upstream.router()).await.unwrap();
    let ttl = Duration::from_millis(800);
    let chain = DelegationChain::root(
        test_user("user:alice"),
        AgentId::new("agent:a"),
        CapabilitySet::from_iter([Capability::new(SERVER, "read_*")]),
        time::OffsetDateTime::now_utc(),
        time::Duration::try_from(ttl).unwrap(),
        LeaseId::new("lease-short"),
    )
    .unwrap();
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain("alice", chain));
    let proxy = proxy_with(&up, authorizer).await;
    let stream = open_listen_stream(&proxy, "alice").await;

    let (text, _) = drain(stream, ttl + Duration::from_secs(2)).await;
    assert_eq!(
        last_event(&text)["error"]["data"]["reason"],
        "token_expired"
    );
}

/// SR-28: re-checking does not disturb a stream whose lease stays live.
#[tokio::test]
async fn an_untouched_listen_stream_keeps_flowing() {
    let upstream = SessionUpstream::default();
    let up = spawn_router(upstream.router()).await.unwrap();
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain(
        "alice",
        test_chain("user:alice", "agent:a", [Capability::new(SERVER, "read_*")]),
    ));
    let proxy = proxy_with(&up, authorizer).await;
    let mut stream = open_listen_stream(&proxy, "alice").await;

    // Several re-check intervals' worth of events, all upstream notifications.
    let mut events = 0;
    let deadline = tokio::time::Instant::now() + RECHECK * 8;
    while let Ok(next) = tokio::time::timeout_at(deadline, stream.next()).await {
        let chunk = next
            .expect("stream still open")
            .expect("no transport error");
        let text = String::from_utf8_lossy(&chunk).into_owned();
        assert!(!text.contains("-32001"), "{text}");
        events += text.matches("notifications/message").count();
    }
    assert!(events >= 8, "only {events} events in {:?}", RECHECK * 8);
}

/// SR-28: a `tools/call` answered over a long-lived SSE stream is re-checked too.
#[tokio::test]
async fn a_revoked_sse_tool_call_response_ends() {
    let up = spawn_router(Router::new().route(
        "/mcp",
        post(|| async {
            let events = futures_util::stream::unfold(0u64, |i| async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let event = format!(
                    "event: message\ndata: {}\n\n",
                    json!({"jsonrpc": "2.0", "method": "notifications/progress",
                           "params": {"progressToken": "t", "progress": i}})
                );
                Some((Ok::<_, std::io::Error>(event), i + 1))
            });
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(events))
                .unwrap()
        }),
    ))
    .await
    .unwrap();
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain(
        "alice",
        test_chain("user:alice", "agent:a", [Capability::new(SERVER, "read_*")]),
    ));
    let proxy = proxy_with(&up, authorizer.clone()).await;
    let resp = reqwest::Client::new()
        .post(proxy.url(&format!("/mcp/{SERVER}")))
        .bearer_auth("alice")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                   "params": {"name": "read_slowly", "arguments": {}}})
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut stream = Box::pin(resp.bytes_stream());
    let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("first event")
        .expect("stream open")
        .unwrap();
    assert!(String::from_utf8_lossy(&first).contains("notifications/progress"));

    authorizer.revoke("alice");
    let (text, took) = drain(stream, Duration::from_secs(5)).await;
    assert!(took < RECHECK * 10, "took {took:?}");
    assert_eq!(
        last_event(&text)["error"]["data"]["reason"],
        "lease_revoked"
    );
}
