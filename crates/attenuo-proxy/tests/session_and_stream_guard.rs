//! Session headers and the stream guard: regression tests for the proxy findings of the
//! 2026-10-23 security review, pass 3 (`docs/research/security-review-2026-10-23.md`).
//! Formerly `security_pass3.rs`.
//!
//! Both findings here are in `crates/attenuo-proxy/src/proxy.rs`: SR-27 (ambiguous
//! `Mcp-Session-Id` headers) and SR-28 (long-lived streams outliving revocation, the audit
//! record of a stream the proxy ends, how listen streams ending are counted, and the bound on
//! `stream.end` records per chain and reason). The SR-27 tests share the session upstream the
//! SR-28 listen-stream tests use.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use attenuo_core::{
    AgentId, Capability, CapabilitySet, Decision, DelegationChain, LeaseId, ManualClock,
};
use attenuo_proxy::guard::{StreamEndCause, STREAM_END_TOOL};
use attenuo_proxy::session::session_tag;
use attenuo_proxy::testing::{spawn_router, test_chain, test_user, Spawned, StaticAuthorizer};
use attenuo_proxy::{router_with_clock, ProxyConfig, UpstreamConfig};
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use futures_util::StreamExt;
use serde_json::json;

const SERVER: &str = "github";

/// The stream re-check interval used in these tests (SR-28); production defaults to 2 s.
const RECHECK: Duration = Duration::from_millis(100);

/// Polls `done` every 10 ms until it is true; panics, naming `what`, after 5 s.
async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// How many of an upstream's response streams are still open. The proxy's guarded body owns
/// the upstream response, so an upstream stream is dropped only after the guard wrapping it
/// is: once none is open, no guard of those streams is left to re-check, record or count
/// anything, and a check of "nothing more happened" is exact instead of a wait.
#[derive(Clone, Default)]
struct Live(Arc<AtomicUsize>);

/// Held by one open upstream stream; dropping it closes the stream in [`Live`].
struct Open(Arc<AtomicUsize>);

impl Drop for Open {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Live {
    fn open(&self) -> Open {
        self.0.fetch_add(1, Ordering::SeqCst);
        Open(self.0.clone())
    }

    /// Wait until every stream this upstream opened is closed.
    async fn all_closed(&self) {
        eventually("upstream streams still open", || {
            self.0.load(Ordering::SeqCst) == 0
        })
        .await;
    }
}

/// An upstream that hands out a fresh session id to every POST without one, records every
/// `Mcp-Session-Id` value it receives (all of them, per request), and answers `GET` with an
/// SSE stream that emits one event every 50 ms for as long as the connection stays open.
#[derive(Clone, Default)]
struct SessionUpstream {
    next: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Vec<Vec<u8>>>>>,
    streams: Live,
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
                    let open = me.streams.open();
                    let events =
                        futures_util::stream::unfold((0u64, open), |(i, open)| async move {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            let event = format!(
                                "event: message\ndata: {}\n\n",
                                json!({"jsonrpc": "2.0", "method": "notifications/message",
                                       "params": {"level": "info", "data": i}})
                            );
                            Some((Ok::<_, std::io::Error>(event), (i + 1, open)))
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
    proxy_with_clock(upstream, authorizer, ManualClock::new()).await
}

/// [`proxy_with`], on `clock`: [`ManualClock::advance`] steps the proxy, and the re-checks of
/// its streams, past a token's expiry.
async fn proxy_with_clock(
    upstream: &Spawned,
    authorizer: Arc<StaticAuthorizer>,
    clock: Arc<ManualClock>,
) -> Spawned {
    let config = ProxyConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        vec![UpstreamConfig::new(SERVER, upstream.url("/mcp"))],
    )
    .with_stream_recheck(RECHECK);
    spawn_router(router_with_clock(config, authorizer, clock))
        .await
        .unwrap()
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
    open_listen_stream_in(proxy, bearer).await.1
}

/// [`open_listen_stream`], also returning the session id.
async fn open_listen_stream_in(
    proxy: &Spawned,
    bearer: &str,
) -> (
    String,
    impl futures_util::Stream<Item = reqwest::Result<axum::body::Bytes>>,
) {
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
    (sid, stream)
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

/// The one record a stream end left: a `deny` of [`STREAM_END_TOOL`] for `reason`, with the
/// session's hash tag, whose id the final event carries.
fn assert_stream_end_record(
    authorizer: &StaticAuthorizer,
    last: &serde_json::Value,
    reason: &str,
    sid: Option<&str>,
) {
    let records: Vec<_> = authorizer
        .decisions()
        .into_iter()
        .filter(|r| r.tool == STREAM_END_TOOL)
        .collect();
    assert_eq!(records.len(), 1, "{records:?}");
    let r = &records[0];
    assert_eq!(r.decision, Decision::Deny);
    assert_eq!(r.reason, reason);
    assert_eq!(r.server, SERVER);
    assert_eq!(r.session_id.as_deref(), sid.map(session_tag).as_deref());
    assert_eq!(last["error"]["data"]["decision_id"], r.id.to_string());
}

/// SR-28: the stream ends within a few re-check intervals of the revocation, its last event
/// says why, and the end is recorded once, against the session, with the event naming the
/// record.
#[tokio::test]
async fn a_revoked_listen_stream_ends_promptly_with_a_reason() {
    let upstream = SessionUpstream::default();
    let up = spawn_router(upstream.router()).await.unwrap();
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain(
        "alice",
        test_chain("user:alice", "agent:a", [Capability::new(SERVER, "read_*")]),
    ));
    let proxy = proxy_with(&up, authorizer.clone()).await;
    let (sid, stream) = open_listen_stream_in(&proxy, "alice").await;
    assert!(authorizer.decisions().is_empty());

    authorizer.revoke("alice");
    let (text, took) = drain(stream, Duration::from_secs(5)).await;
    assert!(took < RECHECK * 10, "took {took:?}");
    let last = last_event(&text);
    assert_eq!(last["error"]["code"], -32001);
    assert_eq!(last["error"]["data"]["reason"], "lease_revoked");
    assert_stream_end_record(&authorizer, &last, "lease_revoked", Some(&sid));
    assert_eq!(authorizer.decisions().len(), 1);
    upstream.streams.all_closed().await;
    assert_stream_ends(&authorizer, &[StreamEndCause::LeaseRevoked]).await;
}

/// Wait until `authorizer` has seen `expected.len()` listen-stream ends, then check they are
/// exactly `expected` (each stream is counted once, never again). The caller first makes sure
/// no guard of its streams is left to count anything: [`Live::all_closed`] for an upstream
/// that tracks its streams; for a single stream whose upstream ended it, the count itself
/// (taken when the guard is dropped).
async fn assert_stream_ends(authorizer: &StaticAuthorizer, expected: &[StreamEndCause]) {
    eventually("listen-stream ends", || {
        authorizer.stream_ends().len() >= expected.len()
    })
    .await;
    assert_eq!(authorizer.stream_ends(), expected);
}

/// SR-28: a listen stream the client drops, or the upstream ends, is not a decision: nothing
/// is recorded, even when the lease is revoked afterwards.
#[tokio::test]
async fn a_dropped_or_finished_listen_stream_leaves_no_record() {
    let upstream = SessionUpstream::default();
    let up = spawn_router(upstream.router()).await.unwrap();
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain(
        "alice",
        test_chain("user:alice", "agent:a", [Capability::new(SERVER, "read_*")]),
    ));
    let proxy = proxy_with(&up, authorizer.clone()).await;
    let stream = open_listen_stream(&proxy, "alice").await;
    drop(stream);
    // The proxy has dropped the stream's guard: nothing is left to see the revocation.
    upstream.streams.all_closed().await;
    authorizer.revoke("alice");
    assert!(authorizer.decisions().is_empty(), "client drop");
    // Counted, as a client disconnect, once.
    assert_stream_ends(&authorizer, &[StreamEndCause::ClientDisconnect]).await;

    // An upstream that ends its listen stream after one event.
    let finite = spawn_router(Router::new().route(
        "/mcp",
        post(|| async {
            (
                [(header::CONTENT_TYPE, "application/json")],
                json!({"jsonrpc": "2.0", "id": 1, "result": {}}).to_string(),
            )
        })
        .get(|| async {
            (
                [(header::CONTENT_TYPE, "text/event-stream")],
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n",
            )
        }),
    ))
    .await
    .unwrap();
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain(
        "alice",
        test_chain("user:alice", "agent:a", [Capability::new(SERVER, "read_*")]),
    ));
    let proxy = proxy_with(&finite, authorizer.clone()).await;
    let resp = reqwest::Client::new()
        .get(proxy.url(&format!("/mcp/{SERVER}")))
        .bearer_auth("alice")
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (text, _) = drain(resp.bytes_stream(), Duration::from_secs(5)).await;
    assert!(text.contains("notifications/message"), "{text}");
    assert!(!text.contains("-32001"), "{text}");
    // Counted when the proxy drops the stream's guard: once it is, nothing is left to see
    // the revocation.
    assert_stream_ends(&authorizer, &[StreamEndCause::UpstreamEof]).await;
    authorizer.revoke("alice");
    assert!(authorizer.decisions().is_empty(), "upstream end");
    assert_eq!(authorizer.stream_ends(), [StreamEndCause::UpstreamEof]);
}

/// A listen stream the upstream breaks (here: the upstream's body fails after one event) is
/// counted as `upstream_error`, once, and leaves no record.
#[tokio::test]
async fn a_listen_stream_the_upstream_breaks_is_counted_as_an_upstream_error() {
    let broken = spawn_router(Router::new().route(
        "/mcp",
        post(|| async {
            (
                [(header::CONTENT_TYPE, "application/json")],
                json!({"jsonrpc": "2.0", "id": 1, "result": {}}).to_string(),
            )
        })
        .get(|| async {
            let events = futures_util::stream::unfold(0u8, |i| async move {
                match i {
                    0 => Some((
                        Ok::<_, std::io::Error>(
                            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n"
                                .to_owned(),
                        ),
                        1,
                    )),
                    1 => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Some((Err(std::io::Error::other("upstream failed")), 2))
                    }
                    _ => None,
                }
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
    let proxy = proxy_with(&broken, authorizer.clone()).await;
    let resp = reqwest::Client::new()
        .get(proxy.url(&format!("/mcp/{SERVER}")))
        .bearer_auth("alice")
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let (text, _) = drain(resp.bytes_stream(), Duration::from_secs(5)).await;
    assert!(text.contains("notifications/message"), "{text}");
    assert!(!text.contains("-32001"), "{text}");
    assert_stream_ends(&authorizer, &[StreamEndCause::UpstreamError]).await;
    assert!(authorizer.decisions().is_empty());
}

/// A listen stream whose lease expires is cut, recorded with `lease_expired` and counted.
#[tokio::test]
async fn a_listen_stream_whose_lease_expired_ends_and_is_counted() {
    let upstream = SessionUpstream::default();
    let up = spawn_router(upstream.router()).await.unwrap();
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain(
        "alice",
        test_chain("user:alice", "agent:a", [Capability::new(SERVER, "read_*")]),
    ));
    let proxy = proxy_with(&up, authorizer.clone()).await;
    let (sid, stream) = open_listen_stream_in(&proxy, "alice").await;
    authorizer.expire_lease("alice");
    let (text, _) = drain(stream, Duration::from_secs(5)).await;
    let last = last_event(&text);
    assert_eq!(last["error"]["data"]["reason"], "lease_expired");
    assert_stream_end_record(&authorizer, &last, "lease_expired", Some(&sid));
    upstream.streams.all_closed().await;
    assert_stream_ends(&authorizer, &[StreamEndCause::LeaseExpired]).await;
}

/// Several listen streams of one chain cut by one revocation (several sessions of one token):
/// every stream ends with the same final event, but only the first end is a `stream.end`
/// record; the others are counted as suppressed and their final event names that record.
/// Another chain keeps its own record. Reopening the stream is still refused every time; those
/// refusals (`http.GET`) are bounded by their own window, so the first is recorded and the
/// second counted.
#[tokio::test]
async fn listen_streams_of_one_chain_cut_together_leave_one_record() {
    let upstream = SessionUpstream::default();
    let up = spawn_router(upstream.router()).await.unwrap();
    let authorizer = Arc::new(
        StaticAuthorizer::new()
            .with_chain(
                "alice",
                test_chain("user:alice", "agent:a", [Capability::new(SERVER, "read_*")]),
            )
            .with_chain(
                "bob",
                test_chain("user:bob", "agent:b", [Capability::new(SERVER, "read_*")]),
            ),
    );
    let proxy = proxy_with(&up, authorizer.clone()).await;
    let mut alice = Vec::new();
    for _ in 0..3 {
        alice.push(open_listen_stream_in(&proxy, "alice").await);
    }
    let (bob_sid, bob) = open_listen_stream_in(&proxy, "bob").await;

    authorizer.revoke("alice");
    authorizer.revoke("bob");
    let mut ids = Vec::new();
    for (_, stream) in alice {
        let (text, _) = drain(stream, Duration::from_secs(5)).await;
        let last = last_event(&text);
        assert_eq!(last["error"]["code"], -32001);
        assert_eq!(last["error"]["data"]["reason"], "lease_revoked");
        ids.push(last["error"]["data"]["decision_id"].clone());
    }
    let (text, _) = drain(bob, Duration::from_secs(5)).await;
    let bob_last = last_event(&text);

    let ends: Vec<_> = authorizer
        .decisions()
        .into_iter()
        .filter(|r| r.tool == STREAM_END_TOOL)
        .collect();
    assert_eq!(ends.len(), 2, "{ends:?}");
    let alice_record = ends
        .iter()
        .find(|r| r.originating_subject == "user:alice")
        .unwrap();
    let bob_record = ends
        .iter()
        .find(|r| r.originating_subject == "user:bob")
        .unwrap();
    assert!(
        ids.iter().all(|id| *id == alice_record.id.to_string()),
        "{ids:?}"
    );
    assert_eq!(
        bob_last["error"]["data"]["decision_id"],
        bob_record.id.to_string()
    );
    assert_eq!(
        bob_record.session_id.as_deref(),
        Some(session_tag(&bob_sid).as_str())
    );
    assert_eq!(
        authorizer.suppressed_records(),
        vec![(STREAM_END_TOOL.to_owned(), StreamEndCause::LeaseRevoked); 2]
    );
    upstream.streams.all_closed().await;
    assert_stream_ends(&authorizer, &[StreamEndCause::LeaseRevoked; 4]).await;

    // Reopening is refused each time; the first refusal is recorded, the second counted, and
    // both 401s name the record.
    let mut named = Vec::new();
    for _ in 0..2 {
        let resp = reqwest::Client::new()
            .get(proxy.url(&format!("/mcp/{SERVER}")))
            .bearer_auth("alice")
            .header("accept", "text/event-stream")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        named.push(resp.headers()["x-attenuo-decision-id"].clone());
    }
    let refusals: Vec<_> = authorizer
        .decisions()
        .into_iter()
        .filter(|r| r.tool == "http.GET")
        .collect();
    assert_eq!(refusals.len(), 1);
    assert!(named.iter().all(|h| h == &refusals[0].id.to_string()));
    assert_eq!(
        authorizer.suppressed_records()[2..],
        [("http.GET".to_owned(), StreamEndCause::LeaseRevoked)]
    );
}

/// The lifetime of the token [`short_lived_chain`] issues.
const SHORT_TTL: Duration = Duration::from_secs(60);

/// A [`ManualClock`], and an authorizer knowing `alice` by a chain whose token expires
/// [`SHORT_TTL`] from now on that clock.
fn short_lived_chain() -> (Arc<ManualClock>, Arc<StaticAuthorizer>) {
    let clock = ManualClock::new();
    let chain = DelegationChain::root(
        test_user("user:alice"),
        AgentId::new("agent:a"),
        CapabilitySet::from_iter([Capability::new(SERVER, "read_*")]),
        attenuo_core::Clock::now_utc(&*clock),
        time::Duration::try_from(SHORT_TTL).unwrap(),
        LeaseId::new("lease-short"),
    )
    .unwrap();
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain("alice", chain));
    (clock, authorizer)
}

/// SR-28: a listen stream does not outlive the token that opened it.
#[tokio::test]
async fn an_expired_tokens_listen_stream_ends() {
    let upstream = SessionUpstream::default();
    let up = spawn_router(upstream.router()).await.unwrap();
    let (clock, authorizer) = short_lived_chain();
    let proxy = proxy_with_clock(&up, authorizer.clone(), clock.clone()).await;
    let (sid, stream) = open_listen_stream_in(&proxy, "alice").await;

    clock.advance(SHORT_TTL);
    let (text, _) = drain(stream, Duration::from_secs(2)).await;
    let last = last_event(&text);
    assert_eq!(last["error"]["data"]["reason"], "token_expired");
    assert_stream_end_record(&authorizer, &last, "token_expired", Some(&sid));
    upstream.streams.all_closed().await;
    assert_stream_ends(&authorizer, &[StreamEndCause::TokenExpired]).await;
}

/// `token_expired` volume: every listen stream of one token still open at its expiry ends,
/// but only the first is recorded; the others are counted as suppressed. A client that then
/// reopens the stream with the expired token is refused (`401`, `token_expired`) without a
/// record, as before: an expired token is refused before any lease check, and is never
/// recorded.
#[tokio::test]
async fn listen_streams_open_at_token_expiry_leave_one_record() {
    let upstream = SessionUpstream::default();
    let up = spawn_router(upstream.router()).await.unwrap();
    let (clock, authorizer) = short_lived_chain();
    let proxy = proxy_with_clock(&up, authorizer.clone(), clock.clone()).await;
    let first = open_listen_stream(&proxy, "alice").await;
    let second = open_listen_stream(&proxy, "alice").await;

    clock.advance(SHORT_TTL);
    let (a, b) = tokio::join!(
        drain(first, Duration::from_secs(2)),
        drain(second, Duration::from_secs(2))
    );
    let (a, b) = (last_event(&a.0), last_event(&b.0));
    for last in [&a, &b] {
        assert_eq!(last["error"]["data"]["reason"], "token_expired");
    }
    let records: Vec<_> = authorizer
        .decisions()
        .into_iter()
        .filter(|r| r.tool == STREAM_END_TOOL)
        .collect();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].reason, "token_expired");
    assert_eq!(
        authorizer.suppressed_records(),
        vec![(STREAM_END_TOOL.to_owned(), StreamEndCause::TokenExpired)]
    );
    upstream.streams.all_closed().await;
    assert_stream_ends(&authorizer, &[StreamEndCause::TokenExpired; 2]).await;

    for _ in 0..3 {
        let resp = reqwest::Client::new()
            .get(proxy.url(&format!("/mcp/{SERVER}")))
            .bearer_auth("alice")
            .header("accept", "text/event-stream")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"]["data"]["reason"], "token_expired");
        assert!(body["error"]["data"].get("decision_id").is_none());
    }
    assert_eq!(authorizer.decisions().len(), 1);
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
    let proxy = proxy_with(&up, authorizer.clone()).await;
    let mut stream = open_listen_stream(&proxy, "alice").await;

    // Several re-check intervals' worth of events, all upstream notifications. On paused
    // tokio time: the re-check ticks and the upstream's gaps between events are tokio timers,
    // so once every task waits the runtime jumps to the next one, and the eight intervals pass
    // in their real order without being slept through.
    tokio::time::pause();
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
    assert!(authorizer.decisions().is_empty());
}

/// SR-28: a `tools/call` answered over a long-lived SSE stream is re-checked too.
#[tokio::test]
async fn a_revoked_sse_tool_call_response_ends() {
    let streams = Live::default();
    let live = streams.clone();
    let up = spawn_router(Router::new().route(
        "/mcp",
        post(move || async move {
            let open = live.open();
            let events = futures_util::stream::unfold((0u64, open), |(i, open)| async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let event = format!(
                    "event: message\ndata: {}\n\n",
                    json!({"jsonrpc": "2.0", "method": "notifications/progress",
                           "params": {"progressToken": "t", "progress": i}})
                );
                Some((Ok::<_, std::io::Error>(event), (i + 1, open)))
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
    let last = last_event(&text);
    assert_eq!(last["error"]["data"]["reason"], "lease_revoked");
    // The call's own decision, then the end of its answer stream (no session here).
    assert_eq!(authorizer.decisions()[0].tool, "read_slowly");
    assert_stream_end_record(&authorizer, &last, "lease_revoked", None);
    // Not a listen stream: not counted in `proxy_streams_ended_total`, also once its guard
    // is gone.
    streams.all_closed().await;
    assert!(authorizer.stream_ends().is_empty());
}
