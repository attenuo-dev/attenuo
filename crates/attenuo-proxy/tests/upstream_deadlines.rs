//! Upstream deadlines (audit A-3): the proxy waits a bounded time for an upstream to connect
//! and to answer, so a hung upstream answers the agent with a reason code instead of holding
//! the request (and a task) open without end. A stream that has started is never cut by the
//! deadline: it governs the wait for response headers and for bodies the proxy buffers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use attenuo_core::Capability;
use attenuo_proxy::testing::{spawn_router, test_chain, Spawned, StaticAuthorizer};
use attenuo_proxy::{
    router, ProxyConfig, UpstreamConfig, REASON_UPSTREAM_TIMEOUT, REASON_UPSTREAM_UNREACHABLE,
};
use axum::body::{Body, Bytes};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use futures_util::StreamExt;
use serde_json::{json, Value};

const SERVER: &str = "github";

/// The response deadline of these tests: short, so the tests are quick, and far below the
/// delays the slow upstreams use.
const DEADLINE: Duration = Duration::from_millis(300);

/// Longer than [`DEADLINE`]: how late the slow upstreams are.
const LATE: Duration = Duration::from_millis(900);

async fn proxy_for(upstream_url: String) -> Spawned {
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain(
        "tok",
        test_chain(
            "user:alice",
            "agent:reader",
            [Capability::new(SERVER, "read_*")],
        ),
    ));
    let config = ProxyConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        vec![UpstreamConfig::new(SERVER, upstream_url)],
    )
    .with_upstream_timeouts(Duration::from_secs(5), DEADLINE);
    spawn_router(router(config, authorizer)).await.unwrap()
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap()
}

async fn post_list(proxy: &Spawned) -> reqwest::Response {
    client()
        .post(proxy.url(&format!("/mcp/{SERVER}")))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .bearer_auth("tok")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#)
        .send()
        .await
        .unwrap()
}

async fn get_listen(proxy: &Spawned) -> reqwest::Response {
    client()
        .get(proxy.url(&format!("/mcp/{SERVER}")))
        .header("accept", "text/event-stream")
        .bearer_auth("tok")
        .send()
        .await
        .unwrap()
}

async fn reason_of(resp: reqwest::Response) -> String {
    let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    body["error"]["data"]["reason"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn tools_list_result() -> String {
    json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "read_file"}]}}).to_string()
}

/// An upstream that accepts connections and never sends a byte: `504 upstream_timeout` at
/// the deadline, for a `POST` and for the `GET` listen stream.
#[tokio::test]
async fn an_upstream_that_never_answers_times_out() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let silent = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    let proxy = proxy_for(format!("http://{addr}/mcp")).await;

    let started = Instant::now();
    let resp = post_list(&proxy).await;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(reason_of(resp).await, REASON_UPSTREAM_TIMEOUT);
    let waited = started.elapsed();
    assert!(
        waited >= DEADLINE && waited < Duration::from_secs(10),
        "{waited:?}"
    );

    let resp = get_listen(&proxy).await;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(reason_of(resp).await, REASON_UPSTREAM_TIMEOUT);
    silent.abort();
}

/// Nothing listening is still `502 upstream_unreachable`: a refused connection is not a
/// timeout, and nothing was sent.
#[tokio::test]
async fn a_refused_connection_is_still_unreachable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let proxy = proxy_for(format!("http://{addr}/mcp")).await;
    let resp = post_list(&proxy).await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(reason_of(resp).await, REASON_UPSTREAM_UNREACHABLE);
}

/// An upstream that accepts the request but sends its headers after the deadline: `504`.
/// The same upstream answering in time is relayed as usual.
#[tokio::test]
async fn headers_after_the_deadline_time_out() {
    let delay = Arc::new(std::sync::Mutex::new(LATE));
    let d = delay.clone();
    let up = spawn_router(Router::new().route(
        "/mcp",
        post(move || {
            let wait = *d.lock().unwrap();
            async move {
                tokio::time::sleep(wait).await;
                Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(tools_list_result()))
                    .unwrap()
            }
        }),
    ))
    .await
    .unwrap();
    let proxy = proxy_for(up.url("/mcp")).await;

    let resp = post_list(&proxy).await;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(reason_of(resp).await, REASON_UPSTREAM_TIMEOUT);

    *delay.lock().unwrap() = Duration::ZERO;
    let resp = post_list(&proxy).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["result"]["tools"][0]["name"], "read_file");
}

/// Headers in time, but a JSON body the proxy must buffer (to filter the list) that is not
/// complete by the deadline: `504` as well, since the proxy cannot answer without it.
#[tokio::test]
async fn a_buffered_body_after_the_deadline_times_out() {
    let up = spawn_router(Router::new().route(
        "/mcp",
        post(|| async {
            let body = futures_util::stream::once(async {
                tokio::time::sleep(LATE).await;
                Ok::<_, std::io::Error>(Bytes::from(tools_list_result()))
            });
            Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from_stream(body))
                .unwrap()
        }),
    ))
    .await
    .unwrap();
    let proxy = proxy_for(up.url("/mcp")).await;
    let resp = post_list(&proxy).await;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(reason_of(resp).await, REASON_UPSTREAM_TIMEOUT);
}

/// An SSE body whose events keep coming after the deadline (`LATE` apart, three times the
/// deadline in all): the headers were in time, so neither the `POST` answer stream nor the
/// `GET` listen stream is cut.
#[tokio::test]
async fn streams_outlive_the_deadline() {
    fn slow_events(last: String) -> Body {
        let events = futures_util::stream::unfold(0u8, move |i| {
            let last = last.clone();
            async move {
                match i {
                    0 => Some((
                        Ok::<_, std::io::Error>(Bytes::from_static(b": open\n\n")),
                        1,
                    )),
                    1..=2 => {
                        tokio::time::sleep(LATE).await;
                        let ev = if i == 2 {
                            format!("event: message\ndata: {last}\n\n")
                        } else {
                            ": still here\n\n".to_owned()
                        };
                        Some((Ok(Bytes::from(ev)), i + 1))
                    }
                    _ => None,
                }
            }
        });
        Body::from_stream(events)
    }
    let up = spawn_router(
        Router::new().route(
            "/mcp",
            post(|| async {
                Response::builder()
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(slow_events(tools_list_result()))
                    .unwrap()
            })
            .get(|| async {
                let note = json!({"jsonrpc": "2.0", "method": "notifications/message",
                    "params": {"level": "info", "data": "late"}})
                .to_string();
                Response::builder()
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(slow_events(note))
                    .unwrap()
            }),
        ),
    )
    .await
    .unwrap();
    let proxy = proxy_for(up.url("/mcp")).await;

    let started = Instant::now();
    let resp = post_list(&proxy).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let text = collect(resp).await;
    assert!(text.contains("read_file"), "{text}");
    assert!(started.elapsed() >= 2 * LATE, "{:?}", started.elapsed());

    let started = Instant::now();
    let resp = get_listen(&proxy).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let text = collect(resp).await;
    assert!(text.contains("notifications/message"), "{text}");
    assert!(started.elapsed() >= 2 * LATE, "{:?}", started.elapsed());
}

/// The whole body of a streamed response, as text.
async fn collect(resp: reqwest::Response) -> String {
    let mut out = Vec::new();
    let mut body = resp.bytes_stream();
    while let Some(chunk) = body.next().await {
        out.extend_from_slice(&chunk.unwrap());
    }
    String::from_utf8_lossy(&out).into_owned()
}
