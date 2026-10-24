//! Cost of the list filter on the `GET` listen stream (`docs/design/bench/
//! 2026-10-24-vm-listen-stream-filter.md`). Not a check: both tests are `#[ignore]`d and print
//! numbers. Run them on a release build, one at a time:
//!
//! ```text
//! cargo test --release -p attenuo-proxy --test listen_stream_cost -- --ignored --nocapture --test-threads 1
//! ```
//!
//! `stage` times the SSE stage alone: [`SseFramer`] (relay byte for byte, the `GET` path before
//! the list filter) against [`SseRewriter`] with the same filter closure the proxy installs,
//! one event per chunk. `end_to_end` sends a `GET` through the real proxy to an upstream that
//! writes `N` events and closes, and times the client reading all of them.

use std::sync::Arc;
use std::time::{Duration, Instant};

use attenuo_core::{Capability, CapabilitySet};
use attenuo_proxy::filter::{list_kinds_by_shape, ListFilter};
use attenuo_proxy::sse::{SseFramer, SseRewriter};
use attenuo_proxy::testing::{spawn_router, test_chain, StaticAuthorizer};
use attenuo_proxy::{router, ProxyConfig, UpstreamConfig};
use axum::body::Bytes;
use axum::response::IntoResponse;
use futures_util::StreamExt;
use serde_json::{json, Value};

const SERVER: &str = "github";
const TOKEN: &str = "tok";

/// A progress notification, the most frequent event on a listen stream (about 150 bytes).
fn small_event(n: usize) -> String {
    let msg = json!({"jsonrpc": "2.0", "method": "notifications/progress",
        "params": {"progressToken": format!("call-{n}"), "progress": n % 100, "total": 100,
                   "message": "indexing repository"}});
    format!("id: {n}\nevent: message\ndata: {msg}\n\n")
}

/// A replayed `tools/list` answer with 200 tools, each with a description and a small input
/// schema (about 70 KB).
fn large_event(n: usize) -> String {
    let tools: Vec<Value> = (0..200)
        .map(|i| {
            json!({"name": format!("tool_{i:03}"),
                "description": format!("Tool number {i}: reads or writes one kind of object in the repository and returns it as JSON."),
                "inputSchema": {"type": "object",
                    "properties": {"owner": {"type": "string", "description": "Repository owner"},
                                   "repo": {"type": "string", "description": "Repository name"},
                                   "path": {"type": "string", "description": "Path inside the repository"}},
                    "required": ["owner", "repo"]},
                "annotations": {"readOnlyHint": i % 2 == 0}})
        })
        .collect();
    let msg = json!({"jsonrpc": "2.0", "id": n, "result": {"tools": tools}});
    format!("id: {n}\nevent: message\ndata: {msg}\n\n")
}

/// A `tools/call` answer of the same size and shape that is not a list (its objects sit under
/// `structuredContent`), as an upstream may send on the listen stream after a `202`.
fn large_result_event(n: usize) -> String {
    let tools = large_event(n);
    let data = tools
        .strip_prefix(&format!("id: {n}\nevent: message\ndata: "))
        .unwrap()
        .trim_end();
    let list: Value = serde_json::from_str(data).unwrap();
    let msg = json!({"jsonrpc": "2.0", "id": n,
        "result": {"content": [], "structuredContent": {"items": list["result"]["tools"]}}});
    format!("id: {n}\nevent: message\ndata: {msg}\n\n")
}

/// The chain's capabilities keep half of the 200 tools (`tool_0*` is `tool_000`..`tool_099`).
fn caps() -> Vec<Capability> {
    vec![Capability::new(SERVER, "tool_0*")]
}

/// The proxy's listen-stream filter closure, rebuilt from the public API (`listen_list_filter`
/// in `proxy.rs`, without the SR-25 bookkeeping of listed tools).
fn listen_filter(caps: CapabilitySet) -> impl FnMut(&mut Value) {
    move |body: &mut Value| {
        let messages: Vec<&mut Value> = match body {
            Value::Array(items) => items.iter_mut().collect(),
            other => vec![other],
        };
        for msg in messages {
            let pending = list_kinds_by_shape(msg);
            if pending.is_empty() {
                continue;
            }
            ListFilter::new(&pending, &caps, SERVER).apply_message(msg);
        }
    }
}

fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    xs[xs.len() / 2]
}

/// Nanoseconds per event, median of `runs`, for `push` over `events` (one chunk each).
fn time_per_event(events: &[String], runs: usize, mut push: impl FnMut(&[u8]) -> usize) -> f64 {
    let samples = (0..runs)
        .map(|_| {
            let start = Instant::now();
            let mut out = 0;
            for e in events {
                out += push(e.as_bytes());
            }
            assert!(out > 0);
            start.elapsed().as_nanos() as f64 / events.len() as f64
        })
        .collect();
    median(samples)
}

#[test]
#[ignore = "measurement; run on a release build with --ignored --nocapture"]
fn stage() {
    let caps = CapabilitySet::from_iter(caps());
    for (name, events, runs) in [
        (
            "small",
            (0..20_000).map(small_event).collect::<Vec<_>>(),
            15,
        ),
        ("large", (0..200).map(large_event).collect::<Vec<_>>(), 15),
        (
            "large_result",
            (0..200).map(large_result_event).collect::<Vec<_>>(),
            15,
        ),
    ] {
        let bytes = events[0].len();
        let mut framer = SseFramer::with_limit(16 << 20);
        let relay = time_per_event(&events, runs, |c| framer.push(c).unwrap().len());
        let mut rewriter = SseRewriter::with_limit(16 << 20);
        let mut f = listen_filter(caps.clone());
        let rewrite = time_per_event(&events, runs, |c| rewriter.push(c, &mut f).unwrap().len());
        println!(
            "stage {name}: event {bytes} B, relay {:.2} us, filter {:.2} us, added {:.2} us/event",
            relay / 1e3,
            rewrite / 1e3,
            (rewrite - relay) / 1e3
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement; run on a release build with --ignored --nocapture"]
async fn end_to_end() -> anyhow::Result<()> {
    for (name, count, runs) in [
        ("small", 20_000usize, 9),
        ("large", 300, 9),
        ("large_result", 300, 9),
    ] {
        let make = match name {
            "small" => small_event,
            "large" => large_event,
            _ => large_result_event,
        };
        let events: Arc<Vec<Bytes>> = Arc::new((0..count).map(|n| Bytes::from(make(n))).collect());
        let upstream = {
            let events = events.clone();
            axum::Router::new().route(
                "/mcp",
                axum::routing::get(move || {
                    let events = events.clone();
                    async move {
                        let body = futures_util::stream::iter(
                            (0..events.len())
                                .map(move |i| Ok::<_, std::io::Error>(events[i].clone())),
                        );
                        (
                            [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                            axum::body::Body::from_stream(body),
                        )
                            .into_response()
                    }
                }),
            )
        };
        let up = spawn_router(upstream).await?;
        let chain = test_chain("user:a", "agent:a", caps());
        let authorizer = Arc::new(StaticAuthorizer::new().with_chain(TOKEN, chain));
        let config = ProxyConfig::new(
            "127.0.0.1:0".parse()?,
            vec![UpstreamConfig::new(SERVER, up.url("/mcp"))],
        );
        let proxy = spawn_router(router(config, authorizer)).await?;
        let client = reqwest::Client::new();
        let mut samples = Vec::new();
        let mut reads = Vec::new();
        for run in 0..runs + 1 {
            let start = Instant::now();
            let resp = client
                .get(proxy.url(&format!("/mcp/{SERVER}")))
                .header("accept", "text/event-stream")
                .bearer_auth(TOKEN)
                .send()
                .await?;
            assert_eq!(resp.status(), 200);
            let mut stream = resp.bytes_stream();
            let mut seen = 0usize;
            let mut chunks = 0usize;
            let mut tail = 0u8;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                chunks += 1;
                // Count event ends ("\n\n"), across chunk boundaries.
                for &b in chunk.iter() {
                    if b == b'\n' && tail == b'\n' {
                        seen += 1;
                    }
                    tail = b;
                }
            }
            assert_eq!(seen, count, "{name}: events relayed");
            // The first run warms the connection pool and is dropped.
            if run > 0 {
                samples.push(start.elapsed());
                reads.push(chunks as f64);
            }
        }
        let per = median(
            samples
                .iter()
                .map(|d: &Duration| d.as_nanos() as f64 / count as f64)
                .collect(),
        );
        println!(
            "end_to_end {name}: {count} events of {} B, {:.2} us/event, {:.0} events/s, \
             {:.0} client reads (median of {runs})",
            events[0].len(),
            per / 1e3,
            1e9 / per,
            median(reads)
        );
    }
    Ok(())
}
