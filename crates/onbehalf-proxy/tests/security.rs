//! Regression tests for findings of the 2026-10-22 security review
//! (`docs/research/security-review-2026-10-22.md`).

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use onbehalf_core::Capability;
use onbehalf_proxy::jsonrpc::CODE_INVALID_PARAMS;
use onbehalf_proxy::testing::{spawn_router, test_chain, Spawned, StaticAuthorizer};
use onbehalf_proxy::{router, ProxyConfig, UpstreamConfig};
use serde_json::{json, Value};

const SERVER: &str = "github";

/// An upstream that records the raw bytes of every POST and answers with `reply`.
#[derive(Clone, Default)]
struct RawUpstream {
    bodies: Arc<Mutex<Vec<Bytes>>>,
}

impl RawUpstream {
    fn bodies(&self) -> Vec<String> {
        self.bodies
            .lock()
            .unwrap()
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect()
    }

    fn router(&self, reply: fn() -> axum::response::Response) -> Router {
        let me = self.clone();
        Router::new().route(
            "/mcp",
            post(move |body: Bytes| {
                let me = me.clone();
                async move {
                    me.bodies.lock().unwrap().push(body);
                    reply()
                }
            }),
        )
    }
}

fn json_ok() -> axum::response::Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json!({"jsonrpc": "2.0", "id": 1, "result": {}}).to_string(),
    )
        .into_response()
}

async fn proxy_for(upstream_url: String) -> anyhow::Result<Spawned> {
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain(
        "tok",
        test_chain(
            "user:alice",
            "agent:reader",
            [Capability::new(SERVER, "read_*")],
        ),
    ));
    let config = ProxyConfig::new(
        "127.0.0.1:0".parse()?,
        vec![UpstreamConfig::new(SERVER, upstream_url)],
    );
    spawn_router(router(config, authorizer)).await
}

async fn post_raw(proxy: &Spawned, body: &str) -> anyhow::Result<reqwest::Response> {
    Ok(reqwest::Client::new()
        .post(proxy.url(&format!("/mcp/{SERVER}")))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .bearer_auth("tok")
        .body(body.to_owned())
        .send()
        .await?)
}

/// SR-01: a single message used to be forwarded byte-for-byte after being screened from a
/// serde_json parse (last duplicate member wins). A first-wins upstream parser would then see
/// a different method or tool than the one that was authorized.
#[tokio::test]
async fn duplicate_member_names_cannot_smuggle_a_different_call_upstream() -> anyhow::Result<()> {
    let upstream = RawUpstream::default();
    let up = spawn_router(upstream.router(json_ok)).await?;
    let proxy = proxy_for(up.url("/mcp")).await?;

    // serde_json sees `ping` (never screened); a first-wins parser sees `tools/call`.
    let smuggle_method = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo","arguments":{}},"method":"ping"}"#;
    // serde_json authorizes `read_file`; a first-wins parser calls `delete_repo`.
    let smuggle_name = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repo","arguments":{},"name":"read_file"}}"#;
    for body in [smuggle_method, smuggle_name] {
        let resp = post_raw(&proxy, body).await?;
        assert_eq!(resp.status(), 200);
    }

    let seen = upstream.bodies();
    assert_eq!(seen.len(), 2);
    for raw in &seen {
        // What reached the upstream is exactly one encoding of what was screened.
        let parsed: Value = serde_json::from_str(raw)?;
        assert_eq!(raw, &serde_json::to_string(&parsed)?);
        assert_eq!(raw.matches("\"method\"").count(), 1, "{raw}");
        assert_eq!(raw.matches("\"name\"").count(), 1, "{raw}");
    }
    assert_eq!(serde_json::from_str::<Value>(&seen[0])?["method"], "ping");
    assert_eq!(
        serde_json::from_str::<Value>(&seen[1])?["params"]["name"],
        "read_file"
    );
    Ok(())
}

/// SR-02: the upstream is untrusted; its redirects must not be followed by the proxy.
#[tokio::test]
async fn upstream_redirects_are_not_followed() -> anyhow::Result<()> {
    let internal = RawUpstream::default();
    let internal_task = spawn_router(internal.router(json_ok)).await?;
    let target = internal_task.url("/mcp");

    let redirecting = Router::new().route(
        "/mcp",
        post(move || {
            let target = target.clone();
            async move {
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(header::LOCATION, target)],
                    "",
                )
                    .into_response()
            }
        }),
    );
    let up = spawn_router(redirecting).await?;
    let proxy = proxy_for(up.url("/mcp")).await?;

    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "read_file", "arguments": {"path": "x"}}});
    let resp = post_raw(&proxy, &body.to_string()).await?;
    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(resp.headers().get(header::LOCATION).is_none());
    assert!(
        internal.bodies().is_empty(),
        "the authorized call was replayed to the redirect target"
    );
    Ok(())
}

/// SR-03: non-object `arguments` were authorized as "no arguments" but forwarded as-is.
#[tokio::test]
async fn non_object_arguments_are_rejected() -> anyhow::Result<()> {
    let upstream = RawUpstream::default();
    let up = spawn_router(upstream.router(json_ok)).await?;
    let proxy = proxy_for(up.url("/mcp")).await?;

    for args in [json!(["acme/x"]), json!("acme/x"), json!(7)] {
        let body = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                          "params": {"name": "read_file", "arguments": args}});
        let resp: Value = post_raw(&proxy, &body.to_string()).await?.json().await?;
        assert_eq!(resp["error"]["code"], CODE_INVALID_PARAMS, "{resp}");
        assert_eq!(resp["id"], 9);
    }
    // null and absent still mean "no arguments"
    for params in [
        json!({"name": "read_file", "arguments": null}),
        json!({"name": "read_file"}),
    ] {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params});
        let resp: Value = post_raw(&proxy, &body.to_string()).await?.json().await?;
        assert!(resp.get("error").is_none(), "{resp}");
    }
    assert_eq!(upstream.bodies().len(), 2);
    Ok(())
}
