//! Regression tests for findings of the 2026-10-22 security review
//! (`docs/research/security-review-2026-10-22.md`).

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use onbehalf_core::{AgentId, Capability, CapabilitySet, LeaseId};
use onbehalf_proxy::jsonrpc::{CODE_DENIED, CODE_INVALID_PARAMS};
use onbehalf_proxy::session::session_tag;
use onbehalf_proxy::testing::{spawn_router, test_chain, Spawned, StaticAuthorizer};
use onbehalf_proxy::{router, ProxyConfig, UpstreamConfig, REASON_SESSION_MISMATCH};
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

/// The session id the [`session_upstream`] assigns.
const UPSTREAM_SESSION: &str = "upstream-session-7f3a";

/// An upstream that assigns [`UPSTREAM_SESSION`] on every POST and accepts GET and DELETE.
fn session_upstream(hits: Arc<Mutex<Vec<String>>>) -> Router {
    let (h1, h2, h3) = (hits.clone(), hits.clone(), hits);
    Router::new().route(
        "/mcp",
        post(move || {
            let hits = h1.clone();
            async move {
                hits.lock().unwrap().push("POST".into());
                let mut r = json_ok();
                r.headers_mut()
                    .insert("mcp-session-id", UPSTREAM_SESSION.parse().unwrap());
                r
            }
        })
        .get(move || {
            let hits = h2.clone();
            async move {
                hits.lock().unwrap().push("GET".into());
                StatusCode::OK
            }
        })
        .delete(move || {
            let hits = h3.clone();
            async move {
                hits.lock().unwrap().push("DELETE".into());
                StatusCode::OK
            }
        }),
    )
}

/// SR-11: `Mcp-Session-Id` was forwarded for any authenticated caller, so a token of another
/// user (or another run of the same user) could use, listen on or end someone else's session.
#[tokio::test]
async fn session_ids_are_bound_to_the_principal() -> anyhow::Result<()> {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let up = spawn_router(session_upstream(hits.clone())).await?;

    let caps = || [Capability::new(SERVER, "read_*")];
    let alice = test_chain("user:alice", "agent:reader", caps());
    let now = time::OffsetDateTime::now_utc();
    // A sub-agent of alice's run: same root lease, so it shares the session.
    let alice_child = alice.extend(
        AgentId::new("agent:helper"),
        CapabilitySet::from_iter(caps()),
        now,
        time::Duration::minutes(10),
        LeaseId::new("lease-helper"),
        8,
    )?;
    // Another run of the same user (another root lease) and another user.
    let alice_other_run = test_chain("user:alice", "agent:other", caps());
    let bob = test_chain("user:bob", "agent:reader2", caps());
    let authorizer = Arc::new(
        StaticAuthorizer::new()
            .with_chain("alice", alice)
            .with_chain("alice-child", alice_child)
            .with_chain("alice-other", alice_other_run)
            .with_chain("bob", bob),
    );
    let config = ProxyConfig::new(
        "127.0.0.1:0".parse()?,
        vec![UpstreamConfig::new(SERVER, up.url("/mcp"))],
    );
    let proxy = spawn_router(router(config, authorizer.clone())).await?;
    let client = reqwest::Client::new();
    let url = proxy.url(&format!("/mcp/{SERVER}"));
    let send = |method: reqwest::Method, bearer: &str, sid: Option<&str>| {
        let mut req = client
            .request(method.clone(), &url)
            .bearer_auth(bearer)
            .header("accept", "application/json, text/event-stream");
        if method == reqwest::Method::POST {
            req = req
                .header("content-type", "application/json")
                .body(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string());
        }
        if let Some(s) = sid {
            req = req.header("mcp-session-id", s);
        }
        req.send()
    };

    // A session id the upstream never assigned through the proxy: 404, start a new session.
    let resp = send(reqwest::Method::POST, "alice", Some("made-up")).await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // alice opens a session; it is bound to her.
    let resp = send(reqwest::Method::POST, "alice", None).await?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["mcp-session-id"], UPSTREAM_SESSION);
    let sid = Some(UPSTREAM_SESSION);
    assert_eq!(
        send(reqwest::Method::POST, "alice", sid).await?.status(),
        200
    );
    assert_eq!(
        send(reqwest::Method::POST, "alice-child", sid)
            .await?
            .status(),
        200,
        "a sub-agent of the same run shares the session"
    );

    // Everyone else is refused on POST, GET (listen stream) and DELETE, and it is recorded.
    let before = hits.lock().unwrap().len();
    let mut rejected = Vec::new();
    for bearer in ["bob", "alice-other"] {
        for method in [
            reqwest::Method::POST,
            reqwest::Method::GET,
            reqwest::Method::DELETE,
        ] {
            let resp = send(method.clone(), bearer, sid).await?;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{bearer} {method}");
            let body: Value = resp.json().await?;
            assert_eq!(body["error"]["code"], CODE_DENIED);
            assert_eq!(body["error"]["data"]["reason"], REASON_SESSION_MISMATCH);
            rejected.push((bearer, method, body["error"]["data"]["decision_id"].clone()));
        }
    }
    assert_eq!(
        hits.lock().unwrap().len(),
        before,
        "nothing reached the upstream"
    );
    let records = authorizer.decisions();
    for (bearer, method, id) in &rejected {
        let r = records
            .iter()
            .find(|r| r.id.to_string() == id.as_str().unwrap())
            .unwrap_or_else(|| panic!("{bearer} {method} not recorded"));
        assert!(!r.decision.is_allow());
        assert_eq!(r.reason, REASON_SESSION_MISMATCH);
        assert_eq!(r.tool, format!("http.{method}"));
        // The record carries a hash prefix of the session id, not the id.
        assert_eq!(
            r.session_id.as_deref(),
            Some(session_tag(UPSTREAM_SESSION).as_str())
        );
    }

    // The upstream assigning alice's session id to bob does not hand it over: the header is
    // dropped from bob's response and the binding stays alice's.
    let resp = send(reqwest::Method::POST, "bob", None).await?;
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("mcp-session-id").is_none());
    assert_eq!(
        send(reqwest::Method::GET, "alice", sid).await?.status(),
        200
    );

    // alice ends the session; afterwards the id is unknown to everyone.
    assert_eq!(
        send(reqwest::Method::DELETE, "alice", sid).await?.status(),
        200
    );
    assert_eq!(
        send(reqwest::Method::POST, "alice", sid).await?.status(),
        StatusCode::NOT_FOUND
    );
    Ok(())
}
