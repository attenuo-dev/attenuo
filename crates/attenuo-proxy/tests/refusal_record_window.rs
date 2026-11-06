//! SR-81 (security review pass 7, `docs/research/security-review-2026-10-25-pass7.md`): a
//! record window opens only on a record that was written. A failed audit append for a bounded
//! refusal must not suppress the repeats that follow it. Formerly `security_pass7_sr81.rs`.

use std::sync::Arc;

use attenuo_core::Capability;
use attenuo_proxy::jsonrpc::CODE_UNAUTHORIZED;
use attenuo_proxy::testing::{spawn_router, test_chain, FakeMcpServer, StaticAuthorizer};
use attenuo_proxy::{router, ProxyConfig, UpstreamConfig, DECISION_ID_HEADER};
use serde_json::{json, Value};

const BEARER: &str = "t";

/// `initialize` on the revoked lease: refused with 401 and `lease_revoked`. Returns the
/// decision id the refusal names, if any (header and body agree).
async fn refused_initialize(client: &reqwest::Client, url: &str, id: u64) -> Option<String> {
    let resp = client
        .post(url)
        .bearer_auth(BEARER)
        .header("accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc": "2.0", "id": id, "method": "initialize",
                      "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "t", "version": "0"}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let header = resp
        .headers()
        .get(DECISION_ID_HEADER)
        .map(|h| h.to_str().unwrap().to_owned());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], CODE_UNAUTHORIZED);
    assert_eq!(body["error"]["data"]["reason"], "lease_revoked", "{body}");
    assert_eq!(
        body["error"]["data"]["decision_id"]
            .as_str()
            .map(str::to_owned),
        header,
        "{body}"
    );
    header
}

/// With appends failing, two refusals of one chain, tool and reason in one window each try to
/// record (nothing is suppressed behind the record that was not written) and name no decision
/// id. With appends succeeding again, the next refusal is recorded and the one after it is
/// suppressed behind it, as before.
#[tokio::test]
async fn a_failed_append_opens_no_record_window_sr81() {
    let upstream = FakeMcpServer::new(&["read_file"]);
    let upstream_task = upstream.spawn().await.unwrap();
    let chain = test_chain("user:a", "agent:a", [Capability::new("s", "*")]);
    let authorizer = Arc::new(StaticAuthorizer::new().with_chain(BEARER, chain));
    let config = ProxyConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        vec![UpstreamConfig::new("s", upstream_task.url("/mcp"))],
    );
    let proxy = spawn_router(router(config, authorizer.clone()))
        .await
        .unwrap();
    let client = reqwest::Client::new();
    let url = proxy.url("/mcp/s");
    authorizer.revoke(BEARER);

    authorizer.fail_rejections(true);
    let named = [
        refused_initialize(&client, &url, 1).await,
        refused_initialize(&client, &url, 2).await,
    ];
    assert_eq!(
        authorizer.rejection_attempts(),
        2,
        "the second refusal was suppressed behind a record that was never written"
    );
    // A refusal whose record was not written names no decision id.
    assert_eq!(named, [None, None]);
    assert!(authorizer.decisions().is_empty());
    assert!(authorizer.suppressed_records().is_empty());

    authorizer.fail_rejections(false);
    let first = refused_initialize(&client, &url, 3).await;
    let records = authorizer.decisions();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].tool, "initialize");
    assert_eq!(records[0].reason, "lease_revoked");
    assert_eq!(first, Some(records[0].id.to_string()));
    assert_eq!(refused_initialize(&client, &url, 4).await, first);
    assert_eq!(authorizer.rejection_attempts(), 3);
    assert_eq!(authorizer.decisions().len(), 1);
    assert_eq!(authorizer.suppressed_records().len(), 1);
}
