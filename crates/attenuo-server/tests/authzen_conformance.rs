//! AuthZEN conformance fixtures: every `tests/fixtures/authzen/*.json` file is a request (or a
//! short sequence of requests) and the answer the server must give, modelled on the OpenID
//! AuthZEN Authorization API 1.0 shapes. What the server implements, extends and leaves out
//! is in `docs/reference/authzen.md`.
//!
//! Fixture format (one JSON object per file):
//!
//! ```json
//! {
//!   "_note": "which spec section this exercises, and why",
//!   "token": { "capabilities": ["github:*"], "revoke": false },
//!   "steps": [
//!     {
//!       "method": "POST",
//!       "path": "/access/v1/evaluation",
//!       "auth": "bearer",
//!       "headers": { "x-request-id": "abc" },
//!       "grant_previous_approval": false,
//!       "body": { "subject": { "type": "agent", "id": "" }, "...": "..." },
//!       "raw_body": "only instead of body: sent as is, as application/json",
//!       "expect": { "status": 200, "headers": { "x-request-id": "abc" }, "body": { } }
//!     }
//!   ]
//! }
//! ```
//!
//! - `token` (optional): a root token is minted for `alice`, agent `planner`, through the dev
//!   root-mint route, with these capabilities (default `["github:*"]`); `revoke` revokes its
//!   lease before the first step. Each fixture gets its own run, so budgets and approvals do
//!   not leak between fixtures.
//! - `auth`: `"bearer"` (default: the fixture's token), `"none"`, or any other string, sent
//!   verbatim as the `Authorization` header.
//! - `grant_previous_approval`: before this step, grant (as an operator) the approval named by
//!   the previous answer's `context.approval_id`; the string `"$approval_token"` anywhere in
//!   this step's body is then replaced by the grant's approval token.
//! - The answer is normalised before it is compared, so only values that are random or depend
//!   on the clock are tolerated: `decision_id`, `approval_id`, `call_hash`, `expires_at` and
//!   `approval.id` become `"<decision_id>"`, `"<approval_id>"`, ... and the server's base URL
//!   inside a string becomes `<base>`. Everything else, `decision` and `context.reason` above
//!   all, is compared exactly, and a member the fixture does not list is a failure. The
//!   expected value `"<any>"` accepts any value that is present (used for free-text error
//!   details).

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::{AppState, Config};
use reqwest::StatusCode;
use serde_json::{json, Map, Value};

const ADMIN: &str = "authzen-conformance-admin";

/// The policy every fixture runs against. The ids are what fixtures expect in
/// `context.policy_ids`.
const POLICY: &str = r#"
@id("public_reads")
permit(principal, action == Action::"github/read_file", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };

@id("issues")
permit(principal, action == Action::"github/create_issue", resource);

@id("quarantined_sessions")
forbid(principal, action, resource)
when { context has session_id && context.session_id == "quarantined" };

@id("deletes")
permit(principal, action == Action::"github/delete_repo", resource);

@id("confirm_deletes")
@obligation("approval")
forbid(principal, action == Action::"github/delete_repo", resource)
when { !context.approval.present };

@id("payments")
permit(principal, action == Action::"github/pay", resource);
"#;

struct Harness {
    server: Spawned,
    _state: Arc<AppState>,
    client: reqwest::Client,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policies.cedar");
        std::fs::write(&policy_path, POLICY).unwrap();
        let mut cfg = Config::default();
        cfg.issuer.issuer = "https://attenuo.test".into();
        cfg.issuer.audience = "attenuo-test".into();
        cfg.issuer.private_key_pem_path = Some(dir.path().join("keys/issuer.pem"));
        cfg.policy.policies_path = Some(policy_path);
        let repo = || ToolAttrs::new().with_input("repo", ArgType::String);
        cfg.policy.catalog = BTreeMap::from([(
            "github".to_string(),
            BTreeMap::from([
                ("read_file".to_string(), repo().readonly(true)),
                ("create_issue".to_string(), repo()),
                ("delete_repo".to_string(), repo()),
                (
                    "pay".to_string(),
                    ToolAttrs::new()
                        .with_input("recipient", ArgType::String)
                        .with_input("amount", ArgType::Long),
                ),
            ]),
        )]);
        cfg.audit.sqlite_path = dir.path().join("audit.db").to_string_lossy().into_owned();
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        Self {
            server: spawn_router(router).await.unwrap(),
            _state: state,
            client: reqwest::Client::new(),
            _dir: dir,
        }
    }

    fn base(&self) -> String {
        self.server.url("")
    }

    async fn admin_post(&self, path: &str, body: Value) -> Value {
        let resp = self
            .client
            .post(self.server.url(path))
            .bearer_auth(ADMIN)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        assert_eq!(status, StatusCode::OK, "POST {path}: {v}");
        v
    }

    /// A root token for alice and agent `planner`, as `token` in the fixture asks.
    async fn mint(&self, spec: &Value) -> String {
        let caps = spec
            .get("capabilities")
            .cloned()
            .unwrap_or_else(|| json!(["github:*"]));
        let v = self
            .admin_post(
                "/admin/root-token",
                json!({"subject": "alice", "issuer": "https://idp.example",
                       "agent": "planner", "capabilities": caps}),
            )
            .await;
        if spec.get("revoke").and_then(Value::as_bool) == Some(true) {
            let lease = v["lease"].as_str().unwrap();
            self.admin_post(
                &format!("/admin/leases/{lease}/revoke"),
                json!({"reason": "conformance fixture"}),
            )
            .await;
        }
        v["access_token"].as_str().unwrap().to_string()
    }
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/authzen")
}

fn fixtures() -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = std::fs::read_dir(fixture_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&p).unwrap();
            let v: Value =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: not JSON: {e}"));
            (name, v)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Replace values that are random or clock-dependent with fixed placeholders.
fn normalise(v: &mut Value, base: &str) {
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                let placeholder = match k.as_str() {
                    "decision_id" | "approval_id" | "call_hash" | "expires_at" => {
                        Some(format!("<{k}>"))
                    }
                    _ => None,
                };
                match placeholder {
                    Some(p) if val.is_string() => *val = Value::String(p),
                    _ => normalise(val, base),
                }
            }
            // `context.approval.id` is the approval's id.
            if map.contains_key("by") && map.get("id").is_some_and(Value::is_string) {
                map.insert("id".into(), json!("<approval_id>"));
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|i| normalise(i, base)),
        Value::String(s) if s.contains(base) => *s = s.replace(base, "<base>"),
        _ => {}
    }
}

/// Exact comparison, except that the expected string `"<any>"` accepts any present value.
/// Returns the path of the first difference.
fn matches(expected: &Value, actual: &Value, path: &str) -> Result<(), String> {
    match (expected, actual) {
        (Value::String(s), _) if s == "<any>" => Ok(()),
        (Value::Object(e), Value::Object(a)) => {
            for k in e.keys().chain(a.keys()) {
                let p = format!("{path}.{k}");
                match (e.get(k), a.get(k)) {
                    (Some(ev), Some(av)) => matches(ev, av, &p)?,
                    (Some(_), None) => return Err(format!("{p}: missing from the answer")),
                    (None, Some(av)) => return Err(format!("{p}: not expected, got {av}")),
                    (None, None) => unreachable!(),
                }
            }
            Ok(())
        }
        (Value::Array(e), Value::Array(a)) => {
            if e.len() != a.len() {
                return Err(format!("{path}: {} entries, expected {}", a.len(), e.len()));
            }
            for (i, (ev, av)) in e.iter().zip(a).enumerate() {
                matches(ev, av, &format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        _ if expected == actual => Ok(()),
        _ => Err(format!("{path}: expected {expected}, got {actual}")),
    }
}

fn substitute(v: &mut Value, vars: &Map<String, Value>) {
    match v {
        Value::String(s) if s.starts_with('$') => {
            if let Some(val) = vars.get(&s[1..]) {
                *v = val.clone();
            }
        }
        Value::Object(map) => map.values_mut().for_each(|x| substitute(x, vars)),
        Value::Array(items) => items.iter_mut().for_each(|x| substitute(x, vars)),
        _ => {}
    }
}

async fn run_fixture(h: &Harness, name: &str, fx: &Value) -> Result<(), String> {
    let note = fx.get("_note").and_then(Value::as_str).unwrap_or_default();
    if note.trim().is_empty() {
        return Err("no `_note` naming the spec section it exercises".into());
    }
    let token = match fx.get("token") {
        Some(spec) => Some(h.mint(spec).await),
        None => None,
    };
    let steps = fx["steps"].as_array().ok_or("`steps` must be an array")?;
    if steps.is_empty() {
        return Err("`steps` is empty".into());
    }
    let mut vars = Map::new();
    let mut previous: Option<Value> = None;
    for (i, step) in steps.iter().enumerate() {
        let at = format!("{name} step {i}");
        if step.get("grant_previous_approval").and_then(Value::as_bool) == Some(true) {
            let id = previous
                .as_ref()
                .and_then(|p| p["context"]["approval_id"].as_str())
                .ok_or_else(|| format!("{at}: the previous answer has no approval_id"))?
                .to_string();
            let granted = h
                .admin_post(
                    &format!("/admin/approvals/{id}"),
                    json!({"decision": "grant"}),
                )
                .await;
            let t = granted["approval_token"]
                .as_str()
                .ok_or_else(|| format!("{at}: the grant carried no approval_token: {granted}"))?;
            vars.insert("approval_token".into(), json!(t));
        }

        let method = step.get("method").and_then(Value::as_str).unwrap_or("POST");
        let path = step["path"].as_str().ok_or(format!("{at}: no path"))?;
        let url = h.server.url(path);
        let mut req = match method {
            "GET" => h.client.get(&url),
            "POST" => h.client.post(&url),
            m => return Err(format!("{at}: unsupported method {m}")),
        };
        match step.get("auth").and_then(Value::as_str).unwrap_or("bearer") {
            "bearer" => {
                let t = token
                    .as_deref()
                    .ok_or_else(|| format!("{at}: auth bearer needs a `token` block"))?;
                req = req.bearer_auth(t);
            }
            "none" => {}
            raw => req = req.header("authorization", raw),
        }
        if let Some(hs) = step.get("headers").and_then(Value::as_object) {
            for (k, v) in hs {
                req = req.header(k.as_str(), v.as_str().unwrap_or_default());
            }
        }
        if let Some(raw) = step.get("raw_body").and_then(Value::as_str) {
            req = req
                .header("content-type", "application/json")
                .body(raw.to_string());
        } else if let Some(body) = step.get("body") {
            let mut body = body.clone();
            substitute(&mut body, &vars);
            req = req.json(&body);
        }
        let resp = req.send().await.map_err(|e| format!("{at}: {e}"))?;

        let expect = &step["expect"];
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let text = resp.text().await.unwrap_or_default();
        let mut body: Value = serde_json::from_str(&text)
            .map_err(|e| format!("{at}: answer is not JSON ({e}): {text}"))?;
        let want_status = expect["status"]
            .as_u64()
            .ok_or(format!("{at}: no status"))?;
        if u64::from(status) != want_status {
            return Err(format!(
                "{at}: status {status}, expected {want_status}: {body}"
            ));
        }
        if let Some(hs) = expect.get("headers").and_then(Value::as_object) {
            for (k, v) in hs {
                let got = headers.get(k.as_str()).and_then(|x| x.to_str().ok());
                match (v, got) {
                    (Value::Null, None) => {}
                    (Value::Null, Some(g)) => {
                        return Err(format!("{at}: header {k} should be absent, got {g:?}"))
                    }
                    (Value::String(w), Some(g)) if w == g => {}
                    (w, g) => return Err(format!("{at}: header {k}: expected {w}, got {g:?}")),
                }
            }
        }
        previous = Some(body.clone());
        normalise(&mut body, &h.base());
        let want = expect
            .get("body")
            .ok_or(format!("{at}: no expected body"))?;
        matches(want, &body, "$").map_err(|e| format!("{at}: {e}\n  answer: {body}"))?;
    }
    Ok(())
}

/// Every fixture in the directory, in name order, against one server. Failures are collected
/// so one run names them all.
#[tokio::test]
async fn authzen_fixtures_conform() {
    let h = Harness::start().await;
    let all = fixtures();
    assert!(
        all.len() >= 20,
        "expected the full fixture set, found {}",
        all.len()
    );
    let mut failures = Vec::new();
    for (name, fx) in &all {
        if let Err(e) = run_fixture(&h, name, fx).await {
            failures.push(e);
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} fixtures failed:\n{}",
        failures.len(),
        all.len(),
        failures.join("\n")
    );
}

/// The comparator and normaliser themselves: a fixture suite that accepts anything proves
/// nothing.
#[test]
fn comparator_is_exact_where_it_should_be() {
    let exp = json!({"decision": false, "context": {"reason": "policy_deny", "detail": "<any>"}});
    assert!(matches(
        &exp,
        &json!({"decision": false, "context": {"reason": "policy_deny", "detail": "x"}}),
        "$"
    )
    .is_ok());
    // A different decision, a different reason, an extra member and a missing member fail.
    for bad in [
        json!({"decision": true, "context": {"reason": "policy_deny", "detail": "x"}}),
        json!({"decision": false, "context": {"reason": "policy_allow", "detail": "x"}}),
        json!({"decision": false, "context": {"reason": "policy_deny", "detail": "x", "more": 1}}),
        json!({"decision": false, "context": {"reason": "policy_deny"}}),
    ] {
        assert!(matches(&exp, &bad, "$").is_err(), "{bad}");
    }
    let mut v = json!({"context": {"decision_id": "0193-abc", "approval": {"id": "a1", "by": "operator"},
                                   "url": "http://127.0.0.1:1/x"}});
    normalise(&mut v, "http://127.0.0.1:1");
    assert_eq!(
        v,
        json!({"context": {"decision_id": "<decision_id>",
                           "approval": {"id": "<approval_id>", "by": "operator"},
                           "url": "<base>/x"}})
    );
}

/// A batch stopped by `deny_on_first_deny` or `permit_on_first_permit` (AuthZEN 1.0 section
/// 7.1.2.1) audits exactly the entries it decided: one record per answered entry, with the
/// answer's `decision_id`, and none for the entries after the stop.
#[tokio::test]
async fn stopped_batch_audits_only_what_it_ran() {
    let h = Harness::start().await;
    let token = h.mint(&json!({})).await;
    let entry = |repo: &str, session: &str| json!({"context": {"input": {"repo": repo}, "session_id": session}});
    let cases = [
        (
            "deny_on_first_deny",
            [
                entry("alice/public-a", "dofd-1"),
                entry("alice/private-b", "dofd-2"),
                entry("alice/public-c", "dofd-3"),
            ],
            vec![("dofd-1", "allow"), ("dofd-2", "deny")],
        ),
        (
            "permit_on_first_permit",
            [
                entry("alice/private-b", "pofp-1"),
                entry("alice/public-a", "pofp-2"),
                entry("alice/private-d", "pofp-3"),
            ],
            vec![("pofp-1", "deny"), ("pofp-2", "allow")],
        ),
    ];
    for (semantic, entries, want) in cases {
        let body = json!({
            "subject": {"type": "agent", "id": ""},
            "action": {"name": "read_file"},
            "resource": {"type": "tool", "id": "github/read_file", "properties": {"server": "github"}},
            "options": {"evaluations_semantic": semantic},
            "evaluations": entries,
        });
        let resp = h
            .client
            .post(h.server.url("/access/v1/evaluations"))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{semantic}");
        let answer: Value = resp.json().await.unwrap();
        let answered = answer["evaluations"].as_array().unwrap();
        assert_eq!(answered.len(), want.len(), "{semantic}: {answer}");

        let listing = h
            .client
            .get(h.server.url("/admin/audit?from=1&limit=1000"))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        let prefix = &want[0].0[..5];
        let records: Vec<&Value> = listing["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| &e["record"])
            .filter(|r| {
                r["session_id"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(prefix))
            })
            .collect();
        let got: Vec<(&str, &str)> = records
            .iter()
            .map(|r| {
                (
                    r["session_id"].as_str().unwrap(),
                    r["decision"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(got, want, "{semantic}: records {records:?}");
        for (r, a) in records.iter().zip(answered) {
            assert_eq!(r["id"], a["context"]["decision_id"], "{semantic}");
            assert_eq!(r["tool"], "read_file");
        }
    }
}
