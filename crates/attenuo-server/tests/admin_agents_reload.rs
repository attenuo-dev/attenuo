//! `POST /admin/agents/reload`: `[[agents]]` and `[[peps]]` re-read from the config file the
//! server was started with, checked as at startup and swapped in at once. An added agent can
//! exchange at once, a removed one cannot (its earlier token works until its lease is
//! revoked), a rotated secret or key is refused in its old form and accepted in its new one,
//! a PEP comes and goes, a file that fails a startup rule changes nothing, exchanges keep
//! working during repeated reloads, the route needs the admin role, and the audit record names
//! ids, never a digest or a key. Sections other than the two lists are not applied; the answer
//! names them.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::operators::token_sha256_hex;
use attenuo_server::{AppState, Config};
use attenuo_token::client_assertion::{self, CLIENT_ASSERTION_TYPE};
use attenuo_token::DpopKey;
use reqwest::StatusCode;
use serde_json::{json, Value};

use common::sha256_hex;

const LEGACY: &str = "legacy-admin-token-0123456789abcdef";
/// `[issuer] issuer`: the `aud` of a client assertion.
const ISSUER: &str = "https://attenuo.test";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// One `[[agents]]` entry with the digest of `secret`.
fn agent(id: &str, secret: &str) -> String {
    format!(
        "[[agents]]\nid = \"{id}\"\nsecret_sha256 = \"{}\"\n",
        sha256_hex(secret)
    )
}

/// One `[[agents]]` entry with the public half of `key` as its only key, kid `kid`.
fn agent_with_key(id: &str, key: &DpopKey, kid: &str) -> String {
    let mut jwk = key.public_jwk().clone();
    jwk["kid"] = kid.into();
    let jwks = json!({"keys": [jwk]}).to_string();
    format!("[[agents]]\nid = \"{id}\"\njwks = '''{jwks}'''\n")
}

/// One `[[peps]]` entry with the digest of `secret`.
fn pep(id: &str, secret: &str) -> String {
    format!(
        "[[peps]]\nid = \"{id}\"\nsecret_sha256 = \"{}\"\n",
        sha256_hex(secret)
    )
}

/// Write `<dir>/attenuo.toml`: the fixed sections (`[admin] token`, a viewer and an operator,
/// the dev root mint, unsigned AuthZEN chains), then `extra` sections, then `lists` (the
/// `[[agents]]` and `[[peps]]` entries). Replaced in one rename, so a reload never reads half
/// of it.
fn write_config(dir: &Path, extra: &str, lists: &str) -> PathBuf {
    write_config_with_token(dir, LEGACY, extra, lists)
}

fn write_config_with_token(dir: &Path, token: &str, extra: &str, lists: &str) -> PathBuf {
    let path = dir.join("attenuo.toml");
    let tmp = dir.join("attenuo.toml.tmp");
    let op = |name: &str, role: &str| {
        format!(
            "[[admin.operators]]\nname = \"{name}\"\ntoken_sha256 = \"{}\"\nrole = \"{role}\"\n",
            token_sha256_hex(&format!("{name}-token"))
        )
    };
    std::fs::write(
        &tmp,
        format!(
            "[issuer]\nissuer = \"{ISSUER}\"\nprivate_key_pem_path = \"{}\"\n\n\
             [audit]\nsqlite_path = \"{}\"\n\n\
             [admin]\ntoken = \"{token}\"\n\n{}{}\n\
             [dev]\nallow_root_mint = true\n\n\
             [authzen]\nallow_unsigned_chain = true\n\n{extra}\n{lists}",
            dir.join("keys/issuer.pem").display(),
            dir.join("audit.sqlite").display(),
            op("vera", "viewer"),
            op("bob", "operator"),
        ),
    )
    .unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    path
}

struct Harness {
    server: Spawned,
    state: Arc<AppState>,
    client: reqwest::Client,
    path: PathBuf,
}

impl Harness {
    /// A server started from the config file at `path`, as `attenuo-server --config` does.
    async fn start(path: PathBuf) -> Self {
        let cfg = Config::load(&path).unwrap();
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        Self {
            server: spawn_router(router).await.unwrap(),
            state,
            client: reqwest::Client::new(),
            path,
        }
    }

    fn url(&self, path: &str) -> String {
        self.server.url(path)
    }

    async fn reload_as(&self, bearer: &str) -> (StatusCode, Value) {
        let resp = self
            .client
            .post(self.url("/admin/agents/reload"))
            .bearer_auth(bearer)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn reload(&self) -> Value {
        let (status, v) = self.reload_as(LEGACY).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        v
    }

    /// A root token for `planner` from the dev mint: (token, lease).
    async fn root(&self) -> (String, String) {
        root(&self.client, &self.url("")).await
    }

    /// Exchange a fresh root token for a child for `actor`, which authenticates with `auth`
    /// (body fields: a secret or an assertion).
    async fn exchange(&self, actor: &str, auth: Value) -> (StatusCode, Value) {
        exchange(&self.client, &self.url(""), actor, auth).await
    }

    async fn audit(&self) -> Vec<Value> {
        let v: Value = self
            .client
            .get(self.url("/admin/audit?from=1&limit=1000"))
            .bearer_auth(LEGACY)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["record"].clone())
            .collect()
    }

    /// An AuthZEN evaluation with `bearer`, from the PEP `pep_id` authenticating with
    /// `pep_secret` in the body: the status.
    async fn evaluate_as_pep(&self, bearer: &str, pep_id: &str, pep_secret: &str) -> StatusCode {
        self.client
            .post(self.url("/access/v1/evaluation"))
            .bearer_auth(bearer)
            .json(&json!({
                "subject": {"type": "agent", "id": ""},
                "action": {"name": "read_file"},
                "resource": {"type": "tool", "id": "github/read_file",
                             "properties": {"server": "github"}},
                "context": {"input": {}},
                "pep_id": pep_id,
                "pep_secret": pep_secret,
            }))
            .send()
            .await
            .unwrap()
            .status()
    }
}

async fn root(client: &reqwest::Client, base: &str) -> (String, String) {
    let resp = client
        .post(format!("{base}/admin/root-token"))
        .bearer_auth(LEGACY)
        .json(
            &json!({"subject": "alice", "issuer": "https://idp.test", "agent": "planner",
                      "capabilities": ["github:*"]}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    (
        v["access_token"].as_str().unwrap().into(),
        v["lease"].as_str().unwrap().into(),
    )
}

async fn exchange(
    client: &reqwest::Client,
    base: &str,
    actor: &str,
    auth: Value,
) -> (StatusCode, Value) {
    let (parent, _) = root(client, base).await;
    let mut body = json!({
        "grant_type": EXCHANGE, "subject_token": parent, "subject_token_type": JWT,
        "actor": actor,
        "authorization_details": [{"type": "attenuo_capabilities",
            "capabilities": [{"server": "github", "tool": "read_file"}]}],
    });
    for (k, v) in auth.as_object().unwrap() {
        body[k] = v.clone();
    }
    let resp = client
        .post(format!("{base}/token"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

fn secret(id: &str, secret: &str) -> Value {
    json!({"client_id": id, "client_secret": secret})
}

fn assertion(key: &DpopKey, kid: &str, client: &str) -> Value {
    let a = client_assertion::sign(
        key,
        Some(kid),
        client,
        ISSUER,
        client_assertion::DEFAULT_LIFETIME,
        time::OffsetDateTime::now_utc(),
    );
    json!({"client_assertion_type": CLIENT_ASSERTION_TYPE, "client_assertion": a})
}

fn description(v: &Value) -> &str {
    v["error_description"].as_str().unwrap_or_default()
}

/// The part of a reload's answer for one list.
fn list(count: usize, added: &[&str], removed: &[&str], changed: &[&str]) -> Value {
    json!({"count": count, "added": added, "removed": removed, "changed": changed})
}

/// Add an agent, remove one, rotate a secret, in one reload: the answer names each by id
/// and no digest, the next requests see the new lists, and a token issued to the removed
/// agent keeps working until its lease is revoked.
#[tokio::test]
async fn a_reload_adds_removes_and_rotates_agents() {
    let dir = tempfile::tempdir().unwrap();
    let before = agent("planner", "planner-secret")
        + &agent("coder", "coder-secret")
        + &agent("reviewer", "reviewer-secret")
        + &pep("gw1", "gw1-secret");
    let h = Harness::start(write_config(dir.path(), "", &before)).await;
    assert_eq!(
        h.exchange("tester", secret("tester", "tester-secret"))
            .await
            .0,
        StatusCode::UNAUTHORIZED,
        "not configured yet"
    );
    let (status, issued) = h.exchange("coder", secret("coder", "coder-secret")).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let coder_token = issued["access_token"].as_str().unwrap().to_string();

    // coder removed, reviewer's secret rotated, tester added; planner and gw1 unchanged.
    let after = agent("planner", "planner-secret")
        + &agent("reviewer", "reviewer-secret-2")
        + &agent("tester", "tester-secret")
        + &pep("gw1", "gw1-secret");
    write_config(dir.path(), "", &after);
    let v = h.reload().await;
    assert_eq!(v["agents"], list(3, &["tester"], &["coder"], &["reviewer"]));
    assert_eq!(v["peps"], list(1, &[], &[], &[]));
    assert_eq!(v["restart_needed"], json!([]), "{v}");
    assert_eq!(v["warnings"], json!([]), "{v}");
    assert!(v["audit_id"].is_string(), "{v}");
    for s in ["coder-secret", "reviewer-secret-2", "tester-secret"] {
        assert!(!v.to_string().contains(&sha256_hex(s)), "{v}");
    }

    // The added agent exchanges at once.
    let (status, v) = h
        .exchange("tester", secret("tester", "tester-secret"))
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // The removed one is refused as an unknown client.
    let (status, v) = h.exchange("coder", secret("coder", "coder-secret")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(v["error"], "invalid_client");
    assert_eq!(description(&v), "client_authentication_failed");
    // The old secret is refused, the new one accepted.
    let (status, v) = h
        .exchange("reviewer", secret("reviewer", "reviewer-secret"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(description(&v), "client_authentication_failed");
    let (status, v) = h
        .exchange("reviewer", secret("reviewer", "reviewer-secret-2"))
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // The token issued to coder before the reload is not revoked by it: it still renews...
    let renew = || {
        h.client
            .post(h.url("/token/renew"))
            .bearer_auth(&coder_token)
            .json(&json!({}))
            .send()
    };
    let resp = renew().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let lease = resp.json::<Value>().await.unwrap()["lease"]
        .as_str()
        .unwrap()
        .to_string();
    // ...until its lease is revoked.
    let resp = h
        .client
        .post(h.url(&format!("/admin/leases/{lease}/revoke")))
        .bearer_auth(LEGACY)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = renew().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(resp.json::<Value>().await.unwrap()["code"], "lease_revoked");

    // The same file again changes nothing.
    let v = h.reload().await;
    assert_eq!(v["agents"], list(3, &[], &[], &[]));
}

/// A `private_key_jwt` agent's key is rotated: an assertion signed with the old key is
/// refused after the reload, one signed with the new key accepted. The new entry is reported
/// as changed.
#[tokio::test]
async fn a_reload_rotates_a_client_key() {
    let dir = tempfile::tempdir().unwrap();
    let old = DpopKey::generate().unwrap();
    let new = DpopKey::generate().unwrap();
    let lists = |key: &DpopKey, kid: &str| {
        agent("planner", "planner-secret") + &agent_with_key("signer", key, kid) + &pep("gw1", "s")
    };
    let h = Harness::start(write_config(dir.path(), "", &lists(&old, "k1"))).await;
    let (status, v) = h.exchange("signer", assertion(&old, "k1", "signer")).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, _) = h.exchange("signer", assertion(&new, "k2", "signer")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    write_config(dir.path(), "", &lists(&new, "k2"));
    let v = h.reload().await;
    assert_eq!(v["agents"], list(2, &[], &[], &["signer"]));
    let old_jwk = old.public_jwk()["x"].as_str().unwrap().to_string();
    assert!(!v.to_string().contains(&old_jwk), "{v}");

    let (status, v) = h.exchange("signer", assertion(&old, "k1", "signer")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(description(&v), "client_authentication_failed");
    let (status, v) = h.exchange("signer", assertion(&new, "k2", "signer")).await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

/// A PEP added by a reload authenticates at once; one removed is refused.
#[tokio::test]
async fn a_reload_adds_and_removes_a_pep() {
    let dir = tempfile::tempdir().unwrap();
    let base = agent("planner", "planner-secret");
    let h = Harness::start(write_config(
        dir.path(),
        "",
        &(base.clone() + &pep("gw1", "gw1-secret") + &pep("gw2", "gw2-secret")),
    ))
    .await;
    let (token, _) = h.root().await;
    assert_eq!(
        h.evaluate_as_pep(&token, "gw2", "gw2-secret").await,
        StatusCode::OK
    );
    assert_eq!(
        h.evaluate_as_pep(&token, "gw3", "gw3-secret").await,
        StatusCode::UNAUTHORIZED
    );

    write_config(
        dir.path(),
        "",
        &(base + &pep("gw1", "gw1-secret") + &pep("gw3", "gw3-secret")),
    );
    let v = h.reload().await;
    assert_eq!(v["agents"], list(1, &[], &[], &[]));
    assert_eq!(v["peps"], list(2, &["gw3"], &["gw2"], &[]));
    assert_eq!(
        h.evaluate_as_pep(&token, "gw3", "gw3-secret").await,
        StatusCode::OK
    );
    assert_eq!(
        h.evaluate_as_pep(&token, "gw2", "gw2-secret").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.evaluate_as_pep(&token, "gw1", "gw1-secret").await,
        StatusCode::OK
    );
}

/// A file that does not parse, or whose lists break a startup rule, is refused with the
/// startup message and changes nothing; the message never quotes the file.
#[tokio::test]
async fn an_invalid_file_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let ok = agent("planner", "planner-secret") + &agent("coder", "coder-secret");
    let h = Harness::start(write_config(
        dir.path(),
        "",
        &(ok.clone() + &pep("gw1", "gw1-secret")),
    ))
    .await;
    for (lists, want) in [
        ("[[agents]\n".to_string(), "not valid TOML (line"),
        (
            ok.clone() + "[[agents]]\nid = \"x\"\nsecret = \"plain\"\n" + &pep("gw1", "s"),
            "unknown field `secret`",
        ),
        (
            ok.clone() + &agent("planner", "other") + &pep("gw1", "s"),
            "[[agents]]: id `planner` is listed twice",
        ),
        (
            ok.clone() + "[[agents]]\nid = \"weak\"\nsecret_sha256 = \"abc\"\n" + &pep("gw1", "s"),
            "[[agents]] `weak`: secret_sha256 must be 64 hex characters",
        ),
        (
            ok.clone() + "[[agents]]\nid = \"empty\"\n" + &pep("gw1", "s"),
            "[[agents]] `empty`: set secret_sha256, jwks (private_key_jwt), or both",
        ),
        (
            ok.clone() + &agent("attenuo", "x") + &pep("gw1", "s"),
            "[[agents]]: agent id `attenuo` is reserved",
        ),
        (
            ok.clone() + "[[agents]]\nid = \"k\"\njwks = '{\"keys\": []}'\n" + &pep("gw1", "s"),
            "[[agents]] `k`: jwks",
        ),
        (ok.clone() + &pep("", "s"), "[[peps]]: id must not be empty"),
        // `[authzen] allow_unsigned_chain = true` (in force) needs a PEP.
        (
            ok.clone(),
            "[authzen] allow_unsigned_chain = true needs at least one [[peps]] entry",
        ),
    ] {
        write_config(dir.path(), "", &lists);
        let (status, v) = h.reload_as(LEGACY).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{lists}: {v}");
        assert_eq!(v["code"], "agents_invalid", "{v}");
        let detail = v["detail"].as_str().unwrap();
        assert!(detail.contains(want), "{want}: {detail}");
        assert!(
            detail.ends_with("the agents and peps in force are unchanged"),
            "{detail}"
        );
        assert!(!detail.contains(LEGACY), "{detail}");
        // Nothing changed.
        let (status, v) = h.exchange("coder", secret("coder", "coder-secret")).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        let (token, _) = h.root().await;
        assert_eq!(
            h.evaluate_as_pep(&token, "gw1", "gw1-secret").await,
            StatusCode::OK
        );
    }
    // Each refusal is audited as a deny with the code as its reason.
    let denies = h
        .audit()
        .await
        .into_iter()
        .filter(|r| r["tool"] == "admin.agents.reload")
        .collect::<Vec<_>>();
    assert_eq!(denies.len(), 9);
    for r in &denies {
        assert_eq!(r["decision"], "deny", "{r}");
        assert_eq!(r["reason"], "agents_invalid", "{r}");
    }
    // A file that is gone: 500 with its own code, the path in the log only.
    std::fs::remove_file(&h.path).unwrap();
    let (status, v) = h.reload_as(LEGACY).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    assert_eq!(v["code"], "config_unreadable");
    assert!(!v.to_string().contains("attenuo.toml"), "{v}");
}

/// Only the two lists are reloaded: a section that differs from the one in force is named in
/// `restart_needed` and not applied, `[[admin.operators]]` (which has its own reload) is not
/// named, and the startup warnings the new lists raise are answered.
#[tokio::test]
async fn other_sections_are_named_not_applied() {
    let dir = tempfile::tempdir().unwrap();
    let lists = agent("planner", "planner-secret") + &pep("gw1", "gw1-secret");
    let h = Harness::start(write_config(dir.path(), "", &lists)).await;
    let grants = "[[root_grants]]\nissuer = \"https://idp.test\"\nagent = \"planner\"\n\
                  capabilities = [\"github:read_file\"]\n\n\
                  [server]\nlisten = \"127.0.0.1:9999\"\n\n\
                  [[idps]]\nissuer = \"https://idp.test\"\njwks_url = \"http://127.0.0.1:9/jwks\"\n";
    write_config_with_token(
        dir.path(),
        "another-legacy-token-0123456789abcdef",
        grants,
        &(lists.clone() + &agent("tester", "tester-secret")),
    );
    let v = h.reload().await;
    assert_eq!(v["agents"], list(2, &["tester"], &[], &[]));
    assert_eq!(
        v["restart_needed"],
        json!(["[[idps]]", "[[root_grants]]", "[admin]", "[server]"]),
        "{v}"
    );
    // Checked against the `[[idps]]` in force (none), so no IdP warning.
    assert_eq!(v["warnings"], json!([]), "{v}");
    // Neither the grants, the IdP nor the token were applied.
    assert!(h.state.root_grants.is_empty());
    assert!(h.state.idps.is_empty());
    let whoami = |t: &'static str| h.client.get(h.url("/admin/whoami")).bearer_auth(t).send();
    assert_eq!(whoami(LEGACY).await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        whoami("another-legacy-token-0123456789abcdef")
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // Only the operators differ: nothing to restart for.
    std::fs::write(
        &h.path,
        std::fs::read_to_string(&h.path)
            .unwrap()
            .replace("another-legacy-token-0123456789abcdef", LEGACY)
            .replace(grants, "")
            .replace("role = \"viewer\"", "role = \"admin\""),
    )
    .unwrap();
    let v = h.reload().await;
    assert_eq!(v["restart_needed"], json!([]), "{v}");
}

/// The reload is recorded once, as an admin action of the caller, with the counts and ids
/// (whose digest the record keeps), and nothing of a secret or a key.
#[tokio::test]
async fn a_reload_is_audited_with_ids_only() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(write_config(
        dir.path(),
        "",
        &(agent("planner", "planner-secret") + &agent("coder", "c1") + &pep("gw1", "g1")),
    ))
    .await;
    let key = DpopKey::generate().unwrap();
    write_config(
        dir.path(),
        "",
        &(agent("planner", "planner-secret")
            + &agent("coder", "c2")
            + &agent_with_key("signer", &key, "k1")
            + &pep("gw2", "g2")),
    );
    let v = h.reload().await;
    let records: Vec<Value> = h
        .audit()
        .await
        .into_iter()
        .filter(|r| r["tool"] == "admin.agents.reload")
        .collect();
    assert_eq!(records.len(), 1, "{records:?}");
    let r = &records[0];
    assert_eq!(r["id"], v["audit_id"]);
    assert_eq!(r["originating_subject"], "urn:attenuo:admin");
    assert_eq!(r["decision"], "allow");
    assert_eq!(r["server"], "attenuo");
    let args = json!({
        "path": h.path,
        "agents": list(3, &["signer"], &[], &["coder"]),
        "peps": list(1, &["gw2"], &["gw1"], &[]),
        "restart_needed": [],
    });
    let want = attenuo_core::ToolCall::new("attenuo", "admin.agents.reload", args);
    assert_eq!(r["arguments_digest"], want.arguments_digest());
    let text = r.to_string();
    for s in ["c1", "c2", "g1", "g2", "planner-secret"] {
        assert!(!text.contains(&sha256_hex(s)), "{text}");
    }
    assert!(
        !text.contains(key.public_jwk()["x"].as_str().unwrap()),
        "{text}"
    );
    // The operators reload's record is not this one.
    assert!(records
        .iter()
        .all(|r| r["tool"] != "admin.operators.reload"));
}

/// A viewer and an operator are refused for their role; a server whose config was not read
/// from a file has nothing to reload.
#[tokio::test]
async fn a_reload_needs_the_admin_role_and_a_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(write_config(
        dir.path(),
        "",
        &(agent("planner", "planner-secret") + &pep("gw1", "g1")),
    ))
    .await;
    write_config(
        dir.path(),
        "",
        &(agent("planner", "planner-secret") + &agent("x", "x") + &pep("gw1", "g1")),
    );
    for token in ["vera-token", "bob-token"] {
        let (status, v) = h.reload_as(token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
        assert_eq!(v["code"], "admin_role_insufficient");
        assert!(v["detail"].as_str().unwrap().contains("`admin`"), "{v}");
    }
    // Nothing was reloaded by the refused calls.
    let (status, _) = h.exchange("x", secret("x", "x")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let other = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.issuer.private_key_pem_path = Some(other.path().join("issuer.pem"));
    cfg.audit.sqlite_path = ":memory:".into();
    cfg.admin.token = Some(LEGACY.into());
    assert_eq!(cfg.source_path, None);
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let resp = reqwest::Client::new()
        .post(server.url("/admin/agents/reload"))
        .bearer_auth(LEGACY)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["code"],
        "reload_unavailable"
    );
}

/// On the console listener the route is served exactly where the operators reload is: with
/// `[admin_ui] allow_write = true`, and not without it.
#[tokio::test]
async fn the_console_serves_the_reload_with_allow_write_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        "",
        &(agent("planner", "planner-secret") + &pep("gw1", "g1")),
    );
    for allow_write in [false, true] {
        let mut cfg = Config::load(&path).unwrap();
        cfg.admin_ui.allow_write = allow_write;
        // A database of its own: the first server still holds the file's.
        cfg.audit.sqlite_path = dir
            .path()
            .join(format!("console-{allow_write}.sqlite"))
            .to_string_lossy()
            .into_owned();
        let (_router, state) = attenuo_server::build(&cfg).unwrap();
        let console = spawn_router(attenuo_server::admin_ui::router(state, &cfg))
            .await
            .unwrap();
        for route in ["/admin/agents/reload", "/admin/operators/reload"] {
            let resp = reqwest::Client::new()
                .post(console.url(route))
                .bearer_auth(LEGACY)
                .json(&json!({}))
                .send()
                .await
                .unwrap();
            let want = if allow_write {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            };
            assert_eq!(
                resp.status(),
                want,
                "{route} with allow_write = {allow_write}"
            );
        }
    }
}

/// Exchanges keep being answered while reloads swap the lists: an agent present in every
/// version never fails, and one that comes and goes is either accepted or refused as an
/// unknown client, never anything else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exchanges_during_reloads_never_fail_for_an_agent_in_both_lists() {
    let dir = tempfile::tempdir().unwrap();
    let with = agent("planner", "planner-secret")
        + &agent("stable", "stable-secret")
        + &agent("flaky", "flaky-secret")
        + &pep("gw1", "g1");
    let without =
        agent("planner", "planner-secret") + &agent("stable", "stable-secret") + &pep("gw1", "g1");
    let h = Harness::start(write_config(dir.path(), "", &with)).await;
    let base = h.url("");

    let mut workers = Vec::new();
    for i in 0..6 {
        let (client, base) = (h.client.clone(), base.clone());
        workers.push(tokio::spawn(async move {
            for _ in 0..15 {
                let (status, v) =
                    exchange(&client, &base, "stable", secret("stable", "stable-secret")).await;
                assert_eq!(status, StatusCode::OK, "worker {i}: {v}");
                let (status, v) =
                    exchange(&client, &base, "flaky", secret("flaky", "flaky-secret")).await;
                match status {
                    StatusCode::OK => {}
                    StatusCode::UNAUTHORIZED => {
                        assert_eq!(description(&v), "client_authentication_failed", "{v}");
                    }
                    other => panic!("worker {i}: {other} {v}"),
                }
            }
        }));
    }
    let reloads = async {
        for n in 0..30 {
            write_config(dir.path(), "", if n % 2 == 0 { &without } else { &with });
            let v = h.reload().await;
            assert_eq!(v["agents"]["count"], if n % 2 == 0 { 2 } else { 3 });
        }
    };
    let joined = async {
        for w in workers {
            w.await.unwrap();
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(120), async {
        tokio::join!(reloads, joined)
    })
    .await
    .expect("exchanges or reloads did not finish");
}
