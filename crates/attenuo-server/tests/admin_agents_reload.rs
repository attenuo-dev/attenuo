//! `POST /admin/agents/reload`: `[[agents]]` and `[[peps]]` re-read from the config file the
//! server was started with, checked as at startup and swapped in at once. An added agent can
//! exchange at once, a removed one cannot (its earlier token works until its lease is
//! revoked), a rotated secret or key is refused in its old form and accepted in its new one,
//! a PEP comes and goes, a file that fails a startup rule changes nothing, exchanges keep
//! working during repeated reloads, the route needs the admin role, and the audit record holds
//! ids and a digest of each list, never a secret's digest or a key. Sections other than the
//! two lists are not applied; the answer names them. A file that empties a list or looks like
//! another server's is refused unless asked for, and the file's own settings are checked too.

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
    write_file(dir, &File::default(), extra, lists)
}

fn write_config_with_token(dir: &Path, token: &str, extra: &str, lists: &str) -> PathBuf {
    let file = File {
        token: Some(token.to_string()),
        ..File::default()
    };
    write_file(dir, &file, extra, lists)
}

/// What [`write_file`] varies in the fixed sections.
struct File {
    /// `[admin] token`; default [`LEGACY`].
    token: Option<String>,
    /// `[issuer] issuer`; default [`ISSUER`].
    issuer: &'static str,
    /// `[authzen] allow_unsigned_chain`; default `true`.
    unsigned: bool,
}

impl Default for File {
    fn default() -> Self {
        Self {
            token: None,
            issuer: ISSUER,
            unsigned: true,
        }
    }
}

fn write_file(dir: &Path, file: &File, extra: &str, lists: &str) -> PathBuf {
    let token = file.token.as_deref().unwrap_or(LEGACY);
    let (issuer, unsigned) = (file.issuer, file.unsigned);
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
            "[issuer]\nissuer = \"{issuer}\"\nprivate_key_pem_path = \"{}\"\n\n\
             [audit]\nsqlite_path = \"{}\"\n\n\
             [admin]\ntoken = \"{token}\"\n\n{}{}\n\
             [dev]\nallow_root_mint = true\n\n\
             [authzen]\nallow_unsigned_chain = {unsigned}\n\n{extra}\n{lists}",
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
        self.reload_with(bearer, json!({})).await
    }

    async fn reload_with(&self, bearer: &str, body: Value) -> (StatusCode, Value) {
        let resp = self
            .client
            .post(self.url("/admin/agents/reload"))
            .bearer_auth(bearer)
            .json(&body)
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

/// One list's part of a reload's answer without its `sha256`.
fn strip(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(o) = v.as_object_mut() {
        assert!(o
            .remove("sha256")
            .is_some_and(|d| d.as_str().is_some_and(|d| d.len() == 64)));
    }
    v
}

/// The part of a reload's answer for one list, without its `sha256`.
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
    assert_eq!(
        strip(&v["agents"]),
        list(3, &["tester"], &["coder"], &["reviewer"])
    );
    assert_eq!(strip(&v["peps"]), list(1, &[], &[], &[]));
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
    assert_eq!(strip(&v["agents"]), list(3, &[], &[], &[]));
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
    assert_eq!(strip(&v["agents"]), list(2, &[], &[], &["signer"]));
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
    assert_eq!(strip(&v["agents"]), list(1, &[], &[], &[]));
    assert_eq!(strip(&v["peps"]), list(2, &["gw3"], &["gw2"], &[]));
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
            "key `secret` in [[agents]]): unknown field",
        ),
        // A value of the wrong type, and an unknown variant: named by key, never repeated.
        (
            "[limits]\nmax_in_flight = \"hunter2-s3cret-value\"\n".to_string()
                + &ok
                + &pep("gw1", "s"),
            "key `max_in_flight` in [limits]): invalid type: string",
        ),
        (
            "[token]\nactor_auth = \"hunter2-variant-value\"\n".to_string()
                + &ok
                + &pep("gw1", "s"),
            "key `actor_auth` in [token]): unknown variant `…`, expected one of",
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
        // The last case leaves `[[peps]]` empty, which is refused on its own unless allowed.
        let (status, v) = h.reload_with(LEGACY, json!({"allow_empty": true})).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{lists}: {v}");
        assert_eq!(v["code"], "agents_invalid", "{v}");
        let detail = v["detail"].as_str().unwrap();
        assert!(detail.contains(want), "{want}: {detail}");
        assert!(
            detail.ends_with("the agents and peps in force are unchanged"),
            "{detail}"
        );
        assert!(!detail.contains(LEGACY), "{detail}");
        assert!(!detail.contains("hunter2"), "{detail}");
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
    assert_eq!(denies.len(), 11);
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
    assert_eq!(strip(&v["agents"]), list(2, &["tester"], &[], &[]));
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
    // Each list's digest is the SHA-256 of its canonical form: `[id, secret digest or null,
    // sorted key thumbprints]` per entry, sorted by id, as compact JSON.
    let canonical = |rows: Value| sha256_hex(&rows.to_string());
    let agents_sha256 = canonical(json!([
        ["coder", sha256_hex("c2"), []],
        ["planner", sha256_hex("planner-secret"), []],
        ["signer", null, [key.thumbprint()]],
    ]));
    let peps_sha256 = canonical(json!([["gw2", sha256_hex("g2"), []]]));
    assert_eq!(v["agents"]["sha256"], agents_sha256, "{v}");
    assert_eq!(v["peps"]["sha256"], peps_sha256, "{v}");
    let with = |mut l: Value, d: &str| {
        l["sha256"] = d.into();
        l
    };
    let args = json!({
        "path": h.path,
        "agents": with(list(3, &["signer"], &[], &["coder"]), &agents_sha256),
        "peps": with(list(1, &["gw2"], &["gw1"], &[]), &peps_sha256),
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
    for allow_write in [false, true] {
        // A directory of its own each time: the first server still holds its database.
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            dir.path(),
            "",
            &(agent("planner", "planner-secret") + &pep("gw1", "g1")),
        );
        let mut cfg = Config::load(&path).unwrap();
        cfg.admin_ui.allow_write = allow_write;
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
/// unknown client, never anything else. The reloads go on until the flipping agent has been
/// both accepted and refused while they ran, so the exchanges did overlap them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exchanges_during_reloads_never_fail_for_an_agent_in_both_lists() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let dir = tempfile::tempdir().unwrap();
    let with = agent("planner", "planner-secret")
        + &agent("stable", "stable-secret")
        + &agent("flaky", "flaky-secret")
        + &pep("gw1", "g1");
    let without =
        agent("planner", "planner-secret") + &agent("stable", "stable-secret") + &pep("gw1", "g1");
    let h = Harness::start(write_config(dir.path(), "", &with)).await;
    let base = h.url("");
    let done = Arc::new(AtomicBool::new(false));
    let accepted = Arc::new(AtomicUsize::new(0));
    let refused = Arc::new(AtomicUsize::new(0));
    let stable_ok = Arc::new(AtomicUsize::new(0));

    let mut workers = Vec::new();
    for i in 0..6 {
        let (client, base) = (h.client.clone(), base.clone());
        let (done, accepted, refused, stable_ok) = (
            done.clone(),
            accepted.clone(),
            refused.clone(),
            stable_ok.clone(),
        );
        workers.push(tokio::spawn(async move {
            while !done.load(Ordering::SeqCst) {
                let (status, v) =
                    exchange(&client, &base, "stable", secret("stable", "stable-secret")).await;
                assert_eq!(status, StatusCode::OK, "worker {i}: {v}");
                stable_ok.fetch_add(1, Ordering::SeqCst);
                let (status, v) =
                    exchange(&client, &base, "flaky", secret("flaky", "flaky-secret")).await;
                match status {
                    StatusCode::OK => {
                        accepted.fetch_add(1, Ordering::SeqCst);
                    }
                    StatusCode::UNAUTHORIZED => {
                        assert_eq!(description(&v), "client_authentication_failed", "{v}");
                        refused.fetch_add(1, Ordering::SeqCst);
                    }
                    other => panic!("worker {i}: {other} {v}"),
                }
            }
        }));
    }
    let reloads = async {
        let mut n = 0;
        // At least 30 reloads, and on until both outcomes were seen (at most 2000).
        while n < 30
            || (n < 2000
                && (accepted.load(Ordering::SeqCst) == 0 || refused.load(Ordering::SeqCst) == 0))
        {
            write_config(dir.path(), "", if n % 2 == 0 { &without } else { &with });
            let v = h.reload().await;
            assert_eq!(v["agents"]["count"], if n % 2 == 0 { 2 } else { 3 });
            n += 1;
            tokio::task::yield_now().await;
        }
        done.store(true, Ordering::SeqCst);
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
    let (accepted, refused) = (
        accepted.load(Ordering::SeqCst),
        refused.load(Ordering::SeqCst),
    );
    assert!(
        accepted > 0 && refused > 0,
        "accepted {accepted}, refused {refused}"
    );
    assert!(stable_ok.load(Ordering::SeqCst) > 0);
}

/// A fake IdP that publishes one ES256 key through OIDC discovery and signs ID tokens with it.
struct Idp {
    issuer: String,
    encoding: jsonwebtoken::EncodingKey,
    _server: Spawned,
}

impl Idp {
    async fn start() -> Self {
        use axum::routing::get;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let point = pair.public_key().as_ref().to_vec();
        let jwk = json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "ec1",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..]),
        });
        let cell = Arc::new(std::sync::OnceLock::<String>::new());
        let read = cell.clone();
        let app = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let iss = read.get().cloned().unwrap_or_default();
                    async move {
                        axum::Json(json!({ "issuer": iss, "jwks_uri": format!("{iss}/jwks") }))
                    }
                }),
            )
            .route(
                "/jwks",
                get(move || {
                    let jwk = jwk.clone();
                    async move { axum::Json(json!({ "keys": [jwk] })) }
                }),
            );
        let server = spawn_router(app).await.unwrap();
        let issuer = server.url("").trim_end_matches('/').to_string();
        cell.set(issuer.clone()).unwrap();
        Self {
            issuer,
            encoding: jsonwebtoken::EncodingKey::from_ec_der(pkcs8.as_ref()),
            _server: server,
        }
    }

    /// A fresh ID token for `alice` with `aud` = `agent` (no `client_ids` entry).
    fn id_token(&self, agent: &str) -> String {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some("ec1".into());
        let claims = json!({
            "iss": self.issuer, "aud": agent, "sub": "alice", "iat": now, "exp": now + 300,
            "jti": uuid_like(),
        });
        jsonwebtoken::encode(&header, &claims, &self.encoding).unwrap()
    }
}

/// A unique string for a `jti`.
fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    format!(
        "jti-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    )
}

/// Hop 0 from an ID token follows the reload: an agent added can bring a user in, one removed
/// cannot.
#[tokio::test]
async fn idp_intake_follows_the_reload() {
    let idp = Idp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let extra = format!(
        "[[idps]]\nissuer = \"{0}\"\nallowed_algs = [\"ES256\"]\n\n\
         [[root_grants]]\nissuer = \"{0}\"\nagent = \"tester\"\ncapabilities = [\"github:*\"]\n",
        idp.issuer
    );
    let base = agent("planner", "planner-secret") + &pep("gw1", "g1");
    let h = Harness::start(write_config(dir.path(), &extra, &base)).await;
    let intake = |agent: &'static str| {
        let body = serde_urlencoded::to_string([
            ("grant_type", EXCHANGE),
            ("subject_token", idp.id_token(agent).as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:id_token",
            ),
            ("client_id", agent),
            ("client_secret", "tester-secret"),
            ("scope", "github:read_file"),
        ])
        .unwrap();
        let req = h
            .client
            .post(h.url("/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body);
        async move {
            let resp = req.send().await.unwrap();
            let status = resp.status();
            (status, resp.json::<Value>().await.unwrap_or(Value::Null))
        }
    };
    let (status, v) = intake("tester").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "not configured yet: {v}");

    write_config(
        dir.path(),
        &extra,
        &(base.clone() + &agent("tester", "tester-secret")),
    );
    let v = h.reload().await;
    assert_eq!(strip(&v["agents"]), list(2, &["tester"], &[], &[]));
    let (status, v) = intake("tester").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["access_token"].is_string(), "{v}");

    write_config(dir.path(), &extra, &base);
    let v = h.reload().await;
    assert_eq!(strip(&v["agents"]), list(1, &[], &["tester"], &[]));
    let (status, v) = intake("tester").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(v["error"], "invalid_client", "{v}");
}

/// The reasons of the `deny` records of the agents reload, in order.
async fn denied(h: &Harness) -> Vec<String> {
    h.audit()
        .await
        .into_iter()
        .filter(|r| r["tool"] == "admin.agents.reload" && r["decision"] == "deny")
        .map(|r| r["reason"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// A 0-byte file, and one cut off before its lists, parse with no entries: emptying a list
/// that is not empty now is refused unless `allow_empty` is sent. Allowed, the lists are
/// emptied and the startup warning for that is answered.
#[tokio::test]
async fn emptying_the_lists_needs_allow_empty() {
    let dir = tempfile::tempdir().unwrap();
    let file = File {
        unsigned: false,
        ..File::default()
    };
    let lists =
        agent("planner", "planner-secret") + &agent("coder", "coder-secret") + &pep("gw1", "g1");
    let h = Harness::start(write_file(dir.path(), &file, "", &lists)).await;
    let whole = std::fs::read_to_string(&h.path).unwrap();

    // Cut off just before `[[agents]]`: the other sections are whole, so only the empty
    // lists are refused.
    let cut = &whole[..whole.find("[[agents]]").unwrap()];
    std::fs::write(&h.path, cut).unwrap();
    let (status, v) = h.reload_as(LEGACY).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["code"], "agents_reload_empties", "{v}");
    let detail = v["detail"].as_str().unwrap();
    assert!(
        detail.contains("the file has no [[agents]] and no [[peps]] entries"),
        "{detail}"
    );
    assert!(detail.contains("--allow-empty"), "{detail}");
    // Nothing changed.
    let (status, v) = h.exchange("coder", secret("coder", "coder-secret")).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // Only one list emptied is refused too, naming that list.
    std::fs::write(
        &h.path,
        format!("{cut}{}", agent("planner", "planner-secret")),
    )
    .unwrap();
    let (status, v) = h.reload_as(LEGACY).await;
    assert_eq!(v["code"], "agents_reload_empties", "{v}");
    assert!(
        v["detail"]
            .as_str()
            .unwrap()
            .contains("no [[peps]] entries"),
        "{v}"
    );
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // A 0-byte file: refused for the empty lists before anything else.
    std::fs::write(&h.path, "").unwrap();
    let (status, v) = h.reload_as(LEGACY).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["code"], "agents_reload_empties", "{v}");
    // Allowed to empty the lists, it still differs in `[issuer]` and `[audit]`.
    let (status, v) = h.reload_with(LEGACY, json!({"allow_empty": true})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["code"], "config_file_mismatch", "{v}");
    assert_eq!(denied(&h).await.len(), 4);

    // The cut-off file with `allow_empty`: the lists are emptied.
    std::fs::write(&h.path, cut).unwrap();
    let (status, v) = h.reload_with(LEGACY, json!({"allow_empty": true})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        strip(&v["agents"]),
        list(0, &[], &["coder", "planner"], &[])
    );
    assert_eq!(strip(&v["peps"]), list(0, &[], &["gw1"], &[]));
    assert_eq!(
        v["warnings"],
        json!([
            "[[agents]] and [[actor_trust]] are empty and [token] require_actor_auth = \
                true: every token exchange will be rejected"
        ]),
        "{v}"
    );
    let (status, _) = h.exchange("coder", secret("coder", "coder-secret")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // An empty list stays empty without the flag: nothing is being emptied.
    let v = h.reload().await;
    assert_eq!(strip(&v["agents"]), list(0, &[], &[], &[]));
    assert_eq!(
        denied(&h).await,
        [
            "agents_reload_empties",
            "agents_reload_empties",
            "agents_reload_empties",
            "config_file_mismatch"
        ]
    );
}

/// A file whose `[issuer]` (or `[audit]`) differs from the running config looks like another
/// server's: refused unless `allow_mismatch` is sent, and then only its lists are applied.
#[tokio::test]
async fn another_servers_file_needs_allow_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let lists = agent("planner", "planner-secret") + &pep("gw1", "gw1-secret");
    let h = Harness::start(write_config(dir.path(), "", &lists)).await;
    let other = File {
        issuer: "https://other.test",
        ..File::default()
    };
    write_file(
        dir.path(),
        &other,
        "",
        &(lists.clone() + &agent("tester", "tester-secret")),
    );
    let (status, v) = h.reload_as(LEGACY).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["code"], "config_file_mismatch", "{v}");
    let detail = v["detail"].as_str().unwrap();
    assert!(
        detail.starts_with("the file's [issuer] differs from the running config"),
        "{detail}"
    );
    assert!(detail.contains("--allow-mismatch"), "{detail}");
    assert!(!detail.contains("other.test"), "{detail}");
    let (status, _) = h
        .exchange("tester", secret("tester", "tester-secret"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "not applied");
    // `allow_empty` is not the override for this.
    let (_, v) = h.reload_with(LEGACY, json!({"allow_empty": true})).await;
    assert_eq!(v["code"], "config_file_mismatch", "{v}");

    let (status, v) = h.reload_with(LEGACY, json!({"allow_mismatch": true})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(strip(&v["agents"]), list(2, &["tester"], &[], &[]));
    assert_eq!(v["restart_needed"], json!(["[issuer]"]), "{v}");
    let (status, v) = h
        .exchange("tester", secret("tester", "tester-secret"))
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // The issuer in force is unchanged: an assertion for it is still accepted.
    let key = DpopKey::generate().unwrap();
    write_file(
        dir.path(),
        &other,
        "",
        &(lists.clone() + &agent_with_key("signer", &key, "k1")),
    );
    let (status, v) = h.reload_with(LEGACY, json!({"allow_mismatch": true})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, v) = h.exchange("signer", assertion(&key, "k1", "signer")).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(denied(&h).await, ["config_file_mismatch"; 2]);

    // An unknown body field, or a body that is not JSON, is a 400, not audited.
    let (status, v) = h
        .reload_with(LEGACY, json!({"allow_everything": true}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(denied(&h).await.len(), 2);
}

/// A removed agent that the settings in force still let get a token is warned about: by name
/// when `[token] require_actor_auth = false`, and with a workload token when an
/// `[[actor_trust]]` entry maps to it.
#[tokio::test]
async fn a_removed_agent_still_reachable_is_warned_about() {
    let dir = tempfile::tempdir().unwrap();
    let trust = "[[actor_trust]]\nissuer = \"https://workloads.test\"\n\
                 jwks_url = \"http://127.0.0.1:9/jwks\"\naudience = \"attenuo\"\n\
                 subject_to_agent = { \"wl-coder\" = \"coder\" }\n";
    let lists = agent("planner", "planner-secret")
        + &agent("coder", "coder-secret")
        + &agent("reviewer", "reviewer-secret")
        + &pep("gw1", "g1");
    let h = Harness::start(write_config(dir.path(), trust, &lists)).await;
    write_config(
        dir.path(),
        trust,
        &(agent("planner", "planner-secret") + &pep("gw1", "g1")),
    );
    let v = h.reload().await;
    assert_eq!(
        strip(&v["agents"]),
        list(1, &[], &["coder", "reviewer"], &[])
    );
    // Only coder is mapped; reviewer is not reachable that way.
    assert_eq!(
        v["warnings"],
        json!([
            "the removed agent `coder` may still authenticate with an actor_token: an \
                [[actor_trust]] entry can map a workload to this id, and removing that takes \
                a restart"
        ]),
        "{v}"
    );

    let dir = tempfile::tempdir().unwrap();
    let open = "[token]\nrequire_actor_auth = false\n";
    let h = Harness::start(write_config(dir.path(), open, &lists)).await;
    write_config(
        dir.path(),
        open,
        &(agent("planner", "planner-secret") + &agent("coder", "coder-secret") + &pep("gw1", "g1")),
    );
    let v = h.reload().await;
    assert_eq!(
        v["warnings"],
        json!([
            "the removed agent `reviewer` can still be named as the actor of an exchange: \
                [token] require_actor_auth = false does not authenticate it (a restart with \
                require_actor_auth = true stops that)"
        ]),
        "{v}"
    );
    // And it can: an exchange naming it, with no credentials, is still answered.
    let (status, v) = h.exchange("reviewer", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

/// The lists are checked against the settings in force; the file's own settings are checked
/// too, as a restart would apply them. A refusal by a rule in force that the file changes says
/// so; lists that the file's own settings would refuse are answered in `restart_warnings`.
#[tokio::test]
async fn the_files_own_settings_are_checked_too() {
    // In force: unsigned chains, so a PEP is needed. The file turns them off and drops the
    // PEPs: refused now, though it would start.
    let dir = tempfile::tempdir().unwrap();
    let lists = agent("planner", "planner-secret") + &pep("gw1", "g1");
    let h = Harness::start(write_config(dir.path(), "", &lists)).await;
    let off = File {
        unsigned: false,
        ..File::default()
    };
    write_file(dir.path(), &off, "", &agent("planner", "planner-secret"));
    let (status, v) = h.reload_with(LEGACY, json!({"allow_empty": true})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["code"], "agents_invalid", "{v}");
    assert_eq!(
        v["detail"],
        "[authzen] allow_unsigned_chain = true needs at least one [[peps]] entry (a rule in \
         force; the file changes it, which needs a restart); the agents and peps in force are \
         unchanged"
    );
    // A file that keeps the rule gets no such note.
    write_config(dir.path(), "", &agent("planner", "planner-secret"));
    let (_, v) = h.reload_with(LEGACY, json!({"allow_empty": true})).await;
    assert!(
        !v["detail"].as_str().unwrap().contains("needs a restart"),
        "{v}"
    );

    // In force: no unsigned chains, no PEPs. The file turns them on with no PEP: accepted
    // now, and the answer says a restart with this file would refuse it.
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(write_file(
        dir.path(),
        &off,
        "",
        &agent("planner", "planner-secret"),
    ))
    .await;
    write_config(
        dir.path(),
        "",
        &(agent("planner", "planner-secret") + &agent("tester", "tester-secret")),
    );
    let v = h.reload().await;
    assert_eq!(strip(&v["agents"]), list(2, &["tester"], &[], &[]));
    assert_eq!(v["restart_needed"], json!(["[authzen]"]), "{v}");
    assert_eq!(
        v["restart_warnings"],
        json!([
            "after a restart with this file, its settings would refuse these lists: \
                [authzen] allow_unsigned_chain = true needs at least one [[peps]] entry"
        ]),
        "{v}"
    );
    assert_eq!(v["warnings"], json!([]), "{v}");
    // The same settings as in force: nothing to warn about.
    write_file(
        dir.path(),
        &off,
        "",
        &(agent("planner", "planner-secret") + &agent("tester", "tester-secret")),
    );
    let v = h.reload().await;
    assert_eq!(v["restart_warnings"], json!([]), "{v}");
    assert_eq!(v["restart_needed"], json!([]), "{v}");
}

/// A PEP added by a reload can send a body chain (`allow_unsigned_chain`) and have it
/// decided; once removed it is refused.
#[tokio::test]
async fn the_unsigned_chain_path_follows_the_peps() {
    let dir = tempfile::tempdir().unwrap();
    let base = agent("planner", "planner-secret");
    let h = Harness::start(write_config(
        dir.path(),
        "",
        &(base.clone() + &pep("gw1", "g1")),
    ))
    .await;
    let (token, _) = h.root().await;
    let chain = h
        .state
        .keys()
        .verifier
        .verify(&token, time::OffsetDateTime::now_utc())
        .unwrap()
        .chain;
    let call = attenuo_core::ToolCall::new("github", "read_file", json!({"repo": "a/b"}));
    let unsigned = |id: &str, secret: &str| {
        let mut body =
            serde_json::to_value(attenuo_policy::authzen::to_request(&chain, &call)).unwrap();
        body["pep_id"] = json!(id);
        body["pep_secret"] = json!(secret);
        h.client
            .post(h.url("/access/v1/evaluation"))
            .json(&body)
            .send()
    };
    let decided = |resp: reqwest::Response| async move {
        let status = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        (status, v)
    };
    let (status, v) = decided(unsigned("gw2", "g2").await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");

    write_config(
        dir.path(),
        "",
        &(base.clone() + &pep("gw1", "g1") + &pep("gw2", "g2")),
    );
    h.reload().await;
    let (status, v) = decided(unsigned("gw2", "g2").await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // Decided (this config has no tool catalog, so the answer is a deny with its reason).
    assert!(v["decision"].is_boolean(), "{v}");
    assert!(v["context"]["decision_id"].is_string(), "{v}");

    write_config(dir.path(), "", &(base + &pep("gw1", "g1")));
    h.reload().await;
    let (status, v) = decided(unsigned("gw2", "g2").await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(v["error"], "invalid_client", "{v}");
    let (status, v) = decided(unsigned("gw1", "g1").await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

/// A PEP that authenticates with `private_key_jwt`: added by a reload it is accepted, its key
/// rotated the old one is refused, removed it is refused.
#[tokio::test]
async fn a_pep_with_private_key_jwt_follows_the_reload() {
    let dir = tempfile::tempdir().unwrap();
    let base = agent("planner", "planner-secret") + &pep("gw1", "g1");
    let h = Harness::start(write_config(dir.path(), "", &base)).await;
    let (token, _) = h.root().await;
    let (k1, k2) = (DpopKey::generate().unwrap(), DpopKey::generate().unwrap());
    let keyed = |key: &DpopKey, kid: &str| {
        agent_with_key("gw-signed", key, kid).replacen("[[agents]]", "[[peps]]", 1)
    };
    let evaluate = |key: &DpopKey, kid: &str| {
        let mut body = json!({
            "subject": {"type": "agent", "id": ""},
            "action": {"name": "read_file"},
            "resource": {"type": "tool", "id": "github/read_file",
                         "properties": {"server": "github"}},
            "context": {"input": {}},
        });
        for (k, v) in assertion(key, kid, "gw-signed").as_object().unwrap() {
            body[k] = v.clone();
        }
        h.client
            .post(h.url("/access/v1/evaluation"))
            .bearer_auth(&token)
            .json(&body)
            .send()
    };
    assert_eq!(
        evaluate(&k1, "k1").await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    write_config(dir.path(), "", &(base.clone() + &keyed(&k1, "k1")));
    let v = h.reload().await;
    assert_eq!(strip(&v["peps"]), list(2, &["gw-signed"], &[], &[]));
    assert_eq!(evaluate(&k1, "k1").await.unwrap().status(), StatusCode::OK);

    write_config(dir.path(), "", &(base.clone() + &keyed(&k2, "k2")));
    let v = h.reload().await;
    assert_eq!(strip(&v["peps"]), list(2, &[], &[], &["gw-signed"]));
    assert_eq!(
        evaluate(&k1, "k1").await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(evaluate(&k2, "k2").await.unwrap().status(), StatusCode::OK);

    write_config(dir.path(), "", &base);
    h.reload().await;
    assert_eq!(
        evaluate(&k2, "k2").await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

/// The replay cache is not part of the lists: an assertion used before a reload that keeps the
/// key stays used after it.
#[tokio::test]
async fn a_spent_assertion_stays_spent_across_a_reload() {
    let dir = tempfile::tempdir().unwrap();
    let key = DpopKey::generate().unwrap();
    let lists = agent("planner", "planner-secret")
        + &agent_with_key("signer", &key, "k1")
        + &pep("gw1", "g1");
    let h = Harness::start(write_config(dir.path(), "", &lists)).await;
    let used = assertion(&key, "k1", "signer");
    let (status, v) = h.exchange("signer", used.clone()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, _) = h.exchange("signer", used.clone()).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "replayed before the reload"
    );

    write_config(dir.path(), "", &(lists + &agent("tester", "tester-secret")));
    let v = h.reload().await;
    assert_eq!(strip(&v["agents"]), list(3, &["tester"], &[], &[]));
    let (status, v) = h.exchange("signer", used).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "replayed after the reload: {v}"
    );
    let (status, v) = h.exchange("signer", assertion(&key, "k1", "signer")).await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

/// Two reloads at once are taken one after the other: each is answered and audited, and the
/// lists in force are one file's agents with the same file's PEPs, never a mix.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_reloads_at_once_are_serialized() {
    let dir = tempfile::tempdir().unwrap();
    let a = agent("planner", "planner-secret") + &agent("alpha", "a") + &pep("gw-a", "a");
    let b = agent("planner", "planner-secret") + &agent("beta", "b") + &pep("gw-b", "b");
    let h = Harness::start(write_config(dir.path(), "", &b)).await;
    // Each file's pair of digests, from a reload of it alone.
    let digests = |v: &Value| {
        (
            v["agents"]["sha256"].as_str().unwrap().to_string(),
            v["peps"]["sha256"].as_str().unwrap().to_string(),
        )
    };
    write_config(dir.path(), "", &a);
    let pair_a = digests(&h.reload().await);
    write_config(dir.path(), "", &b);
    let pair_b = digests(&h.reload().await);
    assert_ne!(pair_a, pair_b);
    let in_force = || {
        let s = h.state.clients.snapshot();
        let (x, y) = s.sha256();
        (x.to_string(), y.to_string())
    };
    let before = h.audit().await.len();
    for n in 0..10 {
        let (first, second) = if n % 2 == 0 { (&a, &b) } else { (&b, &a) };
        write_config(dir.path(), "", first);
        let one = h.reload_as(LEGACY);
        let two = async {
            write_config(dir.path(), "", second);
            h.reload_as(LEGACY).await
        };
        let ((s1, v1), (s2, v2)) = tokio::join!(one, two);
        assert_eq!(s1, StatusCode::OK, "{v1}");
        assert_eq!(s2, StatusCode::OK, "{v2}");
        for v in [&v1, &v2] {
            let pair = digests(v);
            assert!(pair == pair_a || pair == pair_b, "a mix: {v}");
        }
        let now = in_force();
        assert!(now == pair_a || now == pair_b, "a mix in force");
    }
    let records: Vec<Value> = h.audit().await.into_iter().skip(before).collect();
    let reloads = records
        .iter()
        .filter(|r| r["tool"] == "admin.agents.reload" && r["decision"] == "allow")
        .count();
    assert_eq!(reloads, 20);
}

/// The startup warnings the new lists raise against the `[[idps]]` in force are answered.
#[tokio::test]
async fn idp_warnings_are_answered() {
    let dir = tempfile::tempdir().unwrap();
    let idps = "[[idps]]\nissuer = \"https://idp.test\"\njwks_url = \"http://127.0.0.1:9/jwks\"\n\
                client_ids = { planner = \"planner-client\" }\n";
    let lists = agent("planner", "planner-secret") + &pep("gw1", "g1");
    let h = Harness::start(write_config(dir.path(), idps, &lists)).await;
    write_config(
        dir.path(),
        idps,
        &(lists.clone() + &agent("tester", "tester-secret")),
    );
    let v = h.reload().await;
    let warnings = v["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 1, "{v}");
    assert!(
        warnings[0].as_str().unwrap().starts_with(
            "[[idps]] `https://idp.test`: client_ids has no entry for the agent `tester`"
        ),
        "{v}"
    );
    write_config(dir.path(), idps, &pep("gw1", "g1"));
    let (status, v) = h.reload_with(LEGACY, json!({"allow_empty": true})).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        v["warnings"],
        json!([
            "[[agents]] and [[actor_trust]] are empty and [token] require_actor_auth = true: \
             every token exchange will be rejected",
            "[[idps]] are configured but [[agents]] is empty; IdP intake rejects every request"
        ]),
        "{v}"
    );
}
