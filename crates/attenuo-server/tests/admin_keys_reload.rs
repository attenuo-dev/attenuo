//! `POST /admin/keys/reload`: the issuer's signing key and retired keys re-read from the key
//! files the config file names, and swapped in at once. A rotation with an overlap keeps old
//! tokens verifying while new ones carry the new `kid` and the JWKS lists both; dropping the
//! current key, or a key that signed the audit log, is refused unless asked for; a bad,
//! unreadable or repeated key file changes nothing; refusals and successes are audited with key
//! ids only; the route needs the admin role and a config file; tokens issued and checked during
//! repeated reloads never fail while their key stays trusted; and `audit verify` (on the
//! server and on an export, with the published JWKS) still passes across a rotation, prune
//! anchors included. Other sections of the file are named, not applied.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use attenuo_audit::{parse_export, verify_export, AuditSink, CheckpointKeys};
use attenuo_core::{Decision, DecisionRecord, RecordKind, ToolCall};
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::operators::token_sha256_hex;
use attenuo_server::{AppState, Config};
use attenuo_token::{Issuer, IssuerConfig};
use base64::Engine as _;
use reqwest::StatusCode;
use serde_json::{json, Value};

use common::sha256_hex;

const LEGACY: &str = "legacy-admin-token-0123456789abcdef";
const ISSUER: &str = "https://attenuo.test";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const TOOL: &str = "admin.keys.reload";

/// A fresh Ed25519 key.
fn new_key() -> Issuer {
    Issuer::generate(IssuerConfig {
        issuer: ISSUER.into(),
        audience: "attenuo".into(),
        max_depth: 4,
        default_ttl: time::Duration::minutes(5),
    })
}

/// A PKCS#8 `PRIVATE KEY` PEM of a P-256 key: a key of another curve.
fn p256_pem() -> String {
    let rng = ring::rand::SystemRandom::new();
    let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(doc.as_ref());
    format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n")
}

/// What [`write_file`] varies.
struct File<'a> {
    /// `[issuer] private_key_pem_path`, a file name in the directory; `None` leaves it out.
    signing: Option<&'a str>,
    /// `[issuer] previous_key_paths`, file names in the directory.
    previous: &'a [&'a str],
    /// `[issuer] issuer`.
    issuer: &'a str,
    /// More sections.
    extra: &'a str,
}

impl Default for File<'_> {
    fn default() -> Self {
        Self {
            signing: Some("k1.pem"),
            previous: &[],
            issuer: ISSUER,
            extra: "",
        }
    }
}

/// Write `<dir>/attenuo.toml` in one rename: the `[issuer]` of `file`, a file-backed audit log
/// with a checkpoint every 5 entries, a file sink and manual pruning, `[admin] token`, a viewer
/// and an operator, the dev root mint and two agents, `coder` and `tester`.
fn write_file(dir: &Path, file: &File) -> PathBuf {
    let path = dir.join("attenuo.toml");
    let tmp = dir.join("attenuo.toml.tmp");
    let signing = file
        .signing
        .map(|s| format!("private_key_pem_path = \"{}\"\n", dir.join(s).display()))
        .unwrap_or_default();
    let previous: Vec<String> = file
        .previous
        .iter()
        .map(|p| format!("\"{}\"", dir.join(p).display()))
        .collect();
    let op = |name: &str, role: &str| {
        format!(
            "[[admin.operators]]\nname = \"{name}\"\ntoken_sha256 = \"{}\"\nrole = \"{role}\"\n",
            token_sha256_hex(&format!("{name}-token"))
        )
    };
    std::fs::write(
        &tmp,
        format!(
            "[issuer]\nissuer = \"{}\"\n{signing}previous_key_paths = [{}]\n\n\
             [audit]\nsqlite_path = \"{}\"\ncheckpoint_every = 5\n\n\
             [audit.sink]\nkind = \"file\"\npath = \"{}\"\ninitial_backoff_ms = 5\n\
             max_backoff_seconds = 1\n\n\
             [audit.retention]\nprune = \"manual\"\n\n\
             [admin]\ntoken = \"{LEGACY}\"\n\n{}{}\n\
             [dev]\nallow_root_mint = true\n\n{}\n\
             [[agents]]\nid = \"coder\"\nsecret_sha256 = \"{}\"\n\n\
             [[agents]]\nid = \"tester\"\nsecret_sha256 = \"{}\"\n",
            file.issuer,
            previous.join(", "),
            dir.join("audit.sqlite").display(),
            dir.join("shipped.jsonl").display(),
            op("vera", "viewer"),
            op("bob", "operator"),
            file.extra,
            sha256_hex("coder-secret"),
            sha256_hex("tester-secret"),
        ),
    )
    .unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    path
}

/// The files `k1.pem`, `k2.pem`, `k3.pem` (private keys) and `k1.pub` (k1's public key) in
/// `dir`, with their `kid`s.
struct Keys {
    k1: String,
    k2: String,
    k3: String,
}

fn write_keys(dir: &Path) -> Keys {
    let (k1, k2, k3) = (new_key(), new_key(), new_key());
    std::fs::write(dir.join("k1.pem"), k1.private_key_pem()).unwrap();
    std::fs::write(dir.join("k1.pub"), k1.public_key_pem()).unwrap();
    std::fs::write(dir.join("k2.pem"), k2.private_key_pem()).unwrap();
    std::fs::write(dir.join("k3.pem"), k3.private_key_pem()).unwrap();
    Keys {
        k1: k1.key_id(),
        k2: k2.key_id(),
        k3: k3.key_id(),
    }
}

struct Harness {
    server: Spawned,
    state: Arc<AppState>,
    client: reqwest::Client,
    dir: tempfile::TempDir,
    keys: Keys,
}

impl Harness {
    /// Keys written, a server started from a config file whose signing key is k1.
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let keys = write_keys(dir.path());
        let path = write_file(dir.path(), &File::default());
        let cfg = Config::load(&path).unwrap();
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        Self {
            server: spawn_router(router).await.unwrap(),
            state,
            client: reqwest::Client::new(),
            dir,
            keys,
        }
    }

    fn url(&self, path: &str) -> String {
        self.server.url(path)
    }

    fn write(&self, file: &File) {
        write_file(self.dir.path(), file);
    }

    async fn reload_with(&self, bearer: &str, body: Value) -> (StatusCode, Value) {
        let resp = self
            .client
            .post(self.url("/admin/keys/reload"))
            .bearer_auth(bearer)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn reload_body(&self, body: Value) -> Value {
        let (status, v) = self.reload_with(LEGACY, body).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        v
    }

    async fn reload(&self) -> Value {
        self.reload_body(json!({})).await
    }

    /// A refused reload: its code, after checking the 422 and the keys in force (unchanged).
    async fn refused(&self, body: Value) -> Value {
        let before = self.jwks_kids().await;
        let (status, v) = self.reload_with(LEGACY, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert_eq!(self.jwks_kids().await, before, "nothing changed");
        let detail = v["detail"].as_str().unwrap();
        assert!(!detail.contains("BEGIN"), "{detail}");
        assert!(detail.ends_with("in force are unchanged"), "{detail}");
        v
    }

    async fn get(&self, path: &str) -> Value {
        self.client
            .get(self.url(path))
            .bearer_auth(LEGACY)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn jwks(&self) -> Value {
        self.client
            .get(self.url("/.well-known/jwks.json"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn jwks_kids(&self) -> Vec<String> {
        kids_of(&self.jwks().await)
    }

    /// A root token for `coder`'s user from the dev mint.
    async fn root(&self) -> String {
        root(&self.client, &self.url("")).await
    }

    /// Exchange `parent` for a child for `coder`.
    async fn exchange(&self, parent: &str) -> (StatusCode, Value) {
        self.exchange_as(parent, "coder").await
    }

    /// Exchange `parent` for a child for `actor` (`coder` or `tester`).
    async fn exchange_as(&self, parent: &str, actor: &str) -> (StatusCode, Value) {
        exchange(&self.client, &self.url(""), parent, actor).await
    }

    /// The records of `tool`, oldest first.
    async fn records(&self, tool: &str) -> Vec<Value> {
        let v = self.get("/admin/audit?from=1&limit=1000").await;
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["record"].clone())
            .filter(|r| r["tool"] == tool)
            .collect()
    }
}

async fn root(client: &reqwest::Client, base: &str) -> String {
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
    v["access_token"].as_str().unwrap().into()
}

async fn exchange(
    client: &reqwest::Client,
    base: &str,
    parent: &str,
    actor: &str,
) -> (StatusCode, Value) {
    let resp = client
        .post(format!("{base}/token"))
        .json(&json!({
            "grant_type": EXCHANGE, "subject_token": parent, "subject_token_type": JWT,
            "actor": actor, "client_id": actor, "client_secret": format!("{actor}-secret"),
            "authorization_details": [{"type": "attenuo_capabilities",
                "capabilities": [{"server": "github", "tool": "read_file"}]}],
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// The `kid` in a JWT's header.
fn kid_of(token: &str) -> String {
    let header = token.split('.').next().unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header)
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["kid"].as_str().unwrap().to_string()
}

fn kids_of(jwks: &Value) -> Vec<String> {
    jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap().to_string())
        .collect()
}

/// An admin-like record of no chain at `at`, as the audit retention tests write.
fn record(i: usize, at: time::OffsetDateTime) -> DecisionRecord {
    let call = ToolCall::new("attenuo", "admin.test", json!({ "i": i }));
    DecisionRecord {
        id: uuid::Uuid::new_v4(),
        at,
        kind: RecordKind::Admin,
        chain_id: None,
        decision: Decision::Allow,
        reason: "admin_action".into(),
        originating_subject: "urn:attenuo:admin".into(),
        agents: Vec::new(),
        chain_depth: 0,
        chain_digest: attenuo_core::digest::sha256_json(&Value::Null),
        leases: Vec::new(),
        server: "attenuo".into(),
        tool: call.tool.clone(),
        arguments_digest: call.arguments_digest(),
        session_id: None,
        policy_ids: Vec::new(),
        dpop_bound: false,
        decision_id: None,
        result: None,
        labels: None,
        approval: None,
        budget: None,
        usage: None,
        search: None,
        id_jag_ceiling: None,
    }
}

/// k1 to k2 with k1 kept: a token k1 signed keeps verifying (it is exchanged), the child
/// carries k2's `kid`, the JWKS lists k2 then k1, and the answer names kids only.
#[tokio::test]
async fn a_rotation_with_an_overlap_keeps_old_tokens() {
    let h = Harness::start().await;
    let k = &h.keys;
    let old = h.root().await;
    assert_eq!(kid_of(&old), k.k1);
    assert_eq!(h.jwks_kids().await, std::slice::from_ref(&k.k1));

    h.write(&File {
        signing: Some("k2.pem"),
        previous: &["k1.pub"],
        ..File::default()
    });
    let v = h.reload().await;
    assert_eq!(v["signing_kid"], k.k2.as_str(), "{v}");
    assert_eq!(v["previous_signing_kid"], k.k1.as_str(), "{v}");
    assert_eq!(v["changed"], true, "{v}");
    assert_eq!(v["verifying_kids"], json!([k.k2, k.k1]), "{v}");
    assert_eq!(v["added"], json!([k.k2]), "{v}");
    assert_eq!(v["removed"], json!([]), "{v}");
    assert_eq!(v["audit_signing_kid"], k.k2.as_str(), "{v}");
    assert_eq!(v["kept_until_restart"], json!([]), "{v}");
    assert_eq!(v["restart_needed"], json!([]), "{v}");
    assert_eq!(v["warnings"], json!([]), "{v}");
    assert!(v["audit_id"].is_string(), "{v}");
    assert!(!v.to_string().contains("BEGIN"), "{v}");

    assert_eq!(h.jwks_kids().await, [k.k2.clone(), k.k1.clone()]);
    let (status, child) = h.exchange(&old).await;
    assert_eq!(status, StatusCode::OK, "{child}");
    let child = child["access_token"].as_str().unwrap();
    assert_eq!(kid_of(child), k.k2, "the child is signed with the new key");
    let fresh = h.root().await;
    assert_eq!(kid_of(&fresh), k.k2);
    // A child of the old token, signed with k2, can itself be exchanged: its `ou_sig` was
    // made by k1, which still verifies.
    let (status, grandchild) = h.exchange_as(child, "tester").await;
    assert_eq!(status, StatusCode::OK, "{grandchild}");

    // Reloading the same file changes nothing.
    let v = h.reload().await;
    assert_eq!(v["changed"], false, "{v}");
    assert_eq!(v["added"], json!([]), "{v}");

    // k1 retired after its tokens expired: allowed, as k1 is not the signing key, once its
    // audit signatures are let go (see `a_key_that_signed_the_audit_log_needs_its_flag`).
    h.write(&File {
        signing: Some("k2.pem"),
        ..File::default()
    });
    let v = h.reload_body(json!({"allow_drop_audit_key": true})).await;
    assert_eq!(v["removed"], json!([k.k1]), "{v}");
    assert!(
        v["warnings"].to_string().contains(&format!(
            "tokens signed by the retired kid `{}` no longer verify",
            k.k1
        )),
        "{v}"
    );
    assert_eq!(h.jwks_kids().await, std::slice::from_ref(&k.k2));
    let (status, _) = h.exchange(&old).await;
    assert_ne!(status, StatusCode::OK, "k1 no longer verifies");
    let (status, v) = h.exchange(&fresh).await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

/// A new signing key without the current one in `previous_key_paths` is refused; asked for,
/// it is done, every token of the old key stops verifying, and the answer warns of it.
#[tokio::test]
async fn dropping_the_current_key_needs_allow_drop_current() {
    let h = Harness::start().await;
    let k = &h.keys;
    let old = h.root().await;
    h.write(&File {
        signing: Some("k3.pem"),
        ..File::default()
    });
    let v = h.refused(json!({})).await;
    assert_eq!(v["code"], "keys_reload_drops_current", "{v}");
    let detail = v["detail"].as_str().unwrap();
    assert!(detail.contains(&k.k1) && detail.contains(&k.k3), "{detail}");
    assert!(detail.contains("--allow-drop-current"), "{detail}");
    // The other flags are not the override for this.
    let v = h
        .refused(json!({"allow_drop_audit_key": true, "allow_mismatch": true}))
        .await;
    assert_eq!(v["code"], "keys_reload_drops_current", "{v}");
    let (status, v) = h.exchange(&old).await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // k1 also signs the audit log: that needs its own flag.
    let v = h.refused(json!({"allow_drop_current": true})).await;
    assert_eq!(v["code"], "keys_reload_drops_audit_key", "{v}");
    assert!(v["detail"].as_str().unwrap().contains(&k.k1), "{v}");

    let v = h
        .reload_body(json!({"allow_drop_current": true, "allow_drop_audit_key": true}))
        .await;
    assert_eq!(v["verifying_kids"], json!([k.k3]), "{v}");
    assert_eq!(v["removed"], json!([k.k1]), "{v}");
    let warnings = v["warnings"].to_string();
    assert!(
        warnings.contains(&format!("tokens signed by kid `{}` no longer verify", k.k1)),
        "{warnings}"
    );
    assert!(
        warnings.contains("audit checkpoints and anchors"),
        "{warnings}"
    );
    assert_eq!(h.jwks_kids().await, std::slice::from_ref(&k.k3));
    let (status, _) = h.exchange(&old).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(kid_of(&h.root().await), k.k3);
}

/// Unreadable, invalid and repeated key files, and config files that do not name a signing
/// key or do not parse: each refused with its code, the file named but never quoted, and the
/// keys in force untouched.
#[tokio::test]
async fn bad_key_files_change_nothing() {
    let h = Harness::start().await;
    let k = &h.keys;
    let dir = h.dir.path();
    let token = h.root().await;
    std::fs::write(
        dir.join("garbage.pem"),
        "not a key at all: s3cr3t-content\n",
    )
    .unwrap();
    std::fs::write(dir.join("p256.pem"), p256_pem()).unwrap();
    std::fs::write(
        dir.join("rsa.pem"),
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("damaged.pem"),
        "-----BEGIN PRIVATE KEY-----\n!!s3cr3t!!\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    std::fs::write(dir.join("binary.pem"), [0xff, 0xfe, 0x00, 0x80]).unwrap();

    let cases: [(Option<&str>, &[&str], &str, &str); 10] = [
        (
            Some("missing.pem"),
            &[],
            "key_file_unreadable",
            "missing.pem",
        ),
        (
            Some("k2.pem"),
            &["missing.pem"],
            "key_file_unreadable",
            "missing.pem",
        ),
        (Some("binary.pem"), &[], "key_file_unreadable", "binary.pem"),
        (
            Some("garbage.pem"),
            &[],
            "key_file_invalid",
            "no `PRIVATE KEY` PEM block",
        ),
        (
            Some("k1.pub"),
            &[],
            "key_file_invalid",
            "holds a public key only",
        ),
        (
            Some("p256.pem"),
            &[],
            "key_file_invalid",
            "another type or curve",
        ),
        (Some("rsa.pem"), &[], "key_file_invalid", "holds an RSA key"),
        (
            Some("k2.pem"),
            &["damaged.pem"],
            "key_file_invalid",
            "damaged.pem",
        ),
        (
            Some("k2.pem"),
            &["k1.pem", "k1.pub"],
            "key_duplicate",
            "hold the same key",
        ),
        (
            Some("k2.pem"),
            &["k2.pem"],
            "key_duplicate",
            "hold the same key",
        ),
    ];
    for (signing, previous, code, needle) in cases {
        h.write(&File {
            signing,
            previous,
            ..File::default()
        });
        let v = h.refused(json!({})).await;
        assert_eq!(v["code"], code, "{signing:?} {previous:?}: {v}");
        let detail = v["detail"].as_str().unwrap();
        assert!(detail.contains(needle), "{detail}");
        assert!(!detail.contains("s3cr3t"), "{detail}");
        assert!(!detail.contains("MIIB"), "{detail}");
    }
    // The duplicate names the kid and both files.
    h.write(&File {
        signing: Some("k2.pem"),
        previous: &["k1.pem", "k1.pub"],
        ..File::default()
    });
    let v = h.refused(json!({})).await;
    let detail = v["detail"].as_str().unwrap();
    assert!(
        detail.contains(&k.k1) && detail.contains("k1.pem") && detail.contains("k1.pub"),
        "{detail}"
    );

    // No signing key file named: a reload never generates one.
    h.write(&File {
        signing: None,
        ..File::default()
    });
    let v = h.refused(json!({})).await;
    assert_eq!(v["code"], "keys_config_invalid", "{v}");
    assert!(v["detail"]
        .as_str()
        .unwrap()
        .contains("sets no [issuer] private_key_pem_path"));
    // A file that does not parse: the line, never the value.
    std::fs::write(
        dir.join("attenuo.toml"),
        "[admin]\ntoken = \"s3cr3t-admin-token-0123456789\"\n[issuer\n",
    )
    .unwrap();
    let v = h.refused(json!({})).await;
    assert_eq!(v["code"], "keys_config_invalid", "{v}");
    assert!(!v["detail"].as_str().unwrap().contains("s3cr3t"), "{v}");
    // A body that is not the expected JSON: 400, not audited.
    let (status, v) = h.reload_with(LEGACY, json!({"allow_drop": true})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");

    assert_eq!(h.jwks_kids().await, std::slice::from_ref(&k.k1));
    assert_eq!(kid_of(&h.root().await), k.k1);
    let (status, v) = h.exchange(&token).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        h.state.audit.checkpoint_signer_kid().as_deref(),
        Some(k.k1.as_str())
    );
    // Every 422 above was audited as a deny with its code; the 400 was not.
    let denies: Vec<String> = h
        .records(TOOL)
        .await
        .iter()
        .map(|r| {
            assert_eq!(r["decision"], "deny", "{r}");
            r["reason"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(denies.len(), 13, "{denies:?}");
    assert_eq!(denies[0], "key_file_unreadable");
    assert_eq!(denies[12], "keys_config_invalid");
}

/// The audit records of a reload: a deny with the refusal's code and the kids involved, an
/// allow with the kids before and after. The arguments are kept as a digest; they are checked
/// here against the kids and paths only, so they hold no key material.
#[tokio::test]
async fn reloads_are_audited_with_kids_only() {
    let h = Harness::start().await;
    let k = &h.keys;
    let path = h.dir.path().join("attenuo.toml");
    h.write(&File {
        signing: Some("k2.pem"),
        ..File::default()
    });
    let v = h.refused(json!({})).await;
    assert_eq!(v["code"], "keys_reload_drops_current");
    h.write(&File {
        signing: Some("k2.pem"),
        previous: &["k1.pem"],
        ..File::default()
    });
    let ok = h.reload().await;
    let records = h.records(TOOL).await;
    assert_eq!(records.len(), 2, "{records:?}");
    let digest = |args: Value| ToolCall::new("attenuo", TOOL, args).arguments_digest();

    let deny = &records[0];
    assert_eq!(deny["decision"], "deny");
    assert_eq!(deny["reason"], "keys_reload_drops_current");
    assert_eq!(deny["originating_subject"], "urn:attenuo:admin");
    assert_eq!(
        deny["arguments_digest"],
        digest(json!({
            "path": path,
            "signing_kid": k.k2,
            "previous_signing_kid": k.k1,
            "verifying_kids": [k.k2],
        }))
    );
    let allow = &records[1];
    assert_eq!(allow["decision"], "allow");
    assert_eq!(allow["id"], ok["audit_id"]);
    assert_eq!(
        allow["arguments_digest"],
        digest(json!({
            "path": path,
            "signing_kid": k.k2,
            "previous_signing_kid": k.k1,
            "changed": true,
            "verifying_kids": [k.k2, k.k1],
            "added": [k.k2],
            "removed": [],
            "restart_needed": [],
        }))
    );
    for r in &records {
        assert!(!r.to_string().contains("BEGIN"), "{r}");
    }
}

/// Viewer and operator are refused; a server not started from a config file answers 409, as
/// the other reloads do; the console serves the route with `allow_write` only.
#[tokio::test]
async fn the_reload_needs_the_admin_role_and_a_config_file() {
    let h = Harness::start().await;
    h.write(&File {
        signing: Some("k2.pem"),
        previous: &["k1.pem"],
        ..File::default()
    });
    for token in ["vera-token", "bob-token"] {
        let (status, v) = h.reload_with(token, json!({})).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
        assert_eq!(v["code"], "admin_role_insufficient");
    }
    assert_eq!(
        h.jwks_kids().await,
        std::slice::from_ref(&h.keys.k1),
        "not reloaded"
    );

    let other = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.issuer.private_key_pem_path = Some(other.path().join("issuer.pem"));
    cfg.audit.sqlite_path = ":memory:".into();
    cfg.admin.token = Some(LEGACY.into());
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    for route in [
        "/admin/keys/reload",
        "/admin/agents/reload",
        "/admin/operators/reload",
    ] {
        let resp = reqwest::Client::new()
            .post(server.url(route))
            .bearer_auth(LEGACY)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "{route}");
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["code"], "reload_unavailable", "{route}");
        assert_eq!(
            v["detail"],
            "the server was not started from a config file; there is nothing to reload"
        );
    }

    for allow_write in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        write_keys(dir.path());
        let path = write_file(dir.path(), &File::default());
        let mut cfg = Config::load(&path).unwrap();
        cfg.admin_ui.allow_write = allow_write;
        let (_router, state) = attenuo_server::build(&cfg).unwrap();
        let console = spawn_router(attenuo_server::admin_ui::router(state, &cfg))
            .await
            .unwrap();
        let resp = reqwest::Client::new()
            .post(console.url("/admin/keys/reload"))
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
        assert_eq!(resp.status(), want, "allow_write = {allow_write}");
    }
}

/// The key paths come from the file on disk; other sections that differ are named in
/// `restart_needed` and not applied. A file whose `[issuer] issuer` differs needs
/// `allow_mismatch`, and then only its keys are applied (`iss` stays). An agents reload after
/// a key reload does not take the new key paths for another server's file.
#[tokio::test]
async fn only_the_key_files_are_applied() {
    let h = Harness::start().await;
    let k = &h.keys;
    h.write(&File {
        signing: Some("k2.pem"),
        previous: &["k1.pem"],
        extra: "[server]\nlisten = \"127.0.0.1:9999\"\n",
        ..File::default()
    });
    let v = h.reload().await;
    assert_eq!(v["signing_kid"], k.k2.as_str(), "{v}");
    assert_eq!(v["restart_needed"], json!(["[server]"]), "{v}");

    // The agents reload reads the same file: its key paths are not a mismatch.
    let resp = h
        .client
        .post(h.url("/admin/agents/reload"))
        .bearer_auth(LEGACY)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let v: Value = resp.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["restart_needed"], json!(["[server]"]), "{v}");

    h.write(&File {
        signing: Some("k3.pem"),
        previous: &["k2.pem", "k1.pem"],
        issuer: "https://other.test",
        ..File::default()
    });
    let v = h.refused(json!({})).await;
    assert_eq!(v["code"], "config_file_mismatch", "{v}");
    let detail = v["detail"].as_str().unwrap();
    assert!(
        detail.starts_with("the file's [issuer] differs"),
        "{detail}"
    );
    assert!(
        detail.contains("attenuo admin key reload --allow-mismatch"),
        "{detail}"
    );
    assert!(!detail.contains("other.test"), "{detail}");
    let v = h.reload_body(json!({"allow_mismatch": true})).await;
    assert_eq!(v["signing_kid"], k.k3.as_str(), "{v}");
    assert_eq!(v["restart_needed"], json!(["[issuer]"]), "{v}");
    let token = h.root().await;
    let claims = token.split('.').nth(1).unwrap();
    let claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["iss"], ISSUER, "the running `iss` stays");
    assert_eq!(kid_of(&token), k.k3);
}

/// A key that signed audit checkpoints or a prune anchor stays needed: dropping it is refused
/// unless asked for. Across a rotation with an overlap, `audit verify` passes on the server and
/// on an export checked with the published JWKS, with checkpoints by both keys and an anchor
/// by the old one.
#[tokio::test]
async fn audit_verify_passes_across_a_rotation() {
    let h = Harness::start().await;
    let k = &h.keys;
    // Old entries, then a prune through 10 with the old key: an anchor signed by k1.
    let old = time::OffsetDateTime::now_utc() - time::Duration::days(200);
    for i in 0..12 {
        h.state.audit.append(record(i, old)).unwrap();
    }
    let sink = h.state.checkpoint_sink.as_ref().unwrap();
    common::wait_for(|| sink.delivered_through() >= Some(10)).await;
    let resp = h
        .client
        .post(h.url("/admin/audit/prune"))
        .bearer_auth(LEGACY)
        .json(&json!({"through": 10}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "{}",
        resp.text().await.unwrap()
    );
    let before = h.get("/admin/audit/checkpoint").await;
    assert_eq!(before["kid"], k.k1.as_str(), "{before}");

    h.write(&File {
        signing: Some("k2.pem"),
        previous: &["k1.pub"],
        ..File::default()
    });
    h.reload().await;
    for i in 0..7 {
        h.state
            .audit
            .append(record(100 + i, time::OffsetDateTime::now_utc()))
            .unwrap();
    }
    let after = h.get("/admin/audit/checkpoint").await;
    assert_eq!(after["kid"], k.k2.as_str(), "{after}");

    let report = h.get("/admin/audit/verify").await;
    assert_eq!(report["ok"], true, "{report}");
    assert_eq!(report["bad_checkpoints"], json!([]), "{report}");
    let anchors = h.get("/admin/audit/anchors").await;
    assert_eq!(anchors["anchors"][0]["kid"], k.k1.as_str(), "{anchors}");
    let checkpoints = h.get("/admin/audit/checkpoints?limit=1000").await;
    let cp_kids: std::collections::BTreeSet<String> = checkpoints["checkpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kid"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        cp_kids,
        [k.k1.clone(), k.k2.clone()].into_iter().collect(),
        "{checkpoints}"
    );
    // An export, checked offline with the JWKS the server publishes, as `attenuo audit verify
    // --jwks` does.
    let export = h
        .client
        .get(h.url("/admin/audit/export"))
        .bearer_auth(LEGACY)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let keys = CheckpointKeys::from_jwks(&h.jwks().await).unwrap();
    let rep = verify_export(&parse_export(&export).unwrap(), &keys).unwrap();
    assert!(rep.report.ok, "{:?}", rep.report);

    // Retiring k1 would leave its checkpoints and the anchor unverifiable: refused.
    h.write(&File {
        signing: Some("k2.pem"),
        ..File::default()
    });
    let v = h.refused(json!({})).await;
    assert_eq!(v["code"], "keys_reload_drops_audit_key", "{v}");
    assert!(v["detail"].as_str().unwrap().contains(&k.k1), "{v}");
    assert!(
        v["detail"]
            .as_str()
            .unwrap()
            .contains("--allow-drop-audit-key"),
        "{v}"
    );
    let report = h.get("/admin/audit/verify").await;
    assert_eq!(report["ok"], true, "{report}");
}

/// Tokens are minted, exchanged and checked while the keys flip between k1 and k2 (each time
/// with the other kept as retired): no request fails, since every token's key stays trusted.
/// Two reloads sent at once are both answered, one after the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tokens_during_reloads_never_fail() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let h = Arc::new(Harness::start().await);
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for _ in 0..3 {
        let (h, stop, done) = (h.clone(), stop.clone(), done.clone());
        workers.push(tokio::spawn(async move {
            let mut kids = std::collections::BTreeSet::new();
            while !stop.load(Ordering::Relaxed) {
                let parent = h.root().await;
                kids.insert(kid_of(&parent));
                let (status, v) = h.exchange(&parent).await;
                assert_eq!(status, StatusCode::OK, "{v}");
                let child = v["access_token"].as_str().unwrap().to_string();
                kids.insert(kid_of(&child));
                let (status, v) = h.exchange_as(&child, "tester").await;
                assert_eq!(status, StatusCode::OK, "{v}");
                done.fetch_add(1, Ordering::Relaxed);
            }
            kids
        }));
    }
    let mut seen_kids = std::collections::BTreeSet::new();
    for round in 0..12 {
        let (signing, previous) = if round % 2 == 0 {
            ("k2.pem", "k1.pem")
        } else {
            ("k1.pem", "k2.pem")
        };
        h.write(&File {
            signing: Some(signing),
            previous: &[previous],
            ..File::default()
        });
        let v = h.reload().await;
        seen_kids.insert(v["signing_kid"].as_str().unwrap().to_string());
        let jwks = h.jwks_kids().await;
        assert_eq!(jwks.len(), 2, "{jwks:?}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // Two at once: both answered, serialized.
    let (a, b) = tokio::join!(
        h.reload_with(LEGACY, json!({})),
        h.reload_with(LEGACY, json!({}))
    );
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(b.0, StatusCode::OK, "{}", b.1);
    stop.store(true, Ordering::Relaxed);
    let mut minted = std::collections::BTreeSet::new();
    for w in workers {
        minted.extend(w.await.unwrap());
    }
    assert!(done.load(Ordering::Relaxed) > 0);
    assert_eq!(seen_kids.len(), 2);
    assert_eq!(
        minted,
        [h.keys.k1.clone(), h.keys.k2.clone()].into_iter().collect(),
        "tokens were minted under both keys"
    );
    let report = h.get("/admin/audit/verify").await;
    assert_eq!(report["ok"], true, "{report}");
}
