//! `attenuo token exchange --subject-token-type id-token | id-jag` against a real server: hop 0
//! from a user's credential, signed here by a local IdP whose JWKS the server fetches.

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::process::{Command, Output, Stdio};

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::config::{AgentConfig, CapSpec, IdpConfig, RootGrant};
use attenuo_server::Config;
use attenuo_token::DpopKey;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use time::OffsetDateTime;

use common::{attenuo, sha256_hex};

const PLANNER_SECRET: &str = "hop0-test-planner-secret";
/// The client id the IdP knows the planner by: an ID token's `aud`.
const CLIENT_AUD: &str = "agent-platform";
/// The server's `[issuer] issuer`: an ID-JAG's `aud`, and a client assertion's.
const SERVER_ISSUER: &str = "https://attenuo.test";
/// What the planner asks for at hop 0: the `[[root_grants]]` ceiling, constraint included.
const CAP: &str = r#"{"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"prefix","value":"acme/"}}}"#;

/// Run the CLI off the async runtime (the server runs on it), with `stdin` on its stdin.
async fn run(mut cmd: Command, stdin: Option<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        {
            use std::io::Write;
            let mut pipe = child.stdin.take().unwrap();
            if let Some(s) = stdin {
                pipe.write_all(s.as_bytes()).unwrap();
            }
        }
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

fn ok(out: &Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

fn refused(out: &Output) -> String {
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).to_string()
}

/// A local IdP: one Ed25519 key, published as a JWKS at `/jwks`; its URL is the issuer.
struct Idp {
    issuer: String,
    key: DpopKey,
    _server: Spawned,
}

impl Idp {
    async fn start() -> Self {
        let key = DpopKey::generate().unwrap();
        let mut jwk = key.public_jwk().clone();
        jwk["kid"] = "idp-1".into();
        jwk["alg"] = "EdDSA".into();
        jwk["use"] = "sig".into();
        let app = Router::new().route(
            "/jwks",
            get(move || {
                let jwk = jwk.clone();
                async move { Json(json!({ "keys": [jwk] })) }
            }),
        );
        let server = spawn_router(app).await.unwrap();
        Self {
            issuer: server.url("").trim_end_matches('/').to_string(),
            key,
            _server: server,
        }
    }

    fn sign(&self, typ: &str, claims: &Value) -> String {
        let header = json!({"alg": "EdDSA", "kid": "idp-1", "typ": typ});
        self.key.sign_jws(&header, claims)
    }

    /// A fresh ID token for alice, issued to the agent platform, with a unique `jti`.
    fn id_token(&self, n: u32) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.sign(
            "JWT",
            &json!({
                "iss": self.issuer, "aud": CLIENT_AUD, "sub": "alice", "jti": format!("id-{n}"),
                "iat": now, "exp": now + 300, "email": "alice@example.com", "amr": ["pwd"],
            }),
        )
    }

    /// An ID-JAG for alice and the planner, bound to `jkt`.
    fn id_jag(&self, jkt: &str) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.sign(
            "oauth-id-jag+jwt",
            &json!({
                "iss": self.issuer, "aud": SERVER_ISSUER, "sub": "alice", "client_id": "planner",
                "jti": "jag-1", "iat": now, "exp": now + 300, "cnf": {"jkt": jkt},
            }),
        )
    }
}

/// A server that trusts `idp` for the planner, with the planner's `[[agents]]` entry `agent`.
async fn server(
    idp: &Idp,
    agent: AgentConfig,
    dir: &tempfile::TempDir,
) -> (Spawned, std::sync::Arc<attenuo_server::AppState>) {
    let mut cfg = Config::default();
    cfg.issuer.issuer = SERVER_ISSUER.into();
    cfg.issuer.private_key_pem_path = Some(dir.path().join("issuer.pem"));
    cfg.audit.sqlite_path = ":memory:".into();
    cfg.idps = vec![IdpConfig {
        issuer: idp.issuer.clone(),
        audience: String::new(),
        jwks_url: Some(format!("{}/jwks", idp.issuer)),
        allowed_algs: vec!["EdDSA".into()],
        attribute_claims: vec!["email".into(), "amr".into()],
        jwks_ttl_seconds: 300,
        clock_skew_seconds: 60,
        tenant: None,
        client_ids: BTreeMap::from([("planner".to_string(), CLIENT_AUD.to_string())]),
    }];
    cfg.agents = vec![agent];
    cfg.root_grants = vec![RootGrant {
        subject: None,
        issuer: idp.issuer.clone(),
        agent: "planner".into(),
        capabilities: vec![CapSpec::Full(serde_json::from_str(CAP).unwrap())],
        attributes: BTreeMap::new(),
        may_act: None,
    }];
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    (spawn_router(router).await.unwrap(), state)
}

/// `attenuo --server URL --json token exchange --subject-token-type TYPE --actor planner
/// --cap CAP` plus `extra`.
fn hop0(url: &str, ty: &str, extra: &[&str]) -> Command {
    let mut c = attenuo();
    c.args(["--server", url, "--json", "token", "exchange"])
        .args([
            "--subject-token-type",
            ty,
            "--actor",
            "planner",
            "--cap",
            CAP,
        ])
        .args(extra);
    c
}

/// An ID token exchanged through the CLI from each of the subject token's sources, with the
/// secret from each of its sources: a root token for alice and the planner, within the grant;
/// the same ID token again is refused.
#[tokio::test(flavor = "multi_thread")]
async fn an_id_token_becomes_a_root_token() {
    let dir = tempfile::tempdir().unwrap();
    let idp = Idp::start().await;
    let agent = AgentConfig::with_secret_sha256("planner", sha256_hex(PLANNER_SECRET));
    let (server, state) = server(&idp, agent, &dir).await;
    let url = server.url("").trim_end_matches('/').to_string();
    let verify = |token: &str| {
        state
            .verifier
            .verify(token, OffsetDateTime::now_utc())
            .unwrap()
    };

    // ID token in ATTENUO_TOKEN, secret in ATTENUO_CLIENT_SECRET.
    let first = idp.id_token(1);
    let mut c = hop0(&url, "id-token", &["--no-delegation"]);
    c.env("ATTENUO_TOKEN", &first)
        .env("ATTENUO_CLIENT_SECRET", PLANNER_SECRET);
    let resp: Value = serde_json::from_str(&ok(&run(c, None).await)).unwrap();
    let root = verify(resp["access_token"].as_str().unwrap());
    let hop = &root.chain.hops[0];
    assert_eq!(root.chain.hops.len(), 1);
    assert_eq!(hop.agent.0, "planner");
    let user = &root.chain.originating_user;
    assert_eq!(user.subject, "alice");
    assert_eq!(user.issuer, idp.issuer);
    assert_eq!(user.attributes["email"], "alice@example.com");
    let caps = serde_json::to_value(&hop.capabilities).unwrap();
    assert_eq!(caps, json!([serde_json::from_str::<Value>(CAP).unwrap()]));
    assert_eq!(root.claims.may_act.map(|m| m.sub), Some(Vec::new()));
    assert!(root.claims.cnf.is_none());

    // The same ID token again: each IdP credential mints one root token.
    let mut c = hop0(&url, "id-token", &[]);
    c.env("ATTENUO_TOKEN", &first)
        .env("ATTENUO_CLIENT_SECRET", PLANNER_SECRET);
    let err = refused(&run(c, None).await);
    // The stable code (`replayed`) is named after the OAuth error.
    assert!(
        err.contains("400 Bad Request: invalid_grant (replayed): this credential was already used"),
        "{err}"
    );

    // ID token on stdin (`--subject-token -`), secret from a file.
    let secret_file = dir.path().join("secret");
    std::fs::write(&secret_file, format!("{PLANNER_SECRET}\n")).unwrap();
    let mut c = hop0(&url, "id-token", &["--subject-token", "-"]);
    c.arg("--client-secret-file").arg(&secret_file);
    let resp: Value =
        serde_json::from_str(&ok(&run(c, Some(format!("{}\n", idp.id_token(2)))).await)).unwrap();
    assert_eq!(
        verify(resp["access_token"].as_str().unwrap())
            .chain
            .originating_user
            .subject,
        "alice"
    );

    // ID token from a file, secret on stdin, `--print token`.
    let token_file = dir.path().join("id_token");
    std::fs::write(&token_file, format!("{}\n", idp.id_token(3))).unwrap();
    let mut c = attenuo();
    c.args(["--server", &url, "token", "exchange"])
        .args(["--subject-token-type", "id-token", "--actor", "planner"])
        .args(["--cap", CAP, "--client-secret-stdin", "--print", "token"])
        .arg("--subject-token-file")
        .arg(&token_file);
    let printed = ok(&run(c, Some(format!("{PLANNER_SECRET}\n"))).await);
    assert_eq!(verify(printed.trim()).chain.hops.len(), 1);

    // A request for more than the grant (no constraint) is refused by the server.
    let mut c = attenuo();
    c.args(["--server", &url, "token", "exchange"])
        .args(["--subject-token-type", "id-token", "--actor", "planner"])
        .args(["--cap", "github:get_file_contents"]);
    c.env("ATTENUO_TOKEN", idp.id_token(4))
        .env("ATTENUO_CLIENT_SECRET", PLANNER_SECRET);
    let err = refused(&run(c, None).await);
    assert!(err.contains("400 Bad Request: invalid_scope"), "{err}");

    // Without the flag the CLI sends an attenuo token's type, as before, and the server
    // refuses the ID token as one.
    let mut c = attenuo();
    c.args(["--server", &url, "token", "exchange"])
        .args(["--actor", "planner", "--cap", CAP]);
    c.env("ATTENUO_TOKEN", idp.id_token(5))
        .env("ATTENUO_CLIENT_SECRET", PLANNER_SECRET);
    let err = refused(&run(c, None).await);
    assert!(err.contains("invalid_grant"), "{err}");

    // A parent's sign-off has no meaning at hop 0: refused before anything is sent.
    let mut c = hop0(
        &url,
        "id-token",
        &["--subject-token-dpop-file", "/nonexistent"],
    );
    c.env("ATTENUO_TOKEN", idp.id_token(6))
        .env("ATTENUO_CLIENT_SECRET", PLANNER_SECRET);
    let err = refused(&run(c, None).await);
    assert!(err.contains("at hop 0"), "{err}");
}

/// An ID-JAG bound to a DPoP key, with the agent authenticating by `private_key_jwt`: the
/// root token is bound to the same key.
#[tokio::test(flavor = "multi_thread")]
async fn a_bound_id_jag_with_a_client_key_becomes_a_bound_root_token() {
    let dir = tempfile::tempdir().unwrap();
    let idp = Idp::start().await;
    let client_key = DpopKey::generate().unwrap();
    let mut public = client_key.public_jwk().clone();
    public["kid"] = "planner-1".into();
    let mut private = client_key.private_jwk();
    private["kid"] = "planner-1".into();
    let client_key_file = dir.path().join("planner.jwk");
    std::fs::write(&client_key_file, private.to_string()).unwrap();
    let agent = AgentConfig::with_jwks("planner", json!({ "keys": [public] }).to_string());
    let (server, state) = server(&idp, agent, &dir).await;
    let url = server.url("").trim_end_matches('/').to_string();

    let dpop = DpopKey::generate().unwrap();
    let dpop_file = dir.path().join("dpop.jwk");
    std::fs::write(&dpop_file, dpop.private_jwk().to_string()).unwrap();
    let jag = idp.id_jag(dpop.thumbprint());

    // A client assertion's audience cannot come from the IdP's credential.
    let mut c = hop0(&url, "id-jag", &[]);
    c.env("ATTENUO_TOKEN", &jag)
        .arg("--client-key")
        .arg(&client_key_file)
        .arg("--dpop-key")
        .arg(&dpop_file);
    let err = refused(&run(c, None).await);
    assert!(err.contains("--client-assertion-audience"), "{err}");

    let mut c = hop0(
        &url,
        "id-jag",
        &["--client-assertion-audience", SERVER_ISSUER],
    );
    c.env("ATTENUO_TOKEN", &jag)
        .arg("--client-key")
        .arg(&client_key_file)
        .arg("--dpop-key")
        .arg(&dpop_file);
    let resp: Value = serde_json::from_str(&ok(&run(c, None).await)).unwrap();
    assert_eq!(resp["token_type"], "DPoP", "{resp}");
    let root = state
        .verifier
        .verify(
            resp["access_token"].as_str().unwrap(),
            OffsetDateTime::now_utc(),
        )
        .unwrap();
    assert_eq!(root.chain.originating_user.subject, "alice");
    assert_eq!(root.chain.hops[0].agent.0, "planner");
    assert_eq!(
        root.claims.cnf.map(|c| c.jkt).as_deref(),
        Some(dpop.thumbprint())
    );
}
