//! `[[agents]]` and `[[peps]]` `jwks_url`: a client publishes its `private_key_jwt` keys at a
//! URL (ADR-0017, update of 2026-11-22). Covers an agent at an exchange and at hop 0 and a
//! PEP at AuthZEN with keys from the URL; key rotation (a new key through the unknown-`kid`
//! refetch, a removed key refused after the TTL); a URL that is down or hangs (refused, and
//! other clients go on); the refetch limit under a flood of made-up `kid`s; no redirects; key
//! sets that are too large, not JSON or hold a private key; `ca_pem_path`; `jwks` and
//! `jwks_url` together refused at startup and at a reload; a reload that moves the URL; the
//! SR-110 comparison of refusals; and single use of an assertion.
//!
//! The mock key server counts the requests of each path, so the tests can say when the
//! server fetched and when it did not.

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::{AppState, Config};
use attenuo_token::client_assertion::{self, CLIENT_ASSERTION_TYPE};
use attenuo_token::DpopKey;
use axum::extract::{Path as UrlPath, State};
use axum::http::{header, StatusCode as AxumStatus};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use reqwest::StatusCode;
use serde_json::{json, Value};

use common::sha256_hex;
use common::tls::{Ca, TlsKeyServer};

const ADMIN: &str = "test-admin-token";
/// `[issuer] issuer`: the `aud` of a client assertion.
const ISSUER: &str = "https://attenuo.test";
const IDP: &str = "https://idp.test";
const CLIENT_AUD: &str = "attenuo-client";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
const REFUSED: &str = "client_authentication_failed";

// --- the mock key server ------------------------------------------------------------------

/// What the mock answers on a path.
#[derive(Clone)]
enum Answer {
    Json(Value),
    Text(&'static str),
    Status(u16),
    /// A 302 to another path of the mock.
    Redirect(&'static str),
    /// No answer for a minute: longer than the server's fetch timeout.
    Hang,
}

#[derive(Default)]
struct Paths {
    answers: HashMap<String, Answer>,
    hits: HashMap<String, usize>,
}

/// An HTTP key server on 127.0.0.1 (plain http on loopback is accepted for key URLs, for
/// tests): `GET /<name>` answers what [`KeyServer::set`] stored for the name, 404 otherwise.
struct KeyServer {
    server: Spawned,
    paths: Arc<Mutex<Paths>>,
}

impl KeyServer {
    async fn start() -> Self {
        let paths: Arc<Mutex<Paths>> = Arc::default();
        async fn serve(
            State(paths): State<Arc<Mutex<Paths>>>,
            UrlPath(name): UrlPath<String>,
        ) -> Response {
            let answer = {
                let mut p = paths.lock().unwrap();
                *p.hits.entry(name.clone()).or_default() += 1;
                p.answers.get(&name).cloned()
            };
            match answer {
                Some(Answer::Json(v)) => axum::Json(v).into_response(),
                Some(Answer::Text(t)) => t.into_response(),
                Some(Answer::Status(s)) => AxumStatus::from_u16(s).unwrap().into_response(),
                Some(Answer::Redirect(to)) => {
                    (AxumStatus::FOUND, [(header::LOCATION, to)]).into_response()
                }
                Some(Answer::Hang) => {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    AxumStatus::OK.into_response()
                }
                None => AxumStatus::NOT_FOUND.into_response(),
            }
        }
        let app = Router::new()
            .route("/{name}", get(serve))
            .with_state(paths.clone());
        Self {
            server: spawn_router(app).await.unwrap(),
            paths,
        }
    }

    fn url(&self, name: &str) -> String {
        self.server.url(&format!("/{name}"))
    }

    fn set(&self, name: &str, answer: Answer) {
        self.paths
            .lock()
            .unwrap()
            .answers
            .insert(name.into(), answer);
    }

    fn serve_keys(&self, name: &str, keys: &[&Key]) {
        self.set(name, Answer::Json(jwk_set(keys)));
    }

    fn hits(&self, name: &str) -> usize {
        self.paths
            .lock()
            .unwrap()
            .hits
            .get(name)
            .copied()
            .unwrap_or(0)
    }

    fn total_hits(&self) -> usize {
        self.paths.lock().unwrap().hits.values().sum()
    }
}

// --- keys and assertions ------------------------------------------------------------------

/// A client's Ed25519 key pair and the `kid` its public half has in the published set.
struct Key {
    key: DpopKey,
    kid: String,
}

impl Key {
    fn new(kid: &str) -> Self {
        Self {
            key: DpopKey::generate().unwrap(),
            kid: kid.into(),
        }
    }

    fn public(&self) -> Value {
        let mut jwk = self.key.public_jwk().clone();
        jwk["kid"] = self.kid.as_str().into();
        jwk
    }

    /// A fresh assertion for `client`, as the CLI makes it.
    fn assertion(&self, client: &str) -> String {
        self.assertion_with_kid(client, &self.kid)
    }

    /// A fresh assertion for `client` whose header names `kid`.
    fn assertion_with_kid(&self, client: &str, kid: &str) -> String {
        client_assertion::sign(
            &self.key,
            Some(kid),
            client,
            ISSUER,
            client_assertion::DEFAULT_LIFETIME,
            time::OffsetDateTime::now_utc(),
        )
    }
}

fn jwk_set(keys: &[&Key]) -> Value {
    json!({ "keys": keys.iter().map(|k| k.public()).collect::<Vec<_>>() })
}

fn fields(assertion: &str) -> Value {
    json!({"client_assertion_type": CLIENT_ASSERTION_TYPE, "client_assertion": assertion})
}

/// An IdP for hop 0: an EdDSA key whose set the mock serves at `/idp`.
struct Idp {
    key: DpopKey,
}

impl Idp {
    fn new(keys: &KeyServer) -> Self {
        let key = DpopKey::generate().unwrap();
        let mut jwk = key.public_jwk().clone();
        jwk["kid"] = "idp-1".into();
        keys.set("idp", Answer::Json(json!({ "keys": [jwk] })));
        Self { key }
    }

    fn id_token(&self, sub: &str) -> String {
        let t = time::OffsetDateTime::now_utc().unix_timestamp();
        self.key.sign_jws(
            &json!({"alg": "EdDSA", "kid": "idp-1", "typ": "JWT"}),
            &json!({"iss": IDP, "aud": CLIENT_AUD, "sub": sub, "iat": t, "exp": t + 300,
                    "jti": uuid::Uuid::new_v4().to_string()}),
        )
    }
}

// --- config files and the server ----------------------------------------------------------

/// An `[[agents]]` entry with a secret.
fn agent_secret(id: &str, secret: &str) -> String {
    format!(
        "[[agents]]\nid = \"{id}\"\nsecret_sha256 = \"{}\"\n",
        sha256_hex(secret)
    )
}

/// An `[[agents]]` (or `[[peps]]`, with `list`) entry whose keys are at `url`, with `more`
/// lines (`jwks_ttl_seconds`, `ca_pem_path`).
fn remote(list: &str, id: &str, url: &str, more: &str) -> String {
    format!("[[{list}]]\nid = \"{id}\"\njwks_url = \"{url}\"\n{more}\n")
}

/// Write `<dir>/attenuo.toml`: the issuer, the audit file, the admin token, the dev root mint,
/// an IdP whose keys are at `<keys>/idp` (`coder`'s ID tokens carry aud `attenuo-client`),
/// root grants for `planner` and `coder`, then `lists`. Replaced in one rename, so a reload
/// never reads half of it.
fn write_config(dir: &Path, keys: &KeyServer, lists: &str) -> PathBuf {
    let path = dir.join("attenuo.toml");
    let tmp = dir.join("attenuo.toml.tmp");
    let grant = |agent: &str| {
        format!(
            "[[root_grants]]\nissuer = \"{IDP}\"\nagent = \"{agent}\"\n\
             capabilities = [\"github:*\"]\n"
        )
    };
    std::fs::write(
        &tmp,
        format!(
            "[issuer]\nissuer = \"{ISSUER}\"\nprivate_key_pem_path = \"{}\"\n\n\
             [audit]\nsqlite_path = \"{}\"\n\n\
             [admin]\ntoken = \"{ADMIN}\"\n\n\
             [dev]\nallow_root_mint = true\n\n\
             [[idps]]\nissuer = \"{IDP}\"\njwks_url = \"{}\"\nallowed_algs = [\"EdDSA\"]\n\
             client_ids = {{ coder = \"{CLIENT_AUD}\" }}\n\n{}{}\n{lists}",
            dir.join("keys/issuer.pem").display(),
            dir.join("audit.sqlite").display(),
            keys.url("idp"),
            grant("planner"),
            grant("coder"),
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
    /// A root token for `planner` from the dev mint, the bearer of AuthZEN requests.
    root: String,
}

impl Harness {
    /// A server started from the config file at `path`, as `attenuo-server --config` does.
    async fn start(path: &Path) -> Self {
        let cfg = Config::load(path).unwrap();
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let server = spawn_router(router).await.unwrap();
        let client = reqwest::Client::new();
        let root = mint_root(&client, &server).await;
        Self {
            root,
            server,
            state,
            client,
        }
    }

    async fn post(&self, path: &str, body: &Value) -> reqwest::Response {
        self.client
            .post(self.server.url(path))
            .json(body)
            .send()
            .await
            .unwrap()
    }

    /// Exchange a fresh root token (a parent delegates to an actor once) for a child for
    /// `actor`, authenticated by `auth` (body fields).
    async fn exchange(&self, actor: &str, auth: Value) -> reqwest::Response {
        let parent = mint_root(&self.client, &self.server).await;
        let mut body = json!({
            "grant_type": EXCHANGE, "subject_token": parent, "subject_token_type": JWT,
            "actor": actor,
            "authorization_details": [{"type": "attenuo_capabilities",
                "capabilities": [{"server": "github", "tool": "read_file"}]}],
        });
        for (k, v) in auth.as_object().unwrap() {
            body[k] = v.clone();
        }
        self.post("/token", &body).await
    }

    /// [`exchange`](Self::exchange) with an assertion: the status and the sub-code.
    async fn exchange_as(&self, actor: &str, assertion: &str) -> (StatusCode, String) {
        answer(self.exchange(actor, fields(assertion)).await).await
    }

    /// Hop 0: an ID token of `idp`, the agent authenticating with `assertion`.
    async fn intake(&self, idp: &Idp, assertion: &str) -> reqwest::Response {
        let mut body = json!({
            "grant_type": EXCHANGE, "subject_token": idp.id_token("alice"),
            "subject_token_type": ID_TOKEN,
            "authorization_details": [{"type": "attenuo_capabilities",
                "capabilities": [{"server": "github", "tool": "read_file"}]}],
        });
        for (k, v) in fields(assertion).as_object().unwrap() {
            body[k] = v.clone();
        }
        self.post("/token", &body).await
    }

    /// An AuthZEN evaluation with the root token, the PEP authenticating with `assertion`:
    /// the status and the sub-code.
    async fn evaluate_as_pep(&self, assertion: &str) -> (StatusCode, String) {
        let resp = self
            .client
            .post(self.server.url("/access/v1/evaluation"))
            .bearer_auth(&self.root)
            .json(&json!({
                "subject": {"type": "agent", "id": ""},
                "action": {"name": "read_file"},
                "resource": {"type": "tool", "id": "github/read_file",
                             "properties": {"server": "github"}},
                "context": {"input": {}},
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": assertion,
            }))
            .send()
            .await
            .unwrap();
        answer(resp).await
    }

    async fn reload(&self) -> (StatusCode, Value) {
        let resp = self
            .client
            .post(self.server.url("/admin/agents/reload"))
            .bearer_auth(ADMIN)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }
}

/// A root token for `planner` from the dev mint.
async fn mint_root(client: &reqwest::Client, server: &Spawned) -> String {
    let resp = client
        .post(server.url("/admin/root-token"))
        .bearer_auth(ADMIN)
        .json(
            &json!({"subject": "alice", "issuer": IDP, "agent": "planner",
                      "capabilities": ["github:*"]}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    v["access_token"].as_str().unwrap().into()
}

/// The status and the `error_description` of an answer (`""` for a success).
async fn answer(resp: reqwest::Response) -> (StatusCode, String) {
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    let code = v["error_description"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    (status, code)
}

/// The status, the headers (all but `date`) and the body bytes of an answer.
async fn whole(resp: reqwest::Response) -> (StatusCode, Vec<(String, String)>, String) {
    let status = resp.status();
    let mut headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter(|(k, _)| *k != reqwest::header::DATE)
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_owned()))
        .collect();
    headers.sort();
    (status, headers, resp.text().await.unwrap())
}

const OK: (StatusCode, &str) = (StatusCode::OK, "");
const NOT_AUTHENTICATED: (StatusCode, &str) = (StatusCode::UNAUTHORIZED, REFUSED);

fn is(got: &(StatusCode, String), want: (StatusCode, &str)) -> bool {
    got.0 == want.0 && got.1 == want.1
}

/// Polls `f` until it is true; panics after 20 seconds.
async fn eventually<F: std::future::Future<Output = bool>>(mut f: impl FnMut() -> F) {
    let end = Instant::now() + Duration::from_secs(20);
    while !f().await {
        assert!(Instant::now() < end, "timed out");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// --- logs ---------------------------------------------------------------------------------

/// What the server logged at WARN and above, for every test of this binary.
static LOGS: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct LogWriter;

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOGS.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Installs, once per process, a global subscriber that keeps WARN lines in [`LOGS`] (as
/// `key_url_ca.rs` does). A test finds its own lines by the key URL, whose port is its own.
fn capture_logs() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(|| LogWriter)
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("no other test in this binary installs a subscriber");
    });
}

/// The logged lines that report a failed fetch of `url`.
fn fetch_failures(url: &str) -> Vec<String> {
    let logs = String::from_utf8_lossy(&LOGS.lock().unwrap()).into_owned();
    logs.lines()
        .filter(|l| l.contains("client JWKS unavailable") && l.contains(url))
        .map(str::to_owned)
        .collect()
}

// --- tests --------------------------------------------------------------------------------

/// An agent authenticates with a key from its URL at an exchange and at hop 0, and a PEP at
/// the AuthZEN endpoint. The set is fetched once and then cached. A secret-only agent and an
/// unknown id cause no fetch at all.
#[tokio::test]
async fn an_agent_and_a_pep_authenticate_with_keys_from_their_urls() {
    let keys = KeyServer::start().await;
    let idp = Idp::new(&keys);
    let (coder, gateway) = (Key::new("coder-1"), Key::new("gw-1"));
    keys.serve_keys("coder", &[&coder]);
    keys.serve_keys("gateway", &[&gateway]);
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        &keys,
        &(agent_secret("planner", "planner-secret")
            + &remote("agents", "coder", &keys.url("coder"), "")
            + &remote("peps", "gateway", &keys.url("gateway"), "")),
    );
    let h = Harness::start(&path).await;
    // Nothing is fetched at startup.
    assert_eq!(keys.hits("coder") + keys.hits("gateway"), 0);

    for _ in 0..3 {
        let got = h.exchange_as("coder", &coder.assertion("coder")).await;
        assert!(is(&got, OK), "{got:?}");
    }
    let (status, _, v) = whole(h.intake(&idp, &coder.assertion("coder")).await).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(keys.hits("coder"), 1, "the set is cached");

    let got = h.evaluate_as_pep(&gateway.assertion("gateway")).await;
    assert!(is(&got, OK), "{got:?}");
    assert_eq!(keys.hits("gateway"), 1);
    // A PEP's keys are not an agent's, and the other way round.
    let got = h.evaluate_as_pep(&coder.assertion("coder")).await;
    assert!(is(&got, NOT_AUTHENTICATED), "{got:?}");
    let got = h
        .exchange_as("gateway", &gateway.assertion("gateway"))
        .await;
    assert!(is(&got, NOT_AUTHENTICATED), "{got:?}");

    // No fetch for an id that is not configured with jwks_url.
    let before = keys.total_hits();
    for id in ["nobody", "planner"] {
        let got = h.exchange_as(id, &coder.assertion(id)).await;
        assert!(is(&got, NOT_AUTHENTICATED), "{id}: {got:?}");
    }
    assert_eq!(keys.total_hits(), before);
}

/// An assertion authenticates one request, also when the key came from a URL.
#[tokio::test]
async fn a_replayed_assertion_is_refused() {
    let keys = KeyServer::start().await;
    let (coder, gateway) = (Key::new("c"), Key::new("g"));
    keys.serve_keys("coder", &[&coder]);
    keys.serve_keys("gateway", &[&gateway]);
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(&write_config(
        dir.path(),
        &keys,
        &(agent_secret("planner", "p")
            + &remote("agents", "coder", &keys.url("coder"), "")
            + &remote("peps", "gateway", &keys.url("gateway"), "")),
    ))
    .await;
    let a = coder.assertion("coder");
    assert!(is(&h.exchange_as("coder", &a).await, OK));
    let got = h.exchange_as("coder", &a).await;
    assert_eq!(
        got,
        (StatusCode::UNAUTHORIZED, "client_assertion_replayed".into())
    );
    let a = gateway.assertion("gateway");
    assert!(is(&h.evaluate_as_pep(&a).await, OK));
    let got = h.evaluate_as_pep(&a).await;
    assert_eq!(
        got,
        (StatusCode::UNAUTHORIZED, "client_assertion_replayed".into())
    );
}

/// Rotation without a config change: a key added to the set works at once (an unknown `kid`
/// fetches the set again), and a key removed from it stops working once the TTL has passed.
#[tokio::test]
async fn keys_rotate_at_the_url_without_a_config_change() {
    let keys = KeyServer::start().await;
    let (old, new) = (Key::new("2026-10"), Key::new("2026-11"));
    keys.serve_keys("long", &[&old]);
    keys.serve_keys("short", &[&old]);
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(&write_config(
        dir.path(),
        &keys,
        &(agent_secret("planner", "p")
            + &remote(
                "agents",
                "long",
                &keys.url("long"),
                "jwks_ttl_seconds = 3600",
            )
            + &remote(
                "agents",
                "short",
                &keys.url("short"),
                "jwks_ttl_seconds = 1",
            )),
    ))
    .await;
    assert!(is(&h.exchange_as("long", &old.assertion("long")).await, OK));
    assert_eq!(keys.hits("long"), 1);
    // A new key, long before the TTL: the unknown kid fetches the set once more.
    keys.serve_keys("long", &[&old, &new]);
    let got = h.exchange_as("long", &new.assertion("long")).await;
    assert!(is(&got, OK), "{got:?}");
    assert_eq!(keys.hits("long"), 2);
    assert!(is(&h.exchange_as("long", &old.assertion("long")).await, OK));
    assert_eq!(keys.hits("long"), 2);

    // The old key is removed: refused once the one-second TTL has passed.
    assert!(is(
        &h.exchange_as("short", &old.assertion("short")).await,
        OK
    ));
    keys.serve_keys("short", &[&new]);
    eventually(|| async {
        is(
            &h.exchange_as("short", &old.assertion("short")).await,
            NOT_AUTHENTICATED,
        )
    })
    .await;
    assert!(is(
        &h.exchange_as("short", &new.assertion("short")).await,
        OK
    ));
}

/// A flood of assertions with made-up `kid`s, which anyone can send, fetches the set at most
/// once more within the refetch cooldown, and the client's real key keeps working.
#[tokio::test]
async fn a_flood_of_unknown_kids_fetches_the_set_at_most_once_more() {
    let keys = KeyServer::start().await;
    let coder = Key::new("real");
    keys.serve_keys("coder", &[&coder]);
    let dir = tempfile::tempdir().unwrap();
    let h = Arc::new(
        Harness::start(&write_config(
            dir.path(),
            &keys,
            &(agent_secret("planner", "p") + &remote("agents", "coder", &keys.url("coder"), "")),
        ))
        .await,
    );
    let stranger = Arc::new(Key::new("x"));
    for wave in 0..2 {
        let tasks: Vec<_> = (0..25)
            .map(|i| {
                let (h, stranger) = (h.clone(), stranger.clone());
                tokio::spawn(async move {
                    let a = stranger.assertion_with_kid("coder", &format!("made-up-{wave}-{i}"));
                    h.exchange_as("coder", &a).await
                })
            })
            .collect();
        for t in tasks {
            let got = t.await.unwrap();
            assert!(is(&got, NOT_AUTHENTICATED), "{got:?}");
        }
    }
    assert!(
        (1..=2).contains(&keys.hits("coder")),
        "{} fetches",
        keys.hits("coder")
    );
    let fetched = keys.hits("coder");
    assert!(is(
        &h.exchange_as("coder", &coder.assertion("coder")).await,
        OK
    ));
    assert_eq!(keys.hits("coder"), fetched);
}

/// A client whose URL is down, answers an error or hangs is refused, with the answer an
/// unknown client gets, and the cause in a WARN line; other clients are not held up, and the
/// failed fetch is not tried again at once.
#[tokio::test]
async fn a_client_whose_keys_cannot_be_fetched_is_refused_and_others_go_on() {
    capture_logs();
    let keys = KeyServer::start().await;
    let coder = Key::new("c");
    keys.serve_keys("coder", &[&coder]);
    keys.set("down", Answer::Status(500));
    keys.set("stuck", Answer::Hang);
    // A port nobody listens on.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://127.0.0.1:{}/jwks", l.local_addr().unwrap().port())
    };
    let dir = tempfile::tempdir().unwrap();
    let h = Arc::new(
        Harness::start(&write_config(
            dir.path(),
            &keys,
            &(agent_secret("planner", "p")
                + &remote("agents", "coder", &keys.url("coder"), "")
                + &remote("agents", "down", &keys.url("down"), "")
                + &remote("agents", "closed", &closed, "")
                + &remote("agents", "stuck", &keys.url("stuck"), "")),
        ))
        .await,
    );
    for id in ["down", "closed"] {
        let got = h.exchange_as(id, &coder.assertion(id)).await;
        assert!(is(&got, NOT_AUTHENTICATED), "{id}: {got:?}");
    }
    let lines = fetch_failures(&keys.url("down"));
    assert!(!lines.is_empty(), "no WARN line for the failed fetch");
    assert!(lines[0].contains("HTTP 500"), "{}", lines[0]);
    assert!(fetch_failures(&closed)[0].contains("error sending request"));
    // Within the failure backoff the next assertion is refused without a fetch.
    let got = h.exchange_as("down", &coder.assertion("down")).await;
    assert!(is(&got, NOT_AUTHENTICATED), "{got:?}");
    assert_eq!(keys.hits("down"), 1);

    // While a fetch hangs, other clients authenticate.
    let stuck = {
        let (h, a) = (h.clone(), coder.assertion("stuck"));
        tokio::spawn(async move { h.exchange_as("stuck", &a).await })
    };
    eventually(|| async { keys.hits("stuck") == 1 }).await;
    assert!(is(
        &h.exchange_as("coder", &coder.assertion("coder")).await,
        OK
    ));
    assert!(!stuck.is_finished(), "the hanging fetch was not waited for");
    // It ends with the fetch timeout, and the request is refused.
    let got = stuck.await.unwrap();
    assert!(is(&got, NOT_AUTHENTICATED), "{got:?}");
}

/// A redirect is not followed: the fetch fails, and the target is never asked.
#[tokio::test]
async fn a_redirect_is_not_followed() {
    capture_logs();
    let keys = KeyServer::start().await;
    let coder = Key::new("c");
    keys.serve_keys("target", &[&coder]);
    keys.set("moved", Answer::Redirect("/target"));
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(&write_config(
        dir.path(),
        &keys,
        &(agent_secret("planner", "p") + &remote("agents", "coder", &keys.url("moved"), "")),
    ))
    .await;
    let got = h.exchange_as("coder", &coder.assertion("coder")).await;
    assert!(is(&got, NOT_AUTHENTICATED), "{got:?}");
    assert_eq!(keys.hits("moved"), 1);
    assert_eq!(keys.hits("target"), 0);
    assert!(fetch_failures(&keys.url("moved"))[0].contains("redirects are not followed"));
}

/// A set that is too large, not JSON, not a JWK Set, or that holds a private or symmetric
/// key, too many keys or a short RSA key is refused whole, by the rules of an inline `jwks`:
/// the client is not authenticated, also by a good key beside the bad one. The WARN line
/// names the problem, never a private value.
#[tokio::test]
async fn bad_key_sets_are_refused() {
    capture_logs();
    let keys = KeyServer::start().await;
    let good = Key::new("good");
    let private = Key::new("leaked");
    let d = private.key.private_jwk()["d"].as_str().unwrap().to_owned();
    let mut leaked = private.key.private_jwk();
    leaked["kid"] = "leaked".into();
    let padding = "x".repeat(300 * 1024);
    let many: Vec<Value> = (0..9)
        .map(|i| Key::new(&format!("k{i}")).public())
        .collect();
    let cases: Vec<(&str, Answer, &str)> = vec![
        (
            "big",
            Answer::Json(json!({"keys": [good.public()], "padding": padding})),
            "document too large",
        ),
        (
            "garbage",
            Answer::Text("<html>not a key set</html>"),
            "expected value",
        ),
        ("nokeys", Answer::Json(json!({"no": "keys"})), "JWK Set"),
        ("empty", Answer::Json(json!({"keys": []})), "empty"),
        (
            "private",
            Answer::Json(json!({"keys": [good.public(), leaked]})),
            "private key member `d`",
        ),
        (
            "oct",
            Answer::Json(
                json!({"keys": [good.public(), {"kty": "oct", "kid": "h", "k": "c2VjcmV0"}]}),
            ),
            "symmetric",
        ),
        ("many", Answer::Json(json!({ "keys": many })), "at most 8"),
        (
            "weak",
            Answer::Json(json!({"keys": [{"kty": "RSA", "kid": "good", "e": "AQAB",
                "n": base64_url(&[0xC5; 128])}]})),
            "2048",
        ),
    ];
    let mut lists = agent_secret("planner", "p");
    for (name, answer, _) in &cases {
        keys.set(name, answer.clone());
        lists += &remote("agents", name, &keys.url(name), "");
    }
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(&write_config(dir.path(), &keys, &lists)).await;
    for (name, _, why) in &cases {
        let got = h.exchange_as(name, &good.assertion(name)).await;
        assert!(is(&got, NOT_AUTHENTICATED), "{name}: {got:?}");
        let lines = fetch_failures(&keys.url(name));
        assert!(!lines.is_empty(), "{name}: no WARN line");
        assert!(lines[0].contains(why), "{name}: {}", lines[0]);
        assert!(
            !lines[0].contains(&d),
            "{name}: the private value is logged"
        );
    }
    let all = String::from_utf8_lossy(&LOGS.lock().unwrap()).into_owned();
    assert!(!all.contains(&d), "the private value is logged");
}

/// `bytes` as base64url without padding.
fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// `ca_pem_path`: a URL whose certificate a private CA issued is trusted with the CA in the
/// entry's file, and refused without it.
#[tokio::test]
async fn ca_pem_path_trusts_a_private_ca_for_that_entry() {
    let ca = Ca::new("attenuo test CA");
    let tls = TlsKeyServer::start(&ca).await;
    let coder = Key::new("c");
    tls.serve("/jwks", jwk_set(&[&coder]));
    let keys = KeyServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let ca_file = ca.write(dir.path(), "ca.pem");
    let h = Harness::start(&write_config(
        dir.path(),
        &keys,
        &(agent_secret("planner", "p")
            + &remote(
                "agents",
                "trusting",
                &tls.url("/jwks"),
                &format!("ca_pem_path = \"{}\"", ca_file.display()),
            )
            + &remote("agents", "plain", &tls.url("/jwks"), "")),
    ))
    .await;
    assert!(is(
        &h.exchange_as("trusting", &coder.assertion("trusting"))
            .await,
        OK
    ));
    let got = h.exchange_as("plain", &coder.assertion("plain")).await;
    assert!(is(&got, NOT_AUTHENTICATED), "{got:?}");
    assert_eq!(tls.hits("/jwks"), 1, "the untrusted fetch sent no request");
}

/// `jwks` and `jwks_url` on one entry are refused at startup and by a reload, with the same
/// message; so is a plain-http URL off loopback.
#[tokio::test]
async fn inline_keys_with_a_url_are_refused_at_startup_and_at_a_reload() {
    let keys = KeyServer::start().await;
    let k = Key::new("k");
    let both = format!(
        "[[agents]]\nid = \"coder\"\njwks = '''{}'''\njwks_url = \"{}\"\n",
        jwk_set(&[&k]),
        keys.url("coder")
    );
    let want = "[[agents]] `coder`: set jwks or jwks_url, not both";
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), &keys, &(agent_secret("planner", "p") + &both));
    let cfg = Config::load(&path).unwrap();
    let e = attenuo_server::build(&cfg).err().unwrap().to_string();
    assert!(e.starts_with(want), "{e}");

    let path = write_config(dir.path(), &keys, &agent_secret("planner", "p"));
    let h = Harness::start(&path).await;
    for (lists, want) in [
        (both.clone(), want.to_owned()),
        (
            remote("agents", "coder", "http://keys.example/jwks", ""),
            "[[agents]] `coder`: jwks_url \"http://keys.example/jwks\": must be https://".into(),
        ),
    ] {
        write_config(dir.path(), &keys, &(agent_secret("planner", "p") + &lists));
        let (status, v) = h.reload().await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert_eq!(v["code"], "agents_invalid", "{v}");
        assert!(v["detail"].as_str().unwrap().contains(&want), "{v}");
    }
    assert_eq!(keys.total_hits(), 0);
}

/// A reload that moves a client to another URL drops the keys of the old one at once, with no
/// TTL to wait for; one that removes the client refuses it from the next request on. The
/// answer counts the URL as a change, and the list digest covers it.
#[tokio::test]
async fn a_reload_that_moves_the_url_drops_the_old_keys_at_once() {
    let keys = KeyServer::start().await;
    let (a, b) = (Key::new("a"), Key::new("b"));
    keys.serve_keys("a", &[&a]);
    keys.serve_keys("b", &[&b]);
    let dir = tempfile::tempdir().unwrap();
    let planner = agent_secret("planner", "p");
    let at = |url: &str| remote("agents", "coder", url, "jwks_ttl_seconds = 3600");
    let h = Harness::start(&write_config(
        dir.path(),
        &keys,
        &(planner.clone() + &at(&keys.url("a"))),
    ))
    .await;
    assert!(is(&h.exchange_as("coder", &a.assertion("coder")).await, OK));

    write_config(dir.path(), &keys, &(planner.clone() + &at(&keys.url("b"))));
    let (status, v) = h.reload().await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["agents"]["changed"], json!(["coder"]), "{v}");
    let canonical = json!([
        ["coder", null, [], keys.url("b")],
        ["planner", sha256_hex("p"), []],
    ]);
    assert_eq!(
        v["agents"]["sha256"],
        sha256_hex(&canonical.to_string()),
        "{v}"
    );
    let got = h.exchange_as("coder", &a.assertion("coder")).await;
    assert!(is(&got, NOT_AUTHENTICATED), "{got:?}");
    assert!(is(&h.exchange_as("coder", &b.assertion("coder")).await, OK));
    assert_eq!(keys.hits("b"), 1);

    write_config(dir.path(), &keys, &planner);
    let (status, v) = h.reload().await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["agents"]["removed"], json!(["coder"]), "{v}");
    let got = h.exchange_as("coder", &b.assertion("coder")).await;
    assert!(is(&got, NOT_AUTHENTICATED), "{got:?}");
    assert_eq!(keys.hits("b"), 1, "no fetch for a removed client");
}

/// SR-110: a caller without a key of the client learns nothing about it from a refusal. An
/// unknown id, an id with a secret only, an id whose URL is down, and an id whose URL works
/// but does not hold the signing key (by `kid`, or with the right `kid`) get the same answer,
/// byte for byte apart from `Date`, at an exchange, at hop 0 and at AuthZEN.
#[tokio::test]
async fn a_refusal_does_not_tell_unknown_secret_only_and_unreachable_clients_apart_sr110() {
    let keys = KeyServer::start().await;
    let idp = Idp::new(&keys);
    let coder = Key::new("coder-1");
    keys.serve_keys("coder", &[&coder]);
    keys.serve_keys("gateway", &[&coder]);
    keys.set("down", Answer::Status(503));
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::start(&write_config(
        dir.path(),
        &keys,
        &(agent_secret("planner", "p")
            + &agent_secret("reviewer", "r")
            + &remote("agents", "coder", &keys.url("coder"), "")
            + &remote("agents", "down", &keys.url("down"), "")
            + "[[peps]]\nid = \"gw-secret\"\nsecret_sha256 = \""
            + &sha256_hex("g")
            + "\"\n"
            + &remote("peps", "gw-down", &keys.url("down"), "")
            + &remote("peps", "gateway", &keys.url("gateway"), "")),
    ))
    .await;
    // A key nobody configured, whose kid is the one `coder` publishes.
    let stranger = Key::new("coder-1");
    let probe = |id: &str, kid: &str| (id.to_owned(), stranger.assertion_with_kid(id, kid));
    let probes = || {
        [
            probe("nobody", "k"),
            probe("reviewer", "k"),
            probe("down", "k"),
            // A kid that is not in the set, and the right kid with another key.
            probe("coder", "nope"),
            probe("coder", "coder-1"),
        ]
    };
    let mut exchange = Vec::new();
    let mut hop0 = Vec::new();
    for (id, a) in probes() {
        exchange.push(whole(h.exchange(&id, fields(&a)).await).await);
    }
    for (_, a) in probes() {
        hop0.push(whole(h.intake(&idp, &a).await).await);
    }
    let mut authzen = Vec::new();
    for a in [
        stranger.assertion_with_kid("nobody", "k"),
        stranger.assertion_with_kid("gw-secret", "k"),
        stranger.assertion_with_kid("gw-down", "k"),
        stranger.assertion_with_kid("gateway", "nope"),
        stranger.assertion_with_kid("gateway", "coder-1"),
    ] {
        let resp = h
            .client
            .post(h.server.url("/access/v1/evaluation"))
            .bearer_auth(&h.root)
            .json(&json!({
                "subject": {"type": "agent", "id": ""},
                "action": {"name": "read_file"},
                "resource": {"type": "tool", "id": "github/read_file",
                             "properties": {"server": "github"}},
                "context": {"input": {}},
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": a,
            }))
            .send()
            .await
            .unwrap();
        authzen.push(whole(resp).await);
    }
    // The URL that is down was asked, so the answer did not come before the fetch.
    assert!(keys.hits("down") >= 1);
    for answers in [&exchange, &hop0, &authzen] {
        let (status, headers, body) = &answers[0];
        assert_eq!(*status, StatusCode::UNAUTHORIZED, "{body}");
        let v: Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            v,
            json!({"error": "invalid_client", "code": REFUSED,
                   "error_description": REFUSED,
                   "detail": "unknown client, or the client_assertion is not signed by one of the client's keys"})
        );
        assert!(
            headers.contains(&(
                "www-authenticate".to_owned(),
                "Basic realm=\"attenuo\"".to_owned()
            )),
            "{headers:?}"
        );
        for (i, a) in answers.iter().enumerate() {
            assert_eq!(a, &answers[0], "case {i}");
        }
    }
    assert_eq!(exchange[0], hop0[0]);
    assert_eq!(h.state.replay.len(), 0, "a refusal recorded an assertion");
}
