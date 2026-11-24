//! RFC 8705 `self_signed_tls_client_auth`: agents and PEPs that authenticate with a
//! self-signed TLS client certificate, pinned by its SHA-256 in `tls_client_cert_sha256`,
//! over the native listener with `[server.tls] client_certificates = "optional"`. Real TLS
//! handshakes through [`attenuo_server::run`], the code `serve` runs.
//!
//! RFC 8705 `tls_client_auth` (the `pki_` tests at the end): certificates a CA issued, with
//! `tls_client_ca_pem_path` and a SPIFFE ID or a DNS name.
//!
//! Covers hop 0, an exchange and the AuthZEN endpoints; the refusals as one answer (SR-110);
//! a certificate sent without its private key; a body credential next to a certificate; an
//! entry with a secret only; `client_certificates = "off"`; forwarded-certificate headers,
//! which are never read; the `[token] actor_auth` modes; the SR-109 peer table; a reload that
//! removes and adds a thumbprint under an open connection; the audit records; discovery; the
//! certificate's dates; and the plain listener, unchanged.

// Configs are built field by field, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::{AppState, Config};
use attenuo_token::DpopKey;
use axum::routing::get;
use axum::{Json, Router};
use common::tls::{Ca, ClientCert};
use common::{sha256_hex, Running};
use reqwest::StatusCode;
use serde_json::{json, Value};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ADMIN: &str = "mtls-test-admin-token-0123456789abcdef";
const ISSUER: &str = "https://attenuo.test";
const PUBLIC_URL: &str = "https://localhost:8443";
const IDP: &str = "https://idp.test";
const WORKLOAD: &str = "https://workload.test";
const CLIENT_AUD: &str = "attenuo-client";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
const METHOD: &str = "self_signed_tls_client_auth";

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// A fake IdP and workload issuer: one EdDSA key each, their key sets at `/jwks` and
/// `/actor-jwks`.
struct Issuers {
    idp: DpopKey,
    workload: DpopKey,
    server: Spawned,
}

impl Issuers {
    async fn start() -> Self {
        let idp = DpopKey::generate().unwrap();
        let workload = DpopKey::generate().unwrap();
        let set = |key: &DpopKey, kid: &str| {
            let mut jwk = key.public_jwk().clone();
            jwk["kid"] = kid.into();
            jwk["alg"] = "EdDSA".into();
            json!({ "keys": [jwk] })
        };
        let (a, b) = (set(&idp, "idp-1"), set(&workload, "wl-1"));
        let app = Router::new()
            .route(
                "/jwks",
                get(move || {
                    let d = a.clone();
                    async move { Json(d) }
                }),
            )
            .route(
                "/actor-jwks",
                get(move || {
                    let d = b.clone();
                    async move { Json(d) }
                }),
            );
        Self {
            idp,
            workload,
            server: spawn_router(app).await.unwrap(),
        }
    }

    fn id_token(&self, sub: &str) -> String {
        let t = now().unix_timestamp();
        self.idp.sign_jws(
            &json!({"alg": "EdDSA", "kid": "idp-1", "typ": "JWT"}),
            &json!({"iss": IDP, "aud": CLIENT_AUD, "sub": sub, "iat": t, "exp": t + 300,
                    "jti": uuid::Uuid::new_v4().to_string()}),
        )
    }

    /// A workload token naming agent `sub`, for `actor_token`.
    fn actor_token(&self, sub: &str) -> String {
        let t = now().unix_timestamp();
        self.workload.sign_jws(
            &json!({"alg": "EdDSA", "kid": "wl-1", "typ": "JWT"}),
            &json!({"iss": WORKLOAD, "aud": ISSUER, "sub": sub, "iat": t, "exp": t + 300,
                    "jti": uuid::Uuid::new_v4().to_string()}),
        )
    }
}

/// The client certificates of the test: `planner`, `coder` (two: a rotation), `both` (an
/// entry with a secret too), the PEP `gateway`, and one nobody pinned.
struct Certs {
    planner: ClientCert,
    coder: ClientCert,
    coder_next: ClientCert,
    both: ClientCert,
    gateway: ClientCert,
    stranger: ClientCert,
}

impl Certs {
    fn new() -> Self {
        Self {
            planner: ClientCert::new("planner"),
            coder: ClientCert::new("coder"),
            coder_next: ClientCert::new("coder"),
            both: ClientCert::new("both"),
            gateway: ClientCert::new("gateway"),
            stranger: ClientCert::new("stranger"),
        }
    }

    /// The lists for a server that asks for no certificate: secrets only.
    fn plain_lists() -> String {
        format!(
            "[[agents]]\nid = \"planner\"\nsecret_sha256 = \"{}\"\n\n\
             [[agents]]\nid = \"coder\"\nsecret_sha256 = \"{}\"\n\n\
             [[agents]]\nid = \"reviewer\"\nsecret_sha256 = \"{}\"\n\n\
             [[peps]]\nid = \"pep-secret\"\nsecret_sha256 = \"{}\"\n",
            sha256_hex("planner-secret"),
            sha256_hex("coder-secret"),
            sha256_hex("reviewer-secret"),
            sha256_hex("pep-secret"),
        )
    }

    /// The `[[agents]]` and `[[peps]]` of the test, with `coder` pinned to `coder_pins`.
    fn lists(&self, coder_pins: &[&ClientCert]) -> String {
        let pins = |certs: &[&ClientCert]| {
            certs
                .iter()
                .map(|c| format!("\"{}\"", c.sha256_hex()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let coder = if coder_pins.is_empty() {
            format!("secret_sha256 = \"{}\"\n", sha256_hex("coder-secret"))
        } else {
            format!("tls_client_cert_sha256 = [{}]\n", pins(coder_pins))
        };
        format!(
            "[[agents]]\nid = \"planner\"\ntls_client_cert_sha256 = [{}]\n\n\
             [[agents]]\nid = \"coder\"\n{coder}\n\
             [[agents]]\nid = \"reviewer\"\nsecret_sha256 = \"{}\"\n\n\
             [[agents]]\nid = \"both\"\nsecret_sha256 = \"{}\"\ntls_client_cert_sha256 = [{}]\n\n\
             [[peps]]\nid = \"gateway\"\ntls_client_cert_sha256 = [{}]\n\n\
             [[peps]]\nid = \"pep-secret\"\nsecret_sha256 = \"{}\"\n",
            pins(&[&self.planner]),
            sha256_hex("reviewer-secret"),
            sha256_hex("both-secret"),
            pins(&[&self.both]),
            pins(&[&self.gateway]),
            sha256_hex("pep-secret"),
        )
    }
}

/// What a test changes in the config file.
struct Opts {
    /// `[server.tls]` at all.
    tls: bool,
    /// `client_certificates`.
    client_certificates: &'static str,
    /// `[token] actor_auth`.
    actor_auth: &'static str,
    /// More sections, before the lists.
    extra: String,
    /// The `[[agents]]` and `[[peps]]`, instead of the self-signed ones of [`Certs::lists`].
    lists: Option<String>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            tls: true,
            client_certificates: "optional",
            actor_auth: "either",
            extra: String::new(),
            lists: None,
        }
    }
}

/// Write `<dir>/attenuo.toml`, replaced in one rename so a reload never reads half of it.
fn write_config(
    dir: &Path,
    server_files: &(PathBuf, PathBuf),
    issuers: &Issuers,
    opts: &Opts,
    lists: &str,
) -> PathBuf {
    let tls = if opts.tls {
        format!(
            "[server]\npublic_url = \"{PUBLIC_URL}\"\n\n[server.tls]\ncert_pem_path = \"{}\"\n\
             key_pem_path = \"{}\"\nclient_certificates = \"{}\"\n\n",
            server_files.0.display(),
            server_files.1.display(),
            opts.client_certificates
        )
    } else {
        String::new()
    };
    let path = dir.join("attenuo.toml");
    let tmp = dir.join("attenuo.toml.tmp");
    std::fs::write(
        &tmp,
        format!(
            "{tls}[issuer]\nissuer = \"{ISSUER}\"\nprivate_key_pem_path = \"{}\"\n\n\
             [audit]\nsqlite_path = \"{}\"\n\n\
             [admin]\ntoken = \"{ADMIN}\"\n\n\
             [dev]\nallow_root_mint = true\n\n\
             [authzen]\nallow_unsigned_chain = true\n\n\
             [token]\nactor_auth = \"{}\"\n\n\
             [[idps]]\nissuer = \"{IDP}\"\njwks_url = \"{}\"\nallowed_algs = [\"EdDSA\"]\n\
             client_ids = {{ planner = \"{CLIENT_AUD}\" }}\n\n\
             [[root_grants]]\nissuer = \"{IDP}\"\nagent = \"planner\"\ncapabilities = [\"github:*\"]\n\n\
             [[actor_trust]]\nissuer = \"{WORKLOAD}\"\njwks_url = \"{}\"\naudience = \"{ISSUER}\"\n\
             subject_to_agent = \"sub\"\nallowed_algs = [\"EdDSA\"]\n\n{}\n{lists}",
            dir.join("keys/issuer.pem").display(),
            dir.join("audit.sqlite").display(),
            opts.actor_auth,
            issuers.server.url("/jwks"),
            issuers.server.url("/actor-jwks"),
            opts.extra,
        ),
    )
    .unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    path
}

struct Harness {
    dir: tempfile::TempDir,
    ca: Ca,
    server_files: (PathBuf, PathBuf),
    issuers: Issuers,
    certs: Certs,
    opts: Opts,
    running: Running,
    state: Arc<AppState>,
}

impl Harness {
    async fn start(opts: Opts) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::new("mtls test CA");
        let server_files = ca.write_server_files(dir.path(), &["127.0.0.1"]);
        let issuers = Issuers::start().await;
        let certs = Certs::new();
        let lists = if let Some(lists) = &opts.lists {
            lists.clone()
        } else if opts.tls && opts.client_certificates == "optional" {
            certs.lists(&[&certs.coder, &certs.coder_next])
        } else {
            Certs::plain_lists()
        };
        let path = write_config(dir.path(), &server_files, &issuers, &opts, &lists);
        let cfg = Config::load(&path).unwrap();
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let running = Running::start(cfg, state.clone(), router).await;
        Self {
            dir,
            ca,
            server_files,
            issuers,
            certs,
            opts,
            running,
            state,
        }
    }

    async fn stop(self) {
        self.running.stop(self.state).await;
    }

    fn url(&self, path: &str) -> String {
        if self.opts.tls {
            self.running.https_url(path)
        } else {
            self.running.url(path)
        }
    }

    /// A client that presents `cert`, or none.
    fn client(&self, cert: Option<&ClientCert>) -> reqwest::Client {
        self.ca.reqwest_client(cert)
    }

    async fn post(&self, cert: Option<&ClientCert>, path: &str, body: &Value) -> Answer {
        self.post_with(cert, path, body, &[]).await
    }

    async fn post_with(
        &self,
        cert: Option<&ClientCert>,
        path: &str,
        body: &Value,
        headers: &[(&str, &str)],
    ) -> Answer {
        let mut req = self.client(cert).post(self.url(path)).json(body);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        Answer::of(req.send().await.unwrap()).await
    }

    /// A root token for `planner` from the dev mint: (token, lease).
    async fn root(&self) -> (String, String) {
        let resp = self
            .client(None)
            .post(self.url("/admin/root-token"))
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
        (
            v["access_token"].as_str().unwrap().into(),
            v["lease"].as_str().unwrap().into(),
        )
    }

    async fn audit(&self) -> Vec<Value> {
        let v: Value = self
            .client(None)
            .get(self.url("/admin/audit?from=1&limit=1000"))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["entries"].as_array().unwrap().clone()
    }

    /// The arguments digest of the last record with `tool`.
    async fn last_digest(&self, tool: &str) -> Value {
        self.audit()
            .await
            .into_iter()
            .rfind(|e| e["record"]["tool"] == tool)
            .unwrap()["record"]["arguments_digest"]
            .clone()
    }

    /// Rewrite the config file with `coder` pinned to `coder_pins` and reload the lists.
    async fn reload_coder(&self, coder_pins: &[&ClientCert]) -> Value {
        write_config(
            self.dir.path(),
            &self.server_files,
            &self.issuers,
            &self.opts,
            &self.certs.lists(coder_pins),
        );
        let resp = self
            .client(None)
            .post(self.url("/admin/agents/reload"))
            .bearer_auth(ADMIN)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        let a = Answer::of(resp).await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
        a.body
    }

    /// The decision request of an AuthZEN evaluation for a root token's chain, with `pep`
    /// fields in the body.
    async fn evaluation(&self, pep: Value) -> Value {
        let (root, _) = self.root().await;
        let chain = self
            .state
            .keys()
            .verifier
            .verify(&root, now())
            .unwrap()
            .chain;
        let read =
            attenuo_core::ToolCall::new("github", "read_file", json!({"repo": "alice/site"}));
        let mut body =
            serde_json::to_value(attenuo_policy::authzen::to_request(&chain, &read)).unwrap();
        for (k, v) in pep.as_object().unwrap() {
            body[k] = v.clone();
        }
        body
    }
}

/// An HTTP answer: status, `WWW-Authenticate`, body.
#[derive(Debug, PartialEq)]
struct Answer {
    status: StatusCode,
    challenge: Option<String>,
    body: Value,
}

impl Answer {
    async fn of(resp: reqwest::Response) -> Self {
        let status = resp.status();
        let challenge = resp
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .map(|v| v.to_str().unwrap().to_owned());
        Self {
            status,
            challenge,
            body: resp.json().await.unwrap_or(Value::Null),
        }
    }

    fn code(&self) -> (&str, &str) {
        (
            self.body["error"].as_str().unwrap_or_default(),
            self.body["error_description"].as_str().unwrap_or_default(),
        )
    }
}

fn exchange_body(parent: &str, actor: &str, extra: Value) -> Value {
    let mut body = json!({
        "grant_type": EXCHANGE, "subject_token": parent, "subject_token_type": JWT,
        "actor": actor,
        "authorization_details": [{"type": "attenuo_capabilities",
            "capabilities": [{"server": "github", "tool": "read_file"}]}],
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

fn intake_body(id_token: &str, extra: Value) -> Value {
    let mut body = json!({
        "grant_type": EXCHANGE, "subject_token": id_token, "subject_token_type": ID_TOKEN,
        "authorization_details": [{"type": "attenuo_capabilities",
            "capabilities": [{"server": "github", "tool": "read_file"}]}],
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

/// The `client_cert` member of a record of a request `cert` authenticated.
fn client_cert_member(cert: &ClientCert) -> Value {
    json!({"x5t#S256": cert.x5t_s256(), "source": "tls"})
}

/// The digest the exchange record's arguments have: `how` the actor authenticated, the
/// certificate when it was one, and the actor token's subject and trust entry when there was
/// one.
fn exchange_digest(
    actor: &str,
    parent_lease: &str,
    how: &str,
    cert: Option<&ClientCert>,
    actor_token: bool,
) -> String {
    let requested: attenuo_core::CapabilitySet =
        serde_json::from_value(json!([{"server": "github", "tool": "read_file"}])).unwrap();
    let mut args = json!({"actor": actor, "requested": requested, "parent_lease": parent_lease,
                          "actor_auth": how, "dpop_bound": false});
    if actor_token {
        args["actor_subject"] = actor.into();
        args["actor_trust"] = WORKLOAD.into();
    }
    if let Some(c) = cert {
        args["client_cert"] = client_cert_member(c);
    }
    attenuo_core::ToolCall::new("attenuo", "token.exchange", args).arguments_digest()
}

/// A raw TLS 1.3 connection to the server presenting `client`, from `source` when given
/// (another loopback address, as another peer).
async fn connect(
    h: &Harness,
    client: Option<Arc<dyn rustls::client::ResolvesClientCert>>,
    source: Option<std::net::IpAddr>,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let config = match client {
        Some(c) => h.ca.rustls_client_with(c),
        None => {
            h.ca.rustls_client(&[&rustls::version::TLS13], &[b"http/1.1"])
        }
    };
    let tcp = match source {
        None => tokio::net::TcpStream::connect(h.running.addr()).await?,
        Some(ip) => {
            let socket = tokio::net::TcpSocket::new_v4()?;
            socket.bind(std::net::SocketAddr::new(ip, 0))?;
            socket.connect(h.running.addr()).await?
        }
    };
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
}

/// Send one request on `stream` (kept alive) and read the answer by its `Content-Length`.
async fn request_on<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&Value>,
) -> std::io::Result<(u16, Value)> {
    let body = body.map(Value::to_string).unwrap_or_default();
    let auth = bearer
        .map(|b| format!("Authorization: Bearer {b}\r\n"))
        .unwrap_or_default();
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.flush().await?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("closed before a full response: {buf:?}"),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map_or(0, |v| v.trim().parse::<usize>().unwrap());
            if buf.len() >= end + 4 + len {
                let status = head
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let v = serde_json::from_slice(&buf[end + 4..end + 4 + len]).unwrap_or(Value::Null);
                return Ok((status, v));
            }
        }
    }
}

// --- the happy paths --------------------------------------------------------------------

/// Hop 0 and an exchange with a pinned certificate and `client_id`: tokens, and records whose
/// arguments say `self_signed_tls_client_auth` and carry the certificate's thumbprint.
#[tokio::test]
async fn an_agent_authenticates_with_its_certificate() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;

    // Hop 0.
    let a = h
        .post(
            Some(&c.planner),
            "/token",
            &intake_body(
                &h.issuers.id_token("alice"),
                json!({"client_id": "planner"}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    let root = a.body["access_token"].as_str().unwrap();
    let verified = h.state.keys().verifier.verify(root, now()).unwrap();
    assert_eq!(verified.chain.hops[0].agent.0, "planner");
    let requested = verified.chain.hops[0].capabilities.clone();
    let digest = |how: &str, cert: Option<&ClientCert>| {
        let mut args = json!({"agent": "planner", "requested": requested, "credential": "id_token",
                              "idp": IDP, "agent_auth": how, "dpop_bound": false});
        if let Some(c) = cert {
            args["client_cert"] = client_cert_member(c);
        }
        attenuo_core::ToolCall::new("attenuo", "token.root", args).arguments_digest()
    };
    let got = h.last_digest("token.root").await;
    assert_eq!(got, digest(METHOD, Some(&c.planner)));
    assert_ne!(got, digest(METHOD, None));

    // An exchange, with either of coder's two certificates (a rotation).
    for cert in [&c.coder, &c.coder_next] {
        let (root, lease) = h.root().await;
        let a = h
            .post(
                Some(cert),
                "/token",
                &exchange_body(&root, "coder", json!({"client_id": "coder"})),
            )
            .await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
        let child = h
            .state
            .keys()
            .verifier
            .verify(a.body["access_token"].as_str().unwrap(), now())
            .unwrap();
        assert_eq!(child.claims.act.sub, "coder");
        // A bearer token: not bound to the certificate (no cnf).
        assert!(child.claims.cnf.is_none());
        assert_eq!(
            h.last_digest("token.exchange").await,
            exchange_digest("coder", &lease, METHOD, Some(cert), false)
        );
    }

    // With an actor token as well (`actor_auth = "either"`): both are checked.
    let (root, lease) = h.root().await;
    let a = h
        .post(
            Some(&c.coder),
            "/token",
            &exchange_body(
                &root,
                "coder",
                json!({"client_id": "coder", "actor_token": h.issuers.actor_token("coder"),
                       "actor_token_type": JWT}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest(
            "coder",
            &lease,
            "actor_token+self_signed_tls_client_auth",
            Some(&c.coder),
            true
        )
    );
    // With an actor token and `client_id`, over a connection with a certificate that is not
    // pinned for that id: the certificate is a presented client credential, so it is checked
    // too, and fails. Leaving `client_id` out, or sending no certificate, uses the actor
    // token alone.
    let (root, lease) = h.root().await;
    let with_token = |client_id: bool| {
        let mut extra = json!({"actor_token": h.issuers.actor_token("coder"),
                               "actor_token_type": JWT});
        if client_id {
            extra["client_id"] = "coder".into();
        }
        exchange_body(&root, "coder", extra)
    };
    let a = h.post(Some(&c.stranger), "/token", &with_token(true)).await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
    assert_eq!(a.code(), ("invalid_client", "client_authentication_failed"));
    let a = h
        .post(Some(&c.stranger), "/token", &with_token(false))
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest("coder", &lease, "actor_token", None, true)
    );
    let (root, _) = h.root().await;
    let body = exchange_body(
        &root,
        "coder",
        json!({"client_id": "coder", "actor_token": h.issuers.actor_token("coder"),
               "actor_token_type": JWT}),
    );
    let a = h.post(None, "/token", &body).await;
    // No certificate: `client_id` alone is no credential, so the actor token decides.
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);

    // An actor token for another agent than the certificate's: refused.
    let (root, _) = h.root().await;
    let a = h
        .post(
            Some(&c.coder),
            "/token",
            &exchange_body(
                &root,
                "coder",
                json!({"client_id": "coder", "actor_token": h.issuers.actor_token("reviewer"),
                       "actor_token_type": JWT}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
    assert_eq!(a.code(), ("invalid_request", "actor_mismatch"));

    // A client without a certificate still works over the same listener, with a secret.
    let (root, lease) = h.root().await;
    let a = h
        .post(
            None,
            "/token",
            &exchange_body(
                &root,
                "reviewer",
                json!({"client_id": "reviewer", "client_secret": "reviewer-secret"}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    // Its record is exactly as before: no `client_cert` member.
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest("reviewer", &lease, "client_secret", None, false)
    );
    h.stop().await;
}

/// A PEP authenticates to the AuthZEN endpoints with its certificate and `pep_id`: an
/// unsigned body chain, single and batch; and with a bearer, to get diagnostics.
#[tokio::test]
async fn a_pep_authenticates_with_its_certificate() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let body = h.evaluation(json!({"pep_id": "gateway"})).await;
    let a = h
        .post(Some(&c.gateway), "/access/v1/evaluation", &body)
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert!(a.body["context"]["decision_id"].is_string(), "{}", a.body);
    // The same request again: a certificate is not used up.
    let a = h
        .post(Some(&c.gateway), "/access/v1/evaluation", &body)
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    // A batch.
    let mut batch = body.clone();
    batch["evaluations"] = json!([{}, {}]);
    let a = h
        .post(Some(&c.gateway), "/access/v1/evaluations", &batch)
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(a.body["evaluations"].as_array().unwrap().len(), 2);
    // A larger batch (the certificate is checked once for the request, then reused): every
    // entry is decided as a single evaluation is.
    let single = h
        .post(Some(&c.gateway), "/access/v1/evaluation", &body)
        .await;
    let mut batch = body.clone();
    batch["evaluations"] = json!([{}, {}, {}, {}, {}, {}]);
    let a = h
        .post(Some(&c.gateway), "/access/v1/evaluations", &batch)
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    let entries = a.body["evaluations"].as_array().unwrap();
    assert_eq!(entries.len(), 6);
    for e in entries {
        assert_eq!(e["decision"], single.body["decision"], "{e}");
        assert_eq!(
            e["context"]["reason"], single.body["context"]["reason"],
            "{e}"
        );
    }
    // An entry that names another PEP (one with a secret only) refuses the whole batch with
    // the one answer, also after earlier entries passed with the certificate.
    batch["evaluations"] = json!([{}, {}, {"pep_id": "pep-secret"}, {}]);
    let refused = h
        .post(Some(&c.gateway), "/access/v1/evaluations", &batch)
        .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{}", refused.body);
    assert_eq!(
        refused.code(),
        ("invalid_client", "client_authentication_failed")
    );
    assert!(refused.challenge.is_some());

    // Refused: no certificate, an agent's certificate, a PEP with a secret only.
    let a = h.post(None, "/access/v1/evaluation", &body).await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
    assert_eq!(a.code(), ("invalid_client", "client_auth_missing"));
    let wrong = h
        .post(Some(&c.planner), "/access/v1/evaluation", &body)
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{}", wrong.body);
    assert_eq!(
        wrong.code(),
        ("invalid_client", "client_authentication_failed")
    );
    assert!(wrong.challenge.is_some());
    let other = h.evaluation(json!({"pep_id": "pep-secret"})).await;
    let a = h
        .post(Some(&c.gateway), "/access/v1/evaluation", &other)
        .await;
    assert_eq!(&a, &wrong);
    // With a bearer: the certificate and `pep_id` make it a PEP, which gets diagnostics; the
    // token holder alone, or with another certificate, does not get them / is refused.
    let (root, _) = h.root().await;
    let denied = |pep: Option<&str>| {
        let mut b = json!({
            "subject": {"type": "agent", "id": ""},
            "action": {"name": "delete_repo"},
            "resource": {"type": "tool", "id": "github/delete_repo",
                         "properties": {"server": "github"}},
            "context": {"input": {"repo": "acme/api"}},
        });
        if let Some(p) = pep {
            b["pep_id"] = p.into();
        }
        b
    };
    let with_bearer = |cert: Option<&ClientCert>, body: Value| {
        let req = h
            .client(cert)
            .post(h.url("/access/v1/evaluation"))
            .bearer_auth(&root)
            .json(&body);
        async move { Answer::of(req.send().await.unwrap()).await }
    };
    let a = with_bearer(Some(&c.gateway), denied(Some("gateway"))).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(a.body["decision"], false, "{}", a.body);
    assert!(
        !a.body["context"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{}",
        a.body
    );
    let a = with_bearer(Some(&c.gateway), denied(None)).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert!(
        a.body["context"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{}",
        a.body
    );
    let a = with_bearer(Some(&c.stranger), denied(Some("gateway"))).await;
    assert_eq!(&a, &wrong);

    // An agent id is not a PEP id.
    let planner = h.evaluation(json!({"pep_id": "planner"})).await;
    let a = h
        .post(Some(&c.planner), "/access/v1/evaluation", &planner)
        .await;
    assert_eq!(a.code(), ("invalid_client", "client_authentication_failed"));
    h.stop().await;
}

// --- refusals -----------------------------------------------------------------------------

/// No certificate is `client_auth_missing`. An unknown certificate, another agent's
/// certificate, and a certificate for an entry with a secret only are one answer (SR-110),
/// and none issues a token or writes a record.
#[tokio::test]
async fn refused_certificates_are_one_answer() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let (root, _) = h.root().await;
    let records = h.audit().await.len();
    let send = |cert: Option<&ClientCert>, client_id: &str| {
        let body = exchange_body(&root, client_id, json!({"client_id": client_id}));
        let h = &h;
        let cert = cert.cloned();
        async move { h.post(cert.as_ref(), "/token", &body).await }
    };
    let missing = send(None, "coder").await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED, "{}", missing.body);
    assert_eq!(missing.code(), ("invalid_client", "client_auth_missing"));

    let unknown = send(Some(&c.stranger), "coder").await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED, "{}", unknown.body);
    assert_eq!(
        unknown.code(),
        ("invalid_client", "client_authentication_failed")
    );
    // Agent A's certificate with client_id B.
    let crossed = send(Some(&c.planner), "coder").await;
    // A certificate for an entry with a secret only.
    let secret_only = send(Some(&c.planner), "reviewer").await;
    // An id nobody has.
    let nobody = send(Some(&c.planner), "nobody").await;
    // A PEP's certificate used as an agent.
    let pep = send(Some(&c.gateway), "coder").await;
    for a in [&crossed, &secret_only, &nobody, &pep] {
        assert_eq!(a, &unknown);
    }
    // A's certificate and client_id, but B as the actor: authenticated, then refused (and
    // audited) as a mismatch, as for any other method.
    let a = h
        .post(
            Some(&c.planner),
            "/token",
            &exchange_body(&root, "coder", json!({"client_id": "planner"})),
        )
        .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
    assert_eq!(a.code(), ("invalid_request", "actor_mismatch"));
    // Only the mismatch was recorded.
    let entries = h.audit().await;
    assert_eq!(entries.len(), records + 1, "{entries:?}");
    // Hop 0 the same way.
    let a = h
        .post(
            Some(&c.stranger),
            "/token",
            &intake_body(
                &h.issuers.id_token("alice"),
                json!({"client_id": "planner"}),
            ),
        )
        .await;
    assert_eq!(a, unknown);
    let a = h
        .post(
            None,
            "/token",
            &intake_body(
                &h.issuers.id_token("alice"),
                json!({"client_id": "planner"}),
            ),
        )
        .await;
    assert_eq!(a.code(), ("invalid_client", "client_auth_missing"));
    // A certificate without a client id authenticates nobody.
    let a = h
        .post(
            Some(&c.planner),
            "/token",
            &intake_body(&h.issuers.id_token("alice"), json!({})),
        )
        .await;
    assert_eq!(a.code(), ("invalid_client", "client_auth_missing"));
    assert_eq!(h.audit().await.len(), records + 1);
    h.stop().await;
}

/// A body credential decides when a certificate is on the connection too: a wrong secret is
/// refused, a right one authenticates by the secret (and the record says so, with no
/// `client_cert`).
#[tokio::test]
async fn a_body_credential_decides_over_the_certificate() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let (root, _) = h.root().await;
    let a = h
        .post(
            Some(&c.both),
            "/token",
            &exchange_body(
                &root,
                "both",
                json!({"client_id": "both", "client_secret": "wrong"}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
    assert_eq!(a.code(), ("invalid_client", "client_authentication_failed"));
    let a = h
        .post(
            Some(&c.both),
            "/token",
            &exchange_body(
                &root,
                "both",
                json!({"client_id": "both", "client_secret": "both-secret"}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    let lease = h
        .state
        .keys()
        .verifier
        .verify(&root, now())
        .unwrap()
        .chain
        .hops[0]
        .lease
        .0
        .clone();
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest("both", &lease, "client_secret", None, false)
    );
    // The certificate alone authenticates `both` too.
    let (root, lease) = h.root().await;
    let a = h
        .post(
            Some(&c.both),
            "/token",
            &exchange_body(&root, "both", json!({"client_id": "both"})),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest("both", &lease, METHOD, Some(&c.both), false)
    );
    h.stop().await;
}

/// A client that sends a pinned certificate but signs the handshake with another key fails
/// the handshake: no request is served on that connection. The same certificate with its own
/// key works.
#[tokio::test]
async fn a_certificate_without_its_private_key_fails_the_handshake() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let forged = c.coder.resolver_signing_with(&c.stranger);
    // TLS 1.3: the client may finish its side of the handshake before the server has checked
    // its CertificateVerify, so the failure can show on the first read instead.
    let served = match connect(&h, Some(forged), None).await {
        Err(_) => false,
        Ok(mut stream) => request_on(&mut stream, "GET", "/healthz", None, None)
            .await
            .is_ok(),
    };
    assert!(!served, "a forged CertificateVerify was accepted");
    let mut good = connect(&h, Some(c.coder.resolver()), None).await.unwrap();
    let (status, _) = request_on(&mut good, "GET", "/healthz", None, None)
        .await
        .unwrap();
    assert_eq!(status, 200);
    h.stop().await;
}

/// A pinned certificate outside its dates, a pinned CA certificate and a pinned certificate
/// whose extended key usage is server-only are refused like an unknown one (SR-110).
#[tokio::test]
async fn a_pinned_certificate_must_be_usable() {
    let day = time::Duration::days(1);
    let expired = ClientCert::with_dates("old", now() - day * 30, now() - day);
    let future = ClientCert::with_dates("new", now() + day, now() + day * 30);
    let ca = ClientCert::made("ca", |p| {
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.extended_key_usages = vec![];
    });
    let server_only = ClientCert::made("srv", |p| {
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    });
    let bare = ClientCert::made("bare", |p| {
        p.is_ca = rcgen::IsCa::NoCa;
        p.extended_key_usages = vec![];
    });
    let pins = [&expired, &future, &ca, &server_only, &bare]
        .iter()
        .enumerate()
        .map(|(i, c)| {
            format!(
                "[[agents]]\nid = \"a{i}\"\ntls_client_cert_sha256 = [\"{}\"]\n\n",
                c.sha256_hex()
            )
        })
        .collect::<String>();
    let h = Harness::start(Opts {
        extra: String::new(),
        ..Opts::default()
    })
    .await;
    // The harness's lists plus these.
    let path = write_config(
        h.dir.path(),
        &h.server_files,
        &h.issuers,
        &h.opts,
        &format!(
            "{}{pins}",
            h.certs.lists(&[&h.certs.coder, &h.certs.coder_next])
        ),
    );
    assert!(path.exists());
    let r = h.reload_coder_raw().await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let unknown = {
        let (root, _) = h.root().await;
        h.post(
            Some(&h.certs.stranger),
            "/token",
            &exchange_body(&root, "coder", json!({"client_id": "coder"})),
        )
        .await
    };
    for (i, cert) in [&expired, &future, &ca, &server_only].iter().enumerate() {
        let (root, _) = h.root().await;
        let id = format!("a{i}");
        let a = h
            .post(
                Some(cert),
                "/token",
                &exchange_body(&root, &id, json!({"client_id": id})),
            )
            .await;
        assert_eq!(a, unknown, "{i}");
    }
    // No basicConstraints and no extended key usage at all: usable.
    let (root, _) = h.root().await;
    let a = h
        .post(
            Some(&bare),
            "/token",
            &exchange_body(&root, "a4", json!({"client_id": "a4"})),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    h.stop().await;
}

impl Harness {
    /// Reload the lists from the file as it is now.
    async fn reload_coder_raw(&self) -> Answer {
        let resp = self
            .client(None)
            .post(self.url("/admin/agents/reload"))
            .bearer_auth(ADMIN)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        Answer::of(resp).await
    }
}

/// `Client-Cert` (RFC 9440) and `X-Forwarded-Client-Cert` headers are never read: over TLS
/// without a certificate, and on the plain listener, a request that names the client and
/// carries such a header has no credential.
#[tokio::test]
async fn forwarded_certificate_headers_change_nothing() {
    use base64::Engine as _;
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let b64 = base64::engine::general_purpose::STANDARD.encode(c.coder.der.as_ref());
    let rfc9440 = format!(":{b64}:");
    let xfcc = format!(
        "Hash={};Cert=\"{}\"",
        c.coder.sha256_hex(),
        c.coder.cert_pem.replace('\n', "%0A")
    );
    let headers = [
        ("Client-Cert", rfc9440.as_str()),
        ("X-Forwarded-Client-Cert", xfcc.as_str()),
        ("X-Client-Cert", rfc9440.as_str()),
        ("ssl-client-cert", rfc9440.as_str()),
    ];
    let (root, _) = h.root().await;
    let a = h
        .post_with(
            None,
            "/token",
            &exchange_body(&root, "coder", json!({"client_id": "coder"})),
            &headers,
        )
        .await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
    assert_eq!(a.code(), ("invalid_client", "client_auth_missing"));
    // With another certificate on the connection, the header does not replace it.
    let a = h
        .post_with(
            Some(&c.stranger),
            "/token",
            &exchange_body(&root, "coder", json!({"client_id": "coder"})),
            &headers,
        )
        .await;
    assert_eq!(a.code(), ("invalid_client", "client_authentication_failed"));
    let body = h.evaluation(json!({"pep_id": "gateway"})).await;
    let a = h
        .post_with(None, "/access/v1/evaluation", &body, &headers)
        .await;
    assert_eq!(a.code(), ("invalid_client", "client_auth_missing"));
    h.stop().await;

    // The plain listener: no TLS, so no certificate settings either; the header is ignored.
    let h = Harness::start(Opts {
        tls: false,
        ..Opts::default()
    })
    .await;
    let (root, _) = h.root().await;
    let a = h
        .post_with(
            None,
            "/token",
            &exchange_body(&root, "reviewer", json!({"client_id": "reviewer"})),
            &headers,
        )
        .await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
    assert_eq!(a.code(), ("invalid_client", "client_auth_missing"));
    h.stop().await;
}

/// Counts the times the server asked the client for a certificate.
#[derive(Debug)]
struct Counting {
    inner: Arc<dyn rustls::client::ResolvesClientCert>,
    asked: std::sync::atomic::AtomicUsize,
}

impl rustls::client::ResolvesClientCert for Counting {
    fn resolve(
        &self,
        hints: &[&[u8]],
        schemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // The server sends no acceptable issuers: a client sends what it is configured with.
        assert!(hints.is_empty(), "{hints:?}");
        self.inner.resolve(hints, schemes)
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// With `client_certificates = "off"` the handshake never asks for a certificate (with
/// `"optional"` it does), and certificate settings stop the server: with `"off"`, and without
/// `[server.tls]` at all. A reload that adds one to an `"off"` server is refused.
#[tokio::test]
async fn client_certificates_off_never_asks_and_refuses_the_settings() {
    for (mode, asked) in [("off", 0), ("optional", 1)] {
        let h = Harness::start(Opts {
            client_certificates: mode,
            ..Opts::default()
        })
        .await;
        let counting = Arc::new(Counting {
            inner: h.certs.planner.resolver(),
            asked: Default::default(),
        });
        let mut stream = connect(&h, Some(counting.clone()), None).await.unwrap();
        let (status, _) = request_on(&mut stream, "GET", "/healthz", None, None)
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(
            counting.asked.load(std::sync::atomic::Ordering::SeqCst),
            asked,
            "{mode}"
        );
        if mode == "off" {
            // The planner's certificate on an "off" listener: never seen, so a request that
            // names planner has no credential.
            let (root, _) = h.root().await;
            let (status, v) = request_on(
                &mut stream,
                "POST",
                "/token",
                None,
                Some(&exchange_body(
                    &root,
                    "planner",
                    json!({"client_id": "planner"}),
                )),
            )
            .await
            .unwrap();
            assert_eq!(
                (status, v["error_description"].as_str()),
                (401, Some("client_auth_missing")),
                "{v}"
            );
            // A reload that adds a thumbprint is refused, and the lists stay as they were.
            write_config(
                h.dir.path(),
                &h.server_files,
                &h.issuers,
                &h.opts,
                &h.certs.lists(&[&h.certs.coder]),
            );
            let r = h.reload_coder_raw().await;
            assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
            assert!(
                r.body.to_string().contains("client_certificates"),
                "{}",
                r.body
            );
        }
        h.stop().await;
    }

    // At start: pins with "off", and pins without [server.tls].
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("mtls test CA");
    let files = ca.write_server_files(dir.path(), &["127.0.0.1"]);
    let issuers = Issuers::start().await;
    let certs = Certs::new();
    for opts in [
        Opts {
            client_certificates: "off",
            ..Opts::default()
        },
        Opts {
            tls: false,
            ..Opts::default()
        },
    ] {
        let path = write_config(
            dir.path(),
            &files,
            &issuers,
            &opts,
            &certs.lists(&[&certs.coder]),
        );
        let cfg = Config::load(&path).unwrap();
        let err = attenuo_server::build(&cfg).err().expect("refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(
                "tls_client_cert_sha256 needs [server.tls] with client_certificates = \"optional\""
            ),
            "{msg}"
        );
    }
}

/// `[token] actor_auth`: `"secret"` accepts a certificate like any client credential;
/// `"actor_token"` refuses a certificate with a `client_id` (`client_auth_not_accepted`) at an
/// exchange and at hop 0, and still serves an actor token alone over a connection that has a
/// certificate. `"either"` is covered above.
#[tokio::test]
async fn the_actor_auth_modes_treat_a_certificate_as_a_client_credential() {
    let h = Harness::start(Opts {
        actor_auth: "secret",
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let (root, lease) = h.root().await;
    let a = h
        .post(
            Some(&c.coder),
            "/token",
            &exchange_body(&root, "coder", json!({"client_id": "coder"})),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest("coder", &lease, METHOD, Some(&c.coder), false)
    );
    let a = h
        .post(
            Some(&c.planner),
            "/token",
            &intake_body(
                &h.issuers.id_token("alice"),
                json!({"client_id": "planner"}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    h.stop().await;

    let h = Harness::start(Opts {
        actor_auth: "actor_token",
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let (root, lease) = h.root().await;
    let a = h
        .post(
            Some(&c.coder),
            "/token",
            &exchange_body(&root, "coder", json!({"client_id": "coder"})),
        )
        .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
    assert_eq!(a.code(), ("invalid_request", "client_auth_not_accepted"));
    // A client_id next to an actor token, with a certificate on the connection: the
    // certificate makes it a client credential, which this mode does not accept.
    let a = h
        .post(
            Some(&c.coder),
            "/token",
            &exchange_body(
                &root,
                "coder",
                json!({"client_id": "coder", "actor_token": h.issuers.actor_token("coder"),
                       "actor_token_type": JWT}),
            ),
        )
        .await;
    assert_eq!(a.code(), ("invalid_request", "client_auth_not_accepted"));
    let a = h
        .post(
            Some(&c.planner),
            "/token",
            &intake_body(
                &h.issuers.id_token("alice"),
                json!({"client_id": "planner"}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
    assert_eq!(a.code(), ("invalid_request", "client_auth_not_accepted"));
    // An actor token alone, over a connection with a certificate: served, and the record
    // has no `client_cert`.
    let a = h
        .post(
            Some(&c.coder),
            "/token",
            &exchange_body(
                &root,
                "coder",
                json!({"actor_token": h.issuers.actor_token("coder"), "actor_token_type": JWT}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest("coder", &lease, "actor_token", None, true)
    );
    h.stop().await;
}

/// A reload that removes a thumbprint stops it on the next request of a connection that is
/// already open, and one that adds a thumbprint makes it work on an open connection too.
#[tokio::test]
async fn a_reload_applies_to_open_connections() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let mut coder = connect(&h, Some(c.coder.resolver()), None).await.unwrap();
    let mut stranger = connect(&h, Some(c.stranger.resolver()), None)
        .await
        .unwrap();
    let exchange = |root: &str| exchange_body(root, "coder", json!({"client_id": "coder"}));

    let (root, _) = h.root().await;
    let (status, v) = request_on(&mut coder, "POST", "/token", None, Some(&exchange(&root)))
        .await
        .unwrap();
    assert_eq!(status, 200, "{v}");
    let (root, _) = h.root().await;
    let (status, v) = request_on(
        &mut stranger,
        "POST",
        "/token",
        None,
        Some(&exchange(&root)),
    )
    .await
    .unwrap();
    assert_eq!(
        (status, v["error_description"].as_str()),
        (401, Some("client_authentication_failed")),
        "{v}"
    );

    // coder's first thumbprint out, the stranger's in.
    let r = h.reload_coder(&[&c.coder_next, &c.stranger]).await;
    assert_eq!(r["agents"]["changed"], json!(["coder"]), "{r}");
    assert_eq!(r["agents"]["added"], json!([]), "{r}");
    assert_eq!(r["agents"]["removed"], json!([]), "{r}");
    // Thumbprints are never in the answer.
    for cert in [&c.coder, &c.coder_next, &c.stranger] {
        assert!(!r.to_string().contains(&cert.sha256_hex()), "{r}");
    }

    let (root, _) = h.root().await;
    let (status, v) = request_on(&mut coder, "POST", "/token", None, Some(&exchange(&root)))
        .await
        .unwrap();
    assert_eq!(
        (status, v["error_description"].as_str()),
        (401, Some("client_authentication_failed")),
        "{v}"
    );
    let (root, lease) = h.root().await;
    let (status, v) = request_on(
        &mut stranger,
        "POST",
        "/token",
        None,
        Some(&exchange(&root)),
    )
    .await
    .unwrap();
    assert_eq!(status, 200, "{v}");
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest("coder", &lease, METHOD, Some(&c.stranger), false)
    );
    // Back to a secret only: the open connection's certificate stops working.
    let r = h.reload_coder(&[]).await;
    assert_eq!(r["agents"]["changed"], json!(["coder"]), "{r}");
    let (root, _) = h.root().await;
    let (status, v) = request_on(
        &mut stranger,
        "POST",
        "/token",
        None,
        Some(&exchange(&root)),
    )
    .await
    .unwrap();
    assert_eq!(
        (status, v["error_description"].as_str()),
        (401, Some("client_authentication_failed")),
        "{v}"
    );
    h.stop().await;
}

/// SR-109 over real TLS connections from distinct loopback addresses: once the per-peer table
/// is full, a new address whose request names a client and carries its pinned certificate is
/// authenticated and served; one that names a client with no certificate, or with a
/// certificate nobody pinned, gets the `429`.
#[tokio::test]
async fn a_full_peer_table_lets_a_certificate_authenticate_sr109() {
    let h = Harness::start(Opts {
        extra: "[limits]\ntoken_unauthenticated_requests_per_minute = 2\n\
                rate_limit_max_keys = 100\n"
            .into(),
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let (root, _) = h.root().await;
    let body = exchange_body(&root, "coder", json!({"client_id": "coder"}));
    for i in 0..100u8 {
        let ip = std::net::IpAddr::from([127, 0, 1, i]);
        let mut s = connect(&h, None, Some(ip)).await.unwrap();
        let (status, v) = request_on(&mut s, "POST", "/token", None, Some(&body))
            .await
            .unwrap();
        assert_eq!(status, 401, "{i}: {v}");
    }
    let from = |last: u8| Some(std::net::IpAddr::from([127, 0, 2, last]));
    let mut s = connect(&h, Some(c.coder.resolver()), from(1))
        .await
        .unwrap();
    let (status, v) = request_on(&mut s, "POST", "/token", None, Some(&body))
        .await
        .unwrap();
    assert_eq!(status, 200, "{v}");
    let mut refusals = Vec::new();
    for (i, cert) in [None, Some(&c.stranger)].into_iter().enumerate() {
        let mut s = connect(&h, cert.map(ClientCert::resolver), from(10 + i as u8))
            .await
            .unwrap();
        let (status, v) = request_on(&mut s, "POST", "/token", None, Some(&body))
            .await
            .unwrap();
        assert_eq!(status, 429, "{i}: {v}");
        refusals.push(v);
    }
    assert_eq!(refusals[0], refusals[1]);
    h.stop().await;
}

/// The server publishes no OAuth authorization server metadata, so no
/// `token_endpoint_auth_methods_supported`; and it never advertises certificate-bound tokens.
#[tokio::test]
async fn discovery_advertises_no_certificate_bound_tokens() {
    let h = Harness::start(Opts::default()).await;
    for path in [
        "/.well-known/authzen-configuration",
        "/.well-known/jwks.json",
    ] {
        let resp = h.client(None).get(h.url(path)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let text = resp.text().await.unwrap();
        assert!(
            !text.contains("tls_client_certificate_bound_access_tokens"),
            "{text}"
        );
        assert!(
            !text.contains("token_endpoint_auth_methods_supported"),
            "{text}"
        );
        assert!(!text.contains("x5c"), "{text}");
    }
    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ] {
        let resp = h.client(None).get(h.url(path)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
    h.stop().await;
}

/// Without `[server.tls]` the listener is plain HTTP, as before: secrets work, and the records
/// carry no `client_cert`.
#[tokio::test]
async fn a_plain_server_is_unchanged() {
    let h = Harness::start(Opts {
        tls: false,
        ..Opts::default()
    })
    .await;
    let (root, lease) = h.root().await;
    let a = h
        .post(
            None,
            "/token",
            &exchange_body(
                &root,
                "reviewer",
                json!({"client_id": "reviewer", "client_secret": "reviewer-secret"}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest("reviewer", &lease, "client_secret", None, false)
    );
    h.stop().await;
}

// --- tls_client_auth: certificates from a CA ----------------------------------------------

const PKI_METHOD: &str = "tls_client_auth";
const TRUST_DOMAIN: &str = "spiffe://example.org/ns/agents/sa";

fn spiffe(agent: &str) -> String {
    format!("{TRUST_DOMAIN}/{agent}")
}

fn uri_san(s: &str) -> rcgen::SanType {
    rcgen::SanType::URI(s.try_into().unwrap())
}

fn dns_san(s: &str) -> rcgen::SanType {
    rcgen::SanType::DnsName(s.try_into().unwrap())
}

/// The CAs of the `tls_client_auth` tests: the agents' root CA (in `agents-ca.pem`), an
/// intermediate CA under it, and a CA nobody trusts. Their files live in a directory of their
/// own, so the server's lists can name them before the harness starts.
struct Pki {
    dir: tempfile::TempDir,
    root: Ca,
    mid: Ca,
    other: Ca,
    /// A self-signed certificate pinned for `pinned`, so both methods share one list.
    pinned: ClientCert,
}

impl Pki {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = Ca::new("agents root CA");
        let mid = root.intermediate("agents intermediate CA");
        root.write(dir.path(), "agents-ca.pem");
        Self {
            dir,
            root,
            mid,
            other: Ca::new("another CA"),
            pinned: ClientCert::new("pinned"),
        }
    }

    fn ca_path(&self) -> PathBuf {
        self.dir.path().join("agents-ca.pem")
    }

    /// `coder` and `reviewer` by SPIFFE ID, `planner` by DNS name, `both` by SPIFFE ID and a
    /// secret, `pinned` by thumbprint, `secretive` by a secret only; the PEP `gateway` by DNS
    /// name. `coder` has `coder_san` (a `tls_client_auth_san_*` line) instead of its SPIFFE ID
    /// when given.
    fn lists(&self, coder_san: Option<&str>) -> String {
        let ca = self.ca_path().display().to_string();
        let coder = coder_san.map_or_else(
            || format!("tls_client_auth_san_uri = \"{}\"", spiffe("coder")),
            str::to_owned,
        );
        format!(
            "[[agents]]\nid = \"coder\"\ntls_client_ca_pem_path = \"{ca}\"\n{coder}\n\n\
             [[agents]]\nid = \"reviewer\"\ntls_client_ca_pem_path = \"{ca}\"\n\
             tls_client_auth_san_uri = \"{}\"\n\n\
             [[agents]]\nid = \"planner\"\ntls_client_ca_pem_path = \"{ca}\"\n\
             tls_client_auth_san_dns = \"planner.agents.internal\"\n\n\
             [[agents]]\nid = \"both\"\nsecret_sha256 = \"{}\"\ntls_client_ca_pem_path = \"{ca}\"\n\
             tls_client_auth_san_uri = \"{}\"\n\n\
             [[agents]]\nid = \"pinned\"\ntls_client_cert_sha256 = [\"{}\"]\n\n\
             [[agents]]\nid = \"secretive\"\nsecret_sha256 = \"{}\"\n\n\
             [[peps]]\nid = \"gateway\"\ntls_client_ca_pem_path = \"{ca}\"\n\
             tls_client_auth_san_dns = \"gateway.peps.internal\"\n\n\
             [[peps]]\nid = \"pep-secret\"\nsecret_sha256 = \"{}\"\n",
            spiffe("reviewer"),
            sha256_hex("both-secret"),
            spiffe("both"),
            self.pinned.sha256_hex(),
            sha256_hex("secretive-secret"),
            sha256_hex("pep-secret"),
        )
    }

    /// A certificate from the root CA with these names.
    fn client(&self, names: Vec<rcgen::SanType>) -> ClientCert {
        self.root.client(|p| p.subject_alt_names = names)
    }

    async fn harness(&self, opts: Opts) -> Harness {
        Harness::start(Opts {
            lists: Some(self.lists(None)),
            ..opts
        })
        .await
    }
}

impl Harness {
    /// Rewrite the config file with `lists` and reload them.
    async fn reload_lists(&self, lists: &str) -> Answer {
        write_config(
            self.dir.path(),
            &self.server_files,
            &self.issuers,
            &self.opts,
            lists,
        );
        self.reload_coder_raw().await
    }
}

/// Hop 0 by DNS name (in another case), an exchange by SPIFFE ID (with the root CA, and
/// through an intermediate the client sends), with an actor token too, and a PEP by DNS name:
/// served, and the records say `tls_client_auth` and carry the certificate's thumbprint.
#[tokio::test]
async fn pki_agents_and_peps_authenticate_by_name() {
    let pki = Pki::new();
    let h = pki.harness(Opts::default()).await;

    // Hop 0, by DNS name, written in another case in the certificate.
    let planner = pki.client(vec![dns_san("Planner.Agents.INTERNAL")]);
    let a = h
        .post(
            Some(&planner),
            "/token",
            &intake_body(
                &h.issuers.id_token("alice"),
                json!({"client_id": "planner"}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    let verified = h
        .state
        .keys()
        .verifier
        .verify(a.body["access_token"].as_str().unwrap(), now())
        .unwrap();
    let requested = verified.chain.hops[0].capabilities.clone();
    let args = json!({"agent": "planner", "requested": requested, "credential": "id_token",
                      "idp": IDP, "agent_auth": PKI_METHOD, "dpop_bound": false,
                      "client_cert": client_cert_member(&planner)});
    assert_eq!(
        h.last_digest("token.root").await,
        attenuo_core::ToolCall::new("attenuo", "token.root", args).arguments_digest()
    );

    // An exchange by SPIFFE ID: from the root CA, and from the intermediate with its chain.
    let coder = pki.client(vec![uri_san(&spiffe("coder"))]);
    let via_mid = pki
        .mid
        .client(|p| p.subject_alt_names = vec![uri_san(&spiffe("coder"))]);
    assert_eq!(via_mid.chain.len(), 1);
    for cert in [&coder, &via_mid] {
        let (root, lease) = h.root().await;
        let a = h
            .post(
                Some(cert),
                "/token",
                &exchange_body(&root, "coder", json!({"client_id": "coder"})),
            )
            .await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
        assert_eq!(
            h.last_digest("token.exchange").await,
            exchange_digest("coder", &lease, PKI_METHOD, Some(cert), false)
        );
    }
    // With an actor token too, under "either": both are checked.
    let (root, lease) = h.root().await;
    let a = h
        .post(
            Some(&coder),
            "/token",
            &exchange_body(
                &root,
                "coder",
                json!({"client_id": "coder", "actor_token": h.issuers.actor_token("coder"),
                       "actor_token_type": JWT}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest(
            "coder",
            &lease,
            "actor_token+tls_client_auth",
            Some(&coder),
            true
        )
    );

    // A PEP by DNS name, single and batch.
    let gateway = pki.client(vec![dns_san("gateway.peps.internal")]);
    let body = h.evaluation(json!({"pep_id": "gateway"})).await;
    let a = h.post(Some(&gateway), "/access/v1/evaluation", &body).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    let mut batch = body.clone();
    batch["evaluations"] = json!([{}, {}, {}]);
    let a = h
        .post(Some(&gateway), "/access/v1/evaluations", &batch)
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(a.body["evaluations"].as_array().unwrap().len(), 3);
    // An agent's certificate from the same CA is not the PEP's.
    let a = h.post(Some(&coder), "/access/v1/evaluation", &body).await;
    assert_eq!(a.code(), ("invalid_client", "client_authentication_failed"));
    h.stop().await;
}

/// Every certificate that must not authenticate gets the one answer the self-signed method
/// gives (SR-110), and none issues a token or writes a record: another agent's certificate
/// from the same CA (both ways), a certificate from another CA, expired and not yet valid,
/// `CA:TRUE`, the CA's own certificate, server use only, two URI names for a SPIFFE ID, a
/// wildcard DNS name for an exact one, a self-signed certificate with the right name, an
/// intermediate's certificate sent without the intermediate, and certificates for an unknown
/// id and for an entry with a secret only. A certificate with no extended key usage at all
/// authenticates.
#[tokio::test]
async fn pki_refusals_are_one_answer() {
    let pki = Pki::new();
    let h = pki.harness(Opts::default()).await;
    let (root, _) = h.root().await;
    let records = h.audit().await.len();
    let day = time::Duration::days(1);
    let coder_name = || vec![uri_san(&spiffe("coder"))];
    let send = |cert: ClientCert, id: &'static str| {
        let body = exchange_body(&root, id, json!({"client_id": id}));
        let h = &h;
        async move { h.post(Some(&cert), "/token", &body).await }
    };

    // The self-signed method's refusal, as the reference.
    let reference = send(ClientCert::new("stranger"), "pinned").await;
    assert_eq!(
        reference.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        reference.body
    );
    assert_eq!(
        reference.code(),
        ("invalid_client", "client_authentication_failed")
    );
    assert!(reference.challenge.is_some());

    let self_signed = ClientCert::made("coder", |p| p.subject_alt_names = coder_name());
    let cases: Vec<(&str, ClientCert, &'static str)> = vec![
        (
            "reviewer's certificate as coder",
            pki.client(vec![uri_san(&spiffe("reviewer"))]),
            "coder",
        ),
        (
            "coder's certificate as reviewer",
            pki.client(coder_name()),
            "reviewer",
        ),
        (
            "another CA",
            pki.other.client(|p| p.subject_alt_names = coder_name()),
            "coder",
        ),
        (
            "expired",
            pki.root.client(|p| {
                p.subject_alt_names = coder_name();
                p.not_before = now() - day * 30;
                p.not_after = now() - day;
            }),
            "coder",
        ),
        (
            "not yet valid",
            pki.root.client(|p| {
                p.subject_alt_names = coder_name();
                p.not_before = now() + day;
                p.not_after = now() + day * 30;
            }),
            "coder",
        ),
        (
            "CA:TRUE",
            pki.root.client(|p| {
                p.subject_alt_names = coder_name();
                p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            }),
            "coder",
        ),
        ("the CA itself", pki.root.as_client(), "coder"),
        ("the intermediate CA itself", pki.mid.as_client(), "coder"),
        (
            "server use only",
            pki.root.client(|p| {
                p.subject_alt_names = coder_name();
                p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            }),
            "coder",
        ),
        (
            "two URI names",
            pki.client(vec![
                uri_san(&spiffe("coder")),
                uri_san(&spiffe("reviewer")),
            ]),
            "coder",
        ),
        (
            "a wildcard DNS name",
            pki.client(vec![dns_san("*.agents.internal")]),
            "planner",
        ),
        (
            "a DNS name as a URI",
            pki.client(vec![uri_san("dns:planner.agents.internal")]),
            "planner",
        ),
        ("self-signed with the right name", self_signed, "coder"),
        (
            "no intermediate sent",
            pki.mid
                .client(|p| p.subject_alt_names = coder_name())
                .without_chain(),
            "coder",
        ),
        ("an unknown id", pki.client(coder_name()), "nobody"),
        (
            "an entry with a secret only",
            pki.client(coder_name()),
            "secretive",
        ),
        ("a pinned entry", pki.client(coder_name()), "pinned"),
    ];
    for (what, cert, id) in cases {
        let a = send(cert, id).await;
        assert_eq!(a, reference, "{what}");
    }
    assert_eq!(h.audit().await.len(), records, "a refusal wrote a record");

    // No extended key usage and no basicConstraints at all: usable.
    let bare = pki.root.client(|p| {
        p.subject_alt_names = coder_name();
        p.extended_key_usages = vec![];
        p.is_ca = rcgen::IsCa::NoCa;
    });
    let a = send(bare, "coder").await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    // No certificate: no credential.
    let a = h
        .post(
            None,
            "/token",
            &exchange_body(&root, "coder", json!({"client_id": "coder"})),
        )
        .await;
    assert_eq!(a.code(), ("invalid_client", "client_auth_missing"));
    h.stop().await;
}

/// A body credential decides when a CA certificate is on the connection too, and
/// `[token] actor_auth = "actor_token"` refuses a CA certificate with a `client_id`, as for
/// the self-signed method.
#[tokio::test]
async fn pki_body_credentials_and_actor_auth_work_as_for_pins() {
    let pki = Pki::new();
    let h = pki.harness(Opts::default()).await;
    let both = pki.client(vec![uri_san(&spiffe("both"))]);
    let (root, lease) = h.root().await;
    let a = h
        .post(
            Some(&both),
            "/token",
            &exchange_body(
                &root,
                "both",
                json!({"client_id": "both", "client_secret": "wrong"}),
            ),
        )
        .await;
    assert_eq!(a.code(), ("invalid_client", "client_authentication_failed"));
    let a = h
        .post(
            Some(&both),
            "/token",
            &exchange_body(
                &root,
                "both",
                json!({"client_id": "both", "client_secret": "both-secret"}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest("both", &lease, "client_secret", None, false)
    );
    let (root, lease) = h.root().await;
    let a = h
        .post(
            Some(&both),
            "/token",
            &exchange_body(&root, "both", json!({"client_id": "both"})),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest("both", &lease, PKI_METHOD, Some(&both), false)
    );
    h.stop().await;

    let h = pki
        .harness(Opts {
            actor_auth: "actor_token",
            ..Opts::default()
        })
        .await;
    let coder = pki.client(vec![uri_san(&spiffe("coder"))]);
    let (root, lease) = h.root().await;
    let a = h
        .post(
            Some(&coder),
            "/token",
            &exchange_body(&root, "coder", json!({"client_id": "coder"})),
        )
        .await;
    assert_eq!(a.code(), ("invalid_request", "client_auth_not_accepted"));
    let a = h
        .post(
            Some(&coder),
            "/token",
            &exchange_body(
                &root,
                "coder",
                json!({"actor_token": h.issuers.actor_token("coder"), "actor_token_type": JWT}),
            ),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest("coder", &lease, "actor_token", None, true)
    );
    h.stop().await;
}

/// Bad `tls_client_auth` settings stop the server: a pin and a CA on one entry, a CA without
/// a listener that asks for certificates (`"off"`, or no `[server.tls]`), a CA file that holds
/// a client certificate, and a name without a CA file. The message never quotes the file.
#[tokio::test]
async fn pki_settings_are_refused_at_start() {
    let pki = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("mtls test CA");
    let files = ca.write_server_files(dir.path(), &["127.0.0.1"]);
    let issuers = Issuers::start().await;
    let leaf = pki.client(vec![uri_san(&spiffe("coder"))]);
    let leaf_file = pki.dir.path().join("leaf.pem");
    std::fs::write(&leaf_file, &leaf.cert_pem).unwrap();
    let ca_path = pki.ca_path().display().to_string();
    let coder = |extra: &str| {
        format!(
            "[[agents]]\nid = \"coder\"\n{extra}\n[[agents]]\nid = \"planner\"\nsecret_sha256 = \"{}\"\n",
            sha256_hex("p")
        )
    };
    let by_ca = format!(
        "tls_client_ca_pem_path = \"{ca_path}\"\ntls_client_auth_san_uri = \"{}\"\n",
        spiffe("coder")
    );
    let cases: Vec<(Opts, String, String)> = vec![
        (
            Opts::default(),
            coder(&format!(
                "{by_ca}tls_client_cert_sha256 = [\"{}\"]\n",
                leaf.sha256_hex()
            )),
            "set tls_client_cert_sha256 (a self-signed certificate) or tls_client_ca_pem_path \
             (certificates from a CA), not both"
                .into(),
        ),
        (
            Opts {
                client_certificates: "off",
                ..Opts::default()
            },
            coder(&by_ca),
            "tls_client_ca_pem_path needs [server.tls] with client_certificates = \"optional\""
                .into(),
        ),
        (
            Opts {
                tls: false,
                ..Opts::default()
            },
            coder(&by_ca),
            "tls_client_ca_pem_path needs [server.tls] with client_certificates = \"optional\""
                .into(),
        ),
        (
            Opts::default(),
            coder(&format!(
                "tls_client_ca_pem_path = \"{}\"\ntls_client_auth_san_uri = \"{}\"\n",
                leaf_file.display(),
                spiffe("coder")
            )),
            "certificate 1 of the file is not a CA certificate".into(),
        ),
        (
            Opts::default(),
            coder("tls_client_auth_san_dns = \"coder.agents.internal\"\n"),
            "tls_client_auth_san_dns needs tls_client_ca_pem_path".into(),
        ),
        (
            Opts::default(),
            coder(&format!("tls_client_ca_pem_path = \"{ca_path}\"\n")),
            "tls_client_ca_pem_path needs tls_client_auth_san_uri or tls_client_auth_san_dns"
                .into(),
        ),
    ];
    for (opts, lists, want) in cases {
        let path = write_config(dir.path(), &files, &issuers, &opts, &lists);
        let cfg = Config::load(&path).unwrap();
        let err = attenuo_server::build(&cfg).err().expect("refused");
        let msg = format!("{err:#}");
        assert!(msg.contains(&want), "{want}: {msg}");
        assert!(msg.contains("[[agents]] `coder`"), "{msg}");
        let body_line = leaf.cert_pem.lines().nth(1).unwrap();
        assert!(!msg.contains(body_line), "{msg}");
    }
}

/// An exchange for `coder` with `client_id`, on `conn`.
async fn send(
    h: &Harness,
    conn: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> (u16, Value) {
    let (root, _) = h.root().await;
    let body = exchange_body(&root, "coder", json!({"client_id": "coder"}));
    request_on(conn, "POST", "/token", None, Some(&body))
        .await
        .unwrap()
}

/// A reload applies to connections already open: a new content of the CA file (another CA)
/// is a change, and the open connection's certificate stops working on its next request;
/// the file back, it works again; a new name for the entry stops it again; and so does
/// removing the CA settings. Lists without CA settings keep their digest.
#[tokio::test]
async fn pki_a_reload_applies_to_open_connections() {
    let pki = Pki::new();
    let h = pki.harness(Opts::default()).await;
    let coder = pki.client(vec![uri_san(&spiffe("coder"))]);
    let mut conn = connect(&h, Some(coder.resolver()), None).await.unwrap();
    let ok = |(status, v): (u16, Value)| assert_eq!(status, 200, "{v}");
    let refused = |(status, v): (u16, Value)| {
        assert_eq!(
            (status, v["error_description"].as_str()),
            (401, Some("client_authentication_failed")),
            "{v}"
        );
    };
    ok(send(&h, &mut conn).await);

    // The same lists and files: no change, same digest.
    let first = h.reload_lists(&pki.lists(None)).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert_eq!(first.body["agents"]["changed"], json!([]), "{}", first.body);
    ok(send(&h, &mut conn).await);

    // Another CA in the same file: every entry that names it changed.
    pki.other.write(pki.dir.path(), "agents-ca.pem");
    let r = h.reload_lists(&pki.lists(None)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        r.body["agents"]["changed"],
        json!(["both", "coder", "planner", "reviewer"]),
        "{}",
        r.body
    );
    assert_eq!(r.body["peps"]["changed"], json!(["gateway"]), "{}", r.body);
    assert_ne!(r.body["agents"]["sha256"], first.body["agents"]["sha256"]);
    refused(send(&h, &mut conn).await);

    // The file back: the same digest as before, and the open connection works again.
    pki.root.write(pki.dir.path(), "agents-ca.pem");
    let r = h.reload_lists(&pki.lists(None)).await;
    assert_eq!(r.body["agents"]["changed"].as_array().unwrap().len(), 4);
    assert_eq!(r.body["agents"]["sha256"], first.body["agents"]["sha256"]);
    ok(send(&h, &mut conn).await);

    // Another name for coder.
    let r = h
        .reload_lists(&pki.lists(Some(&format!(
            "tls_client_auth_san_uri = \"{}\"",
            spiffe("coder-v2")
        ))))
        .await;
    assert_eq!(r.body["agents"]["changed"], json!(["coder"]), "{}", r.body);
    refused(send(&h, &mut conn).await);
    // A certificate with the new name works at once, on a new connection.
    let v2 = pki.client(vec![uri_san(&spiffe("coder-v2"))]);
    let mut conn2 = connect(&h, Some(v2.resolver()), None).await.unwrap();
    ok(send(&h, &mut conn2).await);

    // No CA settings any more (a secret only): the certificate stops working.
    let lists = pki.lists(None).replace(
        &format!(
            "id = \"coder\"\ntls_client_ca_pem_path = \"{}\"\ntls_client_auth_san_uri = \"{}\"",
            pki.ca_path().display(),
            spiffe("coder")
        ),
        &format!(
            "id = \"coder\"\nsecret_sha256 = \"{}\"",
            sha256_hex("coder-secret")
        ),
    );
    assert!(!lists.contains(&spiffe("coder\"")), "{lists}");
    let r = h.reload_lists(&lists).await;
    assert_eq!(r.body["agents"]["changed"], json!(["coder"]), "{}", r.body);
    refused(send(&h, &mut conn2).await);

    // A reload with a bad CA file is refused, and the lists in force stay.
    std::fs::write(pki.ca_path(), &coder.cert_pem).unwrap();
    let r = h.reload_lists(&pki.lists(None)).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    assert!(
        r.body.to_string().contains("not a CA certificate"),
        "{}",
        r.body
    );
    let reviewer = pki.client(vec![uri_san(&spiffe("reviewer"))]);
    let (root, _) = h.root().await;
    let a = h
        .post(
            Some(&reviewer),
            "/token",
            &exchange_body(&root, "reviewer", json!({"client_id": "reviewer"})),
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    h.stop().await;
}
