//! Certificate-bound access tokens (RFC 8705 §3, ADR-0022): `[token]
//! tls_client_certificate_bound_access_tokens`. Real sockets through [`attenuo_server::run`],
//! the code `serve` runs, with the native TLS listener and the forwarding listener of ADR-0021.
//!
//! Covers: the binding at hop 0 and at an exchange (pinned and CA-issued certificates, from the
//! handshake and from a trusted proxy's header), `token_type`, the audit records, the setting
//! off by default, the refusal of DPoP with a certificate binding, every route that takes a
//! token (MCP `POST` and `GET`, `POST /token/renew`, the three AuthZEN routes,
//! `GET /approvals/{id}`, `POST /token` as subject token, the ext-authz adapter) with the bound
//! certificate, no certificate, another certificate, another certificate of the same CA with the
//! same SAN, and DPoP; children that keep the certificate; a DPoP parent that keeps the DPoP
//! rules; token confusion across listeners; certificate rotation; and the startup refusals.

// Configs are built field by field, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::{ExtAuthzRoute, UpstreamConfig};
use attenuo_server::{AppState, Config};
use attenuo_token::DpopKey;
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use common::tls::{Ca, ClientCert};
use common::{free_port, sha256_hex, Running};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ADMIN: &str = "cert-bound-test-admin-token-0123456789abcdef";
const ISSUER: &str = "https://attenuo.test";
const PUBLIC_URL: &str = "https://localhost:8443";
const IDP: &str = "https://idp.test";
const CLIENT_AUD: &str = "attenuo-client";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const WORKLOAD: &str = "https://workload.test";
const SPIFFE_CODER: &str = "spiffe://example.org/ns/agents/sa/pki-coder";
const GATEWAY_SECRET: &str = "cert-bound-gateway-secret";

const REQUIRED: &str = "client_certificate_required";
const MISMATCH: &str = "client_certificate_mismatch";
const WITH_DPOP: &str = "dpop_with_certificate_binding";

/// Everything is allowed except a destructive call without an approval.
const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);

@id("confirm_destructive")
@obligation("approval")
forbid(principal, action, resource)
when { resource.destructive && !context.approval.present };
"#;

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn uri_san(s: &str) -> rcgen::SanType {
    rcgen::SanType::URI(s.try_into().unwrap())
}

/// A fake IdP and workload issuer, one key each, and the key of the `private_key_jwt` agent
/// `jwt-agent`.
struct Idp {
    key: DpopKey,
    workload: DpopKey,
    agent_key: DpopKey,
    server: Spawned,
}

/// `key`'s public JWK with `kid`, as a JWK Set.
fn jwk_set(key: &DpopKey, kid: &str) -> Value {
    let mut jwk = key.public_jwk().clone();
    jwk["kid"] = kid.into();
    jwk["alg"] = "EdDSA".into();
    json!({ "keys": [jwk] })
}

impl Idp {
    async fn start() -> Self {
        let key = DpopKey::generate().unwrap();
        let workload = DpopKey::generate().unwrap();
        let (a, b) = (jwk_set(&key, "idp-1"), jwk_set(&workload, "wl-1"));
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
            key,
            workload,
            agent_key: DpopKey::generate().unwrap(),
            server: spawn_router(app).await.unwrap(),
        }
    }

    /// An ID-JAG for `sub` and the agent `client_id`, bound by `cnf` when given.
    fn id_jag(&self, sub: &str, client_id: &str, cnf: Option<Value>) -> String {
        let t = now().unix_timestamp();
        let mut claims = json!({"iss": IDP, "aud": ISSUER, "sub": sub, "client_id": client_id,
                                "iat": t, "exp": t + 300,
                                "jti": uuid::Uuid::new_v4().to_string()});
        if let Some(c) = cnf {
            claims["cnf"] = c;
        }
        self.key.sign_jws(
            &json!({"alg": "EdDSA", "kid": "idp-1", "typ": "oauth-id-jag+jwt"}),
            &claims,
        )
    }

    /// A workload-identity JWT for the agent `sub`, from the `[[actor_trust]]` issuer.
    fn actor_token(&self, sub: &str) -> String {
        let t = now().unix_timestamp();
        self.workload.sign_jws(
            &json!({"alg": "EdDSA", "kid": "wl-1", "typ": "JWT"}),
            &json!({"iss": WORKLOAD, "aud": ISSUER, "sub": sub, "iat": t, "exp": t + 300,
                    "jti": uuid::Uuid::new_v4().to_string()}),
        )
    }

    /// A `private_key_jwt` client assertion for `jwt-agent`.
    fn assertion(&self) -> String {
        let t = now().unix_timestamp();
        self.agent_key.sign_jws(
            &json!({"alg": "EdDSA", "kid": "agent-1", "typ": "JWT"}),
            &json!({"iss": "jwt-agent", "sub": "jwt-agent", "aud": ISSUER, "iat": t,
                    "exp": t + 60, "jti": uuid::Uuid::new_v4().to_string()}),
        )
    }

    fn id_token(&self, sub: &str) -> String {
        let t = now().unix_timestamp();
        self.key.sign_jws(
            &json!({"alg": "EdDSA", "kid": "idp-1", "typ": "JWT"}),
            &json!({"iss": IDP, "aud": CLIENT_AUD, "sub": sub, "iat": t, "exp": t + 300,
                    "jti": uuid::Uuid::new_v4().to_string()}),
        )
    }
}

/// The client certificates: self-signed ones pinned for `planner`, `coder` (two, for a
/// rotation) and `both` (with a secret), and two from one
/// intermediate CA with the same SAN URI, which both authenticate as `pki-coder`.
struct Certs {
    dir: tempfile::TempDir,
    planner: ClientCert,
    coder: ClientCert,
    coder_next: ClientCert,
    both: ClientCert,
    pki_coder: ClientCert,
    pki_coder_2: ClientCert,
}

impl Certs {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = Ca::new("cert-bound test root CA");
        let mid = root.intermediate("cert-bound test intermediate CA");
        root.write(dir.path(), "ca.pem");
        Self {
            planner: ClientCert::new("planner"),
            coder: ClientCert::new("coder"),
            coder_next: ClientCert::new("coder"),
            both: ClientCert::new("both"),
            pki_coder: mid.client(|p| p.subject_alt_names = vec![uri_san(SPIFFE_CODER)]),
            pki_coder_2: mid.client(|p| p.subject_alt_names = vec![uri_san(SPIFFE_CODER)]),
            dir,
        }
    }

    fn lists(&self, agent_jwks: &Value) -> String {
        let pin = |c: &ClientCert| format!("\"{}\"", c.sha256_hex());
        let ca = self.dir.path().join("ca.pem").display().to_string();
        format!(
            "[[agents]]\nid = \"planner\"\ntls_client_cert_sha256 = [{}]\n\n\
             [[agents]]\nid = \"coder\"\ntls_client_cert_sha256 = [{}, {}]\n\n\
             [[agents]]\nid = \"reviewer\"\nsecret_sha256 = \"{}\"\n\n\
             [[agents]]\nid = \"both\"\nsecret_sha256 = \"{}\"\ntls_client_cert_sha256 = [{}]\n\n\
             [[agents]]\nid = \"pki-coder\"\ntls_client_ca_pem_path = \"{ca}\"\n\
             tls_client_auth_san_uri = \"{SPIFFE_CODER}\"\n\n\
             [[agents]]\nid = \"jwt-agent\"\njwks = '{agent_jwks}'\n",
            pin(&self.planner),
            pin(&self.coder),
            pin(&self.coder_next),
            sha256_hex("reviewer-secret"),
            sha256_hex("both-secret"),
            pin(&self.both),
        )
    }
}

/// What a test changes in the config.
#[derive(Clone, Copy)]
struct Opts {
    /// `[token] tls_client_certificate_bound_access_tokens`.
    bound: bool,
    /// `[server.tls]` on the main listener, with `client_certificates = "optional"`.
    main_tls: bool,
    /// `[server.forwarded_client_cert]`, trusting `127.0.0.1` only.
    forwarded: bool,
    /// `[token] dpop`.
    dpop: &'static str,
    /// More sections, as TOML.
    extra: &'static str,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            bound: true,
            main_tls: true,
            forwarded: true,
            dpop: "optional",
            extra: "",
        }
    }
}

fn write_config(
    dir: &Path,
    server_files: &(PathBuf, PathBuf),
    idp: &Idp,
    certs: &Certs,
    forwarded: SocketAddr,
    opts: Opts,
) -> PathBuf {
    let mut server = format!("[server]\npublic_url = \"{PUBLIC_URL}\"\n\n");
    if opts.main_tls {
        server += &format!(
            "[server.tls]\ncert_pem_path = \"{}\"\nkey_pem_path = \"{}\"\n\
             client_certificates = \"optional\"\n\n",
            server_files.0.display(),
            server_files.1.display(),
        );
    }
    if opts.forwarded {
        server += &format!(
            "[server.forwarded_client_cert]\nlisten = \"{forwarded}\"\n\
             trusted_peers = [\"127.0.0.1/32\"]\n\n"
        );
    }
    let path = dir.join("attenuo.toml");
    std::fs::write(
        &path,
        format!(
            "{server}[issuer]\nissuer = \"{ISSUER}\"\nprivate_key_pem_path = \"{}\"\n\n\
             [audit]\nsqlite_path = \"{}\"\n\n\
             [admin]\ntoken = \"{ADMIN}\"\n\n\
             [dev]\nallow_root_mint = true\n\n{}\
             [token]\ndpop = \"{}\"\ntls_client_certificate_bound_access_tokens = {}\n\n\
             [[idps]]\nissuer = \"{IDP}\"\njwks_url = \"{}\"\nallowed_algs = [\"EdDSA\"]\n\
             client_ids = {{ planner = \"{CLIENT_AUD}\", \"pki-coder\" = \"{CLIENT_AUD}\", \
             both = \"{CLIENT_AUD}\" }}\n\n\
             [[actor_trust]]\nissuer = \"{WORKLOAD}\"\njwks_url = \"{}\"\naudience = \"{ISSUER}\"\n\
             subject_to_agent = \"sub\"\nallowed_algs = [\"EdDSA\"]\n\n\
             [[root_grants]]\nissuer = \"{IDP}\"\nagent = \"planner\"\ncapabilities = [\"github:*\"]\n\n\
             [[root_grants]]\nissuer = \"{IDP}\"\nagent = \"pki-coder\"\ncapabilities = [\"github:*\"]\n\n\
             [[root_grants]]\nissuer = \"{IDP}\"\nagent = \"both\"\ncapabilities = [\"github:*\"]\n\n{}",
            dir.join("keys/issuer.pem").display(),
            dir.join("audit.sqlite").display(),
            opts.extra,
            opts.dpop,
            opts.bound,
            idp.server.url("/jwks"),
            idp.server.url("/actor-jwks"),
            certs.lists(&jwk_set(&idp.agent_key, "agent-1")),
        ),
    )
    .unwrap();
    path
}

/// The config of a test, with the policy, catalog, upstream and ext-authz route set in code.
fn load(path: &Path, dir: &Path, upstream: &Spawned) -> anyhow::Result<Config> {
    let mut cfg = Config::load(path)?;
    let policy = dir.join("policies.cedar");
    std::fs::write(&policy, POLICY).unwrap();
    cfg.policy.policies_path = Some(policy);
    let repo = || ToolAttrs::new().with_input("repo", ArgType::String);
    cfg.policy.catalog = BTreeMap::from([(
        "github".to_string(),
        BTreeMap::from([
            ("read_file".to_string(), repo().readonly(true)),
            ("delete_repo".to_string(), repo()),
        ]),
    )]);
    cfg.upstreams = vec![UpstreamConfig::new("github", upstream.url("/mcp"))];
    cfg.ext_authz = vec![ExtAuthzRoute {
        server: "github".into(),
        secret_sha256: sha256_hex(GATEWAY_SECRET),
        dpop_url: None,
    }];
    Ok(cfg)
}

/// How a request reaches the server.
#[derive(Clone, Copy)]
enum Via<'a> {
    /// The main listener over TLS (`[server.tls]`), with this certificate in the handshake.
    Native(Option<&'a ClientCert>),
    /// The main listener without TLS.
    Plain,
    /// The forwarding listener, with the headers a trusted proxy sets for this certificate.
    Fwd(Option<&'a ClientCert>),
}

/// How a request carries the token.
#[derive(Clone, Copy, PartialEq)]
enum Auth {
    /// `Authorization: Bearer`.
    Bearer,
    /// `Authorization: Bearer` and a `DPoP` header (a well-formed proof by a fresh key).
    BearerAndProof,
    /// `Authorization: DPoP`, without a proof.
    DpopScheme,
}

struct Harness {
    dir: tempfile::TempDir,
    ca: Ca,
    idp: Idp,
    certs: Certs,
    forwarded: SocketAddr,
    opts: Opts,
    _upstream: Spawned,
    running: Running,
    state: Arc<AppState>,
}

/// What a stopped harness keeps for the next one: the directory (issuer key, audit log and
/// leases), the server CA, the IdP and the client certificates.
struct Kept {
    dir: tempfile::TempDir,
    ca: Ca,
    idp: Idp,
    certs: Certs,
}

impl Harness {
    async fn start(opts: Opts) -> Self {
        Self::start_on(opts, None).await
    }

    /// Start, on what a stopped harness kept when given.
    async fn start_on(opts: Opts, kept: Option<Kept>) -> Self {
        let Kept {
            dir,
            ca,
            idp,
            certs,
        } = match kept {
            Some(k) => k,
            None => Kept {
                dir: tempfile::tempdir().unwrap(),
                ca: Ca::new("cert-bound test server CA"),
                idp: Idp::start().await,
                certs: Certs::new(),
            },
        };
        let server_files = ca.write_server_files(dir.path(), &["127.0.0.1"]);
        let forwarded = free_port();
        let upstream = FakeMcpServer::new(&["read_file", "delete_repo"])
            .spawn()
            .await
            .unwrap();
        let path = write_config(dir.path(), &server_files, &idp, &certs, forwarded, opts);
        let cfg = load(&path, dir.path(), &upstream).unwrap();
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let running = Running::start(cfg, state.clone(), router).await;
        let h = Self {
            dir,
            ca,
            idp,
            certs,
            forwarded,
            opts,
            _upstream: upstream,
            running,
            state,
        };
        // `run` binds the forwarding listener before it serves the main one.
        let a = h
            .send(h.main(None), Method::GET, "/healthz", None, None, &[])
            .await;
        assert_eq!(a.status, StatusCode::OK);
        h
    }

    async fn stop(self) {
        self.running.stop(self.state).await;
    }

    /// Stop, and keep what the next harness needs to serve the same tokens.
    async fn stop_keeping(self) -> Kept {
        self.running.stop(self.state).await;
        Kept {
            dir: self.dir,
            ca: self.ca,
            idp: self.idp,
            certs: self.certs,
        }
    }

    /// The main listener, with `cert` in the handshake when it is TLS.
    fn main<'a>(&self, cert: Option<&'a ClientCert>) -> Via<'a> {
        if self.opts.main_tls {
            Via::Native(cert)
        } else {
            Via::Plain
        }
    }

    /// One request. `token` goes in `Authorization` as `auth` says.
    async fn send(
        &self,
        via: Via<'_>,
        method: Method,
        path: &str,
        token: Option<(&str, Auth)>,
        body: Option<&Value>,
        extra: &[(&str, String)],
    ) -> Answer {
        let (client, url) = match via {
            Via::Native(cert) => {
                assert!(self.opts.main_tls);
                (self.ca.reqwest_client(cert), self.running.https_url(path))
            }
            Via::Plain => {
                assert!(!self.opts.main_tls);
                (plain_client(), self.running.url(path))
            }
            Via::Fwd(_) => (plain_client(), format!("http://{}{path}", self.forwarded)),
        };
        let mut req = client
            .request(method.clone(), url)
            .header("accept", "application/json, text/event-stream");
        if let Via::Fwd(Some(cert)) = via {
            for (k, v) in forwarded_headers(cert) {
                req = req.header(k, v);
            }
        }
        if let Some((t, auth)) = token {
            req = match auth {
                Auth::Bearer => req.bearer_auth(t),
                Auth::BearerAndProof => {
                    let key = DpopKey::generate().unwrap();
                    let proof = key.proof(
                        method.as_str(),
                        &format!("{PUBLIC_URL}{path}"),
                        Some(t),
                        now(),
                    );
                    req.bearer_auth(t).header("DPoP", proof)
                }
                Auth::DpopScheme => req.header("authorization", format!("DPoP {t}")),
            };
        }
        for (k, v) in extra {
            req = req.header(*k, v);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        Answer::of(req.send().await.unwrap()).await
    }

    /// `POST /token` with `body`.
    async fn token(&self, via: Via<'_>, body: &Value, extra: &[(&str, String)]) -> Answer {
        self.send(via, Method::POST, "/token", None, Some(body), extra)
            .await
    }

    /// A root token for `agent` from the dev mint (never bound to a certificate), bound to
    /// `key` when given.
    async fn dev_root(&self, key: Option<&DpopKey>) -> String {
        let extra: Vec<(&str, String)> = key
            .map(|k| {
                vec![(
                    "DPoP",
                    k.proof(
                        "POST",
                        &format!("{PUBLIC_URL}/admin/root-token"),
                        None,
                        now(),
                    ),
                )]
            })
            .unwrap_or_default();
        let a = self
            .send(
                self.main(None),
                Method::POST,
                "/admin/root-token",
                Some((ADMIN, Auth::Bearer)),
                Some(
                    &json!({"subject": "alice", "issuer": IDP, "agent": "planner",
                             "capabilities": ["github:*"]}),
                ),
                &extra,
            )
            .await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
        a.body["access_token"].as_str().unwrap().into()
    }

    /// A token for `actor`, exchanged from a fresh dev root by `cert` over `via`: bound to
    /// `cert` when the setting is on.
    async fn bound_to(&self, via: Via<'_>, actor: &str) -> String {
        let root = self.dev_root(None).await;
        let a = self
            .token(
                via,
                &exchange_body(&root, actor, json!({"client_id": actor})),
                &[],
            )
            .await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
        a.body["access_token"].as_str().unwrap().into()
    }

    fn cnf(&self, token: &str) -> Option<attenuo_token::Confirmation> {
        self.state
            .keys()
            .verifier
            .verify(token, now())
            .unwrap()
            .claims
            .cnf
    }

    fn x5t(&self, token: &str) -> Option<String> {
        self.cnf(token)
            .and_then(|c| c.cert_thumbprint().map(str::to_owned))
    }

    async fn audit(&self) -> Vec<Value> {
        let a = self
            .send(
                self.main(None),
                Method::GET,
                "/admin/audit?from=1&limit=1000",
                Some((ADMIN, Auth::Bearer)),
                None,
                &[],
            )
            .await;
        a.body["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["record"].clone())
            .collect()
    }

    async fn last(&self, tool: &str) -> Value {
        self.audit()
            .await
            .into_iter()
            .rfind(|r| r["tool"] == tool)
            .unwrap_or_else(|| panic!("no {tool} record"))
    }

    async fn count(&self, tool: &str) -> usize {
        self.audit()
            .await
            .iter()
            .filter(|r| r["tool"] == tool)
            .count()
    }
}

fn plain_client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

fn sf_binary(der: &[u8]) -> String {
    format!(
        ":{}:",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

fn forwarded_headers(cert: &ClientCert) -> Vec<(&'static str, String)> {
    let mut h = vec![("Client-Cert", sf_binary(cert.der.as_ref()))];
    if !cert.chain.is_empty() {
        let chain: Vec<String> = cert.chain.iter().map(|c| sf_binary(c.as_ref())).collect();
        h.push(("Client-Cert-Chain", chain.join(", ")));
    }
    h
}

/// An HTTP answer: status and body (JSON, or the `data:` line of an SSE answer).
#[derive(Debug)]
struct Answer {
    status: StatusCode,
    body: Value,
}

impl Answer {
    async fn of(resp: reqwest::Response) -> Self {
        let status = resp.status();
        let text = resp.text().await.unwrap();
        let body = serde_json::from_str(&text)
            .ok()
            .or_else(|| {
                text.lines()
                    .find_map(|l| l.strip_prefix("data:"))
                    .and_then(|d| serde_json::from_str(d.trim()).ok())
            })
            .unwrap_or(Value::Null);
        Self { status, body }
    }

    /// The stable code: a REST error's `code`, the proxy's `error.data.reason`, or the
    /// ext-authz adapter's `error.data.code`.
    fn code(&self) -> &str {
        self.body["code"]
            .as_str()
            .or(self.body["error"]["data"]["reason"].as_str())
            .or(self.body["error"]["data"]["code"].as_str())
            .unwrap_or_default()
    }

    /// Refused with 401 and `code`.
    fn refused(&self, code: &str, what: &str) {
        assert_eq!(
            self.status,
            StatusCode::UNAUTHORIZED,
            "{what}: {}",
            self.body
        );
        assert_eq!(self.code(), code, "{what}: {}", self.body);
    }
}

fn exchange_body(parent: &str, actor: &str, extra: Value) -> Value {
    let mut body = json!({
        "grant_type": EXCHANGE, "subject_token": parent, "subject_token_type": JWT,
        "actor": actor,
        "authorization_details": [{"type": "attenuo_capabilities",
            "capabilities": [{"server": "github", "tool": "read_file"},
                             {"server": "github", "tool": "delete_repo"}]}],
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

fn read_call() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "read_file", "arguments": {"repo": "acme/api"}}})
}

fn evaluation() -> Value {
    json!({
        "subject": {"type": "agent", "id": ""},
        "action": {"name": "read_file"},
        "resource": {"type": "tool", "id": "github/read_file"},
        "context": {"input": {"repo": "acme/api"}},
    })
}

/// A raw TCP connection to `addr` from `source`.
async fn tcp(addr: SocketAddr, source: IpAddr) -> tokio::net::TcpStream {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::new(source, 0)).unwrap();
    socket.connect(addr).await.unwrap()
}

/// One request on a raw connection, read to its end: (status, body).
async fn raw_request(
    stream: &mut tokio::net::TcpStream,
    path: &str,
    headers: &[(&str, String)],
) -> (u16, Value) {
    let extra: String = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect();
    stream
        .write_all(
            format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{extra}\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

// --- issue --------------------------------------------------------------------------------

/// Hop 0 by a pinned certificate (handshake and forwarded) and by a CA-issued one, and an
/// exchange from an unbound parent: the token carries `cnf.x5t#S256` of the certificate,
/// `token_type` is `Bearer`, and the records say `cert_bound`, also in the digest. A client
/// that authenticated with its secret gets no binding, even over a connection with a
/// certificate.
#[tokio::test]
async fn tokens_are_bound_to_the_certificate_that_authenticated() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    for (via, cert, agent, how, source) in [
        (
            Via::Native(Some(&c.planner)),
            &c.planner,
            "planner",
            "self_signed_tls_client_auth",
            "tls",
        ),
        (
            Via::Fwd(Some(&c.planner)),
            &c.planner,
            "planner",
            "self_signed_tls_client_auth",
            "forwarded",
        ),
        (
            Via::Native(Some(&c.pki_coder)),
            &c.pki_coder,
            "pki-coder",
            "tls_client_auth",
            "tls",
        ),
        (
            Via::Fwd(Some(&c.pki_coder)),
            &c.pki_coder,
            "pki-coder",
            "tls_client_auth",
            "forwarded",
        ),
    ] {
        let a = h
            .token(
                via,
                &intake_body(&h.idp.id_token("alice"), json!({"client_id": agent})),
                &[],
            )
            .await;
        assert_eq!(a.status, StatusCode::OK, "{agent} {source}: {}", a.body);
        assert_eq!(a.body["token_type"], "Bearer", "{}", a.body);
        let root = a.body["access_token"].as_str().unwrap();
        assert_eq!(h.x5t(root), Some(cert.x5t_s256()), "{agent} {source}");
        assert_eq!(h.cnf(root).unwrap().key_thumbprint(), None);
        let r = h.last("token.root").await;
        assert_eq!(r["cert_bound"], true, "{r}");
        assert_ne!(r["dpop_bound"], true, "{r}");
        let requested = h
            .state
            .keys()
            .verifier
            .verify(root, now())
            .unwrap()
            .chain
            .hops[0]
            .capabilities
            .clone();
        let args = json!({"agent": agent, "requested": requested, "credential": "id_token",
                          "idp": IDP, "agent_auth": how, "dpop_bound": false,
                          "cert_bound": true,
                          "client_cert": {"x5t#S256": cert.x5t_s256(), "source": source}});
        assert_eq!(
            r["arguments_digest"],
            attenuo_core::ToolCall::new("attenuo", "token.root", args).arguments_digest()
        );
    }

    // An exchange from an unbound parent, by the actor's certificate.
    let child = h.bound_to(Via::Native(Some(&c.coder)), "coder").await;
    assert_eq!(h.x5t(&child), Some(c.coder.x5t_s256()));
    let r = h.last("token.exchange").await;
    assert_eq!(r["cert_bound"], true, "{r}");
    let child = h.bound_to(Via::Fwd(Some(&c.coder)), "coder").await;
    assert_eq!(h.x5t(&child), Some(c.coder.x5t_s256()));

    // A secret decides over the certificate: no binding, no `cert_bound`.
    let a = h
        .token(
            Via::Native(Some(&c.both)),
            &intake_body(
                &h.idp.id_token("alice"),
                json!({"client_id": "both", "client_secret": "both-secret"}),
            ),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(h.cnf(a.body["access_token"].as_str().unwrap()), None);
    let r = h.last("token.root").await;
    assert!(r.get("cert_bound").is_none(), "{r}");
    let root = h.dev_root(None).await;
    let a = h
        .token(
            Via::Native(Some(&c.coder)),
            &exchange_body(
                &root,
                "reviewer",
                json!({"client_id": "reviewer", "client_secret": "reviewer-secret"}),
            ),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(h.cnf(a.body["access_token"].as_str().unwrap()), None);
    assert!(h.last("token.exchange").await.get("cert_bound").is_none());
    h.stop().await;
}

/// Off by default: the same requests get unbound tokens, and no record says `cert_bound`.
#[tokio::test]
async fn the_setting_is_off_by_default() {
    assert!(
        !Config::default()
            .token
            .tls_client_certificate_bound_access_tokens
    );
    let h = Harness::start(Opts {
        bound: false,
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let a = h
        .token(
            Via::Native(Some(&c.planner)),
            &intake_body(&h.idp.id_token("alice"), json!({"client_id": "planner"})),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(a.body["token_type"], "Bearer");
    let root = a.body["access_token"].as_str().unwrap().to_owned();
    assert_eq!(h.cnf(&root), None);
    let child = h.bound_to(Via::Fwd(Some(&c.coder)), "coder").await;
    assert_eq!(h.cnf(&child), None);
    // A bearer token, usable without a certificate.
    let a = h
        .send(
            Via::Native(None),
            Method::POST,
            "/mcp/github",
            Some((&child, Auth::Bearer)),
            Some(&read_call()),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert!(a.body.get("result").is_some(), "{}", a.body);
    assert!(h
        .audit()
        .await
        .iter()
        .all(|r| r.get("cert_bound").is_none()));
    h.stop().await;
}

/// A token has one binding: a request that would bind to the certificate and carries a DPoP
/// proof is refused (400), at hop 0 and at an exchange of an unbound or certificate-bound
/// parent, `subject_token_dpop` included. Nothing is issued.
#[tokio::test]
async fn dpop_with_a_certificate_binding_is_refused_at_issue() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let key = DpopKey::generate().unwrap();
    let proof = || {
        vec![(
            "DPoP",
            key.proof("POST", &format!("{PUBLIC_URL}/token"), None, now()),
        )]
    };
    // The dev mint writes `token.root` records too: take the parents first.
    let root = h.dev_root(None).await;
    let bound = h.bound_to(Via::Native(Some(&c.coder)), "coder").await;
    let roots = h.count("token.root").await;
    let exchanges = h.count("token.exchange").await;
    for via in [Via::Native(Some(&c.planner)), Via::Fwd(Some(&c.planner))] {
        let a = h
            .token(
                via,
                &intake_body(&h.idp.id_token("alice"), json!({"client_id": "planner"})),
                &proof(),
            )
            .await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
        assert_eq!(a.body["error"], "invalid_request");
        assert_eq!(a.code(), WITH_DPOP);
    }
    let a = h
        .token(
            Via::Native(Some(&c.coder)),
            &exchange_body(&root, "coder", json!({"client_id": "coder"})),
            &proof(),
        )
        .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
    assert_eq!(a.code(), WITH_DPOP);
    let reviewer = || json!({"client_id": "reviewer", "client_secret": "reviewer-secret"});
    let a = h
        .token(
            Via::Native(Some(&c.coder)),
            &exchange_body(&bound, "reviewer", reviewer()),
            &proof(),
        )
        .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
    assert_eq!(a.code(), WITH_DPOP);
    let sign_off = key.sign_off(
        &format!("{PUBLIC_URL}/token"),
        &bound,
        key.thumbprint(),
        "reviewer",
        now(),
    );
    let mut with_sign_off = reviewer();
    with_sign_off["subject_token_dpop"] = sign_off.into();
    let a = h
        .token(
            Via::Native(Some(&c.coder)),
            &exchange_body(&bound, "reviewer", with_sign_off),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
    assert_eq!(a.code(), WITH_DPOP);
    assert_eq!(h.count("token.root").await, roots);
    assert_eq!(h.count("token.exchange").await, exchanges);
    h.stop().await;
}

// --- every route that takes a token ---------------------------------------------------------

/// Every route that takes a token, with a token bound to a CA-issued certificate: accepted with
/// that certificate (handshake or forwarded); refused with none, with a pinned certificate of
/// another agent, with another certificate of the same CA and the same SAN (which
/// authenticates as the same agent), with a DPoP proof and with the `DPoP` scheme.
#[tokio::test]
async fn every_route_enforces_the_binding() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let token = h
        .bound_to(Via::Native(Some(&c.pki_coder)), "pki-coder")
        .await;
    assert_eq!(h.x5t(&token), Some(c.pki_coder.x5t_s256()));
    assert_ne!(c.pki_coder.x5t_s256(), c.pki_coder_2.x5t_s256());

    // An approval of this run, for `GET /approvals/{id}`.
    let a = h
        .send(
            Via::Native(Some(&c.pki_coder)),
            Method::POST,
            "/mcp/github",
            Some((&token, Auth::Bearer)),
            Some(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": "delete_repo", "arguments": {"repo": "acme/api"}}})),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        a.body["error"]["data"]["reason"], "approval_required",
        "{}",
        a.body
    );
    let approval = a.body["error"]["data"]["approval_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let mut batch = evaluation();
    batch["evaluations"] = json!([{}, {}]);
    let search = json!({"subject": {"type": "agent", "id": ""},
                        "resource": {"type": "mcp_server", "id": "github"}});
    let approval_path = format!("/approvals/{approval}");
    let routes: Vec<(Method, &str, Option<Value>)> = vec![
        (Method::POST, "/mcp/github", Some(read_call())),
        // A JSON-RPC batch: one token check for the whole request.
        (
            Method::POST,
            "/mcp/github",
            Some(json!([read_call(), {"jsonrpc": "2.0", "id": 9, "method": "tools/list"}])),
        ),
        (Method::GET, "/mcp/github", None),
        (Method::DELETE, "/mcp/github", None),
        (Method::POST, "/token/renew", None),
        (Method::POST, "/access/v1/evaluation", Some(evaluation())),
        (Method::POST, "/access/v1/evaluations", Some(batch)),
        (Method::POST, "/access/v1/search/action", Some(search)),
        (Method::GET, &approval_path, None),
    ];
    for (method, path, body) in &routes {
        let send = |via, auth| {
            h.send(
                via,
                method.clone(),
                path,
                Some((&token, auth)),
                body.as_ref(),
                &[],
            )
        };
        for via in [
            Via::Native(Some(&c.pki_coder)),
            Via::Fwd(Some(&c.pki_coder)),
        ] {
            let a = send(via, Auth::Bearer).await;
            assert_ne!(a.status, StatusCode::UNAUTHORIZED, "{path}: {}", a.body);
            // `GET` and `DELETE` reach the upstream, which answers as it does (405, 400).
            assert!(
                a.status == StatusCode::OK || (*method != Method::POST && path.starts_with("/mcp")),
                "{method} {path}: {} {}",
                a.status,
                a.body
            );
        }
        send(Via::Native(None), Auth::Bearer)
            .await
            .refused(REQUIRED, &format!("{path} native, no certificate"));
        send(Via::Fwd(None), Auth::Bearer)
            .await
            .refused(REQUIRED, &format!("{path} forwarded, no header"));
        for other in [&c.planner, &c.pki_coder_2] {
            send(Via::Native(Some(other)), Auth::Bearer)
                .await
                .refused(MISMATCH, &format!("{path} native, other certificate"));
            send(Via::Fwd(Some(other)), Auth::Bearer)
                .await
                .refused(MISMATCH, &format!("{path} forwarded, other certificate"));
        }
        for auth in [Auth::BearerAndProof, Auth::DpopScheme] {
            send(Via::Native(Some(&c.pki_coder)), auth)
                .await
                .refused(WITH_DPOP, &format!("{path} with DPoP"));
            send(Via::Fwd(Some(&c.pki_coder)), auth)
                .await
                .refused(WITH_DPOP, &format!("{path} forwarded with DPoP"));
        }
    }

    // The records of the accepted requests say `cert_bound`.
    let records = h.audit().await;
    let call = records.iter().rfind(|r| r["tool"] == "read_file").unwrap();
    assert_eq!(call["cert_bound"], true, "{call}");
    assert_ne!(call["dpop_bound"], true, "{call}");
    let renew = h.last("lease.renew").await;
    assert_eq!(renew["cert_bound"], true, "{renew}");

    // The second certificate authenticates as `pki-coder` in its own right.
    let other = h
        .bound_to(Via::Fwd(Some(&c.pki_coder_2)), "pki-coder")
        .await;
    assert_eq!(h.x5t(&other), Some(c.pki_coder_2.x5t_s256()));

    // `POST /token` with it as the subject token: the same certificate only.
    let ex = || {
        exchange_body(
            &token,
            "reviewer",
            json!({"client_id": "reviewer", "client_secret": "reviewer-secret"}),
        )
    };
    let before = h.count("token.exchange").await;
    for via in [
        Via::Native(Some(&c.pki_coder_2)),
        Via::Fwd(Some(&c.pki_coder_2)),
    ] {
        h.token(via, &ex(), &[])
            .await
            .refused(MISMATCH, "exchange, same CA and SAN");
    }
    assert_eq!(h.count("token.exchange").await, before);
    // (One exchange per subject token and actor: a second is a replay.)
    let a = h.token(Via::Fwd(Some(&c.pki_coder)), &ex(), &[]).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.x5t(a.body["access_token"].as_str().unwrap()),
        Some(c.pki_coder.x5t_s256())
    );

    // The ext-authz adapter never sees the agent's certificate: the gateway's own certificate
    // is not the agent's, so a certificate-bound token is refused there. (The forwarding
    // listener does not serve the adapter at all.)
    for via in [
        Via::Native(Some(&c.pki_coder)),
        Via::Fwd(Some(&c.pki_coder)),
    ] {
        let a = h
            .send(
                via,
                Method::POST,
                "/ext-authz/v1/mcp/github",
                Some((&token, Auth::Bearer)),
                Some(&read_call()),
                &[
                    ("x-attenuo-gateway-secret", GATEWAY_SECRET.into()),
                    ("x-envoy-auth-partial-body", "false".into()),
                ],
            )
            .await;
        match via {
            Via::Fwd(_) => assert_eq!(a.status, StatusCode::NOT_FOUND, "{}", a.body),
            _ => a.refused(REQUIRED, "ext-authz"),
        }
    }
    h.stop().await;
}

// --- exchange -------------------------------------------------------------------------------

/// The child of a certificate-bound token is bound to the same certificate, whoever it is for
/// and however that actor authenticated, and the request must show that certificate. Another
/// holder's certificate, no certificate and a secret with another certificate are refused, and
/// nothing is issued.
#[tokio::test]
async fn children_keep_the_certificate() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    // planner (dev mint, unbound) -> coder, bound to coder's certificate.
    let parent = h.bound_to(Via::Native(Some(&c.coder)), "coder").await;
    let x5t = Some(c.coder.x5t_s256());
    let reviewer = || json!({"client_id": "reviewer", "client_secret": "reviewer-secret"});

    let before = h.count("token.exchange").await;
    // Other holders: their own certificates are not the bound one.
    for via in [Via::Native(Some(&c.both)), Via::Fwd(Some(&c.both))] {
        h.token(
            via,
            &exchange_body(&parent, "both", json!({"client_id": "both"})),
            &[],
        )
        .await
        .refused(MISMATCH, "both's certificate");
    }
    for via in [
        Via::Native(Some(&c.pki_coder)),
        Via::Fwd(Some(&c.pki_coder)),
    ] {
        h.token(
            via,
            &exchange_body(&parent, "pki-coder", json!({"client_id": "pki-coder"})),
            &[],
        )
        .await
        .refused(MISMATCH, "pki-coder's certificate");
    }
    // No certificate: a secret alone cannot take the child.
    for via in [Via::Native(None), Via::Fwd(None)] {
        h.token(via, &exchange_body(&parent, "reviewer", reviewer()), &[])
            .await
            .refused(REQUIRED, "no certificate");
    }
    // A secret with another agent's certificate on the connection.
    for via in [Via::Native(Some(&c.planner)), Via::Fwd(Some(&c.planner))] {
        h.token(via, &exchange_body(&parent, "reviewer", reviewer()), &[])
            .await
            .refused(MISMATCH, "secret, other certificate");
    }
    assert_eq!(h.count("token.exchange").await, before);

    // An actor that authenticates by its secret, over a connection with the bound certificate:
    // its child is bound to that certificate, not unbound.
    let a = h
        .token(
            Via::Native(Some(&c.coder)),
            &exchange_body(&parent, "reviewer", reviewer()),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(a.body["token_type"], "Bearer");
    let child = a.body["access_token"].as_str().unwrap().to_owned();
    assert_eq!(h.x5t(&child), x5t);
    let r = h.last("token.exchange").await;
    assert_eq!(r["cert_bound"], true, "{r}");
    // A grandchild, through the forwarding listener, for an agent with a pin of its own: bound
    // to the first certificate still, so `both` could not use it with its own.
    let a = h
        .token(
            Via::Fwd(Some(&c.coder)),
            &exchange_body(
                &child,
                "both",
                json!({"client_id": "both", "client_secret": "both-secret"}),
            ),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    let grandchild = a.body["access_token"].as_str().unwrap().to_owned();
    assert_eq!(h.x5t(&grandchild), x5t);
    h.send(
        Via::Native(Some(&c.both)),
        Method::POST,
        "/mcp/github",
        Some((&grandchild, Auth::Bearer)),
        Some(&read_call()),
        &[],
    )
    .await
    .refused(MISMATCH, "grandchild with both's own certificate");
    h.stop().await;
}

/// A key-bound parent keeps today's DPoP rules exactly, with the setting on and an actor that
/// authenticates with its certificate: the child is key-bound, and without a proof the
/// exchange is refused as before.
#[tokio::test]
async fn a_dpop_parent_keeps_the_dpop_rules() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let key = DpopKey::generate().unwrap();
    let root = h.dev_root(Some(&key)).await;
    assert_eq!(
        h.cnf(&root).unwrap().key_thumbprint(),
        Some(key.thumbprint())
    );
    let ex = || exchange_body(&root, "coder", json!({"client_id": "coder"}));
    // No proof: the DPoP refusal of today, not a certificate binding.
    h.token(Via::Native(Some(&c.coder)), &ex(), &[])
        .await
        .refused("dpop_required", "DPoP parent without a proof");
    // With the parent's proof: a child bound to the same key, `token_type` DPoP.
    let proof = key.proof("POST", &format!("{PUBLIC_URL}/token"), Some(&root), now());
    let a = h
        .token(Via::Native(Some(&c.coder)), &ex(), &[("DPoP", proof)])
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(a.body["token_type"], "DPoP");
    let child = a.body["access_token"].as_str().unwrap();
    assert_eq!(
        h.cnf(child).unwrap().key_thumbprint(),
        Some(key.thumbprint())
    );
    let r = h.last("token.exchange").await;
    assert_eq!(r["dpop_bound"], true, "{r}");
    assert!(r.get("cert_bound").is_none(), "{r}");
    h.stop().await;
}

// --- token confusion ------------------------------------------------------------------------

/// A certificate-bound token replayed where no certificate is shown: on the plain main
/// listener, with a `Client-Cert` header on it, from an untrusted peer of the forwarding
/// listener, and (without the forwarded section) with a header the server ignores.
#[tokio::test]
async fn a_bound_token_is_useless_without_its_certificate() {
    // A plain main listener next to the forwarding listener.
    let h = Harness::start(Opts {
        main_tls: false,
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let token = h.bound_to(Via::Fwd(Some(&c.coder)), "coder").await;
    assert_eq!(h.x5t(&token), Some(c.coder.x5t_s256()));
    for (method, path, body) in [
        (Method::POST, "/mcp/github", Some(read_call())),
        (Method::POST, "/token/renew", None),
        (Method::POST, "/access/v1/evaluation", Some(evaluation())),
    ] {
        h.send(
            Via::Plain,
            method.clone(),
            path,
            Some((&token, Auth::Bearer)),
            body.as_ref(),
            &[],
        )
        .await
        .refused(REQUIRED, &format!("{path} on the plain listener"));
        // A `Client-Cert` header on the plain listener is refused before any route.
        let a = h
            .send(
                Via::Plain,
                method.clone(),
                path,
                Some((&token, Auth::Bearer)),
                body.as_ref(),
                &forwarded_headers(&c.coder),
            )
            .await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST, "{path}: {}", a.body);
        assert_eq!(a.code(), "client_cert_header_not_accepted");
        // The right header from a peer the forwarding listener does not trust.
        let mut conn = tcp(h.forwarded, "127.0.0.2".parse().unwrap()).await;
        let mut headers = forwarded_headers(&c.coder);
        headers.push(("Authorization", format!("Bearer {token}")));
        headers.push(("X-Forwarded-For", "127.0.0.1".into()));
        let (status, v) = raw_request(&mut conn, path, &headers).await;
        assert_eq!(status, 403, "{path}: {v}");
        assert_eq!(v["code"], "forwarded_peer_not_trusted", "{v}");
    }
    // The child exchange on the plain listener: refused too.
    h.token(
        Via::Plain,
        &exchange_body(
            &token,
            "reviewer",
            json!({"client_id": "reviewer", "client_secret": "reviewer-secret"}),
        ),
        &[],
    )
    .await
    .refused(REQUIRED, "exchange on the plain listener");
    // The ext-authz adapter on the plain listener.
    h.send(
        Via::Plain,
        Method::POST,
        "/ext-authz/v1/mcp/github",
        Some((&token, Auth::Bearer)),
        Some(&read_call()),
        &[
            ("x-attenuo-gateway-secret", GATEWAY_SECRET.into()),
            ("x-envoy-auth-partial-body", "false".into()),
        ],
    )
    .await
    .refused(REQUIRED, "ext-authz on the plain listener");
    h.stop().await;

    // Without the forwarded section the header is ignored: it never stands in for a
    // handshake certificate.
    let h = Harness::start(Opts {
        forwarded: false,
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let token = h.bound_to(Via::Native(Some(&c.coder)), "coder").await;
    h.send(
        Via::Native(None),
        Method::POST,
        "/mcp/github",
        Some((&token, Auth::Bearer)),
        Some(&read_call()),
        &forwarded_headers(&c.coder),
    )
    .await
    .refused(REQUIRED, "ignored header, no handshake certificate");
    h.send(
        Via::Native(Some(&c.planner)),
        Method::POST,
        "/mcp/github",
        Some((&token, Auth::Bearer)),
        Some(&read_call()),
        &forwarded_headers(&c.coder),
    )
    .await
    .refused(MISMATCH, "ignored header, other handshake certificate");
    h.stop().await;
}

/// A bound token dies with its certificate: after a rotation the agent authenticates with the
/// new certificate, but its old tokens are refused; a new token is bound to the new one.
#[tokio::test]
async fn a_rotated_certificate_does_not_carry_the_binding() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let old = h.bound_to(Via::Native(Some(&c.coder)), "coder").await;
    for via in [
        Via::Native(Some(&c.coder_next)),
        Via::Fwd(Some(&c.coder_next)),
    ] {
        h.send(
            via,
            Method::POST,
            "/mcp/github",
            Some((&old, Auth::Bearer)),
            Some(&read_call()),
            &[],
        )
        .await
        .refused(MISMATCH, "old token, new certificate");
        h.token(
            via,
            &exchange_body(&old, "coder", json!({"client_id": "coder"})),
            &[],
        )
        .await
        .refused(
            MISMATCH,
            "exchange of the old token with the new certificate",
        );
    }
    let new = h.bound_to(Via::Native(Some(&c.coder_next)), "coder").await;
    assert_eq!(h.x5t(&new), Some(c.coder_next.x5t_s256()));
    let a = h
        .send(
            Via::Native(Some(&c.coder_next)),
            Method::POST,
            "/mcp/github",
            Some((&new, Auth::Bearer)),
            Some(&read_call()),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert!(a.body.get("result").is_some(), "{}", a.body);
    h.stop().await;
}

/// Turning the setting off later does not unbind a token: once bound, always bound. The same
/// issuer key, audit log and certificates, the setting off: the token still needs its
/// certificate.
#[tokio::test]
async fn a_bound_token_stays_bound_with_the_setting_off() {
    let h = Harness::start(Opts::default()).await;
    let token = h.bound_to(Via::Native(Some(&h.certs.coder)), "coder").await;
    let kept = h.stop_keeping().await;
    let h = Harness::start_on(
        Opts {
            bound: false,
            ..Opts::default()
        },
        Some(kept),
    )
    .await;
    let c = &h.certs;
    assert_eq!(h.x5t(&token), Some(c.coder.x5t_s256()));
    let body = read_call();
    let call = |via| {
        h.send(
            via,
            Method::POST,
            "/mcp/github",
            Some((&token, Auth::Bearer)),
            Some(&body),
            &[],
        )
    };
    let a = call(Via::Native(Some(&c.coder))).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert!(a.body.get("result").is_some(), "{}", a.body);
    call(Via::Native(None))
        .await
        .refused(REQUIRED, "setting off, no certificate");
    call(Via::Fwd(Some(&c.planner)))
        .await
        .refused(MISMATCH, "setting off, other certificate");
    // And its child keeps the certificate.
    let a = h
        .token(
            Via::Native(Some(&c.coder)),
            &exchange_body(
                &token,
                "reviewer",
                json!({"client_id": "reviewer", "client_secret": "reviewer-secret"}),
            ),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.x5t(a.body["access_token"].as_str().unwrap()),
        Some(c.coder.x5t_s256())
    );
    h.stop().await;
}

// --- client credentials, ID-JAG and actor tokens -------------------------------------------

/// A `private_key_jwt` assertion is used once (SR-108, SR-111). An exchange of a
/// certificate-bound subject token that is refused for its binding (a DPoP proof of either
/// kind, no certificate, another certificate) is refused before the assertion is recorded, so
/// the same assertion works on the corrected request.
#[tokio::test]
async fn a_binding_refusal_does_not_use_up_the_client_assertion() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let parent = h.bound_to(Via::Native(Some(&c.coder)), "coder").await;
    let assertion = h.idp.assertion();
    let body = |extra: Value| {
        let mut b = exchange_body(
            &parent,
            "jwt-agent",
            json!({"client_id": "jwt-agent", "client_assertion": assertion,
                   "client_assertion_type":
                       "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}),
        );
        for (k, v) in extra.as_object().unwrap() {
            b[k] = v.clone();
        }
        b
    };
    let key = DpopKey::generate().unwrap();
    let url = format!("{PUBLIC_URL}/token");
    let a = h
        .token(
            Via::Native(Some(&c.coder)),
            &body(json!({})),
            &[("DPoP", key.proof("POST", &url, None, now()))],
        )
        .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
    assert_eq!(a.code(), WITH_DPOP);
    let sign_off = key.sign_off(&url, &parent, key.thumbprint(), "jwt-agent", now());
    let a = h
        .token(
            Via::Native(Some(&c.coder)),
            &body(json!({"subject_token_dpop": sign_off})),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
    assert_eq!(a.code(), WITH_DPOP);
    h.token(Via::Native(None), &body(json!({})), &[])
        .await
        .refused(REQUIRED, "assertion, no certificate");
    h.token(Via::Native(Some(&c.planner)), &body(json!({})), &[])
        .await
        .refused(MISMATCH, "assertion, other certificate");
    // Corrected: the same assertion, over the bound certificate.
    let a = h
        .token(Via::Native(Some(&c.coder)), &body(json!({})), &[])
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.x5t(a.body["access_token"].as_str().unwrap()),
        Some(c.coder.x5t_s256())
    );
    // And now it is used up, as any assertion is after an exchange.
    let fresh = h.bound_to(Via::Native(Some(&c.coder)), "coder").await;
    let mut again = body(json!({}));
    again["subject_token"] = fresh.into();
    let a = h.token(Via::Native(Some(&c.coder)), &again, &[]).await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
    assert_eq!(a.code(), "client_assertion_replayed", "{}", a.body);
    h.stop().await;
}

/// An ID-JAG at hop 0, by an agent that authenticates with its certificate: an unbound one
/// gives a certificate-bound root token. One bound to a DPoP key (`cnf.jkt`) cannot be used:
/// with the `DPoP` proof it needs, the request asks for a second binding
/// (`dpop_with_certificate_binding`); without it, the ID-JAG's own rule refuses it
/// (`credential_pop_required`).
#[tokio::test]
async fn a_dpop_bound_id_jag_does_not_go_with_a_certificate_binding() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let body = |jag: String| {
        json!({"grant_type": JWT_BEARER, "assertion": jag, "client_id": "planner",
               "authorization_details": [{"type": "attenuo_capabilities",
                   "capabilities": [{"server": "github", "tool": "read_file"}]}]})
    };
    let a = h
        .token(
            Via::Native(Some(&c.planner)),
            &body(h.idp.id_jag("alice", "planner", None)),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(a.body["token_type"], "Bearer");
    assert_eq!(
        h.x5t(a.body["access_token"].as_str().unwrap()),
        Some(c.planner.x5t_s256())
    );
    let key = DpopKey::generate().unwrap();
    let jkt = || Some(json!({"jkt": key.thumbprint()}));
    let proof = key.proof("POST", &format!("{PUBLIC_URL}/token"), None, now());
    for via in [Via::Native(Some(&c.planner)), Via::Fwd(Some(&c.planner))] {
        let a = h
            .token(
                via,
                &body(h.idp.id_jag("alice", "planner", jkt())),
                &[("DPoP", proof.clone())],
            )
            .await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
        assert_eq!(a.code(), WITH_DPOP, "{}", a.body);
        let a = h
            .token(via, &body(h.idp.id_jag("alice", "planner", jkt())), &[])
            .await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
        assert_eq!(a.body["error"], "invalid_grant", "{}", a.body);
        assert_eq!(a.code(), "credential_pop_required", "{}", a.body);
    }
    h.stop().await;
}

/// Actor tokens (`actor_auth = "either"`, the default). An exchange of a certificate-bound
/// subject token by an actor token alone, over a connection with the parent's certificate,
/// gives a child bound to that certificate; without it or with another one it is refused. An
/// actor token alone never binds an unbound parent's child; with a certificate client next to
/// it, the child is bound.
#[tokio::test]
async fn actor_tokens_and_the_certificate_binding() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let actor =
        |agent: &str| json!({"actor_token": h.idp.actor_token(agent), "actor_token_type": JWT});
    let parent = h.bound_to(Via::Native(Some(&c.coder)), "coder").await;
    let before = h.count("token.exchange").await;
    h.token(
        Via::Native(None),
        &exchange_body(&parent, "reviewer", actor("reviewer")),
        &[],
    )
    .await
    .refused(REQUIRED, "actor token, no certificate");
    h.token(
        Via::Fwd(Some(&c.planner)),
        &exchange_body(&parent, "reviewer", actor("reviewer")),
        &[],
    )
    .await
    .refused(MISMATCH, "actor token, other certificate");
    assert_eq!(h.count("token.exchange").await, before);
    let a = h
        .token(
            Via::Native(Some(&c.coder)),
            &exchange_body(&parent, "reviewer", actor("reviewer")),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.x5t(a.body["access_token"].as_str().unwrap()),
        Some(c.coder.x5t_s256())
    );
    let r = h.last("token.exchange").await;
    assert_eq!(r["cert_bound"], true, "{r}");

    // An unbound parent: an actor token alone, over a certificate connection, binds nothing.
    let root = h.dev_root(None).await;
    let a = h
        .token(
            Via::Native(Some(&c.coder)),
            &exchange_body(&root, "reviewer", actor("reviewer")),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(h.cnf(a.body["access_token"].as_str().unwrap()), None);
    // With the certificate client next to the actor token, both are checked and the child is
    // bound to the certificate.
    let mut both = actor("coder");
    both["client_id"] = "coder".into();
    let a = h
        .token(
            Via::Native(Some(&c.coder)),
            &exchange_body(&root, "coder", both),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.x5t(a.body["access_token"].as_str().unwrap()),
        Some(c.coder.x5t_s256())
    );
    h.stop().await;
}

/// `[limits] token_requests_per_minute` counts an exchange refused for its certificate binding
/// before the client credential is used, as it counts any other exchange: repeated refusals
/// reach 429. An exchange that passes that check is counted once, not twice.
#[tokio::test]
async fn binding_refusals_are_counted_by_the_agent_rate_limit() {
    let h = Harness::start(Opts {
        extra: "[limits]\ntoken_requests_per_minute = 2\n\n",
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let secret = |id: &str| json!({"client_id": id, "client_secret": format!("{id}-secret")});
    // Refused for the binding, twice; the third is over the limit.
    let parent = h.bound_to(Via::Native(Some(&c.coder)), "coder").await;
    for _ in 0..2 {
        h.token(
            Via::Native(Some(&c.planner)),
            &exchange_body(&parent, "reviewer", secret("reviewer")),
            &[],
        )
        .await
        .refused(MISMATCH, "reviewer over planner's certificate");
    }
    let a = h
        .token(
            Via::Native(Some(&c.planner)),
            &exchange_body(&parent, "reviewer", secret("reviewer")),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::TOO_MANY_REQUESTS, "{}", a.body);
    assert_eq!(a.code(), "rate_limited", "{}", a.body);
    // Over the limit even with the right certificate.
    let a = h
        .token(
            Via::Native(Some(&c.coder)),
            &exchange_body(&parent, "reviewer", secret("reviewer")),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::TOO_MANY_REQUESTS, "{}", a.body);

    // Exchanges that pass the check: two fit in the limit of two, so each counts once.
    let p1 = h
        .bound_to(Via::Native(Some(&c.pki_coder)), "pki-coder")
        .await;
    let p2 = h
        .bound_to(Via::Native(Some(&c.pki_coder)), "pki-coder")
        .await;
    for p in [&p1, &p2] {
        let a = h
            .token(
                Via::Native(Some(&c.pki_coder)),
                &exchange_body(p, "both", secret("both")),
                &[],
            )
            .await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    }
    let a = h
        .token(
            Via::Native(Some(&c.pki_coder)),
            &exchange_body(&p1, "both", secret("both")),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::TOO_MANY_REQUESTS, "{}", a.body);
    h.stop().await;
}

// --- one connection, many tokens ------------------------------------------------------------

/// Send one request on `stream` (kept alive) and read the answer by its `Content-Length`:
/// (status, body).
async fn request_on(
    stream: &mut tokio::net::TcpStream,
    path: &str,
    headers: &[(&str, String)],
    body: &Value,
) -> (u16, Value) {
    let body = body.to_string();
    let extra: String = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect();
    stream
        .write_all(
            format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{extra}\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "closed before a full response");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map_or(0, |v| v.trim().parse::<usize>().unwrap());
            if buf.len() >= end + 4 + len {
                let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
                let v = serde_json::from_slice(&buf[end + 4..end + 4 + len]).unwrap_or(Value::Null);
                return (status, v);
            }
        }
    }
}

/// Requests with different tokens on one kept-alive connection each get their own answer: a
/// token bound to one certificate and a token bound to another, with each certificate, and
/// with none. On the forwarding listener (a proxy sends many clients' requests on one
/// connection) and on one TLS connection with one handshake certificate.
#[tokio::test]
async fn tokens_on_one_connection_each_get_their_own_answer() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let a_token = h.bound_to(Via::Fwd(Some(&c.coder)), "coder").await;
    let b_token = h.bound_to(Via::Fwd(Some(&c.pki_coder)), "pki-coder").await;
    let mut conn = tcp(h.forwarded, "127.0.0.1".parse().unwrap()).await;
    let ask = |token: &str, cert: Option<&ClientCert>| {
        let mut hd = cert.map(forwarded_headers).unwrap_or_default();
        hd.push(("Authorization", format!("Bearer {token}")));
        hd
    };
    for round in 0..2 {
        for (token, cert, want) in [
            (&a_token, Some(&c.coder), None),
            (&b_token, Some(&c.coder), Some(MISMATCH)),
            (&b_token, Some(&c.pki_coder), None),
            (&a_token, Some(&c.pki_coder), Some(MISMATCH)),
            (&a_token, None, Some(REQUIRED)),
            (&b_token, Some(&c.pki_coder), None),
        ] {
            let (status, v) = request_on(
                &mut conn,
                "/access/v1/evaluation",
                &ask(token, cert),
                &evaluation(),
            )
            .await;
            match want {
                None => assert_eq!(status, 200, "round {round}: {v}"),
                Some(code) => {
                    assert_eq!(status, 401, "round {round}: {v}");
                    assert_eq!(v["code"], code, "round {round}: {v}");
                }
            }
        }
    }

    // One TLS client, one handshake certificate, kept-alive connections.
    let client = h.ca.reqwest_client(Some(&c.coder));
    for (token, ok) in [(&a_token, true), (&b_token, false), (&a_token, true)] {
        let a = Answer::of(
            client
                .post(h.running.https_url("/access/v1/evaluation"))
                .bearer_auth(token)
                .json(&evaluation())
                .send()
                .await
                .unwrap(),
        )
        .await;
        if ok {
            assert_eq!(a.status, StatusCode::OK, "{}", a.body);
        } else {
            a.refused(MISMATCH, "other token on the same TLS client");
        }
    }
    h.stop().await;
}

// --- startup ----------------------------------------------------------------------------------

/// The setting needs a listener that takes client certificates, and does not go with
/// `dpop = "required"`.
#[tokio::test]
async fn startup_refuses_settings_that_cannot_work() {
    let idp = Idp::start().await;
    let certs = Certs::new();
    let upstream = FakeMcpServer::new(&["read_file"]).spawn().await.unwrap();
    for (opts, needle) in [
        (
            Opts {
                main_tls: false,
                forwarded: false,
                ..Opts::default()
            },
            "needs a listener that takes client certificates",
        ),
        (
            Opts {
                dpop: "required",
                ..Opts::default()
            },
            "dpop = \"required\"",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::new("startup CA");
        let files = ca.write_server_files(dir.path(), &["127.0.0.1"]);
        let path = write_config(dir.path(), &files, &idp, &certs, free_port(), opts);
        let err = load(&path, dir.path(), &upstream)
            .and_then(|cfg| attenuo_server::build(&cfg).map(|_| ()))
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("tls_client_certificate_bound_access_tokens"),
            "{msg}"
        );
        assert!(msg.contains(needle), "{msg}");
    }
}

// --- ID-JAG bound to a certificate (ADR-0025) ----------------------------------------------

const CERT_REQUIRED: &str = "credential_cert_required";
const CERT_MISMATCH: &str = "credential_cert_mismatch";
const CNF_UNSUPPORTED: &str = "credential_cnf_unsupported";

/// A `jwt-bearer` body for `jag`, with the agent's credentials in `auth`.
fn jag_body(jag: &str, auth: Value) -> Value {
    let mut body = json!({"grant_type": JWT_BEARER, "assertion": jag,
        "authorization_details": [{"type": "attenuo_capabilities",
            "capabilities": [{"server": "github", "tool": "read_file"}]}]});
    for (k, v) in auth.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

/// `cnf` binding an ID-JAG to `cert`.
fn x5t_cnf(cert: &ClientCert) -> Option<Value> {
    Some(json!({ "x5t#S256": cert.x5t_s256() }))
}

/// Refused with 400 `invalid_grant` and `code`.
fn refused_grant(a: &Answer, code: &str, what: &str) {
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{what}: {}", a.body);
    assert_eq!(a.body["error"], "invalid_grant", "{what}: {}", a.body);
    assert_eq!(a.code(), code, "{what}: {}", a.body);
}

/// An ID-JAG with `cnf.x5t#S256` is accepted at hop 0 from an agent that authenticated with
/// that certificate: pinned or CA-issued, from the handshake or from the trusted proxy. The
/// root token is bound to the same certificate, the record says so (`cert_bound`, and
/// `id_jag_cnf`, in the digest too), and a child keeps the binding.
#[tokio::test]
async fn a_certificate_bound_id_jag_is_accepted_with_its_certificate() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    for (via, cert, agent, how, source) in [
        (
            Via::Native(Some(&c.planner)),
            &c.planner,
            "planner",
            "self_signed_tls_client_auth",
            "tls",
        ),
        (
            Via::Fwd(Some(&c.planner)),
            &c.planner,
            "planner",
            "self_signed_tls_client_auth",
            "forwarded",
        ),
        (
            Via::Native(Some(&c.pki_coder)),
            &c.pki_coder,
            "pki-coder",
            "tls_client_auth",
            "tls",
        ),
        (
            Via::Fwd(Some(&c.pki_coder)),
            &c.pki_coder,
            "pki-coder",
            "tls_client_auth",
            "forwarded",
        ),
    ] {
        let jag = h.idp.id_jag("alice", agent, x5t_cnf(cert));
        let a = h
            .token(via, &jag_body(&jag, json!({"client_id": agent})), &[])
            .await;
        assert_eq!(a.status, StatusCode::OK, "{agent} {source}: {}", a.body);
        assert_eq!(a.body["token_type"], "Bearer", "{}", a.body);
        let root = a.body["access_token"].as_str().unwrap();
        assert_eq!(h.x5t(root), Some(cert.x5t_s256()), "{agent} {source}");
        let r = h.last("token.root").await;
        assert_eq!(r["cert_bound"], true, "{r}");
        let requested = h
            .state
            .keys()
            .verifier
            .verify(root, now())
            .unwrap()
            .chain
            .hops[0]
            .capabilities
            .clone();
        let args = json!({"agent": agent, "requested": requested, "credential": "id-jag",
                          "idp": IDP, "agent_auth": how, "dpop_bound": false,
                          "cert_bound": true, "id_jag_cnf": "x5t#S256",
                          "client_cert": {"x5t#S256": cert.x5t_s256(), "source": source}});
        assert_eq!(
            r["arguments_digest"],
            attenuo_core::ToolCall::new("attenuo", "token.root", args).arguments_digest(),
            "{agent} {source}"
        );
        // The same ID-JAG again: used once.
        let a = h
            .token(via, &jag_body(&jag, json!({"client_id": agent})), &[])
            .await;
        refused_grant(&a, "replayed", "the ID-JAG replayed");
    }
    // An unbound ID-JAG's record has no `id_jag_cnf`.
    let a = h
        .token(
            Via::Native(Some(&c.planner)),
            &jag_body(
                &h.idp.id_jag("alice", "planner", None),
                json!({"client_id": "planner"}),
            ),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert!(h.last("token.root").await.get("id_jag_cnf").is_none());

    // A child keeps the certificate: an exchange over a connection that shows it, for an
    // actor that authenticates by its secret; refused without the certificate.
    let jag = h.idp.id_jag("alice", "planner", x5t_cnf(&c.planner));
    let a = h
        .token(
            Via::Native(Some(&c.planner)),
            &jag_body(&jag, json!({"client_id": "planner"})),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    let root = a.body["access_token"].as_str().unwrap().to_owned();
    // The root token carries `github:read_file` only.
    let child_body = || {
        let mut b = exchange_body(
            &root,
            "reviewer",
            json!({"client_id": "reviewer", "client_secret": "reviewer-secret"}),
        );
        b["authorization_details"][0]["capabilities"] =
            json!([{"server": "github", "tool": "read_file"}]);
        b
    };
    h.token(Via::Native(None), &child_body(), &[])
        .await
        .refused(REQUIRED, "child without the certificate");
    let a = h
        .token(Via::Fwd(Some(&c.planner)), &child_body(), &[])
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    let child = a.body["access_token"].as_str().unwrap().to_owned();
    assert_eq!(h.x5t(&child), Some(c.planner.x5t_s256()));
    for (via, refusal) in [
        (Via::Native(Some(&c.planner)), None),
        (Via::Native(None), Some(REQUIRED)),
        (Via::Native(Some(&c.coder)), Some(MISMATCH)),
    ] {
        let a = h
            .send(
                via,
                Method::POST,
                "/mcp/github",
                Some((&child, Auth::Bearer)),
                Some(&read_call()),
                &[],
            )
            .await;
        match refusal {
            None => assert_eq!(a.status, StatusCode::OK, "{}", a.body),
            Some(code) => a.refused(code, "the child on MCP"),
        }
    }
    h.stop().await;
}

/// Refusals of an ID-JAG bound to a certificate, each with nothing issued and nothing used up:
/// no certificate; a certificate on the connection that did not authenticate the agent;
/// another certificate (a pinned one, and a second one from the same CA with the same SAN); a
/// `DPoP` proof alongside; both `cnf` members; an `x5t#S256` of the wrong length or encoding;
/// an actor token alone. After them the same ID-JAG, and the same DPoP proof, still work.
#[tokio::test]
async fn a_certificate_bound_id_jag_is_refused_without_its_certificate() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let roots = h.count("token.root").await;
    let both = || json!({"client_id": "both", "client_secret": "both-secret"});
    let jag = h.idp.id_jag("alice", "both", x5t_cnf(&c.both));

    // No certificate: the agent authenticates by its secret.
    for via in [Via::Native(None), Via::Fwd(None)] {
        refused_grant(
            &h.token(via, &jag_body(&jag, both()), &[]).await,
            CERT_REQUIRED,
            "secret, no certificate",
        );
    }
    // The bound certificate is on the connection, but the secret authenticated the agent.
    for via in [Via::Native(Some(&c.both)), Via::Fwd(Some(&c.both))] {
        refused_grant(
            &h.token(via, &jag_body(&jag, both()), &[]).await,
            CERT_REQUIRED,
            "secret, bound certificate on the connection",
        );
    }
    // Another certificate: planner's ID-JAG bound to coder's, and pki-coder's ID-JAG presented
    // with the second certificate of the same CA and the same SAN, which authenticates as
    // pki-coder too.
    let to_coder = h.idp.id_jag("alice", "planner", x5t_cnf(&c.coder));
    let pki = h.idp.id_jag("alice", "pki-coder", x5t_cnf(&c.pki_coder));
    for via in [Via::Native(Some(&c.planner)), Via::Fwd(Some(&c.planner))] {
        refused_grant(
            &h.token(
                via,
                &jag_body(&to_coder, json!({"client_id": "planner"})),
                &[],
            )
            .await,
            CERT_MISMATCH,
            "another pinned certificate",
        );
    }
    for via in [
        Via::Native(Some(&c.pki_coder_2)),
        Via::Fwd(Some(&c.pki_coder_2)),
    ] {
        refused_grant(
            &h.token(via, &jag_body(&pki, json!({"client_id": "pki-coder"})), &[])
                .await,
            CERT_MISMATCH,
            "same CA, same SAN",
        );
    }
    // An actor token alone authenticates the agent without its certificate.
    let planner_jag = h.idp.id_jag("alice", "planner", x5t_cnf(&c.planner));
    let actor = json!({"actor_token": h.idp.actor_token("planner"), "actor_token_type": JWT});
    refused_grant(
        &h.token(
            Via::Native(Some(&c.planner)),
            &jag_body(&planner_jag, actor),
            &[],
        )
        .await,
        CERT_REQUIRED,
        "actor token alone",
    );
    // A DPoP proof alongside: one binding only, whatever the certificate.
    let key = DpopKey::generate().unwrap();
    let proof = key.proof("POST", &format!("{PUBLIC_URL}/token"), None, now());
    for via in [Via::Native(Some(&c.planner)), Via::Fwd(Some(&c.planner))] {
        let a = h
            .token(
                via,
                &jag_body(&planner_jag, json!({"client_id": "planner"})),
                &[("DPoP", proof.clone())],
            )
            .await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
        assert_eq!(a.body["error"], "invalid_request", "{}", a.body);
        assert_eq!(a.code(), WITH_DPOP, "{}", a.body);
    }
    // Both members, a member this server does not know, an `x5t#S256` of the wrong length or
    // encoding.
    let x5t = c.planner.x5t_s256();
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&x5t)
        .unwrap();
    let std_b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    for cnf in [
        json!({"jkt": key.thumbprint(), "x5t#S256": x5t}),
        json!({"x5t#S256": x5t, "x5t": "abc"}),
        json!({ "x5t#S256": &x5t[..42] }),
        json!({ "x5t#S256": format!("{x5t}A") }),
        json!({ "x5t#S256": format!("{x5t}=") }),
        json!({ "x5t#S256": std_b64 }),
        json!({ "x5t#S256": c.planner.sha256_hex() }),
        json!({ "x5t#S256": [x5t] }),
    ] {
        let jag = h.idp.id_jag("alice", "planner", Some(cnf.clone()));
        refused_grant(
            &h.token(
                Via::Native(Some(&c.planner)),
                &jag_body(&jag, json!({"client_id": "planner"})),
                &[],
            )
            .await,
            CNF_UNSUPPORTED,
            &cnf.to_string(),
        );
    }
    assert_eq!(h.count("token.root").await, roots, "nothing was issued");

    // None of these used anything up: the same ID-JAGs with their certificates work now, and
    // the DPoP proof binds an unbound ID-JAG's root token.
    for (via, jag, auth) in [
        (
            Via::Native(Some(&c.planner)),
            &planner_jag,
            json!({"client_id": "planner"}),
        ),
        (
            Via::Fwd(Some(&c.pki_coder)),
            &pki,
            json!({"client_id": "pki-coder"}),
        ),
    ] {
        let a = h.token(via, &jag_body(jag, auth), &[]).await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    }
    let a = h
        .token(
            Via::Native(None),
            &jag_body(&h.idp.id_jag("alice", "both", None), both()),
            &[("DPoP", proof)],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.cnf(a.body["access_token"].as_str().unwrap())
            .unwrap()
            .key_thumbprint(),
        Some(key.thumbprint())
    );
    h.stop().await;
}

/// A refused ID-JAG bound to a certificate does not use up a `private_key_jwt` assertion: an
/// agent with keys and no certificate is refused before the assertion is recorded, and the
/// same assertion works on the next request.
#[tokio::test]
async fn a_certificate_bound_id_jag_refusal_does_not_use_up_the_client_assertion() {
    let h = Harness::start(Opts {
        extra: "[[root_grants]]\nissuer = \"https://idp.test\"\nagent = \"jwt-agent\"\n\
                capabilities = [\"github:*\"]\n\n",
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let assertion = h.idp.assertion();
    let auth = || {
        json!({"client_id": "jwt-agent", "client_assertion": assertion,
               "client_assertion_type":
                   "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"})
    };
    let bound = h.idp.id_jag("alice", "jwt-agent", x5t_cnf(&c.planner));
    for via in [Via::Native(None), Via::Native(Some(&c.planner))] {
        refused_grant(
            &h.token(via, &jag_body(&bound, auth()), &[]).await,
            CERT_REQUIRED,
            "assertion",
        );
    }
    let a = h
        .token(
            Via::Native(Some(&c.planner)),
            &jag_body(&h.idp.id_jag("alice", "jwt-agent", None), auth()),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    let a = h
        .token(
            Via::Native(None),
            &jag_body(&h.idp.id_jag("alice", "jwt-agent", None), auth()),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
    assert_eq!(a.code(), "client_assertion_replayed", "{}", a.body);
    h.stop().await;
}

/// The certificate must come from the handshake or the trusted proxy: a `Client-Cert` header
/// on the main listener is refused before any route, the forwarding listener refuses a peer it
/// does not trust, and without the forwarded section the header is ignored.
#[tokio::test]
async fn a_certificate_bound_id_jag_takes_no_header_from_elsewhere() {
    let h = Harness::start(Opts {
        main_tls: false,
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let jag = h.idp.id_jag("alice", "planner", x5t_cnf(&c.planner));
    let body = jag_body(&jag, json!({"client_id": "planner"}));
    let a = h
        .token(Via::Plain, &body, &forwarded_headers(&c.planner))
        .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
    assert_eq!(a.code(), "client_cert_header_not_accepted");
    let mut conn = tcp(h.forwarded, "127.0.0.2".parse().unwrap()).await;
    let (status, v) = raw_request(&mut conn, "/token", &forwarded_headers(&c.planner)).await;
    assert_eq!(status, 403, "{v}");
    assert_eq!(v["code"], "forwarded_peer_not_trusted", "{v}");
    // The ID-JAG was not used up.
    let a = h.token(Via::Fwd(Some(&c.planner)), &body, &[]).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    h.stop().await;

    let h = Harness::start(Opts {
        forwarded: false,
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let jag = h.idp.id_jag("alice", "both", x5t_cnf(&c.both));
    let a = h
        .token(
            Via::Native(None),
            &jag_body(
                &jag,
                json!({"client_id": "both", "client_secret": "both-secret"}),
            ),
            &forwarded_headers(&c.both),
        )
        .await;
    refused_grant(&a, CERT_REQUIRED, "ignored header");
    h.stop().await;
}

/// With `[token] tls_client_certificate_bound_access_tokens` off the root token would be a
/// bearer token, so an ID-JAG bound to a certificate is refused even with that certificate:
/// its binding is never dropped. With a DPoP proof it is refused for the second binding.
#[tokio::test]
async fn a_certificate_bound_id_jag_is_refused_when_tokens_are_not_bound() {
    let h = Harness::start(Opts {
        bound: false,
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let jag = h.idp.id_jag("alice", "planner", x5t_cnf(&c.planner));
    let body = jag_body(&jag, json!({"client_id": "planner"}));
    for via in [Via::Native(Some(&c.planner)), Via::Fwd(Some(&c.planner))] {
        refused_grant(
            &h.token(via, &body, &[]).await,
            CERT_REQUIRED,
            "setting off",
        );
    }
    let key = DpopKey::generate().unwrap();
    let proof = key.proof("POST", &format!("{PUBLIC_URL}/token"), None, now());
    let a = h
        .token(
            Via::Native(Some(&c.planner)),
            &body,
            &[("DPoP", proof.clone())],
        )
        .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
    assert_eq!(a.code(), WITH_DPOP, "{}", a.body);
    // The proof was not used: it binds an unbound ID-JAG's root token now.
    let a = h
        .token(
            Via::Native(Some(&c.planner)),
            &jag_body(
                &h.idp.id_jag("alice", "planner", None),
                json!({"client_id": "planner"}),
            ),
            &[("DPoP", proof)],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(a.body["token_type"], "DPoP", "{}", a.body);
    assert_eq!(h.count("token.root").await, 1);
    h.stop().await;
}

/// `[[root_grants]]` for `jwt-agent` and `[limits] token_requests_per_minute = 2`.
const JWT_AGENT_LIMITED: &str = "[[root_grants]]\nissuer = \"https://idp.test\"\n\
    agent = \"jwt-agent\"\ncapabilities = [\"github:*\"]\n\n\
    [limits]\ntoken_requests_per_minute = 2\n\n";

/// `client_assertion` fields for `jwt-agent`.
fn assertion_auth(assertion: &str) -> Value {
    json!({"client_id": "jwt-agent", "client_assertion": assertion,
           "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"})
}

/// A subject token nobody signed, whose payload has the `cnf` given.
fn forged_with_cnf(cnf: Value) -> String {
    let b64 = |v: Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap())
    };
    format!(
        "{}.{}.c2ln",
        b64(json!({"alg": "none", "typ": "oauth-id-jag+jwt"})),
        b64(json!({ "cnf": cnf }))
    )
}

/// A used `private_key_jwt` assertion on a request the early `cnf` pass refuses is a replay:
/// 401 `client_assertion_replayed`, as on any other request, and it is not counted by
/// `[limits] token_requests_per_minute`, so whoever holds an old assertion cannot spend the
/// agent's budget. An unused assertion's early refusal is counted, once.
#[tokio::test]
async fn a_used_assertion_is_a_replay_before_the_early_cnf_refusal() {
    let h = Harness::start(Opts {
        extra: JWT_AGENT_LIMITED,
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let used = h.idp.assertion();
    let unbound = || h.idp.id_jag("alice", "jwt-agent", None);
    // Counted: 1.
    let a = h
        .token(
            Via::Native(None),
            &jag_body(&unbound(), assertion_auth(&used)),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    for (forged, via) in [
        (forged_with_cnf(json!("x")), Via::Native(None)),
        (
            forged_with_cnf(json!({"jkt": "k", "kid": "k"})),
            Via::Native(None),
        ),
        (
            h.idp.id_jag("alice", "jwt-agent", x5t_cnf(&c.planner)),
            Via::Native(Some(&c.planner)),
        ),
    ] {
        for _ in 0..3 {
            let a = h
                .token(via, &jag_body(&forged, assertion_auth(&used)), &[])
                .await;
            assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
            assert_eq!(a.code(), "client_assertion_replayed", "{}", a.body);
        }
    }
    // The agent's budget is untouched: its next request passes (counted: 2).
    let a = h
        .token(
            Via::Native(None),
            &jag_body(&unbound(), assertion_auth(&h.idp.assertion())),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    // An unused assertion's early refusal is counted: over the limit now.
    let a = h
        .token(
            Via::Native(None),
            &jag_body(
                &forged_with_cnf(json!("x")),
                assertion_auth(&h.idp.assertion()),
            ),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::TOO_MANY_REQUESTS, "{}", a.body);
    h.stop().await;
}

/// `[limits] token_requests_per_minute` counts each early intake refusal once and each
/// request that passes once: two refusals reach the limit of two, and two issuances fit in it.
#[tokio::test]
async fn early_intake_refusals_are_counted_once() {
    let h = Harness::start(Opts {
        extra: "[limits]\ntoken_requests_per_minute = 2\n\n",
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let planner = || json!({"client_id": "planner"});
    let to_coder = || h.idp.id_jag("alice", "planner", x5t_cnf(&c.coder));
    for _ in 0..2 {
        refused_grant(
            &h.token(
                Via::Native(Some(&c.planner)),
                &jag_body(&to_coder(), planner()),
                &[],
            )
            .await,
            CERT_MISMATCH,
            "another certificate",
        );
    }
    let a = h
        .token(
            Via::Native(Some(&c.planner)),
            &jag_body(&to_coder(), planner()),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::TOO_MANY_REQUESTS, "{}", a.body);
    // Passing requests, for another agent: each counts once.
    let pki = || json!({"client_id": "pki-coder"});
    for _ in 0..2 {
        let jag = h.idp.id_jag("alice", "pki-coder", x5t_cnf(&c.pki_coder));
        let a = h
            .token(Via::Native(Some(&c.pki_coder)), &jag_body(&jag, pki()), &[])
            .await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    }
    let jag = h.idp.id_jag("alice", "pki-coder", x5t_cnf(&c.pki_coder));
    let a = h
        .token(Via::Native(Some(&c.pki_coder)), &jag_body(&jag, pki()), &[])
        .await;
    assert_eq!(a.status, StatusCode::TOO_MANY_REQUESTS, "{}", a.body);
    h.stop().await;
}

/// The exchange's early binding refusal (a certificate-bound subject token without its
/// certificate) answers a used assertion as a replay too, and does not count it.
#[tokio::test]
async fn a_used_assertion_is_a_replay_before_the_early_exchange_refusal() {
    let h = Harness::start(Opts {
        extra: "[limits]\ntoken_requests_per_minute = 2\n\n",
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let ex = |parent: &str, assertion: &str| {
        exchange_body(parent, "jwt-agent", assertion_auth(assertion))
    };
    let used = h.idp.assertion();
    let parent = h.bound_to(Via::Native(Some(&c.coder)), "coder").await;
    // Counted: 1.
    let a = h
        .token(Via::Native(Some(&c.coder)), &ex(&parent, &used), &[])
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    for via in [Via::Native(None), Via::Native(Some(&c.planner))] {
        for _ in 0..3 {
            let a = h.token(via, &ex(&parent, &used), &[]).await;
            assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
            assert_eq!(a.code(), "client_assertion_replayed", "{}", a.body);
        }
    }
    // Budget untouched (counted: 2). The parents come from other agents, each with a budget
    // of its own.
    let fresh = h.bound_to(Via::Native(Some(&c.both)), "both").await;
    let a = h
        .token(
            Via::Native(Some(&c.both)),
            &ex(&fresh, &h.idp.assertion()),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    // An unused assertion's early refusal is counted: over the limit now, and the assertion
    // is still unused.
    let unused = h.idp.assertion();
    let other = h
        .bound_to(Via::Native(Some(&c.pki_coder)), "pki-coder")
        .await;
    let a = h.token(Via::Native(None), &ex(&other, &unused), &[]).await;
    assert_eq!(a.status, StatusCode::TOO_MANY_REQUESTS, "{}", a.body);
    h.stop().await;
}
