//! `[server.forwarded_client_cert]`: TLS client certificates a trusted reverse proxy forwards
//! in the RFC 9440 `Client-Cert` and `Client-Cert-Chain` headers, on a listener of its own.
//! Real sockets through [`attenuo_server::run`], the code `serve` runs.
//!
//! Covers the fences of ADR-0021: the headers are read on the forwarding listener only; that
//! listener takes the peers in `trusted_peers` only (by TCP address; `X-Forwarded-For` plays
//! no part); with the section set, every other listener (main, native TLS, admin, console,
//! metrics) refuses the headers with 400, and without it they are ignored as before; the
//! admin API is never served on the forwarding listener; strict header parsing; the same
//! client authentication as the handshake path (pinned and CA-issued certificates, agents and
//! PEPs, one answer for every refusal and the same answer as the native path, a body
//! credential first, `actor_auth`), a fresh CA-check cache per request on one kept-alive
//! connection, `source = "forwarded"` in the audit records, a reload of the lists, the
//! startup refusals and the environment override rule.
//!
//! The proxy here is the test itself: it sends the headers a proxy would set after its own
//! handshake. A small test proxy that ends a real TLS handshake and forwards the headers is in
//! `a_tls_proxy_forwards_the_handshake_certificate`.

// Configs are built field by field, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::{AppState, Config};
use attenuo_token::DpopKey;
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine as _;
use common::tls::{Ca, ClientCert};
use common::{free_port, sha256_hex, Running};
use reqwest::StatusCode;
use serde_json::{json, Value};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ADMIN: &str = "forwarded-test-admin-token-0123456789abcdef";
const ISSUER: &str = "https://attenuo.test";
const PUBLIC_URL: &str = "https://localhost:8443";
const IDP: &str = "https://idp.test";
const WORKLOAD: &str = "https://workload.test";
const CLIENT_AUD: &str = "attenuo-client";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
const SPIFFE_CODER: &str = "spiffe://example.org/ns/agents/sa/pki-coder";
const PEP_DNS: &str = "pep-dns.peps.internal";
const PEP_URI: &str = "spiffe://example.org/ns/peps/sa/pep-uri";

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn uri_san(s: &str) -> rcgen::SanType {
    rcgen::SanType::URI(s.try_into().unwrap())
}

fn dns_san(s: &str) -> rcgen::SanType {
    rcgen::SanType::DnsName(s.try_into().unwrap())
}

/// A fake IdP and workload issuer, as in `mtls.rs`.
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

    fn actor_token(&self, sub: &str) -> String {
        let t = now().unix_timestamp();
        self.workload.sign_jws(
            &json!({"alg": "EdDSA", "kid": "wl-1", "typ": "JWT"}),
            &json!({"iss": WORKLOAD, "aud": ISSUER, "sub": sub, "iat": t, "exp": t + 300,
                    "jti": uuid::Uuid::new_v4().to_string()}),
        )
    }
}

/// The certificates of the test: self-signed ones pinned for `planner`, `coder`, `both` and
/// the PEP `gateway`; ones from an intermediate CA under the root in `ca.pem` for the agent
/// `pki-coder` (SAN URI) and the PEPs `pep-dns` (SAN DNS) and `pep-uri` (SAN URI); and one
/// nobody trusts.
struct Certs {
    dir: tempfile::TempDir,
    mid: Ca,
    planner: ClientCert,
    coder: ClientCert,
    coder_next: ClientCert,
    both: ClientCert,
    gateway: ClientCert,
    stranger: ClientCert,
    pki_coder: ClientCert,
    pep_dns: ClientCert,
    pep_uri: ClientCert,
}

impl Certs {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = Ca::new("forwarded test root CA");
        let mid = root.intermediate("forwarded test intermediate CA");
        root.write(dir.path(), "ca.pem");
        Self {
            planner: ClientCert::new("planner"),
            coder: ClientCert::new("coder"),
            coder_next: ClientCert::new("coder"),
            both: ClientCert::new("both"),
            gateway: ClientCert::new("gateway"),
            stranger: ClientCert::new("stranger"),
            pki_coder: mid.client(|p| p.subject_alt_names = vec![uri_san(SPIFFE_CODER)]),
            pep_dns: mid.client(|p| p.subject_alt_names = vec![dns_san(PEP_DNS)]),
            pep_uri: mid.client(|p| p.subject_alt_names = vec![uri_san(PEP_URI)]),
            dir,
            mid,
        }
    }

    fn ca_path(&self) -> PathBuf {
        self.dir.path().join("ca.pem")
    }

    /// The lists, with `coder` pinned to `coder_pins`.
    fn lists(&self, coder_pins: &[&ClientCert]) -> String {
        let pins = |certs: &[&ClientCert]| {
            certs
                .iter()
                .map(|c| format!("\"{}\"", c.sha256_hex()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let ca = self.ca_path().display().to_string();
        format!(
            "[[agents]]\nid = \"planner\"\ntls_client_cert_sha256 = [{}]\n\n\
             [[agents]]\nid = \"coder\"\ntls_client_cert_sha256 = [{}]\n\n\
             [[agents]]\nid = \"reviewer\"\nsecret_sha256 = \"{}\"\n\n\
             [[agents]]\nid = \"both\"\nsecret_sha256 = \"{}\"\ntls_client_cert_sha256 = [{}]\n\n\
             [[agents]]\nid = \"pki-coder\"\ntls_client_ca_pem_path = \"{ca}\"\n\
             tls_client_auth_san_uri = \"{SPIFFE_CODER}\"\n\n\
             [[peps]]\nid = \"gateway\"\ntls_client_cert_sha256 = [{}]\n\n\
             [[peps]]\nid = \"pep-dns\"\ntls_client_ca_pem_path = \"{ca}\"\n\
             tls_client_auth_san_dns = \"{PEP_DNS}\"\n\n\
             [[peps]]\nid = \"pep-uri\"\ntls_client_ca_pem_path = \"{ca}\"\n\
             tls_client_auth_san_uri = \"{PEP_URI}\"\n\n\
             [[peps]]\nid = \"pep-secret\"\nsecret_sha256 = \"{}\"\n",
            pins(&[&self.planner]),
            pins(coder_pins),
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
    /// `[server.forwarded_client_cert]` at all.
    forwarded: bool,
    /// `trusted_peers`, as TOML.
    trusted_peers: &'static str,
    /// `[server.tls]` on the main listener, with `client_certificates = "optional"`.
    main_tls: bool,
    /// `[admin] listen`, `[admin_ui]` and `[metrics]` on listeners of their own.
    other_listeners: bool,
    /// `[token] actor_auth`.
    actor_auth: &'static str,
    /// The `[[agents]]` and `[[peps]]`, instead of [`Certs::lists`].
    lists: Option<String>,
    /// More sections, as TOML.
    extra: &'static str,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            forwarded: true,
            trusted_peers: "[\"127.0.0.1/32\"]",
            main_tls: false,
            other_listeners: false,
            actor_auth: "either",
            lists: None,
            extra: "",
        }
    }
}

/// The listener addresses `run` binds itself.
#[derive(Clone, Copy)]
struct Ports {
    forwarded: SocketAddr,
    admin: SocketAddr,
    console: SocketAddr,
    metrics: SocketAddr,
}

/// Write `<dir>/attenuo.toml`, replaced in one rename so a reload never reads half of it.
fn write_config(
    dir: &Path,
    server_files: &(PathBuf, PathBuf),
    issuers: &Issuers,
    ports: &Ports,
    opts: &Opts,
    lists: &str,
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
            "[server.forwarded_client_cert]\nlisten = \"{}\"\ntrusted_peers = {}\n\n",
            ports.forwarded, opts.trusted_peers
        );
    }
    let admin_listen = if opts.other_listeners {
        format!("listen = \"{}\"\n", ports.admin)
    } else {
        String::new()
    };
    let others = if opts.other_listeners {
        format!(
            "[admin_ui]\nenabled = true\nlisten = \"{}\"\n\n[metrics]\nenabled = true\nlisten = \"{}\"\n\n",
            ports.console, ports.metrics
        )
    } else {
        String::new()
    };
    let path = dir.join("attenuo.toml");
    let tmp = dir.join("attenuo.toml.tmp");
    std::fs::write(
        &tmp,
        format!(
            "{server}[issuer]\nissuer = \"{ISSUER}\"\nprivate_key_pem_path = \"{}\"\n\n\
             [audit]\nsqlite_path = \"{}\"\n\n\
             [admin]\ntoken = \"{ADMIN}\"\n{admin_listen}\n\
             {others}{}\
             [dev]\nallow_root_mint = true\n\n\
             [authzen]\nallow_unsigned_chain = true\n\n\
             [token]\nactor_auth = \"{}\"\n\n\
             [[idps]]\nissuer = \"{IDP}\"\njwks_url = \"{}\"\nallowed_algs = [\"EdDSA\"]\n\
             client_ids = {{ planner = \"{CLIENT_AUD}\" }}\n\n\
             [[root_grants]]\nissuer = \"{IDP}\"\nagent = \"planner\"\ncapabilities = [\"github:*\"]\n\n\
             [[actor_trust]]\nissuer = \"{WORKLOAD}\"\njwks_url = \"{}\"\naudience = \"{ISSUER}\"\n\
             subject_to_agent = \"sub\"\nallowed_algs = [\"EdDSA\"]\n\n{lists}",
            dir.join("keys/issuer.pem").display(),
            dir.join("audit.sqlite").display(),
            opts.extra,
            opts.actor_auth,
            issuers.server.url("/jwks"),
            issuers.server.url("/actor-jwks"),
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
    ports: Ports,
    opts: Opts,
    running: Running,
    state: Arc<AppState>,
}

impl Harness {
    async fn start(opts: Opts) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::new("forwarded test server CA");
        let server_files = ca.write_server_files(dir.path(), &["127.0.0.1"]);
        let issuers = Issuers::start().await;
        let certs = Certs::new();
        let ports = Ports {
            forwarded: free_port(),
            admin: free_port(),
            console: free_port(),
            metrics: free_port(),
        };
        let lists = opts
            .lists
            .clone()
            .unwrap_or_else(|| certs.lists(&[&certs.coder, &certs.coder_next]));
        let path = write_config(dir.path(), &server_files, &issuers, &ports, &opts, &lists);
        let cfg = Config::load(&path).unwrap();
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let running = Running::start(cfg, state.clone(), router).await;
        let h = Self {
            dir,
            ca,
            server_files,
            issuers,
            certs,
            ports,
            opts,
            running,
            state,
        };
        // `run` binds the other listeners before it serves the main one; wait until the main
        // listener answers, so they are all up.
        let healthz = h.main_client(None).get(h.main_url("/healthz"));
        assert_eq!(healthz.send().await.unwrap().status(), StatusCode::OK);
        h
    }

    async fn stop(self) {
        self.running.stop(self.state).await;
    }

    fn main_url(&self, path: &str) -> String {
        if self.opts.main_tls {
            self.running.https_url(path)
        } else {
            self.running.url(path)
        }
    }

    /// Where the admin API is: `[admin] listen` when the test has one, else the main listener.
    fn admin_url(&self, path: &str) -> String {
        if self.opts.other_listeners {
            format!("http://{}{path}", self.ports.admin)
        } else {
            self.main_url(path)
        }
    }

    /// A client of the admin API.
    fn admin_client(&self) -> reqwest::Client {
        if self.opts.other_listeners {
            plain_client()
        } else {
            self.main_client(None)
        }
    }

    fn fwd_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.ports.forwarded)
    }

    /// A client of the main listener that presents `cert` in the TLS handshake (with
    /// `[server.tls]`), or none.
    fn main_client(&self, cert: Option<&ClientCert>) -> reqwest::Client {
        if self.opts.main_tls {
            self.ca.reqwest_client(cert)
        } else {
            plain_client()
        }
    }

    /// A request to the forwarding listener with the headers a proxy sets for `cert` (with
    /// its chain), or none.
    async fn fwd(
        &self,
        cert: Option<&ClientCert>,
        path: &str,
        body: &Value,
        extra: &[(&str, &str)],
    ) -> Answer {
        let mut req = plain_client().post(self.fwd_url(path)).json(body);
        if let Some(c) = cert {
            for (k, v) in forwarded_headers(c) {
                req = req.header(k, v);
            }
        }
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        Answer::of(req.send().await.unwrap()).await
    }

    /// The same request to the native TLS listener, with `cert` in the handshake.
    async fn native(&self, cert: Option<&ClientCert>, path: &str, body: &Value) -> Answer {
        assert!(self.opts.main_tls);
        let req = self.main_client(cert).post(self.main_url(path)).json(body);
        Answer::of(req.send().await.unwrap()).await
    }

    /// A root token for `planner` from the dev mint on the main listener: (token, lease).
    async fn root(&self) -> (String, String) {
        let resp = self
            .admin_client()
            .post(self.admin_url("/admin/root-token"))
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
            .admin_client()
            .get(self.admin_url("/admin/audit?from=1&limit=1000"))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["entries"].as_array().unwrap().clone()
    }

    async fn last_digest(&self, tool: &str) -> Value {
        self.audit()
            .await
            .into_iter()
            .rfind(|e| e["record"]["tool"] == tool)
            .unwrap()["record"]["arguments_digest"]
            .clone()
    }

    /// Rewrite the config file with `coder` pinned to `coder_pins` and reload the lists.
    async fn reload_coder(&self, coder_pins: &[&ClientCert]) {
        write_config(
            self.dir.path(),
            &self.server_files,
            &self.issuers,
            &self.ports,
            &self.opts,
            &self.certs.lists(coder_pins),
        );
        let resp = self
            .admin_client()
            .post(self.admin_url("/admin/agents/reload"))
            .bearer_auth(ADMIN)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        let a = Answer::of(resp).await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    }

    /// An AuthZEN evaluation for a root token's chain, with `pep` fields in the body.
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

    fn lease_of(&self, token: &str) -> String {
        self.state
            .keys()
            .verifier
            .verify(token, now())
            .unwrap()
            .chain
            .hops[0]
            .lease
            .0
            .clone()
    }
}

/// A plain-HTTP client that never goes through a proxy from the environment.
fn plain_client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// `:<base64 of der>:`, an RFC 8941 Byte Sequence.
fn sf_binary(der: &[u8]) -> String {
    format!(
        ":{}:",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

/// The headers a proxy sets for `cert`: `Client-Cert`, and `Client-Cert-Chain` when the
/// certificate came with intermediates.
fn forwarded_headers(cert: &ClientCert) -> Vec<(&'static str, String)> {
    let mut h = vec![("Client-Cert", sf_binary(cert.der.as_ref()))];
    if !cert.chain.is_empty() {
        let chain: Vec<String> = cert.chain.iter().map(|c| sf_binary(c.as_ref())).collect();
        h.push(("Client-Cert-Chain", chain.join(", ")));
    }
    h
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
            self.body["code"].as_str().unwrap_or_default(),
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

/// The `client_cert` member of a record of a request `cert` authenticated from `source`.
fn client_cert_member(cert: &ClientCert, source: &str) -> Value {
    json!({"x5t#S256": cert.x5t_s256(), "source": source})
}

/// The digest the exchange record's arguments have.
fn exchange_digest(
    actor: &str,
    parent_lease: &str,
    how: &str,
    cert: Option<(&ClientCert, &str)>,
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
    if let Some((c, source)) = cert {
        args["client_cert"] = client_cert_member(c, source);
    }
    attenuo_core::ToolCall::new("attenuo", "token.exchange", args).arguments_digest()
}

/// A raw TCP connection to `addr`, from `source` when given (another loopback address).
async fn tcp(addr: SocketAddr, source: Option<IpAddr>) -> std::io::Result<tokio::net::TcpStream> {
    match source {
        None => tokio::net::TcpStream::connect(addr).await,
        Some(ip) => {
            let socket = tokio::net::TcpSocket::new_v4()?;
            socket.bind(SocketAddr::new(ip, 0))?;
            socket.connect(addr).await
        }
    }
}

/// Send one request on `stream` (kept alive) and read the answer by its `Content-Length`:
/// (status, lowercase head, body).
async fn request_on<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: Option<&Value>,
) -> std::io::Result<(u16, String, Value)> {
    let body = body.map(Value::to_string).unwrap_or_default();
    let extra: String = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect();
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{extra}\
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
                return Ok((status, head, v));
            }
        }
    }
}

// --- the happy paths --------------------------------------------------------------------

/// Through the forwarding listener: hop 0 and exchanges with pinned self-signed certificates
/// and with a CA-issued one (SAN URI, through a forwarded intermediate), with an actor token
/// too; the records say `source = "forwarded"`. Run over a plain main listener and next to a
/// native TLS main listener with client certificates (two sources, one per listener).
#[tokio::test]
async fn agents_authenticate_with_forwarded_certificates() {
    for main_tls in [false, true] {
        let h = Harness::start(Opts {
            main_tls,
            ..Opts::default()
        })
        .await;
        let c = &h.certs;

        // Hop 0 by a pinned certificate.
        let a = h
            .fwd(
                Some(&c.planner),
                "/token",
                &intake_body(
                    &h.issuers.id_token("alice"),
                    json!({"client_id": "planner"}),
                ),
                &[],
            )
            .await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
        let root = a.body["access_token"].as_str().unwrap();
        let verified = h.state.keys().verifier.verify(root, now()).unwrap();
        assert_eq!(verified.chain.hops[0].agent.0, "planner");
        let requested = verified.chain.hops[0].capabilities.clone();
        let digest = |source: Option<&str>| {
            let mut args = json!({"agent": "planner", "requested": requested,
                                  "credential": "id_token", "idp": IDP,
                                  "agent_auth": "self_signed_tls_client_auth",
                                  "dpop_bound": false});
            if let Some(s) = source {
                args["client_cert"] = client_cert_member(&c.planner, s);
            }
            attenuo_core::ToolCall::new("attenuo", "token.root", args).arguments_digest()
        };
        let got = h.last_digest("token.root").await;
        assert_eq!(got, digest(Some("forwarded")));
        assert_ne!(got, digest(Some("tls")));
        assert_ne!(got, digest(None));

        // An exchange by a pinned certificate (either of a rotation's two).
        for cert in [&c.coder, &c.coder_next] {
            let (root, lease) = h.root().await;
            let a = h
                .fwd(
                    Some(cert),
                    "/token",
                    &exchange_body(&root, "coder", json!({"client_id": "coder"})),
                    &[],
                )
                .await;
            assert_eq!(a.status, StatusCode::OK, "{}", a.body);
            assert_eq!(
                h.last_digest("token.exchange").await,
                exchange_digest(
                    "coder",
                    &lease,
                    "self_signed_tls_client_auth",
                    Some((cert, "forwarded")),
                    false
                )
            );
        }

        // By a CA-issued certificate (SAN URI) whose intermediate is forwarded in
        // Client-Cert-Chain.
        assert_eq!(c.pki_coder.chain.len(), 1);
        let (root, lease) = h.root().await;
        let a = h
            .fwd(
                Some(&c.pki_coder),
                "/token",
                &exchange_body(&root, "pki-coder", json!({"client_id": "pki-coder"})),
                &[],
            )
            .await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
        assert_eq!(
            h.last_digest("token.exchange").await,
            exchange_digest(
                "pki-coder",
                &lease,
                "tls_client_auth",
                Some((&c.pki_coder, "forwarded")),
                false
            )
        );
        // Without the chain header there is no path to the root: the one answer.
        let a = h
            .fwd(
                Some(&c.pki_coder.without_chain()),
                "/token",
                &exchange_body(&root, "pki-coder", json!({"client_id": "pki-coder"})),
                &[],
            )
            .await;
        assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
        assert_eq!(a.code(), ("invalid_client", "client_authentication_failed"));

        // With an actor token too (`actor_auth = "either"`): both are checked.
        let (root, lease) = h.root().await;
        let a = h
            .fwd(
                Some(&c.coder),
                "/token",
                &exchange_body(
                    &root,
                    "coder",
                    json!({"client_id": "coder", "actor_token": h.issuers.actor_token("coder"),
                           "actor_token_type": JWT}),
                ),
                &[],
            )
            .await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
        assert_eq!(
            h.last_digest("token.exchange").await,
            exchange_digest(
                "coder",
                &lease,
                "actor_token+self_signed_tls_client_auth",
                Some((&c.coder, "forwarded")),
                true
            )
        );

        if main_tls {
            // The native listener still takes the handshake certificate, with source "tls".
            let (root, lease) = h.root().await;
            let a = h
                .native(
                    Some(&c.coder),
                    "/token",
                    &exchange_body(&root, "coder", json!({"client_id": "coder"})),
                )
                .await;
            assert_eq!(a.status, StatusCode::OK, "{}", a.body);
            assert_eq!(
                h.last_digest("token.exchange").await,
                exchange_digest(
                    "coder",
                    &lease,
                    "self_signed_tls_client_auth",
                    Some((&c.coder, "tls")),
                    false
                )
            );
        }
        // The public routes are there; discovery names the public URL.
        let a = plain_client()
            .get(h.fwd_url("/.well-known/authzen-configuration"))
            .send()
            .await
            .unwrap();
        assert_eq!(a.status(), StatusCode::OK);
        let v: Value = a.json().await.unwrap();
        assert_eq!(v["policy_decision_point"], PUBLIC_URL, "{v}");
        let a = plain_client()
            .get(h.fwd_url("/healthz"))
            .send()
            .await
            .unwrap();
        assert_eq!(a.status(), StatusCode::OK);
        h.stop().await;
    }
}

/// A PEP authenticates to the AuthZEN endpoints through the forwarding listener: pinned, and
/// CA-issued by SAN DNS and SAN URI through a forwarded intermediate; single and batch.
#[tokio::test]
async fn peps_authenticate_with_forwarded_certificates() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    for (pep, cert) in [
        ("gateway", &c.gateway),
        ("pep-dns", &c.pep_dns),
        ("pep-uri", &c.pep_uri),
    ] {
        let body = h.evaluation(json!({"pep_id": pep})).await;
        let a = h.fwd(Some(cert), "/access/v1/evaluation", &body, &[]).await;
        assert_eq!(a.status, StatusCode::OK, "{pep}: {}", a.body);
        assert!(a.body["context"]["decision_id"].is_string(), "{}", a.body);
        let mut batch = body.clone();
        batch["evaluations"] = json!([{}, {}]);
        let a = h
            .fwd(Some(cert), "/access/v1/evaluations", &batch, &[])
            .await;
        assert_eq!(a.status, StatusCode::OK, "{pep}: {}", a.body);
        // No header: no credential.
        let a = h.fwd(None, "/access/v1/evaluation", &body, &[]).await;
        assert_eq!(a.code(), ("invalid_client", "client_auth_missing"));
    }
    // An agent's certificate as a PEP, a PEP's as another PEP: the one answer.
    let body = h.evaluation(json!({"pep_id": "pep-dns"})).await;
    let a = h
        .fwd(Some(&c.pep_uri), "/access/v1/evaluation", &body, &[])
        .await;
    assert_eq!(a.code(), ("invalid_client", "client_authentication_failed"));
    let b = h
        .fwd(Some(&c.planner), "/access/v1/evaluation", &body, &[])
        .await;
    assert_eq!(a, b);
    h.stop().await;
}

// --- refusals: the same as on the native path -------------------------------------------

/// Every certificate refusal on the forwarding listener is one answer, and the same answer
/// the native TLS listener gives for the same certificate and id (SR-110). A body credential
/// decides over a forwarded certificate, as over a handshake one.
#[tokio::test]
async fn refusals_are_one_answer_and_the_native_one() {
    let h = Harness::start(Opts {
        main_tls: true,
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let (root, _) = h.root().await;
    let records = h.audit().await.len();
    let ex = |id: &str| exchange_body(&root, id, json!({"client_id": id}));
    let mid_ca = c.mid.as_client();
    let cases: Vec<(&ClientCert, &str)> = vec![
        (&c.stranger, "coder"),
        // A's certificate with client id B.
        (&c.planner, "coder"),
        // A certificate for an entry with a secret only.
        (&c.planner, "reviewer"),
        (&c.planner, "nobody"),
        // A PEP's certificate as an agent.
        (&c.gateway, "coder"),
        // A CA certificate of one entry for another.
        (&c.pki_coder, "coder"),
        (&c.pep_dns, "pki-coder"),
        // An intermediate CA's own certificate.
        (&mid_ca, "pki-coder"),
    ];
    let mut first = None;
    for (cert, id) in &cases {
        let fwd = h.fwd(Some(cert), "/token", &ex(id), &[]).await;
        assert_eq!(fwd.status, StatusCode::UNAUTHORIZED, "{id}: {}", fwd.body);
        assert_eq!(
            fwd.code(),
            ("invalid_client", "client_authentication_failed")
        );
        let native = h.native(Some(cert), "/token", &ex(id)).await;
        assert_eq!(fwd, native, "{id}");
        match &first {
            None => first = Some(fwd),
            Some(f) => assert_eq!(&fwd, f, "{id}"),
        }
    }
    // No certificate is `client_auth_missing`, on both.
    let fwd = h.fwd(None, "/token", &ex("coder"), &[]).await;
    assert_eq!(fwd.code(), ("invalid_client", "client_auth_missing"));
    assert_eq!(fwd, h.native(None, "/token", &ex("coder")).await);
    // Nothing was issued or recorded.
    assert_eq!(h.audit().await.len(), records);

    // A body credential decides: a wrong secret next to the pinned certificate is refused,
    // the right one authenticates by the secret (no `client_cert` in the record).
    let a = h
        .fwd(
            Some(&c.both),
            "/token",
            &exchange_body(
                &root,
                "both",
                json!({"client_id": "both", "client_secret": "wrong"}),
            ),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
    assert_eq!(a.code(), ("invalid_client", "client_authentication_failed"));
    let a = h
        .fwd(
            Some(&c.both),
            "/token",
            &exchange_body(
                &root,
                "both",
                json!({"client_id": "both", "client_secret": "both-secret"}),
            ),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest("both", &h.lease_of(&root), "client_secret", None, false)
    );
    h.stop().await;
}

/// `[token] actor_auth = "actor_token"` refuses a forwarded certificate with a `client_id`
/// as it refuses a handshake one (`client_auth_not_accepted`); the actor token alone works.
#[tokio::test]
async fn actor_auth_actor_token_refuses_a_forwarded_certificate() {
    let h = Harness::start(Opts {
        main_tls: true,
        actor_auth: "actor_token",
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let (root, lease) = h.root().await;
    let body = exchange_body(
        &root,
        "coder",
        json!({"client_id": "coder", "actor_token": h.issuers.actor_token("coder"),
               "actor_token_type": JWT}),
    );
    let fwd = h.fwd(Some(&c.coder), "/token", &body, &[]).await;
    assert_eq!(fwd.status, StatusCode::BAD_REQUEST, "{}", fwd.body);
    assert_eq!(fwd.code(), ("invalid_request", "client_auth_not_accepted"));
    let body = exchange_body(
        &root,
        "coder",
        json!({"client_id": "coder", "actor_token": h.issuers.actor_token("coder"),
               "actor_token_type": JWT}),
    );
    let native = h.native(Some(&c.coder), "/token", &body).await;
    assert_eq!(fwd, native);
    let a = h
        .fwd(
            Some(&c.coder),
            "/token",
            &exchange_body(
                &root,
                "coder",
                json!({"actor_token": h.issuers.actor_token("coder"), "actor_token_type": JWT}),
            ),
            &[],
        )
        .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.last_digest("token.exchange").await,
        exchange_digest("coder", &lease, "actor_token", None, true)
    );
    h.stop().await;
}

// --- one kept-alive connection, many certificates ----------------------------------------

/// A proxy sends many clients' requests on one upstream connection. Two CA-issued
/// certificates alternate on one kept-alive connection, each with its own id and with the
/// other's: every request gets its own answer, so no CA-check answer is shared between the
/// two certificates. A pinned one and a request with no header are mixed in.
#[tokio::test]
async fn certificates_alternating_on_one_connection_each_get_their_own_answer() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let dns = h.evaluation(json!({"pep_id": "pep-dns"})).await;
    let uri = h.evaluation(json!({"pep_id": "pep-uri"})).await;
    let gw = h.evaluation(json!({"pep_id": "gateway"})).await;
    let mut conn = tcp(h.ports.forwarded, None).await.unwrap();
    let headers = |cert: &ClientCert| -> Vec<(&str, String)> { forwarded_headers(cert) };
    for round in 0..3 {
        for (cert, body, ok) in [
            (&c.pep_dns, &dns, true),
            (&c.pep_uri, &uri, true),
            (&c.pep_dns, &uri, false),
            (&c.pep_uri, &dns, false),
            (&c.gateway, &gw, true),
            (&c.gateway, &dns, false),
            (&c.pep_dns, &dns, true),
        ] {
            let (status, _, v) = request_on(
                &mut conn,
                "POST",
                "/access/v1/evaluation",
                &headers(cert),
                Some(body),
            )
            .await
            .unwrap();
            if ok {
                assert_eq!(status, 200, "round {round}: {v}");
            } else {
                assert_eq!(status, 401, "round {round}: {v}");
                assert_eq!(v["code"], "client_authentication_failed", "{v}");
            }
        }
        // The same connection without a header: no certificate is left over from before.
        let (status, _, v) =
            request_on(&mut conn, "POST", "/access/v1/evaluation", &[], Some(&dns))
                .await
                .unwrap();
        assert_eq!(status, 401, "{v}");
        assert_eq!(v["code"], "client_auth_missing", "{v}");
    }
    h.stop().await;
}

/// A reload of the lists applies to the next request on an open connection to the
/// forwarding listener: a removed pin is refused, an added one accepted.
#[tokio::test]
async fn a_reload_changes_the_next_answer() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let mut conn = tcp(h.ports.forwarded, None).await.unwrap();
    let send = |root: String, cert: ClientCert| {
        let body = exchange_body(&root, "coder", json!({"client_id": "coder"}));
        (forwarded_headers(&cert), body)
    };
    let (root, _) = h.root().await;
    let (hd, body) = send(root.clone(), c.coder.clone());
    let (status, _, v) = request_on(&mut conn, "POST", "/token", &hd, Some(&body))
        .await
        .unwrap();
    assert_eq!(status, 200, "{v}");
    h.reload_coder(&[&c.coder_next]).await;
    let (status, _, v) = request_on(&mut conn, "POST", "/token", &hd, Some(&body))
        .await
        .unwrap();
    assert_eq!(status, 401, "{v}");
    assert_eq!(v["code"], "client_authentication_failed");
    let (root, _) = h.root().await;
    let (hd, body) = send(root, c.coder_next.clone());
    let (status, _, v) = request_on(&mut conn, "POST", "/token", &hd, Some(&body))
        .await
        .unwrap();
    assert_eq!(status, 200, "{v}");
    h.stop().await;
}

// --- the fences -------------------------------------------------------------------------

/// With the section set, either header is refused with 400 on every other listener: the
/// plain main listener, the admin, console and metrics listeners, and (below) the native TLS
/// listener, also with a handshake certificate. Any path, also one that does not exist and
/// one that needs no credential.
#[tokio::test]
async fn the_headers_are_refused_on_every_other_listener() {
    let h = Harness::start(Opts {
        other_listeners: true,
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let leaf = sf_binary(c.coder.der.as_ref());
    let (root, _) = h.root().await;
    let body = exchange_body(&root, "coder", json!({"client_id": "coder"}));
    let main = h.main_url("");
    let admin = format!("http://{}", h.ports.admin);
    let console = format!("http://{}", h.ports.console);
    let metrics = format!("http://{}", h.ports.metrics);
    let urls = [
        format!("{main}/token"),
        format!("{main}/healthz"),
        format!("{main}/no/such/path"),
        format!("{main}/access/v1/evaluation"),
        format!("{admin}/admin/whoami"),
        format!("{admin}/healthz"),
        format!("{console}/admin/ui/"),
        format!("{console}/admin/whoami"),
        format!("{metrics}/metrics"),
    ];
    let mut first: Option<Answer> = None;
    for url in &urls {
        for header in ["Client-Cert", "Client-Cert-Chain", "client-cert"] {
            let a = Answer::of(
                plain_client()
                    .post(url)
                    .bearer_auth(ADMIN)
                    .header(header, &leaf)
                    .json(&body)
                    .send()
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(
                a.status,
                StatusCode::BAD_REQUEST,
                "{url} {header}: {}",
                a.body
            );
            assert_eq!(
                a.code(),
                ("invalid_request", "client_cert_header_not_accepted"),
                "{url}"
            );
            assert!(!a.body.to_string().contains(&leaf[1..20]), "{}", a.body);
            match &first {
                None => first = Some(a),
                Some(f) => assert_eq!(f.body, a.body, "{url}"),
            }
        }
        // Without the header the same listener answers as usual (not 400).
        let a = plain_client()
            .get(url)
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap();
        assert_ne!(a.status(), StatusCode::BAD_REQUEST, "{url}");
    }
    // Nothing was issued: the header refused the request before it reached the route.
    let records = h.audit().await.len();
    let a = plain_client()
        .post(h.main_url("/token"))
        .header("Client-Cert", &leaf)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(a.status(), StatusCode::BAD_REQUEST);
    assert_eq!(h.audit().await.len(), records);
    h.stop().await;

    // The native TLS listener, with a pinned handshake certificate: the header still refuses
    // the request, even one the handshake certificate alone would authenticate.
    let h = Harness::start(Opts {
        main_tls: true,
        ..Opts::default()
    })
    .await;
    let (root, _) = h.root().await;
    let body = exchange_body(&root, "coder", json!({"client_id": "coder"}));
    let a = h.native(Some(&h.certs.coder), "/token", &body).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    let a = Answer::of(
        h.main_client(Some(&h.certs.coder))
            .post(h.main_url("/token"))
            .header("Client-Cert", sf_binary(h.certs.coder.der.as_ref()))
            .json(&body)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(a.status, StatusCode::BAD_REQUEST, "{}", a.body);
    assert_eq!(
        a.code(),
        ("invalid_request", "client_cert_header_not_accepted")
    );
    h.stop().await;
}

/// Without the section, the headers are ignored on every listener, exactly as before: a
/// request with them is answered as one without them.
#[tokio::test]
async fn without_the_section_the_headers_are_ignored() {
    let h = Harness::start(Opts {
        forwarded: false,
        other_listeners: true,
        main_tls: true,
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    let leaf = sf_binary(c.coder.der.as_ref());
    let (root, _) = h.root().await;
    let body = exchange_body(&root, "coder", json!({"client_id": "coder"}));
    // No handshake certificate: the header does not stand in for one.
    let with = Answer::of(
        h.main_client(None)
            .post(h.main_url("/token"))
            .header("Client-Cert", &leaf)
            .header("Client-Cert-Chain", &leaf)
            .json(&body)
            .send()
            .await
            .unwrap(),
    )
    .await;
    let without = h.native(None, "/token", &body).await;
    assert_eq!(with, without);
    assert_eq!(with.code(), ("invalid_client", "client_auth_missing"));
    // A handshake certificate is used, the header is not.
    let a = Answer::of(
        h.main_client(Some(&c.coder))
            .post(h.main_url("/token"))
            .header("Client-Cert", sf_binary(c.stranger.der.as_ref()))
            .json(&body)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    for url in [
        format!("http://{}/admin/whoami", h.ports.admin),
        format!("http://{}/metrics", h.ports.metrics),
        format!("http://{}/admin/whoami", h.ports.console),
    ] {
        let a = plain_client()
            .get(&url)
            .bearer_auth(ADMIN)
            .header("Client-Cert", &leaf)
            .send()
            .await
            .unwrap();
        assert_eq!(a.status(), StatusCode::OK, "{url}");
    }
    // And nothing listens on the forwarding address.
    assert!(tcp(h.ports.forwarded, None).await.is_err());
    h.stop().await;
}

/// Only the peers in `trusted_peers` are served on the forwarding listener, by TCP address:
/// another loopback address gets `403 forwarded_peer_not_trusted` for any request (with or
/// without the headers, on any path) and the connection is closed; `X-Forwarded-For` neither
/// helps an untrusted peer nor hurts a trusted one.
#[tokio::test]
async fn an_untrusted_peer_is_refused() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let other: IpAddr = "127.0.0.2".parse().unwrap();
    let (root, _) = h.root().await;
    let body = exchange_body(&root, "coder", json!({"client_id": "coder"}));
    let mut hd = forwarded_headers(&c.coder);
    hd.push(("X-Forwarded-For", "127.0.0.1".into()));
    hd.push(("Forwarded", "for=127.0.0.1".into()));
    hd.push(("X-Real-IP", "127.0.0.1".into()));
    for (path, headers) in [
        ("/token", hd.clone()),
        ("/healthz", Vec::new()),
        ("/no/such/path", Vec::new()),
    ] {
        // No body: an unread body could turn the server's close into a reset that loses the
        // answer.
        let mut conn = tcp(h.ports.forwarded, Some(other)).await.unwrap();
        let (status, head, v) = request_on(&mut conn, "POST", path, &headers, None)
            .await
            .unwrap();
        assert_eq!(status, 403, "{path}: {v}");
        assert_eq!(v["code"], "forwarded_peer_not_trusted", "{v}");
        assert_eq!(v["error"], "forwarded_peer_not_trusted", "{v}");
        assert!(head.contains("connection: close"), "{head}");
        // The connection is closed after the answer.
        let mut rest = Vec::new();
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            conn.read_to_end(&mut rest),
        )
        .await
        .expect("the connection was not closed")
        .unwrap_or(0);
        assert_eq!(n, 0);
    }
    // Nothing was issued.
    assert!(h
        .audit()
        .await
        .iter()
        .all(|e| e["record"]["tool"] != "token.exchange"));
    // The trusted peer, with a header that names another address, is served.
    let mut hd = forwarded_headers(&c.coder);
    hd.push(("X-Forwarded-For", "127.0.0.2".into()));
    let mut conn = tcp(h.ports.forwarded, None).await.unwrap();
    let (status, _, v) = request_on(&mut conn, "POST", "/token", &hd, Some(&body))
        .await
        .unwrap();
    assert_eq!(status, 200, "{v}");
    h.stop().await;

    // The other way round: only 127.0.0.2 is trusted, so 127.0.0.1 is refused.
    let h = Harness::start(Opts {
        trusted_peers: "[\"127.0.0.2\"]",
        ..Opts::default()
    })
    .await;
    let a = plain_client()
        .get(h.fwd_url("/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(a.status(), StatusCode::FORBIDDEN);
    let mut conn = tcp(h.ports.forwarded, Some(other)).await.unwrap();
    let (status, _, _) = request_on(&mut conn, "GET", "/healthz", &[], None)
        .await
        .unwrap();
    assert_eq!(status, 200);
    h.stop().await;
}

/// The admin API is never served on the forwarding listener, also while it is on the main
/// listener: every admin path answers there as a path that does not exist, for any method,
/// with or without the admin bearer (no dev mint, no reload).
#[tokio::test]
async fn the_admin_api_is_not_on_the_forwarding_listener() {
    let h = Harness::start(Opts::default()).await;
    let unknown = |method: reqwest::Method, path: &str, bearer: bool| {
        let mut req = plain_client().request(method, h.fwd_url(path));
        if bearer {
            req = req.bearer_auth(ADMIN);
        }
        async move {
            let r = req.json(&json!({})).send().await.unwrap();
            (r.status(), r.text().await.unwrap())
        }
    };
    let none = unknown(reqwest::Method::GET, "/no/such/admin", true).await;
    assert_eq!(none.0, StatusCode::NOT_FOUND);
    for method in [
        reqwest::Method::GET,
        reqwest::Method::POST,
        reqwest::Method::DELETE,
    ] {
        for path in [
            "/admin/whoami",
            "/admin/root-token",
            "/admin/agents/reload",
            "/admin/audit",
            "/admin/leases/x/revoke",
        ] {
            for bearer in [false, true] {
                let got = unknown(method.clone(), path, bearer).await;
                assert_eq!(got, none, "{method} {path} {bearer}");
            }
        }
    }
    // The listed routes are there.
    for path in [
        "/healthz",
        "/readyz",
        "/.well-known/jwks.json",
        "/.well-known/authzen-configuration",
    ] {
        let a = plain_client().get(h.fwd_url(path)).send().await.unwrap();
        assert_eq!(a.status(), StatusCode::OK, "{path}");
    }
    for path in [
        "/token",
        "/token/renew",
        "/access/v1/evaluation",
        "/mcp/github",
    ] {
        // Answered by the route (`/mcp/github` names no upstream here: the proxy's own 404,
        // with a body), not the bare 404 of a path that is not served.
        let got = unknown(reqwest::Method::POST, path, false).await;
        assert_ne!(got, none, "{path}");
    }
    // On the main listener they are there.
    let a = plain_client()
        .get(h.main_url("/admin/whoami"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(a.status(), StatusCode::OK);
    h.stop().await;
}

/// `[limits] token_unauthenticated_requests_per_minute` on the forwarding listener: every
/// peer there is the proxy, so the minute is counted per forwarded certificate, and requests
/// without one are not counted (the proxy must limit those). Anonymous requests and another
/// certificate's failures do not lock a certificate client out; a certificate's own failures
/// do.
#[tokio::test]
async fn one_client_behind_the_proxy_cannot_use_up_the_minute_of_the_others() {
    let h = Harness::start(Opts {
        extra: "[limits]\ntoken_unauthenticated_requests_per_minute = 3\n\n",
        ..Opts::default()
    })
    .await;
    let anonymous = || async {
        let mut conn = tcp(h.ports.forwarded, None).await.unwrap();
        request_on(&mut conn, "POST", "/token", &[], None)
            .await
            .unwrap()
            .0
    };
    for _ in 0..6 {
        assert_ne!(anonymous().await, 429);
    }
    let exchange = |cert: &'static str| {
        let h = &h;
        async move {
            let cert = match cert {
                "coder" => &h.certs.coder,
                _ => &h.certs.stranger,
            };
            let (root, _) = h.root().await;
            let body = exchange_body(&root, "coder", json!({"client_id": "coder"}));
            h.fwd(Some(cert), "/token", &body, &[]).await
        }
    };
    assert_eq!(exchange("coder").await.status, StatusCode::OK);
    // The stranger's certificate fails three times, then its minute is used up.
    for _ in 0..3 {
        assert_eq!(exchange("stranger").await.status, StatusCode::UNAUTHORIZED);
    }
    let a = exchange("stranger").await;
    assert_eq!(a.status, StatusCode::TOO_MANY_REQUESTS, "{}", a.body);
    // Not anyone else's: coder's certificate and anonymous requests go on.
    assert_eq!(exchange("coder").await.status, StatusCode::OK);
    assert_ne!(anonymous().await, 429);
    h.stop().await;
}

/// The other direction: on the native TLS listener the minute stays per peer address, so a
/// peer that used it up gets no new one by presenting a certificate it made up, nor with a
/// pinned one.
#[tokio::test]
async fn a_new_certificate_gives_a_native_peer_no_new_minute() {
    let h = Harness::start(Opts {
        main_tls: true,
        extra: "[limits]\ntoken_unauthenticated_requests_per_minute = 3\n\n",
        ..Opts::default()
    })
    .await;
    let c = &h.certs;
    for _ in 0..3 {
        let a = h.native(None, "/token", &json!({})).await;
        assert_ne!(a.status, StatusCode::TOO_MANY_REQUESTS, "{}", a.body);
    }
    for cert in [ClientCert::new("made up"), ClientCert::new("another")] {
        let (root, _) = h.root().await;
        let body = exchange_body(&root, "coder", json!({"client_id": "coder"}));
        let a = h.native(Some(&cert), "/token", &body).await;
        assert_eq!(a.status, StatusCode::TOO_MANY_REQUESTS, "{}", a.body);
    }
    let (root, _) = h.root().await;
    let body = exchange_body(&root, "coder", json!({"client_id": "coder"}));
    let a = h.native(Some(&c.coder), "/token", &body).await;
    assert_eq!(a.status, StatusCode::TOO_MANY_REQUESTS, "{}", a.body);
    // The forwarding listener's table is apart: coder through the proxy goes on.
    let (root, _) = h.root().await;
    let body = exchange_body(&root, "coder", json!({"client_id": "coder"}));
    assert_eq!(
        h.fwd(Some(&c.coder), "/token", &body, &[]).await.status,
        StatusCode::OK
    );
    h.stop().await;
}

/// Malformed, repeated and oversized headers, a chain without a leaf, and DER that is not a
/// certificate are one fixed `400 client_cert_header_malformed` that does not echo the
/// header, and nothing is issued.
#[tokio::test]
async fn malformed_headers_are_refused() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let (root, _) = h.root().await;
    let body = exchange_body(&root, "coder", json!({"client_id": "coder"}));
    let leaf = sf_binary(c.coder.der.as_ref());
    let mid = sf_binary(c.mid.cert.der().as_ref());
    let b64 = &leaf[1..leaf.len() - 1];
    let five = vec![mid.clone(); 5].join(", ");
    let big = sf_binary(&vec![0x30; 70 * 1024]);
    // A certificate whose base64 has padding and uses `+` or `/`, so that dropping the padding
    // and the URL-safe alphabet really change the value (a fixed certificate would not be
    // enough: a DER length that is a multiple of 3 has no padding).
    let odd = (0..64)
        .map(|_| ClientCert::new("odd"))
        .find(|c| {
            let e = base64::engine::general_purpose::STANDARD.encode(c.der.as_ref());
            e.ends_with('=') && (e.contains('+') || e.contains('/'))
        })
        .expect("a certificate with padded base64 and + or /");
    let odd_b64 = base64::engine::general_purpose::STANDARD.encode(odd.der.as_ref());
    let unpadded = odd_b64.trim_end_matches('=');
    let url_safe = odd_b64.replace('+', "-").replace('/', "_");
    assert_ne!(unpadded, odd_b64);
    assert_ne!(url_safe, odd_b64);
    let cases: Vec<Vec<(&str, String)>> = vec![
        vec![("Client-Cert", b64.to_owned())],
        // An empty value, as a proxy that sets the header for a client without a certificate
        // would send: refused, never read as "no certificate".
        vec![("Client-Cert", String::new())],
        vec![("Client-Cert", " ".into())],
        vec![("Client-Cert", format!("{leaf};sha256=abc"))],
        vec![("Client-Cert", format!("{leaf}, {leaf}"))],
        vec![("Client-Cert", leaf.clone()), ("Client-Cert", leaf.clone())],
        vec![("Client-Cert", format!(":{unpadded}:"))],
        vec![("Client-Cert", format!(":{url_safe}:"))],
        vec![("Client-Cert", "::".into())],
        vec![(
            "Client-Cert",
            format!(
                ":{}:",
                base64::engine::general_purpose::STANDARD.encode(b"not a certificate")
            ),
        )],
        vec![("Client-Cert", big)],
        vec![("Client-Cert-Chain", mid.clone())],
        vec![("Client-Cert", leaf.clone()), ("Client-Cert-Chain", five)],
        vec![
            ("Client-Cert", leaf.clone()),
            ("Client-Cert-Chain", format!("{mid},")),
        ],
        vec![
            ("Client-Cert", leaf.clone()),
            ("Client-Cert-Chain", mid.clone()),
            ("Client-Cert-Chain", mid.clone()),
        ],
        vec![
            ("Client-Cert", leaf.clone()),
            ("Client-Cert-Chain", ":AAAA:".into()),
        ],
        vec![
            ("Client-Cert", leaf.clone()),
            ("Client-Cert-Chain", String::new()),
        ],
    ];
    let mut first: Option<(u16, Value)> = None;
    for case in &cases {
        // No body: the answer comes before the route, and an unread body could make the
        // server's close a reset that loses the answer.
        let mut conn = tcp(h.ports.forwarded, None).await.unwrap();
        let (status, _, v) = request_on(&mut conn, "POST", "/token", case, None)
            .await
            .unwrap();
        assert_eq!(status, 400, "{case:?}: {v}");
        assert_eq!(v["code"], "client_cert_header_malformed", "{v}");
        assert!(!v.to_string().contains(&b64[..16]), "{v}");
        match &first {
            None => first = Some((status, v)),
            Some(f) => assert_eq!(f, &(status, v), "{case:?}"),
        }
    }
    // Bytes that are not visible ASCII.
    let mut conn = tcp(h.ports.forwarded, None).await.unwrap();
    conn.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nClient-Cert: :\xc3\xa9:\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = conn.read(&mut buf).await.unwrap();
    assert!(
        String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 400"),
        "{:?}",
        String::from_utf8_lossy(&buf[..n])
    );
    // The well-formed header with the same body is served.
    let a = h.fwd(Some(&c.coder), "/token", &body, &[]).await;
    assert_eq!(a.status, StatusCode::OK, "{}", a.body);
    assert_eq!(
        h.audit()
            .await
            .iter()
            .filter(|e| e["record"]["tool"] == "token.exchange")
            .count(),
        1
    );
    // The odd certificate itself, padded and in the standard alphabet, is a well-formed
    // header: it is not pinned, so the answer is the usual refusal, not 400.
    let (root, _) = h.root().await;
    let odd_body = exchange_body(&root, "coder", json!({"client_id": "coder"}));
    let a = h.fwd(Some(&odd), "/token", &odd_body, &[]).await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
    h.stop().await;
}

/// The forwarding listener speaks plain HTTP only: a TLS handshake to it fails, and the
/// listener goes on.
#[tokio::test]
async fn the_forwarding_listener_speaks_no_tls() {
    let h = Harness::start(Opts {
        main_tls: true,
        ..Opts::default()
    })
    .await;
    let config =
        h.ca.rustls_client(&[&rustls::version::TLS13], &[b"http/1.1"]);
    let tcp = tcp(h.ports.forwarded, None).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await;
    assert!(tls.is_err());
    let a = plain_client()
        .get(h.fwd_url("/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(a.status(), StatusCode::OK);
    h.stop().await;
}

// --- a TLS proxy in front ---------------------------------------------------------------

/// A minimal TLS-terminating proxy: it asks for a client certificate (any, proven in the
/// handshake), takes off any `Client-Cert` headers the client sent, sets them from its own
/// handshake, and forwards each request to `upstream` on one kept-alive connection. What the
/// guide's HAProxy recipe does.
async fn tls_proxy(ca: &Ca, upstream: SocketAddr) -> SocketAddr {
    let (cert, key) = ca.leaf(&["127.0.0.1"]);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(AnyClientCert(provider.clone()));
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![cert],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let chain: Vec<Vec<u8>> = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .unwrap_or_default()
                    .iter()
                    .map(|c| c.as_ref().to_vec())
                    .collect();
                let mut up = tokio::net::TcpStream::connect(upstream).await.unwrap();
                loop {
                    let Some((head, body)) = read_request(&mut tls).await else {
                        return;
                    };
                    let mut lines = head.split("\r\n");
                    let mut out = format!("{}\r\n", lines.next().unwrap());
                    for line in lines {
                        let name = line
                            .split(':')
                            .next()
                            .unwrap_or_default()
                            .to_ascii_lowercase();
                        if name == "client-cert" || name == "client-cert-chain" {
                            continue;
                        }
                        out += line;
                        out += "\r\n";
                    }
                    if let Some((leaf, rest)) = chain.split_first() {
                        out += &format!("Client-Cert: {}\r\n", sf_binary(leaf));
                        if !rest.is_empty() {
                            let items: Vec<String> = rest.iter().map(|c| sf_binary(c)).collect();
                            out += &format!("Client-Cert-Chain: {}\r\n", items.join(", "));
                        }
                    }
                    out += "\r\n";
                    up.write_all(out.as_bytes()).await.unwrap();
                    up.write_all(&body).await.unwrap();
                    let Some((head, body)) = read_response(&mut up).await else {
                        return;
                    };
                    tls.write_all(head.as_bytes()).await.unwrap();
                    tls.write_all(b"\r\n\r\n").await.unwrap();
                    tls.write_all(&body).await.unwrap();
                    tls.flush().await.unwrap();
                }
            });
        }
    });
    addr
}

/// The head (without the blank line) and the `Content-Length` body of one HTTP message.
async fn read_message<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8(buf[..buf.len() - 4].to_vec()).ok()?;
    let len = head
        .to_ascii_lowercase()
        .lines()
        .find_map(|l| {
            l.strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>())
        })
        .transpose()
        .ok()?
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await.ok()?;
    Some((head, body))
}

async fn read_request<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Option<(String, Vec<u8>)> {
    read_message(s).await
}

async fn read_response<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Option<(String, Vec<u8>)> {
    read_message(s).await
}

/// The test proxy's client certificate check: any certificate whose TLS 1.3 handshake
/// signature verifies (proof of possession), as attenuo's own listener does; the trust
/// decision is attenuo's.
#[derive(Debug)]
struct AnyClientCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::server::danger::ClientCertVerifier for AnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// End to end through a TLS-terminating proxy: an agent with a pinned certificate and one
/// with a CA-issued certificate and an intermediate present them in the proxy's handshake,
/// and get tokens; a `Client-Cert` header the client sends itself is taken off by the proxy
/// and has no effect. A client that connects to the forwarding listener directly from an
/// untrusted address cannot claim a certificate.
#[tokio::test]
async fn a_tls_proxy_forwards_the_handshake_certificate() {
    let h = Harness::start(Opts::default()).await;
    let c = &h.certs;
    let proxy = tls_proxy(&h.ca, h.ports.forwarded).await;
    let via = |cert: &ClientCert| {
        reqwest::Client::builder()
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(h.ca.reqwest_root())
            .identity(cert.identity())
            .http1_only()
            .build()
            .unwrap()
    };
    for (cert, id, method) in [
        (&c.coder, "coder", "self_signed_tls_client_auth"),
        (&c.pki_coder, "pki-coder", "tls_client_auth"),
    ] {
        let (root, lease) = h.root().await;
        let resp = via(cert)
            .post(format!("https://{proxy}/token"))
            // The client tries to claim another certificate: the proxy takes it off.
            .header("Client-Cert", sf_binary(c.stranger.der.as_ref()))
            .json(&exchange_body(&root, id, json!({"client_id": id})))
            .send()
            .await
            .unwrap();
        let a = Answer::of(resp).await;
        assert_eq!(a.status, StatusCode::OK, "{id}: {}", a.body);
        assert_eq!(
            h.last_digest("token.exchange").await,
            exchange_digest(id, &lease, method, Some((cert, "forwarded")), false)
        );
    }
    // The stranger's own certificate through the proxy: refused, as on the native path.
    let (root, _) = h.root().await;
    let a = Answer::of(
        via(&c.stranger)
            .post(format!("https://{proxy}/token"))
            .json(&exchange_body(
                &root,
                "coder",
                json!({"client_id": "coder"}),
            ))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(a.code(), ("invalid_client", "client_authentication_failed"));
    h.stop().await;
}

// --- start-up rules ---------------------------------------------------------------------

/// Bad sections stop `build`; certificate settings are accepted with the forwarding listener
/// as the only certificate source, and refused with neither source.
#[tokio::test]
async fn bad_configs_refuse_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let certs = Certs::new();
    let base = |server: &str, lists: &str| {
        format!(
            "{server}[issuer]\nissuer = \"{ISSUER}\"\nprivate_key_pem_path = \"{}\"\n\n\
             [audit]\nsqlite_path = \":memory:\"\n\n[admin]\ntoken = \"{ADMIN}\"\n\n{lists}",
            dir.path().join("issuer.pem").display()
        )
    };
    let build = |toml: String| {
        let path = dir.path().join("attenuo.toml");
        std::fs::write(&path, toml).unwrap();
        let cfg = Config::load(&path).map_err(|e| e.to_string())?;
        attenuo_server::build(&cfg)
            .map(drop)
            .map_err(|e| format!("{e:#}"))
    };
    let lists = certs.lists(&[&certs.coder]);
    let fwd = |listen: &str, peers: &str| {
        format!(
            "[server]\npublic_url = \"{PUBLIC_URL}\"\n\n[server.forwarded_client_cert]\n\
             listen = \"{listen}\"\ntrusted_peers = {peers}\n\n"
        )
    };
    // Pins with the forwarding listener only: accepted.
    build(base(&fwd("127.0.0.1:18444", "[\"127.0.0.1\"]"), &lists)).unwrap();
    // Pins with no certificate source.
    let e = build(base(
        &format!("[server]\npublic_url = \"{PUBLIC_URL}\"\n\n"),
        &lists,
    ))
    .unwrap_err();
    assert!(
        e.contains("needs [server.tls] with client_certificates = \"optional\", or [server.forwarded_client_cert]"),
        "{e}"
    );
    for (server, want) in [
        (fwd("127.0.0.1:18444", "[]"), "trusted_peers is empty"),
        (fwd("127.0.0.1:18444", "[\"0.0.0.0/0\"]"), "wider than /8"),
        (fwd("127.0.0.1:18444", "[\"::/0\"]"), "wider than /32"),
        (
            fwd("127.0.0.1:18444", "[\"0.0.0.0\"]"),
            "unspecified address",
        ),
        (fwd("127.0.0.1:18444", "[\"fe80::1\"]"), "link-local"),
        (fwd("127.0.0.1:18444", "[\"10.0.0.0/4\"]"), "wider than /8"),
        (
            fwd("127.0.0.1:18444", "[\"proxy.internal\"]"),
            "not an IP address",
        ),
        (
            fwd("127.0.0.1:8080", "[\"127.0.0.1\"]"),
            "is [server] listen too",
        ),
        (
            "[server.forwarded_client_cert]\nlisten = \"127.0.0.1:18444\"\n\
             trusted_peers = [\"127.0.0.1\"]\n\n"
                .to_owned(),
            "needs [server] public_url",
        ),
        (
            fwd("127.0.0.1:18444", "[\"127.0.0.1\"]")
                + "[metrics]\nenabled = true\nlisten = \"127.0.0.1:18444\"\n\n",
            "is [metrics] listen too",
        ),
    ] {
        let e = build(base(&server, "")).unwrap_err();
        assert!(e.contains(want), "{server}: {e}");
    }
    let e = build(
        base(&fwd("127.0.0.1:18444", "[\"127.0.0.1\"]"), "")
            .replace("[admin]\n", "[admin]\nlisten = \"127.0.0.1:18444\"\n"),
    )
    .unwrap_err();
    assert!(e.contains("is [admin] listen too"), "{e}");
    // Missing keys and unknown keys are refused when the file is read.
    for server in [
        "[server.forwarded_client_cert]\ntrusted_peers = [\"127.0.0.1\"]\n\n",
        "[server.forwarded_client_cert]\nlisten = \"127.0.0.1:18444\"\n\n",
        "[server.forwarded_client_cert]\nlisten = \"127.0.0.1:18444\"\ntrusted_peers = \
         [\"127.0.0.1\"]\ntrust_x_forwarded_for = true\n\n",
    ] {
        assert!(build(base(server, "")).is_err(), "{server}");
    }
}

/// An environment override cannot create the section, nor change it.
#[test]
fn an_environment_override_cannot_enable_the_section() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attenuo.toml");
    std::fs::write(&path, "[server]\npublic_url = \"https://a.example\"\n").unwrap();
    let vars = [
        (
            "ATTENUO__SERVER__FORWARDED_CLIENT_CERT__LISTEN",
            "127.0.0.1:18444",
        ),
        (
            "ATTENUO__SERVER__FORWARDED_CLIENT_CERT__TRUSTED_PEERS",
            "127.0.0.1",
        ),
    ];
    for (var, value) in vars {
        let e = Config::load_with_env(&path, [(var, value)])
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("[server.forwarded_client_cert] keys cannot be set from the environment"),
            "{e}"
        );
    }
}

/// The HAProxy recipe in the deploying guide is `deploy/haproxy/forwarded-client-cert.cfg` as
/// it is, and the file runs HAProxy in HTTP mode with the lines that remove the client's own
/// headers, so the copy people paste is the one `scripts/haproxy-forwarded-smoke.sh` ran.
#[test]
fn the_guide_shows_the_haproxy_recipe_file_as_it_is() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let file =
        std::fs::read_to_string(root.join("deploy/haproxy/forwarded-client-cert.cfg")).unwrap();
    let guide = std::fs::read_to_string(root.join("docs/guides/deploying.md")).unwrap();
    let section = &guide[guide.find("#### HAProxy").expect("the HAProxy section")..];
    let start = section.find("```haproxy\n").expect("the recipe block") + "```haproxy\n".len();
    let block = &section[start..start + section[start..].find("```").unwrap()];
    assert_eq!(
        block, file,
        "docs/guides/deploying.md and deploy/haproxy/forwarded-client-cert.cfg differ"
    );
    let lines: Vec<&str> = file
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect();
    for want in [
        "mode http",
        "http-request del-header Client-Cert",
        "http-request del-header Client-Cert-Chain",
    ] {
        assert!(lines.contains(&want), "{want}");
    }
    assert!(!lines.iter().any(|l| l.contains("mode tcp")));
    // The defaults section and the frontend and backend each say `mode http`.
    assert_eq!(lines.iter().filter(|l| **l == "mode http").count(), 3);
    // Removing comes before setting.
    let del = lines
        .iter()
        .position(|l| *l == "http-request del-header Client-Cert")
        .unwrap();
    let set = lines
        .iter()
        .position(|l| l.starts_with("http-request set-header Client-Cert "))
        .unwrap();
    assert!(del < set);
}
