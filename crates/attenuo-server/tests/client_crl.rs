//! CRL files for RFC 8705 `tls_client_auth` (ADR-0023): `tls_client_crl_paths`,
//! `tls_client_crl_issuer_pem_path`, `tls_client_crl_stale` and `tls_client_crl_missing` on
//! `[[agents]]` entries with `tls_client_ca_pem_path`. Real sockets through
//! [`attenuo_server::run`], the code `serve` runs, with the native TLS listener and the
//! forwarding listener of ADR-0021, and a manual clock.
//!
//! Covers: a revoked leaf refused over TLS and when forwarded, and other certificates of its CA
//! accepted; a revoked intermediate CA; a CRL of another CA, which revokes nothing here; the
//! startup refusals (another key, an unknown issuer, a stale CRL, a bad file, a scoped CRL, the
//! limits, settings on a pinned entry); a CRL that goes stale at its `nextUpdate` without a
//! reload, under both `tls_client_crl_stale` values; `tls_client_crl_missing`; a reload that
//! revokes a certificate on a connection kept open, and the reloads that keep the CRLs in force
//! (a bad CRL, an older one); certificate-bound tokens; and pinned certificates, which no CRL
//! touches.

// Configs are built field by field, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use attenuo_core::{Clock, ManualClock};
use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::{AppState, Config};
use base64::Engine as _;
use common::tls::{Ca, ClientCert};
use common::{free_port, sha256_hex, Running};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ADMIN: &str = "crl-test-admin-token-0123456789abcdef";
const ISSUER: &str = "https://attenuo.test";
const PUBLIC_URL: &str = "https://localhost:8443";
const IDP: &str = "https://idp.test";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const TRUST_DOMAIN: &str = "spiffe://example.org/ns/agents/sa";

const REVOKED: &str = "client_certificate_revoked";
const UNKNOWN: &str = "client_certificate_revocation_unknown";
const FAILED: &str = "client_authentication_failed";
const REQUIRED: &str = "client_certificate_required";

/// The serial number of the intermediate CA.
const MID_SERIAL: u64 = 2;
/// Serial numbers of leaves: from the root, accepted and revoked; from the intermediate,
/// accepted and revoked.
const ROOT_OK: u64 = 100;
const ROOT_REVOKED: u64 = 101;
const MID_OK: u64 = 200;
const MID_REVOKED: u64 = 201;

const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);
"#;

fn spiffe(agent: &str) -> String {
    format!("{TRUST_DOMAIN}/{agent}")
}

fn uri_san(s: &str) -> rcgen::SanType {
    rcgen::SanType::URI(s.try_into().unwrap())
}

/// The CAs and files of a test: the agents' root CA (`ca.pem`), an intermediate CA under it
/// (`mid.pem`, also the CRL issuer file), another CA (`other.pem`), and their CRLs
/// (`root.crl`, `mid.crl`, `other.crl`), in a directory of their own.
struct Pki {
    dir: tempfile::TempDir,
    root: Ca,
    mid: Ca,
    other: Ca,
    /// A self-signed certificate pinned for `pinned`, with the serial number of a certificate
    /// the root's CRL revokes.
    pinned: ClientCert,
}

/// The CRL settings of the `coder` and `reviewer` entries.
#[derive(Clone, Copy)]
struct Rules {
    stale: Option<&'static str>,
    missing: Option<&'static str>,
    /// `mid.crl` listed too.
    mid_crl: bool,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            stale: None,
            missing: None,
            mid_crl: true,
        }
    }
}

impl Pki {
    /// The CAs, and CRLs valid for an hour from `now`: the root's revokes [`ROOT_REVOKED`],
    /// the intermediate's [`MID_REVOKED`], the other CA's [`ROOT_OK`] (its own certificate of
    /// that serial).
    fn new(now: OffsetDateTime) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = Ca::new("crl test root CA");
        let mid = root.intermediate_with("crl test intermediate CA", |p| {
            p.serial_number = Some(rcgen::SerialNumber::from(MID_SERIAL));
        });
        let other = Ca::new("crl test other CA");
        root.write(dir.path(), "ca.pem");
        mid.write(dir.path(), "mid.pem");
        other.write(dir.path(), "other.pem");
        let pinned = ClientCert::made("pinned", |p| {
            p.serial_number = Some(rcgen::SerialNumber::from(ROOT_REVOKED));
        });
        let pki = Self {
            dir,
            root,
            mid,
            other,
            pinned,
        };
        let (this, next) = (now - Duration::minutes(1), now + Duration::hours(1));
        pki.write("root.crl", pki.root.crl(&[ROOT_REVOKED], this, next, 1));
        pki.write("mid.crl", pki.mid.crl(&[MID_REVOKED], this, next, 1));
        pki.write("other.crl", pki.other.crl(&[ROOT_OK], this, next, 1));
        pki
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write `name`, replaced in one rename.
    fn write(&self, name: &str, contents: impl AsRef<[u8]>) {
        let tmp = self.path(&format!("{name}.tmp"));
        std::fs::write(&tmp, contents).unwrap();
        std::fs::rename(&tmp, self.path(name)).unwrap();
    }

    /// A certificate `ca` issues for agent `agent` (by SPIFFE ID), with serial `serial`.
    fn leaf(&self, ca: &Ca, serial: u64, agent: &str) -> ClientCert {
        ca.client(|p| {
            p.serial_number = Some(rcgen::SerialNumber::from(serial));
            p.subject_alt_names = vec![uri_san(&spiffe(agent))];
        })
    }

    /// The CRL settings of an entry under `rules`, as TOML lines.
    fn crl_keys(&self, rules: Rules) -> String {
        let mut paths = vec![format!("\"{}\"", self.path("root.crl").display())];
        if rules.mid_crl {
            paths.push(format!("\"{}\"", self.path("mid.crl").display()));
        }
        let mut out = format!(
            "tls_client_crl_paths = [{}]\ntls_client_crl_issuer_pem_path = \"{}\"\n",
            paths.join(", "),
            self.path("mid.pem").display()
        );
        if let Some(s) = rules.stale {
            out += &format!("tls_client_crl_stale = \"{s}\"\n");
        }
        if let Some(m) = rules.missing {
            out += &format!("tls_client_crl_missing = \"{m}\"\n");
        }
        out
    }

    /// `planner` and `auditor` (secrets), `coder` and `reviewer` (the root CA, with CRLs as
    /// `rules` say), `pinned` (by thumbprint) and `outsider` (the other CA, with its CRL and
    /// the `tls_client_crl_stale` of `rules`).
    fn lists(&self, rules: Rules) -> String {
        let ca = self.path("ca.pem").display().to_string();
        let keys = self.crl_keys(rules);
        let outsider_stale = rules
            .stale
            .map(|s| format!("tls_client_crl_stale = \"{s}\"\n"))
            .unwrap_or_default();
        format!(
            "[[agents]]\nid = \"planner\"\nsecret_sha256 = \"{}\"\n\n\
             [[agents]]\nid = \"auditor\"\nsecret_sha256 = \"{}\"\n\n\
             [[agents]]\nid = \"coder\"\ntls_client_ca_pem_path = \"{ca}\"\n\
             tls_client_auth_san_uri = \"{}\"\n{keys}\n\
             [[agents]]\nid = \"reviewer\"\ntls_client_ca_pem_path = \"{ca}\"\n\
             tls_client_auth_san_uri = \"{}\"\n{keys}\n\
             [[agents]]\nid = \"pinned\"\ntls_client_cert_sha256 = [\"{}\"]\n\n\
             [[agents]]\nid = \"outsider\"\ntls_client_ca_pem_path = \"{}\"\n\
             tls_client_auth_san_uri = \"{}\"\ntls_client_crl_paths = [\"{}\"]\n{outsider_stale}",
            sha256_hex("planner-secret"),
            sha256_hex("auditor-secret"),
            spiffe("coder"),
            spiffe("reviewer"),
            self.pinned.sha256_hex(),
            self.path("other.pem").display(),
            spiffe("outsider"),
            self.path("other.crl").display(),
        )
    }
}

/// Write `<dir>/attenuo.toml` with `lists`, replaced in one rename so a reload never reads half
/// of it.
fn write_config(
    dir: &Path,
    server_files: &(PathBuf, PathBuf),
    forwarded: SocketAddr,
    lists: &str,
) -> PathBuf {
    let path = dir.join("attenuo.toml");
    let tmp = dir.join("attenuo.toml.tmp");
    std::fs::write(
        &tmp,
        format!(
            "[server]\npublic_url = \"{PUBLIC_URL}\"\n\n\
             [server.tls]\ncert_pem_path = \"{}\"\nkey_pem_path = \"{}\"\n\
             client_certificates = \"optional\"\n\n\
             [server.forwarded_client_cert]\nlisten = \"{forwarded}\"\n\
             trusted_peers = [\"127.0.0.1/32\"]\n\n\
             [issuer]\nissuer = \"{ISSUER}\"\nprivate_key_pem_path = \"{}\"\n\n\
             [audit]\nsqlite_path = \"{}\"\n\n\
             [admin]\ntoken = \"{ADMIN}\"\n\n\
             [dev]\nallow_root_mint = true\n\n\
             [token]\ntls_client_certificate_bound_access_tokens = true\n\n{lists}",
            server_files.0.display(),
            server_files.1.display(),
            dir.join("keys/issuer.pem").display(),
            dir.join("audit.sqlite").display(),
        ),
    )
    .unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    path
}

/// The config of a test, with the policy, catalog and upstream set in code.
fn load(path: &Path, dir: &Path, upstream: &Spawned) -> Config {
    let mut cfg = Config::load(path).unwrap();
    let policy = dir.join("policies.cedar");
    std::fs::write(&policy, POLICY).unwrap();
    cfg.policy.policies_path = Some(policy);
    cfg.policy.catalog = BTreeMap::from([(
        "github".to_string(),
        BTreeMap::from([(
            "read_file".to_string(),
            ToolAttrs::new()
                .with_input("repo", ArgType::String)
                .readonly(true),
        )]),
    )]);
    cfg.upstreams = vec![UpstreamConfig::new("github", upstream.url("/mcp"))];
    cfg
}

/// How a request reaches the server.
#[derive(Clone, Copy, Debug)]
enum Via<'a> {
    /// The main listener over TLS, with this certificate in the handshake.
    Native(Option<&'a ClientCert>),
    /// The forwarding listener, with the headers a trusted proxy sets for this certificate.
    Fwd(Option<&'a ClientCert>),
}

/// The server's files and settings that outlive one server, for a test that starts another.
struct Setup {
    dir: tempfile::TempDir,
    ca: Ca,
    server_files: (PathBuf, PathBuf),
    forwarded: SocketAddr,
    upstream: Spawned,
}

impl Setup {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::new("crl test server CA");
        let server_files = ca.write_server_files(dir.path(), &["127.0.0.1"]);
        let upstream = FakeMcpServer::new(&["read_file"]).spawn().await.unwrap();
        Self {
            dir,
            ca,
            server_files,
            forwarded: free_port(),
            upstream,
        }
    }

    /// The config with `lists`.
    fn config(&self, lists: &str) -> Config {
        let path = write_config(self.dir.path(), &self.server_files, self.forwarded, lists);
        load(&path, self.dir.path(), &self.upstream)
    }

    /// Why a server with `lists` does not start.
    fn refusal(&self, lists: &str) -> String {
        let err = attenuo_server::build(&self.config(lists))
            .err()
            .expect("the server must not start");
        format!("{err:#}")
    }
}

struct Harness {
    setup: Setup,
    clock: Arc<ManualClock>,
    running: Running,
    state: Arc<AppState>,
}

impl Harness {
    async fn start(lists: &str) -> Self {
        let setup = Setup::new().await;
        let clock = ManualClock::new();
        let cfg = setup.config(lists);
        let (router, state) = attenuo_server::build_with_clock(&cfg, clock.clone()).unwrap();
        let running = Running::start(cfg, state.clone(), router).await;
        let h = Self {
            setup,
            clock,
            running,
            state,
        };
        // `run` binds the forwarding listener before it serves the main one.
        let a = h
            .send(Via::Native(None), Method::GET, "/healthz", None, None)
            .await;
        assert_eq!(a.status, StatusCode::OK);
        h
    }

    async fn stop(self) {
        self.running.stop(self.state).await;
    }

    fn now(&self) -> OffsetDateTime {
        self.clock.now_utc()
    }

    /// One request; `token` as a bearer token.
    async fn send(
        &self,
        via: Via<'_>,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Answer {
        let (client, url) = match via {
            Via::Native(cert) => (
                self.setup.ca.reqwest_client(cert),
                self.running.https_url(path),
            ),
            Via::Fwd(_) => (
                plain_client(),
                format!("http://{}{path}", self.setup.forwarded),
            ),
        };
        let mut req = client
            .request(method, url)
            .header("accept", "application/json, text/event-stream");
        if let Via::Fwd(Some(cert)) = via {
            for (k, v) in forwarded_headers(cert) {
                req = req.header(k, v);
            }
        }
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        Answer::of(req.send().await.unwrap()).await
    }

    /// A root token for `planner` from the dev mint.
    async fn root(&self) -> String {
        let a = self
            .send(
                Via::Native(None),
                Method::POST,
                "/admin/root-token",
                Some(ADMIN),
                Some(
                    &json!({"subject": "alice", "issuer": IDP, "agent": "planner",
                             "capabilities": ["github:*"]}),
                ),
            )
            .await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.body);
        a.body["access_token"].as_str().unwrap().into()
    }

    /// An exchange from a fresh root token to `actor`, which authenticates with the
    /// certificate of `via`: the token is bound to it.
    async fn exchange(&self, via: Via<'_>, actor: &str) -> Answer {
        let root = self.root().await;
        let body = exchange_body(&root, actor);
        self.send(via, Method::POST, "/token", None, Some(&body))
            .await
    }

    /// Rewrite the config with `lists` and reload the agents.
    async fn reload(&self, lists: &str) -> Answer {
        write_config(
            self.setup.dir.path(),
            &self.setup.server_files,
            self.setup.forwarded,
            lists,
        );
        self.send(
            Via::Native(None),
            Method::POST,
            "/admin/agents/reload",
            Some(ADMIN),
            Some(&json!({})),
        )
        .await
    }

    async fn audit(&self) -> Vec<Value> {
        let a = self
            .send(
                Via::Native(None),
                Method::GET,
                "/admin/audit?from=1&limit=1000",
                Some(ADMIN),
                None,
            )
            .await;
        a.body["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["record"].clone())
            .collect()
    }

    /// A raw TLS 1.3 connection presenting `cert`, kept open across requests.
    async fn connect(
        &self,
        cert: &ClientCert,
    ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        let config = self.setup.ca.rustls_client_with(cert.resolver());
        let tcp = tokio::net::TcpStream::connect(self.running.addr())
            .await
            .unwrap();
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .unwrap()
    }

    /// An exchange to `actor` on the open connection `conn`.
    async fn exchange_on(
        &self,
        conn: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        actor: &str,
    ) -> (u16, Value) {
        let root = self.root().await;
        request_on(conn, "/token", &exchange_body(&root, actor)).await
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

    /// The stable code: the server's `code`, or the proxy's `error.data.reason`.
    fn code(&self) -> &str {
        self.body["code"]
            .as_str()
            .or(self.body["error"]["data"]["reason"].as_str())
            .unwrap_or_default()
    }

    fn ok(&self, what: &str) {
        assert_eq!(self.status, StatusCode::OK, "{what}: {}", self.body);
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

fn exchange_body(parent: &str, actor: &str) -> Value {
    json!({
        "grant_type": EXCHANGE, "subject_token": parent, "subject_token_type": JWT,
        "actor": actor, "client_id": actor,
        "authorization_details": [{"type": "attenuo_capabilities",
            "capabilities": [{"server": "github", "tool": "read_file"}]}],
    })
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

/// One `POST` on `stream` (kept alive), read by its `Content-Length`.
async fn request_on<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    path: &str,
    body: &Value,
) -> (u16, Value) {
    let body = body.to_string();
    stream
        .write_all(
            format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "closed before a full response: {buf:?}");
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
                return (status, v);
            }
        }
    }
}

fn status_code((status, v): &(u16, Value)) -> (u16, &str) {
    (*status, v["code"].as_str().unwrap_or_default())
}

/// The forwarding listener with `cert` when `fwd`, else the native TLS listener.
fn via(fwd: bool, cert: &ClientCert) -> Via<'_> {
    if fwd {
        Via::Fwd(Some(cert))
    } else {
        Via::Native(Some(cert))
    }
}

/// `cert` is refused as revoked, from the proxy and on a new TLS connection.
async fn assert_revoked(h: &Harness, cert: &ClientCert) {
    for fwd in [false, true] {
        let v = via(fwd, cert);
        h.exchange(v, "coder")
            .await
            .refused(REVOKED, &format!("{v:?}, after the reload"));
    }
}

/// The exchange records in the audit log.
async fn exchange_records(h: &Harness) -> usize {
    h.audit()
        .await
        .iter()
        .filter(|r| r["tool"] == "token.exchange")
        .count()
}

/// The reload records in the audit log.
async fn reload_records(h: &Harness) -> usize {
    h.audit()
        .await
        .iter()
        .filter(|r| r["tool"] == "admin.agents.reload")
        .count()
}

// --- authentication -----------------------------------------------------------------------

/// Over TLS and from a trusted proxy: a revoked leaf of the root CA and of the intermediate CA
/// is refused with `client_certificate_revoked`, the other certificates of each CA (and of the
/// other entry) are accepted, and a refusal writes no record. A revoked certificate sent for
/// another entry gets the one answer of every refused certificate (SR-110). The other CA's CRL
/// lists the serial number of an accepted certificate of the root CA, and revokes nothing here.
#[tokio::test]
async fn revoked_certificates_are_refused_over_tls_and_forwarded() {
    let pki = Pki::new(OffsetDateTime::now_utc());
    let h = Harness::start(&pki.lists(Rules::default())).await;
    let coder_ok = pki.leaf(&pki.root, ROOT_OK, "coder");
    let coder_revoked = pki.leaf(&pki.root, ROOT_REVOKED, "coder");
    let mid_ok = pki.leaf(&pki.mid, MID_OK, "coder");
    let mid_revoked = pki.leaf(&pki.mid, MID_REVOKED, "coder");
    let reviewer = pki.leaf(&pki.root, ROOT_OK + 50, "reviewer");
    let outsider_revoked = pki.leaf(&pki.other, ROOT_OK, "outsider");
    let outsider_ok = pki.leaf(&pki.other, ROOT_REVOKED, "outsider");
    assert_eq!(mid_ok.chain.len(), 1);

    for fwd in [false, true] {
        for (cert, actor) in [
            (&coder_ok, "coder"),
            (&mid_ok, "coder"),
            (&reviewer, "reviewer"),
            (&outsider_ok, "outsider"),
        ] {
            let v = via(fwd, cert);
            h.exchange(v, actor).await.ok(&format!("{v:?} {actor}"));
        }
        let exchanges = exchange_records(&h).await;
        for (cert, actor) in [
            (&coder_revoked, "coder"),
            (&mid_revoked, "coder"),
            (&outsider_revoked, "outsider"),
        ] {
            let v = via(fwd, cert);
            let a = h.exchange(v, actor).await;
            a.refused(REVOKED, &format!("{v:?} {actor}"));
            assert_eq!(a.body["error"], "invalid_client", "{}", a.body);
        }
        // Refusals of client authentication are logged, not audited.
        assert_eq!(exchange_records(&h).await, exchanges);
        // Sent for another entry: the name does not match, so the generic answer.
        h.exchange(via(fwd, &coder_revoked), "reviewer")
            .await
            .refused(FAILED, "a revoked certificate for another entry");
    }
    h.stop().await;
}

/// The root's CRL revokes the intermediate CA: every certificate below it is refused, over
/// both paths, whether or not the intermediate's own CRL lists it, and the root's other
/// certificates are accepted.
#[tokio::test]
async fn a_revoked_intermediate_refuses_every_certificate_below_it() {
    let pki = Pki::new(OffsetDateTime::now_utc());
    let now = OffsetDateTime::now_utc();
    pki.write(
        "root.crl",
        pki.root.crl(
            &[ROOT_REVOKED, MID_SERIAL],
            now - Duration::minutes(1),
            now + Duration::hours(1),
            1,
        ),
    );
    let h = Harness::start(&pki.lists(Rules::default())).await;
    let mid_ok = pki.leaf(&pki.mid, MID_OK, "coder");
    let coder_ok = pki.leaf(&pki.root, ROOT_OK, "coder");
    for fwd in [false, true] {
        h.exchange(via(fwd, &mid_ok), "coder")
            .await
            .refused(REVOKED, "below a revoked intermediate");
        h.exchange(via(fwd, &coder_ok), "coder")
            .await
            .ok("the root's own certificate");
    }
    h.stop().await;
}

// --- startup ------------------------------------------------------------------------------

/// The server does not start with a CRL signed by another key (the CA's name, an attacker's
/// key), a CRL whose issuer no CA file holds, a stale CRL (by default), a CRL whose
/// `thisUpdate` is far ahead, a file that is no CRL, a scoped CRL, a file over the size limit,
/// too many files, two CRLs of one CA, two entries with different CRLs of one CA, CRL settings
/// on a pinned entry or without `tls_client_crl_paths`, or an issuer file whose CA no CA file
/// issued. The message names the setting and never quotes the file.
#[tokio::test]
async fn bad_crls_stop_the_server() {
    let now = OffsetDateTime::now_utc();
    let pki = Pki::new(now);
    let setup = Setup::new().await;
    let (this, next) = (now - Duration::minutes(1), now + Duration::hours(1));
    let good = pki.lists(Rules::default());
    let root_crl = pki.path("root.crl").display().to_string();
    let replace_root = |name: &str, contents: String| {
        pki.write(name, contents);
        good.replace(&root_crl, &pki.path(name).display().to_string())
    };
    let impostor = Ca::new("crl test root CA");
    let scoped = pki.root.crl_with(&[], this, next, 1, |p| {
        p.issuing_distribution_point = Some(rcgen::CrlIssuingDistributionPoint {
            distribution_point: rcgen::CrlDistributionPoint {
                uris: vec!["http://crl.example/root.crl".into()],
            },
            scope: Some(rcgen::CrlScope::UserCertsOnly),
        });
    });
    let pinned_entry = format!(
        "[[agents]]\nid = \"pinned\"\ntls_client_cert_sha256 = [\"{}\"]\n",
        pki.pinned.sha256_hex()
    );
    let cases: Vec<(String, &str)> = vec![
        (
            replace_root("impostor.crl", impostor.crl(&[], this, next, 1)),
            "signed by another key",
        ),
        (
            replace_root("other-ca.crl", pki.other.crl(&[], this, next, 1)),
            "its issuer is not a CA certificate",
        ),
        (
            replace_root(
                "stale.crl",
                pki.root
                    .crl(&[], now - Duration::hours(2), now - Duration::hours(1), 1),
            ),
            "it is stale",
        ),
        (
            replace_root(
                "ahead.crl",
                pki.root
                    .crl(&[], now + Duration::hours(1), now + Duration::hours(2), 1),
            ),
            "ahead of the server clock",
        ),
        (
            replace_root("cert.crl", pki.root.cert.pem()),
            "exactly one PEM block, -----BEGIN X509 CRL-----",
        ),
        (
            replace_root("scoped.crl", scoped),
            "issuingDistributionPoint",
        ),
        (
            {
                pki.write("big.crl", vec![b'x'; 4 * 1024 * 1024 + 1]);
                good.replace(&root_crl, &pki.path("big.crl").display().to_string())
            },
            "tls_client_crl_paths",
        ),
        (
            good.replace(
                &format!("\"{root_crl}\""),
                &vec![format!("\"{root_crl}\""); 17].join(", "),
            ),
            "must list 1 to 16 files",
        ),
        (
            {
                pki.write("root-2.crl", pki.root.crl(&[], this, next, 2));
                good.replace(
                    &format!("\"{root_crl}\""),
                    &format!("\"{root_crl}\", \"{}\"", pki.path("root-2.crl").display()),
                )
            },
            "list one CRL per CA",
        ),
        (
            {
                // `reviewer` lists another CRL of the root than `coder` does.
                let (head, tail) = good.split_once("id = \"reviewer\"").unwrap();
                format!(
                    "{head}id = \"reviewer\"{}",
                    tail.replacen(&root_crl, &pki.path("root-2.crl").display().to_string(), 1)
                )
            },
            "both CRLs of one CA, with different contents",
        ),
        (
            format!("{pinned_entry}tls_client_crl_paths = [\"{root_crl}\"]\n"),
            "tls_client_ca_pem_path",
        ),
        (
            format!("{pinned_entry}tls_client_crl_stale = \"allow\"\n"),
            "tls_client_crl_paths",
        ),
    ];
    for (lists, want) in cases {
        let msg = setup.refusal(&lists);
        assert!(msg.contains(want), "{want}: {msg}");
        let body_line = pki.root.cert.pem().lines().nth(1).unwrap().to_owned();
        assert!(!msg.contains(&body_line), "{msg}");
    }
    // An issuer file with a CA the entry's CA file did not issue.
    let foreign = good.replace(
        &format!(
            "tls_client_crl_issuer_pem_path = \"{}\"",
            pki.path("mid.pem").display()
        ),
        &format!(
            "tls_client_crl_issuer_pem_path = \"{}\"",
            pki.path("other.pem").display()
        ),
    );
    let msg = setup.refusal(&foreign);
    assert!(msg.contains("tls_client_crl_issuer_pem_path"), "{msg}");
    // And the good lists start.
    let _ = attenuo_server::build(&setup.config(&good)).unwrap();
}

// --- staleness ----------------------------------------------------------------------------

/// With `tls_client_crl_stale = "refuse"` (the default), the CRL's `nextUpdate` ends its use
/// with no reload: a connection kept open, a new connection and the forwarding listener all get
/// `client_certificate_revocation_unknown` from then on, while a revoked certificate stays
/// `client_certificate_revoked`. A reload with the stale file is refused and audited; a reload
/// with a fresh CRL brings the certificates back.
#[tokio::test]
async fn a_crl_goes_stale_at_its_next_update_without_a_reload() {
    let now = OffsetDateTime::now_utc();
    let pki = Pki::new(now);
    let h = Harness::start(&pki.lists(Rules::default())).await;
    let coder = pki.leaf(&pki.root, ROOT_OK, "coder");
    let revoked = pki.leaf(&pki.root, ROOT_REVOKED, "coder");
    let mut conn = h.connect(&coder).await;
    assert_eq!(status_code(&h.exchange_on(&mut conn, "coder").await).0, 200);
    h.exchange(Via::Fwd(Some(&coder)), "coder")
        .await
        .ok("forwarded");

    // One second before nextUpdate: still in use (and cached).
    let left = (now + Duration::hours(1)) - h.now();
    h.clock
        .advance(std::time::Duration::try_from(left - Duration::seconds(2)).unwrap());
    assert_eq!(status_code(&h.exchange_on(&mut conn, "coder").await).0, 200);
    h.clock.advance(std::time::Duration::from_secs(3));
    assert_eq!(
        status_code(&h.exchange_on(&mut conn, "coder").await),
        (401, UNKNOWN)
    );
    for fwd in [false, true] {
        h.exchange(via(fwd, &coder), "coder")
            .await
            .refused(UNKNOWN, "stale");
        h.exchange(via(fwd, &revoked), "coder")
            .await
            .refused(REVOKED, "stale, and listed");
    }

    // A reload with the same, now stale, files is refused, and audited.
    let reloads = reload_records(&h).await;
    let a = h.reload(&pki.lists(Rules::default())).await;
    assert_eq!(a.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", a.body);
    assert_eq!(a.body["code"], "agents_invalid", "{}", a.body);
    assert!(a.body.to_string().contains("it is stale"), "{}", a.body);
    assert_eq!(reload_records(&h).await, reloads + 1);

    // A fresh CRL of each CA: in use again, on the open connection too.
    let t = h.now();
    let (this, next) = (t - Duration::minutes(1), t + Duration::hours(1));
    pki.write("root.crl", pki.root.crl(&[ROOT_REVOKED], this, next, 2));
    pki.write("mid.crl", pki.mid.crl(&[MID_REVOKED], this, next, 2));
    pki.write("other.crl", pki.other.crl(&[ROOT_OK], this, next, 2));
    h.reload(&pki.lists(Rules::default())).await.ok("reload");
    assert_eq!(status_code(&h.exchange_on(&mut conn, "coder").await).0, 200);
    h.exchange(Via::Fwd(Some(&coder)), "coder")
        .await
        .ok("forwarded, fresh CRL");
    h.stop().await;
}

/// With `tls_client_crl_stale = "allow"`, a stale CRL stays in use: certificates it does not
/// list are accepted, those it lists are refused. A stale CRL under "allow" also starts.
#[tokio::test]
async fn allow_keeps_using_a_stale_crl() {
    let now = OffsetDateTime::now_utc();
    let pki = Pki::new(now);
    let allow = Rules {
        stale: Some("allow"),
        ..Rules::default()
    };
    let lists = pki.lists(allow);
    assert_eq!(lists.matches("tls_client_crl_stale = \"allow\"").count(), 3);
    let h = Harness::start(&lists).await;
    let coder = pki.leaf(&pki.root, ROOT_OK, "coder");
    let revoked = pki.leaf(&pki.mid, MID_REVOKED, "coder");
    h.clock.advance(std::time::Duration::from_secs(2 * 3600));
    for fwd in [false, true] {
        h.exchange(via(fwd, &coder), "coder")
            .await
            .ok("stale, allowed");
        h.exchange(via(fwd, &revoked), "coder")
            .await
            .refused(REVOKED, "stale, allowed, and listed");
    }
    // A reload with the stale files is accepted under "allow".
    h.reload(&lists)
        .await
        .ok("reload of stale CRLs under allow");
    h.stop().await;

    // And a server starts with them.
    let setup = Setup::new().await;
    let t = OffsetDateTime::now_utc();
    pki.write(
        "root.crl",
        pki.root
            .crl(&[], t - Duration::hours(2), t - Duration::hours(1), 3),
    );
    let _ = attenuo_server::build(&setup.config(&lists)).unwrap();
}

/// `tls_client_crl_missing`: by default a CA with no CRL listed is not checked; with
/// "refuse", a certificate below a CA without a CRL gets `client_certificate_revocation_unknown`,
/// and the root's own certificates (whose CA has a CRL) are accepted.
#[tokio::test]
async fn a_missing_crl_is_allowed_by_default_and_refused_when_asked() {
    let pki = Pki::new(OffsetDateTime::now_utc());
    let mid_leaf = pki.leaf(&pki.mid, MID_REVOKED, "coder");
    let root_leaf = pki.leaf(&pki.root, ROOT_OK, "coder");
    let only_root = Rules {
        mid_crl: false,
        ..Rules::default()
    };
    let h = Harness::start(&pki.lists(only_root)).await;
    // Not listed anywhere the server reads: accepted.
    h.exchange(Via::Native(Some(&mid_leaf)), "coder")
        .await
        .ok("no CRL for the intermediate, allowed");
    let r = h
        .reload(&pki.lists(Rules {
            missing: Some("refuse"),
            ..only_root
        }))
        .await;
    r.ok("reload");
    assert_eq!(r.body["agents"]["changed"], json!(["coder", "reviewer"]));
    for fwd in [false, true] {
        h.exchange(via(fwd, &mid_leaf), "coder")
            .await
            .refused(UNKNOWN, "no CRL for the intermediate, refused");
        h.exchange(via(fwd, &root_leaf), "coder")
            .await
            .ok("the root has its CRL");
    }
    h.stop().await;
}

// --- reload -------------------------------------------------------------------------------

/// A reload with a new CRL that revokes a certificate refuses it on its next request, on a
/// connection kept open (whose cache accepted it before) and from the proxy. A reload with a
/// bad CRL, a CRL signed by another key, or an older CRL is refused, audited, and the CRLs in
/// force stay: the certificate stays revoked. The same CRL again is no change.
#[tokio::test]
async fn a_reload_revokes_on_open_connections_and_never_goes_back() {
    let now = OffsetDateTime::now_utc();
    let pki = Pki::new(now);
    let lists = pki.lists(Rules::default());
    let h = Harness::start(&lists).await;
    let coder = pki.leaf(&pki.mid, MID_OK, "coder");
    let mut conn = h.connect(&coder).await;
    for _ in 0..2 {
        assert_eq!(status_code(&h.exchange_on(&mut conn, "coder").await).0, 200);
        h.exchange(Via::Fwd(Some(&coder)), "coder")
            .await
            .ok("forwarded");
    }

    // The same files: no change.
    let r = h.reload(&lists).await;
    r.ok("same files");
    assert_eq!(r.body["agents"]["changed"], json!([]), "{}", r.body);

    // A newer CRL of the intermediate that revokes the certificate.
    let crl_1 = std::fs::read(pki.path("mid.crl")).unwrap();
    pki.write(
        "mid.crl",
        pki.mid.crl(
            &[MID_REVOKED, MID_OK],
            now - Duration::seconds(30),
            now + Duration::hours(1),
            2,
        ),
    );
    let crl_2 = std::fs::read(pki.path("mid.crl")).unwrap();
    let r = h.reload(&lists).await;
    r.ok("newer CRL");
    assert_eq!(
        r.body["agents"]["changed"],
        json!(["coder", "reviewer"]),
        "{}",
        r.body
    );
    assert_eq!(
        status_code(&h.exchange_on(&mut conn, "coder").await),
        (401, REVOKED)
    );
    assert_revoked(&h, &coder).await;

    // Reloads that are refused, audited, and keep the CRL in force.
    let reloads_before = reload_records(&h).await;
    let other_key = Ca::new("crl test intermediate CA");
    let cases: Vec<(Vec<u8>, &str, &str)> = vec![
        (b"not a CRL".to_vec(), "agents_invalid", "neither a PEM CRL"),
        (
            other_key
                .crl(&[], now, now + Duration::hours(1), 3)
                .into_bytes(),
            "agents_invalid",
            "signed by another key",
        ),
        // The first CRL again: an older thisUpdate and cRLNumber.
        (crl_1.clone(), "client_crl_older", "older than the CRL"),
        // A later thisUpdate but a smaller cRLNumber.
        (
            pki.mid
                .crl(&[MID_REVOKED], now, now + Duration::hours(1), 1)
                .into_bytes(),
            "client_crl_older",
            "older than the CRL",
        ),
    ];
    let n = cases.len();
    for (crl, code, want) in cases {
        pki.write("mid.crl", &crl);
        let a = h.reload(&lists).await;
        assert_eq!(a.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", a.body);
        assert_eq!(a.body["code"], code, "{}", a.body);
        assert!(a.body.to_string().contains(want), "{want}: {}", a.body);
        assert!(a.body.to_string().contains("are unchanged"), "{}", a.body);
        assert_eq!(
            status_code(&h.exchange_on(&mut conn, "coder").await),
            (401, REVOKED)
        );
        assert_revoked(&h, &coder).await;
    }
    assert_eq!(reload_records(&h).await, reloads_before + n);

    // The CRL in force, again: no change.
    pki.write("mid.crl", &crl_2);
    let r = h.reload(&lists).await;
    r.ok("the CRL in force");
    assert_eq!(r.body["agents"]["changed"], json!([]), "{}", r.body);
    h.stop().await;
}

// --- certificate-bound tokens and pinned certificates --------------------------------------

/// `token` over `via` on the MCP route, an AuthZEN route and `POST /token/renew`: accepted
/// when `want` is `None`, else refused with `want`, and on the MCP route with
/// `client_certificate_required` (the proxy is not handed a certificate that fails its CRL
/// check).
async fn check_routes(h: &Harness, want: Option<&str>, token: &str, via: Via<'_>) {
    let routes: [(Method, &str, Option<Value>); 3] = [
        (Method::POST, "/mcp/github", Some(read_call())),
        (Method::POST, "/access/v1/evaluation", Some(evaluation())),
        (Method::POST, "/token/renew", None),
    ];
    for (method, path, body) in routes {
        let a = h.send(via, method, path, Some(token), body.as_ref()).await;
        let what = format!("{via:?} {path}");
        match want {
            None => a.ok(&what),
            Some(_) if path.starts_with("/mcp") => a.refused(REQUIRED, &what),
            Some(code) => a.refused(code, &what),
        }
    }
}

/// A token bound to a certificate of an entry with CRLs follows the CRLs: once a reload revokes
/// the certificate, `POST /token/renew`, the AuthZEN routes and an exchange with the token as
/// subject token answer `client_certificate_revoked`, and the MCP route
/// `client_certificate_required` (the proxy is not handed the certificate); once the CRL is
/// stale, `client_certificate_revocation_unknown`. A token bound to a pinned certificate whose
/// serial number a CRL lists is unaffected, as is the pinned client's authentication.
#[tokio::test]
async fn bound_tokens_follow_the_crls_and_pinned_certificates_are_unaffected() {
    let now = OffsetDateTime::now_utc();
    let pki = Pki::new(now);
    let lists = pki.lists(Rules::default());
    let h = Harness::start(&lists).await;
    let coder = pki.leaf(&pki.root, ROOT_OK, "coder");
    let reviewer = pki.leaf(&pki.root, ROOT_OK + 50, "reviewer");

    let token_of = |a: Answer| -> String {
        a.ok("exchange");
        a.body["access_token"].as_str().unwrap().to_owned()
    };
    let coder_native = token_of(h.exchange(Via::Native(Some(&coder)), "coder").await);
    let coder_fwd = token_of(h.exchange(Via::Fwd(Some(&coder)), "coder").await);
    let pinned_token = token_of(h.exchange(Via::Native(Some(&pki.pinned)), "pinned").await);
    let reviewer_token = token_of(h.exchange(Via::Fwd(Some(&reviewer)), "reviewer").await);

    check_routes(&h, None, &coder_native, Via::Native(Some(&coder))).await;
    check_routes(&h, None, &coder_fwd, Via::Fwd(Some(&coder))).await;

    // Revoke coder's certificate.
    pki.write(
        "root.crl",
        pki.root
            .crl(&[ROOT_REVOKED, ROOT_OK], now, now + Duration::minutes(4), 2),
    );
    h.reload(&lists).await.ok("reload");
    let native = Via::Native(Some(&coder));
    check_routes(&h, Some(REVOKED), &coder_native, native).await;
    check_routes(&h, Some(REVOKED), &coder_fwd, Via::Fwd(Some(&coder))).await;
    // The token as the subject token of an exchange.
    let a = h
        .send(
            Via::Native(Some(&coder)),
            Method::POST,
            "/token",
            None,
            Some(&json!({
                "grant_type": EXCHANGE, "subject_token": coder_fwd, "subject_token_type": JWT,
                "actor": "auditor", "client_id": "auditor", "client_secret": "auditor-secret",
                "authorization_details": [{"type": "attenuo_capabilities",
                    "capabilities": [{"server": "github", "tool": "read_file"}]}],
            })),
        )
        .await;
    a.refused(
        REVOKED,
        "exchange of a token bound to a revoked certificate",
    );
    assert_eq!(a.body["error"], "invalid_token", "{}", a.body);

    // The pinned certificate carries the serial number the root's CRL lists: unaffected.
    check_routes(&h, None, &pinned_token, Via::Native(Some(&pki.pinned))).await;
    h.exchange(Via::Fwd(Some(&pki.pinned)), "pinned")
        .await
        .ok("pinned, forwarded");

    // The root's CRL goes stale: the reviewer's bound token stops at its nextUpdate (within
    // the lease interval, so the lease is still alive).
    let fwd = Via::Fwd(Some(&reviewer));
    check_routes(&h, None, &reviewer_token, fwd).await;
    let left = (now + Duration::minutes(4)) - h.now();
    h.clock
        .advance(std::time::Duration::try_from(left + Duration::seconds(1)).unwrap());
    check_routes(&h, Some(UNKNOWN), &reviewer_token, fwd).await;
    h.stop().await;
}
