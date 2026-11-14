//! `[[idps]]` and `[[actor_trust]]` `ca_pem_path`: key URLs served over HTTPS with a
//! certificate from a private CA made in the test. Without the setting the fetch is refused
//! (the CA is not a web PKI root); with the entry's CA it succeeds; with another CA it is
//! refused; and an entry without the setting still refuses the same server. The hostname
//! check, the refusal of redirects and the read-once-at-start rule are checked over TLS too,
//! and the log line of a refused fetch names the TLS cause.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::config::{
    ActorTrustConfig, AgentConfig, CapSpec, IdpConfig, RootGrant, SubjectToAgent,
};
use attenuo_server::Config;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::StatusCode;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::sha256_hex;

const ADMIN: &str = "test-admin-token";
const TRUST_DOMAIN: &str = "example.org";
const ACTOR_AUD: &str = "https://attenuo.test";
const WL_ISSUER: &str = "https://workload.test";
const CODER_ID: &str = "spiffe://example.org/ns/agents/sa/coder";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
const EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const CLIENT_AUD: &str = "attenuo-client";
const PLANNER_SECRET: &str = "planner-secret";

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// A certificate authority made for one test.
struct Ca {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl Ca {
    fn new(name: &str) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let cert = params.self_signed(&key).unwrap();
        Self { cert, key }
    }

    /// Write the CA certificate as PEM into `dir`.
    fn write(&self, dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, self.cert.pem()).unwrap();
        path
    }

    /// A server certificate for `names` (DNS names or IP addresses) signed by this CA.
    fn leaf(&self, names: &[&str]) -> (rustls::pki_types::CertificateDer<'static>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        (cert.der().clone(), key.serialize_der())
    }
}

/// An HTTPS server on 127.0.0.1 whose certificate (for `127.0.0.1` only) chains to `ca`. It
/// answers `GET <path>` with the JSON stored for the path, `/moved` with a redirect, anything
/// else with 404, and counts the requests per path. HTTP/1.1, one request per connection.
struct TlsKeyServer {
    port: u16,
    docs: Arc<Mutex<HashMap<String, Value>>>,
    hits: Arc<Mutex<HashMap<String, usize>>>,
    handshakes_failed: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TlsKeyServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TlsKeyServer {
    async fn start(ca: &Ca) -> Self {
        let (cert, key) = ca.leaf(&["127.0.0.1"]);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert, ca.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let docs: Arc<Mutex<HashMap<String, Value>>> = Arc::default();
        let hits: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
        let handshakes_failed = Arc::new(AtomicUsize::new(0));
        let (d, h, f) = (docs.clone(), hits.clone(), handshakes_failed.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, d, h, f) = (acceptor.clone(), d.clone(), h.clone(), f.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        f.fetch_add(1, Ordering::SeqCst);
                        return;
                    };
                    let mut req = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !req.windows(4).any(|w| w == b"\r\n\r\n") && req.len() < 16 * 1024 {
                        match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => req.extend_from_slice(&buf[..n]),
                        }
                    }
                    let line = String::from_utf8_lossy(&req);
                    let path = line.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    *h.lock().unwrap().entry(path.clone()).or_default() += 1;
                    let doc = d.lock().unwrap().get(&path).cloned();
                    let resp = match (path.as_str(), doc) {
                        ("/moved", _) => "HTTP/1.1 302 Found\r\nLocation: /bundle\r\n\
                             Content-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_owned(),
                        (_, Some(doc)) => {
                            let body = doc.to_string();
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            )
                        }
                        (_, None) => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\
                             Connection: close\r\n\r\n"
                            .to_owned(),
                    };
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self {
            port,
            docs,
            hits,
            handshakes_failed,
            task,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    fn serve(&self, path: &str, doc: Value) {
        self.docs.lock().unwrap().insert(path.into(), doc);
    }

    fn hits(&self, path: &str) -> usize {
        self.hits.lock().unwrap().get(path).copied().unwrap_or(0)
    }
}

/// An ES256 signing key and its public JWK.
struct Key {
    kid: String,
    encoding: EncodingKey,
    jwk: Value,
}

impl Key {
    /// `usage` is the JWK `use`: `jwt-svid` in a SPIFFE bundle, `sig` in a JWKS.
    fn es256(kid: &str, usage: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let point = pair.public_key().as_ref().to_vec();
        Self {
            kid: kid.into(),
            encoding: EncodingKey::from_ec_der(pkcs8.as_ref()),
            jwk: json!({
                "kty": "EC", "crv": "P-256", "use": usage, "kid": kid,
                "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
                "y": URL_SAFE_NO_PAD.encode(&point[33..]),
            }),
        }
    }

    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        header.typ = Some("JWT".into());
        jsonwebtoken::encode(&header, claims, &self.encoding).unwrap()
    }

    fn svid(&self, spiffe_id: &str) -> String {
        self.sign(&json!({
            "sub": spiffe_id, "aud": [ACTOR_AUD], "exp": now() + 300, "iat": now(),
            "jti": uuid::Uuid::new_v4().to_string(),
        }))
    }

    fn workload_token(&self, sub: &str) -> String {
        self.sign(&json!({
            "iss": WL_ISSUER, "sub": sub, "aud": ACTOR_AUD, "exp": now() + 300, "iat": now(),
            "jti": uuid::Uuid::new_v4().to_string(),
        }))
    }
}

fn spiffe_entry(bundle_url: String, ca: Option<PathBuf>) -> ActorTrustConfig {
    ActorTrustConfig {
        issuer: None,
        jwks_url: None,
        spiffe_trust_domain: Some(TRUST_DOMAIN.into()),
        spiffe_bundle_url: Some(bundle_url),
        ca_pem_path: ca,
        audience: ACTOR_AUD.into(),
        subject_to_agent: SubjectToAgent::Map(BTreeMap::from([(
            CODER_ID.to_string(),
            "coder".to_string(),
        )])),
        allowed_algs: vec!["ES256".into()],
        jwks_ttl_seconds: 300,
        clock_skew_seconds: 0,
    }
}

fn workload_entry(jwks_url: String, ca: Option<PathBuf>) -> ActorTrustConfig {
    ActorTrustConfig {
        issuer: Some(WL_ISSUER.into()),
        jwks_url: Some(jwks_url),
        spiffe_trust_domain: None,
        spiffe_bundle_url: None,
        ca_pem_path: ca,
        audience: ACTOR_AUD.into(),
        subject_to_agent: SubjectToAgent::Sub,
        allowed_algs: vec!["ES256".into()],
        jwks_ttl_seconds: 300,
        clock_skew_seconds: 0,
    }
}

fn base_config() -> Config {
    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.test".into();
    cfg.issuer.audience = "attenuo-test".into();
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.agents = vec![AgentConfig::with_secret_sha256(
        "planner",
        sha256_hex(PLANNER_SECRET),
    )];
    cfg
}

/// A server for `cfg`, and a root token from the dev mint to exchange.
struct Attenuo {
    server: Spawned,
    client: reqwest::Client,
}

impl Attenuo {
    async fn start(cfg: &Config) -> Self {
        let (router, _state) = attenuo_server::build(cfg).unwrap();
        Self {
            server: spawn_router(router).await.unwrap(),
            client: reqwest::Client::new(),
        }
    }

    async fn root_token(&self) -> String {
        let v: Value = self
            .client
            .post(self.server.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&json!({
                "subject": "alice", "issuer": "https://idp.example", "agent": "planner",
                "capabilities": ["github:*"],
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["access_token"].as_str().unwrap().to_owned()
    }

    /// Exchange a fresh root token for `actor`, authenticated by `actor_token`.
    async fn exchange(&self, actor: &str, actor_token: &str) -> (StatusCode, Value) {
        let parent = self.root_token().await;
        let resp = self
            .client
            .post(self.server.url("/token"))
            .json(&json!({
                "grant_type": EXCHANGE,
                "subject_token": parent,
                "subject_token_type": JWT,
                "actor": actor,
                "actor_token": actor_token,
                "actor_token_type": JWT,
                "authorization_details": [{"type": "attenuo_capabilities",
                    "capabilities": [{"server": "github", "tool": "read_file"}]}],
            }))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    /// Hop 0 at `POST /token` with an ID token, `planner` authenticating with its secret.
    async fn intake(&self, id_token: &str) -> (StatusCode, Value) {
        let body = serde_urlencoded::to_string([
            ("grant_type", EXCHANGE),
            ("subject_token", id_token),
            ("subject_token_type", ID_TOKEN),
            ("client_id", "planner"),
            ("client_secret", PLANNER_SECRET),
            ("scope", "github:read_file"),
        ])
        .unwrap();
        let resp = self
            .client
            .post(self.server.url("/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }
}

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

/// Installs, once per process, a global subscriber that keeps WARN lines in [`LOGS`]. Global,
/// not `with_default`: `tracing` caches each callsite's interest process-wide, and the server
/// logs from tasks (see `install_capture` in `hardening.rs`). The tests of this binary run in
/// parallel, so a test finds its own line by the key URL, whose port is its own.
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

/// The logged lines that report a failed key fetch of `url`.
fn fetch_failures(url: &str) -> Vec<String> {
    let logs = String::from_utf8_lossy(&LOGS.lock().unwrap()).into_owned();
    logs.lines()
        .filter(|l| l.contains("JWKS unavailable") && l.contains(url))
        .map(str::to_owned)
        .collect()
}

/// The refusal a key fetch failure gets: 503, the stable code, and no transport detail.
fn assert_jwks_unavailable(status: StatusCode, v: &Value) {
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    assert_eq!(v["error"], "temporarily_unavailable", "{v}");
    assert_eq!(v["error_description"], "jwks_unavailable", "{v}");
    let body = v.to_string();
    for leak in ["certificate", "127.0.0.1", "error sending request"] {
        assert!(!body.contains(leak), "the response names {leak:?}: {body}");
    }
}

/// A SPIFFE bundle endpoint behind a private CA: refused without `ca_pem_path` and with
/// another CA, accepted with the entry's CA. A second entry on the same server without the
/// setting keeps refusing it: the extra root belongs to the entry that names it.
#[tokio::test]
async fn a_bundle_endpoint_behind_a_private_ca_needs_the_entrys_ca() {
    capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("attenuo test CA");
    let other = Ca::new("another test CA");
    let ca_pem = ca.write(dir.path(), "ca.pem");
    let other_pem = other.write(dir.path(), "other.pem");
    let keys = TlsKeyServer::start(&ca).await;
    let svid_key = Key::es256("svid-1", "jwt-svid");
    let wl_key = Key::es256("wl-1", "sig");
    keys.serve(
        "/bundle",
        json!({"spiffe_sequence": 1, "keys": [svid_key.jwk]}),
    );
    keys.serve("/jwks", json!({"keys": [wl_key.jwk]}));

    let cases: [(&str, Option<PathBuf>, bool); 3] = [
        ("no ca_pem_path", None, false),
        ("another CA", Some(other_pem), false),
        ("the issuing CA", Some(ca_pem.clone()), true),
    ];
    for (case, ca_path, ok) in cases {
        let mut cfg = base_config();
        cfg.actor_trust = vec![spiffe_entry(keys.url("/bundle"), ca_path)];
        let attenuo = Attenuo::start(&cfg).await;
        let (status, v) = attenuo.exchange("coder", &svid_key.svid(CODER_ID)).await;
        if ok {
            assert_eq!(status, StatusCode::OK, "{case}: {v}");
        } else {
            assert_jwks_unavailable(status, &v);
        }
    }
    assert!(
        keys.handshakes_failed.load(Ordering::SeqCst) >= 2,
        "the refusals were TLS handshake failures"
    );
    // The log names the TLS cause, not only "error sending request" (#320).
    let lines = fetch_failures(&keys.url("/bundle"));
    assert_eq!(lines.len(), 2, "{lines:#?}");
    for line in &lines {
        assert!(line.contains("WARN"), "{line}");
        assert!(line.contains("invalid peer certificate"), "{line}");
        assert!(line.contains("UnknownIssuer"), "{line}");
    }

    // Two entries, one server: only the entry with the CA can fetch.
    let mut cfg = base_config();
    cfg.actor_trust = vec![
        spiffe_entry(keys.url("/bundle"), Some(ca_pem)),
        workload_entry(keys.url("/jwks"), None),
    ];
    let attenuo = Attenuo::start(&cfg).await;
    let (status, v) = attenuo.exchange("coder", &svid_key.svid(CODER_ID)).await;
    assert_eq!(status, StatusCode::OK, "the entry with the CA: {v}");
    let (status, v) = attenuo
        .exchange("wl:reviewer", &wl_key.workload_token("wl:reviewer"))
        .await;
    assert_jwks_unavailable(status, &v);
    assert_eq!(keys.hits("/jwks"), 0, "no request reached the server");
}

/// The refetch on an unknown `kid` uses the entry's client too.
#[tokio::test]
async fn the_unknown_kid_refetch_uses_the_entrys_ca() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("attenuo test CA");
    let keys = TlsKeyServer::start(&ca).await;
    let first = Key::es256("svid-1", "jwt-svid");
    let second = Key::es256("svid-2", "jwt-svid");
    keys.serve("/bundle", json!({"keys": [first.jwk]}));
    let mut cfg = base_config();
    cfg.actor_trust = vec![spiffe_entry(
        keys.url("/bundle"),
        Some(ca.write(dir.path(), "ca.pem")),
    )];
    let attenuo = Attenuo::start(&cfg).await;
    let (status, v) = attenuo.exchange("coder", &first.svid(CODER_ID)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(keys.hits("/bundle"), 1);

    keys.serve("/bundle", json!({"keys": [first.jwk, second.jwk]}));
    let (status, v) = attenuo.exchange("coder", &second.svid(CODER_ID)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(keys.hits("/bundle"), 2, "the new kid was fetched over TLS");
}

/// `[[idps]]` without `jwks_url`: the discovery document and the `jwks_uri` it names are both
/// fetched over TLS with the entry's CA.
#[tokio::test]
async fn idp_discovery_and_jwks_use_the_entrys_ca() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("attenuo test CA");
    let ca_pem = ca.write(dir.path(), "ca.pem");
    let keys = TlsKeyServer::start(&ca).await;
    let issuer = format!("https://127.0.0.1:{}", keys.port);
    let key = Key::es256("idp-1", "sig");
    keys.serve(
        "/.well-known/openid-configuration",
        json!({"issuer": issuer, "jwks_uri": keys.url("/keys")}),
    );
    keys.serve("/keys", json!({"keys": [key.jwk]}));
    let id_token = |n: u32| {
        key.sign(&json!({
            "iss": issuer, "aud": CLIENT_AUD, "sub": "alice", "iat": now(),
            "exp": now() + 300, "jti": format!("id-{n}"),
        }))
    };

    for (n, ca_path) in [(1, None), (2, Some(ca_pem))] {
        let ok = ca_path.is_some();
        let mut cfg = base_config();
        cfg.idps = vec![IdpConfig {
            issuer: issuer.clone(),
            audience: String::new(),
            jwks_url: None,
            allowed_algs: vec!["ES256".into()],
            attribute_claims: vec![],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 60,
            tenant: None,
            id_jag_ceiling: None,
            credentials: attenuo_server::config::DEFAULT_IDP_CREDENTIALS.to_vec(),
            ca_pem_path: ca_path,
            client_ids: BTreeMap::from([("planner".to_string(), CLIENT_AUD.to_string())]),
        }];
        cfg.root_grants = vec![RootGrant {
            subject: None,
            issuer: issuer.clone(),
            agent: "planner".into(),
            capabilities: vec![CapSpec::Short("github:*".into())],
            attributes: BTreeMap::new(),
            may_act: None,
        }];
        let attenuo = Attenuo::start(&cfg).await;
        let (status, v) = attenuo.intake(&id_token(n)).await;
        if ok {
            assert_eq!(status, StatusCode::OK, "{v}");
        } else {
            assert_jwks_unavailable(status, &v);
        }
    }
    assert_eq!(keys.hits("/.well-known/openid-configuration"), 1);
    assert_eq!(keys.hits("/keys"), 1);
}

/// The CA adds a root and nothing else: the certificate must still name the host (it names
/// `127.0.0.1`, not `localhost`), and a redirect is still refused, not followed.
#[tokio::test]
async fn the_hostname_check_and_the_redirect_refusal_stay() {
    capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("attenuo test CA");
    let ca_pem = ca.write(dir.path(), "ca.pem");
    let keys = TlsKeyServer::start(&ca).await;
    let svid_key = Key::es256("svid-1", "jwt-svid");
    keys.serve("/bundle", json!({"keys": [svid_key.jwk]}));
    for url in [
        format!("https://localhost:{}/bundle", keys.port),
        keys.url("/moved"),
    ] {
        let mut cfg = base_config();
        cfg.actor_trust = vec![spiffe_entry(url.clone(), Some(ca_pem.clone()))];
        let attenuo = Attenuo::start(&cfg).await;
        let (status, v) = attenuo.exchange("coder", &svid_key.svid(CODER_ID)).await;
        assert_jwks_unavailable(status, &v);
    }
    assert_eq!(keys.hits("/moved"), 1, "the redirect was answered");
    assert_eq!(keys.hits("/bundle"), 0, "and not followed");
    let lines = fetch_failures(&format!("https://localhost:{}/bundle", keys.port));
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert!(
        lines[0].contains("invalid peer certificate"),
        "{}",
        lines[0]
    );
    assert!(
        lines[0].contains("not valid for name") || lines[0].contains("NotValidForName"),
        "the hostname mismatch is named: {}",
        lines[0]
    );
    let lines = fetch_failures(&keys.url("/moved"));
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert!(lines[0].contains("redirect"), "{}", lines[0]);
}

/// The file is read once, when the server starts: removing it afterwards changes nothing
/// (no reload re-reads `[[idps]]` or `[[actor_trust]]`; a new CA file needs a restart).
#[tokio::test]
async fn the_ca_file_is_read_at_start_only() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("attenuo test CA");
    let ca_pem = ca.write(dir.path(), "ca.pem");
    let keys = TlsKeyServer::start(&ca).await;
    let svid_key = Key::es256("svid-1", "jwt-svid");
    keys.serve("/bundle", json!({"keys": [svid_key.jwk]}));
    let mut cfg = base_config();
    cfg.actor_trust = vec![spiffe_entry(keys.url("/bundle"), Some(ca_pem.clone()))];
    let attenuo = Attenuo::start(&cfg).await;
    std::fs::remove_file(&ca_pem).unwrap();
    // The first fetch happens now, after the file is gone.
    let (status, v) = attenuo.exchange("coder", &svid_key.svid(CODER_ID)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

/// A file that is missing, empty, holds no certificate, or a certificate that does not parse
/// refuses to start, naming the entry, the key and the path.
#[test]
fn a_bad_ca_file_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, text: &str| {
        let p = dir.path().join(name);
        std::fs::write(&p, text).unwrap();
        p
    };
    let key_only = rcgen::KeyPair::generate().unwrap().serialize_pem();
    let cases = [
        (dir.path().join("missing.pem"), "cannot read the file"),
        (write("empty.pem", "\n"), "empty"),
        (write("key.pem", &key_only), "no PEM certificate"),
        (
            write("text.pem", "not a certificate\n"),
            "no PEM certificate",
        ),
        (
            write(
                "garbage.pem",
                "-----BEGIN CERTIFICATE-----\nAAECAwQFBgcICQ==\n-----END CERTIFICATE-----\n",
            ),
            "trust anchor",
        ),
    ];
    for (path, want) in cases {
        let mut cfg = base_config();
        cfg.actor_trust = vec![spiffe_entry(
            "https://spire.example.org/bundle".into(),
            Some(path.clone()),
        )];
        let err = attenuo_server::build(&cfg).err().expect("must not start");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("[[actor_trust]] `spiffe://example.org`"),
            "{msg}"
        );
        assert!(msg.contains("ca_pem_path"), "{msg}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");
        assert!(msg.contains(want), "{want}: {msg}");

        let mut cfg = base_config();
        cfg.idps = vec![IdpConfig {
            issuer: "https://idp.example".into(),
            audience: String::new(),
            jwks_url: None,
            allowed_algs: vec!["ES256".into()],
            attribute_claims: vec![],
            jwks_ttl_seconds: 300,
            clock_skew_seconds: 60,
            tenant: None,
            id_jag_ceiling: None,
            credentials: attenuo_server::config::DEFAULT_IDP_CREDENTIALS.to_vec(),
            ca_pem_path: Some(path.clone()),
            client_ids: BTreeMap::new(),
        }];
        let err = attenuo_server::build(&cfg).err().expect("must not start");
        let msg = format!("{err:#}");
        assert!(msg.contains("[[idps]] `https://idp.example`"), "{msg}");
        assert!(msg.contains("ca_pem_path"), "{msg}");
        assert!(msg.contains(want), "{want}: {msg}");
    }
}

/// The key parses from TOML under its documented name.
#[test]
fn ca_pem_path_parses_from_toml() {
    let cfg = Config::from_toml(
        r#"
[[idps]]
issuer = "https://idp.example"
ca_pem_path = "/etc/attenuo/idp-ca.pem"

[[actor_trust]]
spiffe_trust_domain = "example.org"
spiffe_bundle_url = "https://spire.example.org:8443"
audience = "https://attenuo.example"
ca_pem_path = "spire-ca.pem"
"#,
    )
    .unwrap();
    assert_eq!(
        cfg.idps[0].ca_pem_path.as_deref(),
        Some(Path::new("/etc/attenuo/idp-ca.pem"))
    );
    assert_eq!(
        cfg.actor_trust[0].ca_pem_path.as_deref(),
        Some(Path::new("spire-ca.pem"))
    );
}
