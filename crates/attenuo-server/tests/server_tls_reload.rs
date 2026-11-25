//! `POST /admin/tls/reload` and the TLS series of `/metrics`, with real handshakes through
//! [`attenuo_server::run`], the code `serve` runs.
//!
//! Covers: a reload puts the new certificate in force for new connections while a kept-alive
//! connection goes on with the old one; every refusal (files that cannot be read or used, a
//! key of another certificate, an empty chain, a key file open to others, an expired or not yet
//! valid certificate) keeps the old certificate serving, is audited and counted; wrong admin
//! credentials; a server without `[server.tls]`; concurrent reloads and handshakes during
//! reloads; the handshake failure counter by reason; the certificate's `notAfter` gauge.

// Configs are built field by field, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use attenuo_core::ToolCall;
use attenuo_server::config::{AdminOperator, ClientCertificates, ServerTlsSection};
use attenuo_server::operators::AdminRole;
use attenuo_server::Config;
use common::tls::{Ca, ClientCert};
use common::{sha256_hex, wait_for, Running};
use reqwest::StatusCode;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ADMIN: &str = "tls-reload-test-admin-token-0123456789abcdef";
const VIEWER: &str = "tls-reload-test-viewer-token-0123456789abcdef";
const PUBLIC_URL: &str = "https://localhost:8443";
const TOOL: &str = "admin.tls.reload";
const DAY: time::Duration = time::Duration::days(1);

fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

/// A server with `[server.tls]` whose files are `dir/server.crt` and `dir/server.key`, issued
/// by `ca`.
struct Server {
    dir: tempfile::TempDir,
    ca: Ca,
    running: Running,
    state: Arc<attenuo_server::AppState>,
}

impl Server {
    async fn start(client_certificates: ClientCertificates, header_read_timeout: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::new("tls-reload test CA");
        let (cert, key) = ca.write_server_files(dir.path(), &["127.0.0.1"]);
        let mut cfg = base_config(dir.path(), header_read_timeout);
        cfg.server.public_url = Some(PUBLIC_URL.into());
        cfg.server.tls = Some(ServerTlsSection {
            cert_pem_path: cert,
            key_pem_path: key,
            client_certificates,
        });
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let running = Running::start(cfg, state.clone(), router).await;
        Self {
            dir,
            ca,
            running,
            state,
        }
    }

    async fn stop(self) {
        self.running.stop(self.state).await;
    }

    fn cert_path(&self) -> PathBuf {
        self.dir.path().join("server.crt")
    }

    fn key_path(&self) -> PathBuf {
        self.dir.path().join("server.key")
    }

    /// Write a new certificate (made with `edit`) and its key over the files.
    fn renew(&self, edit: impl FnOnce(&mut rcgen::CertificateParams)) -> CertificateDer<'static> {
        self.ca
            .write_server_files_with(self.dir.path(), &["127.0.0.1"], edit);
        file_leaf(&self.cert_path())
    }

    /// `POST /admin/tls/reload` with `bearer`, on a new connection.
    async fn reload_as(&self, bearer: Option<&str>) -> (StatusCode, Value) {
        let mut req = self
            .ca
            .reqwest_client(None)
            .post(self.running.https_url("/admin/tls/reload"));
        if let Some(b) = bearer {
            req = req.bearer_auth(b);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn reload(&self) -> (StatusCode, Value) {
        self.reload_as(Some(ADMIN)).await
    }

    /// The first certificate the server sends on a new connection.
    async fn served_leaf(&self) -> CertificateDer<'static> {
        let stream = connect(&self.ca, self.running.addr()).await.unwrap();
        leaf_of(&stream)
    }

    /// The value of the series `line` (name and labels) in `/metrics`.
    fn metric(&self, line: &str) -> u64 {
        metric(&self.state.metrics.render(), line)
    }

    /// The audit records of `admin.tls.reload`, oldest first.
    async fn reload_records(&self) -> Vec<Value> {
        let resp = self
            .ca
            .reqwest_client(None)
            .get(self.running.https_url("/admin/audit?from=1&limit=1000"))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["record"].clone())
            .filter(|r| r["tool"] == TOOL)
            .collect()
    }
}

fn base_config(dir: &Path, header_read_timeout: u64) -> Config {
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir.join("audit.sqlite").to_string_lossy().into_owned();
    cfg.admin.token = Some(ADMIN.into());
    cfg.admin.operators = vec![AdminOperator {
        name: "watcher".into(),
        token_sha256: sha256_hex(VIEWER),
        role: AdminRole::Viewer,
        expires_at: None,
    }];
    cfg.limits.header_read_timeout_seconds = header_read_timeout;
    cfg
}

/// The first certificate of a PEM file.
fn file_leaf(path: &Path) -> CertificateDer<'static> {
    let pem = std::fs::read(path).unwrap();
    CertificateDer::pem_slice_iter(&pem)
        .next()
        .unwrap()
        .unwrap()
}

/// The server's first certificate on `stream`.
fn leaf_of(
    stream: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> CertificateDer<'static> {
    stream.get_ref().1.peer_certificates().unwrap()[0]
        .clone()
        .into_owned()
}

/// A TLS 1.3 connection that trusts `ca` only, offering `http/1.1`.
async fn connect(
    ca: &Ca,
    addr: std::net::SocketAddr,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    connect_with(
        ca.rustls_client(&[&rustls::version::TLS13], &[b"http/1.1"]),
        addr,
    )
    .await
}

async fn connect_with(
    config: rustls::ClientConfig,
    addr: std::net::SocketAddr,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    connector.connect(name, tcp).await
}

/// One `GET path` on a kept-alive `stream`; the response head and body, read by its
/// `Content-Length`.
async fn get_on<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    path: &str,
) -> String {
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "closed before a full response: {buf:?}");
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let len = text[..end]
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return text;
            }
        }
    }
}

/// The value of the series `line` (its name and labels, exactly as rendered) in `text`.
fn metric(text: &str, line: &str) -> u64 {
    text.lines()
        .find_map(|l| l.strip_prefix(line).and_then(|v| v.strip_prefix(' ')))
        .unwrap_or_else(|| panic!("no {line} in:\n{text}"))
        .parse()
        .unwrap()
}

fn reloads(result: &str) -> String {
    format!("attenuo_tls_certificate_reloads_total{{result=\"{result}\"}}")
}

fn failures(reason: &str) -> String {
    format!("attenuo_tls_handshake_failures_total{{reason=\"{reason}\"}}")
}

const NOT_AFTER: &str = "attenuo_tls_certificate_not_after_timestamp_seconds";

/// A reload puts the new certificate in force for new connections: a connection kept alive
/// from before goes on with the old one, and answers. The answer, the audit record, the gauge
/// and the reload counter say what changed; the same files again change nothing.
#[tokio::test]
async fn a_reload_serves_the_new_certificate_to_new_connections() {
    let s = Server::start(ClientCertificates::Optional, 10).await;
    let old = s.served_leaf().await;
    assert_eq!(old, file_leaf(&s.cert_path()));
    assert!(s.metric(NOT_AFTER) > 0);

    // Kept alive across the reload.
    let mut kept = connect(&s.ca, s.running.addr()).await.unwrap();
    assert!(get_on(&mut kept, "/healthz")
        .await
        .starts_with("HTTP/1.1 200"));

    let until = (now() + time::Duration::days(40))
        .replace_nanosecond(0)
        .unwrap();
    let new = s.renew(|p| {
        p.not_before = now() - DAY;
        p.not_after = until;
    });
    assert_ne!(new, old);
    // Written but not reloaded: still the old one.
    assert_eq!(s.served_leaf().await, old);

    let (status, v) = s.reload().await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let hex = |c: &CertificateDer| {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(c.as_ref()))
    };
    assert_eq!(v["changed"], true, "{v}");
    assert_eq!(v["certificate_sha256"], hex(&new), "{v}");
    assert_eq!(v["previous_certificate_sha256"], hex(&old), "{v}");
    assert_eq!(v["chain_length"], 2, "{v}");
    assert_eq!(
        v["not_after"],
        until
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        "{v}"
    );
    assert!(v["audit_id"].as_str().is_some(), "{v}");
    // No key, no path in the answer.
    let text = v.to_string();
    assert!(!text.contains("PRIVATE"), "{text}");
    assert!(!text.contains(s.dir.path().to_str().unwrap()), "{text}");

    // New connections get the new certificate, through reqwest too.
    assert_eq!(s.served_leaf().await, new);
    let resp =
        s.ca.reqwest_client(None)
            .get(s.running.https_url("/healthz"))
            .send()
            .await
            .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // The kept-alive connection still has the old certificate, and is still served.
    assert_eq!(leaf_of(&kept), old);
    assert!(get_on(&mut kept, "/healthz")
        .await
        .starts_with("HTTP/1.1 200"));
    // The settings stay: TLS 1.3, http/1.1, no session ticket.
    let stream = connect(&s.ca, s.running.addr()).await.unwrap();
    let (_, conn) = stream.get_ref();
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(conn.alpn_protocol(), Some(&b"http/1.1"[..]));
    let old_client = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(s.ca.reqwest_root())
        .max_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .unwrap();
    assert!(old_client
        .get(s.running.https_url("/healthz"))
        .send()
        .await
        .is_err());

    assert_eq!(
        s.metric(NOT_AFTER),
        u64::try_from(until.unix_timestamp()).unwrap()
    );
    assert_eq!(s.metric(&reloads("ok")), 1);
    assert_eq!(s.metric(&reloads("failed")), 0);

    // The same files again: allowed, nothing changes.
    let (status, again) = s.reload().await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["changed"], false, "{again}");
    assert_eq!(again["certificate_sha256"], hex(&new), "{again}");
    assert_eq!(s.metric(&reloads("ok")), 2);

    // Audited as allow, with the paths and digests in the digested arguments.
    let records = s.reload_records().await;
    assert_eq!(records.len(), 2, "{records:?}");
    let r = &records[0];
    assert_eq!(r["decision"], "allow", "{r}");
    assert_eq!(r["reason"], "admin_action", "{r}");
    let args = json!({
        "cert_pem_path": s.cert_path(),
        "key_pem_path": s.key_path(),
        "changed": true,
        "certificate_sha256": hex(&new),
        "previous_certificate_sha256": hex(&old),
        "not_before": v["not_before"],
        "not_after": v["not_after"],
        "chain_length": 2,
    });
    assert_eq!(
        r["arguments_digest"],
        ToolCall::new("attenuo", TOOL, args).arguments_digest(),
        "{r}"
    );
    s.stop().await;
}

/// Every refusal names the problem by its code, never the path or a key's text, keeps the old
/// certificate serving, is audited as a deny with the code as its reason, and is counted as
/// `failed`. Good files afterwards reload.
#[tokio::test]
async fn every_refusal_keeps_the_old_certificate() {
    let s = Server::start(ClientCertificates::Off, 10).await;
    let old = s.served_leaf().await;
    let (good_cert, good_key) = (
        std::fs::read_to_string(s.cert_path()).unwrap(),
        std::fs::read_to_string(s.key_path()).unwrap(),
    );
    let other = tempfile::tempdir().unwrap();
    let (_, other_key) = s.ca.write_server_files(other.path(), &["127.0.0.1"]);
    let other_key = std::fs::read_to_string(other_key).unwrap();
    let restore = || {
        std::fs::write(s.cert_path(), &good_cert).unwrap();
        std::fs::write(s.key_path(), &good_key).unwrap();
        set_mode(&s.key_path(), 0o600);
    };
    // The secret part of a key, which no answer may quote.
    let key_body: String = good_key
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();

    type Breaker<'a> = Box<dyn Fn(&Server) + 'a>;
    let cases: Vec<(&str, &str, Breaker)> = vec![
        (
            "missing key file",
            "tls_file_unreadable",
            Box::new(|s: &Server| std::fs::remove_file(s.key_path()).unwrap()),
        ),
        (
            "missing certificate file",
            "tls_file_unreadable",
            Box::new(|s: &Server| std::fs::remove_file(s.cert_path()).unwrap()),
        ),
        (
            "certificate is a directory",
            "tls_file_unreadable",
            Box::new(|s: &Server| {
                std::fs::remove_file(s.cert_path()).unwrap();
                std::fs::create_dir(s.cert_path()).unwrap();
            }),
        ),
        (
            "empty chain",
            "tls_file_invalid",
            Box::new(|s: &Server| std::fs::write(s.cert_path(), "").unwrap()),
        ),
        (
            "certificate does not parse",
            "tls_file_invalid",
            Box::new(|s: &Server| {
                std::fs::write(
                    s.cert_path(),
                    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
                )
                .unwrap()
            }),
        ),
        (
            "not PEM",
            "tls_file_invalid",
            Box::new(|s: &Server| std::fs::write(s.cert_path(), "hello\n").unwrap()),
        ),
        (
            "key does not parse",
            "tls_file_invalid",
            Box::new(|s: &Server| {
                let broken = good_key.replacen(&key_body[10..20], "**********", 1);
                std::fs::write(s.key_path(), broken).unwrap()
            }),
        ),
        (
            "key of another certificate",
            "tls_key_mismatch",
            Box::new(|s: &Server| std::fs::write(s.key_path(), &other_key).unwrap()),
        ),
        (
            "key in the certificate file",
            "tls_file_invalid",
            Box::new(|s: &Server| {
                std::fs::write(s.cert_path(), format!("{good_cert}{good_key}")).unwrap()
            }),
        ),
        (
            "expired certificate",
            "tls_certificate_expired",
            Box::new(|s: &Server| {
                s.renew(|p| {
                    p.not_before = now() - time::Duration::days(30);
                    p.not_after = now() - DAY;
                });
            }),
        ),
        (
            "certificate not valid yet",
            "tls_certificate_not_yet_valid",
            Box::new(|s: &Server| {
                s.renew(|p| {
                    p.not_before = now() + DAY;
                    p.not_after = now() + time::Duration::days(30);
                });
            }),
        ),
        (
            "more than ten certificates",
            "tls_file_invalid",
            Box::new(|s: &Server| {
                let leaf = good_cert
                    .split_inclusive("-----END CERTIFICATE-----\n")
                    .next();
                let text = format!("{good_cert}{}", leaf.unwrap().repeat(9));
                std::fs::write(s.cert_path(), text).unwrap()
            }),
        ),
        (
            "a CA certificate first",
            "tls_file_invalid",
            Box::new(|s: &Server| {
                s.renew(|p| p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained));
            }),
        ),
        (
            "a second, encrypted key",
            "tls_file_invalid",
            Box::new(|s: &Server| {
                let encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n\
                                 -----END ENCRYPTED PRIVATE KEY-----\n";
                std::fs::write(s.key_path(), format!("{good_key}{encrypted}")).unwrap()
            }),
        ),
    ];
    #[cfg(unix)]
    let cases = {
        let mut cases = cases;
        cases.push((
            "key file readable by others",
            "tls_file_unreadable",
            Box::new(|s: &Server| set_mode(&s.key_path(), 0o644)),
        ));
        cases
    };
    let mut codes = Vec::new();
    for (i, (name, code, breaker)) in cases.iter().enumerate() {
        breaker(&s);
        let (status, v) = s.reload().await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{name}: {v}");
        assert_eq!(v["code"], *code, "{name}: {v}");
        assert_eq!(v["error"], *code, "{name}: {v}");
        let detail = v["detail"].as_str().unwrap();
        assert!(detail.starts_with("[server.tls] "), "{name}: {detail}");
        assert!(
            detail.ends_with("the certificate in force is unchanged"),
            "{name}: {detail}"
        );
        assert!(
            !detail.contains(s.dir.path().to_str().unwrap()),
            "{name}: {detail}"
        );
        assert!(!detail.contains("PRIVATE KEY-"), "{name}: {detail}");
        for i in 0..key_body.len().saturating_sub(8) {
            assert!(!detail.contains(&key_body[i..i + 8]), "{name}: {detail}");
        }
        // The old certificate still serves.
        assert_eq!(s.served_leaf().await, old, "{name}");
        assert_eq!(
            s.metric(&reloads("failed")),
            u64::try_from(i + 1).unwrap(),
            "{name}"
        );
        codes.push(*code);
        if std::fs::metadata(s.cert_path()).is_ok_and(|m| m.is_dir()) {
            std::fs::remove_dir(s.cert_path()).unwrap();
        }
        restore();
    }
    assert_eq!(s.metric(&reloads("ok")), 0);
    // Each refusal is audited as a deny with its code.
    let records = s.reload_records().await;
    let reasons: Vec<&str> = records
        .iter()
        .map(|r| {
            assert_eq!(r["decision"], "deny", "{r}");
            r["reason"].as_str().unwrap()
        })
        .collect();
    assert_eq!(reasons, codes);
    // Good files reload: the old certificate's files, so nothing changes.
    let (status, v) = s.reload().await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["changed"], false, "{v}");
    assert_eq!(s.served_leaf().await, old);
    s.stop().await;
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

/// No bearer, a wrong one and a viewer's are refused before the files are read: nothing
/// changes, nothing is counted.
#[tokio::test]
async fn wrong_admin_credentials_are_refused() {
    let s = Server::start(ClientCertificates::Off, 10).await;
    let old = s.served_leaf().await;
    s.renew(|_| {});
    for (bearer, status, code) in [
        (None, StatusCode::UNAUTHORIZED, None),
        (
            Some("not-the-admin-token-0123456789abcdef"),
            StatusCode::UNAUTHORIZED,
            None,
        ),
        (
            Some(VIEWER),
            StatusCode::FORBIDDEN,
            Some("admin_role_insufficient"),
        ),
    ] {
        let (got, v) = s.reload_as(bearer).await;
        assert_eq!(got, status, "{bearer:?}: {v}");
        if let Some(code) = code {
            assert_eq!(v["code"], code, "{v}");
        }
        assert_eq!(s.served_leaf().await, old);
    }
    assert_eq!(s.metric(&reloads("ok")), 0);
    assert_eq!(s.metric(&reloads("failed")), 0);
    assert!(s.reload_records().await.is_empty());
    // The admin's own reload then works.
    let (got, v) = s.reload().await;
    assert_eq!(got, StatusCode::OK, "{v}");
    assert_ne!(s.served_leaf().await, old);
    s.stop().await;
}

/// Without `[server.tls]` there is nothing to reload: 409 `reload_unavailable`, not counted.
#[tokio::test]
async fn without_server_tls_a_reload_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = base_config(dir.path(), 10);
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let running = Running::start(cfg, state.clone(), router).await;
    let resp = reqwest::Client::new()
        .post(running.url("/admin/tls/reload"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["code"], "reload_unavailable", "{v}");
    let text = state.metrics.render();
    assert_eq!(metric(&text, &reloads("ok")), 0);
    assert_eq!(metric(&text, &reloads("failed")), 0);
    assert_eq!(metric(&text, NOT_AFTER), 0);
    running.stop(state).await;
}

/// Handshakes go on while the certificate is reloaded again and again: every one succeeds
/// (the client checks the certificate against the CA and the server proves its key, so a
/// handshake that mixed one chain with another key would fail), and each gets one of the
/// certificates written. Concurrent reloads are serialised: of a burst over the same files,
/// exactly one reports a change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reloads_and_handshakes_run_concurrently() {
    let s = Arc::new(Server::start(ClientCertificates::Optional, 10).await);
    let mut written = vec![s.served_leaf().await];
    let stop = Arc::new(AtomicBool::new(false));
    let mut clients = Vec::new();
    for _ in 0..4 {
        let (s, stop) = (s.clone(), stop.clone());
        clients.push(tokio::spawn(async move {
            let mut seen = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let mut stream = connect(&s.ca, s.running.addr())
                    .await
                    .expect("a handshake during a reload failed");
                seen.push(leaf_of(&stream));
                assert!(get_on(&mut stream, "/healthz")
                    .await
                    .starts_with("HTTP/1.1 200"));
            }
            seen
        }));
    }
    for _ in 0..8 {
        written.push(s.renew(|_| {}));
        let (status, v) = s.reload().await;
        assert_eq!(status, StatusCode::OK, "{v}");
        assert_eq!(v["changed"], true, "{v}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // A burst of reloads over the same new files.
    written.push(s.renew(|_| {}));
    let burst: Vec<_> = (0..8)
        .map(|_| {
            let s = s.clone();
            tokio::spawn(async move { s.reload().await })
        })
        .collect();
    let mut changed = 0;
    for r in burst {
        let (status, v) = r.await.unwrap();
        assert_eq!(status, StatusCode::OK, "{v}");
        changed += usize::from(v["changed"] == true);
    }
    assert_eq!(
        changed, 1,
        "one reload of the burst puts the files in force"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    stop.store(true, Ordering::Relaxed);
    let mut handshakes = 0;
    for c in clients {
        for leaf in c.await.unwrap() {
            assert!(
                written.contains(&leaf),
                "a certificate that was never written"
            );
            handshakes += 1;
        }
    }
    assert!(handshakes > 0);
    assert_eq!(s.served_leaf().await, *written.last().unwrap());
    assert_eq!(s.metric(&reloads("ok")), 16);
    // No handshake failed.
    for reason in [
        "bad_client_certificate",
        "protocol",
        "peer_alert",
        "timeout",
        "other",
    ] {
        assert_eq!(s.metric(&failures(reason)), 0, "{reason}");
    }
    let s = Arc::try_unwrap(s).ok().unwrap();
    s.stop().await;
}

/// Each kind of failed handshake is counted under its reason, and only there; no series is
/// added and no peer address appears.
#[tokio::test]
async fn handshake_failures_are_counted_by_reason() {
    let s = Server::start(ClientCertificates::Optional, 1).await;
    let addr = s.running.addr();
    let all = [
        "bad_client_certificate",
        "protocol",
        "peer_alert",
        "timeout",
        "other",
    ];
    let mut want = std::collections::BTreeMap::from(all.map(|r| (r, 0u64)));
    let metrics = s.state.metrics.clone();
    let check = |want: &std::collections::BTreeMap<&'static str, u64>| {
        let (want, metrics) = (want.clone(), metrics.clone());
        async move {
            wait_for(|| {
                let text = metrics.render();
                want.iter().all(|(r, n)| metric(&text, &failures(r)) == *n)
            })
            .await;
        }
    };

    // A plain-HTTP request on the TLS port.
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut sink)).await;
    *want.get_mut("protocol").unwrap() += 1;
    check(&want).await;

    // A TLS 1.2 client.
    let tls12 =
        s.ca.rustls_client(&[&rustls::version::TLS12], &[b"http/1.1"]);
    assert!(connect_with(tls12, addr).await.is_err());
    *want.get_mut("protocol").unwrap() += 1;
    check(&want).await;

    // A client that offers only h2.
    let h2 = s.ca.rustls_client(&[&rustls::version::TLS13], &[b"h2"]);
    assert!(connect_with(h2, addr).await.is_err());
    *want.get_mut("protocol").unwrap() += 1;
    check(&want).await;

    // A client that does not trust the server's certificate: it ends with an alert.
    let stranger = Ca::new("another CA");
    assert!(connect(&stranger, addr).await.is_err());
    *want.get_mut("peer_alert").unwrap() += 1;
    check(&want).await;

    // A client certificate whose handshake signature is made with another key.
    let (cert, other) = (ClientCert::new("forger"), ClientCert::new("other"));
    let forged = s.ca.rustls_client_with(cert.resolver_signing_with(&other));
    if let Ok(mut stream) = connect_with(forged, addr).await {
        // TLS 1.3: the client may finish before the server has checked its signature.
        let _ = stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            .await;
        let mut sink = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut sink)).await;
    }
    *want.get_mut("bad_client_certificate").unwrap() += 1;
    check(&want).await;

    // A peer that connects and sends nothing: dropped at the header-read timeout (1 s).
    let silent = tokio::net::TcpStream::connect(addr).await.unwrap();
    *want.get_mut("timeout").unwrap() += 1;
    check(&want).await;
    drop(silent);

    // A peer that sends half a ClientHello and closes.
    let mut half = tokio::net::TcpStream::connect(addr).await.unwrap();
    half.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01])
        .await
        .unwrap();
    drop(half);
    *want.get_mut("other").unwrap() += 1;
    check(&want).await;

    // A good client is not counted, and is served.
    let mut good = connect(&s.ca, addr).await.unwrap();
    assert!(get_on(&mut good, "/healthz")
        .await
        .starts_with("HTTP/1.1 200"));
    drop(good);
    check(&want).await;

    // Five series, fixed labels, no address.
    let text = s.state.metrics.render();
    let series: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("attenuo_tls_handshake_failures_total{"))
        .collect();
    assert_eq!(series.len(), 5, "{series:?}");
    assert!(!text.contains("127.0.0.1"), "an address in the metrics");
    s.stop().await;
}

/// When the audit record of a reload cannot be appended, nothing is swapped: the old
/// certificate keeps serving, the answer is a 500 and the reload counts as `failed`. Once the
/// log takes appends again, the same files reload.
#[tokio::test]
async fn a_reload_that_cannot_be_audited_changes_nothing() {
    let s = Server::start(ClientCertificates::Off, 10).await;
    let old = s.served_leaf().await;
    let not_after = s.metric(NOT_AFTER);
    let new = s.renew(|p| {
        p.not_before = now() - DAY;
        p.not_after = now() + time::Duration::days(30);
    });
    // Every insert into the log fails, as on a full disk.
    s.state
        .audit
        .with_connection(|c| {
            c.execute_batch(
                "CREATE TRIGGER full_disk BEFORE INSERT ON audit \
                 BEGIN SELECT RAISE(FAIL, 'database or disk is full'); END;",
            )?;
            Ok(())
        })
        .unwrap();
    let (status, v) = s.reload().await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    assert_eq!(s.served_leaf().await, old);
    assert_eq!(s.metric(NOT_AFTER), not_after);
    assert_eq!(s.metric(&reloads("failed")), 1);
    assert_eq!(s.metric(&reloads("ok")), 0);

    s.state
        .audit
        .with_connection(|c| {
            c.execute_batch("DROP TRIGGER full_disk")?;
            Ok(())
        })
        .unwrap();
    let (status, v) = s.reload().await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(s.served_leaf().await, new);
    let records = s.reload_records().await;
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["decision"], "allow");
    s.stop().await;
}

/// A reload whose client goes away before the answer still ends as one unit: the audit
/// record and the swap both happen, after the client left. The audit log is held busy so
/// that the reload is stopped between its checks and its record while the client gives up.
#[tokio::test]
async fn a_reload_finishes_when_the_client_goes_away() {
    let s = Server::start(ClientCertificates::Off, 10).await;
    let old = s.served_leaf().await;
    let new = s.renew(|p| {
        p.not_before = now() - DAY;
        p.not_after = now() + time::Duration::days(30);
    });
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let state = s.state.clone();
    let holder = std::thread::spawn(move || {
        state
            .audit
            .with_connection(|_| {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
    });
    held_rx.recv().unwrap();
    let gone =
        s.ca.reqwest_client(None)
            .post(s.running.https_url("/admin/tls/reload"))
            .bearer_auth(ADMIN)
            .timeout(Duration::from_millis(500))
            .send()
            .await;
    assert!(gone.is_err(), "{gone:?}");
    // The client is gone; the reload waits on the log, so nothing is in force yet.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(s.served_leaf().await, old);
    assert_eq!(s.metric(&reloads("ok")), 0);

    release_tx.send(()).unwrap();
    holder.join().unwrap();
    let end = std::time::Instant::now() + Duration::from_secs(20);
    while s.served_leaf().await != new {
        assert!(std::time::Instant::now() < end, "the reload never finished");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(s.metric(&reloads("ok")), 1);
    let records = s.reload_records().await;
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["decision"], "allow");
    s.stop().await;
}

/// Reloads that wait behind a running one hold no thread and are dropped when their clients
/// give up: once the running one ends, none of them runs. Only the started reload is counted
/// and audited.
#[tokio::test]
async fn reloads_whose_clients_gave_up_while_waiting_never_run() {
    let s = Server::start(ClientCertificates::Off, 10).await;
    let new = s.renew(|p| {
        p.not_before = now() - DAY;
        p.not_after = now() + time::Duration::days(30);
    });
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let state = s.state.clone();
    let holder = std::thread::spawn(move || {
        state
            .audit
            .with_connection(|_| {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
    });
    held_rx.recv().unwrap();
    let give_up = |ms: u64| {
        s.ca.reqwest_client(None)
            .post(s.running.https_url("/admin/tls/reload"))
            .bearer_auth(ADMIN)
            .timeout(Duration::from_millis(ms))
            .send()
    };
    // The first one starts and waits on the audit log, holding the reload lock.
    assert!(give_up(500).await.is_err());
    // These wait on the lock, and their clients give up.
    let waiting: Vec<_> = (0..8).map(|_| give_up(300)).collect();
    for r in futures_util::future::join_all(waiting).await {
        assert!(r.is_err(), "{r:?}");
    }
    // Time for the server to see the closed connections.
    tokio::time::sleep(Duration::from_millis(300)).await;

    release_tx.send(()).unwrap();
    holder.join().unwrap();
    let end = std::time::Instant::now() + Duration::from_secs(20);
    while s.served_leaf().await != new {
        assert!(
            std::time::Instant::now() < end,
            "the started reload never finished"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Time for any reload still queued to run, if one were.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(s.metric(&reloads("ok")), 1);
    assert_eq!(s.metric(&reloads("failed")), 0);
    let records = s.reload_records().await;
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["decision"], "allow");
    s.stop().await;
}

/// A client session store that counts the tickets it is given.
#[derive(Debug)]
struct CountingStore {
    inner: rustls::client::ClientSessionMemoryCache,
    tickets: std::sync::atomic::AtomicUsize,
}

impl rustls::client::ClientSessionStore for CountingStore {
    fn set_kx_hint(&self, name: rustls::pki_types::ServerName<'static>, g: rustls::NamedGroup) {
        self.inner.set_kx_hint(name, g);
    }
    fn kx_hint(&self, name: &rustls::pki_types::ServerName<'_>) -> Option<rustls::NamedGroup> {
        self.inner.kx_hint(name)
    }
    fn set_tls12_session(
        &self,
        name: rustls::pki_types::ServerName<'static>,
        value: rustls::client::Tls12ClientSessionValue,
    ) {
        self.inner.set_tls12_session(name, value);
    }
    fn tls12_session(
        &self,
        name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        self.inner.tls12_session(name)
    }
    fn remove_tls12_session(&self, name: &rustls::pki_types::ServerName<'static>) {
        self.inner.remove_tls12_session(name);
    }
    fn insert_tls13_ticket(
        &self,
        name: rustls::pki_types::ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.tickets.fetch_add(1, Ordering::SeqCst);
        self.inner.insert_tls13_ticket(name, value);
    }
    fn take_tls13_ticket(
        &self,
        name: &rustls::pki_types::ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        self.inner.take_tls13_ticket(name)
    }
}

/// After a reload, as before it, the server sends no session ticket, and a client that keeps
/// sessions makes a full handshake on every connection.
#[tokio::test]
async fn a_reloaded_configuration_resumes_no_session() {
    let s = Server::start(ClientCertificates::Optional, 10).await;
    let new = s.renew(|p| {
        p.not_before = now() - DAY;
        p.not_after = now() + time::Duration::days(30);
    });
    let (status, v) = s.reload().await;
    assert_eq!(status, StatusCode::OK, "{v}");

    let store = Arc::new(CountingStore {
        inner: rustls::client::ClientSessionMemoryCache::new(16),
        tickets: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut config =
        s.ca.rustls_client(&[&rustls::version::TLS13], &[b"http/1.1"]);
    config.resumption = rustls::client::Resumption::store(store.clone());
    let config = Arc::new(config);
    for _ in 0..3 {
        let connector = tokio_rustls::TlsConnector::from(config.clone());
        let tcp = tokio::net::TcpStream::connect(s.running.addr())
            .await
            .unwrap();
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        let mut stream = connector.connect(name, tcp).await.unwrap();
        // A request and its answer, so that any ticket sent after the handshake is read.
        assert!(get_on(&mut stream, "/healthz")
            .await
            .starts_with("HTTP/1.1 200"));
        assert_eq!(leaf_of(&stream), new);
        assert_eq!(
            stream.get_ref().1.handshake_kind(),
            Some(rustls::HandshakeKind::Full)
        );
    }
    assert_eq!(
        store.tickets.load(Ordering::SeqCst),
        0,
        "a session ticket was sent"
    );
    s.stop().await;
}
