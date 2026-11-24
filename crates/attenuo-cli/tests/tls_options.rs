//! `--tls-ca-cert`, `--tls-client-cert` and `--tls-client-key` with the real binary: against a
//! real server with `[server.tls]` and `client_certificates = "optional"` (an agent pinned by
//! its certificate's thumbprint), and against a small TLS server that records which client
//! certificate each request came with, for `--admin-server` and `attenuo connect`.

// Configs are written as TOML and loaded, as in the server's TLS tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

// The server tests' CA and certificate helpers.
#[allow(dead_code)]
#[path = "../../attenuo-server/tests/common/tls.rs"]
mod server_tls;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

use attenuo_server::Config;
use serde_json::Value;
use server_tls::{Ca, ClientCert};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{attenuo, sha256_hex};

const ADMIN: &str = "tls-options-test-admin-token-0123456789";

async fn run(mut cmd: Command) -> Output {
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

fn ok(out: &Output) -> String {
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    text(&out.stdout)
}

/// Exit 1 with an error on stderr, never a panic.
fn failed(out: &Output) -> String {
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(err.starts_with("error: "), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    err
}

/// Write `cert` and its key as PEM files into `dir`, the key with mode 0600.
fn write_client(dir: &Path, cert: &ClientCert, name: &str) -> (PathBuf, PathBuf) {
    let c = dir.join(format!("{name}.crt"));
    let k = dir.join(format!("{name}.key"));
    std::fs::write(&c, &cert.cert_pem).unwrap();
    std::fs::write(&k, &cert.key_pem).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (c, k)
}

/// A real server with `[server.tls]` and `client_certificates = "optional"`, run through
/// `attenuo_server::run` on a listener bound first. Agent `coder` is pinned to `coder`'s
/// certificate; `reviewer` has a secret.
struct TlsServer {
    dir: tempfile::TempDir,
    url: String,
    ca_path: PathBuf,
    coder: (PathBuf, PathBuf),
    stranger: (PathBuf, PathBuf),
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl TlsServer {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::new("cli tls test CA");
        let ca_path = ca.write(dir.path(), "ca.pem");
        let (cert, key) = ca.write_server_files(dir.path(), &["127.0.0.1"]);
        let coder_cert = ClientCert::new("coder");
        let coder = write_client(dir.path(), &coder_cert, "coder");
        let stranger = write_client(dir.path(), &ClientCert::new("stranger"), "stranger");
        let path = dir.path().join("attenuo.toml");
        std::fs::write(
            &path,
            format!(
                "[server]\npublic_url = \"https://localhost:8443\"\n\n\
                 [server.tls]\ncert_pem_path = \"{}\"\nkey_pem_path = \"{}\"\n\
                 client_certificates = \"optional\"\n\n\
                 [issuer]\nissuer = \"https://attenuo.test\"\nprivate_key_pem_path = \"{}\"\n\n\
                 [audit]\nsqlite_path = \"{}\"\n\n\
                 [admin]\ntoken = \"{ADMIN}\"\n\n\
                 [dev]\nallow_root_mint = true\n\n\
                 [[agents]]\nid = \"coder\"\ntls_client_cert_sha256 = [\"{}\"]\n\n\
                 [[agents]]\nid = \"reviewer\"\nsecret_sha256 = \"{}\"\n",
                cert.display(),
                key.display(),
                dir.path().join("keys/issuer.pem").display(),
                dir.path().join("audit.sqlite").display(),
                coder_cert.sha256_hex(),
                sha256_hex("reviewer-secret"),
            ),
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        // Bound before the server runs, so the port is never released in between.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}", listener.local_addr().unwrap());
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            attenuo_server::run(&cfg, state, router, listener, async move {
                let _ = stopped.await;
            })
            .await
        });
        Self {
            dir,
            url,
            ca_path,
            coder,
            stranger,
            stop: Some(stop),
            task,
        }
    }

    /// `attenuo --server <url> <args>`.
    fn cli(&self, args: &[&str]) -> Command {
        let mut c = attenuo();
        c.args(["--server", &self.url]).args(args);
        c
    }

    fn ca(&self) -> &str {
        self.ca_path.to_str().unwrap()
    }

    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(30), self.task).await;
        drop(self.dir);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn health_needs_the_ca_of_a_private_ca_server() {
    let s = TlsServer::start().await;

    // With the CA: healthy, by flag and by environment variable.
    let out = run(s.cli(&["--tls-ca-cert", s.ca(), "health"])).await;
    assert_eq!(
        ok(&out).trim(),
        format!("ok (attenuo-server {})", env!("CARGO_PKG_VERSION"))
    );
    let mut c = s.cli(&["health"]);
    c.env("ATTENUO_TLS_CA_CERT", s.ca());
    ok(&run(c).await);
    // After the subcommand too (a global option).
    ok(&run(s.cli(&["health", "--tls-ca-cert", s.ca()])).await);

    // Without it, the built-in public roots are used, as before, and they do not have this
    // CA: a certificate error, exit 1.
    let err = failed(&run(s.cli(&["health"])).await);
    assert!(err.contains("could not reach the server"), "{err}");
    assert!(err.to_lowercase().contains("certificate"), "{err}");
    // An empty environment variable is unset, so the same.
    let mut c = s.cli(&["health"]);
    c.env("ATTENUO_TLS_CA_CERT", "");
    let err = failed(&run(c).await);
    assert!(err.to_lowercase().contains("certificate"), "{err}");

    // Another CA: refused the same way.
    let other = Ca::new("another CA").write(s.dir.path(), "other-ca.pem");
    let err = failed(&run(s.cli(&["--tls-ca-cert", other.to_str().unwrap(), "health"])).await);
    assert!(err.to_lowercase().contains("certificate"), "{err}");

    s.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_authenticates_with_its_client_certificate() {
    let s = TlsServer::start().await;
    let ca = s.ca().to_owned();
    let (coder_cert, coder_key) = (
        s.coder.0.to_str().unwrap().to_owned(),
        s.coder.1.to_str().unwrap().to_owned(),
    );

    // A fresh root token for `planner` for each exchange (a token is exchanged once per
    // actor), over TLS with the CA: an admin request to --server.
    let root = || {
        let mut c = s.cli(&["--tls-ca-cert", &ca, "--json", "token", "root"]);
        c.env("ATTENUO_ADMIN_TOKEN", ADMIN).args([
            "--subject",
            "alice",
            "--agent",
            "planner",
            "--cap",
            "github:*",
        ]);
        c
    };
    let exchange = |root: &Output, extra: &[&str]| {
        let root: Value = serde_json::from_str(&ok(root)).unwrap();
        let mut c = s.cli(&["--tls-ca-cert", &ca]);
        c.env("ATTENUO_TOKEN", root["access_token"].as_str().unwrap())
            .args(extra)
            .args(["--json", "token", "exchange", "--actor", "coder"])
            .args(["--cap", "github:read_file"]);
        c
    };

    // `coder` with its certificate and no secret: the certificate authenticates it.
    let with_cert = [
        "--tls-client-cert",
        coder_cert.as_str(),
        "--tls-client-key",
        coder_key.as_str(),
    ];
    let out = run(exchange(&run(root()).await, &with_cert)).await;
    let child: Value = serde_json::from_str(&ok(&out)).unwrap();
    assert!(child["access_token"].as_str().is_some(), "{child}");

    // The same by environment variables.
    let mut c = exchange(&run(root()).await, &[]);
    c.env("ATTENUO_TLS_CLIENT_CERT", &coder_cert)
        .env("ATTENUO_TLS_CLIENT_KEY", &coder_key);
    ok(&run(c).await);

    // Without the certificate there is nothing to authenticate `coder`.
    let err = failed(&run(exchange(&run(root()).await, &[])).await);
    assert!(err.contains("server answered 401"), "{err}");

    // A certificate that is not pinned for `coder`: refused.
    let stranger = [
        "--tls-client-cert",
        s.stranger.0.to_str().unwrap(),
        "--tls-client-key",
        s.stranger.1.to_str().unwrap(),
    ];
    let err = failed(&run(exchange(&run(root()).await, &stranger)).await);
    assert!(err.contains("client_authentication_failed"), "{err}");

    // `health` with the certificate works too (the server asks, nobody minds).
    ok(&run(s.cli(&[
        "--tls-ca-cert",
        &ca,
        "--tls-client-cert",
        &coder_cert,
        "--tls-client-key",
        &coder_key,
        "health",
    ]))
    .await);

    s.stop().await;
}

/// A certificate without its key, a key without its certificate, and files that cannot be
/// used are refused before anything is sent: the listener named by --server sees no
/// connection.
#[tokio::test(flavor = "multi_thread")]
async fn bad_options_are_refused_before_any_request() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = write_client(dir.path(), &ClientCert::new("coder"), "coder");
    let (_, other_key) = write_client(dir.path(), &ClientCert::new("other"), "other");
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    let garbage = dir.path().join("garbage.key");
    std::fs::write(
        &garbage,
        "-----BEGIN PRIVATE KEY-----TOPSECRETMATERIAL\nnot base64 !!\n",
    )
    .unwrap();
    // Kept open for the whole test, never accepted from: any connection would queue on it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let p = |p: &Path| p.to_str().unwrap().to_owned();

    let cases: Vec<(Vec<String>, &str)> = vec![
        (
            vec!["--tls-client-cert".into(), p(&cert)],
            "--tls-client-cert needs --tls-client-key",
        ),
        (
            vec!["--tls-client-key".into(), p(&key)],
            "--tls-client-key needs --tls-client-cert",
        ),
        (
            vec![
                "--tls-client-cert".into(),
                p(&cert),
                "--tls-client-key".into(),
                p(&dir.path().join("missing.key")),
            ],
            "cannot read --tls-client-key",
        ),
        (
            vec![
                "--tls-client-cert".into(),
                p(&cert),
                "--tls-client-key".into(),
                p(&empty),
            ],
            "is empty",
        ),
        (
            vec![
                "--tls-client-cert".into(),
                p(&cert),
                "--tls-client-key".into(),
                p(&garbage),
            ],
            "is not a readable PEM file",
        ),
        (
            vec![
                "--tls-client-cert".into(),
                p(&cert),
                "--tls-client-key".into(),
                p(&other_key),
            ],
            "is not the private key of the certificate",
        ),
        (vec!["--tls-ca-cert".into(), p(&empty)], "is empty"),
        (vec!["--tls-ca-cert".into(), p(&key)], "holds a private key"),
    ];
    for (args, want) in cases {
        for cmd in [vec!["health"], vec!["policy", "show"]] {
            let mut c = attenuo();
            c.args(["--server", &url]).args(&args).args(&cmd);
            let err = failed(&run(c).await);
            assert!(err.contains(want), "{args:?}: {err}");
            assert!(!err.contains("TOPSECRET"), "{err}");
        }
    }
    // The cert-without-key rule holds for the environment variables too.
    let mut c = attenuo();
    c.args(["--server", &url, "health"])
        .env("ATTENUO_TLS_CLIENT_CERT", &cert);
    let err = failed(&run(c).await);
    assert!(err.contains("needs --tls-client-key"), "{err}");

    // Nothing reached the listener.
    match listener.accept() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("a connection was made: {other:?}"),
    }
}

/// What the recording server saw: the path of each request and the SHA-256 of the client
/// certificate it came with, if any.
type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// A client certificate verifier that asks for a certificate, requires none and accepts any
/// whose handshake signature verifies: so the server can see whether one was sent.
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
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
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

/// An HTTPS server on 127.0.0.1 with a certificate from `ca`, which records each request's
/// path and client certificate and answers `{}`, or a JSON-RPC result for `/mcp/*`.
async fn recording_server(ca: &Ca) -> (String, Seen, tokio::task::JoinHandle<()>) {
    let (cert, key) = ca.leaf(&["127.0.0.1"]);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(Arc::new(AnyClientCert(provider)))
        .with_single_cert(
            vec![cert, ca.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let seen: Seen = Arc::default();
    let s = seen.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, s) = (acceptor.clone(), s.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let peer = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .map(|c| {
                        use sha2::Digest;
                        hex::encode(sha2::Sha256::digest(c.as_ref()))
                    });
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                // The head, then the body by its content-length.
                let head_end = loop {
                    if let Some(i) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&req[..head_end]).to_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                while req.len() < head_end + len {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
                s.lock().unwrap().push((path.clone(), peer));
                let body = if path.starts_with("/mcp/") {
                    r#"{"jsonrpc":"2.0","id":1,"result":{}}"#
                } else {
                    "{}"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (url, seen, task)
}

/// The client certificate goes to --server only: an `/admin/*` request sent to
/// --admin-server carries none, while the CA applies to both. Without --admin-server, the
/// admin request goes to --server, with the certificate.
#[tokio::test(flavor = "multi_thread")]
async fn the_client_certificate_goes_to_server_and_not_to_admin_server() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("recording CA");
    let ca_path = ca.write(dir.path(), "ca.pem");
    let ca_path = ca_path.to_str().unwrap();
    let client = ClientCert::new("coder");
    let (cert, key) = write_client(dir.path(), &client, "coder");
    let (main, main_seen, main_task) = recording_server(&ca).await;
    let (admin, admin_seen, admin_task) = recording_server(&ca).await;
    let flags = [
        "--tls-ca-cert",
        ca_path,
        "--tls-client-cert",
        cert.to_str().unwrap(),
        "--tls-client-key",
        key.to_str().unwrap(),
    ];

    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(["--server", &main, "--admin-server", &admin])
        .args(flags)
        .args(["--json", "policy", "show"]);
    ok(&run(c).await);
    assert_eq!(
        admin_seen.lock().unwrap().clone(),
        vec![("/admin/policies".to_owned(), None)]
    );
    assert!(main_seen.lock().unwrap().is_empty());

    // No --admin-server: `/admin/*` goes to --server, the same host, with the certificate.
    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(["--server", &main])
        .args(flags)
        .args(["--json", "policy", "show"]);
    ok(&run(c).await);
    assert_eq!(
        main_seen.lock().unwrap().clone(),
        vec![("/admin/policies".to_owned(), Some(client.sha256_hex()))]
    );

    // `approval verify --jwks URL`: on the --server origin, the --server client (the CA and
    // the certificate); on another host, the built-in roots (which do not have this CA) and no
    // certificate, so the handshake fails and nothing is recorded.
    let approval = "eyJhbGciOiJFZERTQSJ9.e30.AA";
    let verify = |jwks: String| {
        let mut c = attenuo();
        c.args(["--server", &main])
            .args(flags)
            .args(["approval", "verify", approval, "--jwks", &jwks]);
        c
    };
    let out = run(verify(format!("{main}/jwks"))).await;
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(
        main_seen.lock().unwrap().last().cloned(),
        Some(("/jwks".to_owned(), Some(client.sha256_hex()))),
        "{out:?}"
    );
    let err = failed(&run(verify(format!("{admin}/jwks"))).await);
    assert!(err.contains("fetching the JWKS"), "{err}");
    assert!(err.to_lowercase().contains("certificate"), "{err}");
    assert_eq!(admin_seen.lock().unwrap().len(), 1);

    main_task.abort();
    admin_task.abort();
}

/// `attenuo connect` sends to --server with the CA and the client certificate.
#[tokio::test(flavor = "multi_thread")]
async fn connect_uses_the_ca_and_presents_the_client_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("connect CA");
    let ca_path = ca.write(dir.path(), "ca.pem");
    let client = ClientCert::new("coder");
    let (cert, key) = write_client(dir.path(), &client, "coder");
    let (url, seen, task) = recording_server(&ca).await;

    let mut c = attenuo();
    c.env("ATTENUO_TOKEN", "opaque-test-token")
        .args(["--server", &url])
        .arg("--tls-ca-cert")
        .arg(&ca_path)
        .arg("--tls-client-cert")
        .arg(&cert)
        .arg("--tls-client-key")
        .arg(&key)
        .args(["connect", "--upstream", "files"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = tokio::task::spawn_blocking(move || {
        let mut child = c.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
            .unwrap();
        drop(stdin);
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    let stdout = text(&out.stdout);
    assert!(stdout.contains(r#""result":{}"#), "{out:?}");
    // Every request (the MCP message, and a lease renewal it may send first) went with the
    // client certificate.
    let seen = seen.lock().unwrap().clone();
    assert!(seen.iter().any(|(p, _)| p == "/mcp/files"), "{seen:?}");
    for (path, cert) in &seen {
        assert_eq!(
            cert.as_deref(),
            Some(client.sha256_hex().as_str()),
            "{path}"
        );
    }
    task.abort();
}
