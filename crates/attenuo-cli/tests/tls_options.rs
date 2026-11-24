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

    // An empty value on the command line is a usage error, not "unset".
    for flag in ["--tls-ca-cert", "--tls-client-cert", "--tls-client-key"] {
        let out = run(s.cli(&[flag, "", "health"])).await;
        assert_eq!(out.status.code(), Some(1), "{flag}: {out:?}");
        assert!(text(&out.stderr).contains("a value is required"), "{out:?}");
    }

    // Another CA: refused the same way. With --tls-ca-cert, only its certificates are
    // trusted; that the built-in public roots are then off is not shown by a request here
    // (it would need a server with a public certificate, so the network): the code turns
    // them off in `Tls::apply` (`tls_built_in_root_certs(false)`).
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
    let ca = Ca::new("unused CA").write(dir.path(), "ca.pem");
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
        (
            vec!["--tls-ca-cert".into(), p(dir.path())],
            "is not a regular file",
        ),
    ];
    // `policy show` with an admin token: it would send a request if nothing stopped it.
    for (args, want) in cases {
        for cmd in [vec!["health"], vec!["policy", "show"]] {
            let mut c = attenuo();
            c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
                .args(["--server", &url])
                .args(&args)
                .args(&cmd);
            let err = failed(&run(c).await);
            assert!(err.contains(want), "{args:?}: {err}");
            assert!(!err.contains("TOPSECRET"), "{err}");
        }
    }
    // A FIFO that nobody writes to is refused at once instead of hanging the CLI.
    #[cfg(unix)]
    {
        let fifo = dir.path().join("fifo.key");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .unwrap();
        let mut c = attenuo();
        c.args(["--server", &url, "--tls-client-cert"])
            .arg(&cert)
            .arg("--tls-client-key")
            .arg(&fifo)
            .arg("health");
        let err = failed(&run(c).await);
        assert!(err.contains("is not a regular file"), "{err}");
    }
    // A client certificate with an http:// --server: refused, naming the options.
    let http = url.replacen("https://", "http://", 1);
    let mut c = attenuo();
    c.args(["--server", &http, "--tls-client-cert"])
        .arg(&cert)
        .arg("--tls-client-key")
        .arg(&key)
        .arg("health");
    let err = failed(&run(c).await);
    assert!(err.contains("need an https:// --server"), "{err}");
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

    // --tls-ca-cert alone with only http:// URLs: a warning, and the command runs.
    let mut c = attenuo();
    c.args(["--server", &http, "--tls-ca-cert"])
        .arg(&ca)
        .args(["health", "--timeout", "1"]);
    let out = run(c).await;
    assert!(
        text(&out.stderr).starts_with("warning: --tls-ca-cert"),
        "{out:?}"
    );
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

/// The client certificate goes to the origin of --server only: an `/admin/*` request sent
/// to --admin-server carries none, also when the base URLs have a path prefix, while the CA
/// applies to both. Without --admin-server, the admin request goes to --server, with the
/// certificate. A `--jwks` URL on another origin gets the CA and no certificate.
#[tokio::test(flavor = "multi_thread")]
async fn the_client_certificate_goes_to_server_and_not_to_admin_server() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("recording CA");
    let ca_path = ca.write(dir.path(), "ca.pem");
    let ca_path = ca_path.to_str().unwrap();
    let client = ClientCert::new("coder");
    let (cert, key) = write_client(dir.path(), &client, "coder");
    // Both servers have a certificate from the CA, and ask every client for a certificate.
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
    let with_cert = Some(client.sha256_hex());
    let take = |seen: &Seen| std::mem::take(&mut *seen.lock().unwrap());
    let policy_show = |server: String, admin: Option<String>| {
        let mut c = attenuo();
        c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
            .args(["--server", &server]);
        if let Some(a) = admin {
            c.args(["--admin-server", &a]);
        }
        c.args(flags).args(["--json", "policy", "show"]);
        c
    };

    // --admin-server on another origin, with and without a path prefix on either URL.
    for (server, adm, path) in [
        (main.clone(), admin.clone(), "/admin/policies"),
        (
            format!("{main}/pfx"),
            format!("{admin}/pfx"),
            "/pfx/admin/policies",
        ),
        (main.clone(), format!("{admin}/pfx"), "/pfx/admin/policies"),
        (format!("{main}/pfx"), admin.clone(), "/admin/policies"),
    ] {
        ok(&run(policy_show(server.clone(), Some(adm.clone()))).await);
        assert_eq!(
            take(&admin_seen),
            vec![(path.to_owned(), None)],
            "{server} {adm}"
        );
        assert!(take(&main_seen).is_empty(), "{server} {adm}");
    }

    // No --admin-server: `/admin/*` goes to --server, the same host, with the certificate;
    // a prefixed --server too.
    for (server, path) in [
        (main.clone(), "/admin/policies"),
        (format!("{main}/pfx"), "/pfx/admin/policies"),
    ] {
        ok(&run(policy_show(server.clone(), None)).await);
        assert_eq!(
            take(&main_seen),
            vec![(path.to_owned(), with_cert.clone())],
            "{server}"
        );
    }

    // `approval verify --jwks URL`: on the --server origin, the certificate goes; on another
    // origin, whose certificate the CA trusts and which asks for a client certificate, the
    // handshake succeeds and no certificate is presented.
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
        take(&main_seen),
        vec![("/jwks".to_owned(), with_cert.clone())],
        "{out:?}"
    );
    let out = run(verify(format!("{admin}/jwks"))).await;
    assert_ne!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(
        take(&admin_seen),
        vec![("/jwks".to_owned(), None)],
        "{out:?}"
    );

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

/// Commands that send nothing to --server or --admin-server do not check the TLS options
/// against those URLs: with the client certificate variables set and the default http://
/// --server they succeed, and with the CA variable set they print no warning. The commands
/// that do send still get the error or the warning, before any request. An error about a
/// value from an environment variable names the variable.
#[tokio::test(flavor = "multi_thread")]
async fn offline_commands_ignore_the_targets_and_env_errors_name_the_variable() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = write_client(dir.path(), &ClientCert::new("coder"), "coder");
    let ca = Ca::new("offline CA").write(dir.path(), "ca.pem");

    // A real delegation token for `token inspect`, from a plain server.
    let mut cfg = Config::default();
    cfg.issuer.private_key_pem_path = Some(dir.path().join("issuer.pem"));
    cfg.audit.sqlite_path = ":memory:".into();
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = attenuo_proxy::testing::spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();
    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(["--server", &url, "--json", "token", "root"])
        .args([
            "--subject",
            "alice",
            "--agent",
            "planner",
            "--cap",
            "github:*",
        ]);
    let root: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    let token = root["access_token"].as_str().unwrap().to_owned();

    let offline: Vec<Vec<String>> = vec![
        vec!["token".into(), "inspect".into(), token.clone()],
        vec![
            "key".into(),
            "gen".into(),
            "--dpop".into(),
            dir.path().join("dpop.jwk").to_str().unwrap().into(),
        ],
        vec![
            "admin".into(),
            "operator".into(),
            "new".into(),
            "--name".into(),
            "alice".into(),
            "--role".into(),
            "admin".into(),
        ],
    ];
    for args in &offline {
        // The default --server, http://127.0.0.1:8080.
        let mut c = attenuo();
        c.args(args)
            .env("ATTENUO_TLS_CLIENT_CERT", &cert)
            .env("ATTENUO_TLS_CLIENT_KEY", &key);
        let out = run(c).await;
        ok(&out);
        assert!(!text(&out.stderr).contains("https://"), "{args:?}: {out:?}");
        let _ = std::fs::remove_file(dir.path().join("dpop.jwk"));
        let mut c = attenuo();
        c.args(args).env("ATTENUO_TLS_CA_CERT", &ca);
        let out = run(c).await;
        ok(&out);
        assert!(!text(&out.stderr).contains("warning"), "{args:?}: {out:?}");
        let _ = std::fs::remove_file(dir.path().join("dpop.jwk"));
    }

    // A command that sends: the error with the certificate, the warning with the CA alone.
    let mut c = attenuo();
    c.args(["--server", &url, "health"])
        .env("ATTENUO_TLS_CLIENT_CERT", &cert)
        .env("ATTENUO_TLS_CLIENT_KEY", &key);
    let err = failed(&run(c).await);
    assert!(err.contains("need an https:// --server"), "{err}");
    let mut c = attenuo();
    c.args(["--server", &url, "health"])
        .env("ATTENUO_TLS_CA_CERT", &ca);
    let out = run(c).await;
    ok(&out);
    assert!(
        text(&out.stderr).starts_with("warning: --tls-ca-cert"),
        "{out:?}"
    );
    // `--server` that is not a URL: that message, not the https one.
    let mut c = attenuo();
    c.args(["--server", "github", "health"])
        .env("ATTENUO_TLS_CLIENT_CERT", &cert)
        .env("ATTENUO_TLS_CLIENT_KEY", &key);
    let err = failed(&run(c).await);
    assert!(
        err.contains("--server must be the attenuo server's base URL"),
        "{err}"
    );

    // Errors name the environment variable a path came from, and the flag otherwise.
    let missing = dir.path().join("missing.pem");
    let mut c = attenuo();
    c.args(["--server", &url, "health"])
        .env("ATTENUO_TLS_CA_CERT", &missing);
    let err = failed(&run(c).await);
    assert!(
        err.starts_with("error: cannot read ATTENUO_TLS_CA_CERT "),
        "{err}"
    );
    let mut c = attenuo();
    c.args(["--server", &url, "health"])
        .env("ATTENUO_TLS_CLIENT_CERT", &cert)
        .env("ATTENUO_TLS_CLIENT_KEY", &missing);
    let err = failed(&run(c).await);
    assert!(
        err.starts_with("error: cannot read ATTENUO_TLS_CLIENT_KEY "),
        "{err}"
    );
    let mut c = attenuo();
    c.args(["--server", &url, "health"])
        .env("ATTENUO_TLS_CLIENT_CERT", &cert);
    let err = failed(&run(c).await);
    assert!(
        err.starts_with("error: ATTENUO_TLS_CLIENT_CERT needs --tls-client-key"),
        "{err}"
    );
    let mut c = attenuo();
    c.args(["--server", &url, "--tls-client-key"])
        .arg(&missing)
        .arg("health")
        .env("ATTENUO_TLS_CLIENT_CERT", &cert);
    let err = failed(&run(c).await);
    assert!(
        err.starts_with("error: cannot read --tls-client-key "),
        "{err}"
    );
}
