//! `[server.tls]`: the main listener speaks TLS itself, with real handshakes through
//! [`attenuo_server::run`], the code `serve` runs.
//!
//! TLS 1.3 only, ALPN `http/1.1`, no resumption, no client certificate. The handshake runs in
//! the connection's task under `[limits] header_read_timeout_seconds`: a silent peer is
//! dropped, a plain-HTTP request fails the handshake and the server goes on, and shutdown does
//! not wait for an open connection. Without `[server.tls]` the listener speaks plain HTTP as
//! before.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use attenuo_server::config::ServerTlsSection;
use attenuo_server::Config;
use common::tls::Ca;
use common::Running;
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ADMIN: &str = "server-tls-test-admin-token-0123456789abcdef";
const PUBLIC_URL: &str = "https://localhost:8443";

/// A config with `[server.tls]` (certificate for 127.0.0.1 from `ca`, files in `dir`), the dev
/// root mint on and `header_read_timeout` seconds.
fn tls_config(dir: &std::path::Path, ca: &Ca, header_read_timeout: u64) -> Config {
    let (cert, key) = ca.write_server_files(dir, &["127.0.0.1"]);
    let mut cfg = plain_config(dir, header_read_timeout);
    cfg.server.public_url = Some(PUBLIC_URL.into());
    cfg.server.tls = Some(ServerTlsSection {
        cert_pem_path: cert,
        key_pem_path: key,
    });
    cfg
}

fn plain_config(dir: &std::path::Path, header_read_timeout: u64) -> Config {
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir.join("audit.sqlite").to_string_lossy().into_owned();
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.limits.header_read_timeout_seconds = header_read_timeout;
    cfg
}

async fn start(cfg: Config) -> (Running, Arc<attenuo_server::AppState>) {
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    (Running::start(cfg, state.clone(), router).await, state)
}

/// A reqwest client that trusts `ca` only.
fn client(ca: &Ca) -> reqwest::Client {
    reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca.reqwest_root())
        .build()
        .unwrap()
}

/// A raw TLS 1.3 connection to `addr`, offering `alpn`.
async fn tls_connect(
    ca: &Ca,
    addr: std::net::SocketAddr,
    alpn: &[&[u8]],
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let config = ca.rustls_client(&[&rustls::version::TLS13], alpn);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    connector.connect(name, tcp).await
}

/// Send one `GET path` on `stream` (kept alive) and read the response head and body by its
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

/// healthz, discovery and the dev root mint answer over TLS, with the server's certificate
/// trusted through the test CA; discovery names the https `public_url`.
#[tokio::test]
async fn requests_over_tls_are_served() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let (server, state) = start(tls_config(dir.path(), &ca, 10)).await;
    let http = client(&ca);

    let resp = http.get(server.https_url("/healthz")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let disco: Value = http
        .get(server.https_url("/.well-known/authzen-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(disco["policy_decision_point"], PUBLIC_URL, "{disco}");

    let resp = http
        .post(server.https_url("/admin/root-token"))
        .bearer_auth(ADMIN)
        .json(&json!({
            "subject": "alice",
            "issuer": "https://idp.example",
            "agent": "planner",
            "capabilities": ["github:read_file"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let minted: Value = resp.json().await.unwrap();
    assert!(minted["access_token"].as_str().is_some(), "{minted}");

    // The negotiated parameters: TLS 1.3, http/1.1 by ALPN, a full handshake.
    let stream = tls_connect(&ca, server.addr(), &[b"h2", b"http/1.1"])
        .await
        .unwrap();
    let (_, conn) = stream.get_ref();
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(conn.alpn_protocol(), Some(&b"http/1.1"[..]));
    // A client without ALPN is served too.
    let mut stream = tls_connect(&ca, server.addr(), &[]).await.unwrap();
    assert!(get_on(&mut stream, "/healthz")
        .await
        .starts_with("HTTP/1.1 200"));
    drop(stream);

    server.stop(state).await;
}

/// A client that offers only `h2` by ALPN is refused: the listener serves HTTP/1.1 only.
#[tokio::test]
async fn an_h2_only_client_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let (server, state) = start(tls_config(dir.path(), &ca, 10)).await;
    assert!(tls_connect(&ca, server.addr(), &[b"h2"]).await.is_err());
    server.stop(state).await;
}

/// TLS 1.2 is refused; the server keeps serving TLS 1.3.
#[tokio::test]
async fn a_tls12_only_client_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let (server, state) = start(tls_config(dir.path(), &ca, 10)).await;

    let config = ca.rustls_client(&[&rustls::version::TLS12], &[b"http/1.1"]);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    let err = connector.connect(name, tcp).await.unwrap_err();
    assert!(
        err.to_string().to_ascii_lowercase().contains("protocol"),
        "{err}"
    );

    let old = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca.reqwest_root())
        .max_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .unwrap();
    assert!(old.get(server.https_url("/healthz")).send().await.is_err());

    let resp = client(&ca)
        .get(server.https_url("/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    server.stop(state).await;
}

/// No session resumption: a client that keeps sessions makes a full handshake every time.
#[tokio::test]
async fn every_connection_makes_a_full_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let (server, state) = start(tls_config(dir.path(), &ca, 10)).await;
    // One client config, so one session cache, for every connection.
    let config = Arc::new(ca.rustls_client(&[&rustls::version::TLS13], &[b"http/1.1"]));
    for _ in 0..3 {
        let connector = tokio_rustls::TlsConnector::from(config.clone());
        let tcp = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        let mut stream = connector.connect(name, tcp).await.unwrap();
        // A request, so that any ticket the server sent after the handshake is read.
        assert!(get_on(&mut stream, "/healthz")
            .await
            .starts_with("HTTP/1.1 200"));
        assert_eq!(
            stream.get_ref().1.handshake_kind(),
            Some(rustls::HandshakeKind::Full)
        );
    }
    server.stop(state).await;
}

/// A plain-HTTP request to the TLS port gets no HTTP answer and its connection is closed; the
/// server goes on serving TLS.
#[tokio::test]
async fn plain_http_to_the_tls_port_fails_and_the_server_goes_on() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let (server, state) = start(tls_config(dir.path(), &ca, 10)).await;

    let mut plain = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
    plain
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), plain.read_to_end(&mut buf)).await;
    assert!(read.is_ok(), "the connection was not closed");
    assert!(
        !String::from_utf8_lossy(&buf).contains("HTTP/1.1"),
        "{buf:?}"
    );

    let err = reqwest::get(server.url("/healthz")).await;
    assert!(err.is_err(), "{err:?}");

    let resp = client(&ca)
        .get(server.https_url("/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    server.stop(state).await;
}

/// A client that does not trust the certificate fails its handshake; the server goes on.
#[tokio::test]
async fn a_client_that_does_not_trust_the_certificate_fails() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let other = Ca::new("another CA");
    let (server, state) = start(tls_config(dir.path(), &ca, 10)).await;
    assert!(client(&other)
        .get(server.https_url("/healthz"))
        .send()
        .await
        .is_err());
    assert!(tls_connect(&other, server.addr(), &[b"http/1.1"])
        .await
        .is_err());
    let resp = client(&ca)
        .get(server.https_url("/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    server.stop(state).await;
}

/// A peer that connects and sends nothing, or half a ClientHello, is dropped at the
/// header-read timeout; meanwhile other clients are served (the handshake is not in the
/// accept loop).
#[tokio::test]
async fn a_silent_or_slow_handshake_is_dropped_at_the_header_read_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let (server, state) = start(tls_config(dir.path(), &ca, 1)).await;

    let started = Instant::now();
    let mut silent = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
    let mut half = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
    // A TLS record header announcing a 512-byte handshake message, and then only a few bytes.
    half.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00])
        .await
        .unwrap();

    // While both hang, another client is served at once.
    let resp = client(&ca)
        .get(server.https_url("/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(started.elapsed() < Duration::from_millis(900));

    for stream in [&mut silent, &mut half] {
        let mut buf = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;
        assert!(read.is_ok(), "the hanging connection was not closed");
        assert!(buf.is_empty(), "{buf:?}");
    }
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(900), "{waited:?}");
    assert!(waited < Duration::from_secs(5), "{waited:?}");
    server.stop(state).await;
}

/// After the handshake the request headers are bounded by the same timeout, as on plain HTTP,
/// and an idle kept-alive TLS connection is closed by it too.
#[tokio::test]
async fn an_idle_tls_connection_is_closed_at_the_header_read_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let (server, state) = start(tls_config(dir.path(), &ca, 1)).await;
    let mut stream = tls_connect(&ca, server.addr(), &[b"http/1.1"])
        .await
        .unwrap();
    assert!(get_on(&mut stream, "/healthz")
        .await
        .starts_with("HTTP/1.1 200"));
    let started = Instant::now();
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf)).await;
    assert!(read.is_ok(), "the idle connection was not closed");
    assert!(started.elapsed() >= Duration::from_millis(500));
    server.stop(state).await;
}

/// Shutdown with an open kept-alive TLS connection and a connection still in its handshake:
/// the server stops at once (the long header-read timeout is not waited out), and the TLS
/// connection is closed.
#[tokio::test]
async fn shutdown_closes_open_tls_connections() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let (server, state) = start(tls_config(dir.path(), &ca, 60)).await;
    let mut open = tls_connect(&ca, server.addr(), &[b"http/1.1"])
        .await
        .unwrap();
    assert!(get_on(&mut open, "/healthz")
        .await
        .starts_with("HTTP/1.1 200"));
    let mut handshaking = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
    // Let the server accept it, so it is a live connection when the stop comes.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let started = Instant::now();
    server.stop(state).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );

    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), open.read_to_end(&mut buf)).await;
    assert!(read.is_ok(), "the open TLS connection was not closed");
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        handshaking.read_to_end(&mut Vec::new()),
    )
    .await;
    assert!(read.is_ok(), "the handshaking connection was not closed");
}

/// A request in progress over TLS when the shutdown comes finishes during the drain.
#[tokio::test]
async fn a_tls_request_in_progress_finishes_during_the_drain() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let (server, state) = start(tls_config(dir.path(), &ca, 10)).await;
    let mut stream = tls_connect(&ca, server.addr(), &[b"http/1.1"])
        .await
        .unwrap();
    let body = json!({
        "subject": "alice",
        "issuer": "https://idp.example",
        "agent": "planner",
        "capabilities": ["github:read_file"],
    })
    .to_string();
    let (first, rest) = body.split_at(10);
    // The head and part of the body: the server has the request in progress.
    stream
        .write_all(
            format!(
                "POST /admin/root-token HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                 Authorization: Bearer {ADMIN}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\n\r\n{first}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    stream.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let stopping = tokio::spawn(server.stop(state));
    tokio::time::sleep(Duration::from_millis(200)).await;
    stream.write_all(rest.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("access_token"), "{text}");
    stopping.await.unwrap();
}

/// Without `[server.tls]` the listener speaks plain HTTP as before, and a TLS client gets no
/// handshake.
#[tokio::test]
async fn without_server_tls_the_listener_speaks_plain_http() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let cfg = plain_config(dir.path(), 10);
    assert!(cfg.server.tls.is_none());
    let (server, state) = start(cfg).await;
    let resp = reqwest::get(server.url("/healthz")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let disco: Value = reqwest::get(server.url("/.well-known/authzen-configuration"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        disco["policy_decision_point"]
            .as_str()
            .unwrap()
            .starts_with("http://"),
        "{disco}"
    );
    assert!(tls_connect(&ca, server.addr(), &[b"http/1.1"])
        .await
        .is_err());
    server.stop(state).await;
}

/// The startup refusals reach `build`, so `serve` stops before binding anything.
#[test]
fn a_bad_server_tls_section_stops_the_server_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let good = tls_config(dir.path(), &ca, 10);
    let tls = good.server.tls.clone().unwrap();
    let refused = |cfg: &Config| -> String {
        format!(
            "{:#}",
            attenuo_server::build(cfg).err().expect("must refuse")
        )
    };

    // A missing key file.
    let mut cfg = good.clone();
    cfg.server.tls.as_mut().unwrap().key_pem_path = dir.path().join("missing.key");
    let err = refused(&cfg);
    assert!(
        err.contains("key_pem_path") && err.contains("missing.key"),
        "{err}"
    );

    // The key of another certificate.
    let other = tempfile::tempdir().unwrap();
    let (_, other_key) = ca.write_server_files(other.path(), &["127.0.0.1"]);
    let mut cfg = good.clone();
    cfg.server.tls.as_mut().unwrap().key_pem_path = other_key;
    let err = refused(&cfg);
    assert!(err.contains("does not belong"), "{err}");

    // An http:// public URL, and none at all.
    let mut cfg = good.clone();
    cfg.server.public_url = Some("http://localhost:8443".into());
    let err = refused(&cfg);
    assert!(
        err.contains("[server.tls]") && err.contains("https://"),
        "{err}"
    );
    let mut cfg = good.clone();
    cfg.server.public_url = None;
    let err = refused(&cfg);
    assert!(err.contains("public_url"), "{err}");

    // A key file its group may read.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tls.key_pem_path, std::fs::Permissions::from_mode(0o640))
            .unwrap();
        let err = refused(&good);
        assert!(err.contains("chmod 600"), "{err}");
        std::fs::set_permissions(&tls.key_pem_path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    // The error never shows the key.
    let key_text = std::fs::read_to_string(&tls.key_pem_path).unwrap();
    let body = key_text.lines().nth(1).unwrap();
    let mut cfg = good.clone();
    cfg.server.tls.as_mut().unwrap().cert_pem_path = tls.key_pem_path.clone();
    let err = refused(&cfg);
    assert!(!err.contains(body), "{err}");

    let _ = attenuo_server::build(&good).unwrap();
}

/// `[server.tls]` comes from the file only: an environment override cannot create it.
#[test]
fn server_tls_is_not_created_from_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attenuo.toml");
    std::fs::write(&path, "[server]\nlisten = \"127.0.0.1:8080\"\n").unwrap();
    let err = Config::load_with_env(
        &path,
        [(
            "ATTENUO__SERVER__TLS__CERT_PEM_PATH",
            "/etc/attenuo/tls.crt",
        )],
    )
    .unwrap_err();
    let err = format!("{err:#}");
    assert!(err.contains("[server.tls]"), "{err}");
    assert!(!err.contains("/etc/attenuo/tls.crt"), "{err}");
}
