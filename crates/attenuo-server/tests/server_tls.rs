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
    let read = tokio::time::timeout(Duration::from_secs(15), plain.read_to_end(&mut buf)).await;
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

/// Two peers that hang in their handshake (one sends nothing, one half a ClientHello) do not
/// hold up a third: the handshake is not in the accept loop. The header-read timeout is long
/// (20 s), the well-behaved client must be served within half of it while both hanging
/// sockets are still open, and the test ends there, without waiting for the timeout.
#[tokio::test]
async fn a_hanging_handshake_does_not_hold_up_other_clients() {
    const TIMEOUT: Duration = Duration::from_secs(20);
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let (server, state) = start(tls_config(dir.path(), &ca, TIMEOUT.as_secs())).await;

    let mut silent = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
    let mut half = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
    // A TLS record header announcing a 512-byte handshake message, and then only a few bytes.
    half.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00])
        .await
        .unwrap();
    // Give the accept loop the time to take both (it takes connections in order).
    tokio::time::sleep(Duration::from_millis(200)).await;

    let started = Instant::now();
    let resp = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca.reqwest_root())
        .timeout(TIMEOUT / 2)
        .build()
        .unwrap()
        .get(server.https_url("/healthz"))
        .send()
        .await
        .expect("the client was not served while two handshakes hang");
    assert_eq!(resp.status(), StatusCode::OK);
    let served = started.elapsed();
    assert!(served < TIMEOUT / 2, "{served:?}");

    // Both hanging sockets are still open: no data, no end of stream, no reset.
    for stream in [&mut silent, &mut half] {
        let mut byte = [0u8; 1];
        let peek = tokio::time::timeout(Duration::from_millis(200), stream.peek(&mut byte)).await;
        assert!(peek.is_err(), "a hanging connection was not open: {peek:?}");
    }
    // Shutdown drops them at once.
    server.stop(state).await;
}

/// A peer that connects and sends nothing, or half a ClientHello, is dropped by the server
/// at the header-read timeout (3 s). The lower bound holds by construction: the clock starts
/// before the connections are made. The upper bound is only a generous deadline.
#[tokio::test]
async fn a_silent_or_slow_handshake_is_dropped_at_the_header_read_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let (server, state) = start(tls_config(dir.path(), &ca, 3)).await;

    let started = Instant::now();
    let mut silent = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
    let mut half = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
    half.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00])
        .await
        .unwrap();
    for stream in [&mut silent, &mut half] {
        let mut buf = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut buf)).await;
        assert!(read.is_ok(), "the hanging connection was not closed");
        assert!(buf.is_empty(), "{buf:?}");
    }
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(2500), "{waited:?}");
    server.stop(state).await;
}

/// After the handshake the request headers are bounded by the same timeout, as on plain HTTP,
/// and an idle kept-alive TLS connection is closed by it too.
#[tokio::test]
async fn an_idle_tls_connection_is_closed_at_the_header_read_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let (server, state) = start(tls_config(dir.path(), &ca, 3)).await;
    let mut stream = tls_connect(&ca, server.addr(), &[b"http/1.1"])
        .await
        .unwrap();
    // The clock starts before the request, so the idle timer cannot have started earlier.
    let started = Instant::now();
    assert!(get_on(&mut stream, "/healthz")
        .await
        .starts_with("HTTP/1.1 200"));
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut buf)).await;
    assert!(read.is_ok(), "the idle connection was not closed");
    assert!(started.elapsed() >= Duration::from_millis(2500));
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

    // Not the 60 s header-read timeout, and not the 10 s drain timeout either, which is what
    // a connection left hanging in its handshake would cost.
    let started = Instant::now();
    server.stop(state).await;
    assert!(
        started.elapsed() < attenuo_server::DRAIN_TIMEOUT - Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );

    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(15), open.read_to_end(&mut buf)).await;
    assert!(read.is_ok(), "the open TLS connection was not closed");
    let read = tokio::time::timeout(
        Duration::from_secs(15),
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
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stopping = tokio::spawn(server.stop(state));
    tokio::time::sleep(Duration::from_millis(300)).await;
    stream.write_all(rest.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut buf)).await;
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

/// With `[server.tls]` the other listeners (`[admin] listen`, `[admin_ui]`, `[metrics]`) serve
/// plain HTTP exactly as before: they have routers of their own, without the layer that
/// refuses requests not made over TLS, and they do not speak TLS.
#[tokio::test]
async fn the_side_listeners_stay_plain_http_with_server_tls() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let mut cfg = tls_config(dir.path(), &ca, 10);
    let admin = common::free_port();
    let console = common::free_port();
    let metrics = common::free_port();
    cfg.admin.listen = Some(admin);
    cfg.admin_ui.enabled = true;
    cfg.admin_ui.listen = console;
    cfg.metrics.enabled = true;
    cfg.metrics.listen = metrics;
    let (server, state) = start(cfg).await;
    // `run` binds the side listeners itself, after `start` returns.
    for addr in [admin, console, metrics] {
        let end = Instant::now() + Duration::from_secs(20);
        while tokio::net::TcpStream::connect(addr).await.is_err() {
            assert!(Instant::now() < end, "{addr} never listened");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    let http = reqwest::Client::new();

    // The admin API, on its own listener: plain HTTP, behind the bearer, as before.
    let resp = http
        .get(format!("http://{admin}/admin/whoami"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let me: Value = resp.json().await.unwrap();
    assert_eq!(me["role"], "admin", "{me}");
    let resp = http
        .get(format!("http://{admin}/admin/whoami"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // And not on the main listener, over TLS: an unknown path there.
    let resp = client(&ca)
        .get(server.https_url("/admin/whoami"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // The console: its page and its admin routes, plain HTTP.
    let resp = http
        .get(format!("http://{console}/admin/ui/"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = http
        .get(format!("http://{console}/admin/whoami"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Metrics, plain HTTP; they count the TLS request above too.
    let resp = http
        .get(format!("http://{metrics}/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.text().await.unwrap().contains("attenuo_"));

    // None of them speaks TLS.
    for addr in [admin, console, metrics] {
        assert!(
            tls_connect(&ca, addr, &[b"http/1.1"]).await.is_err(),
            "{addr}"
        );
    }
    server.stop(state).await;
}

/// Without `[admin] listen` the admin API is on the main listener and works over TLS.
#[tokio::test]
async fn admin_routes_on_the_main_listener_work_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let cfg = tls_config(dir.path(), &ca, 10);
    assert!(cfg.admin.listen.is_none());
    let (server, state) = start(cfg).await;
    let https = client(&ca);
    let resp = https
        .get(server.https_url("/admin/whoami"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = https
        .get(server.https_url("/admin/audit/verify"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = https
        .get(server.https_url("/admin/whoami"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    server.stop(state).await;
}

/// `serve_until` never speaks TLS: a router built over a state with `[server.tls]` answers
/// every request it serves with 500 and issues nothing, rather than take tokens in cleartext.
#[tokio::test]
async fn serve_until_refuses_to_serve_a_tls_router_in_cleartext() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("server-tls test CA");
    let cfg = tls_config(dir.path(), &ca, 10);
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(attenuo_server::serve_until(
        listener,
        router,
        async move {
            let _ = stopped.await;
        },
        Duration::from_secs(5),
    ));
    let http = reqwest::Client::new();
    // The TLS marker is a value the accept loop puts into the request, never a header: no
    // header a client sends gets a request through.
    for path in ["/healthz", "/.well-known/authzen-configuration"] {
        let resp = http
            .get(format!("http://{addr}{path}"))
            .header("ServedOverTls", "1")
            .header("X-Forwarded-Proto", "https")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR, "{path}");
        assert!(resp.text().await.unwrap().is_empty(), "{path}");
    }
    let resp = http
        .post(format!("http://{addr}/admin/root-token"))
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
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!resp.text().await.unwrap().contains("access_token"));
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();

    // The same config without [server.tls] is served by serve_until as before.
    let mut plain = plain_config(dir.path(), 10);
    plain.audit.sqlite_path = dir
        .path()
        .join("plain.sqlite")
        .to_string_lossy()
        .into_owned();
    let (router, _state) = attenuo_server::build(&plain).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(attenuo_server::serve_until(
        listener,
        router,
        async move {
            let _ = stopped.await;
        },
        Duration::from_secs(5),
    ));
    let resp = http
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
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
        std::fs::set_permissions(&tls.key_pem_path, std::fs::Permissions::from_mode(0o604))
            .unwrap();
        let err = refused(&good);
        assert!(err.contains("chmod 600"), "{err}");
        std::fs::set_permissions(&tls.key_pem_path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    // A broken key block, in a combined file and in a key file of its own: the error shows
    // no part of the key body (the PEM parser's own error would quote a character of it).
    let key_text = std::fs::read_to_string(&tls.key_pem_path).unwrap();
    let mut lines: Vec<String> = key_text.lines().map(str::to_owned).collect();
    let body: Vec<String> = lines[1..lines.len() - 1].to_vec();
    let at = lines[1].len() / 2;
    lines[1].replace_range(at..=at, "*");
    let broken = lines.join("\n") + "\n";
    let cert_text = std::fs::read_to_string(&tls.cert_pem_path).unwrap();
    let write_secret = |name: &str, text: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    };
    let combined = write_secret("combined.pem", &format!("{cert_text}{broken}"));
    let broken_key = write_secret("broken.key", &broken);
    // The same key and certificate with every line break removed, in both orders: the PEM
    // parser's errors print such a line in full, as a list of byte values.
    let flat = |t: &str| t.replace(['\n', '\r'], "");
    let flat_key_first = write_secret(
        "flat-key-first.pem",
        &flat(&format!("{key_text}{cert_text}")),
    );
    let flat_cert_first = write_secret(
        "flat-cert-first.pem",
        &flat(&format!("{cert_text}{key_text}")),
    );
    let flat_key = write_secret("flat.key", &flat(&key_text));
    let joined: String = body.concat();
    for (cert, key) in [
        (&combined, &combined),
        (&tls.cert_pem_path, &broken_key),
        (&combined, &tls.key_pem_path),
        (&flat_key_first, &tls.key_pem_path),
        (&flat_key_first, &flat_key_first),
        (&flat_cert_first, &tls.key_pem_path),
        (&flat_cert_first, &flat_cert_first),
        (&tls.cert_pem_path, &flat_key),
    ] {
        let mut cfg = good.clone();
        let section = cfg.server.tls.as_mut().unwrap();
        section.cert_pem_path = cert.clone();
        section.key_pem_path = key.clone();
        let err = refused(&cfg)
            .replace(&cert.display().to_string(), "<path>")
            .replace(&key.display().to_string(), "<path>");
        assert!(err.len() < 300, "{} bytes: {err}", err.len());
        for i in 0..joined.len().saturating_sub(6) {
            assert!(!err.contains(&joined[i..i + 6]), "{err}");
        }
        // No list of byte values: at most a few comma-separated numbers in a row.
        let mut run = 0;
        for part in err.split(',') {
            let digits = part.trim().trim_matches(|c| c == '[' || c == ']');
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                run += 1;
                assert!(run <= 3, "{err}");
            } else {
                run = 0;
            }
        }
        assert!(
            !err.contains("InvalidCharacter") && !err.contains('*'),
            "{err}"
        );
    }

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
