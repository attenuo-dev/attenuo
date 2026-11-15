//! An answer sent before the request body was read to its end (here the
//! proxy's 401 for a missing or bad token, with the body late or never sent, and the admin
//! routes' 401) carries `Connection: close`, so a client does not reuse a connection the
//! server is closing. An answer to a request whose body was read keeps the connection open.
//! Raw TCP, so the body can arrive after the headers, as a slow client sends it.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

use std::time::Duration;

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn start(dir: &std::path::Path) -> Spawned {
    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.test".into();
    cfg.issuer.audience = "attenuo-test".into();
    cfg.audit.sqlite_path = dir.join("audit.sqlite").to_string_lossy().into_owned();
    // Never reached: every request here is refused or answered by the server itself.
    cfg.upstreams = vec![UpstreamConfig::new("github", "http://127.0.0.1:9/mcp")];
    cfg.admin.token = Some("early-close-admin".into());
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    spawn_router(router).await.unwrap()
}

/// One HTTP/1.1 answer: status, lowercased headers, body.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Read one answer with a `Content-Length` body from `conn`.
async fn read_answer(conn: &mut TcpStream) -> Answer {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut byte))
            .await
            .expect("answer in time")
            .unwrap();
        assert_eq!(n, 1, "connection closed before the answer's headers");
        buf.push(byte[0]);
    }
    let head = String::from_utf8(buf).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers: Vec<(String, String)> = lines
        .filter(|l| !l.is_empty())
        .map(|l| {
            let (n, v) = l.split_once(':').unwrap();
            (n.trim().to_ascii_lowercase(), v.trim().to_string())
        })
        .collect();
    let len: usize = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .map(|(_, v)| v.parse().unwrap())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    conn.read_exact(&mut body).await.unwrap();
    Answer { status, headers }
}

/// Send the headers of `POST path` with `body`'s length, wait 50 ms, send the body, then read
/// the answer.
async fn post_slowly(conn: &mut TcpStream, path: &str, extra: &str, body: &[u8]) -> Answer {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n{extra}\r\n",
        body.len()
    );
    conn.write_all(head.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    // The server may already have answered and closed its reading side; that is the point.
    let _ = conn.write_all(body).await;
    read_answer(conn).await
}

#[tokio::test]
async fn a_refusal_before_the_body_is_read_closes_the_connection_item63() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let call = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;

    // The proxy authenticates before it reads the body.
    let mut conn = TcpStream::connect(server.addr).await.unwrap();
    let a = post_slowly(&mut conn, "/mcp/github", "", call).await;
    assert_eq!(a.status, 401);
    assert_eq!(a.header("connection"), Some("close"));

    // A declared 100 MiB body, none of it sent: refused unread.
    let mut conn = TcpStream::connect(server.addr).await.unwrap();
    let head = "POST /mcp/github HTTP/1.1\r\nHost: localhost\r\n\
                Authorization: Bearer not-a-token\r\nContent-Length: 104857600\r\n\r\n";
    conn.write_all(head.as_bytes()).await.unwrap();
    let a = read_answer(&mut conn).await;
    assert_eq!(a.status, 401);
    assert_eq!(a.header("connection"), Some("close"));

    // The admin routes refuse a missing bearer before the body.
    let mut conn = TcpStream::connect(server.addr).await.unwrap();
    let a = post_slowly(&mut conn, "/admin/leases/revoke", "", b"{}").await;
    assert_eq!(a.status, 401);
    assert_eq!(a.header("connection"), Some("close"));
}

#[tokio::test]
async fn an_answer_after_the_body_is_read_keeps_the_connection_item63() {
    let dir = tempfile::tempdir().unwrap();
    let server = start(dir.path()).await;
    let mut conn = TcpStream::connect(server.addr).await.unwrap();

    // The admin token is right, so the body is read (and refused for its content): the
    // connection stays open and answers the next request.
    let a = post_slowly(
        &mut conn,
        "/admin/leases/revoke",
        "Authorization: Bearer early-close-admin\r\n",
        b"{}",
    )
    .await;
    assert!(a.status >= 400, "status {}", a.status);
    assert_eq!(a.header("connection"), None);

    // A request with no body.
    conn.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let a = read_answer(&mut conn).await;
    assert_eq!(a.status, 200);
    assert_eq!(a.header("connection"), None);
    conn.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_answer(&mut conn).await.status,
        200,
        "connection reused"
    );
}
