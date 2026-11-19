//! `attenuo health`, the probe the container image runs as its `HEALTHCHECK`: 0 against a real
//! server's `/healthz` and `/readyz`, 1 (never 2, which Docker reserves) when the server is not
//! ready, answers something else, is not there, or hangs; and it needs no token.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use attenuo_proxy::testing::spawn_router;
use attenuo_server::Config;
use serde_json::Value;

use common::attenuo;

async fn run(mut cmd: Command) -> Output {
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

fn health(url: &str, extra: &[&str]) -> Command {
    let mut c = attenuo();
    c.args(["--server", url, "health"]).args(extra);
    c
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

/// A listener that answers each of `answers` (status line, body) once, in order.
fn scripted(answers: Vec<(&'static str, &'static str)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        for (status, body) in answers {
            let (mut sock, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !text(&req).contains("\r\n\r\n") {
                let n = sock.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
            }
            let resp = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).unwrap();
        }
    });
    url
}

#[tokio::test]
async fn health_and_ready_against_a_real_server() {
    let (router, _state) = attenuo_server::build(&Config::default()).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();

    // No admin token anywhere (common::attenuo removes ATTENUO_ADMIN_TOKEN).
    let out = run(health(&url, &[])).await;
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(
        text(&out.stdout).trim(),
        format!("ok (attenuo-server {})", env!("CARGO_PKG_VERSION"))
    );

    let out = run(health(&url, &["--ready"])).await;
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(text(&out.stdout).starts_with("ready "), "{out:?}");

    let out = run(health(&url, &["--ready", "--json"])).await;
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["ready"], true);
    assert_eq!(body["checks"]["audit"], "ok");

    // ATTENUO_SERVER is honoured like for every other command.
    let mut c = attenuo();
    c.env("ATTENUO_SERVER", &url).arg("health");
    assert_eq!(run(c).await.status.code(), Some(0));
}

#[tokio::test]
async fn not_ready_or_not_attenuo_exits_1() {
    let url = scripted(vec![
        (
            "503 Service Unavailable",
            r#"{"ready":false,"checks":{"audit":"ok","audit_append":"error","leases":"ok"}}"#,
        ),
        ("200 OK", "<html>it works</html>"),
        ("404 Not Found", ""),
    ]);
    let out = run(health(&url, &["--ready"])).await;
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let err = text(&out.stderr);
    assert!(err.contains("/readyz answered 503"), "{err}");
    assert!(err.contains("audit_append"), "{err}");
    assert!(out.stdout.is_empty(), "{out:?}");

    // Something else on the port: a 200 that is not attenuo's answer is not healthy.
    let out = run(health(&url, &[])).await;
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(text(&out.stderr).contains("not with JSON"), "{out:?}");

    // The admin listener, for example, has no /healthz.
    let out = run(health(&url, &[])).await;
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(text(&out.stderr).contains("404"), "{out:?}");
}

#[tokio::test]
async fn unreachable_or_hung_server_exits_1() {
    // A port nobody listens on.
    let free = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", free.local_addr().unwrap());
    drop(free);
    let out = run(health(&url, &[])).await;
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        text(&out.stderr).contains("could not reach the server"),
        "{out:?}"
    );

    // A server that accepts and never answers: --timeout bounds the wait.
    let hung = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", hung.local_addr().unwrap());
    let started = Instant::now();
    let out = run(health(&url, &["--timeout", "1"])).await;
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(started.elapsed() < Duration::from_secs(10), "{out:?}");
    drop(hung);

    // A timeout of 0 would never time out a hung probe; it is refused like any usage error.
    let out = run(health(&url, &["--timeout", "0"])).await;
    assert_eq!(out.status.code(), Some(1), "{out:?}");
}
