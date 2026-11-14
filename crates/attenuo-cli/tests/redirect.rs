//! The CLI follows no redirect (SR-112, security review pass 13). It used to follow a `307`
//! from the server URL, as `reqwest` does by default, and send the request body again to the
//! other origin, client secret and subject token included. Now the other origin gets no
//! request and the CLI exits non-zero with an error naming the status and the `Location`.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use common::attenuo;

/// Reads one HTTP/1.1 request (headers and a `content-length` body) from `sock`.
fn read_request(sock: &mut std::net::TcpStream) -> String {
    let mut req = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let text = String::from_utf8_lossy(&req).to_string();
        if let Some(end) = text.find("\r\n\r\n") {
            let len = text[..end]
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            if req.len() >= end + 4 + len {
                return text;
            }
        }
        let n = sock.read(&mut buf).unwrap();
        if n == 0 {
            return String::from_utf8_lossy(&req).to_string();
        }
        req.extend_from_slice(&buf[..n]);
    }
}

/// A listener that records every request it gets and answers `400`.
fn collector() -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for sock in listener.incoming() {
            let mut sock = sock.unwrap();
            tx.send(read_request(&mut sock)).unwrap();
            let body = r#"{"error":"invalid_request"}"#;
            let resp = format!(
                "HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes());
        }
    });
    (url, rx)
}

/// A listener that answers every request with `307` to `location`.
fn redirector(location: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        for sock in listener.incoming() {
            let mut sock = sock.unwrap();
            read_request(&mut sock);
            let resp = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
            let _ = sock.write_all(resp.as_bytes());
        }
    });
    url
}

/// The CLI's standard error, after checking that it failed and that the other origin got no
/// request.
fn refused(out: &std::process::Output, seen: &mpsc::Receiver<String>, location: &str) -> String {
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!out.status.success(), "{err}");
    assert!(
        seen.recv_timeout(Duration::from_millis(500)).is_err(),
        "the other origin got a request"
    );
    assert!(err.contains("307 Temporary Redirect"), "{err}");
    assert!(err.contains(&format!("Location {location}")), "{err}");
    assert!(err.contains("does not follow redirects"), "{err}");
    err
}

#[test]
fn a_307_does_not_send_the_client_secret_to_the_other_origin_sr112() {
    let (other, seen) = collector();
    let location = format!("{other}/collect");
    let front = redirector(location.clone());
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret");
    std::fs::write(&secret, "sr112-client-secret\n").unwrap();
    let out = attenuo()
        .args(["--server", &front, "token", "exchange", "--actor", "coder"])
        .args(["--cap", r#"{"server":"gh","tool":"x"}"#])
        .arg("--client-secret-file")
        .arg(&secret)
        .env("ATTENUO_TOKEN", "a.b.c")
        .output()
        .unwrap();
    let err = refused(&out, &seen, &location);
    assert!(err.contains("--server must be the final URL"), "{err}");
    assert!(!err.contains("sr112-client-secret"), "{err}");
}

#[test]
fn a_307_on_an_admin_request_is_refused_sr112() {
    let (other, seen) = collector();
    let location = format!("{other}/collect");
    let front = redirector(location.clone());
    let out = attenuo()
        .args(["--admin-server", &front, "lease", "revoke"])
        .args(["--chain-id", "00000000-0000-4000-8000-000000000000"])
        .env("ATTENUO_ADMIN_TOKEN", "sr112-admin-token-0123456789abcdef")
        .output()
        .unwrap();
    let err = refused(&out, &seen, &location);
    assert!(
        err.contains("--admin-server must be the final URL"),
        "{err}"
    );
}

#[test]
fn health_reports_a_redirect_and_exits_1_sr112() {
    let (other, seen) = collector();
    let location = format!("{other}/healthz");
    let front = redirector(location.clone());
    let out = attenuo()
        .args(["--server", &front, "health"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    refused(&out, &seen, &location);
}
