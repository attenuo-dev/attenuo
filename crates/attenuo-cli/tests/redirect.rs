//! What the CLI does when the server URL answers a `307` to another origin (SR-112, security
//! review pass 13). Today it follows the redirect, as `reqwest` does by default: the request
//! body, client secret included, is sent again to the other origin; only `Authorization` is
//! dropped. The finding is open; this test pins today's behaviour and changes with the
//! maintainer's choice (the proposal is not to follow redirects, as the Python SDK does not).

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

#[test]
fn a_307_sends_the_client_secret_to_the_other_origin_sr112() {
    let (other, seen) = collector();
    let front = redirector(format!("{other}/collect"));
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
    assert!(!out.status.success());
    let req = seen
        .recv_timeout(Duration::from_secs(10))
        .expect("the redirect was followed");
    assert!(req.starts_with("POST /collect "), "{req}");
    // Today: the body crosses to the other origin, client secret and subject token included.
    assert!(req.contains("sr112-client-secret"), "{req}");
    assert!(req.contains(r#""subject_token":"a.b.c""#), "{req}");
}

#[test]
fn a_307_drops_the_admin_token_but_sends_the_body_sr112() {
    let (other, seen) = collector();
    let front = redirector(format!("{other}/collect"));
    let out = attenuo()
        .args(["--server", &front, "lease", "revoke"])
        .args(["--chain-id", "00000000-0000-4000-8000-000000000000"])
        .env("ATTENUO_ADMIN_TOKEN", "sr112-admin-token-0123456789abcdef")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let req = seen
        .recv_timeout(Duration::from_secs(10))
        .expect("the redirect was followed");
    assert!(!req.contains("sr112-admin-token"), "{req}");
    assert!(
        req.contains(r#""chain_id":"00000000-0000-4000-8000-000000000000""#),
        "{req}"
    );
}
