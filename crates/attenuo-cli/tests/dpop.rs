//! SR-24: `attenuo key gen --dpop` and `--dpop-key` put DPoP proofs on the wire. A one-shot
//! HTTP listener stands in for the server and records the request.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::{self, JoinHandle};

use common::attenuo;

/// Answers one request with `200 <body>` and returns the raw request text.
fn fake_server(body: &'static str) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut req = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = sock.read(&mut buf).unwrap();
            req.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&req).to_string();
            let Some(split) = text.find("\r\n\r\n") else {
                if n == 0 {
                    break;
                }
                continue;
            };
            let len = text[..split]
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::to_owned)
                })
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if req.len() >= split + 4 + len || n == 0 {
                break;
            }
        }
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(resp.as_bytes()).unwrap();
        String::from_utf8_lossy(&req).to_string()
    });
    (url, handle)
}

fn header<'a>(req: &'a str, name: &str) -> Option<&'a str> {
    req.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

#[test]
fn key_gen_and_call_with_a_dpop_key_sr24() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.jwk");
    let out = attenuo()
        .args(["--json", "key", "gen", "--dpop"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let key = attenuo_token::DpopKey::from_jwk(
        &serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(printed["jkt"], key.thumbprint());
    assert_eq!(printed["alg"], "EdDSA");
    // Never overwritten.
    let again = attenuo()
        .args(["key", "gen", "--dpop"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(again.status.code(), Some(1));

    let (url, server) = fake_server(r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#);
    let out = attenuo()
        .env("ATTENUO_TOKEN", "a.b.c")
        .args([
            "--server",
            &url,
            "call",
            "--server",
            "github",
            "--tool",
            "read_file",
        ])
        .arg("--dpop-key")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let req = server.join().unwrap();
    assert_eq!(header(&req, "authorization"), Some("DPoP a.b.c"));
    let proof = header(&req, "dpop").expect("a DPoP header");
    let v = attenuo_token::dpop::verify_proof(
        proof,
        &attenuo_token::dpop::ProofCheck {
            method: "POST",
            url: &format!("{url}/mcp/github"),
            access_token: Some("a.b.c"),
            now: time::OffsetDateTime::now_utc(),
            max_age: time::Duration::seconds(60),
        },
    )
    .unwrap();
    assert_eq!(v.jkt, key.thumbprint());
}
