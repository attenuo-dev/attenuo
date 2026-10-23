//! SR-21: `attenuo audit verify --file <export> --checkpoints <shipped>` reports a
//! checkpoint signed again after it was shipped off the host.

#[path = "../../attenuo-audit/tests/common/mod.rs"]
mod common;

use std::process::Command;

use attenuo_audit::{
    checkpoint_line, entry_line, header_line, AuditSink, ExportHeader, ShippedCheckpoint,
    SqliteAudit,
};
use attenuo_token::{Issuer, IssuerConfig};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};

fn attenuo() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_attenuo"));
    for var in ["ATTENUO_ADMIN_TOKEN", "ATTENUO_SERVER", "ATTENUO_TOKEN"] {
        c.env_remove(var);
    }
    c
}

fn log(issuer: &Issuer, offset: usize) -> SqliteAudit {
    let log = SqliteAudit::open_in_memory()
        .unwrap()
        .with_checkpointing(issuer.detached_signer(), 2);
    for i in offset..offset + 6 {
        log.append(common::record(i)).unwrap();
    }
    log
}

fn export_text(log: &SqliteAudit) -> String {
    let mut out = header_line(&ExportHeader::new(1, 6, "2026-10-23T00:00:00Z".into()));
    for e in log.range(1, 6).unwrap() {
        out.push_str(&entry_line(&e));
    }
    for c in log.checkpoints_between(1, 6).unwrap() {
        out.push_str(&checkpoint_line(&c));
    }
    out
}

#[test]
fn audit_verify_cross_checks_shipped_checkpoints_sr21() {
    let issuer = Issuer::generate(IssuerConfig {
        issuer: "https://attenuo.test".into(),
        audience: "attenuo".into(),
        max_depth: 4,
        default_ttl: time::Duration::minutes(5),
    });
    let keys: Vec<Value> = issuer
        .trusted_public_keys()
        .into_iter()
        .map(|(kid, pem)| {
            let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            let der = STANDARD.decode(b64).unwrap();
            json!({"kty": "OKP", "crv": "Ed25519", "kid": kid,
                   "x": URL_SAFE_NO_PAD.encode(&der[der.len() - 32..])})
        })
        .collect();
    let dir = tempfile::tempdir().unwrap();
    let path = |n: &str| dir.path().join(n);
    std::fs::write(path("jwks.json"), json!({ "keys": keys }).to_string()).unwrap();

    let original = log(&issuer, 0);
    let shipped: String = original
        .checkpoints_between(0, 6)
        .unwrap()
        .iter()
        .map(|c| ShippedCheckpoint::new(c, None).to_line())
        .collect();
    std::fs::write(path("shipped.jsonl"), shipped).unwrap();
    std::fs::write(path("genuine.jsonl"), export_text(&original)).unwrap();
    // Rewritten history, re-signed with the same key.
    std::fs::write(path("tampered.jsonl"), export_text(&log(&issuer, 100))).unwrap();

    let run = |export: &str, extra: &[&str]| {
        let mut c = attenuo();
        c.args(["audit", "verify", "--file"])
            .arg(path(export))
            .arg("--jwks")
            .arg(path("jwks.json"))
            .args(extra);
        c.output().unwrap()
    };
    let shipped_arg = path("shipped.jsonl");
    let shipped_arg = shipped_arg.to_str().unwrap();

    let out = run("genuine.jsonl", &["--checkpoints", shipped_arg]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(
        text.contains("3 inside the export's range, 3 match"),
        "{text}"
    );
    assert!(text.contains("shipped checkpoints: OK"), "{text}");

    // Alone, the tampered export verifies: the attacker had the key.
    let out = run("tampered.jsonl", &[]);
    assert_eq!(out.status.code(), Some(0));

    let out = run("tampered.jsonl", &["--checkpoints", shipped_arg]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert_eq!(
        text.matches("RE-SIGNED after shipping").count(),
        3,
        "{text}"
    );
    assert!(text.contains("shipped checkpoints: FAILED"), "{text}");

    let out = run("tampered.jsonl", &["--checkpoints", shipped_arg, "--json"]);
    assert_eq!(out.status.code(), Some(2));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["shipped"]["ok"], false);
    assert_eq!(v["shipped"]["mismatches"].as_array().unwrap().len(), 3);
    assert_eq!(v["shipped"]["mismatches"][0]["seq"], 2);

    // A shipped file that is not checkpoints is an error, not a pass.
    std::fs::write(path("junk.jsonl"), "{\"type\":\"entry\"}\n").unwrap();
    let junk = path("junk.jsonl");
    let out = run("genuine.jsonl", &["--checkpoints", junk.to_str().unwrap()]);
    assert_ne!(out.status.code(), Some(0));
}
