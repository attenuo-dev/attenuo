//! SR-21: an export cross-checked against checkpoints that were shipped off the host. An
//! attacker holding the signing key can rewrite the log and re-sign every checkpoint (the
//! export then verifies on its own); the shipped copies still catch it.

mod common;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use common::record;
use onbehalf_audit::{
    checkpoint_line, cross_check, entry_line, header_line, parse_export, parse_shipped,
    verify_export, AuditSink, CheckpointKeys, ExportHeader, ShippedCheckpoint, SqliteAudit,
};
use onbehalf_token::{Issuer, IssuerConfig};
use serde_json::{json, Value};
use time::Duration;

fn issuer() -> Issuer {
    Issuer::generate(IssuerConfig {
        issuer: "https://onbehalf.test".into(),
        audience: "onbehalf".into(),
        max_depth: 4,
        default_ttl: Duration::minutes(5),
    })
}

fn keys(issuer: &Issuer) -> CheckpointKeys {
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
    CheckpointKeys::from_jwks(&json!({ "keys": keys })).unwrap()
}

/// A log of `n` entries starting at record `offset`, checkpointed every 2.
fn log(issuer: &Issuer, offset: usize, n: usize) -> SqliteAudit {
    let log = SqliteAudit::open_in_memory()
        .unwrap()
        .with_checkpointing(issuer.detached_signer(), 2);
    for i in offset..offset + n {
        log.append(record(i)).unwrap();
    }
    log
}

fn export_text(log: &SqliteAudit, from: u64, to: u64) -> String {
    let mut out = header_line(&ExportHeader::new(from, to, "2026-10-23T00:00:00Z".into()));
    for e in log.range(from, (to - from + 1) as usize).unwrap() {
        out.push_str(&entry_line(&e));
    }
    for c in log.checkpoints_between(from, to).unwrap() {
        out.push_str(&checkpoint_line(&c));
    }
    out
}

/// What the file sink would have written for `log`'s checkpoints.
fn shipped_text(log: &SqliteAudit, to: u64) -> String {
    log.checkpoints_between(0, to)
        .unwrap()
        .iter()
        .map(|c| ShippedCheckpoint::new(c, Some("https://ob.example".into())).to_line())
        .collect()
}

#[test]
fn a_genuine_export_matches_what_was_shipped_sr21() {
    let iss = issuer();
    let a = log(&iss, 0, 6);
    let export = parse_export(&export_text(&a, 1, 6)).unwrap();
    let shipped = parse_shipped(&shipped_text(&a, 6)).unwrap();
    let r = cross_check(&export, &shipped, &keys(&iss));
    assert!(r.ok, "{r:?}");
    assert_eq!(
        (r.shipped, r.in_range, r.matched, r.beyond_range),
        (3, 3, 3, 0)
    );
    assert_eq!(r.last_shipped_seq, Some(6));
    // A retried delivery (the same line twice) is fine.
    let twice = format!("{0}{0}", shipped_text(&a, 6));
    assert!(cross_check(&export, &parse_shipped(&twice).unwrap(), &keys(&iss)).ok);
}

#[test]
fn a_rewritten_and_re_signed_log_is_caught_by_the_shipped_copies_sr21() {
    let iss = issuer();
    let original = log(&iss, 0, 6);
    let shipped = parse_shipped(&shipped_text(&original, 6)).unwrap();
    // The attacker rewrites history and signs fresh checkpoints with the same key.
    let forged = log(&iss, 100, 6);
    let export = parse_export(&export_text(&forged, 1, 6)).unwrap();
    assert!(
        verify_export(&export, &keys(&iss)).unwrap().report.ok,
        "verifies on its own"
    );

    let r = cross_check(&export, &shipped, &keys(&iss));
    assert!(!r.ok);
    assert_eq!(r.mismatches.len(), 3);
    for m in &r.mismatches {
        assert!(m.reason.contains("RE-SIGNED after shipping"), "{m:?}");
        assert!(m.reason.contains("head_hash"), "{m:?}");
        assert!(m.reason.contains("history rewritten"), "{m:?}");
    }
}

#[test]
fn deleted_forged_and_duplicate_shipped_checkpoints_are_reported_sr21() {
    let iss = issuer();
    let a = log(&iss, 0, 6);
    let shipped_a = shipped_text(&a, 6);

    // The export lost its checkpoint at seq 4.
    let text: String = export_text(&a, 1, 6)
        .lines()
        .filter(|l| !(l.contains("\"type\":\"checkpoint\"") && l.contains("\"seq\":4,")))
        .map(|l| format!("{l}\n"))
        .collect();
    let r = cross_check(
        &parse_export(&text).unwrap(),
        &parse_shipped(&shipped_a).unwrap(),
        &keys(&iss),
    );
    assert_eq!(r.mismatches.len(), 1);
    assert_eq!(r.mismatches[0].seq, 4);
    assert!(r.mismatches[0].reason.contains("deleted after shipping"));

    let export = parse_export(&export_text(&a, 1, 6)).unwrap();
    // The sink got a second, different checkpoint for seq 2 (re-signed and shipped again).
    let b = log(&iss, 100, 2);
    let dup = format!("{shipped_a}{}", shipped_text(&b, 2));
    let r = cross_check(&export, &parse_shipped(&dup).unwrap(), &keys(&iss));
    assert_eq!(r.mismatches.len(), 1);
    assert_eq!(r.mismatches[0].line, 4);
    assert!(r.mismatches[0].reason.contains("two different checkpoints"));

    // A shipped copy signed by a key the JWKS does not hold is not trusted.
    let other = issuer();
    let foreign = shipped_text(&log(&other, 0, 2), 2);
    let r = cross_check(&export, &parse_shipped(&foreign).unwrap(), &keys(&iss));
    assert!(r.mismatches[0].reason.contains("does not verify"), "{r:?}");
}

#[test]
fn shipped_checkpoints_past_the_export_are_counted_not_checked_sr21() {
    let iss = issuer();
    let a = log(&iss, 0, 6);
    let export = parse_export(&export_text(&a, 1, 4)).unwrap();
    let r = cross_check(
        &export,
        &parse_shipped(&shipped_text(&a, 6)).unwrap(),
        &keys(&iss),
    );
    assert!(r.ok);
    assert_eq!((r.in_range, r.matched, r.beyond_range), (2, 2, 1));
}
