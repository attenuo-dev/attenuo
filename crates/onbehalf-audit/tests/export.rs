//! Export format: round trip, offline verification, windows, truncation and tampering.

mod common;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use common::{record, t0};
use onbehalf_audit::{
    checkpoint_line, compute_entry_hash, entry_line, header_line, parse_export, to_json_form,
    verify_export, verify_export_with, AuditSink, CheckpointKeys, ExportHeader, SqliteAudit,
    VerifyOptions,
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

fn jwks(issuer: &Issuer) -> Value {
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
    json!({ "keys": keys })
}

fn log(issuer: &Issuer, every: u64, n: usize) -> SqliteAudit {
    let log = SqliteAudit::open_in_memory()
        .unwrap()
        .with_checkpointing(issuer.detached_signer(), every);
    for i in 0..n {
        log.append(record(i)).unwrap();
    }
    log
}

/// `text` without the entry lines whose seq is in `drop`.
fn without_entries(text: &str, drop: &[u64]) -> String {
    text.lines()
        .filter(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            !(v["type"] == "entry" && drop.contains(&v["seq"].as_u64().unwrap()))
        })
        .map(|l| format!("{l}\n"))
        .collect()
}

/// What `GET /admin/audit/export?from&to` writes.
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

#[test]
fn full_export_round_trips_and_verifies_with_only_the_jwks() {
    let issuer = issuer();
    let log = log(&issuer, 4, 10);
    let text = export_text(&log, 1, 10);
    assert_eq!(text.lines().count(), 1 + 10 + 2);
    assert!(text.lines().all(|l| l.starts_with("{\"")));

    let export = parse_export(&text).unwrap();
    assert_eq!(export.entries.len(), 10);
    assert_eq!(export.checkpoints.len(), 2);
    assert_eq!(export.entries, log.range(1, 100).unwrap());

    let keys = CheckpointKeys::from_jwks(&jwks(&issuer)).unwrap();
    // Entries 9 and 10 come after the last checkpoint (8): strict verification refuses them.
    let r = verify_export(&export, &keys).unwrap();
    assert!(!r.report.ok && r.unsigned_tail_rejected, "{r:?}");
    assert!(r.report.first_bad_seq.is_none() && r.report.bad_checkpoints.is_empty());
    assert_eq!(r.report.unsigned_tail, 2);
    // Accepting an export newer than its last checkpoint is an explicit choice.
    let allow = VerifyOptions {
        allow_unsigned_tail: true,
    };
    let r = verify_export_with(&export, &keys, allow).unwrap();
    assert!(r.report.ok && !r.unsigned_tail_rejected, "{r:?}");
    assert!(r.from_genesis && !r.truncated);
    assert_eq!(r.outside_range, 0);
    assert_eq!((r.first_seq, r.last_seq), (Some(1), Some(10)));
    assert_eq!(r.report.last_signed_seq, Some(8));
    assert_eq!(r.report.unsigned_tail, 2);
    // Up to the last checkpoint, strict verification passes.
    let signed = parse_export(&export_text(&log, 1, 8)).unwrap();
    let r = verify_export(&signed, &keys).unwrap();
    assert!(r.report.ok && r.report.unsigned_tail == 0, "{r:?}");

    // The single-object JSON form carries the same content.
    let json_form = to_json_form(&export).to_string();
    assert_eq!(parse_export(&json_form).unwrap(), export);
}

#[test]
fn window_export_verifies_and_says_it_is_not_from_genesis() {
    let issuer = issuer();
    let log = log(&issuer, 4, 12);
    let export = parse_export(&export_text(&log, 5, 12)).unwrap();
    assert_eq!(export.entries[0].seq, 5);
    // The checkpoint at 4 is outside the window and left out; 8 and 12 are inside.
    assert_eq!(
        export.checkpoints.iter().map(|c| c.seq).collect::<Vec<_>>(),
        [8, 12]
    );
    let keys = CheckpointKeys::from_jwks(&jwks(&issuer)).unwrap();
    let r = verify_export(&export, &keys).unwrap();
    assert!(r.report.ok, "{r:?}");
    assert!(!r.from_genesis);
    assert_eq!(r.report.last_signed_seq, Some(12));
}

#[test]
fn editing_an_exported_entry_is_detected() {
    let issuer = issuer();
    let log = log(&issuer, 4, 8);
    let text = export_text(&log, 1, 8);
    let edited = text.replacen("policy_allow", "policy_deny_", 1);
    assert_ne!(edited, text);
    let keys = CheckpointKeys::from_jwks(&jwks(&issuer)).unwrap();
    let r = verify_export(&parse_export(&edited).unwrap(), &keys).unwrap();
    assert!(!r.report.ok);
    assert_eq!(r.report.first_bad_seq, Some(1));
    assert_eq!(r.report.last_signed_seq, None);
}

#[test]
fn dropped_entries_and_swapped_history_are_detected() {
    let issuer = issuer();
    let log = log(&issuer, 4, 8);
    let keys = CheckpointKeys::from_jwks(&jwks(&issuer)).unwrap();

    // An entry removed from the middle.
    let text = export_text(&log, 1, 8);
    let without_5 = without_entries(&text, &[5]);
    assert_ne!(without_5, text);
    let r = verify_export(&parse_export(&without_5).unwrap(), &keys).unwrap();
    assert!(!r.report.ok);
    assert_eq!(r.report.first_bad_seq, Some(6));

    // Entries cut from the end: the header still names `to = 8`.
    let cut = without_entries(&text, &[7, 8]);
    let r = verify_export(&parse_export(&cut).unwrap(), &keys).unwrap();
    assert!(r.truncated && !r.report.ok);
    // ...and the checkpoint at 8 now points past the end of the file.
    assert!(r.report.bad_checkpoints.is_empty() || r.report.bad_checkpoints[0].seq == 8);

    // Entries cut from the start of a window export.
    let from_3 = export_text(&log, 3, 8).replace("\"from\":3", "\"from\":1");
    let r = verify_export(&parse_export(&from_3).unwrap(), &keys).unwrap();
    assert!(r.truncated && !r.report.ok);
}

#[test]
fn forged_or_foreign_checkpoints_in_an_export_are_rejected() {
    let issuer = issuer();
    let attacker = self::issuer();
    let log = log(&issuer, 4, 8);
    let keys = CheckpointKeys::from_jwks(&jwks(&issuer)).unwrap();

    let mut export = parse_export(&export_text(&log, 1, 8)).unwrap();
    let head_hash = export.entries[7].entry_hash.clone();
    export.checkpoints.push(
        onbehalf_audit::Checkpoint::sign(&attacker.detached_signer(), 8, &head_hash, t0()).unwrap(),
    );
    let r = verify_export(&export, &keys).unwrap();
    assert!(!r.report.ok);
    assert!(r
        .report
        .bad_checkpoints
        .iter()
        .any(|b| b.reason.contains("unknown signing key")));
    // The genuine checkpoint at 4 and 8 still counted.
    assert_eq!(r.report.last_signed_seq, Some(8));
}

/// SR-20: every line of an export is RFC 8785 canonical JSON.
#[test]
fn export_lines_are_canonical_json_sr20() {
    let issuer = issuer();
    let log = log(&issuer, 2, 3);
    let text = export_text(&log, 1, 3);
    assert!(text.starts_with("{\"exported_at\":"), "{text}");
    assert!(text.contains("\"format\":\"onbehalf-audit-export-v2\""));
    for line in text.lines() {
        let v: Value = serde_json::from_str(line).unwrap();
        assert_eq!(onbehalf_core::jcs::to_string(&v).unwrap(), line);
    }
}

/// Fuzzing F5: a signed export of `1..=8` with a forged entry 9 appended (chained to 8 and
/// hashed correctly) used to verify `ok` with `unsigned_tail = 1`. The file holds more than
/// its header declares, so it fails, with or without `allow_unsigned_tail`.
#[test]
fn entries_after_the_declared_range_fail_the_export_f5() {
    let issuer = issuer();
    let log = log(&issuer, 4, 8);
    let keys = CheckpointKeys::from_jwks(&jwks(&issuer)).unwrap();
    let mut export = parse_export(&export_text(&log, 1, 8)).unwrap();
    assert!(verify_export(&export, &keys).unwrap().report.ok);
    let mut forged = export.entries[7].clone();
    forged.seq = 9;
    forged.prev_hash = export.entries[7].entry_hash.clone();
    forged.record.reason = "forged".into();
    forged.entry_hash = compute_entry_hash(forged.seq, &forged.prev_hash, &forged.record);
    export.entries.push(forged);
    for allow_unsigned_tail in [false, true] {
        let r = verify_export_with(
            &export,
            &keys,
            VerifyOptions {
                allow_unsigned_tail,
            },
        )
        .unwrap();
        assert!(!r.report.ok, "{r:?}");
        assert_eq!(r.outside_range, 1);
        // The chain itself is intact: only the range (and the tail) give it away.
        assert!(r.report.first_bad_seq.is_none());
        assert_eq!(r.report.unsigned_tail, 1);
        assert_eq!(r.unsigned_tail_rejected, !allow_unsigned_tail);
    }
    // An entry before `from` is outside the range too.
    let mut window = parse_export(&export_text(&log, 5, 8)).unwrap();
    window.header.as_mut().unwrap().from = 6;
    let r = verify_export(&window, &keys).unwrap();
    assert!(!r.report.ok && r.outside_range == 1 && r.truncated);
}

/// Fuzzing F4, the board's reproducer: a valid export whose first entry is renumbered to
/// `u64::MAX` and re-hashed fails cleanly instead of overflowing in the chain walk.
#[test]
fn an_export_entry_at_u64_max_fails_cleanly_f4() {
    let issuer = issuer();
    let log = log(&issuer, 4, 5);
    let keys = CheckpointKeys::from_jwks(&jwks(&issuer)).unwrap();
    let mut export = parse_export(&export_text(&log, 1, 5)).unwrap();
    let e = &mut export.entries[0];
    e.seq = u64::MAX;
    e.entry_hash = compute_entry_hash(e.seq, &e.prev_hash, &e.record);
    for allow_unsigned_tail in [false, true] {
        let r = verify_export_with(
            &export,
            &keys,
            VerifyOptions {
                allow_unsigned_tail,
            },
        )
        .unwrap();
        assert!(!r.report.ok, "{r:?}");
        assert_eq!(r.report.first_bad_seq, Some(u64::MAX));
    }
}

/// The header is required (it declares the range), and a `v1` export is refused with a
/// message that says why.
#[test]
fn exports_need_a_v2_header_sr20() {
    let issuer = issuer();
    let log = log(&issuer, 4, 4);
    let text = export_text(&log, 1, 4);
    let headerless: String = text.lines().skip(1).map(|l| format!("{l}\n")).collect();
    let err = parse_export(&headerless).unwrap_err().to_string();
    assert!(err.contains("no header"), "{err}");
    let mut export = parse_export(&text).unwrap();
    let json_form = to_json_form(&export);
    let mut no_header = json_form.clone();
    no_header.as_object_mut().unwrap().remove("header");
    assert!(parse_export(&no_header.to_string()).is_err());
    export.header = None;
    let keys = CheckpointKeys::from_jwks(&jwks(&issuer)).unwrap();
    assert!(verify_export(&export, &keys).is_err());
    let v1 = text.replace("onbehalf-audit-export-v2", "onbehalf-audit-export-v1");
    let err = parse_export(&v1).unwrap_err().to_string();
    assert!(
        err.contains("earlier onbehalf") && err.contains("RFC 8785"),
        "{err}"
    );
}

#[test]
fn parser_rejects_garbage_unknown_lines_and_foreign_formats() {
    assert!(parse_export("not json").is_err());
    assert!(parse_export("{\"type\":\"mystery\"}").is_err());
    let bad_format =
        "{\"type\":\"header\",\"format\":\"other-v9\",\"from\":1,\"to\":1,\"exported_at\":\"x\"}";
    assert!(parse_export(bad_format).is_err());
    let two_headers = format!(
        "{}{}",
        header_line(&ExportHeader::new(1, 1, "x".into())),
        header_line(&ExportHeader::new(1, 1, "x".into()))
    );
    assert!(parse_export(&two_headers).is_err());
    // Blank lines are fine; an empty log exports as just a header.
    let empty = format!("\n{}\n", header_line(&ExportHeader::new(1, 0, "x".into())));
    let e = parse_export(&empty).unwrap();
    assert!(e.entries.is_empty());
    let keys = CheckpointKeys::from_jwks(&jwks(&issuer())).unwrap();
    let r = verify_export(&e, &keys).unwrap();
    assert!(r.report.ok && !r.truncated);
}
