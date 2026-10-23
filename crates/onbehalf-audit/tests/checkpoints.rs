//! Signed checkpoints: creation, automatic cadence, forgery, tampering, truncation, rotation.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use common::{record, t0};
use onbehalf_audit::{
    AuditError, AuditSink, Checkpoint, CheckpointKeys, SqliteAudit, GENESIS_HASH,
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

/// The JWKS the server would publish for `issuer` (current key, then retired ones).
fn jwks(issuer: &Issuer) -> Value {
    let keys: Vec<Value> = issuer
        .trusted_public_keys()
        .into_iter()
        .map(|(kid, pem)| {
            let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            let der = STANDARD.decode(b64).unwrap();
            json!({"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
                   "kid": kid, "x": URL_SAFE_NO_PAD.encode(&der[der.len() - 32..])})
        })
        .collect();
    json!({ "keys": keys })
}

fn keys(issuer: &Issuer) -> CheckpointKeys {
    CheckpointKeys::from_jwks(&jwks(issuer)).unwrap()
}

fn log_with(issuer: &Issuer, every: u64, n: usize) -> SqliteAudit {
    let log = SqliteAudit::open_in_memory()
        .unwrap()
        .with_checkpointing(issuer.detached_signer(), every);
    for i in 0..n {
        log.append(record(i)).unwrap();
    }
    log
}

fn exec(log: &SqliteAudit, sql: &str, params: &[&dyn rusqlite::ToSql]) {
    log.with_connection(|c| {
        c.execute(sql, params)?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn automatic_checkpoints_every_n_entries_and_report_last_signed_seq() {
    let issuer = issuer();
    let log = log_with(&issuer, 5, 13);
    let cps = log.checkpoints_between(0, u64::MAX).unwrap();
    assert_eq!(cps.iter().map(|c| c.seq).collect::<Vec<_>>(), [5, 10]);
    for cp in &cps {
        assert_eq!(cp.kid, issuer.key_id());
        assert_eq!(
            cp.head_hash,
            log.range(cp.seq, 1).unwrap()[0].entry_hash,
            "checkpoint {} covers the entry hash at its seq",
            cp.seq
        );
    }
    let report = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(report.ok, "{report:?}");
    assert_eq!(report.entries, 13);
    assert_eq!(report.checkpoints, 2);
    assert_eq!(report.last_signed_seq, Some(10));
    assert_eq!(report.unsigned_tail, 3);
    assert!(report.bad_checkpoints.is_empty());
}

#[test]
fn manual_checkpoint_is_signed_stored_and_idempotent() {
    let issuer = issuer();
    let log = log_with(&issuer, 1000, 3);
    let cp = log.checkpoint_signed(t0()).unwrap();
    assert_eq!(cp.seq, 3);
    assert_eq!(cp.head_hash, log.head().unwrap().unwrap().entry_hash);
    assert_eq!(cp.at, "2026-10-22T21:00:00Z");
    assert_eq!(
        log.checkpoint_signed(t0() + Duration::hours(1)).unwrap(),
        cp
    );
    assert_eq!(log.last_checkpoint().unwrap(), Some(cp.clone()));
    // Nothing new to sign until the head moves.
    assert_eq!(log.checkpoint_if_new(t0()).unwrap(), None);
    log.append(record(3)).unwrap();
    let next = log.checkpoint_if_new(t0()).unwrap().unwrap();
    assert_eq!(next.seq, 4);

    let report = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(report.ok, "{report:?}");
    assert_eq!(report.last_signed_seq, Some(4));
    assert_eq!(report.unsigned_tail, 0);
}

#[test]
fn empty_log_checkpoints_at_genesis_and_without_a_signer_it_errors() {
    let issuer = issuer();
    let log = log_with(&issuer, 10, 0);
    let cp = log.checkpoint_signed(t0()).unwrap();
    assert_eq!((cp.seq, cp.head_hash.as_str()), (0, GENESIS_HASH));
    assert!(log.verify_chain_signed(&keys(&issuer)).unwrap().ok);
    assert_eq!(log.checkpoint_if_new(t0()).unwrap(), None);

    let bare = SqliteAudit::open_in_memory().unwrap();
    assert!(matches!(
        bare.checkpoint_signed(t0()),
        Err(AuditError::NoCheckpointSigner)
    ));
}

#[test]
fn hook_fires_once_per_new_checkpoint() {
    let issuer = issuer();
    let count = Arc::new(AtomicU64::new(0));
    let c = count.clone();
    let log = SqliteAudit::open_in_memory()
        .unwrap()
        .with_checkpointing(issuer.detached_signer(), 2)
        .with_checkpoint_hook(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        });
    for i in 0..5 {
        log.append(record(i)).unwrap();
    }
    assert_eq!(count.load(Ordering::SeqCst), 2); // seq 2 and 4
    log.checkpoint_signed(t0()).unwrap(); // seq 5: new
    log.checkpoint_signed(t0()).unwrap(); // repeat: not counted
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

#[test]
fn forged_checkpoints_are_rejected() {
    let issuer = issuer();
    let log = log_with(&issuer, 5, 10);
    let head = log.range(10, 1).unwrap().remove(0);

    // Signed by a key the JWKS does not list.
    let attacker = self::issuer();
    let forged = Checkpoint::sign(&attacker.detached_signer(), 10, &head.entry_hash, t0()).unwrap();
    exec(&log, "DELETE FROM checkpoints WHERE seq = 10", &[]);
    exec(
        &log,
        "INSERT INTO checkpoints (seq, head_hash, at, kid, signature) VALUES (?1,?2,?3,?4,?5)",
        &[
            &10i64,
            &forged.head_hash,
            &forged.at,
            &forged.kid,
            &forged.signature,
        ],
    );
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(!r.ok);
    assert_eq!(r.bad_checkpoints.len(), 1);
    assert!(r.bad_checkpoints[0].reason.contains("unknown signing key"));
    assert_eq!(r.last_signed_seq, Some(5));

    // Claims the real key's kid but carries the attacker's signature.
    exec(
        &log,
        "UPDATE checkpoints SET kid = ?1 WHERE seq = 10",
        &[&issuer.key_id()],
    );
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(!r.ok);
    assert_eq!(r.bad_checkpoints[0].reason, "signature does not verify");

    // A genuine checkpoint with its fields edited (here: the timestamp) no longer verifies.
    let genuine = log.checkpoints_between(5, 5).unwrap().remove(0);
    exec(
        &log,
        "UPDATE checkpoints SET at = '2030-01-01T00:00:00Z' WHERE seq = 5",
        &[],
    );
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(r.bad_checkpoints.iter().any(|b| b.seq == 5));
    assert_eq!(r.last_signed_seq, None);
    assert_ne!(genuine.at, "2030-01-01T00:00:00Z");
}

#[test]
fn checkpoint_signature_is_not_valid_under_another_context() {
    let issuer = issuer();
    let log = log_with(&issuer, 1000, 2);
    let cp = log.checkpoint_signed(t0()).unwrap();
    let k = keys(&issuer);
    assert!(k.verify(&cp).is_ok());
    // The same bytes signed under a different context string must not pass as a checkpoint.
    let other = issuer
        .detached_signer()
        .sign("onbehalf-checkpoint-v2", &cp.signing_payload());
    let swapped = Checkpoint {
        signature: other,
        ..cp
    };
    assert!(k.verify(&swapped).is_err());
}

#[test]
fn tampered_entry_after_a_checkpoint_is_detected() {
    let issuer = issuer();
    let log = log_with(&issuer, 5, 9);
    exec(
        &log,
        "UPDATE audit SET reason = 'edited' WHERE seq = 8",
        &[],
    );
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_seq, Some(8));
    // The checkpoint before the damage still stands.
    assert_eq!(r.last_signed_seq, Some(5));
    assert!(r.bad_checkpoints.is_empty());
}

#[test]
fn tampered_entry_before_a_checkpoint_is_detected() {
    let issuer = issuer();
    let log = log_with(&issuer, 5, 9);
    exec(
        &log,
        "UPDATE audit SET reason = 'edited' WHERE seq = 3",
        &[],
    );
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_seq, Some(3));
    assert_eq!(r.last_signed_seq, None);
}

#[test]
fn rewriting_history_with_a_consistent_chain_still_fails_the_checkpoint() {
    let issuer = issuer();
    let log = log_with(&issuer, 5, 8);
    let cps = log.checkpoints_between(0, u64::MAX).unwrap();
    assert_eq!(cps.len(), 1);

    // An attacker with write access rebuilds the whole log with entry 2 changed, so every hash
    // from there on is internally consistent, and carries the old checkpoint row over.
    let rebuilt = SqliteAudit::open_in_memory().unwrap();
    for i in 0..8 {
        let mut rec = record(i);
        if i == 1 {
            rec.reason = "rewritten".into();
        }
        rebuilt.append(rec).unwrap();
    }
    assert!(rebuilt.verify_chain().unwrap().ok);
    let cp = &cps[0];
    exec(
        &rebuilt,
        "INSERT INTO checkpoints (seq, head_hash, at, kid, signature) VALUES (?1,?2,?3,?4,?5)",
        &[
            &(cp.seq as i64),
            &cp.head_hash,
            &cp.at,
            &cp.kid,
            &cp.signature,
        ],
    );
    let r = rebuilt.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_seq, None, "the chain alone looks fine");
    assert_eq!(r.bad_checkpoints.len(), 1);
    assert_eq!(
        r.bad_checkpoints[0].reason,
        "head hash differs from the log at that seq"
    );
}

#[test]
fn truncating_the_log_below_a_checkpoint_is_detected() {
    let issuer = issuer();
    let log = log_with(&issuer, 5, 8);
    exec(&log, "DELETE FROM audit WHERE seq > 3", &[]);
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(!r.ok);
    assert_eq!(r.bad_checkpoints.len(), 1);
    assert!(r.bad_checkpoints[0].reason.contains("truncated"));
}

#[test]
fn old_key_checkpoints_verify_after_rotation_only_while_the_old_key_is_listed() {
    let old = issuer();
    let log = log_with(&old, 4, 6); // checkpoint at 4 by the old key
    let old_cp = log.last_checkpoint().unwrap().unwrap();
    assert_eq!(old_cp.kid, old.key_id());

    // Rotation: a new key signs from here on, and the old one is kept as a previous key.
    let mut new = issuer();
    new.trust_previous_key(&old.public_key_pem()).unwrap();
    let log = log_with_continuing(log, &new, 4);
    let cps = log.checkpoints_between(0, u64::MAX).unwrap();
    assert_eq!(cps.iter().map(|c| c.seq).collect::<Vec<_>>(), [4, 8]);
    assert_eq!(cps[0].kid, old.key_id());
    assert_eq!(cps[1].kid, new.key_id());

    let r = log.verify_chain_signed(&keys(&new)).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(r.last_signed_seq, Some(8));

    // Drop the old key from the JWKS and the old checkpoint can no longer be vouched for.
    let only_new =
        CheckpointKeys::from_jwks(&json!({"keys": [jwks(&new)["keys"][0].clone()]})).unwrap();
    let r = log.verify_chain_signed(&only_new).unwrap();
    assert!(!r.ok);
    assert_eq!(r.bad_checkpoints.len(), 1);
    assert_eq!(r.bad_checkpoints[0].seq, 4);
    assert_eq!(r.last_signed_seq, Some(8));
}

/// Keep the stored rows of `log` but append further entries under `new`'s signer, by reopening
/// the same database through a fresh handle.
fn log_with_continuing(log: SqliteAudit, new: &Issuer, every: u64) -> SqliteAudit {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.sqlite");
    // Copy the in-memory database to disk so a second handle can adopt it.
    log.with_connection(|c| {
        c.execute("VACUUM INTO ?1", [path.to_str().unwrap()])?;
        Ok(())
    })
    .unwrap();
    let reopened = SqliteAudit::open(&path)
        .unwrap()
        .with_checkpointing(new.detached_signer(), every);
    for i in 6..8 {
        reopened.append(record(i)).unwrap();
    }
    // Keep the temp dir alive for the life of the process; the test is short.
    std::mem::forget(dir);
    reopened
}

#[test]
fn jwks_parsing_skips_foreign_keys_and_rejects_bad_ones() {
    let issuer = issuer();
    let mut doc = jwks(&issuer);
    doc["keys"]
        .as_array_mut()
        .unwrap()
        .push(json!({"kty": "RSA", "kid": "r", "n": "AQAB", "e": "AQAB"}));
    assert!(!CheckpointKeys::from_jwks(&doc).unwrap().is_empty());
    assert!(CheckpointKeys::from_jwks(&json!({"nope": 1})).is_err());
    let short = json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k", "x": "AAAA"}]});
    assert!(CheckpointKeys::from_jwks(&short).is_err());
}

// ---- group commit under concurrency ----

/// Many threads append to a file-backed log through the group-commit writer while another
/// thread verifies and asks for timer checkpoints. Afterwards the chain is contiguous, every
/// checkpoint (automatic and timer) verifies, each thread saw its own appends in increasing
/// order, and every returned entry is exactly what is stored at its seq.
#[test]
fn group_commit_keeps_the_chain_and_checkpoints_under_concurrency() {
    use onbehalf_audit::Durability;
    let threads = 8;
    let per_thread = 40;
    let total = (threads * per_thread) as u64;
    for durability in [Durability::Normal, Durability::Full] {
        let issuer = issuer();
        let dir = tempfile::tempdir().unwrap();
        let hooked = Arc::new(AtomicU64::new(0));
        let counter = hooked.clone();
        let log = Arc::new(
            SqliteAudit::open_with(dir.path().join("audit.db"), durability)
                .unwrap()
                .with_checkpointing(issuer.detached_signer(), 7)
                .with_checkpoint_hook(move |_| {
                    counter.fetch_add(1, Ordering::Relaxed);
                }),
        );
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let checker = {
            let (log, stop) = (log.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    assert!(log.verify_chain().unwrap().ok);
                    log.checkpoint_if_new(t0()).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            })
        };
        let writers: Vec<_> = (0..threads)
            .map(|t| {
                let log = log.clone();
                std::thread::spawn(move || {
                    (0..per_thread)
                        .map(|i| log.append(record(t * per_thread + i)).unwrap())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut returned = Vec::new();
        for w in writers {
            let mine = w.join().unwrap();
            assert!(
                mine.windows(2).all(|p| p[0].seq < p[1].seq),
                "{durability}: a thread's appends are ordered"
            );
            returned.extend(mine);
        }
        stop.store(true, Ordering::Relaxed);
        checker.join().unwrap();

        let report = log.verify_chain_signed(&keys(&issuer)).unwrap();
        assert!(report.ok, "{durability}: {report:?}");
        assert_eq!(report.entries, total, "{durability}");
        assert!(report.checkpoints >= total / 7, "{durability}: {report:?}");
        assert_eq!(report.checkpoints, hooked.load(Ordering::Relaxed));
        let stored = log.range(1, usize::MAX).unwrap();
        assert_eq!(
            stored.iter().map(|e| e.seq).collect::<Vec<_>>(),
            (1..=total).collect::<Vec<_>>()
        );
        returned.sort_by_key(|e| e.seq);
        assert_eq!(returned, stored, "{durability}: answers match the log");
        for cp in log.checkpoints_between(1, total).unwrap() {
            assert_eq!(cp.head_hash, stored[cp.seq as usize - 1].entry_hash);
        }
    }
}

/// A record the database refuses fails only its own append: the others in the same batch
/// are committed, and the log holds no trace of the refused one.
#[test]
fn a_refused_record_fails_only_its_own_append() {
    let log = Arc::new(SqliteAudit::open_in_memory().unwrap());
    exec(
        &log,
        "CREATE TRIGGER refuse BEFORE INSERT ON audit WHEN NEW.reason = 'boom' \
         BEGIN SELECT RAISE(ABORT, 'refused'); END",
        &[],
    );
    let writers: Vec<_> = (0..8)
        .map(|t| {
            let log = log.clone();
            std::thread::spawn(move || {
                (0..30)
                    .map(|i| {
                        let mut r = record(t * 30 + i);
                        let boom = i % 5 == 0;
                        if boom {
                            r.reason = "boom".into();
                        }
                        (boom, log.append(r))
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut ok = 0u64;
    for w in writers {
        for (boom, result) in w.join().unwrap() {
            match result {
                Ok(_) => {
                    assert!(!boom, "a refused record was reported as written");
                    ok += 1;
                }
                Err(e) => {
                    assert!(boom, "a good record failed: {e}");
                    assert!(e.to_string().contains("refused"), "{e}");
                }
            }
        }
    }
    assert_eq!(ok, 8 * 24);
    let report = log.verify_chain().unwrap();
    assert!(report.ok && report.entries == ok, "{report:?}");
    assert!(log
        .range(1, usize::MAX)
        .unwrap()
        .iter()
        .all(|e| e.record.reason != "boom"));
}
