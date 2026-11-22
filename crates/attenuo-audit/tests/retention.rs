//! Audit retention (ADR-0015): pruning a prefix of the log behind a signed anchor, the guards,
//! a crash at each step, resuming the deletes, verification of a pruned log and of the archive
//! and retained exports, and what an attacker who can write the file but holds no key can and
//! cannot pass off as a prune.

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use attenuo_audit::{
    checkpoint_line, cross_check, entry_line, header_line, parse_export, parse_shipped,
    verify_export, AnchorState, AuditEntry, AuditError, AuditSink, Checkpoint, CheckpointKeys,
    ExportHeader, LeaseRegistry, PlanBound, PruneGuard, PruneLimits, ShippedAnchor,
    ShippedCheckpoint, SinkProgress, SqliteAudit, SqliteLeaseStore, PRUNE_TOOL,
};
use attenuo_core::{Decision, DecisionRecord, LeaseId, RecordKind, ToolCall};
use attenuo_token::{Issuer, IssuerConfig};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use common::{record, t0};
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

fn issuer() -> Issuer {
    Issuer::generate(IssuerConfig {
        issuer: "https://attenuo.test".into(),
        audience: "attenuo".into(),
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
            json!({"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
                   "kid": kid, "x": URL_SAFE_NO_PAD.encode(&der[der.len() - 32..])})
        })
        .collect();
    CheckpointKeys::from_jwks(&json!({ "keys": keys })).unwrap()
}

/// Long after every record: nothing is too recent.
fn now() -> OffsetDateTime {
    t0() + Duration::days(200)
}

fn limits() -> PruneLimits {
    PruneLimits {
        min_age: Duration::days(90),
        sink: None,
        now: now(),
    }
}

/// The prune record, as the server writes it (`audit_admin`'s shape).
fn prune_record(arguments: &Value) -> DecisionRecord {
    let call = ToolCall::new("attenuo", PRUNE_TOOL, arguments.clone());
    DecisionRecord {
        id: uuid::Uuid::new_v4(),
        at: now(),
        kind: RecordKind::Admin,
        chain_id: None,
        decision: Decision::Allow,
        reason: "admin_action".into(),
        originating_subject: "urn:attenuo:admin".into(),
        agents: Vec::new(),
        chain_depth: 0,
        chain_digest: attenuo_core::digest::sha256_json(&Value::Null),
        leases: Vec::new(),
        server: "attenuo".into(),
        tool: call.tool.clone(),
        arguments_digest: call.arguments_digest(),
        session_id: None,
        policy_ids: Vec::new(),
        dpop_bound: false,
        decision_id: None,
        result: None,
        labels: None,
        approval: None,
        budget: None,
        usage: None,
        search: None,
        id_jag_ceiling: None,
    }
}

/// Hooks seen, in order: `cp <seq>` and `anchor <through>`.
type Seen = Arc<Mutex<Vec<String>>>;

fn hooked(log: SqliteAudit, seen: &Seen) -> SqliteAudit {
    let (a, b) = (seen.clone(), seen.clone());
    log.with_checkpoint_hook(move |cp| a.lock().unwrap().push(format!("cp {}", cp.seq)))
        .with_anchor_hook(move |an| b.lock().unwrap().push(format!("anchor {}", an.through_seq)))
}

/// A log of `n` entries with a checkpoint every `every`, in memory.
fn log_of(issuer: &Issuer, every: u64, n: usize) -> SqliteAudit {
    let log = SqliteAudit::open_in_memory()
        .unwrap()
        .with_checkpointing(issuer.detached_signer(), every);
    for i in 0..n {
        log.append(record(i)).unwrap();
    }
    log
}

fn file_log(path: &Path, issuer: &Issuer, every: u64) -> SqliteAudit {
    SqliteAudit::open(path)
        .unwrap()
        .with_checkpointing(issuer.detached_signer(), every)
}

fn prune(
    log: &SqliteAudit,
    through: u64,
    digest: Option<&str>,
) -> Result<attenuo_audit::PruneOutcome, AuditError> {
    log.prune_through(through, digest.map(str::to_string), &limits(), prune_record)
}

fn finish(log: &SqliteAudit, batch: usize) -> u64 {
    let mut deleted = 0;
    loop {
        let step = log.prune_step(batch).unwrap();
        deleted += step.deleted;
        if step.through_seq.is_none() || step.done {
            return deleted;
        }
    }
}

fn guard_of(e: AuditError) -> PruneGuard {
    match e {
        AuditError::PruneRefused { guard, .. } => guard,
        other => panic!("expected a prune refusal, got {other:?}"),
    }
}

/// Every row of the three tables a prune writes, for "nothing changed" checks.
fn snapshot(log: &SqliteAudit) -> BTreeMap<&'static str, Vec<String>> {
    log.with_connection(|c| {
        let mut out = BTreeMap::new();
        for (t, sql) in [
            (
                "audit",
                "SELECT seq || '|' || entry_hash FROM audit ORDER BY seq",
            ),
            (
                "checkpoints",
                "SELECT seq || '|' || head_hash || '|' || signature FROM checkpoints ORDER BY seq",
            ),
            (
                "audit_anchors",
                "SELECT through_seq || '|' || state FROM audit_anchors ORDER BY through_seq",
            ),
        ] {
            let mut stmt = c.prepare(sql)?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            out.insert(t, rows.collect::<Result<_, _>>()?);
        }
        Ok(out)
    })
    .unwrap()
}

fn exec(log: &SqliteAudit, sql: &str) {
    log.with_connection(|c| {
        c.execute_batch(sql)?;
        Ok(())
    })
    .unwrap();
}

/// An export file of `entries` and `checkpoints` with `header`, as the server streams it.
fn export_text(header: &ExportHeader, entries: &[AuditEntry], cps: &[Checkpoint]) -> String {
    let mut s = header_line(header);
    for e in entries {
        s.push_str(&entry_line(e));
    }
    for c in cps {
        s.push_str(&checkpoint_line(c));
    }
    s
}

fn range(log: &SqliteAudit, from: u64, to: u64) -> Vec<AuditEntry> {
    log.range(from, 1_000_000)
        .unwrap()
        .into_iter()
        .filter(|e| e.seq <= to)
        .collect()
}

// --- the attack cases (the ADR's Confirmation paragraph) ----------------------------------

/// Today's behaviour, pinned as the attack case: a prefix deleted through `with_connection`,
/// with no anchor, is a broken chain at the first retained seq.
#[test]
fn a_prefix_deleted_without_an_anchor_is_a_broken_chain_at_the_first_retained_seq() {
    let issuer = issuer();
    let log = log_of(&issuer, 10, 35);
    exec(
        &log,
        "DELETE FROM audit WHERE seq <= 20; DELETE FROM checkpoints WHERE seq < 20;",
    );
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(!r.ok, "{r:?}");
    assert_eq!(r.first_bad_seq, Some(21));
    assert_eq!(r.pruned_through, None);
    assert_eq!(r.anchors, 0);
    assert!(!log.verify_chain().unwrap().ok);
}

/// A hand-written anchor row that copies the genuine checkpoint at the boundary but carries no
/// valid anchor signature (a checkpoint's signature, then garbage) is named in `bad_anchors`,
/// and the chain is reported broken at the first retained row.
#[test]
fn a_forged_anchor_row_with_a_copied_checkpoint_fails() {
    let issuer = issuer();
    let log = log_of(&issuer, 10, 35);
    let cp = log.checkpoints_between(20, 20).unwrap().remove(0);
    let head = log.head().unwrap().unwrap();
    for signature in [cp.signature.clone(), "AAAA".to_string()] {
        exec(&log, "DELETE FROM audit_anchors;");
        exec(
            &log,
            &format!(
                "DELETE FROM audit WHERE seq <= 20; \
                 INSERT INTO audit_anchors VALUES (20, '{}', {}, '{}', NULL, NULL, '{}', '{}', \
                 '{signature}', 'done', NULL);",
                cp.head_hash, head.seq, head.entry_hash, cp.at, cp.kid
            ),
        );
        let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
        assert!(!r.ok, "{r:?}");
        assert_eq!(r.first_bad_seq, Some(21), "{r:?}");
        assert_eq!(r.pruned_through, None);
        assert_eq!(r.anchors, 1);
        assert_eq!(r.bad_anchors.len(), 1, "{r:?}");
        assert_eq!(r.bad_anchors[0].through_seq, 20);
        assert!(
            r.bad_anchors[0]
                .reason
                .contains("signature does not verify"),
            "{r:?}"
        );
    }
}

/// A genuine anchor does not cover a second cut: one more row deleted after `through_seq + 1`
/// breaks the chain at the row after the gap, and deleting `through_seq + 1` itself breaks it
/// there.
#[test]
fn a_genuine_anchor_then_one_more_row_deleted_fails() {
    let issuer = issuer();
    let log = log_of(&issuer, 10, 35);
    prune(&log, 20, None).unwrap();
    finish(&log, 7);
    assert!(log.verify_chain_signed(&keys(&issuer)).unwrap().ok);
    exec(&log, "DELETE FROM audit WHERE seq = 25;");
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_seq, Some(26), "{r:?}");
    assert_eq!(r.pruned_through, Some(20));

    let log = log_of(&issuer, 10, 35);
    prune(&log, 20, None).unwrap();
    finish(&log, 100);
    exec(&log, "DELETE FROM audit WHERE seq = 21;");
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_seq, Some(22), "{r:?}");
}

/// An anchor signed by a key that is not in the JWKS is as good as none.
#[test]
fn an_anchor_by_another_key_fails() {
    let issuer = issuer();
    let other = self::issuer();
    let log = log_of(&issuer, 10, 35);
    prune(&log, 20, None).unwrap();
    finish(&log, 100);
    let r = log.verify_chain_signed(&keys(&other)).unwrap();
    assert!(!r.ok);
    assert!(
        r.bad_anchors[0].reason.contains("unknown signing key"),
        "{r:?}"
    );
    assert_eq!(r.first_bad_seq, Some(21));
}

/// The prune record is bound to the anchor: replacing it with another admin record, even one
/// whose hash is then recomputed for every later entry, is reported.
#[test]
fn a_rewritten_prune_record_is_reported() {
    let issuer = issuer();
    let log = log_of(&issuer, 10, 35);
    let out = prune(&log, 20, Some("aa")).unwrap();
    finish(&log, 100);
    let p = out.anchor.anchor.prune_seq;
    // Another tool in the same place, its JSON and hash rewritten consistently.
    let mut e = log.entry_at(p).unwrap().unwrap();
    e.record.tool = "admin.policies.reload".into();
    let json = attenuo_audit::canonical_record_json(&e.record);
    let hash = attenuo_audit::entry_hash_from_json(p, &e.prev_hash, &json);
    exec(
        &log,
        &format!(
            "UPDATE audit SET tool = 'admin.policies.reload', record_json = '{}', \
             entry_hash = '{hash}' WHERE seq = {p}",
            json.replace('\'', "''")
        ),
    );
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(!r.ok, "{r:?}");
    assert!(
        r.bad_anchors
            .iter()
            .any(|b| b.reason.contains("does not hash to prune_entry_hash")),
        "{r:?}"
    );
}

// --- a prune, step by step -------------------------------------------------------------------

/// A prune through B: the transaction writes the "before" checkpoint at the head H, the prune
/// record at P = H + 1, the anchor and the "after" checkpoint at P, and the hooks see them in
/// that order once it commits. Every read starts at B + 1 at once; the deletes then remove
/// the rows and the checkpoints below B; verify passes with `pruned_through = B`; the next
/// append gets P + 1.
#[test]
fn a_prune_through_b_verifies_from_its_anchor() {
    let issuer = issuer();
    let seen: Seen = Arc::default();
    let log = hooked(
        SqliteAudit::open_in_memory()
            .unwrap()
            .with_checkpointing(issuer.detached_signer(), 10),
        &seen,
    );
    for i in 0..35 {
        log.append(record(i)).unwrap();
    }
    seen.lock().unwrap().clear();
    let out = prune(&log, 20, Some("ab12")).unwrap();
    assert!(!out.already);
    let a = &out.anchor.anchor;
    assert_eq!(out.anchor.state, AnchorState::Deleting);
    assert_eq!((a.through_seq, a.prune_seq), (20, 36));
    assert_eq!(a.previous_through_seq, None);
    assert_eq!(a.archive_sha256.as_deref(), Some("ab12"));
    assert_eq!(out.checkpoint_before.as_ref().unwrap().seq, 35);
    assert_eq!(out.checkpoint_after.as_ref().unwrap().seq, 36);
    assert_eq!(*seen.lock().unwrap(), ["cp 35", "anchor 20", "cp 36"]);
    assert!(keys(&issuer).verify_anchor(a).is_ok());

    // Committed: the log starts at 21 for every reader, although no row is deleted yet.
    assert_eq!(log.rows_at_or_below(20).unwrap(), 20);
    assert_eq!(log.first_retained_seq().unwrap(), 21);
    assert_eq!(log.pruned_through().unwrap(), Some(20));
    assert_eq!(log.entry_at(5).unwrap(), None);
    assert_eq!(log.range(1, 5).unwrap()[0].seq, 21);
    assert_eq!(log.len().unwrap(), 16);
    let first = log.range(1, 100).unwrap()[0].record.id.to_string();
    assert!(log.entry_by_record_id(&first).unwrap().is_some());
    let old = record(3).id.to_string();
    assert!(log.entry_by_record_id(&old).unwrap().is_none());
    assert_eq!(
        log.checkpoints_before(u64::MAX, 100)
            .unwrap()
            .iter()
            .map(|c| c.seq)
            .collect::<Vec<_>>(),
        [36, 35, 30, 20]
    );
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!((r.pruned_through, r.anchors, r.entries), (Some(20), 1, 16));
    assert_eq!(r.first_bad_seq, None);
    assert!(log.verify_chain().unwrap().ok);

    // The prune record is an admin record of the prune, bound to the anchor.
    let p = log.entry_at(36).unwrap().unwrap();
    assert_eq!(
        (p.record.kind, p.record.tool.as_str()),
        (RecordKind::Admin, PRUNE_TOOL)
    );
    assert!(a.check_prune_record(&p).is_ok());

    assert_eq!(finish(&log, 6), 20);
    assert_eq!(log.rows_at_or_below(20).unwrap(), 0);
    assert_eq!(
        log.newest_anchor().unwrap().unwrap().state,
        AnchorState::Done
    );
    let stored: Vec<u64> = snapshot(&log)["checkpoints"]
        .iter()
        .map(|r| r.split('|').next().unwrap().parse().unwrap())
        .collect();
    assert_eq!(
        stored,
        [20, 30, 35, 36],
        "checkpoints below B are gone, B's stays"
    );
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(
        (r.pruned_through, r.entries, r.last_signed_seq),
        (Some(20), 16, Some(36))
    );
    assert_eq!(log.append(record(99)).unwrap().seq, 37);
    assert!(log.verify_chain_signed(&keys(&issuer)).unwrap().ok);
    // Nothing more to delete.
    assert_eq!(log.prune_step(10).unwrap().through_seq, None);
}

/// The head already has a checkpoint: no second "before" checkpoint is signed.
#[test]
fn a_head_with_a_checkpoint_gets_no_second_one() {
    let issuer = issuer();
    let seen: Seen = Arc::default();
    let log = hooked(
        SqliteAudit::open_in_memory()
            .unwrap()
            .with_checkpointing(issuer.detached_signer(), 10),
        &seen,
    );
    for i in 0..30 {
        log.append(record(i)).unwrap();
    }
    seen.lock().unwrap().clear();
    let out = prune(&log, 20, None).unwrap();
    assert_eq!(out.checkpoint_before.unwrap().seq, 30);
    assert_eq!(*seen.lock().unwrap(), ["anchor 20", "cp 31"]);
}

/// The table emptied by hand after a prune: the next append continues from the anchor's prune
/// record, so no seq is given twice; and from a stored checkpoint above it, when the log grew
/// past the prune record before it was emptied.
#[test]
fn head_link_on_an_empty_table_continues_from_the_anchor() {
    let issuer = issuer();
    let log = log_of(&issuer, 10, 30);
    let out = prune(&log, 20, None).unwrap();
    finish(&log, 100);
    exec(&log, "DELETE FROM audit;");
    let e = log.append(record(1)).unwrap();
    assert_eq!(e.seq, out.anchor.anchor.prune_seq + 1);
    assert_eq!(e.prev_hash, out.anchor.anchor.prune_entry_hash);

    let log = log_of(&issuer, 10, 30);
    let out = prune(&log, 20, None).unwrap();
    finish(&log, 100);
    for i in 0..15 {
        log.append(record(100 + i)).unwrap();
    }
    let cp = log.last_checkpoint().unwrap().unwrap();
    assert!(cp.seq > out.anchor.anchor.prune_seq, "{cp:?}");
    exec(&log, "DELETE FROM audit;");
    let e = log.append(record(1)).unwrap();
    assert_eq!((e.seq, e.prev_hash), (cp.seq + 1, cp.head_hash));
}

/// A repeated request answers with the stored anchor and `already: true`, and writes nothing;
/// the same boundary with another digest is refused.
#[test]
fn a_repeated_prune_is_idempotent() {
    let issuer = issuer();
    let log = log_of(&issuer, 10, 35);
    let first = prune(&log, 20, Some("aa")).unwrap();
    let before = snapshot(&log);
    let again = prune(&log, 20, Some("aa")).unwrap();
    assert!(again.already);
    assert_eq!(again.anchor, first.anchor);
    assert_eq!(again.checkpoint_after, first.checkpoint_after);
    assert_eq!(again.checkpoint_before, first.checkpoint_before);
    assert_eq!(snapshot(&log), before);
    assert_eq!(
        guard_of(prune(&log, 20, Some("bb")).unwrap_err()),
        PruneGuard::Conflict
    );
    finish(&log, 100);
    assert!(prune(&log, 20, Some("aa")).unwrap().already);
}

// --- the guards ----------------------------------------------------------------------------

/// Each guard refuses with its own code, and nothing is written.
#[test]
fn every_guard_refuses_and_writes_nothing() {
    let issuer = issuer();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("g.sqlite");
    let log = file_log(&path, &issuer, 10);
    let leases = SqliteLeaseStore::open(&path).unwrap();
    for i in 0..35 {
        log.append(record(i)).unwrap();
    }
    let refuse = |through: u64, limits: &PruneLimits| {
        let before = snapshot(&log);
        let e = log
            .prune_through(through, None, limits, prune_record)
            .unwrap_err();
        assert_eq!(snapshot(&log), before, "a refused prune writes nothing");
        guard_of(e)
    };
    // Not at a checkpoint; a checkpoint whose hash is not the entry's.
    assert_eq!(refuse(21, &limits()), PruneGuard::NotAtCheckpoint);
    exec(
        &log,
        "UPDATE checkpoints SET head_hash = 'x' WHERE seq = 20;",
    );
    assert_eq!(refuse(20, &limits()), PruneGuard::NotAtCheckpoint);
    exec(
        &log,
        &format!(
            "UPDATE checkpoints SET head_hash = '{}' WHERE seq = 20;",
            log.entry_at(20).unwrap().unwrap().entry_hash
        ),
    );
    // Too recent.
    let young = PruneLimits {
        now: t0() + Duration::days(30),
        ..limits()
    };
    assert_eq!(refuse(20, &young), PruneGuard::TooRecent);
    // A live run: the records are of chain `l1`, whose root lease is in the registry.
    leases
        .register(&LeaseId::new("l1"), None, now() + Duration::hours(1))
        .unwrap();
    assert_eq!(refuse(20, &limits()), PruneGuard::LiveRun);
    exec(&log, "DELETE FROM leases;");
    // The sink: degraded, or not yet at B.
    for sink in [
        SinkProgress {
            degraded: true,
            delivered_through: Some(30),
        },
        SinkProgress {
            degraded: false,
            delivered_through: Some(10),
        },
        SinkProgress {
            degraded: false,
            delivered_through: None,
        },
    ] {
        let l = PruneLimits {
            sink: Some(sink),
            ..limits()
        };
        assert_eq!(refuse(20, &l), PruneGuard::SinkBehind, "{sink:?}");
    }
    let caught_up = PruneLimits {
        sink: Some(SinkProgress {
            degraded: false,
            delivered_through: Some(20),
        }),
        ..limits()
    };
    // Accepted now; a second prune while the first deletes is refused.
    log.prune_through(10, None, &caught_up, prune_record)
        .unwrap();
    assert_eq!(refuse(20, &limits()), PruneGuard::InProgress);
    finish(&log, 100);
    // The same boundary again is the idempotent repeat; below it is already pruned.
    assert!(
        log.prune_through(10, None, &limits(), prune_record)
            .unwrap()
            .already
    );
    assert_eq!(refuse(5, &limits()).code(), "audit_pruned");
    assert_eq!(refuse(9, &limits()), PruneGuard::AlreadyPruned);
    // With a sink, the anchor of the prune before must be delivered first.
    assert_eq!(refuse(20, &caught_up), PruneGuard::SinkBehind);
    let plan = log.prune_plan(PlanBound::Through(20), &caught_up).unwrap();
    assert!(plan.guards.anchor_undelivered);
    assert_eq!(
        (plan.through, plan.guards.limited_by),
        (None, Some("sink_behind"))
    );
    assert_eq!(log.unshipped_anchors().unwrap().len(), 1);
    log.mark_anchor_shipped(10, now()).unwrap();
    assert!(log.unshipped_anchors().unwrap().is_empty());
    assert!(log.newest_anchor().unwrap().unwrap().shipped_at.is_some());
    // Without a sink the guard does not apply.
    log.prune_through(20, None, &caught_up, prune_record)
        .unwrap();
}

/// The plan rounds a request down to the newest checkpoint the guards allow, and says which
/// guard limited it.
#[test]
fn the_plan_picks_the_largest_allowed_boundary() {
    let issuer = issuer();
    let log = log_of(&issuer, 10, 35);
    let plan = log.prune_plan(PlanBound::Through(27), &limits()).unwrap();
    assert_eq!((plan.from, plan.through, plan.entries), (1, Some(20), 20));
    assert_eq!(plan.guards.limited_by, Some("prune_not_at_checkpoint"));
    let plan = log.prune_plan(PlanBound::Through(30), &limits()).unwrap();
    assert_eq!(plan.through, Some(30));
    assert_eq!(plan.guards.limited_by, None);
    let sink = PruneLimits {
        sink: Some(SinkProgress {
            degraded: false,
            delivered_through: Some(15),
        }),
        ..limits()
    };
    let plan = log.prune_plan(PlanBound::Through(30), &sink).unwrap();
    assert_eq!(plan.through, Some(10));
    assert_eq!(plan.guards.limited_by, Some("sink_behind"));
    // Records are one second apart from t0: before t0 + 25 s keeps 26 and later.
    let plan = log
        .prune_plan(PlanBound::Before(t0() + Duration::seconds(25)), &limits())
        .unwrap();
    assert_eq!(plan.through, Some(20));
    let young = PruneLimits {
        now: t0() + Duration::days(90) + Duration::seconds(15),
        ..limits()
    };
    let plan = log.prune_plan(PlanBound::Through(30), &young).unwrap();
    assert_eq!(plan.through, Some(10));
    assert_eq!(plan.guards.limited_by, Some("prune_too_recent"));
    // Nothing old enough at all.
    let plan = log
        .prune_plan(
            PlanBound::Through(30),
            &PruneLimits {
                now: t0(),
                ..limits()
            },
        )
        .unwrap();
    assert_eq!(plan.through, None);
    // After a prune the plan starts after it and shows the anchor.
    prune(&log, 20, None).unwrap();
    let plan = log.prune_plan(PlanBound::Through(40), &limits()).unwrap();
    assert_eq!(plan.from, 21);
    assert!(plan.guards.in_progress);
    assert_eq!(plan.through, None);
    assert_eq!(plan.anchor.unwrap().anchor.through_seq, 20);
}

// --- crashes --------------------------------------------------------------------------------

/// A failure at each of the six steps of the transaction rolls it back whole: no record, no
/// anchor, no checkpoint, the hooks see nothing, and the log verifies as it did.
#[test]
fn a_crash_at_each_step_of_the_transaction_leaves_the_old_log() {
    let issuer = issuer();
    for step in 1..=6 {
        let seen: Seen = Arc::default();
        let log = hooked(
            SqliteAudit::open_in_memory()
                .unwrap()
                .with_checkpointing(issuer.detached_signer(), 10),
            &seen,
        );
        for i in 0..35 {
            log.append(record(i)).unwrap();
        }
        seen.lock().unwrap().clear();
        let before = snapshot(&log);
        log.fail_prune_at_step(step);
        let e = prune(&log, 20, None).unwrap_err();
        assert!(e.to_string().contains(&format!("step {step}")), "{e}");
        assert_eq!(snapshot(&log), before, "step {step}");
        assert!(seen.lock().unwrap().is_empty(), "step {step}");
        assert_eq!(log.pruned_through().unwrap(), None);
        let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
        assert!(r.ok && r.pruned_through.is_none(), "step {step}: {r:?}");
        assert_eq!(log.append(record(50)).unwrap().seq, 36, "step {step}");
        // And the prune goes through once the fault is gone.
        log.fail_prune_at_step(0);
        prune(&log, 20, None).unwrap();
        assert!(log.verify_chain_signed(&keys(&issuer)).unwrap().ok);
    }
}

/// The process stops between delete batches: the file reopens with the anchor `deleting`,
/// every read starts at B + 1, verify passes, a second prune is refused, and the deletes resume
/// where they stopped and end in `done`. A crash right after the commit (no batch at all) is
/// the same.
#[test]
fn a_stop_between_delete_batches_resumes_after_reopen() {
    let issuer = issuer();
    for batches_before_stop in [0, 1, 3] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.sqlite");
        {
            let log = file_log(&path, &issuer, 10);
            for i in 0..55 {
                log.append(record(i)).unwrap();
            }
            prune(&log, 40, Some("cd")).unwrap();
            for _ in 0..batches_before_stop {
                assert!(!log.prune_step(7).unwrap().done);
            }
        }
        let log = file_log(&path, &issuer, 10);
        let a = log.newest_anchor().unwrap().unwrap();
        assert_eq!((a.anchor.through_seq, a.state), (40, AnchorState::Deleting));
        assert_eq!(
            log.rows_at_or_below(40).unwrap(),
            40 - 7 * batches_before_stop
        );
        assert_eq!(log.first_retained_seq().unwrap(), 41);
        assert_eq!(log.range(1, 1).unwrap()[0].seq, 41);
        assert_eq!(log.entry_at(40).unwrap(), None);
        let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
        assert!(r.ok, "{r:?}");
        assert_eq!(r.pruned_through, Some(40));
        assert_eq!(
            guard_of(prune(&log, 50, None).unwrap_err()),
            PruneGuard::InProgress
        );
        finish(&log, 7);
        assert_eq!(log.rows_at_or_below(40).unwrap(), 0);
        assert_eq!(
            log.newest_anchor().unwrap().unwrap().state,
            AnchorState::Done
        );
        assert!(log.verify_chain_signed(&keys(&issuer)).unwrap().ok);
        assert_eq!(log.append(record(1)).unwrap().seq, 57);
    }
}

// --- two prunes, archives and exports ------------------------------------------------------

/// The archive of a prune (`first..=B`, with the checkpoint at B) verifies strictly on its
/// own; the export of the retained log from B + 1 carries the anchor in its header and
/// verifies with `from_anchor`; two prunes in a row link (`previous_through_seq`), and the two
/// archives and the retained export form one chain from genesis. Flipping a byte of either the
/// archive or the retained export fails it.
#[test]
fn two_prunes_in_a_row_link_and_their_archives_verify() {
    let issuer = issuer();
    let keys = keys(&issuer);
    let log = log_of(&issuer, 10, 45);
    let archive = |log: &SqliteAudit, from: u64, to: u64| {
        let header = ExportHeader::new(from, to, "2027-01-01T00:00:00Z".into());
        let cps = log.checkpoints_between(from, to).unwrap();
        export_text(&header, &range(log, from, to), &cps)
    };
    let a1 = archive(&log, 1, 20);
    let first = prune(&log, 20, Some("11")).unwrap();
    finish(&log, 100);
    let a2 = archive(&log, 21, 40);
    let second = prune(&log, 40, Some("22")).unwrap();
    assert_eq!(second.anchor.anchor.previous_through_seq, Some(20));
    finish(&log, 100);
    let r = log.verify_chain_signed(&keys).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!((r.pruned_through, r.anchors), (Some(40), 2));
    assert_eq!(
        log.anchors_before(u64::MAX, 10)
            .unwrap()
            .iter()
            .map(|a| a.anchor.through_seq)
            .collect::<Vec<_>>(),
        [40, 20]
    );
    // The first anchor's checkpoint is gone with the second prune; its prune record (at the
    // head of the 45 entries, above 40) is kept.
    assert!(log.checkpoints_between(20, 20).unwrap().is_empty());
    assert_eq!(first.anchor.anchor.prune_seq, 46);
    assert!(log.entry_at(46).unwrap().is_some());

    // The retained export, from B + 1 to the head, with the anchor.
    let head = log.head().unwrap().unwrap().seq;
    let header = ExportHeader::new(41, head, "2027-01-01T00:00:00Z".into())
        .with_anchor(Some(second.anchor.anchor.clone()));
    let retained = export_text(
        &header,
        &range(&log, 41, head),
        &log.checkpoints_between(41, head).unwrap(),
    );
    let mut parts = Vec::new();
    for text in [&a1, &a2, &retained] {
        let export = parse_export(text).unwrap();
        let rep = verify_export(&export, &keys).unwrap();
        assert!(rep.report.ok, "{rep:?}");
        assert!(!rep.unsigned_tail_rejected);
        parts.push(export);
    }
    let rep = verify_export(&parts[2], &keys).unwrap();
    assert!(rep.from_anchor && !rep.from_genesis, "{rep:?}");
    assert_eq!(rep.report.pruned_through, Some(40));
    assert!(verify_export(&parts[0], &keys).unwrap().from_genesis);
    // They link: each file's last entry hash is the next file's first prev_hash, and each
    // archive ends at a checkpoint.
    for w in parts.windows(2) {
        let last = w[0].entries.last().unwrap();
        assert_eq!(last.entry_hash, w[1].entries[0].prev_hash);
        assert!(w[0].checkpoints.iter().any(|c| c.seq == last.seq));
    }
    assert_eq!(
        second.anchor.anchor.through_hash,
        parts[1].entries.last().unwrap().entry_hash
    );

    // One byte flipped in a record of the archive, or of the retained export: reported at
    // that seq.
    for (text, seq) in [(&a1, 7u64), (&retained, 44)] {
        let needle = format!("\"seq\":{seq},\"type\":\"entry\"");
        let line = text.lines().find(|l| l.contains(&needle)).unwrap();
        let flipped = line.replacen("\"chain_depth\":2", "\"chain_depth\":3", 1);
        assert_ne!(line, flipped);
        let rep =
            verify_export(&parse_export(&text.replace(line, &flipped)).unwrap(), &keys).unwrap();
        assert!(!rep.report.ok);
        assert_eq!(rep.report.first_bad_seq, Some(seq), "{rep:?}");
    }
}

/// The header's anchor is checked: one with a bad signature, or one that does not name the
/// file's start, fails the export; without the member the same file verifies as a window, as
/// an older verifier reads it.
#[test]
fn an_export_header_anchor_is_checked() {
    let issuer = issuer();
    let keys = keys(&issuer);
    let log = log_of(&issuer, 10, 35);
    let out = prune(&log, 20, None).unwrap();
    let head = log.head().unwrap().unwrap().seq;
    let entries = range(&log, 21, head);
    let cps = log.checkpoints_between(21, head).unwrap();
    let mut forged = out.anchor.anchor.clone();
    forged.through_hash = "f".repeat(64);
    let base = ExportHeader::new(21, head, "2027-01-01T00:00:00Z".into());
    let rep = |header: &ExportHeader| {
        verify_export(
            &parse_export(&export_text(header, &entries, &cps)).unwrap(),
            &keys,
        )
        .unwrap()
    };
    let r = rep(&base.clone().with_anchor(Some(forged)));
    assert!(!r.report.ok && !r.from_anchor);
    assert_eq!(r.report.bad_anchors.len(), 1);
    let mut later = out.anchor.anchor.clone();
    later.through_seq = 10;
    assert!(!rep(&base.clone().with_anchor(Some(later))).report.ok);
    let plain = rep(&base);
    assert!(
        plain.report.ok && !plain.from_anchor && !plain.from_genesis,
        "{plain:?}"
    );
    assert_eq!(plain.report.pruned_through, None);
    // The member is ignored by a header parser that does not know it.
    let text = header_line(&base.clone().with_anchor(Some(out.anchor.anchor.clone())));
    let v: Value = serde_json::from_str(&text).unwrap();
    assert!(v.get("anchor").is_some());
}

/// The cross-check counts shipped checkpoints below the export's range, and with an anchor in
/// the header checks the shipped checkpoint at its boundary; a shipped anchor in the same file
/// is skipped by the checkpoint parser.
#[test]
fn the_cross_check_counts_below_range_and_checks_the_anchor_boundary() {
    let issuer = issuer();
    let keys = keys(&issuer);
    let log = log_of(&issuer, 10, 35);
    let shipped_cps: Vec<Checkpoint> = log.checkpoints_between(1, 100).unwrap();
    let out = prune(&log, 20, None).unwrap();
    let head = log.head().unwrap().unwrap().seq;
    let header = ExportHeader::new(21, head, "2027-01-01T00:00:00Z".into())
        .with_anchor(Some(out.anchor.anchor.clone()));
    let export = parse_export(&export_text(
        &header,
        &range(&log, 21, head),
        &log.checkpoints_between(21, head).unwrap(),
    ))
    .unwrap();
    let mut file: String = shipped_cps
        .iter()
        .map(|c| ShippedCheckpoint::new(c, None).to_line())
        .collect();
    file.push_str(&ShippedAnchor::new(&out.anchor.anchor, None).to_line());
    let lines = parse_shipped(&file).unwrap();
    assert_eq!(lines.len(), 3, "the anchor line is skipped");
    let anchors = attenuo_audit::parse_shipped_anchors(&file).unwrap();
    assert_eq!(anchors[0].1.anchor, out.anchor.anchor);
    let r = cross_check(&export, &lines, &keys);
    assert!(r.ok, "{r:?}");
    assert_eq!((r.below_range, r.in_range), (2, 1));

    // A shipped checkpoint at B that names another hash than the anchor.
    let mut cp20 = shipped_cps[1].clone();
    assert_eq!(cp20.seq, 20);
    cp20.head_hash = "e".repeat(64);
    let signer = issuer.detached_signer();
    let resigned = Checkpoint::sign(&signer, 20, &cp20.head_hash, t0()).unwrap();
    let bad = parse_shipped(&ShippedCheckpoint::new(&resigned, None).to_line()).unwrap();
    let r = cross_check(&export, &bad, &keys);
    assert!(!r.ok);
    assert!(r.mismatches[0].reason.contains("anchor"), "{r:?}");
}

// --- concurrency ---------------------------------------------------------------------------

/// Appends from several threads while a prune commits and its deletes run: every append gets
/// an entry, none is lost or given a seq twice, each lands before the "before" checkpoint's
/// head or after the prune record, and the log verifies from its anchor.
#[test]
fn concurrent_appends_during_a_prune_are_kept() {
    let issuer = issuer();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.sqlite");
    let log = Arc::new(file_log(&path, &issuer, 50));
    for i in 0..400 {
        log.append(record(i)).unwrap();
    }
    let seqs: Arc<Mutex<Vec<u64>>> = Arc::default();
    let threads: Vec<_> = (0..4)
        .map(|t| {
            let (log, seqs) = (log.clone(), seqs.clone());
            std::thread::spawn(move || {
                for i in 0..150 {
                    let e = log.append(record(1000 + t * 1000 + i)).unwrap();
                    seqs.lock().unwrap().push(e.seq);
                }
            })
        })
        .collect();
    let out = prune(&log, 300, None).unwrap();
    let mut deleted = 0;
    while deleted < 300 {
        deleted += log.prune_step(13).unwrap().deleted;
        std::thread::yield_now();
    }
    for t in threads {
        t.join().unwrap();
    }
    finish(&log, 13);
    let p = out.anchor.anchor.prune_seq;
    let mut seqs = seqs.lock().unwrap().clone();
    seqs.sort_unstable();
    assert_eq!(seqs.len(), 600);
    seqs.dedup();
    assert_eq!(seqs.len(), 600, "no seq given twice");
    assert!(!seqs.contains(&p), "no append took the prune record's seq");
    assert!(seqs.iter().all(|&s| s > 400));
    let head = log.head().unwrap().unwrap().seq;
    assert_eq!(head, 1001);
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!((r.pruned_through, r.entries), (Some(300), 701));
}

// --- the batch cost --------------------------------------------------------------------------

/// How long one delete batch holds the write gate on a large file (run with
/// `cargo test --release -p attenuo-audit --test retention -- --ignored --nocapture`).
#[test]
#[ignore = "a measurement, not a test"]
fn measure_a_delete_batch() {
    let issuer = issuer();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.sqlite");
    let total: usize = std::env::var("ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let log = file_log(&path, &issuer, 1000);
    let batch_records = 256;
    log.with_connection(|c| {
        c.execute_batch("PRAGMA synchronous = OFF")?;
        Ok(())
    })
    .unwrap();
    let mut i = 0;
    while i < total {
        for _ in 0..batch_records.min(total - i) {
            log.append(record(i)).unwrap();
            i += 1;
        }
    }
    log.with_connection(|c| {
        c.execute_batch("PRAGMA synchronous = NORMAL")?;
        Ok(())
    })
    .unwrap();
    let (size, free) = log.db_size().unwrap();
    println!("rows {total}, file {size} bytes, free {free}");
    let through = (total as u64 / 2 / 1000) * 1000;
    prune(&log, through, None).unwrap();
    for batch in [1_000usize, 5_000, 10_000, 20_000] {
        let mut times = Vec::new();
        for _ in 0..3 {
            let started = std::time::Instant::now();
            let step = log.prune_step(batch).unwrap();
            times.push(started.elapsed());
            if step.done {
                break;
            }
        }
        println!("batch {batch}: {times:?}");
    }
    finish(&log, 10_000);
    let (size, free) = log.db_size().unwrap();
    println!("after: file {size} bytes, free {free}");
}

// --- review follow-ups -----------------------------------------------------------------------

/// The plain `verify_chain` of a pruned log walks from the newest anchor row without checking
/// its signature, and says so; a forged row passes it but fails the signed verify.
#[test]
fn the_plain_verify_says_its_start_is_not_authenticated() {
    let issuer = issuer();
    let log = log_of(&issuer, 10, 35);
    let r = log.verify_chain().unwrap();
    assert_eq!(r.unauthenticated_start, None);
    prune(&log, 20, None).unwrap();
    finish(&log, 100);
    let r = log.verify_chain().unwrap();
    assert!(r.ok);
    assert_eq!(r.unauthenticated_start, Some(20));
    // A forged anchor row over a cut the attacker made: the plain walk takes it at its word.
    let log = log_of(&issuer, 10, 35);
    let e20 = log.entry_at(20).unwrap().unwrap();
    exec(
        &log,
        &format!(
            "DELETE FROM audit WHERE seq <= 20; \
             INSERT INTO audit_anchors VALUES (20, '{}', 35, 'x', NULL, NULL, 'at', 'k', 'AAAA', \
             'done', NULL);",
            e20.entry_hash
        ),
    );
    let r = log.verify_chain().unwrap();
    assert!(r.ok && r.unauthenticated_start == Some(20), "{r:?}");
    let signed = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(!signed.ok && !signed.bad_anchors.is_empty(), "{signed:?}");
}

/// The newest anchor needs its checkpoint at `through_seq`: none stored, or one tampered with,
/// is a bad anchor, and the walk falls back to genesis.
#[test]
fn verify_needs_a_good_checkpoint_at_the_anchor() {
    let issuer = issuer();
    let keys = keys(&issuer);
    let log = log_of(&issuer, 10, 35);
    prune(&log, 20, None).unwrap();
    finish(&log, 100);
    exec(&log, "DELETE FROM checkpoints WHERE seq = 20;");
    let r = log.verify_chain_signed(&keys).unwrap();
    assert!(!r.ok && r.pruned_through.is_none(), "{r:?}");
    assert!(
        r.bad_anchors[0]
            .reason
            .contains("no stored checkpoint at through_seq"),
        "{r:?}"
    );
    assert_eq!(r.first_bad_seq, Some(21));

    let log = log_of(&issuer, 10, 35);
    prune(&log, 20, None).unwrap();
    finish(&log, 100);
    exec(
        &log,
        &format!(
            "UPDATE checkpoints SET head_hash = '{}' WHERE seq = 20;",
            "e".repeat(64)
        ),
    );
    let r = log.verify_chain_signed(&keys).unwrap();
    assert!(!r.ok, "{r:?}");
    assert!(
        r.bad_anchors[0]
            .reason
            .contains("does not verify or names another hash"),
        "{r:?}"
    );
}

/// The tail cut from the prune record on: the anchor's prune record is missing.
#[test]
fn a_tail_cut_through_the_prune_record_is_reported() {
    let issuer = issuer();
    let log = log_of(&issuer, 10, 35);
    let out = prune(&log, 20, None).unwrap();
    finish(&log, 100);
    let p = out.anchor.anchor.prune_seq;
    exec(&log, &format!("DELETE FROM audit WHERE seq >= {p};"));
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(!r.ok, "{r:?}");
    assert!(
        r.bad_anchors
            .iter()
            .any(|b| b.reason == "no entry at prune_seq"),
        "{r:?}"
    );
}

/// Two prunes, then the oldest anchor row deleted: the newest names a `previous_through_seq`
/// that no row has.
#[test]
fn a_deleted_older_anchor_row_breaks_the_link() {
    let issuer = issuer();
    let log = log_of(&issuer, 10, 45);
    prune(&log, 20, None).unwrap();
    finish(&log, 100);
    prune(&log, 40, None).unwrap();
    finish(&log, 100);
    assert!(log.verify_chain_signed(&keys(&issuer)).unwrap().ok);
    exec(&log, "DELETE FROM audit_anchors WHERE through_seq = 20;");
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(!r.ok, "{r:?}");
    assert!(
        r.bad_anchors
            .iter()
            .any(|b| b.through_seq == 40 && b.reason.contains("previous_through_seq")),
        "{r:?}"
    );
}

/// An export whose header carries a validly signed anchor that names another start, and one
/// whose prune record inside the file does not match the anchor.
#[test]
fn an_export_header_anchor_must_name_the_start_and_match_the_prune_record() {
    let issuer = issuer();
    let keys = keys(&issuer);
    let log = log_of(&issuer, 10, 45);
    let first = prune(&log, 20, None).unwrap();
    finish(&log, 100);
    let second = prune(&log, 40, None).unwrap();
    finish(&log, 100);
    let head = log.head().unwrap().unwrap().seq;
    let entries = range(&log, 41, head);
    let cps = log.checkpoints_between(41, head).unwrap();
    // Genuine, but the anchor of the first prune: it names seq 21 as the start, not 41.
    assert!(keys.verify_anchor(&first.anchor.anchor).is_ok());
    let header = ExportHeader::new(41, head, "2027-01-01T00:00:00Z".into())
        .with_anchor(Some(first.anchor.anchor.clone()));
    let r = verify_export(
        &parse_export(&export_text(&header, &entries, &cps)).unwrap(),
        &keys,
    )
    .unwrap();
    assert!(!r.report.ok && !r.from_anchor, "{r:?}");
    assert!(
        r.report.bad_anchors[0]
            .reason
            .contains("but the export starts at 41"),
        "{r:?}"
    );
    // The right anchor, but the prune record in the file was replaced (its hash recomputed).
    let p = second.anchor.anchor.prune_seq;
    assert_eq!(p, head, "the prune record is the last entry");
    let mut entries = entries;
    let last = entries.last_mut().unwrap();
    last.record.tool = "admin.policies.reload".into();
    let json = attenuo_audit::canonical_record_json(&last.record);
    last.entry_hash = attenuo_audit::entry_hash_from_json(p, &last.prev_hash, &json);
    let header = ExportHeader::new(41, head, "2027-01-01T00:00:00Z".into())
        .with_anchor(Some(second.anchor.anchor.clone()));
    let r = verify_export(
        &parse_export(&export_text(&header, &entries, &cps)).unwrap(),
        &keys,
    )
    .unwrap();
    assert!(!r.report.ok, "{r:?}");
    assert!(
        r.report.bad_anchors[0]
            .reason
            .contains("does not hash to prune_entry_hash"),
        "{r:?}"
    );
}

/// A prune whose deletes run while a signed verify walks the log: the walk sees rows vanish
/// under it, finds the anchors changed and walks once more from a new snapshot.
#[test]
fn a_verify_that_overlaps_a_prune_walks_again() {
    let issuer = issuer();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.sqlite");
    let log = Arc::new(file_log(&path, &issuer, 10));
    for i in 0..35 {
        log.append(record(i)).unwrap();
    }
    let during = log.clone();
    log.on_next_verify_walk(move || {
        prune(&during, 20, None).unwrap();
        finish(&during, 100);
    });
    let r = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(r.pruned_through, Some(20));
}

/// A busy log has more checkpoints above the age cutoff than the plan looks at: the plan
/// starts at the newest entry old enough, so it still finds the boundary.
#[test]
fn the_plan_finds_a_boundary_below_many_recent_checkpoints() {
    let issuer = issuer();
    // A checkpoint at every entry; records are one second apart from t0.
    let log = log_of(&issuer, 1, 200);
    // Entries up to t0 + 49 s are old enough: 50 of them, 150 younger checkpoints above.
    let young = PruneLimits {
        now: t0() + Duration::days(90) + Duration::seconds(49),
        ..limits()
    };
    let plan = log
        .prune_plan_with_scan(PlanBound::Through(u64::MAX), &young, 10)
        .unwrap();
    assert_eq!(plan.through, Some(50), "{plan:?}");
    assert_eq!(plan.guards.limited_by, Some("prune_too_recent"));
    // And `before` the same way.
    let plan = log
        .prune_plan_with_scan(
            PlanBound::Before(t0() + Duration::seconds(30)),
            &limits(),
            10,
        )
        .unwrap();
    assert_eq!(plan.through, Some(30), "{plan:?}");
    assert_eq!(plan.guards.limited_by, Some("before"));
}

/// A `min_age` too large to subtract from the clock refuses as too recent, never panics.
#[test]
fn a_huge_min_age_is_too_recent_not_a_panic() {
    let issuer = issuer();
    let log = log_of(&issuer, 10, 35);
    let huge = PruneLimits {
        min_age: Duration::MAX,
        ..limits()
    };
    assert_eq!(
        guard_of(
            log.prune_through(20, None, &huge, prune_record)
                .unwrap_err()
        ),
        PruneGuard::TooRecent
    );
    assert_eq!(
        log.prune_plan(PlanBound::Through(30), &huge)
            .unwrap()
            .through,
        None
    );
    // The writer is still usable.
    log.append(record(99)).unwrap();
}

/// How long the live-run lookup takes with many chains whose root lease is in the registry
/// (run with `cargo test --release -p attenuo-audit --test retention -- --ignored --nocapture
/// measure_the_live_run_lookup`).
#[test]
#[ignore = "a measurement, not a test"]
fn measure_the_live_run_lookup() {
    let issuer = issuer();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("l.sqlite");
    let log = file_log(&path, &issuer, 1000);
    let chains: usize = std::env::var("CHAINS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let per_chain: usize = std::env::var("PER_CHAIN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    log.with_connection(|c| {
        c.execute_batch("PRAGMA synchronous = OFF")?;
        Ok(())
    })
    .unwrap();
    let leases = SqliteLeaseStore::open(&path).unwrap();
    let mut n = 0;
    for round in 0..per_chain {
        for c in 0..chains {
            let mut r = record(n);
            r.chain_id = Some(format!("c{c}"));
            log.append(r).unwrap();
            n += 1;
        }
        if round == 0 {
            for c in 0..chains {
                leases
                    .register(
                        &LeaseId::new(format!("c{c}")),
                        None,
                        now() + Duration::hours(1),
                    )
                    .unwrap();
            }
        }
    }
    // The records sit at seq 1.. so the first live record is at 1: the guard refuses, after
    // the lookup ran in full.
    let started = std::time::Instant::now();
    let rounds = 20;
    for _ in 0..rounds {
        let plan = log.prune_plan(PlanBound::Through(1000), &limits()).unwrap();
        assert_eq!(plan.guards.live_run_seq, Some(1));
    }
    println!(
        "{chains} live chains x {per_chain} records ({} rows): one plan (live-run lookup \
         included) {:?}",
        chains * per_chain,
        started.elapsed() / rounds
    );
}
