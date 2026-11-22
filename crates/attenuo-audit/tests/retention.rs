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

// --- several files, and the shipped anchors -------------------------------------------------

/// Two archives and the retained export, as the CLI writes them, for the tests below.
struct ThreeFiles {
    issuer: Issuer,
    keys: CheckpointKeys,
    texts: [String; 3],
    anchors: [attenuo_audit::Anchor; 2],
}

fn three_files() -> ThreeFiles {
    let issuer = issuer();
    let keys = keys(&issuer);
    let log = log_of(&issuer, 10, 45);
    let export = |log: &SqliteAudit, from: u64, to: u64, anchor: Option<attenuo_audit::Anchor>| {
        let header = ExportHeader::new(from, to, "2027-01-01T00:00:00Z".into()).with_anchor(anchor);
        export_text(
            &header,
            &range(log, from, to),
            &log.checkpoints_between(from, to).unwrap(),
        )
    };
    let a1 = export(&log, 1, 20, None);
    let first = prune(&log, 20, None).unwrap().anchor.anchor;
    finish(&log, 100);
    let a2 = export(&log, 21, 40, Some(first.clone()));
    let second = prune(&log, 40, None).unwrap().anchor.anchor;
    finish(&log, 100);
    let head = log.head().unwrap().unwrap().seq;
    let retained = export(&log, 41, head, Some(second.clone()));
    ThreeFiles {
        issuer,
        keys,
        texts: [a1, a2, retained],
        anchors: [first, second],
    }
}

/// The two archives and the retained export link, in order; out of order, with a file left
/// out, or with a file that does not end at a checkpoint, the pair that does not link is named.
#[test]
fn archives_and_the_retained_export_link_as_one_log() {
    let f = three_files();
    let parsed: Vec<_> = f.texts.iter().map(|t| parse_export(t).unwrap()).collect();
    for (i, p) in parsed.iter().enumerate() {
        let r = verify_export(p, &f.keys).unwrap();
        assert!(r.report.ok, "file {i}: {r:?}");
    }
    let all: Vec<_> = parsed.iter().collect();
    assert!(attenuo_audit::link_exports(&all).is_empty());
    // The middle archive left out: the seqs jump from 20 to 41.
    let gap = attenuo_audit::link_exports(&[&parsed[0], &parsed[2]]);
    assert_eq!((gap[0].earlier, gap[0].later), (0, 1));
    assert!(gap[0].reason.contains("not contiguous"), "{gap:?}");
    assert!(
        gap.iter()
            .any(|p| p.reason.contains("header anchor is through seq 40")),
        "{gap:?}"
    );
    // Out of order.
    let swapped = attenuo_audit::link_exports(&[&parsed[1], &parsed[0]]);
    assert!(!swapped.is_empty());
    // An archive cut one entry short of its checkpoint, and its next file starting after it.
    let mut short = parsed[0].clone();
    short.entries.pop();
    short.checkpoints.retain(|c| c.seq != 20);
    let mut next = parsed[1].clone();
    next.header.as_mut().unwrap().anchor = None;
    next.entries
        .insert(0, parsed[0].entries.last().unwrap().clone());
    let p = attenuo_audit::link_exports(&[&short, &next]);
    assert!(
        p.iter()
            .any(|p| p.reason.contains("does not end at a checkpoint")),
        "{p:?}"
    );
    // Two files whose seqs follow but whose hashes do not.
    let mut forged = parsed[1].clone();
    forged.entries[0].prev_hash = "e".repeat(64);
    let p = attenuo_audit::link_exports(&[&parsed[0], &forged]);
    assert!(
        p.iter().any(|p| p.reason.contains("does not link")),
        "{p:?}"
    );
}

/// The shipped anchors: each file accounts for them; a retained export whose header anchor was
/// not shipped, or differs from the shipped one, fails; an export that holds entries a shipped
/// anchor says were pruned (a rewind) fails; a shipped anchor that does not verify fails.
#[test]
fn the_shipped_anchors_are_cross_checked() {
    let f = three_files();
    let shipped_text: String = f
        .anchors
        .iter()
        .map(|a| ShippedAnchor::new(a, None).to_line())
        .collect();
    let shipped = attenuo_audit::parse_shipped_anchors(&shipped_text).unwrap();
    let parsed: Vec<_> = f.texts.iter().map(|t| parse_export(t).unwrap()).collect();
    for (i, p) in parsed.iter().enumerate() {
        let r = attenuo_audit::cross_check_anchors(p, &shipped, &f.keys);
        assert!(r.ok, "file {i}: {r:?}");
    }
    // The archives are not checked against the prunes that came after them.
    let r = attenuo_audit::cross_check_anchors(&parsed[0], &shipped, &f.keys);
    assert_eq!((r.checked, r.beyond_range), (0, 2));
    let r = attenuo_audit::cross_check_anchors(&parsed[2], &shipped, &f.keys);
    assert_eq!((r.checked, r.matched), (2, 2));

    // The second anchor never shipped.
    let only_first = &shipped[..1];
    let r = attenuo_audit::cross_check_anchors(&parsed[2], only_first, &f.keys);
    assert!(!r.ok);
    assert!(
        r.mismatches[0].reason.contains("not in the shipped file"),
        "{r:?}"
    );

    // A rewind: the log restored to before the second prune; the export from 21 holds seqs
    // the shipped second anchor says were pruned.
    let mut rewound = parsed[1].clone();
    rewound.entries.extend(parsed[2].entries.iter().cloned());
    rewound.header.as_mut().unwrap().to = rewound.entries.last().unwrap().seq;
    let r = attenuo_audit::cross_check_anchors(&rewound, &shipped, &f.keys);
    assert!(!r.ok);
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.seq == 40 && m.reason.contains("REWOUND")),
        "{r:?}"
    );

    // Another anchor in the header than the one shipped (re-signed after shipping).
    let other = issuer();
    let mut swapped = parsed[2].clone();
    let mut a = f.anchors[1].clone();
    a.at = "2027-02-02T00:00:00Z".into();
    swapped.header.as_mut().unwrap().anchor = Some(a);
    let r = attenuo_audit::cross_check_anchors(&swapped, &shipped, &f.keys);
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.reason.contains("another anchor for this boundary")),
        "{r:?}"
    );

    // A shipped anchor that does not verify (another key), and an inconsistent envelope.
    let r = attenuo_audit::cross_check_anchors(&parsed[2], &shipped, &keys(&other));
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.reason.contains("does not verify")),
        "{r:?}"
    );
    let mut env = ShippedAnchor::new(&f.anchors[0], None);
    env.anchor_sha256 = "0".repeat(64);
    let bad = vec![(1, env), shipped[1].clone()];
    let r = attenuo_audit::cross_check_anchors(&parsed[2], &bad, &f.keys);
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.reason.contains("anchor_sha256")),
        "{r:?}"
    );
}

/// The ways two files fail to link, each with its reason.
#[test]
fn link_problems_name_their_reason() {
    let f = three_files();
    let parsed: Vec<_> = f.texts.iter().map(|t| parse_export(t).unwrap()).collect();
    let reasons = |files: &[&attenuo_audit::Export]| -> Vec<String> {
        attenuo_audit::link_exports(files)
            .into_iter()
            .map(|p| p.reason)
            .collect()
    };
    // Out of order.
    let r = reasons(&[&parsed[1], &parsed[0]]);
    assert!(
        r.iter().any(|x| x
            == "the seqs are not contiguous: the earlier file ends at seq 40, the later one \
                starts at seq 1"),
        "{r:?}"
    );
    // The same file twice.
    let r = reasons(&[&parsed[0], &parsed[0]]);
    assert!(r[0].contains("not contiguous"), "{r:?}");
    // An empty earlier or later file.
    let mut empty = parsed[1].clone();
    empty.entries.clear();
    assert_eq!(
        reasons(&[&empty, &parsed[2]]),
        vec!["the earlier file holds no entries".to_string()]
    );
    assert_eq!(
        reasons(&[&parsed[0], &empty]),
        vec!["the later file holds no entries".to_string()]
    );
    // A final checkpoint that names another hash than the last entry.
    let mut other = parsed[0].clone();
    other
        .checkpoints
        .iter_mut()
        .find(|c| c.seq == 20)
        .unwrap()
        .head_hash = "e".repeat(64);
    let r = reasons(&[&other, &parsed[1]]);
    assert!(
        r.iter()
            .any(|x| x.contains("checkpoint at its last seq 20 names another hash")),
        "{r:?}"
    );
    // Seqs and hashes link, but the later header's anchor is for another boundary.
    let mut later = parsed[1].clone();
    later.header.as_mut().unwrap().anchor = Some(f.anchors[1].clone());
    assert_eq!(
        reasons(&[&parsed[0], &later]),
        vec![
            "the later file's header anchor is through seq 40, not the earlier file's end at \
             seq 20 and its hash"
                .to_string()
        ]
    );
}

/// More of the shipped-anchor cross-check: two different valid anchors for one boundary, a
/// retried delivery (passes), an envelope whose kid differs, a header anchor not shipped while
/// another is, and an export taken before a prune whose boundary lies inside it.
#[test]
fn shipped_anchor_duplicates_envelopes_and_stale_exports() {
    let f = three_files();
    let parsed: Vec<_> = f.texts.iter().map(|t| parse_export(t).unwrap()).collect();
    let line = |a: &attenuo_audit::Anchor| ShippedAnchor::new(a, None).to_line();
    let parse = |text: String| attenuo_audit::parse_shipped_anchors(&text).unwrap();

    // A retry: the same anchor twice is counted once and passes.
    let retried = parse(line(&f.anchors[0]) + &line(&f.anchors[0]) + &line(&f.anchors[1]));
    let r = attenuo_audit::cross_check_anchors(&parsed[2], &retried, &f.keys);
    assert!(r.ok, "{r:?}");

    // Two valid anchors for one boundary (signed with the server's key both times).
    let a = &f.anchors[0];
    let twin = attenuo_audit::Anchor::sign(
        &f.issuer.detached_signer(),
        a.through_seq,
        &a.through_hash,
        a.prune_seq,
        &a.prune_entry_hash,
        a.previous_through_seq,
        Some("f".repeat(64)),
        OffsetDateTime::now_utc(),
    )
    .unwrap();
    let twins = parse(line(a) + &line(&twin) + &line(&f.anchors[1]));
    let r = attenuo_audit::cross_check_anchors(&parsed[2], &twins, &f.keys);
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.seq == 20 && m.reason.contains("two different anchors")),
        "{r:?}"
    );

    // An envelope whose kid is not the anchor's.
    let mut env = ShippedAnchor::new(&f.anchors[0], None);
    env.kid = "other".into();
    let r = attenuo_audit::cross_check_anchors(&parsed[2], &[(1, env)], &f.keys);
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.reason.contains("`kid` or `signature` differs")),
        "{r:?}"
    );

    // The middle archive's header anchor (the first prune) is not shipped; the second is.
    let only_second = parse(line(&f.anchors[1]));
    let r = attenuo_audit::cross_check_anchors(&parsed[1], &only_second, &f.keys);
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.seq == 20 && m.reason.contains("not in the shipped file")),
        "{r:?}"
    );

    // An export of 21..=45 taken before the second prune (through 40, record at 47): the
    // shipped boundary lies inside it.
    let mut stale = parsed[1].clone();
    stale
        .entries
        .extend(parsed[2].entries.iter().filter(|e| e.seq <= 45).cloned());
    stale.header.as_mut().unwrap().to = 45;
    let all = parse(line(&f.anchors[0]) + &line(&f.anchors[1]));
    let r = attenuo_audit::cross_check_anchors(&stale, &all, &f.keys);
    assert!(!r.ok);
    assert!(
        r.mismatches
            .iter()
            .any(|m| m.seq == 40 && m.reason.contains("has its boundary inside this export")),
        "{r:?}"
    );
    // The archive that ends at that boundary is fine.
    assert!(attenuo_audit::cross_check_anchors(&parsed[1], &all, &f.keys).ok);
}

/// S3 objects (canonical JSON, no newline) joined with `cat` are one line of several objects:
/// both parsers read every object of it.
#[test]
fn s3_objects_joined_without_newlines_parse() {
    let f = three_files();
    let log = parse_export(&f.texts[2]).unwrap();
    let mut joined = Vec::new();
    for cp in &log.checkpoints {
        joined.extend(attenuo_audit::ShippedCheckpoint::new(cp, None).to_canonical_json());
    }
    for a in &f.anchors {
        joined.extend(ShippedAnchor::new(a, None).to_canonical_json());
    }
    let text = String::from_utf8(joined).unwrap();
    assert_eq!(text.lines().count(), 1);
    let cps = attenuo_audit::parse_shipped(&text).unwrap();
    assert_eq!(cps.len(), log.checkpoints.len());
    let anchors = attenuo_audit::parse_shipped_anchors(&text).unwrap();
    assert_eq!(anchors.len(), 2);
    assert!(attenuo_audit::cross_check_anchors(&log, &anchors, &f.keys).ok);
}

// --- golden files, shared with the Python and TypeScript verifiers ------------------------

/// Where the golden files of a pruned log live, for the Rust, Python and TypeScript suites.
fn golden_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/audit-retention")
}

/// A test key from a fixed seed, so a rewrite of the golden files keeps the same `kid`. It
/// signs nothing outside these files.
fn golden_issuer() -> Issuer {
    let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
    der.extend([7u8; 32]);
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(der)
    );
    Issuer::from_pem(
        IssuerConfig {
            issuer: "https://attenuo.test".into(),
            audience: "attenuo".into(),
            max_depth: 4,
            default_ttl: Duration::minutes(5),
        },
        &pem,
    )
    .unwrap()
}

/// Writes `testdata/audit-retention/`: a log of 12 entries with a checkpoint every 5, pruned
/// through 5 and then through 10, as the two archives (`archive-1.jsonl`, 1..=5;
/// `archive-2.jsonl`, 6..=10, its header carrying the first anchor), the retained export
/// (`retained.jsonl`, 11..=14, with the second anchor and both prune records), what the sink
/// shipped (`shipped.jsonl`) and the JWKS. Each archive's digest is signed into its anchor.
///
/// It also writes the negative cases the three verifiers must agree on: `stale.jsonl`, an
/// export of 6..=13 taken before the second prune, whose boundary lies inside it;
/// `rewound.jsonl`, 6..=14 with the first anchor in its header, as a log restored to before the
/// second prune would export (it verifies on its own, the shipped second anchor says 6..=10 were
/// pruned); `shipped-bad-signature.jsonl`, `shipped.jsonl` with the second anchor's signature
/// changed (the envelope made again around it, so only the signature check fails); and
/// `shipped-other-anchor.jsonl`, `shipped.jsonl` with another valid anchor for the first
/// boundary in place of the one in `archive-2.jsonl`'s header. Last come the files
/// [`write_derived_golden_files`] makes from these.
///
/// Run it with `cargo test -p attenuo-audit --test retention write_golden_files -- --ignored`
/// after a change of the formats, then commit the files.
#[test]
#[ignore = "writes the golden files; run by hand"]
fn write_golden_files() {
    use sha2::Digest;
    let issuer = golden_issuer();
    let log = log_of(&issuer, 5, 12);
    let export = |from: u64, to: u64, anchor: Option<attenuo_audit::Anchor>| {
        let header = ExportHeader::new(from, to, "2027-01-01T00:00:00Z".into()).with_anchor(anchor);
        export_text(
            &header,
            &range(&log, from, to),
            &log.checkpoints_between(from, to).unwrap(),
        )
    };
    let sha = |t: &str| hex::encode(sha2::Sha256::digest(t.as_bytes()));
    let a1 = export(1, 5, None);
    let first = prune(&log, 5, Some(&sha(&a1))).unwrap().anchor.anchor;
    finish(&log, 100);
    let a2 = export(6, 10, Some(first.clone()));
    // Before the second prune: an export of everything after the first one, and the entries
    // and checkpoints of 6..=10 that the second prune deletes.
    let before_second = log.head().unwrap().unwrap().seq;
    let stale = export(6, before_second, Some(first.clone()));
    let pruned_entries = range(&log, 6, 10);
    let pruned_cps = log.checkpoints_between(6, 10).unwrap();
    let second = prune(&log, 10, Some(&sha(&a2))).unwrap().anchor.anchor;
    finish(&log, 100);
    let head = log.head().unwrap().unwrap().seq;
    let retained = export(11, head, Some(second.clone()));
    // A log restored to before the second prune: 6..=10 are there again, after them the
    // entries the server wrote since.
    let rewound = {
        let header = ExportHeader::new(6, head, "2027-01-01T00:00:00Z".into())
            .with_anchor(Some(first.clone()));
        let mut entries = pruned_entries;
        entries.extend(range(&log, 11, head));
        let mut cps = pruned_cps;
        cps.extend(log.checkpoints_between(11, head).unwrap());
        export_text(&header, &entries, &cps)
    };
    let checkpoint_lines: String = log
        .checkpoints_between(0, head)
        .unwrap()
        .iter()
        .map(|c| ShippedCheckpoint::new(c, None).to_line())
        .collect();
    let anchor_lines = |anchors: &[&attenuo_audit::Anchor]| -> String {
        anchors
            .iter()
            .map(|a| ShippedAnchor::new(a, None).to_line())
            .collect()
    };
    let shipped = checkpoint_lines.clone() + &anchor_lines(&[&first, &second]);
    // The second anchor with one character of its signature changed.
    let mut forged = second.clone();
    let swap = if forged.signature.starts_with('A') {
        "B"
    } else {
        "A"
    };
    forged.signature.replace_range(..1, swap);
    let bad_signature = checkpoint_lines.clone() + &anchor_lines(&[&first, &forged]);
    // Another anchor for the first boundary, signed with the server's key: the log was pruned
    // through 5 again with another archive digest.
    let twin = attenuo_audit::Anchor::sign(
        &issuer.detached_signer(),
        first.through_seq,
        &first.through_hash,
        first.prune_seq,
        &first.prune_entry_hash,
        first.previous_through_seq,
        Some("f".repeat(64)),
        now(),
    )
    .unwrap();
    let other_anchor = checkpoint_lines + &anchor_lines(&[&twin, &second]);
    let jwks: Vec<Value> = issuer
        .trusted_public_keys()
        .into_iter()
        .map(|(kid, pem)| {
            let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            let der = STANDARD.decode(b64).unwrap();
            json!({"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
                   "kid": kid, "x": URL_SAFE_NO_PAD.encode(&der[der.len() - 32..])})
        })
        .collect();
    let dir = golden_dir();
    std::fs::create_dir_all(&dir).unwrap();
    for (name, text) in [
        ("archive-1.jsonl", a1),
        ("archive-2.jsonl", a2),
        ("retained.jsonl", retained),
        ("shipped.jsonl", shipped),
        ("stale.jsonl", stale),
        ("rewound.jsonl", rewound),
        ("shipped-bad-signature.jsonl", bad_signature),
        ("shipped-other-anchor.jsonl", other_anchor),
        (
            "jwks.json",
            serde_json::to_string_pretty(&json!({ "keys": jwks })).unwrap() + "\n",
        ),
    ] {
        std::fs::write(dir.join(name), text).unwrap();
    }
    write_derived_golden_files();
}

/// Writes the golden files made from the committed ones, so they can change without new
/// uuids everywhere: `shipped-relabelled.jsonl` (see [`relabelled_checkpoint`]), then
/// `cross-checks.json`, what the Rust cross-checks answer for each export and shipped file, for
/// the other suites.
///
/// [`write_golden_files`] runs it; run it alone with `cargo test -p attenuo-audit --test
/// retention write_derived_golden_files -- --ignored`.
#[test]
#[ignore = "writes the golden files; run by hand"]
fn write_derived_golden_files() {
    let dir = golden_dir();
    let shipped = std::fs::read_to_string(dir.join("shipped.jsonl")).unwrap();
    std::fs::write(dir.join(GOLDEN_RELABELLED), relabelled_checkpoint(&shipped)).unwrap();
    let checks = serde_json::to_string_pretty(&golden_checks()).unwrap() + "\n";
    std::fs::write(dir.join(GOLDEN_CHECKS), checks).unwrap();
}

/// A shipped file with a checkpoint envelope relabelled as an anchor.
const GOLDEN_RELABELLED: &str = "shipped-relabelled.jsonl";

/// `shipped` with one more line after its checkpoints: the last checkpoint's envelope with its
/// `head_hash` zeroed and its `format` changed to the anchor format, but no `anchor` member. A
/// reader that skipped lines by their format alone would miss the forged checkpoint; it is an
/// envelope whose format is not the checkpoint format, so the cross-check reports it.
fn relabelled_checkpoint(shipped: &str) -> String {
    let lines: Vec<&str> = shipped.lines().collect();
    let last_cp = lines
        .iter()
        .rposition(|l| l.contains("\"checkpoint\":"))
        .unwrap();
    let mut v: Value = serde_json::from_str(lines[last_cp]).unwrap();
    v["checkpoint"]["head_hash"] = json!("0".repeat(64));
    v["format"] = json!(attenuo_audit::SHIPPED_ANCHOR_FORMAT);
    let forged = serde_json::to_string(&v).unwrap();
    let mut out: Vec<&str> = lines[..=last_cp].to_vec();
    out.push(&forged);
    out.extend(&lines[last_cp + 1..]);
    out.join("\n") + "\n"
}

/// The committed relabelled file is the one [`relabelled_checkpoint`] makes now.
#[test]
fn the_golden_relabelled_file_is_current() {
    let dir = golden_dir();
    let read = |n: &str| std::fs::read_to_string(dir.join(n)).unwrap();
    assert_eq!(
        read(GOLDEN_RELABELLED),
        relabelled_checkpoint(&read("shipped.jsonl"))
    );
}

/// The file of the verdicts the Rust cross-checks give on the golden files.
const GOLDEN_CHECKS: &str = "cross-checks.json";

/// The export and shipped file of each verdict in [`GOLDEN_CHECKS`].
const GOLDEN_PAIRS: [(&str, &str); 9] = [
    ("archive-1.jsonl", "shipped.jsonl"),
    ("archive-2.jsonl", "shipped.jsonl"),
    ("retained.jsonl", "shipped.jsonl"),
    ("rewound.jsonl", "shipped.jsonl"),
    ("stale.jsonl", "shipped.jsonl"),
    ("archive-2.jsonl", "shipped-bad-signature.jsonl"),
    ("retained.jsonl", "shipped-bad-signature.jsonl"),
    ("archive-2.jsonl", "shipped-other-anchor.jsonl"),
    ("retained.jsonl", GOLDEN_RELABELLED),
];

/// What `cross_check` and `cross_check_anchors` answer for each of [`GOLDEN_PAIRS`], as the
/// files on disk are now: the Python and TypeScript suites compare their reports with it.
fn golden_checks() -> Value {
    let dir = golden_dir();
    let read = |n: &str| std::fs::read_to_string(dir.join(n)).unwrap();
    let keys =
        CheckpointKeys::from_jwks(&serde_json::from_str::<Value>(&read("jwks.json")).unwrap())
            .unwrap();
    let checks: Vec<Value> = GOLDEN_PAIRS
        .iter()
        .map(|(export, shipped)| {
            let e = parse_export(&read(export)).unwrap();
            let text = read(shipped);
            let cps = parse_shipped(&text).unwrap();
            let anchors = attenuo_audit::parse_shipped_anchors(&text).unwrap();
            json!({
                "export": export,
                "shipped": shipped,
                "checkpoints": cross_check(&e, &cps, &keys),
                "anchors": attenuo_audit::cross_check_anchors(&e, &anchors, &keys),
            })
        })
        .collect();
    json!({ "checks": checks })
}

/// The committed verdicts are the ones the Rust code gives now.
#[test]
fn the_golden_cross_checks_are_current() {
    let text = std::fs::read_to_string(golden_dir().join(GOLDEN_CHECKS)).unwrap();
    let stored: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(stored, golden_checks());
}

/// The committed golden files verify: each strictly, as one log from genesis, against the
/// shipped checkpoints and anchors, and each anchor names its archive's digest.
#[test]
fn the_golden_files_verify() {
    use sha2::Digest;
    let dir = golden_dir();
    let read = |n: &str| std::fs::read_to_string(dir.join(n)).unwrap();
    let keys =
        CheckpointKeys::from_jwks(&serde_json::from_str::<Value>(&read("jwks.json")).unwrap())
            .unwrap();
    let names = ["archive-1.jsonl", "archive-2.jsonl", "retained.jsonl"];
    let parsed: Vec<_> = names
        .iter()
        .map(|n| parse_export(&read(n)).unwrap())
        .collect();
    for (n, p) in names.iter().zip(&parsed) {
        let r = verify_export(p, &keys).unwrap();
        assert!(r.report.ok, "{n}: {r:?}");
    }
    let r1 = verify_export(&parsed[0], &keys).unwrap();
    let r2 = verify_export(&parsed[1], &keys).unwrap();
    let r3 = verify_export(&parsed[2], &keys).unwrap();
    assert!(r1.from_genesis && !r1.from_anchor);
    assert_eq!((r2.from_anchor, r2.report.pruned_through), (true, Some(5)));
    assert_eq!((r3.from_anchor, r3.report.pruned_through), (true, Some(10)));
    let all: Vec<_> = parsed.iter().collect();
    assert!(attenuo_audit::link_exports(&all).is_empty());
    let shipped = read("shipped.jsonl");
    let cps = parse_shipped(&shipped).unwrap();
    let anchors = attenuo_audit::parse_shipped_anchors(&shipped).unwrap();
    for p in &parsed {
        assert!(cross_check(p, &cps, &keys).ok);
        assert!(attenuo_audit::cross_check_anchors(p, &anchors, &keys).ok);
    }
    // Each anchor signs its archive's digest.
    for (archive, a) in [(names[0], &parsed[1]), (names[1], &parsed[2])] {
        let digest = hex::encode(sha2::Sha256::digest(read(archive).as_bytes()));
        let anchor = a.header.as_ref().unwrap().anchor.as_ref().unwrap();
        assert_eq!(anchor.archive_sha256.as_deref(), Some(digest.as_str()));
    }
    // The counts the Python and TypeScript suites check too.
    let r = attenuo_audit::cross_check_anchors(&parsed[0], &anchors, &keys);
    assert_eq!(
        (r.shipped, r.checked, r.matched, r.beyond_range),
        (2, 0, 0, 2)
    );
    let r = attenuo_audit::cross_check_anchors(&parsed[1], &anchors, &keys);
    assert_eq!((r.checked, r.matched, r.beyond_range), (1, 1, 1));
    let r = attenuo_audit::cross_check_anchors(&parsed[2], &anchors, &keys);
    assert_eq!((r.checked, r.matched, r.beyond_range), (2, 2, 0));
    let r = cross_check(&parsed[2], &cps, &keys);
    assert_eq!(r.below_range, 1);
}

/// The golden negative cases: each export verifies on its own, and the shipped anchors catch
/// it, with the reason the Python and TypeScript suites expect too.
#[test]
fn the_golden_negative_cases_fail_the_anchor_cross_check() {
    let dir = golden_dir();
    let read = |n: &str| std::fs::read_to_string(dir.join(n)).unwrap();
    let keys =
        CheckpointKeys::from_jwks(&serde_json::from_str::<Value>(&read("jwks.json")).unwrap())
            .unwrap();
    let export = |n: &str| parse_export(&read(n)).unwrap();
    let anchors = |n: &str| attenuo_audit::parse_shipped_anchors(&read(n)).unwrap();
    let reasons = |e: &attenuo_audit::Export, shipped: &str| {
        let r = attenuo_audit::cross_check_anchors(e, &anchors(shipped), &keys);
        assert!(!r.ok);
        r.mismatches
            .into_iter()
            .map(|m| (m.seq, m.line, m.reason))
            .collect::<Vec<_>>()
    };
    // A log restored to before the second prune: it verifies, the shipped anchor says no.
    let rewound = export("rewound.jsonl");
    assert!(verify_export(&rewound, &keys).unwrap().report.ok);
    let r = reasons(&rewound, "shipped.jsonl");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!((r[0].0, r[0].1), (10, 6));
    assert!(r[0].2.starts_with("REWOUND: "), "{r:?}");
    // An export taken before the second prune, whose boundary lies inside it.
    let stale = export("stale.jsonl");
    assert!(verify_export(&stale, &keys).unwrap().report.ok);
    let r = reasons(&stale, "shipped.jsonl");
    assert_eq!(r.len(), 1, "{r:?}");
    assert!(
        r[0].2.contains("has its boundary inside this export"),
        "{r:?}"
    );
    // The second anchor's signature changed.
    let retained = export("retained.jsonl");
    let r = reasons(&retained, "shipped-bad-signature.jsonl");
    assert_eq!(
        r.iter().map(|m| m.2.as_str()).collect::<Vec<_>>(),
        vec![
            "shipped anchor does not verify: signature does not verify",
            "the export's header anchor is not in the shipped file (it was not shipped, or \
             the file is incomplete)",
        ]
    );
    // Another anchor for the boundary in the header of archive-2.
    let r = reasons(&export("archive-2.jsonl"), "shipped-other-anchor.jsonl");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0].0, 5);
    assert!(r[0].2.contains("another anchor for this boundary"), "{r:?}");
    // A forged checkpoint envelope relabelled with the anchor format: the checkpoint check
    // reports it, the anchors still match.
    let text = read(GOLDEN_RELABELLED);
    let r = cross_check(&retained, &parse_shipped(&text).unwrap(), &keys);
    assert!(!r.ok);
    assert_eq!(r.mismatches.len(), 1, "{r:?}");
    assert_eq!((r.mismatches[0].seq, r.mismatches[0].line), (14, 5));
    assert!(
        r.mismatches[0].reason.contains("unsupported format"),
        "{r:?}"
    );
    assert!(attenuo_audit::cross_check_anchors(&retained, &anchors(GOLDEN_RELABELLED), &keys).ok);
    // A bare line with the anchor format and no `anchor` is not skipped either.
    let bare = read("shipped.jsonl") + "{\"format\":\"attenuo-shipped-anchor-v1\"}\n";
    assert!(parse_shipped(&bare).is_err());
    // S3 objects joined with no newline parse as the same anchors.
    let joined = read("shipped.jsonl").replace('\n', "");
    let a = attenuo_audit::parse_shipped_anchors(&joined).unwrap();
    assert_eq!(a.len(), 2);
    assert_eq!(
        parse_shipped(&joined).unwrap().len(),
        parse_shipped(&read("shipped.jsonl")).unwrap().len()
    );
    assert!(attenuo_audit::cross_check_anchors(&retained, &a, &keys).ok);
}

/// `verify_retained_through`, which an automatic prune runs before it prunes: it walks the
/// prefix only, so a break above it is not its business, and a break, a rewritten entry or a
/// bad checkpoint inside it fails it. After a prune it walks from the anchor, on to the prune
/// record when that lies above the boundary asked for.
#[test]
fn the_prefix_verify_sees_the_prefix_only() {
    let issuer = issuer();
    let k = keys(&issuer);
    let log = log_of(&issuer, 10, 45);
    let r = log.verify_retained_through(20, &k).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(
        (r.entries, r.last_signed_seq, r.pruned_through),
        (20, Some(20), None)
    );
    // A rewritten entry above the prefix is not seen; inside it, it is.
    exec(
        &log,
        "UPDATE audit SET entry_hash = 'ff' || substr(entry_hash, 3) WHERE seq = 33",
    );
    assert!(log.verify_retained_through(20, &k).unwrap().ok);
    assert!(!log.verify_chain_signed(&k).unwrap().ok);
    let log = log_of(&issuer, 10, 45);
    exec(
        &log,
        "UPDATE audit SET entry_hash = 'ff' || substr(entry_hash, 3) WHERE seq = 7",
    );
    let r = log.verify_retained_through(20, &k).unwrap();
    assert!(!r.ok, "{r:?}");
    assert_eq!(r.first_bad_seq, Some(7));
    // A checkpoint in the prefix signed by another key.
    let log = log_of(&issuer, 10, 45);
    let other = self::issuer();
    let forged = Checkpoint::sign(
        &other.detached_signer(),
        10,
        &log.entry_at(10).unwrap().unwrap().entry_hash,
        now(),
    )
    .unwrap();
    let (sig, kid) = (forged.signature.clone(), forged.kid.clone());
    log.with_connection(|c| {
        c.execute(
            "UPDATE checkpoints SET signature = ?1, kid = ?2 WHERE seq = 10",
            rusqlite::params![sig, kid],
        )?;
        Ok(())
    })
    .unwrap();
    let r = log.verify_retained_through(20, &k).unwrap();
    assert!(!r.ok, "{r:?}");
    assert_eq!(r.bad_checkpoints[0].seq, 10);

    // After a prune through 20 (the prune record at 46): a prefix through 30 is walked from
    // the anchor and on to the prune record, so the anchor is checked whole.
    let log = log_of(&issuer, 10, 45);
    prune(&log, 20, None).unwrap();
    finish(&log, 100);
    let r = log.verify_retained_through(30, &k).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(r.pruned_through, Some(20));
    assert_eq!(r.entries, 26, "21..=46: on to the prune record");
    // The prefix starts after the boundary only through a valid anchor.
    exec(&log, "UPDATE audit_anchors SET signature = 'AAAA'");
    let r = log.verify_retained_through(30, &k).unwrap();
    assert!(!r.ok, "{r:?}");
    assert_eq!(r.pruned_through, None);
}
