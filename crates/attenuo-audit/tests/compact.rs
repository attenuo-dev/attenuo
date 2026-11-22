//! Compacting the database file offline (`attenuo audit compact`, `attenuo_audit::compact`):
//! a pruned file shrinks and every store reads back the same, cursors and positions included;
//! a dry run changes no byte; and each refusal (the file in use, too little free space, another
//! schema version, a corrupt file, a broken chain, a table whose rowids `VACUUM` may renumber)
//! leaves the file as it was. A change slipped in after `VACUUM` fails the check after it.

mod common;

use std::path::{Path, PathBuf};

use attenuo_audit::HopLimit;
use attenuo_audit::{
    compact, Approval, ApprovalState, ApprovalStore, AuditSink, CheckpointKeys, CompactError,
    CompactOptions, EntryFilter, LeaseRegistry, NewNotice, Order, PruneLimits, ReplayOutcome,
    ReplayStore, RunLabel, RunLimits, RunState, SqliteAudit, SqliteLeaseStore, WriterFence,
    AFTER_VACUUM_STEPS, PRUNE_TOOL,
};
use attenuo_core::fingerprint::{Fingerprint, FingerprintKind};
use attenuo_core::windows::window_charges;
use attenuo_core::Limits;
use attenuo_core::{
    Charge, Decision, DecisionRecord, LeaseId, LimitKind, RecordKind, ToolCall, WindowKind,
};
use attenuo_token::{Issuer, IssuerConfig};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use common::{chain, record, t0, user};
use rusqlite::Connection;
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

/// Entries written before the prune, and the boundary (a checkpoint every 10).
const ENTRIES: usize = 1500;
const THROUGH: u64 = 1400;

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

fn now() -> OffsetDateTime {
    t0() + Duration::days(200)
}

/// The prune record, as the server writes it.
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

fn id(s: &str) -> LeaseId {
    LeaseId::new(s)
}

fn approval(n: u32) -> Approval {
    Approval {
        id: format!("00000000-0000-4000-8000-{n:012}"),
        chain_id: id("r0"),
        lease: id("r1"),
        call_hash: format!("h{n}"),
        server: "github".into(),
        tool: "delete_repo".into(),
        arguments: json!({"repo": "alice/site", "n": n}),
        labels: Vec::new(),
        untrusted_args: Vec::new(),
        decision_id: format!("d-gated-{n}"),
        chain: chain("alice", ("r0", "r1")),
        created_at: now(),
        expires_at: now() + Duration::hours(1),
        state: ApprovalState::Pending,
        approver: None,
        decided_at: None,
        consumed_by: None,
        jkt: None,
    }
}

fn calls(lease: &str, max: u64) -> Charge {
    Charge {
        hop: 0,
        cap: 0,
        lease: id(lease),
        kind: LimitKind::Calls,
        arg: None,
        value: None,
        amount: 1,
        max,
        usage: false,
    }
}

fn fp(text: &str) -> Fingerprint {
    Fingerprint::of(FingerprintKind::Leaf, text)
}

const SESSION: &str = "5e55101100000000000000000000000000000000000000000000000000000001";

/// A log of [`ENTRIES`] entries pruned through [`THROUGH`] (the deletes done), then leases,
/// approvals with a gap in their positions, run limits, per-user windows, spans, run labels,
/// sessions, hop limits, outbox notices, credential markers and the DPoP marker, with some
/// rows deleted again so the tables have gaps. Every store is closed on return.
fn populated(path: &Path, issuer: &Issuer) {
    let log = SqliteAudit::open(path)
        .unwrap()
        .with_checkpointing(issuer.detached_signer(), 10);
    for i in 0..ENTRIES {
        log.append(record(i)).unwrap();
    }
    let limits = PruneLimits {
        min_age: Duration::days(90),
        sink: None,
        now: now(),
    };
    log.prune_through(THROUGH, Some("ab".repeat(32)), &limits, prune_record)
        .unwrap();
    loop {
        let step = log.prune_step(500).unwrap();
        if step.through_seq.is_none() || step.done {
            break;
        }
    }
    // A few entries after the prune, and a checkpoint over the head.
    for i in 0..15 {
        log.append(record(ENTRIES + i)).unwrap();
    }
    log.checkpoint_signed(now()).unwrap();

    let store = SqliteLeaseStore::open(path).unwrap();
    let exp = now() + Duration::hours(1);
    store.register(&id("r0"), None, exp).unwrap();
    for i in 1..30 {
        let parent = id(&format!("r{}", (i - 1) / 3));
        store
            .register(&id(&format!("r{i}")), Some(&parent), exp)
            .unwrap();
    }
    store.bind(&id("r0"), "chain-digest-r0").unwrap();
    store
        .record_originating_user(&id("r0"), "https://idp.example", "alice")
        .unwrap();
    store.record_subject(&id("r4"), "bob").unwrap();
    store.revoke(&id("r9"), "test", now()).unwrap();
    store
        .record_session(SESSION, "github", &id("r0"), now())
        .unwrap();
    store
        .add_label(
            &id("r0"),
            &RunLabel {
                source: "github/read_file".into(),
                decision_id: "d-label".into(),
                seq: 1405,
                at: now(),
            },
        )
        .unwrap();
    store
        .add_spans(&id("r0"), 1406, &[fp("pay xx00evil"), fp("shared value")])
        .unwrap();
    store
        .record_hop_limits(
            &id("r1"),
            &[HopLimit {
                cap: 0,
                server: "banking".into(),
                tool: "send_money".into(),
                limits: Limits::default().with_calls(30),
            }],
        )
        .unwrap();
    for n in 0..12 {
        store
            .charge(&format!("d-{n}"), &[calls("r1", 30)], now())
            .unwrap();
    }
    store.refund("d-3", now()).unwrap();
    let call = ToolCall::new("bank", "send_money", json!({"amount": 5}));
    let windows = window_charges(
        &user("alice"),
        &call,
        Some("amount"),
        &WindowKind::ALL,
        now(),
    );
    store
        .charge_windowed("d-w", &[], &windows, now(), false)
        .unwrap();
    for n in 1..=9 {
        store.create_approval(&approval(n)).unwrap();
    }
    // A gap in the positions, in the middle and at the end.
    store.remove_approval(&approval(4).id).unwrap();
    store.remove_approval(&approval(9).id).unwrap();
    for n in 1..=6 {
        store
            .outbox_insert(
                NewNotice {
                    event_id: &format!("evt-{n}"),
                    kind: "approval.pending",
                    approval_id: &approval(n).id,
                    body: format!("{{\"n\":{n}}}").as_bytes(),
                },
                now(),
            )
            .unwrap();
    }
    let first = store.outbox_open(1).unwrap()[0].id;
    store.outbox_delivered(first + 1, now()).unwrap();
    assert_eq!(
        store
            .use_all_once(
                &[("iss\njti-1", 4_000_000_000), ("iss\njti-2", 4_000_000_000)],
                1_000,
                100
            )
            .unwrap(),
        ReplayOutcome::Recorded
    );
    store.extend_dpop_max_iat(4_000_000_000).unwrap();
    for i in 0..6 {
        store
            .bind(&id(&format!("r{}", 20 + i)), &format!("chain-digest-{i}"))
            .unwrap();
    }
    // Gaps in the implicit rowids, as deletes leave them: a lease (a leaf), a binding and a
    // charge in the middle of their tables. `VACUUM` must not close them.
    store
        .with_connection(|c| {
            c.execute_batch(
                "DELETE FROM leases WHERE id = 'r28';
                 DELETE FROM lease_bindings WHERE id = 'r22';
                 DELETE FROM budget_charges WHERE decision_id = 'd-5';",
            )?;
            Ok(())
        })
        .unwrap();
}

/// What the stores answer, through their normal APIs, as text.
fn reads(path: &Path, issuer: &Issuer) -> Vec<String> {
    let log = SqliteAudit::open(path).unwrap();
    let store = SqliteLeaseStore::open(path).unwrap();
    let mut out = Vec::new();
    let mut push = |what: &str, v: String| out.push(format!("{what}: {v}"));

    push(
        "verify",
        format!("{:?}", log.verify_chain_signed(&keys(issuer)).unwrap()),
    );
    push("len", format!("{:?}", log.len().unwrap()));
    push("first", format!("{:?}", log.first_retained_seq().unwrap()));
    push("head", format!("{:?}", log.head().unwrap()));
    push("anchor", format!("{:?}", log.newest_anchor().unwrap()));
    push(
        "anchors",
        format!("{:?}", log.anchors_before(u64::MAX, 10).unwrap()),
    );
    let entries = log.range(0, 1_000_000).unwrap();
    push("range", format!("{entries:?}"));
    for e in entries.iter().step_by(7) {
        let rid = e.record.id.to_string();
        push(
            "by id",
            format!("{:?}", log.entry_by_record_id(&rid).unwrap().map(|e| e.seq)),
        );
        push(
            "at",
            format!("{:?}", log.entry_at(e.seq).unwrap().map(|e| e.entry_hash)),
        );
        push(
            "covering",
            format!("{:?}", log.checkpoint_covering(e.seq).unwrap()),
        );
    }
    // Paging as `GET /admin/audit` pages, both ways, five entries a page.
    for order in [Order::Ascending, Order::Descending] {
        let (mut lo, mut hi) = (0u64, u64::MAX);
        loop {
            let page = log
                .entries_matching(lo, hi, &EntryFilter::default(), order, 5)
                .unwrap();
            push(
                "page",
                format!("{:?}", page.iter().map(|e| e.seq).collect::<Vec<_>>()),
            );
            let Some(last) = page.last() else { break };
            match order {
                Order::Ascending => lo = last.seq + 1,
                Order::Descending => hi = last.seq - 1,
            }
            if page.len() < 5 {
                break;
            }
        }
    }
    let mut before = u64::MAX;
    loop {
        let page = log.checkpoints_before(before, 4).unwrap();
        push("checkpoints", format!("{page:?}"));
        match page.last() {
            Some(c) if page.len() == 4 => before = c.seq,
            _ => break,
        }
    }

    for i in 0..30 {
        let l = id(&format!("r{i}"));
        push("lease", format!("{:?}", store.get(&l).unwrap()));
        push("binding", format!("{:?}", store.binding(&l).unwrap()));
        push("subject", format!("{:?}", store.subject(&l).unwrap()));
        push("user", format!("{:?}", store.originating_user(&l).unwrap()));
        push("hops", format!("{:?}", store.hop_limits(&l).unwrap()));
        push(
            "summary",
            format!("{:?}", store.budget_summary(&l).unwrap()),
        );
    }
    push(
        "tree",
        format!("{:?}", store.subtree(&id("r0"), 100).unwrap()),
    );
    push(
        "tree capped",
        format!("{:?}", store.subtree(&id("r0"), 7).unwrap()),
    );
    push(
        "sessions",
        format!("{:?}", store.sessions(SESSION).unwrap()),
    );
    push("labels", format!("{:?}", store.labels(&id("r0")).unwrap()));
    push(
        "spans",
        format!(
            "{:?}",
            store
                .find_spans(&id("r0"), &[fp("shared value"), fp("absent")])
                .unwrap()
        ),
    );
    push(
        "used",
        format!("{:?}", store.budget_used(&[calls("r1", 30)]).unwrap()),
    );
    let call = ToolCall::new("bank", "send_money", json!({"amount": 5}));
    let windows = window_charges(
        &user("alice"),
        &call,
        Some("amount"),
        &WindowKind::ALL,
        now(),
    );
    push(
        "windows",
        format!("{:?}", store.window_used(&windows).unwrap()),
    );
    // Approvals as `GET /admin/approvals` pages them: by position, two a page.
    let mut cursor = None;
    loop {
        let page = store.approvals(None, None, cursor, 2).unwrap();
        push(
            "approvals",
            format!(
                "{:?}",
                page.iter()
                    .map(|(p, a)| (*p, a.id.clone()))
                    .collect::<Vec<_>>()
            ),
        );
        match page.last() {
            Some((p, _)) if page.len() == 2 => cursor = Some(*p),
            _ => break,
        }
    }
    push(
        "approval",
        format!("{:?}", store.approval(&approval(5).id).unwrap()),
    );
    push(
        "pending",
        format!("{:?}", store.pending_approvals(100).unwrap()),
    );
    push("outbox", format!("{:?}", store.outbox_open(100).unwrap()));
    push(
        "outbox last",
        format!("{:?}", store.outbox_last_open_id().unwrap()),
    );
    push(
        "outbox id",
        format!("{:?}", store.outbox_open_id("evt-5").unwrap()),
    );
    push("dpop", format!("{:?}", store.dpop_max_iat().unwrap()));
    out
}

/// The rowid of every row of the tables whose rowid is not an `INTEGER PRIMARY KEY`.
fn implicit_rowids(path: &Path) -> Vec<(String, Vec<i64>)> {
    let conn = Connection::open(path).unwrap();
    [
        "leases",
        "lease_bindings",
        "lease_subjects",
        "lease_sessions",
        "run_labels",
        "budget_counters",
        "budget_charges",
        "budget_meta",
        "hop_limits",
        "user_window_charges",
        "audit_meta",
    ]
    .iter()
    .map(|t| {
        let rows: Vec<i64> = conn
            .prepare(&format!("SELECT rowid FROM {t} ORDER BY rowid"))
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        ((*t).to_string(), rows)
    })
    .collect()
}

fn options() -> CompactOptions {
    CompactOptions::default().busy_timeout(std::time::Duration::from_millis(200))
}

fn refused(r: Result<attenuo_audit::CompactReport, CompactError>) -> (&'static str, String) {
    match r {
        Err(CompactError::Refused { code, detail }) => (code, detail),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The database file and its `-wal`, byte for byte (`None` for a missing file).
fn bytes(path: &Path) -> (Vec<u8>, Option<Vec<u8>>) {
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    (
        std::fs::read(path).unwrap(),
        std::fs::read(PathBuf::from(wal)).ok(),
    )
}

fn small_file(dir: &Path, issuer: &Issuer) -> PathBuf {
    let path = dir.join("audit.sqlite");
    let log = SqliteAudit::open(&path)
        .unwrap()
        .with_checkpointing(issuer.detached_signer(), 10);
    for i in 0..30 {
        log.append(record(i)).unwrap();
    }
    path
}

// --- the round trip --------------------------------------------------------------------------

/// A pruned, populated file gets smaller, its free pages go to zero, and every store answers
/// exactly as before through its normal APIs: the log verifies with the keys, every page of
/// entries, checkpoints and approvals is the same, as are the lease tree, the run limits, the
/// windows, the spans, the outbox and the markers. Every implicit rowid is kept. New rows
/// continue where the old ones stopped: the next seq, approval position and outbox id are
/// above every earlier one, also above the positions freed by deletes.
#[test]
fn a_pruned_populated_file_shrinks_and_reads_back_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.sqlite");
    let issuer = issuer();
    populated(&path, &issuer);
    let before = reads(&path, &issuer);
    let rowids = implicit_rowids(&path);
    for table in ["leases", "lease_bindings", "budget_charges"] {
        let ids = &rowids.iter().find(|(t, _)| t == table).unwrap().1;
        assert!(
            ids.windows(2).any(|w| w[1] != w[0] + 1),
            "{table} has a gap to keep: {ids:?}"
        );
    }
    assert!(
        before
            .iter()
            .any(|l| l.starts_with("verify: SignedVerifyReport") && l.contains("ok: true")),
        "{:?}",
        before[0]
    );

    let report = compact(&path, options()).unwrap();
    assert!(!report.dry_run);
    let after_state = report.after.as_ref().unwrap();
    assert!(
        report.before.free_bytes > 1_000_000,
        "{:?}",
        report.before.free_bytes
    );
    assert_eq!(after_state.free_bytes, 0);
    assert!(
        report.disk_bytes_after < report.disk_bytes_before,
        "{report:?}"
    );
    assert!(report.bytes_returned() > 1_000_000, "{report:?}");
    let len = std::fs::metadata(&path).unwrap().len();
    assert_eq!(len, report.disk_bytes_after);
    assert_eq!(after_state.file_bytes, len);
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    assert!(std::fs::metadata(PathBuf::from(wal)).map_or(true, |m| m.len() == 0));
    assert_eq!(report.before.pruned_through, Some(THROUGH));
    assert_eq!(report.before.head_seq, after_state.head_seq);
    assert_eq!(report.before.tables, after_state.tables);
    assert!(report.before.chain.ok);

    assert_eq!(implicit_rowids(&path), rowids);
    let after = reads(&path, &issuer);
    assert_eq!(before.len(), after.len());
    for (b, a) in before.iter().zip(&after) {
        assert_eq!(b, a);
    }

    // New rows continue above every earlier one.
    let log = SqliteAudit::open(&path).unwrap();
    let head = log.head().unwrap().unwrap().seq;
    let next = log.append(record(9_999)).unwrap();
    assert_eq!(next.seq, head + 1);
    let store = SqliteLeaseStore::open(&path).unwrap();
    store.create_approval(&approval(10)).unwrap();
    let positions: Vec<u64> = store
        .approvals(None, None, None, 100)
        .unwrap()
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    assert_eq!(
        positions,
        vec![10, 8, 7, 6, 5, 3, 2, 1],
        "9 and 4 are never given again"
    );
    let last = store.outbox_last_open_id().unwrap().unwrap();
    let added = store
        .outbox_insert(
            NewNotice {
                event_id: "evt-7",
                kind: "approval.pending",
                approval_id: &approval(10).id,
                body: b"{}",
            },
            now(),
        )
        .unwrap()
        .unwrap();
    assert!(added > last);
    assert_eq!(
        store
            .use_all_once(&[("iss\njti-1", 4_000_000_000)], 2_000, 100)
            .unwrap(),
        ReplayOutcome::Replayed,
        "a credential redeemed before the compaction stays redeemed"
    );
}

/// A dry run takes the locks and runs the checks before `VACUUM`, reports what it would free,
/// and leaves the file and its WAL byte for byte as they were.
#[test]
fn a_dry_run_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.sqlite");
    let issuer = issuer();
    populated(&path, &issuer);
    let was = bytes(&path);
    let report = compact(&path, options().dry_run(true)).unwrap();
    assert!(report.dry_run);
    assert!(report.after.is_none());
    assert!(report.before.free_bytes > 1_000_000);
    assert_eq!(report.bytes_returned(), 0);
    assert_eq!(report.disk_bytes_after, report.disk_bytes_before);
    assert_eq!(bytes(&path), was);
}

/// A dry run, or a refusal, on a file whose WAL still holds commits (a server that was killed)
/// leaves the WAL alone too: closing would otherwise copy it into the file.
#[test]
fn a_dry_run_leaves_a_wal_with_frames_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    // Commits that stay in the WAL: a connection that never checkpoints, forgotten, not closed.
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "PRAGMA wal_autocheckpoint=0; INSERT INTO hop_limits (lease, limits) VALUES ('w', '[]');",
    )
    .unwrap();
    std::mem::forget(conn);
    // The forgotten connection still holds its lock, as a killed process would not: take a
    // copy of both files, as they would be on disk after the kill.
    let copy = dir.path().join("copy.sqlite");
    std::fs::copy(&path, &copy).unwrap();
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    let mut copy_wal = copy.as_os_str().to_owned();
    copy_wal.push("-wal");
    std::fs::copy(PathBuf::from(&wal), PathBuf::from(&copy_wal)).unwrap();
    let was = bytes(&copy);
    assert!(was.1.as_ref().is_some_and(|w| !w.is_empty()));
    compact(&copy, options().dry_run(true)).unwrap();
    assert_eq!(bytes(&copy), was);
    // So does a refusal.
    let (code, _) = refused(compact(&copy, options().with_free_space_probe(|_| Ok(0))));
    assert_eq!(code, "disk_space");
    assert_eq!(bytes(&copy), was);
    // And the real run takes the WAL in and truncates it.
    let report = compact(&copy, options()).unwrap();
    assert_eq!(report.before.entries, 30);
    assert!(bytes(&copy).1.is_none_or(|w| w.is_empty()));
}

// --- refusals ----------------------------------------------------------------------------------

/// Another connection with a write under way: refused, nothing changed.
#[test]
fn refused_while_another_connection_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    let other = Connection::open(&path).unwrap();
    other
        .execute_batch(
            "BEGIN IMMEDIATE; UPDATE audit_meta SET value = value WHERE key = 'entry_hash';",
        )
        .unwrap();
    let was = std::fs::read(&path).unwrap();
    let (code, detail) = refused(compact(&path, options()));
    assert_eq!(code, "in_use");
    assert!(
        detail.contains("the database is in use; stop the server first"),
        "{detail}"
    );
    other.execute_batch("COMMIT").unwrap();
    drop(other);
    assert_eq!(std::fs::read(&path).unwrap(), was);
}

/// Another connection that has read the file and sits idle, no transaction open: refused too,
/// because in WAL mode it keeps a shared lock until it closes. So is an idle store of this
/// crate (what a running server holds), even without the fence.
#[test]
fn refused_while_an_idle_connection_has_the_file_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    let other = Connection::open(&path).unwrap();
    let n: i64 = other
        .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 30);
    assert_eq!(refused(compact(&path, options())).0, "in_use");
    drop(other);

    let store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(refused(compact(&path, options())).0, "in_use");
    drop(store);
    let log = SqliteAudit::open(&path).unwrap();
    assert_eq!(refused(compact(&path, options())).0, "in_use");
    drop(log);
    compact(&path, options()).unwrap();
}

/// The single-writer fence that a running server holds, idle or not: refused, naming the lock.
#[test]
fn refused_while_the_fence_is_held() {
    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    let fence = WriterFence::acquire(&path).unwrap();
    let (code, detail) = refused(compact(&path, options()));
    assert_eq!(code, "in_use");
    assert!(detail.contains("audit.sqlite.lock"), "{detail}");
    drop(fence);
    compact(&path, options()).unwrap();
}

/// The limit of the check, pinned: a connection that was opened but has not read anything
/// holds no lock and cannot be seen, so the compaction runs. It then reads the compacted file
/// correctly once it starts.
#[test]
fn a_connection_that_has_read_nothing_is_not_seen() {
    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    let other = Connection::open(&path).unwrap();
    compact(&path, options()).unwrap();
    let n: i64 = other
        .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 30);
}

/// Too little free space for the copy `VACUUM` writes: refused with the numbers.
#[test]
fn refused_when_free_space_is_short() {
    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    let was = std::fs::read(&path).unwrap();
    let (code, detail) = refused(compact(
        &path,
        options().with_free_space_probe(|_| Ok(4096)),
    ));
    assert_eq!(code, "disk_space");
    assert!(detail.contains("bytes needed"), "{detail}");
    assert!(detail.contains("4096 bytes available"), "{detail}");
    assert_eq!(std::fs::read(&path).unwrap(), was);
    // A probe that fails is a refusal too, not a guess.
    let (code, _) = refused(compact(
        &path,
        options().with_free_space_probe(|_| Err(std::io::Error::other("no statvfs"))),
    ));
    assert_eq!(code, "disk_space");
    // Enough space: it runs.
    compact(&path, options().with_free_space_probe(|_| Ok(u64::MAX))).unwrap();
}

/// A file at another schema version is refused, older or newer: nothing is migrated here.
#[test]
fn refused_at_another_schema_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    for v in [
        attenuo_audit::SCHEMA_VERSION - 1,
        attenuo_audit::SCHEMA_VERSION + 1,
    ] {
        Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", v)
            .unwrap();
        let was = std::fs::read(&path).unwrap();
        let (code, detail) = refused(compact(&path, options()));
        assert_eq!(code, "schema_version");
        assert!(detail.contains(&format!("schema version {v}")), "{detail}");
        assert_eq!(std::fs::read(&path).unwrap(), was);
    }
}

/// A file whose `integrity_check` is not `ok` is refused.
#[test]
fn refused_on_a_corrupt_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    let (root, page_size): (i64, i64) = {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        (
            conn.query_row(
                "SELECT rootpage FROM sqlite_master WHERE name = 'audit_at_idx'",
                [],
                |r| r.get(0),
            )
            .unwrap(),
            conn.query_row("PRAGMA page_size", [], |r| r.get(0))
                .unwrap(),
        )
    };
    // Zero the index's root page: the schema and the tables still read.
    let mut file = std::fs::read(&path).unwrap();
    let start = usize::try_from((root - 1) * page_size).unwrap();
    let end = start + usize::try_from(page_size).unwrap();
    file[start..end].fill(0);
    std::fs::write(&path, &file).unwrap();
    let (code, detail) = refused(compact(&path, options()));
    assert_eq!(code, "integrity");
    assert!(detail.contains("integrity_check"), "{detail}");
    assert_eq!(std::fs::read(&path).unwrap(), file);
}

/// An entry changed in place: the chain does not verify, and the freed pages may be evidence.
#[test]
fn refused_on_a_broken_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "UPDATE audit SET record_json = replace(record_json, 'policy_', 'policy-') \
             WHERE seq = 4",
        )
        .unwrap();
    let (code, detail) = refused(compact(&path, options()));
    assert_eq!(code, "chain_broken");
    assert!(detail.contains("first bad seq 4"), "{detail}");
}

/// A table `VACUUM` may give new rowids (no `INTEGER PRIMARY KEY`, no index) is refused by
/// name. None of attenuo's own tables is one; this one was added by hand.
#[test]
fn refused_with_a_table_whose_rowids_may_change() {
    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE extra (note TEXT); INSERT INTO extra VALUES ('x');")
        .unwrap();
    let (code, detail) = refused(compact(&path, options()));
    assert_eq!(code, "rowid_unsafe");
    assert!(detail.contains("extra"), "{detail}");
}

/// A missing file is an error and is not created.
#[test]
fn a_missing_file_is_not_created() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nope.sqlite");
    assert!(matches!(
        compact(&path, options()),
        Err(CompactError::Failed(_))
    ));
    assert!(!path.exists());
}

// --- the check after VACUUM ----------------------------------------------------------------

/// Anything that differs after `VACUUM` is a post-check failure naming it: a row of a table,
/// the head of the log, the schema.
#[test]
fn a_change_after_vacuum_fails_the_check() {
    let issuer = issuer();
    for (sql, want) in [
        (
            "UPDATE audit_meta SET value = 'x' WHERE key = 'entry_hash'",
            "table audit_meta",
        ),
        ("DELETE FROM audit WHERE seq = 30", "head was"),
        ("CREATE INDEX extra_idx ON audit(server)", "schema was"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = small_file(dir.path(), &issuer);
        let sql = sql.to_string();
        let err = compact(
            &path,
            options().after_vacuum(move |c| c.execute_batch(&sql)),
        )
        .unwrap_err();
        let CompactError::PostCheck { mismatches } = &err else {
            panic!("expected a post-check failure, got {err:?}");
        };
        assert!(
            mismatches.iter().any(|m| m.contains(want)),
            "{want}: {mismatches:?}"
        );
        let text = err.to_string();
        assert!(text.contains("restore the backup"), "{text}");
    }
}

/// A rowid that moved is a difference, not only a changed value: the digest reads every rowid.
#[test]
fn a_moved_rowid_fails_the_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    let err = compact(
        &path,
        options().after_vacuum(|c| c.execute_batch("UPDATE budget_meta SET rowid = rowid + 100")),
    )
    .unwrap_err();
    let CompactError::PostCheck { mismatches } = &err else {
        panic!("expected a post-check failure, got {err:?}");
    };
    assert!(
        mismatches.iter().any(|m| m.contains("table budget_meta")),
        "{mismatches:?}"
    );
}

/// A failure at any step once `VACUUM` committed is `Unverified`, which names the step and
/// asks for the backup: the file was rewritten and could not be checked.
#[test]
fn a_failure_after_vacuum_is_unverified() {
    let issuer = issuer();
    for step in AFTER_VACUUM_STEPS {
        let dir = tempfile::tempdir().unwrap();
        let path = small_file(dir.path(), &issuer);
        let err = compact(&path, options().fail_after_vacuum_at(step)).unwrap_err();
        let CompactError::Unverified { step: at, .. } = &err else {
            panic!("{step}: expected Unverified, got {err:?}");
        };
        assert_eq!(at, step);
        let text = err.to_string();
        assert!(text.contains("VACUUM rewrote the file"), "{text}");
        assert!(text.contains("restore the backup"), "{text}");
    }
}

/// A file not in WAL mode is refused before anything else: the server never leaves one, and
/// the in-use check relies on WAL mode.
#[test]
fn refused_when_not_in_wal_mode() {
    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    let mode: String = Connection::open(&path)
        .unwrap()
        .query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
    let was = std::fs::read(&path).unwrap();
    let (code, detail) = refused(compact(&path, options()));
    assert_eq!(code, "not_wal");
    assert!(detail.contains("journal mode `delete`"), "{detail}");
    assert_eq!(std::fs::read(&path).unwrap(), was);
}

/// A column named like the rowid hides that name; the digest reads the rowid through a name
/// that is not hidden, and a table whose columns hide all three is refused.
#[test]
fn a_column_named_like_the_rowid() {
    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TABLE shadow (_rowid_ TEXT, note TEXT);
             CREATE INDEX shadow_idx ON shadow(note);
             INSERT INTO shadow VALUES ('a', 'x'), ('b', 'y');",
        )
        .unwrap();
    // `rowid` still reads the rowid: a moved one is caught.
    let err = compact(
        &path,
        options().after_vacuum(|c| c.execute_batch("UPDATE shadow SET rowid = rowid + 100")),
    )
    .unwrap_err();
    assert!(
        matches!(&err, CompactError::PostCheck { mismatches } if mismatches.iter().any(|m| m.contains("table shadow"))),
        "{err:?}"
    );

    let dir = tempfile::tempdir().unwrap();
    let path = small_file(dir.path(), &issuer());
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TABLE hidden (_rowid_ TEXT, rowid TEXT, oid TEXT);
             CREATE INDEX hidden_idx ON hidden(oid);",
        )
        .unwrap();
    let (code, detail) = refused(compact(&path, options()));
    assert_eq!(code, "rowid_unsafe");
    assert!(
        detail.contains("hidden (its columns hide every name of the rowid)"),
        "{detail}"
    );
}
