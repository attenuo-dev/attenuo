//! Versioned schema migrations (audit finding C-7): new files, files from before schema versions
//! in the shapes earlier builds wrote (adoption), files from a newer build (refused), and the
//! audit log and the lease store opening one file or two.
//!
//! The pre-versioning shapes are built by hand from the `CREATE TABLE` statements of the commits
//! that introduced them (named on each fixture); entries and approvals are written by the current
//! code into a scratch file and copied row for row into the old tables, so the rows are real.

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Barrier};

use attenuo_audit::{
    Approval, ApprovalState, ApprovalStore, AuditError, AuditSink, CheckpointKeys, LeaseRegistry,
    NewNotice, ReplayOutcome, ReplayStore, RunState, SqliteAudit, SqliteLeaseStore,
    ENTRY_HASH_VERSION, SCHEMA_VERSION,
};
use attenuo_core::LeaseId;
use attenuo_token::{Issuer, IssuerConfig};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use common::{chain, record, t0};
use rusqlite::types::ValueRef;
use rusqlite::Connection;
use serde_json::json;
use time::Duration;

const SESSION: &str = "5e55101100000000000000000000000000000000000000000000000000000001";

fn id(s: &str) -> LeaseId {
    LeaseId::new(s)
}

fn issuer() -> Issuer {
    Issuer::generate(IssuerConfig {
        issuer: "https://attenuo.test".into(),
        audience: "attenuo".into(),
        max_depth: 4,
        default_ttl: Duration::minutes(5),
    })
}

fn keys(issuer: &Issuer) -> CheckpointKeys {
    let keys: Vec<serde_json::Value> = issuer
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

fn user_version(path: &Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap()
}

fn set_user_version(path: &Path, v: i64) {
    Connection::open(path)
        .unwrap()
        .pragma_update(None, "user_version", v)
        .unwrap();
}

/// Every table and index name in the file.
fn objects(path: &Path) -> Vec<String> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT type || ' ' || name FROM sqlite_master \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .unwrap();
    let rows = stmt.query_map([], |r| r.get(0)).unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

/// The full `sqlite_master` (type, name, SQL), for "nothing changed" checks.
fn master(path: &Path) -> Vec<(String, String, Option<String>)> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn
        .prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
        .unwrap();
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

fn value_text(v: ValueRef<'_>) -> String {
    match v {
        ValueRef::Null => "NULL".into(),
        ValueRef::Integer(i) => format!("i:{i}"),
        ValueRef::Real(f) => format!("r:{f}"),
        ValueRef::Text(t) => format!("t:{}", hex::encode(t)),
        ValueRef::Blob(b) => format!("b:{}", hex::encode(b)),
    }
}

/// Every row of every table, value for value (text and blobs as hex, so byte for byte), keyed
/// by table and limited to the columns each table has now. Rows are sorted, so `WITHOUT ROWID`
/// tables compare too.
fn dump(path: &Path) -> BTreeMap<String, (Vec<String>, Vec<String>)> {
    let conn = Connection::open(path).unwrap();
    let tables: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .unwrap();
        let rows = stmt.query_map([], |r| r.get(0)).unwrap();
        rows.collect::<Result<_, _>>().unwrap()
    };
    let mut out = BTreeMap::new();
    for t in tables {
        let cols: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM pragma_table_info(?1)")
                .unwrap();
            let rows = stmt.query_map([&t], |r| r.get(0)).unwrap();
            rows.collect::<Result<_, _>>().unwrap()
        };
        let mut stmt = conn.prepare(&format!("SELECT * FROM \"{t}\"")).unwrap();
        let n = cols.len();
        let mut rows: Vec<String> = stmt
            .query_map([], |r| {
                let mut vals = Vec::with_capacity(n);
                for i in 0..n {
                    vals.push(value_text(r.get_ref(i)?));
                }
                Ok(vals.join("|"))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        rows.sort();
        out.insert(t, (cols, rows));
    }
    out
}

/// Columns a migration adds with a value in every existing row, as `(table, column)`:
/// `approvals.position` (migration 2) is each row's rowid, which
/// `a_version_1_file_keeps_its_approvals_in_order` checks value for value.
const FILLED_COLUMNS: &[(&str, &str)] = &[("approvals", "position")];

/// Every row of `before` is still in `after`, value for value: every table of `before` is
/// still there, its columns first and in order, any added column NULL in the old rows (set,
/// for the columns of [`FILLED_COLUMNS`]). Rows written after the open may be added.
fn assert_rows_kept(
    before: &BTreeMap<String, (Vec<String>, Vec<String>)>,
    after: &BTreeMap<String, (Vec<String>, Vec<String>)>,
) {
    for (table, (cols, rows)) in before {
        let (now_cols, now_rows) = after
            .get(table)
            .unwrap_or_else(|| panic!("table {table} is gone"));
        assert_eq!(&now_cols[..cols.len()], &cols[..], "columns of {table}");
        let filled = |c: &str| FILLED_COLUMNS.contains(&(table.as_str(), c));
        let mut now: Vec<(String, bool)> = now_rows
            .iter()
            .map(|r| {
                let vals: Vec<&str> = r.split('|').collect();
                let added_ok = vals[cols.len()..]
                    .iter()
                    .zip(&now_cols[cols.len()..])
                    .all(|(v, c)| (*v == "NULL") != filled(c));
                (vals[..cols.len()].join("|"), added_ok)
            })
            .collect();
        for row in rows {
            let at = now
                .iter()
                .position(|(r, _)| r == row)
                .unwrap_or_else(|| panic!("a row of {table} changed or is gone: {row}"));
            assert!(
                now[at].1,
                "an added column of {table} is set (or a filled one unset) on an old row"
            );
            now.swap_remove(at);
        }
    }
}

/// `after` (a table's dump once migrated) limited to the columns `before` had, for "no row
/// added, changed or removed" checks on a table a later migration gave a column to.
/// [`assert_rows_kept`] checks that the added columns are NULL in the old rows.
fn kept_columns(
    after: &(Vec<String>, Vec<String>),
    before: &(Vec<String>, Vec<String>),
) -> (Vec<String>, Vec<String>) {
    let n = before.0.len();
    let mut rows: Vec<String> = after
        .1
        .iter()
        .map(|r| r.split('|').take(n).collect::<Vec<_>>().join("|"))
        .collect();
    rows.sort();
    (after.0[..n].to_vec(), rows)
}

/// The audit log's head as stored: `(seq, entry_hash)`.
fn head(path: &Path) -> (i64, String) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT seq, entry_hash FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

/// Every table and index of the current schema version, as a new file has them.
fn current_objects() -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.db");
    drop(SqliteAudit::open(&path).unwrap());
    objects(&path)
}

/// A log of `n` entries with signed checkpoints every 7, written by the current code.
fn write_log(path: &Path, issuer: &Issuer, n: usize) {
    let log = SqliteAudit::open(path)
        .unwrap()
        .with_checkpointing(issuer.detached_signer(), 7);
    for i in 0..n {
        log.append(record(i)).unwrap();
    }
}

fn approval(n: u32) -> Approval {
    Approval {
        id: format!("00000000-0000-4000-8000-{n:012}"),
        chain_id: id("l1"),
        lease: id("l2"),
        call_hash: "h1".into(),
        server: "github".into(),
        tool: "delete_repo".into(),
        arguments: json!({"repo": "alice/site"}),
        labels: Vec::new(),
        untrusted_args: Vec::new(),
        decision_id: "d-gated".into(),
        chain: chain("alice", ("l1", "l2")),
        created_at: t0(),
        expires_at: t0() + Duration::hours(1),
        state: ApprovalState::Pending,
        approver: None,
        decided_at: None,
        consumed_by: None,
        jkt: None,
    }
}

/// Leases `l1` -> `l2` with a binding, a subject, a session, an approval and an outbox notice,
/// written by the current code.
fn write_leases(store: &SqliteLeaseStore) {
    let exp = t0() + Duration::hours(1);
    store.register(&id("l1"), None, exp).unwrap();
    store.register(&id("l2"), Some(&id("l1")), exp).unwrap();
    store.bind(&id("l1"), "chain-digest-1").unwrap();
    store.record_subject(&id("l1"), "alice").unwrap();
    store
        .record_session(SESSION, "github", &id("l1"), t0())
        .unwrap();
    store.create_approval(&approval(1)).unwrap();
    store
        .outbox_insert(
            NewNotice {
                event_id: "evt-1",
                kind: "approval.pending",
                approval_id: &approval(1).id,
                body: b"{\"n\":1}",
            },
            t0(),
        )
        .unwrap();
}

// --- new files and the two stores -------------------------------------------------------------

/// A new file is created at the current version by whichever store opens it first; the other
/// store, and every later open, finds it current and migrates nothing.
#[test]
fn a_new_file_is_migrated_once_by_the_first_store_to_open_it() {
    for audit_first in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("attenuo.sqlite");
        let (first, second) = if audit_first {
            let a = SqliteAudit::open(&path).unwrap();
            let l = SqliteLeaseStore::open(&path).unwrap();
            (a.schema(), l.schema())
        } else {
            let l = SqliteLeaseStore::open(&path).unwrap();
            let a = SqliteAudit::open(&path).unwrap();
            a.append(record(0)).unwrap();
            (l.schema(), a.schema())
        };
        assert_eq!(first.version, SCHEMA_VERSION);
        assert_eq!(first.migrated_from, Some(0), "audit_first={audit_first}");
        assert_eq!(second.version, SCHEMA_VERSION);
        assert_eq!(second.migrated_from, None, "audit_first={audit_first}");
        assert_eq!(user_version(&path), i64::from(SCHEMA_VERSION));
        assert_eq!(objects(&path), current_objects());
        let again = SqliteAudit::open(&path).unwrap();
        assert_eq!(again.schema().migrated_from, None);
        assert!(again.verify_chain().unwrap().ok);
    }
}

/// The two stores on two files: each file is migrated once, by its own store, and each holds
/// the whole schema.
#[test]
fn separate_files_are_each_migrated_once() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.sqlite");
    let lease_path = dir.path().join("leases.sqlite");
    {
        let a = SqliteAudit::open(&audit_path).unwrap();
        let l = SqliteLeaseStore::open(&lease_path).unwrap();
        assert_eq!(a.schema().migrated_from, Some(0));
        assert_eq!(l.schema().migrated_from, Some(0));
        a.append(record(0)).unwrap();
        write_leases(&l);
    }
    for p in [&audit_path, &lease_path] {
        assert_eq!(user_version(p), i64::from(SCHEMA_VERSION));
        assert_eq!(objects(p), current_objects());
    }
    let a = SqliteAudit::open(&audit_path).unwrap();
    let l = SqliteLeaseStore::open(&lease_path).unwrap();
    assert_eq!(a.schema().migrated_from, None);
    assert_eq!(l.schema().migrated_from, None);
    assert_eq!(a.len().unwrap(), 1);
    assert_eq!(l.subject(&id("l1")).unwrap().as_deref(), Some("alice"));
}

/// Both stores opening one new file at the same moment, from two threads: neither deadlocks
/// or fails, and exactly one of them migrates it.
#[test]
fn concurrent_opens_of_one_new_file_migrate_it_exactly_once() {
    for round in 0..20 {
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("attenuo.sqlite"));
        let start = Arc::new(Barrier::new(2));
        let audit = {
            let (path, start) = (Arc::clone(&path), Arc::clone(&start));
            std::thread::spawn(move || {
                start.wait();
                SqliteAudit::open(path.as_path()).map(|s| s.schema())
            })
        };
        let leases = {
            let (path, start) = (Arc::clone(&path), Arc::clone(&start));
            std::thread::spawn(move || {
                start.wait();
                SqliteLeaseStore::open(path.as_path()).map(|s| s.schema())
            })
        };
        let a = audit.join().unwrap().unwrap();
        let l = leases.join().unwrap().unwrap();
        let migrated = [a, l].iter().filter(|s| s.migrated_from.is_some()).count();
        assert_eq!(migrated, 1, "round {round}: {a:?} {l:?}");
        assert_eq!(user_version(&path), i64::from(SCHEMA_VERSION));
    }
}

/// An in-memory store is migrated like a file.
#[test]
fn in_memory_stores_are_at_the_current_version() {
    let a = SqliteAudit::open_in_memory().unwrap();
    assert_eq!(a.schema().version, SCHEMA_VERSION);
    assert_eq!(a.schema().migrated_from, Some(0));
    let l = SqliteLeaseStore::open_in_memory().unwrap();
    assert_eq!(l.schema().migrated_from, Some(0));
}

// --- a newer file ---------------------------------------------------------------------------

/// A file a newer build wrote is refused by both stores, naming both versions, and left
/// exactly as it was.
#[test]
fn a_file_from_a_newer_build_is_refused_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attenuo.sqlite");
    write_log(&path, &issuer(), 3);
    let newer = i64::from(SCHEMA_VERSION) + 1;
    set_user_version(&path, newer);
    let (rows, schema) = (dump(&path), master(&path));

    let audit_err = SqliteAudit::open(&path).unwrap_err();
    let lease_err = SqliteLeaseStore::open(&path).unwrap_err();
    for err in [audit_err, lease_err] {
        let text = err.to_string();
        assert!(text.contains(&format!("schema version {newer}")), "{text}");
        assert!(text.contains(&format!("up to {SCHEMA_VERSION}")), "{text}");
        assert!(text.contains("no downgrade"), "{text}");
        match err {
            AuditError::SchemaTooNew { found, supported } => {
                assert_eq!(i64::from(found), newer);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected SchemaTooNew, got {other:?}"),
        }
    }
    assert_eq!(user_version(&path), newer);
    assert_eq!(dump(&path), rows);
    assert_eq!(master(&path), schema);

    // A newer file with no tables at all is refused too, and nothing is created in it.
    let empty = dir.path().join("empty.sqlite");
    set_user_version(&empty, 7);
    assert!(matches!(
        SqliteLeaseStore::open(&empty),
        Err(AuditError::SchemaTooNew { found: 7, .. })
    ));
    assert!(objects(&empty).is_empty());
}

// --- adoption: files from before schema versions ---------------------------------------------

/// A file written by the code before schema versions (the same tables as version 1, and
/// `user_version` 0) is adopted, and then migrated to the current version: no table is
/// created and no row changes, except that `approvals` gains `position` from each row's
/// rowid (migration 2); the hash chain reads the same byte for byte, the head is the same,
/// and the signed checkpoints still verify.
#[test]
fn a_file_from_the_pre_versioning_code_is_adopted_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.sqlite");
    let path = dir.path().join("attenuo.sqlite");
    let issuer = issuer();
    write_log(&source, &issuer, 25);
    write_leases(&SqliteLeaseStore::open(&source).unwrap());
    // The pre-versioning code wrote exactly version 1's tables, and never set user_version.
    version_1_copy(&source, &path);
    set_user_version(&path, 0);
    let (rows, before_head) = (dump(&path), head(&path));
    let approvals_before = approval_rowids(&path, "rowid");
    assert_eq!(before_head.0, 25);
    assert_eq!(rows["checkpoints"].1.len(), 3);

    let log = SqliteAudit::open(&path).unwrap();
    assert_eq!(log.schema().migrated_from, Some(0));
    let leases = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(leases.schema().migrated_from, None);
    let report = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(report.ok, "{report:?}");
    assert_eq!(report.checkpoints, 3);
    assert!(report.bad_checkpoints.is_empty());
    let h = log.head().unwrap().unwrap();
    assert_eq!((h.seq as i64, h.entry_hash), before_head.clone());
    assert_eq!(
        leases.approval(&approval(1).id).unwrap().unwrap(),
        approval(1)
    );
    drop((log, leases));

    assert_eq!(user_version(&path), i64::from(SCHEMA_VERSION));
    let after = dump(&path);
    assert_rows_kept(&rows, &after);
    for (table, content) in &rows {
        if table != "approvals" {
            assert_eq!(
                &kept_columns(&after[table], content),
                content,
                "adoption must not change a row of {table}"
            );
        }
    }
    assert_eq!(approval_rowids(&path, "position"), approvals_before);
    assert_eq!(
        master(&path),
        master(&source),
        "the schema is the current one"
    );
    assert_eq!(head(&path), before_head);
}

/// The `approvals` table as schema version 1 has it (`schema.rs`, migration 1), with its
/// index.
const V1_APPROVALS: &str = "
CREATE TABLE approvals (
    id               TEXT PRIMARY KEY,
    chain_id         TEXT NOT NULL,
    lease            TEXT NOT NULL,
    call_hash        TEXT NOT NULL,
    server           TEXT NOT NULL,
    tool             TEXT NOT NULL,
    arguments        TEXT NOT NULL,
    labels           TEXT NOT NULL,
    decision_id      TEXT NOT NULL,
    chain            TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    state            TEXT NOT NULL,
    approver_subject TEXT NULL,
    approver_method  TEXT NULL,
    decided_at       TEXT NULL,
    consumed_by      TEXT NULL,
    jkt              TEXT NULL,
    untrusted_args   TEXT NULL
);
CREATE INDEX approvals_call_idx ON approvals(chain_id, call_hash, state);
";

/// The columns `approvals` has in both versions.
const APPROVAL_COLUMNS: &str = "id, chain_id, lease, call_hash, server, tool, arguments, labels, \
     decision_id, chain, created_at, expires_at, state, approver_subject, approver_method, \
     decided_at, consumed_by, jkt, untrusted_args";

/// Write `path` as a file at schema version 1 with the content of the current-version file
/// `source`: every table and index as `source` has it (from its own `CREATE` statements),
/// except `approvals`, which has version 1's shape and gets each approval's position as its
/// rowid, `used_credentials` (version 3) and `audit_anchors` (version 5), which are left out,
/// and `lease_subjects`, without the `issuer` of version 4; every row of every other table;
/// and `user_version` 1. No
/// `sqlite_sequence`, as in a real version 1 file.
fn version_1_copy(source: &Path, path: &Path) {
    let conn = Connection::open(path).unwrap();
    let statements: Vec<String> = {
        let src = Connection::open(source).unwrap();
        let mut stmt = src
            .prepare(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL \
                 AND name NOT LIKE 'sqlite_%' \
                 AND tbl_name NOT IN ('approvals', 'used_credentials', 'audit_anchors') \
                 ORDER BY type DESC, name",
            )
            .unwrap();
        let rows = stmt.query_map([], |r| r.get(0)).unwrap();
        rows.collect::<Result<_, _>>().unwrap()
    };
    for sql in statements {
        conn.execute_batch(&sql).unwrap();
    }
    without_subject_issuer(&conn);
    conn.execute_batch(V1_APPROVALS).unwrap();
    let tables: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite_%' \
                 AND name NOT IN ('approvals', 'used_credentials', 'audit_anchors')",
            )
            .unwrap();
        let rows = stmt.query_map([], |r| r.get(0)).unwrap();
        rows.collect::<Result<_, _>>().unwrap()
    };
    for t in tables {
        copy_rows(&conn, source, &t);
    }
    conn.execute(
        "ATTACH DATABASE ?1 AS cur",
        [source.to_string_lossy().as_ref()],
    )
    .unwrap();
    conn.execute_batch(&format!(
        "INSERT INTO main.approvals (rowid, {APPROVAL_COLUMNS}) \
         SELECT position, {APPROVAL_COLUMNS} FROM cur.approvals; DETACH DATABASE cur;"
    ))
    .unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
    assert!(
        !master(path)
            .iter()
            .any(|(_, name, _)| name == "sqlite_sequence"),
        "a version 1 file has no AUTOINCREMENT table"
    );
}

/// Take `lease_subjects` back to its shape before migration 4: no `issuer` column.
fn without_subject_issuer(conn: &Connection) {
    conn.execute_batch("ALTER TABLE lease_subjects DROP COLUMN issuer;")
        .unwrap();
}

/// `(position, id)` of every approval in the file, in table order, with the position read
/// from `column` (`rowid` in a version 1 file, `position` after migration 2).
fn approval_rowids(path: &Path, column: &str) -> Vec<(i64, String)> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {column}, id FROM approvals ORDER BY {column}"
        ))
        .unwrap();
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

/// Migration 2 on a version 1 file with approvals that have gaps in their rowids (removed
/// rows): each approval keeps its rowid as its position and every value, the table keeps its
/// index and the uniqueness of `id`, every other table is untouched, and from then on a
/// position is never given again, even after the newest approval is removed.
#[test]
fn a_version_1_file_keeps_its_approvals_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.sqlite");
    let path = dir.path().join("v1.sqlite");
    {
        let store = SqliteLeaseStore::open(&source).unwrap();
        write_leases(&store);
        for n in 2..=6 {
            let mut a = approval(n);
            a.call_hash = format!("h{n}");
            let (a, _) = store.create_approval(&a).unwrap();
            store
                .decide_approval(
                    &a.id,
                    n % 2 == 0,
                    &attenuo_audit::Approver {
                        subject: "alice".into(),
                        method: attenuo_audit::ApprovalMethod::IdToken,
                    },
                    t0(),
                )
                .unwrap();
        }
        // Gaps: one in the middle, and the newest.
        store.remove_approval(&approval(3).id).unwrap();
        store.remove_approval(&approval(6).id).unwrap();
    }
    version_1_copy(&source, &path);
    let before = approval_rowids(&path, "rowid");
    assert_eq!(
        before.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
        [1, 2, 4, 5]
    );
    let rows = dump(&path);

    let store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(store.schema().version, SCHEMA_VERSION);
    assert_eq!(store.schema().migrated_from, Some(1));
    // In store order, newest first, with the old rowids as positions and every field kept.
    let listed = store.approvals(None, None, None, 10).unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|(p, a)| (*p as i64, a.id.clone()))
            .collect::<Vec<_>>(),
        before.iter().rev().cloned().collect::<Vec<_>>()
    );
    let old = SqliteLeaseStore::open(&source).unwrap();
    for (_, a) in &listed {
        assert_eq!(Some(a), old.approval(&a.id).unwrap().as_ref());
    }
    drop(old);

    let after = dump(&path);
    assert_rows_kept(&rows, &after);
    for (table, content) in &rows {
        if table != "approvals" {
            assert_eq!(
                &kept_columns(&after[table], content),
                content,
                "{table} is untouched"
            );
        }
    }
    assert_eq!(approval_rowids(&path, "position"), before);
    assert_eq!(
        master(&path),
        master(&source),
        "the schema is the current one"
    );
    assert_eq!(objects(&path), current_objects());
    {
        let conn = Connection::open(&path).unwrap();
        // `id` is still unique, and the call index is there.
        let dup = conn.execute(
            &format!(
                "INSERT INTO approvals ({APPROVAL_COLUMNS}) \
                 SELECT {APPROVAL_COLUMNS} FROM approvals WHERE id = ?1"
            ),
            [&approval(1).id],
        );
        assert!(dup.is_err(), "a second row with the same id: {dup:?}");
        let indexes: Vec<(String, bool)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT name, \"unique\" FROM pragma_index_list('approvals') ORDER BY name",
                )
                .unwrap();
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            rows.collect::<Result<_, _>>().unwrap()
        };
        assert_eq!(
            indexes,
            [
                ("approvals_call_idx".to_string(), false),
                ("sqlite_autoindex_approvals_1".to_string(), true)
            ]
        );
    }

    // Above every kept position; and once given, never again, even when removed at once.
    let mut a = approval(7);
    a.call_hash = "h7".into();
    store.create_approval(&a).unwrap();
    let first = store.approvals(None, None, None, 1).unwrap()[0].0;
    assert_eq!(first, 6);
    store.remove_approval(&a.id).unwrap();
    let mut b = approval(8);
    b.call_hash = "h8".into();
    store.create_approval(&b).unwrap();
    let (second, got) = store.approvals(None, None, None, 1).unwrap().remove(0);
    assert_eq!((second, got.id), (7, b.id));
}

/// Migration 3 on a version 2 file with a log, checkpoints, leases, an approval and an outbox
/// notice: every row is kept, the file gains an empty `used_credentials` table and its expiry
/// index (the schema of a new file), and markers written after it survive a reopen.
#[test]
fn a_version_2_file_gains_the_replay_table() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v2.sqlite");
    let issuer = issuer();
    write_log(&path, &issuer, 20);
    {
        let store = SqliteLeaseStore::open(&path).unwrap();
        write_leases(&store);
    }
    {
        // Version 2 is the current schema without migration 3's table and index, without
        // migration 4's column and without migration 5's table.
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "DROP TABLE used_credentials; DROP TABLE audit_anchors; PRAGMA user_version = 2;",
        )
        .unwrap();
        without_subject_issuer(&conn);
    }
    assert!(!objects(&path)
        .iter()
        .any(|o| o.starts_with("used_credentials")));
    let rows = dump(&path);
    let head_before = head(&path);

    let log = SqliteAudit::open(&path).unwrap();
    assert_eq!(log.schema().version, SCHEMA_VERSION);
    assert_eq!(log.schema().migrated_from, Some(2));
    let store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(store.schema().migrated_from, None);
    assert_eq!(user_version(&path), i64::from(SCHEMA_VERSION));
    assert_eq!(objects(&path), current_objects());

    let after = dump(&path);
    assert_rows_kept(&rows, &after);
    for (table, content) in &rows {
        assert_eq!(
            &kept_columns(&after[table], content),
            content,
            "{table} is untouched"
        );
    }
    assert_eq!(after["used_credentials"].1, Vec::<String>::new());
    // Migration 4: every subject kept, with no issuer (none is guessed).
    assert_eq!(
        after["lease_subjects"],
        (
            vec!["id".into(), "subject".into(), "issuer".into()],
            vec![format!(
                "t:{}|t:{}|NULL",
                hex::encode("l1"),
                hex::encode("alice")
            )]
        )
    );
    assert_eq!(head(&path), head_before);
    let report = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(report.ok, "{report:?}");

    assert_eq!(
        store
            .use_all_once(&[("iss\njti", 2_000)], 1_000, 10)
            .unwrap(),
        ReplayOutcome::Recorded
    );
    drop((log, store));
    let store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(
        store
            .use_all_once(&[("iss\njti", 2_000)], 1_500, 10)
            .unwrap(),
        ReplayOutcome::Replayed,
        "the marker survives the reopen"
    );
}

/// Migration 4 on a version 3 file with a log, checkpoints, leases with subjects, an approval
/// and an outbox notice: `lease_subjects` gains a NULL `issuer` in every row and nothing else
/// changes (no issuer is filled in), the schema is that of a new file, a lease from before
/// keeps its subject and has no originating user (and cannot be given one later), and a lease
/// recorded after it has both, across a reopen.
#[test]
fn a_version_3_file_gains_the_subject_issuer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v3.sqlite");
    let issuer = issuer();
    write_log(&path, &issuer, 20);
    {
        let store = SqliteLeaseStore::open(&path).unwrap();
        write_leases(&store);
        store.record_subject(&id("l2"), "alice").unwrap();
    }
    {
        // Version 3 is the current schema without migration 4's column and migration 5's
        // table.
        let conn = Connection::open(&path).unwrap();
        without_subject_issuer(&conn);
        conn.execute_batch("DROP TABLE audit_anchors;").unwrap();
        conn.pragma_update(None, "user_version", 3).unwrap();
    }
    let rows = dump(&path);
    assert_eq!(rows["lease_subjects"].0, ["id", "subject"]);
    let head_before = head(&path);

    let store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(store.schema().version, SCHEMA_VERSION);
    assert_eq!(store.schema().migrated_from, Some(3));
    let log = SqliteAudit::open(&path).unwrap();
    assert_eq!(log.schema().migrated_from, None);
    assert_eq!(user_version(&path), i64::from(SCHEMA_VERSION));
    assert_eq!(objects(&path), current_objects());
    {
        let fresh = dir.path().join("fresh.sqlite");
        drop(SqliteLeaseStore::open(&fresh).unwrap());
        let table = |p: &Path| {
            master(p)
                .into_iter()
                .find(|(_, name, _)| name == "lease_subjects")
                .unwrap()
        };
        assert_eq!(table(&path), table(&fresh), "the column of a new file");
    }

    let after = dump(&path);
    assert_rows_kept(&rows, &after);
    for (table, content) in &rows {
        assert_eq!(
            &kept_columns(&after[table], content),
            content,
            "{table} is untouched"
        );
    }
    assert_eq!(after["lease_subjects"].0, ["id", "subject", "issuer"]);
    assert!(after["lease_subjects"]
        .1
        .iter()
        .all(|r| r.ends_with("|NULL")));
    assert_eq!(head(&path), head_before);
    let report = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(report.ok, "{report:?}");

    // The old leases keep their subject and have no originating user, now or later.
    assert_eq!(store.subject(&id("l1")).unwrap().as_deref(), Some("alice"));
    assert_eq!(store.originating_user(&id("l1")).unwrap(), None);
    // Registering one again after the upgrade is accepted and fills nothing in; another
    // subject is still a conflict.
    store
        .record_originating_user(&id("l1"), "https://idp.example", "alice")
        .unwrap();
    assert_eq!(store.originating_user(&id("l1")).unwrap(), None);
    assert!(matches!(
        store.record_originating_user(&id("l1"), "https://idp.example", "bob"),
        Err(AuditError::BindingConflict(_))
    ));
    // A lease issued after it has both.
    store
        .register(&id("l3"), Some(&id("l2")), t0() + Duration::hours(1))
        .unwrap();
    store
        .record_originating_user(&id("l3"), "https://idp.example", "alice")
        .unwrap();
    drop((log, store));
    let store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(store.schema().migrated_from, None);
    assert_eq!(
        store.originating_user(&id("l3")).unwrap(),
        Some(("https://idp.example".into(), "alice".into()))
    );
}

/// Migration 5 on a version 4 file with a log, checkpoints, leases, an approval and an outbox
/// notice: every row is kept, the chain and its checkpoints verify as before, the head is the
/// same, the file gains an empty `audit_anchors` table (the schema of a new file), and the log
/// still reads from seq 1 with no prune boundary.
#[test]
fn a_version_4_file_gains_the_anchor_table() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v4.sqlite");
    let issuer = issuer();
    write_log(&path, &issuer, 30);
    {
        let store = SqliteLeaseStore::open(&path).unwrap();
        write_leases(&store);
    }
    {
        // Version 4 is the current schema without migration 5's table.
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("DROP TABLE audit_anchors; PRAGMA user_version = 4;")
            .unwrap();
    }
    assert!(!objects(&path).iter().any(|o| o == "audit_anchors"));
    let rows = dump(&path);
    assert_eq!(rows["checkpoints"].1.len(), 4);
    let head_before = head(&path);

    let log = SqliteAudit::open(&path).unwrap();
    assert_eq!(log.schema().version, SCHEMA_VERSION);
    assert_eq!(log.schema().migrated_from, Some(4));
    let store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(store.schema().migrated_from, None);
    assert_eq!(user_version(&path), i64::from(SCHEMA_VERSION));
    assert_eq!(objects(&path), current_objects());

    let after = dump(&path);
    assert_rows_kept(&rows, &after);
    for (table, content) in &rows {
        assert_eq!(&after[table], content, "{table} is untouched");
    }
    assert_eq!(after["audit_anchors"].1, Vec::<String>::new());
    assert_eq!(head(&path), head_before);
    let report = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(report.ok, "{report:?}");
    assert_eq!((report.entries, report.checkpoints), (30, 4));
    assert_eq!(report.pruned_through, None);
    assert_eq!(report.anchors, 0);
    assert_eq!(log.pruned_through().unwrap(), None);
    assert_eq!(log.first_retained_seq().unwrap(), 1);
    assert!(log.anchors_before(u64::MAX, 10).unwrap().is_empty());
}

/// The tables as of commit 3593549 (`kind` and `chain_id` on records, before the record-id
/// index of 0f817de and before any table after `lease_bindings`), with `audit_meta` naming the
/// current entry hash.
const SHAPE_3593549: &str = "
CREATE TABLE audit (
    seq                 INTEGER PRIMARY KEY,
    prev_hash           TEXT    NOT NULL,
    entry_hash          TEXT    NOT NULL UNIQUE,
    at                  TEXT    NOT NULL,
    decision            TEXT    NOT NULL,
    reason              TEXT    NOT NULL,
    originating_subject TEXT    NOT NULL,
    agents              TEXT    NOT NULL,
    chain_depth         INTEGER NOT NULL,
    chain_digest        TEXT    NOT NULL,
    leases              TEXT    NOT NULL,
    server              TEXT    NOT NULL,
    tool                TEXT    NOT NULL,
    arguments_digest    TEXT    NOT NULL,
    session_id          TEXT    NULL,
    policy_ids          TEXT    NOT NULL,
    record_json         TEXT    NOT NULL,
    kind                TEXT    NOT NULL,
    chain_id            TEXT    NULL
);
CREATE INDEX audit_subject_idx ON audit(originating_subject);
CREATE INDEX audit_chain_idx   ON audit(chain_digest);
CREATE INDEX audit_at_idx      ON audit(at);
CREATE INDEX audit_kind_idx    ON audit(kind);
CREATE INDEX audit_chain_id_idx ON audit(chain_id);
CREATE TABLE checkpoints (
    seq       INTEGER PRIMARY KEY,
    head_hash TEXT NOT NULL,
    at        TEXT NOT NULL,
    kid       TEXT NOT NULL,
    signature TEXT NOT NULL
);
CREATE TABLE audit_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE leases (
    id            TEXT PRIMARY KEY,
    parent        TEXT NULL,
    expires_at    TEXT NOT NULL,
    revoked_at    TEXT NULL,
    revoke_reason TEXT NULL
);
CREATE INDEX leases_parent_idx ON leases(parent);
CREATE TABLE lease_bindings (
    id      TEXT PRIMARY KEY,
    binding TEXT NOT NULL
);
";

/// Copy every row of `table` from the current-code file `from` into the old-shape file `to`,
/// in the columns `to` has.
fn copy_rows(to: &Connection, from: &Path, table: &str) {
    let cols: Vec<String> = {
        let mut stmt = to
            .prepare("SELECT name FROM pragma_table_info(?1)")
            .unwrap();
        let rows = stmt.query_map([table], |r| r.get(0)).unwrap();
        rows.collect::<Result<_, _>>().unwrap()
    };
    let cols = cols.join(", ");
    to.execute(
        "ATTACH DATABASE ?1 AS cur",
        [from.to_string_lossy().as_ref()],
    )
    .unwrap();
    to.execute_batch(&format!(
        "INSERT INTO main.{table} ({cols}) SELECT {cols} FROM cur.{table}; DETACH DATABASE cur;"
    ))
    .unwrap();
}

/// An audit file in the 3593549 shape with real entries and checkpoints is adopted: the
/// missing tables, indexes and keys are created, every existing row is kept byte for byte, the
/// head is the same and the signed checkpoints verify; both stores then work on it.
#[test]
fn an_audit_file_from_before_the_lease_tables_is_adopted() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.sqlite");
    let issuer = issuer();
    write_log(&source, &issuer, 20);
    let path = dir.path().join("old.sqlite");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(SHAPE_3593549).unwrap();
        for t in ["audit", "checkpoints", "audit_meta"] {
            copy_rows(&conn, &source, t);
        }
        conn.execute_batch(
            "INSERT INTO leases (id, parent, expires_at) VALUES ('l1', NULL, '2026-10-23T00:00:00Z');
             INSERT INTO lease_bindings (id, binding) VALUES ('l1', 'digest');",
        )
        .unwrap();
    }
    let (rows, before_head) = (dump(&path), head(&path));
    assert_eq!(rows["audit"], dump(&source)["audit"], "the copy is exact");
    assert_eq!(user_version(&path), 0);

    let log = SqliteAudit::open(&path).unwrap();
    assert_eq!(log.schema().migrated_from, Some(0));
    let report = log.verify_chain_signed(&keys(&issuer)).unwrap();
    assert!(report.ok, "{report:?}");
    assert_eq!(report.checkpoints, 2);
    assert!(report.bad_checkpoints.is_empty());
    let h = log.head().unwrap().unwrap();
    assert_eq!((h.seq as i64, h.entry_hash), before_head.clone());
    // The record-id index is built and used.
    let rid = log.entry_at(20).unwrap().unwrap().record.id.to_string();
    assert_eq!(log.entry_by_record_id(&rid).unwrap().unwrap().seq, 20);
    log.append(record(20)).unwrap();
    assert!(log.verify_chain().unwrap().ok);

    let leases = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(leases.schema().migrated_from, None);
    assert_eq!(
        leases.binding(&id("l1")).unwrap().as_deref(),
        Some("digest")
    );
    leases
        .register(&id("l2"), Some(&id("l1")), t0() + Duration::hours(1))
        .unwrap();
    leases.record_subject(&id("l2"), "bob").unwrap();
    drop((log, leases));

    assert_eq!(objects(&path), current_objects());
    assert_rows_kept(&rows, &dump(&path));
    let conn = Connection::open(&path).unwrap();
    let old_head: String = conn
        .query_row(
            "SELECT entry_hash FROM audit WHERE seq = ?1",
            [before_head.0],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(old_head, before_head.1);
    let keys_stored: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM budget_meta WHERE key IN ('value_key', 'span_key', 'user_key') \
             AND length(value) = 64",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(keys_stored, 3);
}

/// The lease tables as of commit b87d43e: approvals before `jkt` (f7beb7b) and
/// `untrusted_args` (77ac6a1), and no run-limit tables (1807866).
const LEASE_SHAPE_B87D43E: &str = "
CREATE TABLE leases (
    id            TEXT PRIMARY KEY,
    parent        TEXT NULL,
    expires_at    TEXT NOT NULL,
    revoked_at    TEXT NULL,
    revoke_reason TEXT NULL
);
CREATE INDEX leases_parent_idx ON leases(parent);
CREATE TABLE lease_bindings (
    id      TEXT PRIMARY KEY,
    binding TEXT NOT NULL
);
CREATE TABLE run_labels (
    chain_id    TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    decision_id TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    at          TEXT    NOT NULL,
    PRIMARY KEY (chain_id, source)
);
CREATE TABLE approvals (
    id               TEXT PRIMARY KEY,
    chain_id         TEXT NOT NULL,
    lease            TEXT NOT NULL,
    call_hash        TEXT NOT NULL,
    server           TEXT NOT NULL,
    tool             TEXT NOT NULL,
    arguments        TEXT NOT NULL,
    labels           TEXT NOT NULL,
    decision_id      TEXT NOT NULL,
    chain            TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    state            TEXT NOT NULL,
    approver_subject TEXT NULL,
    approver_method  TEXT NULL,
    decided_at       TEXT NULL,
    consumed_by      TEXT NULL
);
CREATE INDEX approvals_call_idx ON approvals(chain_id, call_hash, state);
";

/// A lease-store file from before `jkt` and `untrusted_args` (b87d43e) gains both columns, as
/// the ad-hoc `ALTER TABLE` used to add them, and every later table; its approval reads back
/// with no key binding and no matched arguments, and the lease store opens it before any
/// audit log has (a lease file of its own).
#[test]
fn a_lease_file_from_before_the_approval_columns_is_adopted() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.sqlite");
    write_leases(&SqliteLeaseStore::open(&source).unwrap());
    let path = dir.path().join("old-leases.sqlite");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(LEASE_SHAPE_B87D43E).unwrap();
        for t in ["leases", "lease_bindings", "approvals"] {
            copy_rows(&conn, &source, t);
        }
    }
    let rows = dump(&path);
    assert_eq!(rows["approvals"].1.len(), 1);

    let store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(store.schema().migrated_from, Some(0));
    assert_eq!(
        store.approval(&approval(1).id).unwrap().unwrap(),
        approval(1)
    );
    // The audit side was created empty and records the current entry hash.
    let log = SqliteAudit::open(&path).unwrap();
    assert_eq!(log.schema().migrated_from, None);
    assert_eq!(log.len().unwrap(), 0);
    drop((store, log));

    let after = dump(&path);
    assert_rows_kept(&rows, &after);
    let approval_cols = &after["approvals"].0;
    assert_eq!(
        &approval_cols[approval_cols.len() - 3..],
        ["jkt", "untrusted_args", "position"]
    );
    assert_eq!(objects(&path), current_objects());
    assert_eq!(
        after["audit_meta"].1,
        [format!(
            "t:{}|t:{}",
            hex::encode("entry_hash"),
            hex::encode(ENTRY_HASH_VERSION)
        )]
    );
}

/// The lease tables as of commit 4858806: approvals with `jkt` but before `untrusted_args`,
/// run-limit tables with only `value_key`, the span index with `span_key`, and nothing from
/// hop limits (606320f), the counter index (71c246d), subjects (836f6a8), sessions (e5a5bd1),
/// the outbox (0292ba6) or user windows (391bf13).
const LEASE_SHAPE_4858806: &str = "
CREATE TABLE leases (
    id            TEXT PRIMARY KEY,
    parent        TEXT NULL,
    expires_at    TEXT NOT NULL,
    revoked_at    TEXT NULL,
    revoke_reason TEXT NULL
);
CREATE INDEX leases_parent_idx ON leases(parent);
CREATE TABLE lease_bindings (
    id      TEXT PRIMARY KEY,
    binding TEXT NOT NULL
);
CREATE TABLE approvals (
    id               TEXT PRIMARY KEY,
    chain_id         TEXT NOT NULL,
    lease            TEXT NOT NULL,
    call_hash        TEXT NOT NULL,
    server           TEXT NOT NULL,
    tool             TEXT NOT NULL,
    arguments        TEXT NOT NULL,
    labels           TEXT NOT NULL,
    decision_id      TEXT NOT NULL,
    chain            TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    state            TEXT NOT NULL,
    approver_subject TEXT NULL,
    approver_method  TEXT NULL,
    decided_at       TEXT NULL,
    consumed_by      TEXT NULL,
    jkt              TEXT NULL
);
CREATE INDEX approvals_call_idx ON approvals(chain_id, call_hash, state);
CREATE TABLE budget_counters (
    lease TEXT    NOT NULL,
    cap   INTEGER NOT NULL,
    kind  TEXT    NOT NULL,
    arg   TEXT    NOT NULL,
    value TEXT    NOT NULL,
    used  INTEGER NOT NULL,
    PRIMARY KEY (lease, cap, kind, arg, value)
);
CREATE TABLE budget_charges (
    decision_id TEXT    NOT NULL,
    lease       TEXT    NOT NULL,
    cap         INTEGER NOT NULL,
    kind        TEXT    NOT NULL,
    arg         TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    amount      INTEGER NOT NULL,
    at          TEXT    NOT NULL,
    refunded_at TEXT    NULL
);
CREATE INDEX budget_charges_decision_idx ON budget_charges(decision_id);
CREATE TABLE budget_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO budget_meta (key, value) VALUES
    ('value_key', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
CREATE TABLE run_spans (
    chain_id TEXT    NOT NULL,
    hash     BLOB    NOT NULL,
    seq      INTEGER NOT NULL,
    PRIMARY KEY (chain_id, hash, seq)
) WITHOUT ROWID;
CREATE INDEX run_spans_seq_idx ON run_spans(chain_id, seq);
INSERT INTO budget_meta (key, value) VALUES
    ('span_key', 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100');
INSERT INTO budget_counters VALUES ('l1', 0, 'calls', '', '', 3);
INSERT INTO budget_charges VALUES ('d1', 'l1', 0, 'calls', '', '', 1, '2026-10-25T00:00:00Z', NULL);
INSERT INTO run_spans VALUES ('l1', x'0102', 4);
";

/// A store in the 4858806 shape keeps its counters, charges, span index and both stored keys
/// (a new `value_key` would orphan every `calls_per` counter), gains `user_key`,
/// `untrusted_args` and every later table, and is then used by both stores.
#[test]
fn a_lease_file_with_run_limits_keeps_its_keys_and_counters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old-limits.sqlite");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(LEASE_SHAPE_4858806).unwrap();
        conn.execute_batch(
            "INSERT INTO leases (id, parent, expires_at) VALUES ('l1', NULL, '2026-10-23T00:00:00Z');",
        )
        .unwrap();
    }
    let rows = dump(&path);

    let log = SqliteAudit::open(&path).unwrap();
    assert_eq!(log.schema().migrated_from, Some(0));
    let store = SqliteLeaseStore::open(&path).unwrap();
    assert_eq!(store.schema().migrated_from, None);
    log.append(record(0)).unwrap();
    store
        .register(&id("l2"), Some(&id("l1")), t0() + Duration::hours(1))
        .unwrap();
    drop((log, store));

    let after = dump(&path);
    assert_rows_kept(&rows, &after);
    let meta = &after["budget_meta"].1;
    assert_eq!(meta.len(), 3);
    for (key, value) in [
        (
            "value_key",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ),
        (
            "span_key",
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        ),
    ] {
        let row = format!("t:{}|t:{}", hex::encode(key), hex::encode(value));
        assert!(meta.contains(&row), "{key} changed: {meta:?}");
    }
    assert_eq!(objects(&path), current_objects());
}

/// The refusals adoption keeps from the ad-hoc code: a log from before records had `kind`
/// (commits before 3593549), and a log with entries but no `audit_meta` row (the v1 entry hash,
/// before 583c006). Both are refused by both stores, and the file is left exactly as it was:
/// still `user_version` 0, no table added.
#[test]
fn adoption_refuses_logs_this_version_cannot_read_and_leaves_them_alone() {
    let dir = tempfile::tempdir().unwrap();
    // Before `kind` and `chain_id` (the audit table of 521270a, cut to two columns: the
    // check looks at the columns only).
    let pre_kind = dir.path().join("pre-kind.sqlite");
    Connection::open(&pre_kind)
        .unwrap()
        .execute_batch(
            "CREATE TABLE audit (seq INTEGER PRIMARY KEY, record_json TEXT NOT NULL);
             INSERT INTO audit VALUES (1, '{}');",
        )
        .unwrap();
    // Entries but no `audit_meta`: hashed before RFC 8785.
    let v1_hash = dir.path().join("v1-hash.sqlite");
    {
        let source = dir.path().join("source.sqlite");
        write_log(&source, &issuer(), 2);
        let conn = Connection::open(&v1_hash).unwrap();
        conn.execute_batch(SHAPE_3593549).unwrap();
        conn.execute_batch("DROP TABLE audit_meta").unwrap();
        copy_rows(&conn, &source, "audit");
    }
    for (path, expect) in [
        (&pre_kind, "`kind` and `chain_id`"),
        (&v1_hash, "earlier attenuo"),
    ] {
        let (rows, schema) = (dump(path), master(path));
        let audit = SqliteAudit::open(path).unwrap_err().to_string();
        let lease = SqliteLeaseStore::open(path).unwrap_err().to_string();
        for err in [audit, lease] {
            assert!(err.contains(expect), "{}: {err}", path.display());
        }
        assert_eq!(user_version(path), 0);
        assert_eq!(master(path), schema, "a refused file gains no table");
        assert_eq!(dump(path), rows);
    }
    // Another entry hash construction is refused the same way.
    let other = dir.path().join("other-hash.sqlite");
    {
        let conn = Connection::open(&other).unwrap();
        conn.execute_batch(SHAPE_3593549).unwrap();
        conn.execute_batch(
            "INSERT INTO audit_meta VALUES ('entry_hash', 'attenuo-audit-entry-v9');",
        )
        .unwrap();
    }
    let err = SqliteAudit::open(&other).unwrap_err().to_string();
    assert!(err.contains("attenuo-audit-entry-v9"), "{err}");
    assert_eq!(user_version(&other), 0);
}

/// A pre-versioning file whose audit table is empty and has no `audit_meta` row (an
/// `audit_meta` table created, no entries yet) is adopted and records the current entry hash.
#[test]
fn an_empty_pre_versioning_log_records_the_current_entry_hash() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty-old.sqlite");
    Connection::open(&path)
        .unwrap()
        .execute_batch(SHAPE_3593549)
        .unwrap();
    let log = SqliteAudit::open(&path).unwrap();
    assert_eq!(log.schema().migrated_from, Some(0));
    log.append(record(0)).unwrap();
    assert!(log.verify_chain().unwrap().ok);
    drop(log);
    let v: String = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT value FROM audit_meta WHERE key = 'entry_hash'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(v, ENTRY_HASH_VERSION);
}
