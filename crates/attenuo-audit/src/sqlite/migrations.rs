//! Versioned schema migrations for the database file of the audit log and the lease store.
//!
//! **The version.** A file's schema version is SQLite's `PRAGMA user_version`. [`MIGRATIONS`] is
//! the one ordered list of changes: migration `N` takes a file from version `N - 1` to `N`, and
//! [`SCHEMA_VERSION`] is the last one. Every store open ([`SqliteAudit`](super::SqliteAudit) and
//! [`SqliteLeaseStore`](super::SqliteLeaseStore), file or memory) calls [`migrate`] on its
//! writer connection before it does anything else with the file. Each migration runs in its own
//! `BEGIN IMMEDIATE` transaction that also sets `user_version` to its number, so a file is always
//! at one version: a migration that fails leaves the file at the version before it.
//!
//! **One file, one migration.** The list covers every table either store keeps, because the
//! server keeps both in one file: whichever store opens a file first migrates it, and the second
//! finds it current and only reads `user_version`. A store on a file of its own migrates that
//! file the same way (so such a file also carries the other store's tables, empty).
//!
//! **Newer files.** A file whose version is above [`SCHEMA_VERSION`] was written by a newer
//! binary; [`AuditError::SchemaTooNew`] refuses it before anything is read or written. There is
//! no downgrade.
//!
//! **Adoption.** Files written before this list existed have `user_version` 0 and tables that
//! the stores created ad hoc (`CREATE TABLE IF NOT EXISTS` at every open, `ALTER TABLE` for the
//! two `approvals` columns that came later). [`adopt_pre_versioning`] brings such a file to
//! version 1 in one transaction: it refuses the audit tables this version cannot read, then
//! creates whatever of version 1 is missing and adds the missing columns. Rows are never
//! rewritten, so the hash chain and its checkpoints are what they were.
//!
//! **Adding migration N + 1.** Append one [`Migration`] with the next number and a one-line
//! description, raise [`SCHEMA_VERSION`] (a compile-time check keeps the two in step), write it
//! as plain DDL that assumes version N exactly (no `IF NOT EXISTS`, no probing for columns), and
//! test it on a file at version N with rows in every table it touches. Never edit or reorder a
//! migration that has been merged: a file that ran it will not run it again.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use super::connection::{file_of, WriteGate};
use super::outbox::OUTBOX_SCHEMA;
use super::replay::REPLAY_SCHEMA;
use super::schema::{
    create_record_id_index, ANCHOR_SCHEMA, AUDIT_SCHEMA, CHECKPOINT_SCHEMA, LEASE_SCHEMA,
    META_SCHEMA,
};
use crate::error::AuditError;
use crate::log::ENTRY_HASH_VERSION;

/// The schema version this build writes and reads: the number of the last migration in the
/// crate's list. A file above it is refused ([`AuditError::SchemaTooNew`]).
pub const SCHEMA_VERSION: u32 = 5;

/// One step of the schema: from version `version - 1` to `version`.
pub(super) struct Migration {
    /// The version the file is at once this step has run; numbered from 1 without gaps.
    pub(super) version: u32,
    /// What the step does, one line, for errors and the design page.
    pub(super) description: &'static str,
    /// The step itself, run inside the migration's transaction.
    pub(super) apply: fn(&Connection) -> Result<(), AuditError>,
}

/// Every migration, oldest first. Append only.
pub(super) const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        description: "the schema as first versioned: audit log, checkpoints, audit_meta, leases \
                      and their bindings, subjects and sessions, run labels, approvals, run-limit \
                      counters and charges, hop limits, span index, per-user windows, notice \
                      outbox",
        apply: v1_initial_schema,
    },
    Migration {
        version: 2,
        description: "approvals get a `position` that is never reused (INTEGER PRIMARY KEY \
                      AUTOINCREMENT, from each row's rowid); `id` stays unique",
        apply: v2_approval_position,
    },
    Migration {
        version: 3,
        description: "single-use credential markers: `used_credentials` (SHA-256 of the replay \
                      key, expiry) and its expiry index, so a credential redeemed before a \
                      restart stays redeemed",
        apply: v3_used_credentials,
    },
    Migration {
        version: 4,
        description: "lease subjects get the originating user's `issuer` (nullable text), so \
                      the admin lease tree can show the run's user's per-user windows",
        apply: v4_lease_subject_issuer,
    },
    Migration {
        version: 5,
        description: "audit retention: `audit_anchors`, one signed anchor per prune of the log \
                      (the last seq pruned, its hash, the prune record, the archive digest, the \
                      deletion state); empty until the first prune",
        apply: v5_audit_anchors,
    },
];

const _: () = assert!(
    MIGRATIONS[MIGRATIONS.len() - 1].version == SCHEMA_VERSION,
    "SCHEMA_VERSION must be the number of the last migration"
);

/// What opening a store found and did to its file's schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaState {
    /// The file's schema version once the store is open: always [`SCHEMA_VERSION`].
    pub version: u32,
    /// The version the file had when this open migrated it: 0 for a new file or one from before
    /// schema versions. `None` when the file was current already (an earlier start, or the
    /// other store on the same file, migrated it).
    pub migrated_from: Option<u32>,
}

/// Bring the file of `conn` to [`SCHEMA_VERSION`], or refuse it.
///
/// A current file costs one read of `user_version` and takes no lock. Otherwise the file's
/// [`WriteGate`] is held for the whole migration, and every step runs in a `BEGIN IMMEDIATE`
/// transaction that reads the version again first, so a store or process that migrated the file
/// meanwhile is noticed and nothing runs twice.
///
/// # Errors
///
/// [`AuditError::SchemaTooNew`] for a file above [`SCHEMA_VERSION`]; [`AuditError::Storage`]
/// for a file this version refuses to adopt (see [`adopt_pre_versioning`]), a step that failed,
/// or a `user_version` that is not one this crate writes; [`AuditError::Sqlite`] when the
/// version cannot be read or a transaction cannot be started or committed.
pub(super) fn migrate(conn: &mut Connection) -> Result<SchemaState, AuditError> {
    run(conn, MIGRATIONS)
}

fn run(conn: &mut Connection, migrations: &[Migration]) -> Result<SchemaState, AuditError> {
    let latest = migrations.last().map_or(0, |m| m.version);
    let found = user_version(conn)?;
    refuse_newer(found, latest)?;
    if found == latest {
        return Ok(SchemaState {
            version: latest,
            migrated_from: None,
        });
    }
    // Writes queue on the gate (see `WriteGate`); taken before the SQLite lock, as everywhere.
    let gate = WriteGate::for_file(file_of(conn).as_deref());
    let _turn = gate.hold();
    let mut migrated_from = None;
    loop {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let at = user_version(&tx)?;
        refuse_newer(at, latest)?;
        if at == latest {
            break;
        }
        migrated_from.get_or_insert(at);
        let next = if at == 0 && has_tables(&tx)? {
            adopt_pre_versioning(&tx)?;
            1
        } else {
            let step = migrations
                .iter()
                .find(|m| m.version == at + 1)
                .ok_or_else(|| {
                    AuditError::Storage(format!("no schema migration from version {at}"))
                })?;
            (step.apply)(&tx).map_err(|e| {
                AuditError::Storage(format!(
                    "schema migration {} ({}) failed; the file stays at version {at}: {e}",
                    step.version, step.description
                ))
            })?;
            step.version
        };
        tx.pragma_update(None, "user_version", next)?;
        tx.commit()?;
    }
    Ok(SchemaState {
        version: latest,
        migrated_from,
    })
}

/// The file's `PRAGMA user_version`.
pub(super) fn user_version(conn: &Connection) -> Result<u32, AuditError> {
    let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    u32::try_from(v).map_err(|_| {
        AuditError::Storage(format!(
            "the database's user_version is {v}, which is not a schema version attenuo writes"
        ))
    })
}

fn refuse_newer(found: u32, supported: u32) -> Result<(), AuditError> {
    if found > supported {
        return Err(AuditError::SchemaTooNew { found, supported });
    }
    Ok(())
}

/// Whether the file has any table: a file at version 0 with tables was written before schema
/// versions and is adopted, one without is new.
fn has_tables(conn: &Connection) -> Result<bool, AuditError> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master \
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%')",
        [],
        |r| r.get(0),
    )?)
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool, AuditError> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |r| r.get(0),
    )?)
}

/// Migration 1: every table, index and key of the schema as first versioned. Its statements
/// keep `IF NOT EXISTS` and `INSERT OR IGNORE` because [`adopt_pre_versioning`] runs them too,
/// to fill in what an older file lacks; later migrations do not need that.
fn v1_initial_schema(conn: &Connection) -> Result<(), AuditError> {
    conn.execute_batch(AUDIT_SCHEMA)?;
    conn.execute_batch(CHECKPOINT_SCHEMA)?;
    conn.execute_batch(META_SCHEMA)?;
    create_record_id_index(conn)?;
    conn.execute_batch(LEASE_SCHEMA)?;
    conn.execute_batch(OUTBOX_SCHEMA)?;
    conn.execute(
        "INSERT OR IGNORE INTO audit_meta (key, value) VALUES ('entry_hash', ?1)",
        [ENTRY_HASH_VERSION],
    )?;
    Ok(())
}

/// Migration 2: the `approvals` table rebuilt with `position INTEGER PRIMARY KEY AUTOINCREMENT`.
///
/// The position of an approval is what `GET /admin/approvals` pages by. In version 1 it was the
/// implicit `rowid`, which SQLite gives as one more than the largest rowid in the table: once
/// the newest approvals are deleted (`remove_approval` after a failed audit append, or the
/// run-state prune) the next approval gets a position a client may already hold a cursor
/// above, and `VACUUM` may renumber an implicit rowid. `AUTOINCREMENT` gives each new row a
/// position above every one the table has ever had (kept in `sqlite_sequence`), and an
/// `INTEGER PRIMARY KEY` is the rowid itself, so `VACUUM` keeps it.
///
/// The steps are SQLite's procedure for a table change `ALTER TABLE` cannot make: create the
/// new table, copy every row with its rowid as its position, drop the old table (and with it
/// `approvals_call_idx`), rename the new one, create the index again. Every column keeps its
/// name, type, nullability and place; `position` comes last. `id` was the `TEXT PRIMARY KEY`
/// and is now `NOT NULL UNIQUE`, which SQLite enforces with the same kind of automatic index.
/// No other table refers to `approvals`. A position given before this migration and freed
/// before it ran is not known to it and can be given once more; every one given after it is
/// never given again.
fn v2_approval_position(conn: &Connection) -> Result<(), AuditError> {
    conn.execute_batch(
        "CREATE TABLE approvals_v2 (
             id               TEXT NOT NULL UNIQUE,
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
             untrusted_args   TEXT NULL,
             position         INTEGER PRIMARY KEY AUTOINCREMENT
         );
         INSERT INTO approvals_v2 (position, id, chain_id, lease, call_hash, server, tool,
             arguments, labels, decision_id, chain, created_at, expires_at, state,
             approver_subject, approver_method, decided_at, consumed_by, jkt, untrusted_args)
         SELECT rowid, id, chain_id, lease, call_hash, server, tool, arguments, labels,
             decision_id, chain, created_at, expires_at, state, approver_subject,
             approver_method, decided_at, consumed_by, jkt, untrusted_args
         FROM approvals ORDER BY rowid;
         DROP TABLE approvals;
         ALTER TABLE approvals_v2 RENAME TO approvals;
         CREATE INDEX approvals_call_idx ON approvals(chain_id, call_hash, state);",
    )?;
    Ok(())
}

/// Migration 3: the `used_credentials` table of the credential replay cache
/// ([`crate::replay`]): one row per single-use credential redeemed, keyed by the SHA-256 of
/// its replay key, with the Unix second after which it could not be accepted anyway. It starts
/// empty: a credential redeemed by the build before the upgrade was only in that process's
/// memory, so the upgrade itself is the last restart that forgets one.
fn v3_used_credentials(conn: &Connection) -> Result<(), AuditError> {
    conn.execute_batch(REPLAY_SCHEMA)?;
    Ok(())
}

/// Migration 4: `lease_subjects.issuer`, the originating user's IdP issuer, next to the
/// subject the issuer already recorded for each lease. A per-user window is keyed by issuer and
/// subject together ([`crate::window`]), so the admin lease tree needs both to show the run's
/// user's windows. Nullable text added at the end: a lease registered before this migration
/// keeps its subject and has no issuer, and nothing fills one in later (its windows are not
/// shown rather than guessed from a configured issuer).
fn v4_lease_subject_issuer(conn: &Connection) -> Result<(), AuditError> {
    conn.execute_batch("ALTER TABLE lease_subjects ADD COLUMN issuer TEXT NULL;")?;
    Ok(())
}

/// Migration 5: the `audit_anchors` table of audit retention (ADR-0015). One row per prune:
/// the signed [`Anchor`](crate::checkpoint::Anchor) that says the log starts after
/// `through_seq`, and `state`, `deleting` until the batched deletes of the rows at or below
/// `through_seq` are done, then `done`. It starts empty, and no existing row changes: a file
/// that is never pruned keeps its chain and checkpoints exactly as they were.
fn v5_audit_anchors(conn: &Connection) -> Result<(), AuditError> {
    conn.execute_batch(ANCHOR_SCHEMA)?;
    Ok(())
}

/// Bring a file written before schema versions (`user_version` 0, tables present) to version 1,
/// inside the caller's transaction. This is where the ad-hoc upgrades the stores used to run at
/// every open now live, once:
///
/// 1. Refuse an `audit` table from before records had `kind` and `chain_id`, and a log whose
///    entries were hashed with another construction than [`ENTRY_HASH_VERSION`] (no
///    `audit_meta` row while entries exist, or another value). Nothing has been written yet,
///    and the transaction is rolled back, so a refused file is left as it was.
/// 2. Run migration 1's statements, which create only what is missing: tables and indexes added
///    after the file was made (from `checkpoints` to `user_windows` and `notice_outbox`), the
///    record-id index, and the `budget_meta` keys (`value_key`, `span_key`, `user_key`) a store
///    lacks. Keys already stored are kept, and an empty log gets its `entry_hash` row.
/// 3. Add the `approvals` columns that came after the table, `jkt` and then `untrusted_args`,
///    as nullable text: an approval stored before reads as one with no key binding and no
///    matched arguments.
///
/// No row of any table is changed.
fn adopt_pre_versioning(conn: &Connection) -> Result<(), AuditError> {
    refuse_audit_without_record_fields(conn)?;
    check_entry_hash(conn, true)?;
    v1_initial_schema(conn)?;
    add_approval_columns(conn)?;
    Ok(())
}

/// Refuse a log created before records had `kind` and `chain_id` (a pre-release shape): its
/// rows lack the columns and its hashes do not cover the fields.
fn refuse_audit_without_record_fields(conn: &Connection) -> Result<(), AuditError> {
    let cols = columns(conn, "audit")?;
    if !cols.is_empty() && !cols.iter().any(|c| c == "kind") {
        return Err(AuditError::Storage(
            "this audit log was written before records had `kind` and `chain_id` (a pre-release \
             build) and cannot be read by this version; move the file aside and start a new log"
                .into(),
        ));
    }
    Ok(())
}

/// Add the `approvals` columns that came after the table: `jkt` (approval tokens) and
/// `untrusted_args` (output labelling phase 2), each in the same release cycle as the table.
/// A missing value reads as `NULL`.
fn add_approval_columns(conn: &Connection) -> Result<(), AuditError> {
    let cols = columns(conn, "approvals")?;
    for column in ["jkt", "untrusted_args"] {
        if !cols.iter().any(|c| c == column) {
            conn.execute_batch(&format!(
                "ALTER TABLE approvals ADD COLUMN {column} TEXT NULL"
            ))?;
        }
    }
    Ok(())
}

fn columns(conn: &Connection, table: &str) -> Result<Vec<String>, AuditError> {
    Ok(conn
        .prepare("SELECT name FROM pragma_table_info(?1)")?
        .query_map([table], |r| r.get(0))?
        .collect::<Result<_, _>>()?)
}

/// Check that the log was hashed with [`ENTRY_HASH_VERSION`].
///
/// When `adopting` a file from before schema versions, a log with no entries and no
/// `audit_meta` row is fine: migration 1's statements record the construction. Otherwise (every
/// open of the audit log, after [`migrate`]) the row must be there, because migration 1 writes
/// it; this check only reads.
pub(super) fn check_entry_hash(conn: &Connection, adopting: bool) -> Result<(), AuditError> {
    let stored: Option<String> = if table_exists(conn, "audit_meta")? {
        conn.query_row(
            "SELECT value FROM audit_meta WHERE key = 'entry_hash'",
            [],
            |r| r.get(0),
        )
        .optional()?
    } else {
        None
    };
    match stored {
        Some(v) if v == ENTRY_HASH_VERSION => Ok(()),
        Some(v) => Err(AuditError::Storage(format!(
            "this audit log was written with entry hash `{v}`; this version reads only \
             `{ENTRY_HASH_VERSION}`"
        ))),
        None => {
            let has_entries = table_exists(conn, "audit")?
                && conn.query_row("SELECT EXISTS (SELECT 1 FROM audit)", [], |r| r.get(0))?;
            if has_entries {
                Err(AuditError::Storage(format!(
                    "this audit log was written by an earlier attenuo (entry hash v1, before \
                     RFC 8785 canonical JSON) and cannot be verified or extended by this \
                     version, which hashes `{ENTRY_HASH_VERSION}`; move the file aside and \
                     start a new log"
                )))
            } else if adopting {
                Ok(())
            } else {
                Err(AuditError::Storage(
                    "the audit log has no `entry_hash` row in `audit_meta`, which schema version \
                     1 always writes; the file was changed outside attenuo"
                        .into(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(conn: &Connection) -> u32 {
        user_version(conn).unwrap()
    }

    fn object_exists(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE name = ?1)",
            [name],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// The list is numbered 1, 2, … without gaps, and every step says what it does.
    #[test]
    fn migrations_are_numbered_in_order_and_described() {
        for (i, m) in MIGRATIONS.iter().enumerate() {
            assert_eq!(m.version as usize, i + 1);
            assert!(!m.description.trim().is_empty());
        }
        assert_eq!(MIGRATIONS.last().unwrap().version, SCHEMA_VERSION);
    }

    fn create_a(conn: &Connection) -> Result<(), AuditError> {
        conn.execute_batch("CREATE TABLE a (x INTEGER)")?;
        Ok(())
    }

    fn create_b_then_fail(conn: &Connection) -> Result<(), AuditError> {
        conn.execute_batch("CREATE TABLE b (y INTEGER); INSERT INTO a VALUES (1);")?;
        Err(AuditError::Storage("step 2 fails on purpose".into()))
    }

    fn create_b(conn: &Connection) -> Result<(), AuditError> {
        conn.execute_batch("CREATE TABLE b (y INTEGER); INSERT INTO a VALUES (1);")?;
        Ok(())
    }

    /// Each step commits with its version; a failing step leaves the file at the version
    /// before it, with nothing of the failed step kept, and running again resumes there.
    #[test]
    fn a_failed_step_rolls_back_to_the_version_before_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.db");
        let mut conn = Connection::open(&path).unwrap();
        let failing = [
            Migration {
                version: 1,
                description: "create a",
                apply: create_a,
            },
            Migration {
                version: 2,
                description: "create b",
                apply: create_b_then_fail,
            },
        ];
        let err = run(&mut conn, &failing).unwrap_err().to_string();
        assert!(
            err.contains("schema migration 2 (create b) failed"),
            "{err}"
        );
        assert!(err.contains("stays at version 1"), "{err}");
        assert_eq!(version(&conn), 1);
        assert!(object_exists(&conn, "a"));
        assert!(
            !object_exists(&conn, "b"),
            "the failed step's DDL is rolled back"
        );
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM a", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "the failed step's rows are rolled back");

        let fixed = [
            Migration {
                version: 1,
                description: "create a",
                apply: create_a,
            },
            Migration {
                version: 2,
                description: "create b",
                apply: create_b,
            },
        ];
        let state = run(&mut conn, &fixed).unwrap();
        assert_eq!(
            state,
            SchemaState {
                version: 2,
                migrated_from: Some(1)
            }
        );
        assert_eq!(version(&conn), 2);
        // Current: nothing runs again.
        let again = run(&mut conn, &fixed).unwrap();
        assert_eq!(again.migrated_from, None);
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM a", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    /// A file one version ahead of the list is refused before anything runs.
    #[test]
    fn a_newer_file_is_refused_by_the_runner() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();
        let only_one = [Migration {
            version: 1,
            description: "create a",
            apply: create_a,
        }];
        match run(&mut conn, &only_one).unwrap_err() {
            AuditError::SchemaTooNew { found, supported } => {
                assert_eq!((found, supported), (2, 1));
            }
            other => panic!("expected SchemaTooNew, got {other:?}"),
        }
        assert!(!object_exists(&conn, "a"));
    }

    /// A build from before migration 5 (its list ends at 4) refuses a file this build
    /// migrated, before reading or writing anything; this build finds it current. So a build
    /// that does not know anchors never opens, and never reports as broken, a pruned log.
    #[test]
    fn a_build_before_migration_5_refuses_a_migrated_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v5.sqlite");
        let mut conn = Connection::open(&path).unwrap();
        assert_eq!(migrate(&mut conn).unwrap().version, 5);
        let older: Vec<Migration> = MIGRATIONS[..4]
            .iter()
            .map(|m| Migration {
                version: m.version,
                description: m.description,
                apply: m.apply,
            })
            .collect();
        match run(&mut conn, &older).unwrap_err() {
            AuditError::SchemaTooNew { found, supported } => {
                assert_eq!((found, supported), (5, 4));
            }
            other => panic!("expected SchemaTooNew, got {other:?}"),
        }
        assert_eq!(version(&conn), 5);
        let mut second = Connection::open(&path).unwrap();
        assert_eq!(migrate(&mut second).unwrap().migrated_from, None);
    }

    /// A negative `user_version` was not written by attenuo.
    #[test]
    fn a_negative_user_version_is_refused() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", -1).unwrap();
        let err = migrate(&mut conn).unwrap_err().to_string();
        assert!(err.contains("user_version is -1"), "{err}");
    }
}
