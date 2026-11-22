//! The SQL of schema version 1 of the audit log and the lease store, and the record id index.
//!
//! These statements are migration 1 (see `migrations.rs`). They keep `IF NOT EXISTS` because
//! adopting a file from before schema versions runs them to add only what it lacks; a later
//! change to the schema is a new migration there, never an edit here.

use rusqlite::Connection;

use crate::error::AuditError;

pub(super) const AUDIT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit (
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
CREATE INDEX IF NOT EXISTS audit_subject_idx ON audit(originating_subject);
CREATE INDEX IF NOT EXISTS audit_chain_idx   ON audit(chain_digest);
CREATE INDEX IF NOT EXISTS audit_at_idx      ON audit(at);
CREATE INDEX IF NOT EXISTS audit_kind_idx    ON audit(kind);
CREATE INDEX IF NOT EXISTS audit_chain_id_idx ON audit(chain_id);
"#;

pub(super) const CHECKPOINT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS checkpoints (
    seq       INTEGER PRIMARY KEY,
    head_hash TEXT NOT NULL,
    at        TEXT NOT NULL,
    kid       TEXT NOT NULL,
    signature TEXT NOT NULL
);
"#;

/// Migration 5 (audit retention, ADR-0015): one signed anchor per prune of the log. Plain DDL,
/// as every migration after the first.
pub(super) const ANCHOR_SCHEMA: &str = r#"
CREATE TABLE audit_anchors (
    through_seq          INTEGER PRIMARY KEY,
    through_hash         TEXT    NOT NULL,
    prune_seq            INTEGER NOT NULL UNIQUE,
    prune_entry_hash     TEXT    NOT NULL,
    previous_through_seq INTEGER NULL,
    archive_sha256       TEXT    NULL,
    at                   TEXT    NOT NULL,
    kid                  TEXT    NOT NULL,
    signature            TEXT    NOT NULL,
    state                TEXT    NOT NULL,
    shipped_at           TEXT    NULL
);
"#;

/// Which entry hash construction the `audit` table was written with (key `entry_hash`).
pub(super) const META_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

pub(super) const LEASE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS leases (
    id            TEXT PRIMARY KEY,
    parent        TEXT NULL,
    expires_at    TEXT NOT NULL,
    revoked_at    TEXT NULL,
    revoke_reason TEXT NULL
);
CREATE INDEX IF NOT EXISTS leases_parent_idx ON leases(parent);
CREATE TABLE IF NOT EXISTS lease_bindings (
    id      TEXT PRIMARY KEY,
    binding TEXT NOT NULL
);
-- The originating user's subject of each lease (`LeaseRegistry::record_subject`), for revoking
-- every lease of one user. Added to a pre-versioning store when it is adopted; a lease
-- registered before then has no row and is not matched by a subject.
CREATE TABLE IF NOT EXISTS lease_subjects (
    id      TEXT PRIMARY KEY,
    subject TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS lease_subjects_subject_idx ON lease_subjects(subject);
-- MCP sessions opened through the proxy and the chain that opened each
-- (`RunState::record_session`), for revoking by session. `session` is the SHA-256 of the
-- `Mcp-Session-Id` in hex, never the id. Write-once per (session, server). Added to a
-- pre-versioning store when it is adopted; a session opened before then has no row and
-- matches nothing.
CREATE TABLE IF NOT EXISTS lease_sessions (
    session  TEXT NOT NULL,
    server   TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    bound_at TEXT NOT NULL,
    PRIMARY KEY (session, server)
);
CREATE TABLE IF NOT EXISTS run_labels (
    chain_id    TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    decision_id TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    at          TEXT    NOT NULL,
    PRIMARY KEY (chain_id, source)
);
CREATE TABLE IF NOT EXISTS approvals (
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
CREATE INDEX IF NOT EXISTS approvals_call_idx ON approvals(chain_id, call_hash, state);
-- Run limits (ADR-0010). One row per counter; `value` is the hex HMAC of a `calls_per`
-- value, or '' for `calls` and `sum`. Keyed by lease id, never joined with `leases`.
CREATE TABLE IF NOT EXISTS budget_counters (
    lease TEXT    NOT NULL,
    cap   INTEGER NOT NULL,
    kind  TEXT    NOT NULL,
    arg   TEXT    NOT NULL,
    value TEXT    NOT NULL,
    used  INTEGER NOT NULL,
    PRIMARY KEY (lease, cap, kind, arg, value)
);
-- What each decision charged, so that it can be refunded exactly and at most once.
CREATE TABLE IF NOT EXISTS budget_charges (
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
CREATE INDEX IF NOT EXISTS budget_charges_decision_idx ON budget_charges(decision_id);
-- A refund looks up the other decisions that used a `distinct` value (SR-62).
CREATE INDEX IF NOT EXISTS budget_charges_counter_idx
    ON budget_charges(lease, cap, kind, arg, value);
-- The key `calls_per` values are hashed under, generated once per store.
CREATE TABLE IF NOT EXISTS budget_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO budget_meta (key, value) VALUES ('value_key', lower(hex(randomblob(32))));
-- The limited capabilities of each hop as issued (JSON list of `HopLimit`), for the admin
-- console only: enforcement reads limits from the token.
CREATE TABLE IF NOT EXISTS hop_limits (
    lease  TEXT PRIMARY KEY,
    limits TEXT NOT NULL
);
-- Output labelling phase 2 (ADR-0009): the span index of each run. `hash` is the HMAC-SHA-256
-- of a result fingerprint under `span_key` (no content); `seq` is the audit seq of the result's
-- `tool_result` record.
CREATE TABLE IF NOT EXISTS run_spans (
    chain_id TEXT    NOT NULL,
    hash     BLOB    NOT NULL,
    seq      INTEGER NOT NULL,
    PRIMARY KEY (chain_id, hash, seq)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS run_spans_seq_idx ON run_spans(chain_id, seq);
INSERT OR IGNORE INTO budget_meta (key, value) VALUES ('span_key', lower(hex(randomblob(32))));
-- Per-user windows (run limits phase 3). `user` is the hex HMAC-SHA-256, under `user_key`
-- in budget_meta, of the RFC 8785 JSON of [issuer, subject]; never the subject itself.
-- Pruned by the window's end (`[leases] user_window_retention_seconds`), never by leases.
CREATE TABLE IF NOT EXISTS user_windows (
    user         TEXT    NOT NULL,
    window_kind  TEXT    NOT NULL,
    window_start INTEGER NOT NULL,
    tool         TEXT    NOT NULL,
    measure      TEXT    NOT NULL,
    used         INTEGER NOT NULL,
    PRIMARY KEY (user, window_kind, window_start, tool, measure)
) WITHOUT ROWID;
-- What each decision charged to a window, for refunds.
CREATE TABLE IF NOT EXISTS user_window_charges (
    decision_id  TEXT    NOT NULL,
    user         TEXT    NOT NULL,
    window_kind  TEXT    NOT NULL,
    window_start INTEGER NOT NULL,
    tool         TEXT    NOT NULL,
    measure      TEXT    NOT NULL,
    amount       INTEGER NOT NULL,
    at           TEXT    NOT NULL,
    refunded_at  TEXT    NULL
);
CREATE INDEX IF NOT EXISTS user_window_charges_decision_idx ON user_window_charges(decision_id);
CREATE INDEX IF NOT EXISTS user_window_charges_window_idx
    ON user_window_charges(user, window_kind, window_start, tool, measure);
INSERT OR IGNORE INTO budget_meta (key, value) VALUES ('user_key', lower(hex(randomblob(32))));
"#;

/// The record id (`DecisionRecord::id`) of a row, as SQL. `record_json` is the hashed text
/// and is only read here. `json_valid` keeps a row whose JSON was damaged from failing the
/// index build (and so the open): such a row indexes as NULL and `verify` reports it.
/// The index and [`SqliteAudit::entry_by_record_id`](super::SqliteAudit::entry_by_record_id) both use this one expression, which is
/// what lets SQLite answer the lookup from the index.
pub(super) const RECORD_ID_EXPR: &str =
    "CASE WHEN json_valid(record_json) THEN json_extract(record_json, '$.id') END";

/// Create the index for looking an entry up by its record id (`GET /admin/audit/records/{id}`).
///
/// Added after the table was first created, so adopting a file from before schema versions
/// builds it when it is missing (migration 1 runs this). An expression index stores derived
/// values in a separate b-tree; it never writes to the `audit` rows, so no hashed data
/// changes. Once built it costs one b-tree insert per append; building it on a large existing
/// log reads every row once.
pub(super) fn create_record_id_index(conn: &Connection) -> Result<(), AuditError> {
    conn.execute_batch(&format!(
        "CREATE INDEX IF NOT EXISTS audit_record_id_idx ON audit({RECORD_ID_EXPR})"
    ))?;
    Ok(())
}
