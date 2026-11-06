//! Approval rows of the lease store.

use attenuo_core::LeaseId;
use rusqlite::{params, Connection, Row};
use time::OffsetDateTime;

use super::parse_time;
use crate::approval::{Approval, ApprovalMethod, ApprovalState, Approver};
use crate::error::AuditError;

/// Columns of an approval row, in the order [`approval_from_row`] reads them.
pub(super) const APPROVAL_COLUMNS: &str =
    "id, chain_id, lease, call_hash, server, tool, arguments, labels, \
     decision_id, chain, created_at, expires_at, state, approver_subject, approver_method, \
     decided_at, consumed_by, jkt, untrusted_args";

pub(super) fn approval_from_row(r: &Row<'_>) -> Result<Approval, AuditError> {
    let text = |i: usize| -> Result<String, AuditError> { Ok(r.get::<_, String>(i)?) };
    let opt =
        |i: usize| -> Result<Option<String>, AuditError> { Ok(r.get::<_, Option<String>>(i)?) };
    let approver = match (opt(13)?, opt(14)?) {
        (Some(subject), Some(method)) => Some(Approver {
            subject,
            method: ApprovalMethod::parse(&method)?,
        }),
        _ => None,
    };
    Ok(Approval {
        id: text(0)?,
        chain_id: LeaseId(text(1)?),
        lease: LeaseId(text(2)?),
        call_hash: text(3)?,
        server: text(4)?,
        tool: text(5)?,
        arguments: serde_json::from_str(&text(6)?)?,
        labels: serde_json::from_str(&text(7)?)?,
        decision_id: text(8)?,
        chain: serde_json::from_str(&text(9)?)?,
        created_at: parse_time(&text(10)?)?,
        expires_at: parse_time(&text(11)?)?,
        state: ApprovalState::parse(&text(12)?)?,
        approver,
        decided_at: opt(15)?.as_deref().map(parse_time).transpose()?,
        consumed_by: opt(16)?,
        jkt: opt(17)?,
        untrusted_args: match opt(18)? {
            Some(json) => serde_json::from_str(&json)?,
            None => Vec::new(),
        },
    })
}

pub(super) fn approval_in(conn: &Connection, id: &str) -> Result<Option<Approval>, AuditError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {APPROVAL_COLUMNS} FROM approvals WHERE id = ?1"
    ))?;
    let mut rows = stmt.query([id])?;
    match rows.next()? {
        Some(r) => Ok(Some(approval_from_row(r)?)),
        None => Ok(None),
    }
}

/// Add the `approvals` columns that came after the table: `jkt` (approval tokens) and
/// `untrusted_args` (output labelling phase 2), each in the same release cycle as the table
/// and never shipped without it, but cheap to carry. A missing value reads as `NULL`: an
/// approval with no key binding, or with no matched arguments.
pub(super) fn add_approval_columns(conn: &Connection) -> Result<(), AuditError> {
    let cols: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('approvals')")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for column in ["jkt", "untrusted_args"] {
        if !cols.iter().any(|c| c == column) {
            conn.execute_batch(&format!(
                "ALTER TABLE approvals ADD COLUMN {column} TEXT NULL"
            ))?;
        }
    }
    Ok(())
}

/// Approvals of one run for one call hash in one state. Expiry is compared in Rust: the
/// stored times are RFC 3339 text, which does not sort as time across offsets.
pub(super) fn approvals_for_call(
    conn: &Connection,
    chain_id: &LeaseId,
    call_hash: &str,
    state: ApprovalState,
) -> Result<Vec<Approval>, AuditError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {APPROVAL_COLUMNS} FROM approvals \
         WHERE chain_id = ?1 AND call_hash = ?2 AND state = ?3"
    ))?;
    let mut rows = stmt.query(params![chain_id.0, call_hash, state.as_str()])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(approval_from_row(r)?);
    }
    Ok(out)
}

/// How many approvals of the run `chain_id` are pending and unexpired at `now`
/// ([`crate::MAX_PENDING_APPROVALS_PER_RUN`]). Expiry is compared in Rust, as in
/// [`approvals_for_call`].
pub(super) fn pending_of_run(
    conn: &Connection,
    chain_id: &LeaseId,
    now: OffsetDateTime,
) -> Result<usize, AuditError> {
    let mut stmt = conn.prepare_cached(
        "SELECT expires_at FROM approvals WHERE chain_id = ?1 AND state = 'pending'",
    )?;
    let mut rows = stmt.query(params![chain_id.0])?;
    let mut n = 0;
    while let Some(r) = rows.next()? {
        if parse_time(&r.get::<_, String>(0)?)? > now {
            n += 1;
        }
    }
    Ok(n)
}
