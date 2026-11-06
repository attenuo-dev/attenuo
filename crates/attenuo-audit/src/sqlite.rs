//! SQLite-backed audit sink and lease store.
//!
//! Both wrap a single `rusqlite::Connection` behind a `Mutex`. Audit appends go through one
//! writer thread (group commit, see [`SqliteAudit`]): it takes the lock, reads the current head
//! and inserts the next rows in one transaction, so two entries can never share a `prev_hash`.
//! The lock and the single writer, not SQLite's locking, keep the chain linear within a
//! process; across processes SQLite's write lock plus the `UNIQUE` constraint on `entry_hash`
//! and the primary key on `seq` make a fork fail rather than succeed.
//!
//! The code is split by store: [`SqliteAudit`] is in `log.rs` (with the WAL checkpointer in
//! `wal.rs`), [`SqliteLeaseStore`] in `leases.rs` (with run limits in `budgets.rs`, approvals
//! in `approvals.rs` and the notice outbox in `outbox.rs`). Both open their connections
//! through `connection.rs` and share the schema in `schema.rs`.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::AuditError;

mod approvals;
mod budgets;
mod connection;
mod leases;
mod log;
mod outbox;
mod schema;
#[cfg(test)]
mod tests;
mod wal;

use approvals::{approval_from_row, APPROVAL_COLUMNS};
pub use connection::Durability;
pub use leases::SqliteLeaseStore;
pub use log::{SqliteAudit, MAX_BATCH};
pub use outbox::{NewNotice, OutboxNotice};
pub use wal::{
    WalCheckpoint, WalStats, CHECKPOINT_PRESYNC_LEAD, DEFAULT_WAL_CHECKPOINT_INTERVAL,
    WAL_CHECKPOINT_COMMITS, WAL_WRITER_BACKSTOP_FRAMES,
};
#[cfg(any(test, feature = "testing"))]
pub use wal::{WalRound, WalTimings};

fn fmt_time(t: OffsetDateTime) -> Result<String, AuditError> {
    Ok(t.format(&Rfc3339)?)
}

fn parse_time(s: &str) -> Result<OffsetDateTime, AuditError> {
    Ok(OffsetDateTime::parse(s, &Rfc3339)?)
}

/// Unix time in whole seconds, at least 1 (0 means "never" in [`WalStats`]).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().max(1))
}

/// A sequence number as SQLite's `INTEGER`; one above `i64::MAX` cannot be stored.
fn seq_to_i64(v: u64) -> Result<i64, AuditError> {
    i64::try_from(v).map_err(|_| AuditError::Storage(format!("sequence number {v} out of range")))
}

/// A row count or limit as SQLite's `INTEGER`, saturating (a limit that large is no limit).
fn usize_to_i64(v: usize) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn to_i64(v: u64) -> Result<i64, AuditError> {
    i64::try_from(v).map_err(|_| AuditError::Storage(format!("budget figure {v} out of range")))
}
