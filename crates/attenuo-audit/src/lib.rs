//! Tamper-evident decision log and lease registry for `attenuo`.
//!
//! Two concerns live here because they are the two halves of accountability:
//!
//! - **Audit log** ([`AuditSink`]): every [`DecisionRecord`](attenuo_core::DecisionRecord) is
//!   appended as an [`AuditEntry`] whose `entry_hash` covers its sequence number, the previous
//!   entry's hash and the record itself. Editing, reordering or deleting any stored entry breaks
//!   the chain, and [`AuditSink::verify_chain`] says where. [`MemoryAudit`] is for tests and
//!   single-process use; [`SqliteAudit`] persists to a file (or `:memory:`).
//! - **Leases** ([`LeaseStore`]): every delegation hop holds a lease. Revoking a lease revokes
//!   every lease delegated from it, and an unknown lease is treated as inactive so a store that
//!   lost data fails closed. [`MemoryLeaseStore`] and [`SqliteLeaseStore`] mirror the two sinks.
//!
//! Nothing here evaluates policy; the sibling crates call into this one after deciding.

pub mod approval;
pub mod budget;
pub mod checkpoint;
pub mod error;
pub mod export;
pub mod lease;
pub mod log;
pub mod memory;
pub mod query;
pub mod shipped;
pub mod spans;
pub mod sqlite;

pub use approval::{Approval, ApprovalLabel, ApprovalMethod, ApprovalState, Approver};
pub use budget::{ChargeOutcome, CounterSummary, HopLimit};
pub use checkpoint::{
    verify_with_checkpoints, BadCheckpoint, Checkpoint, CheckpointKeys, SignedVerifyReport, Start,
    CHECKPOINT_CONTEXT,
};
pub use error::AuditError;
pub use export::{
    checkpoint_line, entry_line, header_line, parse_export, to_json_form, verify_export,
    verify_export_with, Export, ExportHeader, ExportReport, RecordFilter, VerifyOptions,
    EXPORT_FORMAT,
};
pub use lease::{LeaseNode, LeaseStatus, LeaseStore, LeaseSubtree, MemoryLeaseStore, RunLabel};
pub use log::{
    canonical_record_json, compute_entry_hash, entry_hash_from_json, verify_entries, AuditEntry,
    AuditSink, VerifyReport, ENTRY_HASH_VERSION, GENESIS_HASH,
};
pub use memory::MemoryAudit;
pub use query::{EntryFilter, Order};
pub use shipped::{
    checkpoint_sha256, cross_check, parse_shipped, CrossCheckReport, ShippedCheckpoint,
    ShippedLine, ShippedMismatch, SHIPPED_FORMAT,
};
pub use spans::{SpanHit, MAX_SPANS_PER_RUN};
#[cfg(feature = "testing")]
#[doc(hidden)]
pub use sqlite::WalTimings;
pub use sqlite::{
    Durability, SqliteAudit, SqliteLeaseStore, WalCheckpoint, DEFAULT_WAL_CHECKPOINT_INTERVAL,
    WAL_CHECKPOINT_COMMITS, WAL_WRITER_BACKSTOP_FRAMES,
};
