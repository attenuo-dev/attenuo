//! In-memory audit sink, for tests and single-process deployments.

use std::sync::Mutex;

use attenuo_core::DecisionRecord;

use crate::error::AuditError;
use crate::log::{verify_entries, AuditEntry, AuditSink, VerifyReport};

/// A `Mutex<Vec<AuditEntry>>`. Appends are serialized by the lock, so the chain never forks.
#[derive(Debug, Default)]
pub struct MemoryAudit {
    entries: Mutex<Vec<AuditEntry>>,
}

impl MemoryAudit {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries.
    pub fn len(&self) -> Result<usize, AuditError> {
        Ok(self.entries.lock()?.len())
    }

    pub fn is_empty(&self) -> Result<bool, AuditError> {
        Ok(self.len()? == 0)
    }

    /// Snapshot of every entry, in order.
    pub fn snapshot(&self) -> Result<Vec<AuditEntry>, AuditError> {
        Ok(self.entries.lock()?.clone())
    }
}

impl AuditSink for MemoryAudit {
    fn append(&self, record: DecisionRecord) -> Result<AuditEntry, AuditError> {
        let mut entries = self.entries.lock()?;
        let entry = AuditEntry::next(entries.last(), record);
        entries.push(entry.clone());
        Ok(entry)
    }

    fn head(&self) -> Result<Option<AuditEntry>, AuditError> {
        Ok(self.entries.lock()?.last().cloned())
    }

    fn range(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
        let entries = self.entries.lock()?;
        Ok(entries
            .iter()
            .filter(|e| e.seq >= from_seq)
            .take(limit)
            .cloned()
            .collect())
    }

    fn verify_chain(&self) -> Result<VerifyReport, AuditError> {
        let entries = self.entries.lock()?.clone();
        verify_entries(entries.into_iter().map(Ok))
    }
}
