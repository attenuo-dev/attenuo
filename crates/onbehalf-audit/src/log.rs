//! The hash chain: entry layout, hashing and verification shared by every sink.

use onbehalf_core::digest::{sha256_bytes, sha256_json};
use onbehalf_core::DecisionRecord;
use serde::{Deserialize, Serialize};

use crate::error::AuditError;

/// `prev_hash` of the first entry: 64 hex zeros.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One link in the audit chain. Sequence numbers start at 1 and are contiguous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub prev_hash: String,
    pub record: DecisionRecord,
    /// `sha256_json(&(seq, &prev_hash, &record))`.
    pub entry_hash: String,
}

impl AuditEntry {
    /// Build the entry that follows `prev` (or the genesis entry when `prev` is `None`).
    pub fn next(prev: Option<&AuditEntry>, record: DecisionRecord) -> Self {
        let (seq, prev_hash) = match prev {
            Some(p) => (p.seq + 1, p.entry_hash.clone()),
            None => (1, GENESIS_HASH.to_string()),
        };
        let entry_hash = compute_entry_hash(seq, &prev_hash, &record);
        Self {
            seq,
            prev_hash,
            record,
            entry_hash,
        }
    }

    /// Recompute the hash from the stored fields and compare.
    pub fn hash_matches(&self) -> bool {
        compute_entry_hash(self.seq, &self.prev_hash, &self.record) == self.entry_hash
    }
}

/// The canonical entry hash: SHA-256 over the JSON array `[seq, prev_hash, record]`.
///
/// `DecisionRecord` serializes its fields in declaration order and its maps are `BTreeMap`s, so
/// the encoding is stable across processes.
pub fn compute_entry_hash(seq: u64, prev_hash: &str, record: &DecisionRecord) -> String {
    sha256_json(&(seq, prev_hash, record))
}

/// [`compute_entry_hash`] for a record that is already serialized (`record_json` must be
/// `serde_json::to_string(record)`). It hashes the same bytes, `[seq,"prev_hash",record_json]`
/// (compact JSON, which is what `serde_json` writes for the tuple), without serializing the
/// record a second time.
pub fn entry_hash_from_json(seq: u64, prev_hash: &str, record_json: &str) -> String {
    let mut buf = Vec::with_capacity(record_json.len() + prev_hash.len() + 28);
    buf.push(b'[');
    buf.extend_from_slice(seq.to_string().as_bytes());
    buf.push(b',');
    serde_json::to_writer(&mut buf, prev_hash).expect("a string always serializes");
    buf.push(b',');
    buf.extend_from_slice(record_json.as_bytes());
    buf.push(b']');
    sha256_bytes(&buf)
}

/// Result of walking the chain from the first entry to the head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Entries examined (including the first bad one, if any).
    pub entries: u64,
    pub ok: bool,
    /// Sequence number of the first entry that fails verification. For a deleted entry this is
    /// the seq of the entry that follows the gap, since the deleted one is no longer present.
    pub first_bad_seq: Option<u64>,
}

/// Verify an ordered stream of entries. An entry is bad when its seq is not the previous seq + 1
/// (starting at 1), its `prev_hash` does not equal the previous `entry_hash`, or its own hash
/// does not recompute. An item carrying [`AuditError::Corrupt`] (a row that could not be decoded)
/// is reported as a break at that seq; any other error is propagated.
pub fn verify_entries<I>(entries: I) -> Result<VerifyReport, AuditError>
where
    I: IntoIterator<Item = Result<AuditEntry, AuditError>>,
{
    walk_entries(entries, true, |_| {})
}

/// The chain walk behind [`verify_entries`]. With `anchored` the run must start at seq 1 with
/// the genesis `prev_hash`; without it (an export of a window of the log) the first entry sets
/// the expected seq and `prev_hash`, and only its own hash and everything after it is checked.
/// `on_ok` sees each entry that passes, in order.
pub(crate) fn walk_entries<I>(
    entries: I,
    anchored: bool,
    mut on_ok: impl FnMut(&AuditEntry),
) -> Result<VerifyReport, AuditError>
where
    I: IntoIterator<Item = Result<AuditEntry, AuditError>>,
{
    let mut count = 0u64;
    let mut expected_seq = 1u64;
    let mut expected_prev = GENESIS_HASH.to_string();
    let mut first = true;
    for item in entries {
        count += 1;
        let entry = match item {
            Ok(e) => e,
            Err(AuditError::Corrupt { seq, .. }) => {
                return Ok(VerifyReport {
                    entries: count,
                    ok: false,
                    first_bad_seq: Some(seq),
                })
            }
            Err(e) => return Err(e),
        };
        if first && !anchored {
            expected_seq = entry.seq;
            expected_prev = entry.prev_hash.clone();
        }
        first = false;
        let good =
            entry.seq == expected_seq && entry.prev_hash == expected_prev && entry.hash_matches();
        if !good {
            return Ok(VerifyReport {
                entries: count,
                ok: false,
                first_bad_seq: Some(entry.seq),
            });
        }
        on_ok(&entry);
        expected_seq = entry.seq + 1;
        expected_prev = entry.entry_hash;
    }
    Ok(VerifyReport {
        entries: count,
        ok: true,
        first_bad_seq: None,
    })
}

/// An append-only, hash-chained decision log.
pub trait AuditSink: Send + Sync {
    /// Append `record` as the next entry and return it.
    fn append(&self, record: DecisionRecord) -> Result<AuditEntry, AuditError>;
    /// The most recent entry, or `None` for an empty log.
    fn head(&self) -> Result<Option<AuditEntry>, AuditError>;
    /// Up to `limit` entries with `seq >= from_seq`, in ascending order.
    fn range(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditEntry>, AuditError>;
    /// Walk the whole chain and report the first break, if any.
    fn verify_chain(&self) -> Result<VerifyReport, AuditError>;

    /// `(head_seq, head_hash)` for an external signer to countersign. An empty log checkpoints
    /// as `(0, GENESIS_HASH)`.
    fn checkpoint(&self) -> Result<(u64, String), AuditError> {
        Ok(match self.head()? {
            Some(h) => (h.seq, h.entry_hash),
            None => (0, GENESIS_HASH.to_string()),
        })
    }
}
