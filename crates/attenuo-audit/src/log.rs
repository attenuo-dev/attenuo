//! The hash chain: entry layout, hashing and verification shared by every sink.

use attenuo_core::digest::sha256_bytes;
use attenuo_core::{jcs, DecisionRecord};
use serde::{Deserialize, Serialize};

use crate::error::AuditError;

/// `prev_hash` of the first entry: 64 hex zeros.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The entry hash construction, and the first element of the array it hashes (see
/// [`compute_entry_hash`]). Version 1 hashed `serde_json`'s output of `[seq, prev_hash,
/// record]` without a version tag; logs written that way are refused (SR-20).
pub const ENTRY_HASH_VERSION: &str = "attenuo-audit-entry-v2";

/// One link in the audit chain. Sequence numbers start at 1 and are contiguous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Position in the log, from 1.
    pub seq: u64,
    /// `entry_hash` of the entry before, or [`GENESIS_HASH`] for the first.
    pub prev_hash: String,
    /// The decision the entry records.
    pub record: DecisionRecord,
    /// [`compute_entry_hash`] of the three fields above.
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

/// The entry hash (construction [`ENTRY_HASH_VERSION`]): SHA-256, hex, over the RFC 8785
/// canonical JSON ([`attenuo_core::jcs`]) of the array
/// `["attenuo-audit-entry-v2", seq, prev_hash, record]`.
///
/// The bytes depend only on the values, not on field order, map types or `serde_json`'s
/// `preserve_order` feature, so any RFC 8785 implementation can recompute the hash. The leading
/// tag keeps a hash of another construction from ever matching.
pub fn compute_entry_hash(seq: u64, prev_hash: &str, record: &DecisionRecord) -> String {
    entry_hash_from_json(seq, prev_hash, &canonical_record_json(record))
}

/// The canonical (RFC 8785) JSON text of a record: what [`compute_entry_hash`] hashes for it,
/// and what the SQLite sink stores as `record_json`.
pub fn canonical_record_json(record: &DecisionRecord) -> String {
    jcs::to_string(record).expect("a decision record has a canonical JSON form")
}

/// [`compute_entry_hash`] for a record that is already serialized (`record_json` must be
/// [`canonical_record_json`] of it). It hashes the same bytes,
/// `["attenuo-audit-entry-v2",seq,"prev_hash",record_json]` (canonical JSON of an array is
/// its canonical elements joined by commas), without serializing the record a second time.
pub fn entry_hash_from_json(seq: u64, prev_hash: &str, record_json: &str) -> String {
    let mut buf = Vec::with_capacity(record_json.len() + prev_hash.len() + 56);
    buf.push(b'[');
    jcs::write_str(&mut buf, ENTRY_HASH_VERSION);
    buf.push(b',');
    buf.extend_from_slice(seq.to_string().as_bytes());
    buf.push(b',');
    jcs::write_str(&mut buf, prev_hash);
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
    /// Every entry examined links to the one before and re-hashes to its `entry_hash`.
    pub ok: bool,
    /// Sequence number of the first entry that fails verification. For a deleted entry this is
    /// the seq of the entry that follows the gap, since the deleted one is no longer present.
    pub first_bad_seq: Option<u64>,
}

/// Verify an ordered stream of entries. An entry is bad when its seq is not the previous seq + 1
/// (starting at 1), its `prev_hash` does not equal the previous `entry_hash`, its own hash
/// does not recompute, or its seq is `u64::MAX` (no entry could follow it). An item carrying
/// [`AuditError::Corrupt`] (a row that could not be decoded) is reported as a break at that seq.
///
/// # Errors
///
/// The first error an item of `entries` carries other than [`AuditError::Corrupt`] (a store
/// fault while reading the log), propagated as it is. A broken chain is not an error but a
/// report with `ok: false`.
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
        // `u64::MAX` has no successor: an entry claiming it is bad (fuzzing F4), rather than
        // an overflow (a panic with overflow checks on, a wrap to 0 without).
        let next_seq = entry.seq.checked_add(1);
        let good = next_seq.is_some()
            && entry.seq == expected_seq
            && entry.prev_hash == expected_prev
            && entry.hash_matches();
        let Some(next_seq) = next_seq.filter(|_| good) else {
            return Ok(VerifyReport {
                entries: count,
                ok: false,
                first_bad_seq: Some(entry.seq),
            });
        };
        on_ok(&entry);
        expected_seq = next_seq;
        expected_prev = entry.entry_hash;
    }
    Ok(VerifyReport {
        entries: count,
        ok: true,
        first_bad_seq: None,
    })
}

/// An append-only, hash-chained decision log.
///
/// # Errors
///
/// Every method can fail on a sink fault, which each method's own `# Errors` section calls
/// that: [`AuditError::Poisoned`] when a writer panicked holding the sink's lock, and, for the
/// file sink, [`AuditError::Sqlite`] when a query, commit or sync fails, [`AuditError::Serde`],
/// [`AuditError::TimeFormat`] or [`AuditError::TimeParse`] when a record cannot be encoded or
/// read back, [`AuditError::Corrupt`] when a stored row cannot be decoded, and
/// [`AuditError::Storage`] when the background writer has stopped or a figure is out of range.
pub trait AuditSink: Send + Sync {
    /// Append `record` as the next entry and return it.
    ///
    /// # Errors
    ///
    /// A sink fault (see [`AuditSink`]); nothing is appended then.
    fn append(&self, record: DecisionRecord) -> Result<AuditEntry, AuditError>;

    /// The most recent entry, or `None` for an empty log.
    ///
    /// # Errors
    ///
    /// A sink fault (see [`AuditSink`]); an empty log is `Ok(None)`.
    fn head(&self) -> Result<Option<AuditEntry>, AuditError>;

    /// Up to `limit` entries with `seq >= from_seq`, in ascending order.
    ///
    /// # Errors
    ///
    /// A sink fault (see [`AuditSink`]), including [`AuditError::Corrupt`] for a row in the range
    /// that cannot be read back.
    fn range(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditEntry>, AuditError>;

    /// Walk the whole chain and report the first break, if any.
    ///
    /// # Errors
    ///
    /// A sink fault (see [`AuditSink`]) other than a corrupt row: a row that cannot be read back is
    /// reported as the break, not as an error.
    fn verify_chain(&self) -> Result<VerifyReport, AuditError>;

    /// `(head_seq, head_hash)` for an external signer to countersign. An empty log checkpoints
    /// as `(0, GENESIS_HASH)`.
    ///
    /// # Errors
    ///
    /// As [`head`](Self::head).
    fn checkpoint(&self) -> Result<(u64, String), AuditError> {
        Ok(match self.head()? {
            Some(h) => (h.seq, h.entry_hash),
            None => (0, GENESIS_HASH.to_string()),
        })
    }

    /// [`append`](Self::append), and make the whole of [`sync_file`](Self::sync_file) durable
    /// before returning, whatever durability the sink runs at: the commit is synced, and with
    /// it every earlier commit to that file, from any connection. The pipeline uses it for a
    /// decision whose `sum` charge left its sync to the append (see
    /// [`RunLimits::charge_sync_deferred`](crate::RunLimits::charge_sync_deferred)). The
    /// default is a plain `append`, right for a sink with nothing to sync.
    ///
    /// # Errors
    ///
    /// As [`append`](Self::append), and a failed sync of the file is a sink fault too.
    fn append_synced(&self, record: DecisionRecord) -> Result<AuditEntry, AuditError> {
        self.append(record)
    }

    /// The database file that [`append_synced`](Self::append_synced) makes durable, if the
    /// sink is a file (canonical path). `None` (the default) for a sink without one.
    fn sync_file(&self) -> Option<&std::path::Path> {
        None
    }
}
