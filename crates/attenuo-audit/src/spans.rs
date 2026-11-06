//! The span index of a delegation run (output labelling phase 2; ADR-0009,
//! `docs/design/output-labelling.md` section 3.4).
//!
//! For every untrusted result a run reads, the server stores the result's fingerprints
//! ([`attenuo_core::fingerprint`]) under the run's `chain_id`, tagged with the audit `seq` of
//! the result's `tool_result` record. A later call (a destructive one, or any call when a
//! policy reads argument taint) looks its arguments' fingerprints up here ([`LeaseStore::find_spans`](crate::LeaseStore::find_spans)); a hit names the result.
//!
//! - **Keyed.** The store hashes every fingerprint again with HMAC-SHA-256 under a key it
//!   generates once and keeps (the SQLite store in its key table, the memory store in memory),
//!   as it does for `calls_per` values. The index holds no result content. The key lives in the
//!   same store, so this keeps content off the index rows, not out of reach of someone who
//!   holds the whole store and a list of guesses.
//! - **Bounded.** At most [`MAX_SPANS_PER_RUN`] fingerprints per run, and at most
//!   [`attenuo_core::fingerprint::MAX_FINGERPRINTS_PER_VALUE`] per result. A result whose
//!   fingerprints would take the run past the cap evicts the oldest results' sets (smallest
//!   `seq`) first, whole. An evicted result's label stays in the run's taint state, so eviction
//!   can drop an argument match but never makes a run look untainted. A lookup returns at most
//!   [`MAX_SEQS_PER_PROBE`] results per fingerprint, lowest `seq` first, so one fingerprint
//!   that many results share cannot make one call's lookup large; the server also bounds the
//!   fingerprints it looks up per call (`MAX_ARG_PROBES` in `attenuo-server`, SR-91).
//! - **Ends with the run.** Revoking the run's root lease (the lease whose id is the
//!   `chain_id`) deletes its index in the same transaction. A run whose lease merely expires
//!   keeps its index, like its labels and budget counters: an expired lease that was not
//!   revoked may still be renewed, and nothing sweeps expired runs yet.

use attenuo_core::fingerprint::Fingerprint;
use ring::hmac;

use crate::error::AuditError;

/// Most fingerprints the span index keeps for one run. At 32 bytes of hash and a `seq` per
/// entry, about 1 MB of index rows per run in SQLite; ten results at the per-result cap.
pub const MAX_SPANS_PER_RUN: usize = 20_000;

/// Most results [`LeaseStore::find_spans`](crate::LeaseStore::find_spans) returns for one
/// probe: the lowest `seq`s. A decision record keeps 64 `untrusted_args` entries and Cedar
/// only sees which arguments matched, so more results per fingerprint add nothing a decision
/// uses; without a bound, a short string that hundreds of results hold made one lookup return
/// millions of hits (SR-91).
pub const MAX_SEQS_PER_PROBE: usize = 8;

/// One argument fingerprint found in a run's span index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpanHit {
    /// Index of the fingerprint in the `probes` passed to `find_spans`.
    pub probe: usize,
    /// Audit `seq` of the `tool_result` record of a result that held it.
    pub seq: u64,
}

/// The key fingerprints are hashed under before they are stored or looked up.
#[derive(Clone)]
pub(crate) struct SpanKey(hmac::Key);

impl std::fmt::Debug for SpanKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SpanKey(..)")
    }
}

impl SpanKey {
    pub(crate) fn new(secret: &[u8]) -> Self {
        Self(hmac::Key::new(hmac::HMAC_SHA256, secret))
    }

    /// A fresh random key (the memory store's, which lives as long as its index).
    pub(crate) fn random() -> Result<Self, AuditError> {
        let rng = ring::rand::SystemRandom::new();
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &rng)
            .map_err(|_| AuditError::Storage("could not generate a span key".into()))?;
        Ok(Self(key))
    }

    /// The stored form of `f`: HMAC-SHA-256 of its digest (which already covers its kind).
    pub(crate) fn hash(&self, f: &Fingerprint) -> [u8; 32] {
        let tag = hmac::sign(&self.0, &f.digest);
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        out
    }
}

/// The stored hashes of `spans`, without duplicates, in first-seen order.
pub(crate) fn distinct_hashes(key: &SpanKey, spans: &[Fingerprint]) -> Vec<[u8; 32]> {
    let mut seen = std::collections::HashSet::with_capacity(spans.len());
    spans
        .iter()
        .map(|f| key.hash(f))
        .filter(|h| seen.insert(*h))
        .collect()
}

/// The `seq`s of the oldest results to drop so that `incoming` more fingerprints fit under
/// [`MAX_SPANS_PER_RUN`], given each stored result's `(seq, count)` in ascending `seq`.
pub(crate) fn evictions(stored: &[(u64, usize)], incoming: usize) -> Vec<u64> {
    let mut total: usize = stored.iter().map(|(_, n)| n).sum();
    let mut out = Vec::new();
    for (seq, n) in stored {
        if total + incoming <= MAX_SPANS_PER_RUN {
            break;
        }
        total -= n;
        out.push(*seq);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_whole_results_until_it_fits() {
        let half = MAX_SPANS_PER_RUN / 2;
        assert!(evictions(&[(1, half)], half).is_empty());
        assert_eq!(evictions(&[(1, half), (2, half)], 1), vec![1]);
        assert_eq!(
            evictions(&[(1, 10), (2, 10), (3, half + half - 20)], 15),
            vec![1, 2]
        );
        assert!(evictions(&[], MAX_SPANS_PER_RUN).is_empty());
    }
}
