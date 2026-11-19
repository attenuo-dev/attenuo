//! Per-user windows (run limits phase 3, `docs/design/run-limits-phase3.md` section 3.5).
//!
//! A window counter is keyed by (user, window kind, window start, tool, measure). `user` is
//! the hex HMAC-SHA-256, under a key the store generates once and keeps (`user_key`, separate
//! from the `calls_per` value key so the two digests can never be compared), of the RFC 8785
//! JSON of `[issuer, subject]`: the window rows never hold a subject. As with the value key,
//! the key lives in the same store, so the digest keeps subjects off the window rows, not out
//! of reach of someone who holds the whole store and a list of guesses.
//!
//! Window charges are applied with the limits and run usage of the same decision, in the same
//! transaction ([`RunLimits::charge_windowed`](crate::RunLimits::charge_windowed)), and
//! logged under the decision id so an operator refund returns them, once, to the window each
//! was charged to. A window counter saturates at [`WindowCharge::MAX`] and never refuses a
//! call. Revoking a run does not touch windows: "revoke the run, start a new one" must not
//! reset the user's day. Window rows are pruned by their own retention, counted from the
//! window's end ([`window_prunable`]), never by the lease registry.

use attenuo_core::{WindowCharge, WindowKind};
use ring::hmac;

use crate::error::AuditError;

/// The row key of a window counter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct WindowKey {
    pub user: String,
    pub kind: &'static str,
    pub start: i64,
    pub tool: String,
    pub measure: &'static str,
}

impl WindowKey {
    /// The window's end, Unix seconds (an unknown kind counts as the longest, a day).
    pub(crate) fn end(&self) -> i64 {
        let len = WindowKind::parse(self.kind)
            .map_or(WindowKind::Day.length_seconds(), |k| k.length_seconds());
        self.start.saturating_add(len)
    }
}

/// The key users are digested under.
#[derive(Clone)]
pub(crate) struct UserKey(hmac::Key);

impl std::fmt::Debug for UserKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserKey(..)")
    }
}

impl UserKey {
    pub(crate) fn new(secret: &[u8]) -> Self {
        Self(hmac::Key::new(hmac::HMAC_SHA256, secret))
    }

    /// A fresh random key (the memory store's, which lives as long as its windows).
    pub(crate) fn random() -> Result<Self, AuditError> {
        let rng = ring::rand::SystemRandom::new();
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &rng)
            .map_err(|_| AuditError::Storage("could not generate a user window key".into()))?;
        Ok(Self(key))
    }

    /// The digest of one user: HMAC of the canonical JSON of `[issuer, subject]`.
    pub(crate) fn digest(&self, issuer: &str, subject: &str) -> Result<String, AuditError> {
        let bytes = attenuo_core::jcs::to_vec(&serde_json::json!([issuer, subject]))
            .map_err(|e| AuditError::Storage(format!("user digest: {e}")))?;
        Ok(hex::encode(hmac::sign(&self.0, &bytes).as_ref()))
    }

    /// The counter key of `charge`.
    pub(crate) fn key(&self, charge: &WindowCharge) -> Result<WindowKey, AuditError> {
        Ok(WindowKey {
            user: self.digest(&charge.issuer, &charge.subject)?,
            kind: charge.kind.as_str(),
            start: charge.start,
            tool: charge.tool.clone(),
            measure: charge.measure.as_str(),
        })
    }
}

/// The rows one window charge writes: each counter with what it holds afterwards (saturating
/// at [`WindowCharge::MAX`]) and what was logged for it. `used` reads a counter; a counter
/// charged twice in one call adds up.
pub(crate) fn plan_windows(
    keys: &[WindowKey],
    charges: &[WindowCharge],
    mut used: impl FnMut(&WindowKey) -> Result<u64, AuditError>,
) -> Result<Vec<(WindowKey, u64, u64)>, AuditError> {
    let mut out: Vec<(WindowKey, u64, u64)> = Vec::with_capacity(keys.len());
    for (key, charge) in keys.iter().zip(charges) {
        let current = match out.iter().rev().find(|(k, _, _)| k == key) {
            Some((_, after, _)) => *after,
            None => used(key)?,
        };
        let after = current.saturating_add(charge.amount).min(WindowCharge::MAX);
        out.push((key.clone(), after, charge.amount));
    }
    Ok(out)
}

/// What one [`StoreRetention::prune_user_windows`](crate::StoreRetention::prune_user_windows) pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WindowPrune {
    /// Window counters deleted.
    pub pruned_windows: u64,
    /// Window charge-log rows deleted.
    pub pruned_charges: u64,
    /// Nothing prunable is left; the task need not run another pass now.
    pub wrapped: bool,
}

/// Whether a window counter (or a charge logged against it) may be deleted: its window ended
/// longer than `retention` before `now`. An open window is never pruned, whatever the
/// retention, so pruning cannot reset a window (the server refuses a retention below a day,
/// the longest window, at start).
pub fn window_prunable(
    window_end: i64,
    now: time::OffsetDateTime,
    retention: time::Duration,
) -> bool {
    window_end.saturating_add(retention.whole_seconds()) < now.unix_timestamp()
}
