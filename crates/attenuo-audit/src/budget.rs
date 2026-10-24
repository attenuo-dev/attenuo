//! Run-limit counters (ADR-0010, `docs/design/run-limits.md`).
//!
//! A capability's `limits` are static figures in the token ([`attenuo_core::limits`]); what has
//! been spent against them lives here, next to the leases. There is one counter per (hop
//! lease, capability index, limit kind, argument, value): `value` is empty for `calls` and
//! `sum`, and for `calls_per` it is a keyed hash (HMAC-SHA-256 under a key the store generates
//! once and keeps) of the RFC 8785 canonical value, so the store holds no recipient addresses.
//! The key lives in the same store, so the hash keeps addresses off the counter rows, not out
//! of reach of someone who holds the whole store and a list of guesses.
//!
//! [`LeaseStore::charge`](crate::LeaseStore::charge) checks every charge of a call and either
//! applies all of them or none, in one transaction (an `IMMEDIATE` one in SQLite), so two
//! concurrent calls against a budget of one cannot both pass. Every charge is also logged under
//! the decision id that made it, so [`LeaseStore::refund`](crate::LeaseStore::refund) can
//! return exactly what one decision charged, at most once. Counters are keyed by lease id and
//! never joined with the lease table: revoking or expiring a lease does not stop its counters,
//! or its ancestors', from being read.
//!
//! Run usage (design section 3.5) lives in the same table, under the run's chain id, with the
//! kinds `usage_calls`, `usage_amount` and `usage_destination` and the tool as `arg`, and
//! is charged and refunded with the limits of the same decision. Unlike limit counters, usage
//! rows are deleted when their run's root lease is revoked, as the span index is.

use attenuo_core::{Charge, LimitKind};
use ring::hmac;

use crate::error::AuditError;

/// What [`LeaseStore::charge`](crate::LeaseStore::charge) did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChargeOutcome {
    /// Every charge was applied. `used_after[i]` is what the counter of `charges[i]` holds now.
    Charged { used_after: Vec<u64> },
    /// Nothing was applied: `charges[index]` would have taken its counter, which holds `used`,
    /// past its `max`.
    Exhausted { index: usize, used: u64 },
}

/// The row key of a counter. `value` is the hex HMAC of a `calls_per` value, or empty.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CounterKey {
    pub lease: String,
    pub cap: i64,
    pub kind: &'static str,
    pub arg: String,
    pub value: String,
}

/// The `kind` column of run-usage counters: calls, amount and destinations of one tool in one
/// run. Never a token limit's kind (`calls`, `sum`, `calls_per`).
pub(crate) const USAGE_KINDS: [&str; 3] = ["usage_calls", "usage_amount", "usage_destination"];

/// The `kind` column of `charge`'s counter.
fn kind_column(charge: &Charge) -> &'static str {
    match (charge.usage, charge.kind) {
        (false, kind) => kind.as_str(),
        (true, LimitKind::Calls) => USAGE_KINDS[0],
        (true, LimitKind::Sum) => USAGE_KINDS[1],
        (true, LimitKind::CallsPer) => USAGE_KINDS[2],
    }
}

/// The key that `calls_per` values are hashed under.
#[derive(Clone)]
pub(crate) struct ValueKey(hmac::Key);

impl std::fmt::Debug for ValueKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ValueKey(..)")
    }
}

impl ValueKey {
    pub fn new(secret: &[u8]) -> Self {
        Self(hmac::Key::new(hmac::HMAC_SHA256, secret))
    }

    /// A fresh random key (the memory store's, which lives as long as its counters).
    pub fn random() -> Result<Self, AuditError> {
        let rng = ring::rand::SystemRandom::new();
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &rng)
            .map_err(|_| AuditError::Storage("could not generate a budget value key".into()))?;
        Ok(Self(key))
    }

    /// The counter key of `charge`.
    pub fn counter(&self, charge: &Charge) -> Result<CounterKey, AuditError> {
        let cap = i64::try_from(charge.cap).map_err(|_| {
            AuditError::Storage(format!("capability index {} too large", charge.cap))
        })?;
        Ok(CounterKey {
            lease: charge.lease.0.clone(),
            cap,
            kind: kind_column(charge),
            arg: charge.arg.clone().unwrap_or_default(),
            value: charge
                .value
                .as_ref()
                .map(|v| hex::encode(hmac::sign(&self.0, v).as_ref()))
                .unwrap_or_default(),
        })
    }
}

/// Apply `charges` to counters read through `used` (which sees the effect of earlier charges
/// of the same call, so a counter charged twice adds up). Returns the new value of every
/// charged counter in order, or the first charge that would go over its `max`. A run-usage
/// charge never goes over: it saturates at its `max`.
pub(crate) fn plan(
    keys: &[CounterKey],
    charges: &[Charge],
    mut used: impl FnMut(&CounterKey) -> Result<u64, AuditError>,
) -> Result<Result<Vec<u64>, ChargeOutcome>, AuditError> {
    let mut pending: Vec<(CounterKey, u64)> = Vec::new();
    let mut after = Vec::with_capacity(charges.len());
    for (index, (key, charge)) in keys.iter().zip(charges).enumerate() {
        let current = match pending.iter().rev().find(|(k, _)| k == key) {
            Some((_, v)) => *v,
            None => used(key)?,
        };
        let next = if charge.usage {
            Some(current.saturating_add(charge.amount).min(charge.max))
        } else {
            current.checked_add(charge.amount)
        };
        match next {
            Some(next) if next <= charge.max => {
                pending.push((key.clone(), next));
                after.push(next);
            }
            _ => {
                return Ok(Err(ChargeOutcome::Exhausted {
                    index,
                    used: current,
                }))
            }
        }
    }
    Ok(Ok(after))
}
