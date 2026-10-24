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
//! A `distinct` limit keeps two kinds of row: one per value seen (kind `distinct_value`, the
//! value's keyed hash, holding 1), and its count of values (kind `distinct`, empty value). A
//! charge adds to the count only when the value's row is new, in the same transaction, so a
//! repeat of a value already seen costs nothing. Every decision that used a value logs a row
//! for it, with amount 1 when it added the value and 0 when the value was already seen. A
//! refund frees a value (removes its row and takes 1 off the count, so the value counts as new
//! again) only when no other unrefunded decision logged it; otherwise the value stays counted
//! for those decisions, and the last of them to be refunded frees it (SR-62).
//!
//! Run usage (design section 3.5) lives in the same table, under the run's chain id, with the
//! kinds `usage_calls`, `usage_amount` and `usage_destination` and the tool as `arg`, and
//! is charged and refunded with the limits of the same decision. Unlike limit counters, usage
//! rows are deleted when their run's root lease is revoked, as the span index is.

use attenuo_core::{Charge, LimitKind, Limits};
use ring::hmac;
use serde::{Deserialize, Serialize};

use crate::error::AuditError;

/// What [`LeaseStore::charge`](crate::LeaseStore::charge) did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChargeOutcome {
    /// Every charge was applied. `used_after[i]` is what the counter of `charges[i]` holds now
    /// (for a `distinct` charge, how many values its limit has seen).
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

/// One limited capability of a hop, as the server recorded it when it issued the hop's token,
/// so the admin console can show a lease's limits next to its counters
/// ([`LeaseStore::record_hop_limits`](crate::LeaseStore::record_hop_limits)). The token
/// stays the authority; this copy is for display only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopLimit {
    /// Index of the capability in the hop's capability set (its canonical order), as charges
    /// and records name it.
    pub cap: usize,
    pub server: String,
    pub tool: String,
    pub limits: Limits,
}

/// What one counter (or one group of per-value counters) under a lease holds
/// ([`LeaseStore::budget_summary`](crate::LeaseStore::budget_summary)). Value hashes are not
/// exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterSummary {
    /// Capability index (0 for run usage).
    pub cap: usize,
    /// The `kind` column: `calls`, `sum`, `calls_per`, `distinct`, or a run-usage kind
    /// (`usage_calls`, `usage_amount`, `usage_destination`).
    pub kind: String,
    /// The argument counted (`arg#host` for a derived one), the tool for run usage, or empty.
    pub arg: String,
    /// For `calls`, `sum`, `distinct` and the usage counts: what the counter holds (for
    /// `distinct`, how many values it has seen). For per-value kinds (`calls_per`,
    /// `usage_destination`): the most any one value has been used.
    pub used: u64,
    /// For per-value kinds: how many values have been seen. 0 otherwise.
    pub values: u64,
}

/// Group `rows` (counter key, what it holds) of one lease into [`CounterSummary`]s, ordered by
/// capability, kind and argument. The value rows of a `distinct` limit are left out: its count
/// row says how many there are.
pub(crate) fn summarize<'a>(
    rows: impl IntoIterator<Item = (&'a CounterKey, u64)>,
) -> Vec<CounterSummary> {
    let mut out: std::collections::BTreeMap<(i64, &'static str, String), (u64, u64)> =
        std::collections::BTreeMap::new();
    for (key, used) in rows {
        if key.kind == DISTINCT_VALUE_KIND {
            continue;
        }
        let entry = out
            .entry((key.cap, key.kind, key.arg.clone()))
            .or_insert((0, 0));
        entry.0 = entry.0.max(used);
        if !key.value.is_empty() {
            entry.1 += 1;
        }
    }
    out.into_iter()
        .map(|((cap, kind, arg), (used, values))| CounterSummary {
            cap: usize::try_from(cap).unwrap_or(0),
            kind: kind.to_string(),
            arg,
            used,
            values,
        })
        .collect()
}

/// The `kind` column of a counter as a static string (rows read back from SQLite).
pub(crate) fn kind_static(kind: &str) -> Option<&'static str> {
    [
        "calls",
        "sum",
        "calls_per",
        "distinct",
        DISTINCT_VALUE_KIND,
        USAGE_KINDS[0],
        USAGE_KINDS[1],
        USAGE_KINDS[2],
    ]
    .into_iter()
    .find(|k| *k == kind)
}

/// The `kind` column of run-usage counters: calls, amount and destinations of one tool in one
/// run. Never a token limit's kind (`calls`, `sum`, `calls_per`).
pub(crate) const USAGE_KINDS: [&str; 3] = ["usage_calls", "usage_amount", "usage_destination"];

/// The `kind` column of the rows that record which values a `distinct` limit has seen. The
/// limit's count of values is the row of kind `distinct` with an empty value.
pub(crate) const DISTINCT_VALUE_KIND: &str = "distinct_value";

/// The `kind` column of `charge`'s counter. A `distinct` charge with a value names the row of
/// that value; one without (a probe) names the limit's count.
fn kind_column(charge: &Charge) -> &'static str {
    match (charge.usage, charge.kind) {
        (false, LimitKind::Distinct) if charge.value.is_some() => DISTINCT_VALUE_KIND,
        (false, kind) => kind.as_str(),
        (true, LimitKind::Calls) => USAGE_KINDS[0],
        (true, LimitKind::Sum) => USAGE_KINDS[1],
        (true, LimitKind::CallsPer | LimitKind::Distinct) => USAGE_KINDS[2],
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

/// One row a charge writes: the counter, what it holds afterwards and what was added to it
/// (logged, so a refund can take exactly that back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Write {
    pub key: CounterKey,
    pub after: u64,
    pub amount: u64,
}

/// What [`plan`] decided for a call that fits: what each charge's counter holds afterwards
/// (for a `distinct` charge, the limit's count of values) and the rows to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Planned {
    pub used_after: Vec<u64>,
    pub writes: Vec<Write>,
}

/// Apply `charges` to counters read through `used` (which sees the effect of earlier charges
/// of the same call, so a counter charged twice adds up). Returns the new value of every
/// charged counter in order with the rows to write, or the first charge that would go over its
/// `max`. A run-usage charge never goes over: it saturates at its `max`. A `distinct` charge
/// whose value was already seen leaves the counters as they are and logs a zero-amount row
/// for the value; a new value adds its row and 1 to the limit's count, which must stay within
/// `max`.
pub(crate) fn plan(
    keys: &[CounterKey],
    charges: &[Charge],
    mut used: impl FnMut(&CounterKey) -> Result<u64, AuditError>,
) -> Result<Result<Planned, ChargeOutcome>, AuditError> {
    let mut pending: Vec<(CounterKey, u64)> = Vec::new();
    let mut after = Vec::with_capacity(charges.len());
    let mut writes = Vec::with_capacity(charges.len());
    for (index, (key, charge)) in keys.iter().zip(charges).enumerate() {
        let mut current_of = |k: &CounterKey, pending: &[(CounterKey, u64)]| match pending
            .iter()
            .rev()
            .find(|(p, _)| p == k)
        {
            Some((_, v)) => Ok(*v),
            None => used(k),
        };
        if key.kind == DISTINCT_VALUE_KIND {
            let count_key = CounterKey {
                kind: LimitKind::Distinct.as_str(),
                value: String::new(),
                ..key.clone()
            };
            let count = current_of(&count_key, &pending)?;
            let seen = current_of(key, &pending)?;
            if seen > 0 {
                // A zero-amount row in the charge log records that this decision used the
                // value too, so a refund of the decision that added it keeps it (SR-62).
                if !pending.iter().any(|(p, _)| p == key) {
                    pending.push((key.clone(), seen));
                    writes.push(Write {
                        key: key.clone(),
                        after: seen,
                        amount: 0,
                    });
                }
                after.push(count);
                continue;
            }
            match count.checked_add(1) {
                Some(next) if next <= charge.max => {
                    pending.push((key.clone(), 1));
                    pending.push((count_key.clone(), next));
                    writes.push(Write {
                        key: key.clone(),
                        after: 1,
                        amount: 1,
                    });
                    writes.push(Write {
                        key: count_key,
                        after: next,
                        amount: 1,
                    });
                    after.push(next);
                }
                _ => return Ok(Err(ChargeOutcome::Exhausted { index, used: count })),
            }
            continue;
        }
        let current = current_of(key, &pending)?;
        let next = if charge.usage {
            Some(current.saturating_add(charge.amount).min(charge.max))
        } else {
            current.checked_add(charge.amount)
        };
        match next {
            Some(next) if next <= charge.max => {
                pending.push((key.clone(), next));
                writes.push(Write {
                    key: key.clone(),
                    after: next,
                    amount: charge.amount,
                });
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
    Ok(Ok(Planned {
        used_after: after,
        writes,
    }))
}
