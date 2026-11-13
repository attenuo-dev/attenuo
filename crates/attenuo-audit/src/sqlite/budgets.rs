//! Run limit counters (ADR-0010): charging and refunding inside the lease store's
//! transactions.

use attenuo_core::limits::MAX_LIMIT;
use attenuo_core::{Charge, LimitKind, WindowCharge};
use rusqlite::{params, Connection, OptionalExtension};
use time::OffsetDateTime;

use super::connection::{with_full_sync, Durability};
use super::leases::SqliteLeaseStore;
use super::{fmt_time, to_i64};
use crate::budget::{plan, ChargeOutcome, CounterKey, DISTINCT_VALUE_KIND, USAGE_KINDS};
use crate::error::AuditError;
use crate::window::{plan_windows, WindowKey, WindowPrune};

/// What counter `key` holds (0 when it has never been charged).
pub(super) fn counter_in(conn: &Connection, key: &CounterKey) -> Result<u64, AuditError> {
    let used: Option<i64> = conn
        .prepare_cached(
            "SELECT used FROM budget_counters \
             WHERE lease = ?1 AND cap = ?2 AND kind = ?3 AND arg = ?4 AND value = ?5",
        )?
        .query_row(
            params![key.lease, key.cap, key.kind, key.arg, key.value],
            |r| r.get(0),
        )
        .optional()?;
    let used = used.unwrap_or(0);
    u64::try_from(used)
        .map_err(|_| AuditError::Storage(format!("budget counter {used} is negative")))
}

/// What window counter `key` holds (0 when it has never been charged).
pub(super) fn window_in(conn: &Connection, key: &WindowKey) -> Result<u64, AuditError> {
    let used: Option<i64> = conn
        .prepare_cached(
            "SELECT used FROM user_windows WHERE user = ?1 AND window_kind = ?2 \
             AND window_start = ?3 AND tool = ?4 AND measure = ?5",
        )?
        .query_row(
            params![key.user, key.kind, key.start, key.tool, key.measure],
            |r| r.get(0),
        )
        .optional()?;
    let used = used.unwrap_or(0);
    u64::try_from(used)
        .map_err(|_| AuditError::Storage(format!("window counter {used} is negative")))
}

/// [`RunLimits::charge_windowed`](crate::lease::RunLimits::charge_windowed) in one
/// `IMMEDIATE` transaction: the re-check and the writes see the same counters, and a
/// concurrent charge waits for this one to commit. Window charges are written only once every
/// limit fits, in the same transaction.
fn charge_in(
    conn: &mut Connection,
    keys: &[CounterKey],
    decision_id: &str,
    charges: &[Charge],
    windows: (&[WindowKey], &[WindowCharge]),
    at: OffsetDateTime,
) -> Result<ChargeOutcome, AuditError> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let already: bool = tx
        .prepare_cached(
            "SELECT EXISTS (SELECT 1 FROM budget_charges WHERE decision_id = ?1) \
                 OR EXISTS (SELECT 1 FROM user_window_charges WHERE decision_id = ?1)",
        )?
        .query_row([decision_id], |r| r.get(0))?;
    if already {
        return Err(AuditError::Storage(format!(
            "decision `{decision_id}` is already charged"
        )));
    }
    let planned = match plan(keys, charges, |k| counter_in(&tx, k))? {
        Ok(planned) => planned,
        Err(exhausted) => return Ok(exhausted),
    };
    let at = fmt_time(at)?;
    for w in &planned.writes {
        let (key, after, amount) = (&w.key, to_i64(w.after)?, to_i64(w.amount)?);
        tx.prepare_cached(
            "INSERT INTO budget_counters (lease, cap, kind, arg, value, used) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT (lease, cap, kind, arg, value) DO UPDATE SET used = excluded.used",
        )?
        .execute(params![
            key.lease, key.cap, key.kind, key.arg, key.value, after
        ])?;
        tx.prepare_cached(
            "INSERT INTO budget_charges (decision_id, lease, cap, kind, arg, value, amount, at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?
        .execute(params![
            decision_id,
            key.lease,
            key.cap,
            key.kind,
            key.arg,
            key.value,
            amount,
            at
        ])?;
    }
    for (key, after, amount) in plan_windows(windows.0, windows.1, |k| window_in(&tx, k))? {
        tx.prepare_cached(
            "INSERT INTO user_windows (user, window_kind, window_start, tool, measure, used) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT (user, window_kind, window_start, tool, measure) \
             DO UPDATE SET used = excluded.used",
        )?
        .execute(params![
            key.user,
            key.kind,
            key.start,
            key.tool,
            key.measure,
            to_i64(after)?
        ])?;
        tx.prepare_cached(
            "INSERT INTO user_window_charges \
             (decision_id, user, window_kind, window_start, tool, measure, amount, at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?
        .execute(params![
            decision_id,
            key.user,
            key.kind,
            key.start,
            key.tool,
            key.measure,
            to_i64(amount)?,
            at
        ])?;
    }
    tx.commit()?;
    Ok(ChargeOutcome::Charged {
        used_after: planned.used_after,
    })
}

/// [`RunLimits::refund`](crate::lease::RunLimits::refund) in one `IMMEDIATE` transaction. The value rows of a `distinct` limit
/// are freed only when no other unrefunded decision logged them (SR-62); every other counter
/// gets back what the decision logged.
pub(super) fn refund_in(
    conn: &mut Connection,
    decision_id: &str,
    at: OffsetDateTime,
) -> Result<u64, AuditError> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let distinct = LimitKind::Distinct.as_str();
    let (rows, refunded, limits): (i64, i64, i64) = tx
        .prepare_cached(
            "SELECT COUNT(*), COUNT(refunded_at), \
                    COUNT(*) FILTER (WHERE kind NOT IN (?2, ?3, ?4, ?5, ?6)) \
             FROM budget_charges WHERE decision_id = ?1",
        )?
        .query_row(
            params![
                decision_id,
                USAGE_KINDS[0],
                USAGE_KINDS[1],
                USAGE_KINDS[2],
                DISTINCT_VALUE_KIND,
                distinct
            ],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
    let (window_rows, window_refunded): (i64, i64) = tx
        .prepare_cached(
            "SELECT COUNT(*), COUNT(refunded_at) FROM user_window_charges WHERE decision_id = ?1",
        )?
        .query_row([decision_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
    if rows == 0 && window_rows == 0 {
        return Err(AuditError::UnknownCharge(decision_id.to_owned()));
    }
    if refunded > 0 || window_refunded > 0 {
        return Err(AuditError::ChargeRefunded(decision_id.to_owned()));
    }
    refund_windows_in(&tx, decision_id, at)?;
    // The values this decision used, and whether another unrefunded decision used each too.
    let values: Vec<(String, i64, String, String, bool)> = tx
        .prepare_cached(
            "SELECT DISTINCT c.lease, c.cap, c.arg, c.value, EXISTS ( \
                 SELECT 1 FROM budget_charges o WHERE o.lease = c.lease AND o.cap = c.cap \
                   AND o.kind = c.kind AND o.arg = c.arg AND o.value = c.value \
                   AND o.decision_id <> c.decision_id AND o.refunded_at IS NULL) \
             FROM budget_charges c WHERE c.decision_id = ?1 AND c.kind = ?2",
        )?
        .query_map(params![decision_id, DISTINCT_VALUE_KIND], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<Result<_, _>>()?;
    let mut freed: u64 = 0;
    for (lease, cap, arg, value, shared) in values {
        if shared {
            continue;
        }
        let cleared = tx
            .prepare_cached(
                "UPDATE budget_counters SET used = 0 \
                 WHERE lease = ?1 AND cap = ?2 AND kind = ?3 AND arg = ?4 AND value = ?5 \
                   AND used > 0",
            )?
            .execute(params![lease, cap, DISTINCT_VALUE_KIND, arg, value])?;
        if cleared > 0 {
            tx.prepare_cached(
                "UPDATE budget_counters SET used = MAX(0, used - 1) \
                 WHERE lease = ?1 AND cap = ?2 AND kind = ?3 AND arg = ?4 AND value = ''",
            )?
            .execute(params![lease, cap, distinct, arg])?;
            freed += 1;
        }
    }
    // Every other counter: what the decision logged, row by row, saturating at 0. One
    // `UPDATE` per logged row rather than a `SUM` of them: two rows of one decision on one
    // counter (run usage of up to `MAX_LIMIT` each) would overflow SQLite's integer `SUM`
    // and fail the refund, where the memory store succeeds (fuzzing round 2, FZ2-3). A
    // `distinct` limit's count moves with its values, above, not with the amounts logged.
    let rows: Vec<(String, i64, String, String, String, i64)> = tx
        .prepare_cached(
            "SELECT lease, cap, kind, arg, value, amount FROM budget_charges \
             WHERE decision_id = ?1 AND kind NOT IN (?2, ?3)",
        )?
        .query_map(params![decision_id, DISTINCT_VALUE_KIND, distinct], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })?
        .collect::<Result<_, _>>()?;
    let mut usage = Vec::new();
    for (lease, cap, kind, arg, value, amount) in rows {
        if USAGE_KINDS.contains(&kind.as_str()) {
            usage.push((lease, cap, kind, arg, value));
            continue;
        }
        tx.prepare_cached(
            "UPDATE budget_counters SET used = MAX(0, used - ?6) \
             WHERE lease = ?1 AND cap = ?2 AND kind = ?3 AND arg = ?4 AND value = ?5",
        )?
        .execute(params![lease, cap, kind, arg, value, amount])?;
    }
    tx.prepare_cached("UPDATE budget_charges SET refunded_at = ?2 WHERE decision_id = ?1")?
        .execute(params![decision_id, fmt_time(at)?])?;
    // A run-usage counter saturates at `MAX_LIMIT`, so what one decision logged is not what it
    // added once the counter was full: recompute it from the unrefunded rows left (FZ2-4).
    for (lease, cap, kind, arg, value) in usage {
        let amounts: Vec<i64> = tx
            .prepare_cached(
                "SELECT amount FROM budget_charges WHERE lease = ?1 AND cap = ?2 AND kind = ?3 \
                 AND arg = ?4 AND value = ?5 AND refunded_at IS NULL",
            )?
            .query_map(params![lease, cap, kind, arg, value], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let total = amounts
            .into_iter()
            .fold(0u64, |t, a| t.saturating_add(u64::try_from(a).unwrap_or(0)))
            .min(MAX_LIMIT);
        tx.prepare_cached(
            "UPDATE budget_counters SET used = ?6 \
             WHERE lease = ?1 AND cap = ?2 AND kind = ?3 AND arg = ?4 AND value = ?5",
        )?
        .execute(params![lease, cap, kind, arg, value, to_i64(total)?])?;
    }
    tx.commit()?;
    // Token-limit counters only (see `RunLimits::refund`).
    Ok(u64::try_from(limits).unwrap_or(0) + freed)
}

/// The window part of a refund, inside the refund's transaction: mark what `decision_id`
/// charged to windows refunded and recompute each of those windows from the unrefunded charges
/// left (a window saturates at `MAX_LIMIT`, so what one decision logged is not what it added
/// once the window was full).
fn refund_windows_in(
    tx: &Connection,
    decision_id: &str,
    at: OffsetDateTime,
) -> Result<(), AuditError> {
    let keys: Vec<(String, String, i64, String, String)> = tx
        .prepare_cached(
            "SELECT DISTINCT user, window_kind, window_start, tool, measure \
             FROM user_window_charges WHERE decision_id = ?1",
        )?
        .query_map([decision_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<Result<_, _>>()?;
    if keys.is_empty() {
        return Ok(());
    }
    tx.prepare_cached("UPDATE user_window_charges SET refunded_at = ?2 WHERE decision_id = ?1")?
        .execute(params![decision_id, fmt_time(at)?])?;
    for (user, kind, start, tool, measure) in keys {
        let amounts: Vec<i64> = tx
            .prepare_cached(
                "SELECT amount FROM user_window_charges WHERE user = ?1 AND window_kind = ?2 \
                 AND window_start = ?3 AND tool = ?4 AND measure = ?5 AND refunded_at IS NULL",
            )?
            .query_map(params![user, kind, start, tool, measure], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let total = amounts
            .into_iter()
            .fold(0u64, |t, a| t.saturating_add(u64::try_from(a).unwrap_or(0)))
            .min(MAX_LIMIT);
        tx.prepare_cached(
            "UPDATE user_windows SET used = ?6 WHERE user = ?1 AND window_kind = ?2 \
             AND window_start = ?3 AND tool = ?4 AND measure = ?5",
        )?
        .execute(params![user, kind, start, tool, measure, to_i64(total)?])?;
    }
    Ok(())
}

/// [`StoreRetention::prune_user_windows`](crate::lease::StoreRetention::prune_user_windows) in one
/// `IMMEDIATE` transaction: up to `max_rows` window counters whose window ended more than
/// `retention` ago, then the charges logged against windows that old (at most `max_rows`).
pub(super) fn prune_windows_in(
    conn: &mut Connection,
    now: OffsetDateTime,
    retention: time::Duration,
    max_rows: usize,
) -> Result<WindowPrune, AuditError> {
    let max = max_rows.max(1) as u64;
    let max_rows = i64::try_from(max).unwrap_or(i64::MAX);
    // The window's end, as `WindowKey::end` computes it (an unknown kind counts as a day), is
    // compared with `now - retention`: the same rule as `window_prunable`.
    let latest_end = now
        .unix_timestamp()
        .saturating_sub(retention.whole_seconds());
    let ended = "window_start + CASE window_kind WHEN 'hour' THEN 3600 ELSE 86400 END < ?1";
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let windows = tx
        .prepare_cached(&format!(
            "DELETE FROM user_windows WHERE (user, window_kind, window_start, tool, measure) IN \
             (SELECT user, window_kind, window_start, tool, measure FROM user_windows \
              WHERE {ended} LIMIT ?2)"
        ))?
        .execute(params![latest_end, max_rows])?;
    let charges = tx
        .prepare_cached(&format!(
            "DELETE FROM user_window_charges WHERE rowid IN \
             (SELECT rowid FROM user_window_charges WHERE {ended} LIMIT ?2)"
        ))?
        .execute(params![latest_end, max_rows])?;
    tx.commit()?;
    let windows = windows as u64;
    let charges = charges as u64;
    Ok(WindowPrune {
        pruned_windows: windows,
        pruned_charges: charges,
        wrapped: windows < max && charges < max,
    })
}

impl SqliteLeaseStore {
    /// [`RunLimits::charge`](crate::lease::RunLimits::charge), or with `defer` [`RunLimits::charge_sync_deferred`](crate::lease::RunLimits::charge_sync_deferred).
    pub(super) fn charge_with(
        &self,
        decision_id: &str,
        charges: &[Charge],
        windows: &[WindowCharge],
        at: OffsetDateTime,
        defer: bool,
    ) -> Result<(ChargeOutcome, bool), AuditError> {
        if charges.is_empty() && windows.is_empty() {
            let none = ChargeOutcome::Charged {
                used_after: Vec::new(),
            };
            return Ok((none, false));
        }
        let keys = charges
            .iter()
            .map(|c| self.value_key.counter(c))
            .collect::<Result<Vec<_>, _>>()?;
        let window_keys = windows
            .iter()
            .map(|w| self.user_key.key(w))
            .collect::<Result<Vec<_>, _>>()?;
        let windows = (window_keys.as_slice(), windows);
        let _gate = self.gate.hold();
        let mut conn = self.conn.lock()?;
        // A lost `sum` charge could be spent again after a power failure, so a transaction
        // that charges one commits with `synchronous=FULL`, as revocations do (design 3.4).
        // Run usage is not a limit: it never adds the sync (design section 3.5).
        let relaxed = if charges.iter().any(|c| c.kind == LimitKind::Sum && !c.usage) {
            self.durability
                .filter(|d| *d != Durability::Full)
                .map(Durability::level)
        } else {
            None
        };
        if defer && relaxed.is_some() && self.file.is_some() {
            // Committed at the store's own level. The caller's synced append on the same
            // file syncs the WAL, which holds this commit, before the call goes anywhere.
            let outcome = charge_in(&mut conn, &keys, decision_id, charges, windows, at)?;
            self.probe_charge(&conn, &outcome);
            let owed = matches!(outcome, ChargeOutcome::Charged { .. });
            return Ok((outcome, owed));
        }
        let outcome = with_full_sync(&mut conn, relaxed, |conn| {
            let outcome = charge_in(conn, &keys, decision_id, charges, windows, at);
            if let Ok(o) = &outcome {
                self.probe_charge(conn, o);
            }
            outcome
        })??;
        Ok((outcome, false))
    }

    /// Tests: note a charge that committed and the `synchronous` level it committed at.
    #[cfg(not(test))]
    fn probe_charge(&self, _: &Connection, _: &ChargeOutcome) {}

    /// Tests: note a charge that committed and the `synchronous` level it committed at.
    #[cfg(test)]
    fn probe_charge(&self, conn: &Connection, outcome: &ChargeOutcome) {
        if let (Some(log), ChargeOutcome::Charged { .. }) = (&self.probe, outcome) {
            let level: i64 = conn
                .query_row("PRAGMA synchronous", [], |r| r.get(0))
                .unwrap_or(-1);
            log.lock()
                .unwrap()
                .push(format!("charge synchronous={level}"));
        }
    }
}
