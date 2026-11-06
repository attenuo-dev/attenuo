//! Run usage of destructive tools (run-limits design section 3.5) and the result digest.

use attenuo_core::RecordUsage;
use attenuo_policy::UsageContext;
use serde_json::Value;

/// What Cedar sees as `context.usage` when the run's usage cannot be read: the worst case, as an
/// unreadable taint state counts as tainted. A count rule asks or refuses, an amount rule that
/// adds the call's amount overflows (an evaluation error, which denies), and every destination
/// counts as seen.
pub const UNREADABLE_USAGE: UsageContext = UsageContext {
    calls: i64::MAX,
    amount: i64::MAX,
    destination_seen: true,
};

/// `context.usage` as JSON: `{calls, amount, destination_seen}`. What the decision record's
/// `usage` member, the `-32008` / `-32003` error data, AuthZEN answers and the admin dry run
/// carry for a destructive tool.
pub fn usage_json(u: &UsageContext) -> Value {
    serde_json::json!({
        "calls": u.calls,
        "amount": u.amount,
        "destination_seen": u.destination_seen,
    })
}

/// A duration in whole microseconds for a log field, saturating (a `u64` of microseconds is
/// over 500,000 years).
pub(super) fn micros(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

pub(super) fn record_usage(u: &UsageContext) -> RecordUsage {
    RecordUsage {
        calls: u64::try_from(u.calls).unwrap_or(0),
        amount: u64::try_from(u.amount).unwrap_or(0),
        destination_seen: u.destination_seen,
    }
}

/// SHA-256 (hex) and length of the RFC 8785 canonical JSON of an upstream result: what a
/// `tool_result` record stores instead of the result. `Err` for a value with no canonical
/// form (nothing parsed from JSON has one).
pub fn result_digest(result: &Value) -> Result<(String, u64), String> {
    let bytes = attenuo_core::jcs::to_vec(result).map_err(|e| e.to_string())?;
    Ok((
        attenuo_core::digest::sha256_bytes(&bytes),
        bytes.len() as u64,
    ))
}
