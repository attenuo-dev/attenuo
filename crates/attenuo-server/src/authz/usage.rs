//! Run usage of destructive tools and of tools with an outbound argument (run-limits design
//! section 3.5, read-side exfiltration design option d) and the result digest.

use attenuo_core::limits::usage_charges;
use attenuo_core::{Charge, LeaseId, RecordUsage, ToolCall};
use attenuo_policy::{UsageContext, UserWindowContext};
use serde_json::Value;

/// What Cedar sees as `context.usage` when the run's usage cannot be read: the worst case, as an
/// unreadable taint state counts as tainted. A count rule asks or refuses, an amount rule that
/// adds the call's amount overflows (an evaluation error, which denies), and every destination
/// counts as seen.
pub const UNREADABLE_USAGE: UsageContext = UsageContext {
    calls: i64::MAX,
    amount: i64::MAX,
    destination_seen: true,
    user_window: UserWindowContext {
        hour: super::windows::UNREADABLE_WINDOW,
        day: super::windows::UNREADABLE_WINDOW,
    },
};

/// `context.usage` as JSON: `{calls, amount, destination_seen}`, plus `user_window: {hour:
/// {calls, amount}, day: {calls, amount}}` (run limits phase 3) when any of its figures is not
/// zero; left out, it is all zero, which is also what Cedar sees for a kind that is not kept.
/// What the `-32008` / `-32003` error data, AuthZEN answers and the admin dry run carry for a
/// destructive tool.
pub fn usage_json(u: &UsageContext) -> Value {
    let mut v = serde_json::json!({
        "calls": u.calls,
        "amount": u.amount,
        "destination_seen": u.destination_seen,
    });
    if u.user_window != UserWindowContext::default() {
        let w = |f: &attenuo_policy::WindowFigures| serde_json::json!({"calls": f.calls, "amount": f.amount});
        v["user_window"] =
            serde_json::json!({ "hour": w(&u.user_window.hour), "day": w(&u.user_window.day) });
    }
    v
}

/// The catalog inputs run usage counts for one tool: `amount`, `destination` and every
/// `outbound` entry (each `"<input>"` or `"<input>#host"`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct UsageInputs {
    pub(super) amount: Option<String>,
    pub(super) destination: Option<String>,
    pub(super) outbound: Vec<String>,
}

/// The run-usage charges of `call` under `chain_id`: [`usage_charges`] for `amount` and
/// `destination`, then the destinations of each outbound input, derived as `destination` is,
/// added to the same per-tool destination counter. A value already counted (the same canonical
/// value, or host, from `destination` or an earlier outbound input) is counted once.
/// `context.usage.destination_seen` is then true when any of the call's destination values was
/// seen in an earlier allowed call of the tool, as for a list-valued `destination`.
pub(super) fn run_usage_charges(
    chain_id: &LeaseId,
    call: &ToolCall,
    inputs: &UsageInputs,
) -> Vec<Charge> {
    let mut out = usage_charges(
        chain_id,
        call,
        inputs.amount.as_deref(),
        inputs.destination.as_deref(),
    );
    for entry in &inputs.outbound {
        // The first charge is the call count, already in `out`.
        for c in usage_charges(chain_id, call, None, Some(entry))
            .into_iter()
            .skip(1)
        {
            if !out.iter().any(|o| o.kind == c.kind && o.value == c.value) {
                out.push(c);
            }
        }
    }
    out
}

/// A duration in whole microseconds for a log field, saturating (a `u64` of microseconds is
/// over 500,000 years).
pub(super) fn micros(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

pub(super) fn record_usage(
    u: &UsageContext,
    windows: &[attenuo_core::WindowCharge],
) -> RecordUsage {
    RecordUsage {
        calls: u64::try_from(u.calls).unwrap_or(0),
        amount: u64::try_from(u.amount).unwrap_or(0),
        destination_seen: u.destination_seen,
        user_window: super::windows::record_windows(u, windows),
    }
}

/// SHA-256 (hex) and length of the RFC 8785 canonical JSON of an upstream result: what a
/// `tool_result` record stores instead of the result.
///
/// # Errors
///
/// The canonicalization error, as text, for a value with no RFC 8785 form (a number JSON cannot
/// carry); nothing parsed from JSON has one, so in practice this does not fail.
pub fn result_digest(result: &Value) -> Result<(String, u64), String> {
    let bytes = attenuo_core::jcs::to_vec(result).map_err(|e| e.to_string())?;
    Ok((
        attenuo_core::digest::sha256_bytes(&bytes),
        bytes.len() as u64,
    ))
}
