//! Per-user windows (run limits phase 3, `docs/design/run-limits-phase3.md` section 3).
//!
//! A per-user window is the usage of a destructive tool by every run of one originating user
//! (keyed by issuer and subject) over a fixed calendar window in UTC: allowed calls, and the
//! sum of the catalog's `amount` input. Policies read it as `context.usage.user_window.<kind>`;
//! nothing about it is in a token. The window start is `floor(now_unix / length) * length`, so
//! an `hour` window starts on the hour and a `day` window at 00:00 UTC.
//!
//! [`window_charges`] gives the window counters one call is charged against. Like run usage, a
//! window charge never refuses a call: it saturates at [`MAX_LIMIT`]. The store keys the user
//! by a keyed digest of `[issuer, subject]`, never the subject itself.

use time::OffsetDateTime;

use crate::limits::{amount_of, MAX_LIMIT};
use crate::{OriginatingUser, ToolCall};

/// The length of a per-user window: `context.usage.user_window.hour` or `.day`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WindowKind {
    /// A UTC clock hour.
    Hour,
    /// A UTC calendar day.
    Day,
}

impl WindowKind {
    /// Every kind, shortest first.
    pub const ALL: [WindowKind; 2] = [WindowKind::Hour, WindowKind::Day];

    /// The name policies read it under and the store keeps (`hour`, `day`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
        }
    }

    /// The kind named `s`, if any.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// The window's length in seconds.
    pub fn length_seconds(&self) -> i64 {
        match self {
            Self::Hour => 3_600,
            Self::Day => 86_400,
        }
    }

    /// The start (Unix seconds, UTC) of the window of this kind that holds `now`.
    pub fn start_of(&self, now: OffsetDateTime) -> i64 {
        let len = self.length_seconds();
        now.unix_timestamp().div_euclid(len) * len
    }
}

impl std::fmt::Display for WindowKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a window counter counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WindowMeasure {
    /// Allowed calls of the tool.
    Calls,
    /// The sum of the catalog's `amount` input over those calls.
    Amount,
}

impl WindowMeasure {
    /// The store's name for it (`calls`, `amount`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Calls => "calls",
            Self::Amount => "amount",
        }
    }

    /// The measure named `s`, if any.
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Calls, Self::Amount]
            .into_iter()
            .find(|m| m.as_str() == s)
    }
}

/// One window counter a call is charged against: one measure of one tool, for one user, in one
/// window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowCharge {
    /// The originating user's issuer. The store keeps only a keyed digest of issuer and
    /// subject together.
    pub issuer: String,
    /// The originating user's subject.
    pub subject: String,
    /// The window's length.
    pub kind: WindowKind,
    /// The window's start, Unix seconds UTC ([`WindowKind::start_of`]).
    pub start: i64,
    /// The tool, `"<server>/<tool>"`.
    pub tool: String,
    /// What the counter counts.
    pub measure: WindowMeasure,
    /// What the call adds: 1 for `calls`, the amount for `amount`.
    pub amount: u64,
}

impl WindowCharge {
    /// The most a window counter holds: it saturates there and never refuses a call.
    pub const MAX: u64 = MAX_LIMIT;
}

/// The window counters an allowed call to a destructive tool is charged against, for each of
/// `kinds`: a `calls` counter charged 1 and, when the catalog names an `amount` input, an
/// `amount` counter charged that argument's value if it is an amount ([`amount_of`]), else 0.
/// Each window is the one that holds `now`. Ordered by `kinds`, then calls before amount.
pub fn window_charges(
    user: &OriginatingUser,
    call: &ToolCall,
    amount_arg: Option<&str>,
    kinds: &[WindowKind],
    now: OffsetDateTime,
) -> Vec<WindowCharge> {
    let tool = format!("{}/{}", call.server, call.tool);
    let amount = amount_arg.map(|a| call.arguments.get(a).and_then(amount_of).unwrap_or(0));
    let mut out = Vec::with_capacity(kinds.len() * 2);
    for &kind in kinds {
        let base = |measure, amount| WindowCharge {
            issuer: user.issuer.clone(),
            subject: user.subject.clone(),
            kind,
            start: kind.start_of(now),
            tool: tool.clone(),
            measure,
            amount,
        };
        out.push(base(WindowMeasure::Calls, 1));
        if let Some(a) = amount {
            out.push(base(WindowMeasure::Amount, a));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user() -> OriginatingUser {
        OriginatingUser {
            subject: "alice".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: OffsetDateTime::UNIX_EPOCH,
            attributes: Default::default(),
        }
    }

    #[test]
    fn windows_are_fixed_utc_hours_and_days() {
        let t = OffsetDateTime::from_unix_timestamp(1_762_400_000 + 3_725).unwrap();
        let day = WindowKind::Day.start_of(t);
        assert_eq!(day % 86_400, 0);
        assert!(day <= t.unix_timestamp() && t.unix_timestamp() < day + 86_400);
        let hour = WindowKind::Hour.start_of(t);
        assert_eq!(hour % 3_600, 0);
        assert!(hour <= t.unix_timestamp() && t.unix_timestamp() < hour + 3_600);
        // Before the epoch the start still floors.
        let before = OffsetDateTime::from_unix_timestamp(-1).unwrap();
        assert_eq!(WindowKind::Hour.start_of(before), -3_600);
        assert_eq!(WindowKind::parse("day"), Some(WindowKind::Day));
        assert_eq!(WindowKind::parse("month"), None);
        assert_eq!(WindowMeasure::parse("amount"), Some(WindowMeasure::Amount));
    }

    #[test]
    fn charges_count_calls_and_the_amount_per_kind() {
        let now = OffsetDateTime::from_unix_timestamp(90_000).unwrap();
        let call = ToolCall::new("bank", "send", json!({"amount": 250}));
        let c = window_charges(&user(), &call, Some("amount"), &WindowKind::ALL, now);
        let got: Vec<_> = c
            .iter()
            .map(|c| (c.kind, c.start, c.measure, c.amount, c.tool.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    WindowKind::Hour,
                    90_000,
                    WindowMeasure::Calls,
                    1,
                    "bank/send"
                ),
                (
                    WindowKind::Hour,
                    90_000,
                    WindowMeasure::Amount,
                    250,
                    "bank/send"
                ),
                (
                    WindowKind::Day,
                    86_400,
                    WindowMeasure::Calls,
                    1,
                    "bank/send"
                ),
                (
                    WindowKind::Day,
                    86_400,
                    WindowMeasure::Amount,
                    250,
                    "bank/send"
                ),
            ]
        );
        // No amount input: calls only. A non-amount value adds 0.
        assert_eq!(
            window_charges(&user(), &call, None, &[WindowKind::Day], now).len(),
            1
        );
        let odd = ToolCall::new("bank", "send", json!({"amount": "12.5"}));
        let c = window_charges(&user(), &odd, Some("amount"), &[WindowKind::Day], now);
        assert_eq!(c[1].amount, 0);
        assert!(window_charges(&user(), &call, Some("amount"), &[], now).is_empty());
    }
}
