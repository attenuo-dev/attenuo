//! Per-user windows (run limits phase 3, `docs/design/run-limits-phase3.md` section 3): the
//! originating user's usage of a destructive tool across all their runs, per fixed UTC hour and
//! day, read for `context.usage.user_window` and charged with the call's run usage.

use attenuo_audit::RunLimits;
use attenuo_core::windows::window_charges;
use attenuo_core::{
    OriginatingUser, RecordUserWindow, RecordWindow, ToolCall, WindowKind, WindowMeasure,
};
use attenuo_policy::{UsageContext, WindowFigures};
use time::OffsetDateTime;

use super::BudgetView;

/// How many locks per-user windows spread users over (`Pipeline::run_guard`). A separate set
/// from the run stripes, always taken after the run's, so no decision waits for a run stripe
/// while holding a user stripe and none can block on itself.
pub(super) const USER_LOCK_STRIPES: usize = 64;

/// What Cedar sees for a kept window that cannot be read: the worst case, as for unreadable
/// run usage. A count rule refuses or asks, an amount rule that adds the call's amount
/// overflows (an evaluation error, which denies).
pub const UNREADABLE_WINDOW: WindowFigures = WindowFigures {
    calls: i64::MAX,
    amount: i64::MAX,
};

/// The stripe of `user`'s lock: SHA-256 of the canonical `[issuer, subject]`, as the run
/// stripe is of the chain id. In process only, like the run lock.
pub(super) fn user_stripe(user: &OriginatingUser, stripes: usize) -> usize {
    let bytes = attenuo_core::jcs::to_vec(&serde_json::json!([user.issuer, user.subject]))
        .unwrap_or_default();
    let digest = attenuo_core::digest::sha256_bytes(&bytes);
    usize::from_str_radix(&digest[..8], 16).unwrap_or(0) % stripes.max(1)
}

/// Fill in the per-user windows of a call that keeps run usage: the window charges of `kinds`
/// go into `view.windows` (charged with the call if it is allowed), and what the store holds
/// for them into `view.usage.user_window`. When the store cannot be read, every kept kind is
/// [`UNREADABLE_WINDOW`] and a diagnostic is added; the policy decides on that. Nothing is done
/// for a call that keeps no usage or when no kind is kept. When the run's usage itself was
/// unreadable, the worst case is already in place and the windows are not read.
pub(super) fn read_windows(
    leases: &dyn RunLimits,
    view: &mut BudgetView,
    user: &OriginatingUser,
    call: &ToolCall,
    amount_arg: Option<&str>,
    kinds: &[WindowKind],
    now: OffsetDateTime,
) {
    let Some(usage) = view.usage.as_mut() else {
        return;
    };
    if kinds.is_empty() {
        return;
    }
    view.windows = window_charges(user, call, amount_arg, kinds, now);
    if view.usage_error.is_some() {
        return;
    }
    match leases.window_used(&view.windows) {
        Ok(used) => {
            for (w, u) in view.windows.iter().zip(used) {
                let figures = usage.user_window.get_mut(w.kind);
                let u = i64::try_from(u).unwrap_or(i64::MAX);
                match w.measure {
                    WindowMeasure::Calls => figures.calls = u,
                    WindowMeasure::Amount => figures.amount = u,
                }
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "per-user windows unreadable; deciding on the worst case");
            for &k in kinds {
                *usage.user_window.get_mut(k) = UNREADABLE_WINDOW;
            }
            view.usage_error = Some(format!(
                "per-user windows unreadable, worst case assumed: {e}"
            ));
        }
    }
}

/// The record's `usage.user_window`: the kinds charged (`windows`), each with its start and
/// what Cedar saw. `None` when no window is kept.
pub(super) fn record_windows(
    u: &UsageContext,
    windows: &[attenuo_core::WindowCharge],
) -> Option<RecordUserWindow> {
    let mut out = RecordUserWindow::default();
    for w in windows {
        let f = u.user_window.get(w.kind);
        let entry = RecordWindow {
            start: w.start,
            calls: u64::try_from(f.calls).unwrap_or(0),
            amount: u64::try_from(f.amount).unwrap_or(0),
        };
        match w.kind {
            WindowKind::Hour => out.hour = Some(entry),
            WindowKind::Day => out.day = Some(entry),
        }
    }
    (out.hour.is_some() || out.day.is_some()).then_some(out)
}
