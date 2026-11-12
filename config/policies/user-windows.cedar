// Per-user window examples (run limits phase 3, docs/design/run-limits-phase3.md section 3).
//
// For every tool the catalog marks destructive, the server can keep what all runs of one
// originating user (one issuer and subject) did with it in the current fixed UTC hour and UTC
// day, and hands it to Cedar before each call:
//
//   context.usage.user_window.hour.calls    allowed calls of this tool this UTC hour
//   context.usage.user_window.hour.amount   the sum of the catalog's `amount` input over them
//   context.usage.user_window.day.calls     the same for the UTC day (00:00 to 24:00 UTC)
//   context.usage.user_window.day.amount
//
// The server keeps only the kinds a loaded policy reads: this file makes it keep both. A new
// run, or revoking a run, does not reset a window. Windows refuse nothing by themselves; these
// policies turn them into limits that no token can raise.
//
// Asking is the documented default: an injected agent that spends the window then blocks the
// user's other runs only until someone approves, not until the window rolls over. Deny when
// the cap is a regulated one that no approver may pass.

// Soft (the default form): a payment that takes the user's agents past 5000 in a UTC day asks.
@id("ask_over_user_daily_spend_5000")
@obligation("approval")
forbid (principal, action == Action::"banking/send_money", resource)
when {
  context.input has amount &&
  context.usage.user_window.day.amount + context.input.amount > 5000 &&
  !context.approval.present
};

// Hard (a regulated cap): at most 20 payments an hour from all of a user's agents together.
@id("user_hourly_payments_20")
forbid (principal, action == Action::"banking/send_money", resource)
when { context.usage.user_window.hour.calls >= 20 };

// The permit side of this example: everything the token's capabilities allow.
@id("permit_what_the_token_allows")
permit (principal, action, resource);
