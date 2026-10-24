// Run limits examples (ADR-0010; section 3.5 of the run-limits design note).
//
// A capability in a delegation token may carry `limits` (`calls`, `sum`, `calls_per`). The
// server enforces them itself, before Cedar: a call that would take any matching limit, in
// any hop of the chain, past its `max` is denied with `budget_exhausted`, and no policy or
// approval can pass it. What policies see is what is left, always present:
//
//   context.budget.limited           some limit in the chain matches this call
//   context.budget.calls_remaining   before this call, the smallest `max - used` over every
//                                    matching `calls` limit (Cedar's largest Long if none)
//   context.budget.amount_remaining  the same for `sum` limits
//   context.budget.destination_new   the call's `calls_per` value has not appeared in an
//                                    earlier allowed call under that limit (true if none)
//
// Policies read these to explain or to ask earlier, never to raise a limit: the figures in
// the token are the ceiling.

// Ask the user before the last call a budget allows: once it is spent, the run needs a new
// delegation, so the user may want to see what it is spent on.
@id("confirm_last_call_of_a_budget")
@obligation("approval")
forbid (principal, action, resource)
when {
  context.budget.limited &&
  context.budget.calls_remaining <= 1 &&
  resource.destructive &&
  !context.approval.present
};

// A payment to a payee the run has already paid under a `calls_per` limit is refused even
// when that limit would allow another one (a stricter house rule than the token's).
@id("no_repeat_payment_to_a_payee")
forbid (principal, action == Action::"banking/send_money", resource)
when { !context.budget.destination_new };

// The permit side of this example: everything the token's capabilities allow. The
// capability stage runs before Cedar, so this cannot widen a token. Replace it with your own
// permits.
@id("permit_what_the_token_allows")
permit (principal, action, resource);
