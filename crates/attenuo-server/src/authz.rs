//! The decision pipeline and the proxy's real [`Authorizer`].
//!
//! [`Pipeline::decide`] is the one place a tool call is decided. Both the MCP proxy (through
//! [`ServerAuthorizer`]) and the AuthZEN endpoint call it, so they cannot disagree:
//!
//! 1. **Leases.** Every lease in the chain must be known, unrevoked and unexpired
//!    (`LeaseStore::check_all`). Otherwise: deny with `lease_revoked`, `lease_expired` or
//!    `lease_unknown` (checked in that order), or `lease_error` if the store fails.
//! 2. **Labels and budgets.** The taint state of the delegation run (`LeaseStore::labels`
//!    for the chain id, ADR-0009); a store that cannot be read counts as tainted. And the
//!    run limits (ADR-0010): every limited capability, in every hop, that matches the call
//!    ([`attenuo_core::limits::charges_for`]) and what its counters hold
//!    (`LeaseStore::budget_used`), as `context.budget` and as the limit check of step 4.
//!    Unreadable counters deny a limited call with `budget_error`; an argument a limit
//!    cannot count denies it with `limit_arg_invalid`. In the same read, for a tool the
//!    catalog marks destructive, and only when the engine tracks usage
//!    ([`PolicyEngine::tracks_usage`]: something loaded can read it), the run's usage of it
//!    (design section 3.5,
//!    [`attenuo_core::limits::usage_charges`]): calls, the catalog's `amount` input summed,
//!    whether its `destination` was seen, as `context.usage`; with no limit matching,
//!    unreadable usage is the worst case ([`UNREADABLE_USAGE`]) and the policy decides. Then
//!    argument matching (ADR-0009
//!    phase 2, [`Pipeline::arg_taint`]): on a tainted run, for every call when a loaded
//!    policy reads `context.args_contain_untrusted` or `context.untrusted_args`
//!    ([`PolicyEngine::reads_arg_taint`]) and otherwise for a call to a destructive tool,
//!    every argument not pinned by an `equals` or `one_of` constraint is fingerprinted and
//!    looked up in the run's span index (`LeaseStore::find_spans`); the hits are
//!    `context.untrusted_args` and the record's `labels.untrusted_args`. An unreadable index
//!    makes every unpinned argument untrusted.
//! 3. **Approval.** A granted, unexpired approval for this call (same run, same calling hop's
//!    lease, same call hash) is taken from the lease store and marked consumed
//!    (`LeaseStore::take_approval`); Cedar then sees `context.approval.present` and `by`.
//!    When the call presents a signed approval token ([`CallContext::approval_token`]), that
//!    token decides instead: its signature, `typ` and `exp` must verify under the issuer key,
//!    its `chain_id`, `lease`, `ch` and `cnf.jkt` must be the call's run, the calling hop's
//!    lease, the call hash and the hop's key binding, and the approval it names (`jti`) is
//!    taken by id (`LeaseStore::take_approval_by_id`). A token that fails any of this, or
//!    names an approval that is consumed, declined, expired or bound to a dead lease, denies
//!    the call with `approval_invalid` before the policy runs.
//! 4. **Policy.** `PolicyEngine::authorize_labelled`: the capability stage (including the
//!    limit check: a call that would take any matching counter past its `max` is denied with
//!    `budget_exhausted`, before Cedar), then Cedar, with the run's labels as
//!    `context.session`, the budget figures as `context.budget` and the run usage as
//!    `context.usage`. A deny through
//!    `@obligation("approval")` forbids only is `approval_required`.
//! 5. **Charge.** For an allowed call that matched limits, every counter is re-checked and
//!    charged in one store transaction (`LeaseStore::charge`), so concurrent calls cannot
//!    overspend: if one spent first, the decision becomes `budget_exhausted`; if the store
//!    fails, `budget_error`. The run-usage counters of a destructive call are charged in the
//!    same transaction; usage never refuses, and a failed charge of usage alone leaves the
//!    decision as it is (with a diagnostic). Denied calls are never charged. From the budget
//!    read in step 2 to this charge, a call that matches a limited hop or keeps run usage
//!    holds its run's lock (`Pipeline::run_guard`), so a policy over `context.usage` or
//!    `context.budget`, which the charge does not re-check, sees what every earlier call of
//!    the run charged (SR-55).
//! 6. **Audit.** A [`DecisionRecord`] is appended to the hash-chained log, and its id is the
//!    decision id returned to the caller. If the append fails the call is denied with
//!    `audit_error`: an action that cannot be recorded does not happen. An approval taken in
//!    step 3 is given back when the call is not allowed or its record cannot be written, so
//!    it is spent exactly when an allowed decision that names it is in the log. A charge made
//!    in step 5 is refunded the same way when the append fails (`LeaseStore::refund`).
//! 7. **Pending approval.** For `approval_required`, a pending approval is stored (or the
//!    pending one for the same call reused) and an `approval_request` record appended; the
//!    caller gets its id and expiry ([`PipelineDecision::approval`]).
//!
//! After an allowed mediated call returns, [`Pipeline::record_result`] appends a
//! `tool_result` record and, for an untrusted result, labels the run and adds the result's
//! fingerprints (taken by [`ServerAuthorizer`] before the result is relayed) to the run's span
//! index; if any of these fails, the proxy withholds the result (`label_error`).
//!
//! The chain is assumed to be verified already (token signature, structure, expiry).
//!
//! [`Authorizer`]: attenuo_proxy::Authorizer
//! [`PolicyEngine::tracks_usage`]: attenuo_policy::PolicyEngine::tracks_usage
//! [`PolicyEngine::reads_arg_taint`]: attenuo_policy::PolicyEngine::reads_arg_taint
//! [`CallContext::approval_token`]: attenuo_proxy::CallContext::approval_token
//! [`DecisionRecord`]: attenuo_core::DecisionRecord

mod authorizer;
mod budgets;
mod labels;
mod pipeline;
mod usage;

pub use authorizer::{ServerAuthorizer, VERIFIED_TOKENS_CAPACITY, VERIFIED_TOKEN_MAX_BYTES};
pub use budgets::{
    budget_json, BudgetView, CounterSource, LimitHit, StatedBudget, StatedLimit, MAX_STATED_LIMITS,
};
pub use labels::{untrusted_args_json, ArgTaint, RunLabels, MAX_UNTRUSTED_ARG_ENTRIES};
pub use pipeline::{
    Pipeline, PipelineDecision, REASON_AUDIT_ERROR, REASON_LABEL_ERROR, REASON_LEASE_ERROR,
    REASON_LEASE_EXPIRED, REASON_LEASE_REVOKED, REASON_LEASE_UNKNOWN,
};
pub use usage::{result_digest, usage_json, UNREADABLE_USAGE};

#[cfg(test)]
mod arg_taint_tests;
/// Run limits in the pipeline (ADR-0010). The multi-hop, concurrent and HTTP-level cases are
/// in `tests/run_limits.rs`; these use the pipeline directly, with a store or a log that can
/// be made to fail.
#[cfg(test)]
mod budget_tests;
#[cfg(test)]
mod run_lock_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod usage_tracking_tests;
