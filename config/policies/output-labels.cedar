// Output labelling examples (ADR-0009; section 3.6 of the output-labelling design note).
//
// Every upstream result the proxy relays is labelled untrusted unless the catalog marks the
// tool `output = "trusted"`, and a run that has read one is tainted:
//
//   context.session.tainted         the run has read untrusted output (or its taint state
//                                   could not be read)
//   context.session.tainted_by      "<server>/<tool>" of every source
//   resource.destructive            catalog `destructive`, default `!readonly`
//   context.args_contain_untrusted  always false until argument matching exists
//   context.approval.present        always false until approvals exist
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

// Mail whose arguments carry a span of untrusted output needs an approval. This only fires
// once argument matching is built; until then `args_contain_untrusted` is always false.
@id("confirm_untrusted_spans_in_mail")
@obligation("approval")
forbid (principal, action == Action::"workspace/send_email", resource)
when { context.args_contain_untrusted && !context.approval.present };

// The permit side of this example: everything the token's capabilities allow. The
// capability stage runs before Cedar, so this cannot widen a token. Replace it with your own
// permits.
@id("permit_what_the_token_allows")
permit (principal, action, resource);
