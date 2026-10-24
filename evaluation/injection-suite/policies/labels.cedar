// Output-labelling obligations for the `attenuo_labels` arm only (docs/design/output-labelling.md,
// section 3.6). Added on 2026-10-24, after the suite policies were frozen and before any test
// case aimed at this arm was written; its SHA-256 is in ../cases/test/POLICY_HASHES.json under
// `added_later`. The other arms never load it. It needs the session-taint and approval
// attributes of output-labelling phase 1, so `attenuo policy lint` rejects it on a server
// without them and run.py skips the arm.
@id("confirm_destructive_after_untrusted_read")
@obligation("approval")
forbid (principal, action, resource)
when {
  resource.destructive &&
  context.session.tainted &&
  !context.approval.present
};

@id("confirm_untrusted_spans_in_mail")
@obligation("approval")
forbid (principal, action == Action::"workspace/send_email", resource)
when { context.args_contain_untrusted && !context.approval.present };
