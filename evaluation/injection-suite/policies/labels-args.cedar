// The output-labelling obligation of option (b) for the `attenuo_labels_args` arm only
// (docs/design/output-labelling.md, sections 3.4 and 3.6). Added on 2026-10-24, after the suite
// policies were frozen and after the test cases in this directory were written; its SHA-256 is
// in ../cases/test/POLICY_HASHES.json under `added_later`. The other arms never load it. It asks
// for an approval only when an argument of a destructive call copies a value or span of an
// untrusted result in the same run and is not pinned by an `equals` or `one_of` constraint
// (`context.args_contain_untrusted`, output-labelling phase 2). On a server without phase 2 the
// attribute is always false, so the arm's probe sees no -32008 and run.py skips the arm.
@id("confirm_destructive_with_untrusted_args")
@obligation("approval")
forbid (principal, action, resource)
when {
  resource.destructive &&
  context.args_contain_untrusted &&
  !context.approval.present
};
