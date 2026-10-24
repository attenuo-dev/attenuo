// The soft run-usage rule for the `attenuo_usage_soft` arm only (docs/design/run-limits.md,
// sections 3.5 and 3.7, phase 2). Added on 2026-10-24, after the suite policies were frozen and
// after the test cases in this directory were written and read; its SHA-256 is in
// ../cases/test/POLICY_HASHES.json under `added_later`. The other arms never load it. It asks
// for an approval on the second and every later call of the same destructive tool in a run
// (`context.usage.calls`, which counts allowed calls of this server and tool by every hop of the
// run, an approved retry included). On a server without run usage `attenuo policy lint` rejects
// the attribute, and run.py skips the arm.
@id("ask_on_repeat_destructive_call")
@obligation("approval")
forbid (principal, action, resource)
when {
  resource.destructive &&
  context.usage.calls >= 1 &&
  !context.approval.present
};
