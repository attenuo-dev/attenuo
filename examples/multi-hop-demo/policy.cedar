// Policy for the multi-hop delegation demo.
//
// The tokens do most of the narrowing: each hop's capabilities, argument constraints and run
// limits are checked before Cedar, against every hop of the chain. This file adds the rules
// that hold whoever holds the token. Cedar denies by default, and `context.input.*` is optional
// in the schema, so every read is guarded with `has`.

// Reading files and issues is fine anywhere in the acme organisation. The tokens decide which
// acme repositories a given agent may read.
@id("read_in_acme")
permit(
  principal,
  action in [Action::"github/get_file_contents", Action::"github/list_issues"],
  resource
)
when { context.input has repo && context.input.repo like "acme/*" };

// Opening issues in acme. The planner's token has create_issue; the coder's does not, so for
// the coder this permit never comes into play (the capability stage refuses first).
@id("open_issues_in_acme")
permit(principal, action == Action::"github/create_issue", resource)
when { context.input has repo && context.input.repo like "acme/*" };

// Agents write to their own branches, never straight to the default branch. A write needs a
// branch named agent/..., and the forbid below refuses a write to main or master, or one that
// names no branch, by name, so the audit record says which rule decided.
@id("write_to_agent_branches")
permit(principal, action == Action::"github/create_or_update_file", resource)
when {
  context.input has repo && context.input.repo like "acme/*" &&
  context.input has branch && context.input.branch like "agent/*"
};

@id("no_writes_to_default_branch")
forbid(principal, action == Action::"github/create_or_update_file", resource)
unless {
  context.input has branch && context.input.branch != "main" && context.input.branch != "master"
};

// The planner delegates to the coder and the coder's token says nobody may exchange it, so a
// third agent should never appear. If one does, nothing it calls is allowed.
@id("forbid_chains_past_the_coder")
forbid(principal, action, resource)
when { context.chain.depth > 2 };

// Tests for this file: policy_test.yaml, run with `attenuo policy test`.
