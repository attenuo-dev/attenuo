// Policy for the GitHub MCP leak demo.
//
// Cedar denies by default. The first permit is for reading files, and only in alice's public
// repositories. The check runs on every call, after the delegation chain's own capabilities,
// so a prompt-injected "read my private repo" is refused here even though the token allows
// read_file. `context.input.repo` is optional in the schema, so guard with `has`. The action
// names its server, so this permit says nothing about a read_file on any other upstream.
@id("read_file_public_repos_only")
permit(principal, action == Action::"github/read_file", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };

// Opening an issue publishes text, which is how the real leak got the data out. A token that
// holds create_issue (alice's assistant has github:*; the coder never gets it) may open one in
// a public repo, but only after a person approves that exact call: the forbid below turns the
// permit into a request for approval (JSON-RPC -32008), and a granted approval lets the
// identical retry through once. Issues in any other repo get no permit at all.
@id("create_issue_public_repos")
permit(principal, action == Action::"github/create_issue", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };

@id("ask_before_create_issue")
@obligation("approval")
forbid(principal, action == Action::"github/create_issue", resource)
when { !context.approval.present };

// Sensitive tools (delete_repo in the catalog) need a user who authenticated with MFA.
// A missing `mfa` attribute counts as no MFA. No permit covers delete_repo, so even with MFA
// it stays denied; the forbid is the guard rail for the day someone adds a permit.
@id("forbid_sensitive_without_mfa")
forbid(principal, action, resource)
when {
    resource.sensitive &&
    !(context.originating_user.attributes has mfa && context.originating_user.attributes.mfa == true)
};

// Delegation chains deeper than three agents are almost always a bug or an attack.
@id("forbid_deep_chains")
forbid(principal, action, resource)
when { context.chain.depth > 3 };

// Tests for this file: policy_test.yaml, run with `attenuo policy test`.
