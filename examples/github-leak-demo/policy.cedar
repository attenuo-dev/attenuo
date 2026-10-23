// Policy for the GitHub MCP leak demo.
//
// Cedar denies by default. This is the only permit: reading files, and only in alice's public
// repositories. The check runs on every call, after the delegation chain's own capabilities,
// so a prompt-injected "read my private repo" is refused here even though the token allows
// read_file. `context.input.repo` is optional in the schema, so guard with `has`. The action
// names its server, so this permit says nothing about a read_file on any other upstream.
@id("read_file_public_repos_only")
permit(principal, action == Action::"github/read_file", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };

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
