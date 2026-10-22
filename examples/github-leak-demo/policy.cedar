// Policy for the GitHub MCP leak demo.
//
// Cedar denies by default. This is the only permit: reading files, and only in alice's public
// repositories. The check runs on every call, after the delegation chain's own capabilities,
// so a prompt-injected "read my private repo" is refused here even though the token allows
// read_file. `context.input.repo` is optional in the schema, so guard with `has`.
@id("read_file_public_repos_only")
permit(principal, action == Action::"read_file", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };
