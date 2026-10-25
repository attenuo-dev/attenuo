// attenuo starter policy set.
//
// Cedar denies by default: a call is allowed only if at least one `permit` matches and no
// `forbid` matches. Everything below is evaluated after the capability stage, so a policy
// can only narrow what the delegation chain already granted; it can never widen it.
//
// Request shape (see the attenuo-policy crate docs for the full table):
//   principal  Agent::"<agent id>"        in User::"<subject>", in earlier Agents of the chain
//   action     Action::"<server>/<tool>"  in Action::"invoke"
//   resource   Tool::"<server>/<tool>"    in Server::"<server>", attrs readonly/sensitive
//   context    { input, originating_user, chain, session_id?, now_unix }
//
// Tool attributes (`resource.readonly`, `resource.sensitive`) come from the ToolCatalog the
// engine was built with. Tools that are not registered are neither readonly nor sensitive.
//
// Actions name their server: Action::"github/create_issue" is create_issue on the server
// mounted as `github`, and on no other server (SR-13). This file names `create_issue` and
// `delete_repo`, so the catalog must register both for server `github` for the set to
// validate. Give every policy an @id: that id is what shows up in audit records.
//
// `like` has one wildcard, `*`, and it matches any text, `/` and nothing included:
// `"acme/*"` alone also matches "acme/", "acme/a/b" and "acme/../x". The repository rules
// below therefore pin the shape "acme/<name>": one `/`, and a name that is not empty, "."
// or "..". Cedar has no character classes; which characters a name may hold is left to the
// upstream (or to a `one_of` constraint in the token's capability), except for the ones URL
// parsers act on (SR-70): a backslash, which WHATWG parsers (Node's fetch, the `url` crate)
// read as `/` ("acme/..\evil\x" becomes /evil/x), `%` (`%2e%2e` is `..`, and an upstream
// may decode `%2F`), `?` and `#`, and the tab, line feed and carriage return those parsers
// drop. GitHub names hold none of them.

// Read-only tools are fine for any agent on behalf of any user.
// Cedar cannot glob action names (`Action::"read_*"` is not a thing), so tag tools as
// read-only in the catalog and test the tag here.
@id("permit_readonly_tools")
permit(principal, action, resource)
when { resource.readonly };

// Issues may be created on the github server, but only in the acme organisation's
// repositories.
// `input.repo` is optional in the schema, so guard with `has`: a missing argument must
// never satisfy an argument-level rule.
@id("permit_create_issue_in_acme")
permit(principal, action == Action::"github/create_issue", resource)
when {
    context.input has repo &&
    context.input.repo like "acme/*" &&
    !(context.input.repo like "acme/*/*") &&
    !(context.input.repo like "*\\*") &&
    !(context.input.repo like "*%*") &&
    !(context.input.repo like "*?*") &&
    !(context.input.repo like "*#*") &&
    !(context.input.repo like "*\t*") &&
    !(context.input.repo like "*\n*") &&
    !(context.input.repo like "*\r*") &&
    context.input.repo != "acme/" &&
    context.input.repo != "acme/." &&
    context.input.repo != "acme/.."
};

// Throwaway sandbox repositories, "acme/sandbox-<name>", may be deleted. delete_repo is
// sensitive in the catalog, so forbid_sensitive_without_mfa below still requires the user to
// have authenticated with MFA, and the token must grant github:delete_repo: this permit
// cannot widen what the chain delegated. No other repository may be deleted.
@id("permit_delete_acme_sandbox_repo")
permit(principal, action == Action::"github/delete_repo", resource)
when {
    context.input has repo &&
    context.input.repo like "acme/sandbox-*" &&
    !(context.input.repo like "acme/*/*") &&
    !(context.input.repo like "*\\*") &&
    !(context.input.repo like "*%*") &&
    !(context.input.repo like "*?*") &&
    !(context.input.repo like "*#*") &&
    !(context.input.repo like "*\t*") &&
    !(context.input.repo like "*\n*") &&
    !(context.input.repo like "*\r*") &&
    context.input.repo != "acme/sandbox-"
};

// Deep delegation chains are almost always a bug or an attack. Cap the depth regardless of
// what the hops themselves say.
@id("forbid_deep_chains")
forbid(principal, action, resource)
when { context.chain.depth > 3 };

// Sensitive tools require the originating user to have authenticated with MFA.
// A missing `mfa` attribute counts as "no MFA": the forbid applies unless it is present and true.
// A forbid always wins, so this also holds for any permit an operator adds later.
@id("forbid_sensitive_without_mfa")
forbid(principal, action, resource)
when {
    resource.sensitive &&
    !(context.originating_user.attributes has mfa && context.originating_user.attributes.mfa == true)
};
