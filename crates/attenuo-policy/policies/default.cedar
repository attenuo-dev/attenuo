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
// mounted as `github`, and on no other server (SR-13). This file names it, so the catalog
// must register `create_issue` for server `github` for the set to validate. Give every policy
// an @id: that id is what shows up in audit records.

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
when { context.input has repo && context.input.repo like "acme/*" };

// Deep delegation chains are almost always a bug or an attack. Cap the depth regardless of
// what the hops themselves say.
@id("forbid_deep_chains")
forbid(principal, action, resource)
when { context.chain.depth > 3 };

// Sensitive tools require the originating user to have authenticated with MFA.
// A missing `mfa` attribute counts as "no MFA": the forbid applies unless it is present and true.
@id("forbid_sensitive_without_mfa")
forbid(principal, action, resource)
when {
    resource.sensitive &&
    !(context.originating_user.attributes has mfa && context.originating_user.attributes.mfa == true)
};
