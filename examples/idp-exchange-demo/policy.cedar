// Policy for the IdP exchange demo.
//
// The tokens do the narrowing: the root grant, the planner's token and the coder's token are
// checked before Cedar, at every hop. This file only says what holds whoever holds the token.
// Cedar denies by default, and `context.input.*` is optional in the schema, so every read is
// guarded with `has`.

// Reading files and opening issues is fine anywhere in the acme organisation.
@id("acme_only")
permit(
  principal,
  action in [Action::"github/get_file_contents", Action::"github/create_issue"],
  resource
)
when { context.input has repo && context.input.repo like "acme/*" };
