# ADR-0005: Policy decision point: capabilities first, then Cedar with a generated schema

- Status: accepted
- Date: 2026-11-05

## Context

`attenuo-policy` has to answer "may this agent, acting for this user, make this tool call?"
The delegation chain already carries capabilities that only narrow hop by hop. Operators also
want to express rules the chain cannot: argument-level conditions (`repo like "acme/*"`),
user attributes (MFA), chain depth limits, and read-only/sensitive tool classes. Cedar is the
natural language for that, and AWS Bedrock AgentCore already uses Cedar with a similar
principal/action/resource/context shape, so policies should port between the two.

Cedar has three properties that shape the design:

1. It validates policies only against a schema in which every action is declared and every
   record type is closed. Tool names and argument names are open-ended in our world.
2. It has no `null`, and it interprets `__entity`/`__extn` keys in JSON as escapes.
3. When a policy raises an evaluation error it is skipped, and a skipped `forbid` is a
   silent grant.

## Decision

- **Two stages, capabilities first.** `chain.effective_capabilities().permits(call)` runs
  before Cedar and cannot be bypassed by any policy. Reason code `capability_denied`.
- **Request shape** (documented in the crate root): `principal = Agent::"<id>"`,
  `action = Action::"<server>/<tool>"` (member of `Action::"invoke"`; amended 2026-10-23, see
  below), `resource =
  Tool::"<server>/<tool>"` in `Server::"<server>"`, context `{ input, originating_user,
  chain, session_id?, now_unix }`. Agents are `in` the `User` and `in` earlier agents.
- **Schema = fixed entity model + generated action model.** The base schema declares
  `User`, `Agent`, `Server`, `Tool`. The engine appends one action per tool name in the
  `ToolCatalog`, with `context.input` typed from the catalog's declared inputs (all
  optional), and a `UserAttributes` record from the builder. Policies are validated in
  strict mode at load and reload; errors are returned, never ignored.
- **Evaluation is schema-free.** The request is built without a schema, so tools or
  arguments not in the catalog still evaluate correctly; the catalog only improves
  validation and supplies `readonly`/`sensitive`.
- **Fail closed.** Any Cedar evaluation error, any reserved `__` argument key, and any
  request translation failure yields Deny with reason `policy_error`.
- **`null` is absence.** Null-valued members are dropped; `session_id` is omitted when the
  call has none. Policies test with `has`.
- **AuthZEN 1.0** types are provided so any PEP can call the engine as a PDP, with the full
  chain carried in `subject.properties.chain` so a request is self-contained.

## Consequences

- A policy that names `Action::"s/x"` validates only when the catalog has tool `x` on server `s`.
  This catches typos, which for `forbid` rules would otherwise be silent holes. Operators
  must feed the catalog (MCP `tools/list` is the natural source).
- The shipped `policies/default.cedar` requires a `create_issue` tool in the catalog.
- Policies that read undeclared `context.input` attributes validate with an "impossible
  policy" warning (exposed via `validation_warnings()`), not an error.
- Policy ids come from `@id("...")` annotations so audit records carry stable names.

## Alternatives considered

- **Permissive validation / no validation.** Rejected: typos in tool or attribute names
  would silently disable rules.
- **Hand-maintained full schema from the operator.** Rejected as the default: it duplicates
  the catalog and drifts. Still possible through `with_schema_str` for the entity part.
- **Namespacing actions per server (`Github::Action::"read_file"`).** Deferred at first: plain
  action names kept policies portable to AgentCore, and the server is on the resource and its
  parent. **Amended 2026-10-23 (SR-13):** a bare `Action::"read_file"` matched that tool on
  every upstream, so a permit written for one server covered a malicious second one. Action ids
  are now `Action::"<server>/<tool>"` (a plain string id, not a Cedar namespace, so the policy
  syntax is unchanged). The bare form remains behind the deprecated
  `[policy] legacy_bare_actions` switch, and `attenuo policy lint` flags it.
- **Trusting Cedar's decision when a policy errored.** Rejected: a skipped `forbid` is a
  grant.
