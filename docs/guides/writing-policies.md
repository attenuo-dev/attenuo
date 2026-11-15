# Writing and testing policies

attenuo decides every tool call in two stages. First the **capability stage**: the call must be covered by the capabilities of the agent making it (the last hop of the delegation chain). Then the **Cedar stage**: your policies get a vote. Cedar denies by default, so a call is allowed only if at least one `permit` matches and no `forbid` does.

Policies can only narrow what the chain already grants. A `permit` never adds a capability the token lacks. That is the point: the token says what the user delegated, the policy says what the operator will tolerate on top of that.

This guide covers the request shape, the tool catalog, common patterns, and how to test policies offline and in CI. The reference for the request is the [`attenuo-policy` crate docs](https://github.com/attenuo-dev/attenuo/blob/main/crates/attenuo-policy/src/lib.rs); the design is in [RFC-0001](../spec/rfc-0001-attenuo.md).

## The request

Every call becomes one Cedar request.

| Part | Value |
| --- | --- |
| `principal` | `Agent::"<id>"`, the last hop of the chain |
| `action` | `Action::"<server>/<tool>"`, a member of `Action::"invoke"` |
| `resource` | `Tool::"<server>/<tool>"`, which is `in Server::"<server>"` |
| `context.input` | the call's arguments, verbatim |
| `context.originating_user` | `subject`, `issuer`, `authenticated_at_unix`, `attributes` (`mfa`, `roles`, `tenant`, `email`, plus whatever `[policy] user_attributes` declares) |
| `context.chain` | `depth`, `agents` (root first), `root_agent`, `leases` |
| `context.session_id` | present only if the call carries one |
| `context.now_unix` | evaluation time, unix seconds |
| `context.session` | output labels of the delegation run: `tainted` (bool) and `tainted_by` (set of `"<server>/<tool>"`); see [Asking for approval after untrusted output](#asking-for-approval-after-untrusted-output) |
| `context.args_contain_untrusted`, `context.untrusted_args` | on a tainted run, for every call if some loaded policy reads either attribute and otherwise for a destructive call: whether an argument copies a value or span of an untrusted result of the run, and the names of those arguments (an argument pinned by an `equals` or `one_of` constraint never counts); `false` and an empty set otherwise. See [Asking only when an argument copies untrusted output](#asking-only-when-an-argument-copies-untrusted-output) |
| `context.untrusted_outbound` | `true` when one of the arguments in `context.untrusted_args` is one the catalog marks `outbound`; see [Outbound arguments](#outbound-arguments) |
| `context.approval` | `present` (bool) and `by` (`"user"`, `"operator"`, or `""` without an approval): whether this call carries a granted approval for its exact hash; see [Asking for approval after untrusted output](#asking-for-approval-after-untrusted-output) |
| `context.budget` | what the token's run limits matching this call have left: `limited` (bool), `calls_remaining`, `amount_remaining` (Long; the largest Long when no such limit applies) and `destination_new` (bool); see [Run limits](#run-limits) |
| `context.usage` | the delegation run's usage of this tool so far, for a destructive tool or one with an `outbound` input: `calls` (allowed calls by any hop), `amount` (the catalog's `amount` input summed over them) and `destination_seen` (bool); zero and false for other tools. `user_window.hour` and `user_window.day` (each `{calls, amount}`) are the same tool's usage by every run of the originating user in the current UTC hour and day. See [Limits over run usage](#limits-over-run-usage) and [Limits per user across runs](#limits-per-user-across-runs) |

The action names the server as well as the tool. `action == Action::"github/read_file"` matches `read_file` on the upstream mounted as `github` and nothing else: a second upstream that also has a `read_file` tool (a malicious one, say) is not covered by that permit. To write a rule for every tool of one server, use the resource: `resource in Server::"github"`. To write one for every tool everywhere, leave `action` unconstrained or use `action in Action::"invoke"`.

The principal is an `Agent`, and an agent is `in` the originating `User` and in every earlier agent of the chain. So `principal in User::"alice"` and `principal in Agent::"planner"` both work, the latter matching `planner` and anything it delegated to.

`resource` carries `readonly`, `sensitive`, `destructive` and `outbound`, taken from the catalog (below). `principal.chain_depth` is the 1-based position of the agent in the chain.

Four things trip people up:

- **Null and missing values.** Cedar has no `null`. Null arguments are dropped, and optional attributes must be guarded: `context.input has repo && context.input.repo like "acme/*"`. A policy that reads a missing attribute raises an evaluation error, and attenuo then denies the call with `policy_error` rather than trusting a half-evaluated set.
- **Action names are exact.** `Action::"github/read_*"` is not valid. To say "every read-only tool", tag tools in the catalog and test `resource.readonly`.
- **Actions name their server.** `Action::"read_file"` on its own (a *bare* action, the form before 2026-10-23) is rejected: it fails validation, and `attenuo policy lint` reports it as `error[actions]` with the line to fix. See [Migrating from bare actions](#migrating-from-bare-actions).
- **Give every policy an `@id`.** That id is what appears in audit records and in test reports. Without it Cedar names policies `policy0`, `policy1`, ... by position, which changes when you reorder the file.

## The catalog

The catalog declares the tools your upstream servers expose and what is true of them. It lives in the server config:

```toml
[policy.catalog.github.read_file]
readonly = true
inputs = { repo = "string", path = "string" }

[policy.catalog.github.create_issue]
inputs = { repo = "string", title = "string" }

[policy.catalog.github.delete_repo]
sensitive = true
inputs = { repo = "string" }

[policy.catalog.bank.get_balance]
readonly = true
output = "trusted"
```

It does three jobs:

1. **Tool attributes** (`readonly`, `sensitive`, `destructive`) become `resource.readonly`, `resource.sensitive` and `resource.destructive`. `destructive` defaults to the opposite of `readonly`. `outbound` names the arguments whose value is delivered to a party it names, and `resource.outbound` is true when it names any (see [Outbound arguments](#outbound-arguments)). `output` (`untrusted` by default, or `trusted`) says whether the tool's results taint the run; it is not a Cedar attribute. A tool that is not in the catalog is denied before Cedar runs, with reason `tool_not_in_catalog`, unless `[policy] unknown_tools` is `sensitive` (evaluated as `sensitive = true`) or `allow` (evaluated as neither, so a `forbid` keyed on `sensitive` silently skips it). Register every tool the server exposes (MCP `tools/list` is the natural source).
2. **Schema generation.** Each catalog entry becomes a declared action, `Action::"<server>/<tool>"`, and each `inputs` entry a typed, optional attribute of `context.input`. Policies are validated against this schema at load time, so a typo in an argument name or a comparison of a string to a number fails the load instead of misbehaving on a call. A policy that names `Action::"github/x"` validates only if the catalog has a tool `x` under `github`. Argument types are `string`, `long`, `bool`, `decimal`, or `{ set = "string" }`. A `decimal` argument is Cedar's `decimal` type, for amounts with a fraction: `inputs = { amount = "decimal" }` and `context.input.amount.lessThan(decimal("100.0"))`. Cedar has no `<` on decimals, so use `lessThan`, `lessThanOrEqual`, `greaterThan` and `greaterThanOrEqual`.
3. **Argument types on every call.** Evaluation itself is schema-free, so the types are also checked on each call, before Cedar: a present, non-null argument of another type than declared (a number where `repo` is a `string`, a single string where a set is declared, `2.5` for a `long`) is denied with reason `input_type_mismatch`, whether or not a policy reads it. Integral numbers, `5.0` included, count as `long`, as Cedar sees them. For a `decimal`, any number with at most 4 fractional digits counts, whole or not (`100` is `decimal("100.0")`); `12.34567`, a number beyond Cedar's range and a numeric string are refused. Nothing is coerced or rounded, except by the JSON parse itself: a number with more digits than a double holds (more than 15 significant digits) is the nearest double, which is also what the upstream is sent. Arguments the catalog declares no type for are not checked and reach Cedar as sent, and so do all arguments of a tool evaluated under `unknown_tools = "sensitive"` or `"allow"`. Before this check a mistyped argument that a policy read ended as `policy_error`, and one that no policy read went to the upstream.

Write argument names exactly as the tool declares them, in the catalog, in capability constraints and limits, and in policies. Every check reads an argument by its exact name, while an MCP server written in Go with `encoding/json` matches names without regard to case: it reads `Path` as its `path`. So a call whose argument name differs only in case from a name the decision reads for that tool (in its catalog entry, in a constraint or limit of a capability that covers it, or under `context.input` or in a `context.untrusted_args` test of any loaded policy) is denied before the capability stage with reason `argument_case_mismatch`; the exact name passes. A name nothing reads is not checked, since attenuo has no schema of the tool, so declare in `inputs` the arguments your policies and limits are about.

Server names (the `[[upstreams]]` names and the catalog's server keys) and tool names may not contain `/`, so `"<server>/<tool>"` always splits one way. The one exception is on the tool side: the proxy authorizes MCP methods other than `tools/call` under their method name (`resources/read`, `prompts/get`), so those catalog entries are `[policy.catalog.github."resources/read"]` and their action is `Action::"github/resources/read"`. A `tools/call` can never carry a `/` in its tool name, so a tool cannot pose as one of these methods. The server refuses to start with a catalog entry that breaks these rules.

### User attributes

The schema declares four optional attributes of `context.originating_user.attributes`: `mfa` (bool), `roles` (set of strings), `tenant` (string) and `email` (string). A policy that tests any other attribute, `groups` for example, is reported as impossible when it loads (a validation warning in the server log and in `attenuo policy lint`), because the validator has no such attribute to type-check. Declare the extra attributes in the config:

```toml
[policy]
user_attributes = { groups = "set<string>", department = "string" }
```

Types are `string`, `long`, `bool` and `set<T>` (for example `set<string>`); `decimal` is for catalog inputs only. The declarations are merged over the built-in four, so you can also re-type one of them. Then guard every use, since attributes are optional (this example also needs a `[policy.catalog.github.create_deployment]` entry):

```cedar
@id("platform_engineers_may_deploy")
permit(principal, action == Action::"github/create_deployment", resource)
when {
    context.originating_user.attributes has groups &&
    context.originating_user.attributes.groups.contains("platform") &&
    context.originating_user.attributes has department &&
    context.originating_user.attributes.department == "eng"
};
```

Declaring an attribute does not make it appear. The value comes from the verified IdP token: add the claim to `attribute_claims` in the `[[idps]]` entry (`groups` is there by default). If a token carries a value of a different type than declared, for example a string where you declared `set<string>`, attenuo denies the call before any policy runs, with reason `attribute_type_mismatch` (audited, and shown by `attenuo policy test`). Nothing is coerced. This matters because Cedar's `!=` across types is `true` without an error: `attributes.status != "suspended"` would otherwise permit `["suspended"]`. Still guard each use with `has` and prefer `.contains` and `like` over `!=` for exclusions. `attenuo policy lint --config server.toml` and `attenuo policy test` (when the test file's `catalog:` points at the server config) read `user_attributes` too, so tests and lint see the same schema as the server.

### A custom base schema

The schema has two parts: a base that declares the entity types (`User`, `Agent`, `Server`, `Tool` and their attributes; `attenuo_policy::DEFAULT_SCHEMA`, printed at the top of `attenuo policy lint --schema`), and the actions and context types generated from the catalog. You can replace the base with your own Cedar schema file, to declare an extra entity type your policies name or an optional attribute:

```toml
[policy]
schema_path = "config/base.cedarschema"
```

`attenuo policy test --schema-file F` and `attenuo policy lint --schema-file F` take the same file (and both read `schema_path` from the config they are given). The file must keep what attenuo builds every request from: the four entity types with every attribute of the default, each required and of the same type, `Agent in [User, Agent]` and `Tool in [Server]`. Start from the default and add to it. A file that drops or changes any of that is refused, by the server at start and by the CLI before any case runs, with the missing part named, for example `custom base schema: it does not declare the entity type(s) Server`. Leave actions out: they are generated, and a declared one with a generated name (`invoke`, `<server>/<tool>`) fails to parse.

The request data does not change: attenuo fills only the default attributes. Declare anything you add as optional (`owner?: String`) and guard it with `has`; a required attribute that is never filled makes every policy that reads it fail at evaluation, and the call is denied with `policy_error`.

## Patterns

All of these assume the catalog above. The banking examples use the `send_money` entry shown with them, and `merge_only_release_bot` below needs a `github.merge_pull_request` entry; without them `attenuo policy lint --config` reports the action as unrecognized.

### Read-only agents

Permit anything tagged read-only, for any agent and user. Everything else stays denied by default.

```cedar
@id("permit_readonly_tools")
permit(principal, action, resource)
when { resource.readonly };
```

To limit this to one agent or one server, add it to the head: `permit(principal in Agent::"researcher", action, resource in Server::"github") when { resource.readonly };`.

### Argument constraints

Constrain what a permitted tool may touch. Always guard with `has`:

```cedar
@id("read_file_public_repos_only")
permit(principal, action == Action::"github/read_file", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };
```

This is the rule that stops the prompt-injected "read my private repo" in the [GitHub leak demo](https://github.com/attenuo-dev/attenuo/blob/main/examples/github-leak-demo/README.md), even though the token allows `read_file`. Prefer an allow-list (`permit ... when repo like ...`) to a deny-list (`forbid ... when repo like "*private*"`): the deny-list fails open for names you did not think of. For constraints that must travel with the token and survive delegation, put them in the capability itself (`ArgConstraint`) rather than in policy.

### Bounding a number: `range`, Cedar or `sum`

Three tools bound an amount, and they answer different questions:

| You want | Use | Where it lives |
|---|---|---|
| this token, and everything delegated from it, never pays more than 2000 in one call | a `range` constraint, `{"amount": {"op": "range", "value": {"min": 1, "max": 2000}}}` | the signed token; a child can only narrow it |
| no agent of this deployment pays more than 2000 in one call, whatever its token says | Cedar: `forbid ... when { context.input has amount && context.input.amount > 2000 }` | the policy file; changes take effect on reload, for every token |
| a run pays at most 5000 in all, however it splits the payments | a `sum` limit in the token, or `context.usage.amount` in policy ([below](#run-limits)) | counters on the server, per run |

A `range` is the right tool when the bound is part of what the user or planner delegated: it is chosen per token, it is checked before Cedar, so no policy or approval passes a value outside it, and the exchange refuses a child whose range is wider (`exchange_widening`). The Cedar rule is a deployment ceiling that no one has to put in a token, and it can depend on anything in the request, such as the user's attributes. A `range` and a `sum` combine: `0..2000` per call with `sum <= 5000` stops one large payment and many small ones. Neither replaces the other: a `range` alone lets a run make any number of in-range payments, and a `sum` alone lets the first payment take the whole budget.

A value outside the range, a fraction, or a numeric string is denied with `capability_denied`; the diagnostic names the argument and the bound (``argument `amount` is above the maximum 2000``), never the value. Declare the argument as `long` in the catalog too, so Cedar rules that read it see the same type.

### Patterns and `like`

`like` is the only pattern match Cedar has. Its one wildcard, `*`, matches any run of characters, including none and including `/`. There is no single-character wildcard, no character class and no regular expression; `\*` matches a literal star. So `context.input.repo like "acme/*"` holds for `acme/api`, but also for:

- `acme/`, an empty name, because `*` may match nothing;
- `acme/a/b`, because `*` crosses `/`;
- `acme/../x` and `acme/..`, which an upstream that builds a URL or path from the value may resolve outside `acme`.

To pin a shape, add the cases the wildcard should not cover. The starter policy's issue rule allows exactly one `/`, none of the characters URL parsers act on, and a name that is not empty, `.` or `..`:

```cedar
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
```

`!(... like "acme/*/*")` is what rules out a second `/`. It is not enough on its own when the tool puts the value into a URL: WHATWG URL parsers (Node's `fetch` and `URL`, Rust's `url` crate) read a backslash as `/`, so `acme/..\evil\api` in `https://api.github.com/repos/{repo}/issues` becomes `/repos/evil/api/issues`; they read `%2e%2e` as `..` and drop tabs and line breaks, and some upstreams decode `%2F`. The other guards refuse those characters, and `?` and `#`, which would end the path (SR-70). With them, no `..` path leaves the owner. A longer fixed prefix needs the same treatment: `like "acme/sandbox-*"` matches `acme/sandbox-x/../api`, so the starter's sandbox permit also carries `!(... like "acme/*/*")` and `!= "acme/sandbox-"`. Patterns are case-sensitive (`ACME/api` does not match), which is what you want when the upstream is too, and a trap when it is not. Which characters a name may contain cannot be said with `like`. Leave that to the upstream, or list the allowed values (`["acme/api", "acme/web"].contains(context.input.repo)`, or a `one_of` constraint in the token).

A pattern in policy and a `prefix` constraint in the token's capability do different jobs:

- A capability constraint (`{ op: prefix, value: "acme/" }`, `equals`, `one_of`) is checked before Cedar, travels with the token, and can only be narrowed by each delegation (`acme/` to `acme/api`). Use it for "this agent, for this task, may only touch these repositories": it is per token, and a policy cannot widen it. `prefix` is a plain string prefix with the same blind spots as `*` (it accepts `acme/` and `acme/a/../b`), so for a whole repository name prefer `equals` or `one_of`. For a file path use `path_prefix`, which compares by `/` segment and refuses `..`, `//`, `\` and percent-encoded separators ([`prefix` or `path_prefix`](../concepts/capabilities-and-attenuation.md#prefixes-of-strings-and-of-paths)).
- A policy pattern applies to every token the server sees and can say what a prefix cannot (no second `/`, not empty). Use it for the organisation-wide rule, the shape every value must have whatever a token says.

The two compose: the token narrows to `prefix: acme/`, the policy rejects the malformed names inside it. The "capability stage" cases in [`config/policies/default_test.yaml`](https://github.com/attenuo-dev/attenuo/blob/main/config/policies/default_test.yaml) show both together.

### MFA for sensitive tools

```cedar
@id("forbid_sensitive_without_mfa")
forbid(principal, action, resource)
when {
    resource.sensitive &&
    !(context.originating_user.attributes has mfa &&
      context.originating_user.attributes.mfa == true)
};
```

A missing `mfa` attribute counts as no MFA. A `forbid` always wins over a `permit`, so this holds whatever permits are added later. The `mfa` attribute is derived from the IdP's `amr` claim when hop 0 is minted; see the top-level README.

A forbid like this only ever removes access; something has to permit the sensitive tool for MFA to make a difference. In the starter policy that is `permit_delete_acme_sandbox_repo`: `delete_repo` (sensitive in the example catalog) on `acme/sandbox-<name>` only. With MFA the delete of `acme/sandbox-demo` is allowed by that permit; without MFA the same call is denied by `forbid_sensitive_without_mfa`; any other repository is denied by default either way. Drop the permit if your agents should never delete a repository, and the forbid stays as a guard rail for whatever sensitive permit you write next.

### Asking for approval after untrusted output

Every result an upstream returns is recorded, and unless the catalog marks the tool `output = "trusted"`, it taints the delegation run: every later call made with any token of that run sees `context.session.tainted == true` and the source in `context.session.tainted_by`. A run whose taint state cannot be read counts as tainted. A denied call reads nothing, so it taints nothing.

```cedar
@id("confirm_destructive_after_untrusted_read")
@obligation("approval")
forbid(principal, action, resource)
when {
    resource.destructive &&
    context.session.tainted &&
    !context.approval.present
};
```

`@obligation("approval")` turns the forbid into a request for approval. When every forbid that applied carries it, and some permit would allow the call without them, the reason is `approval_required` instead of `policy_deny`, and the proxy answers JSON-RPC `-32008` with the call's `call_hash`. A forbid without the annotation still refuses outright, so an approval cannot unlock what another rule forbids. `approval` is the only value; any other value, or the annotation on a `permit`, fails the load and `attenuo policy lint`. The `-32008` error also carries an `approval_id` and its `expires_at`.

The run's originating user grants the approval with their own ID token (`POST /approvals/{id}`), or an operator does (`attenuo approval grant`, or the console). The agent then retries the identical call, same server, tool and arguments, with a token of the same hop. That one retry sees `context.approval.present == true` and `context.approval.by` set to `"user"` or `"operator"`, so the forbid above no longer applies; a second retry asks again. An approval expires after `[approvals] ttl_seconds` (default 120) or with the hop's lease, whichever comes first. One run can have at most 32 approvals waiting at once: past that, a gated call with new arguments still gets `-32008`, but with no `approval_id`, and the AuthZEN diagnostics say `too many pending approvals for this run`, until one of the waiting approvals is decided or expires, or the hop that asked for it is revoked (a revoked hop's approvals no longer count). Repeating a call that already waits returns its approval as before. To accept only the user's own approval, test `context.approval.by == "user"` instead of `present`.

Set `[approvals] client_id` to a client the agent does not control, such as your approval page's own OAuth client. Unset, an ID token for the root agent's own client approves, which an agent that can get ID tokens for its user could do by itself. With an approval policy loaded and `client_id` unset, the server warns, and refuses to start off a loopback listener unless `[approvals] allow_unset_client_id = true` ([configuration](../reference/config.md#approvals), SR-64).

The grant also returns a signed approval token (`approval_token`, `typ: attenuo-approval+jwt`). An agent may send it with the retry in `params._meta["dev.attenuo/approval"]` (the SDK helpers do); the server then uses exactly the approval the token names, after checking that it is for this call, this hop, this run and, for a DPoP-bound agent, this key. Policy sees the same `context.approval`. A token that fails those checks, or whose approval was already used or declined, denies the call with `approval_invalid` whatever the policy says. Because the token is signed with the issuer key, an external PEP can check it offline; see [Approval tokens](../reference/http-api.md#approval-tokens).

[`config/policies/output-labels.cedar`](https://github.com/attenuo-dev/attenuo/blob/main/config/policies/output-labels.cedar) has this rule, the mail rule from the design and the rule of the next section, with tests in `output-labels_test.yaml` next to it.

### Asking only when an argument copies untrusted output

Session taint asks for every destructive call after any read. To ask only when the call carries something it read, test the arguments instead (ADR-0009 phase 2):

```cedar
@id("confirm_destructive_with_untrusted_args")
@obligation("approval")
forbid (principal, action, resource)
when {
    resource.destructive &&
    context.args_contain_untrusted &&
    !context.approval.present
};
```

The proxy fingerprints every untrusted result before relaying it: each JSON string leaf of 8 characters or more (text that parses as JSON is read as JSON), entities found by pattern at any length (URLs and their host, host names without a scheme such as `www.example.com`, e-mail addresses, IBAN-shaped strings, runs of 6 or more digits, file paths), and winnowed 24-character k-grams of long text, all after NFKC, lower-casing and collapsing whitespace. The run keeps keyed hashes of these, not the text, for up to 20,000 per run (oldest results dropped first) until its root lease is revoked. On a tainted run, each argument that no hop's `equals` or `one_of` constraint pins is fingerprinted the same way and looked up, nested values under the top-level argument name. That happens for every call, reads included, when some loaded policy reads `context.args_contain_untrusted` or `context.untrusted_args`, and for destructive calls only otherwise (so the decision record still names copied arguments). A rule without `resource.destructive`, such as `when { context.args_contain_untrusted && !context.approval.present }`, therefore also asks before a fetch of a URL copied from a result. A match sets `context.args_contain_untrusted` and adds the name to `context.untrusted_args`. If the index cannot be read, or the call's arguments carry more than 8,000 fingerprints in all (four arguments' worth at the per-value cap of 2,000; an ordinary call is far below it), every unpinned argument counts as matched, with kind `unreadable`.

A miss means no verbatim copy was found, not that the call is clean: a paraphrase or a decision the agent took from the text (which hotel to book) does not match. Keep the session-taint rule for tools where that matters, or test `context.untrusted_args.contains("body")` for one argument. The `-32008` answer, the pending approval and the decision record list the matches as `untrusted_args: [{arg, seq, kind}]`, where `seq` is the `tool_result` record matched and `kind` is `leaf`, `entity`, `kgram` or `unreadable`.

### Run limits

A capability in a token can carry `limits`: `calls` (at most this many calls), `sum: {arg, max}` (a total over one integer argument), `calls_per: {arg, max}` (at most `max` calls per value of one argument) and `distinct: {arg, max}` (at most `max` different values of one argument). `calls_per` and `distinct` take `"derive": "host"` to count the host of a URL argument. The server enforces them before Cedar, against every hop of the chain: a call over a limit is denied with `budget_exhausted`, and no policy or approval passes it. A policy cannot raise a limit, only explain or ask earlier, through `context.budget`:

```cedar
@id("confirm_last_call_of_a_budget")
@obligation("approval")
forbid (principal, action, resource)
when {
  context.budget.limited &&
  context.budget.calls_remaining <= 1 &&
  resource.destructive &&
  !context.approval.present
};
```

`calls_remaining` and `amount_remaining` are what is left before this call, the smallest over every matching limit. `destination_new` is false once the call's `calls_per` or `distinct` value has been used in an earlier allowed call. [`config/policies/run-limits.cedar`](https://github.com/attenuo-dev/attenuo/blob/main/config/policies/run-limits.cedar) has this rule and a repeat-payee rule, with tests in `run-limits_test.yaml`.

### Limits over run usage

A token limit needs someone to put a number in the token. For defaults across a deployment, write the limit in policy instead, over what the run has already done. For every tool the catalog marks destructive, the server keeps per run, across every hop: how many calls were allowed (`context.usage.calls`), the sum of one input over them (`context.usage.amount`) and whether one input's value was seen before (`context.usage.destination_seen`). The catalog names the two inputs:

```toml
[policy.catalog.banking.send_money]
inputs = { recipient = "string", amount = "long" }
amount = "amount"
destination = "recipient"
```

Usage refuses nothing by itself. A plain `forbid` makes a hard limit; with `@obligation("approval")` it is a soft one, which asks once the count is reached:

```cedar
// Soft: the second and every later payment of a run asks the user.
@id("ask_on_repeat_payment")
@obligation("approval")
forbid (principal, action == Action::"banking/send_money", resource)
when { context.usage.calls >= 1 && !context.approval.present };

// Hard: never more than 2000 in total in one run, approval or not.
@id("run_spend_cap_2000")
forbid (principal, action == Action::"banking/send_money", resource)
when {
  context.input has amount &&
  context.usage.amount + context.input.amount > 2000
};
```

The gated call gets `-32008` with `usage` in its data; once the user or an operator grants it, the identical retry is allowed and counted, so the next payment asks again. Only allowed calls are counted, and an approval never raises a token's own limits. The figures are what the run had before this call, so `calls >= 1` means "not the first". An `amount` value that is not a non-negative integer adds nothing; a list-valued `destination` counts each element. A rule over `destination_seen` asks only for a repeat to the same payee or recipient, however many others the run has paid. With `destination = "url#host"` in the catalog, `destination_seen` compares the hosts of a URL input, so a rule can ask when a run fetches from a site it has not used before. Usage ends with the run: revoking its root lease deletes it. [`config/policies/run-usage.cedar`](https://github.com/attenuo-dev/attenuo/blob/main/config/policies/run-usage.cedar) has these rules, a per-recipient mail rule and a per-site fetch rule, with tests in `run-usage_test.yaml`.

### Limits per user across runs

Run usage starts again with every run, so it cannot say "at most 5000 a day from this user's agents". A per-user window can. For the same destructive tools, the server can also keep usage per originating user (issuer and subject) across all their runs, in fixed UTC windows: `context.usage.user_window.hour` (the current clock hour) and `context.usage.user_window.day` (00:00 to 24:00 UTC), each with `calls` and `amount`, before this call:

```cedar
// Soft, the recommended form: past 5000 in a UTC day, the user's agents ask.
@id("ask_over_user_daily_spend_5000")
@obligation("approval")
forbid (principal, action == Action::"banking/send_money", resource)
when {
  context.input has amount &&
  context.usage.user_window.day.amount + context.input.amount > 5000 &&
  !context.approval.present
};
```

The server keeps a window only for the kinds a loaded policy reads (the rule above keeps `day`, not `hour`); a kind it does not keep reads as zero. Starting a new run, or revoking one, does not reset a window. An injected agent that spends the window blocks the user's other runs until the window ends, so prefer the asking form, and use a plain `forbid` for a regulated cap that no approver may pass. If the window cannot be read, the policy sees the largest `Long` for both figures, so a count rule refuses or asks and an amount rule overflows and denies. Windows are exact only on one server process: see [deploying](deploying.md). [`config/policies/user-windows.cedar`](https://github.com/attenuo-dev/attenuo/blob/main/config/policies/user-windows.cedar) has an asking daily cap and a hard hourly count, with tests in `user-windows_test.yaml`.

### Outbound arguments

A read can leak. `get_webpage(url)` sends its URL to whatever host the URL names, so `https://attacker.example/?q=<data>` hands `<data>` to the attacker's server log, and the tool is still read-only as far as the user's own data goes. The catalog marks such an argument *outbound*:

```toml
[policy.catalog.web.fetch]
readonly = true
inputs = { url = "string" }
outbound = "url#host"     # or a list: outbound = ["url", "callback#host"]
```

An outbound argument is a destination for run usage whatever `destructive` says, with `#host` counting hosts as `destination = "url#host"` does, so the new-site rule works on a fetch the catalog keeps read-only. `resource.outbound` is true for the tool, so one rule covers every such tool:

```cedar
// Once a run has fetched, a fetch from a host it has not fetched from asks.
@id("ask_on_a_new_outbound_site")
@obligation("approval")
forbid (principal, action, resource)
when {
  resource.outbound &&
  context.usage.calls >= 1 &&
  !context.usage.destination_seen &&
  !context.approval.present
};
```

On a tainted run, an outbound argument that copies a value or span of an untrusted result also sets `context.untrusted_outbound`, so a rule can ask on outbound matches without naming arguments:

```cedar
@id("ask_on_untrusted_outbound")
@obligation("approval")
forbid (principal, action, resource)
when { context.untrusted_outbound == true && !context.approval.present };
```

A matched search phrase or other argument that is not outbound leaves it `false`. When the span index cannot be read, or the call carries more than 8,000 fingerprints, every unpinned argument with a fingerprint counts as matched (`unreadable`), so an outbound one sets `context.untrusted_outbound` too. Both rules run under the usual approval flow (`-32008`, then the approved retry). The first rule leaves a run's first fetch free and depends on order: if the attacker's host is the first one fetched, it is not new. A tool with both `destination` and `outbound` keeps `destination` as it was and counts the outbound values next to it, and `destination_seen` is true when any of them was seen. The examples are in [`config/policies/run-usage.cedar`](https://github.com/attenuo-dev/attenuo/blob/main/config/policies/run-usage.cedar) and [`config/policies/output-labels.cedar`](https://github.com/attenuo-dev/attenuo/blob/main/config/policies/output-labels.cedar). The background is in the [read-side exfiltration design](../design/read-side-exfiltration.md).

### Chain depth

```cedar
@id("forbid_deep_chains")
forbid(principal, action, resource)
when { context.chain.depth > 3 };
```

The core library caps depth at 8. Set your own lower bound: a planner that delegates to a coder that delegates to a helper is plausible; six levels is a bug or an attack.

### Agent-specific rules

You can key rules on who is acting:

```cedar
// Only the "release-bot" agent may merge.
@id("merge_only_release_bot")
permit(principal == Agent::"release-bot", action == Action::"github/merge_pull_request", resource);

// Nothing delegated from the "untrusted-summarizer" agent may write.
@id("summarizer_subtree_is_readonly")
forbid(principal in Agent::"untrusted-summarizer", action, resource)
when { !resource.readonly };
```

**Warning: agent identity is only as strong as actor authentication.** The agent ids in a chain are whatever the token exchange recorded. With `[token] require_actor_auth = true` (the default) an exchange must authenticate as its `actor`, with that agent's `[[agents]]` client secret or client key (`private_key_jwt`), or with an `actor_token` from an `[[actor_trust]]` issuer (`[token] actor_auth`). With a secret or a client key, an id in the chain means "someone holding that agent's secret or private key"; with an actor token, "a workload the identity system vouched for", which is only as strong as that system and its `subject_to_agent` mapping. An operator who turns the setting off makes the `actor` an assertion again. Treat agent-keyed rules as defence in depth. Put the real boundary in things the holder cannot change: the capabilities in the token (attenuation only narrows), attributes of the originating user, and chain depth.

### Migrating from bare actions

Until 2026-10-23 the action was the bare tool name, `Action::"read_file"`, and it matched that tool on every upstream (SR-13 in the [security review](../research/security-review-2026-10-22.md)). To migrate:

1. Run `attenuo policy lint policy.cedar --config server.toml`. Every bare action is reported as `error[actions]` with its line and column.
2. Rewrite each one as `Action::"<server>/<tool>"`. If one bare permit was meant for the same tool on several servers, write one action per server: `action in [Action::"github/read_file", Action::"gitlab/read_file"]`.
3. Run your `attenuo policy test` files; the cases themselves do not change, since they name the server and the tool separately.

If you cannot rewrite the policies before upgrading, `[policy] legacy_bare_actions = true` keeps the old ids (and their old, unscoped meaning) for the whole policy set. It is deprecated: the server logs a warning at start, lint reports each bare action as a warning instead of an error, and the two forms cannot be mixed. `attenuo policy test` follows the same switch from the config its `catalog:` names, or from `legacy_bare_actions: true` in the test file.

## Testing policies

Policies are code. Test them offline, with no server, using `attenuo policy test`.

### Test files

A test file is YAML. Each case says who asks, through which chain, for what, and what must happen:

```yaml
policies: ./policy.cedar            # relative to this file; optional (no policies means deny all)
catalog: ./config.toml              # a server config's [policy.catalog] (and catalog_path), a .json
                                    # catalog, or an inline map as in the server config
unknown_tools: deny                 # optional; default: the config's [policy] unknown_tools, else deny
now: 1760000000                     # optional; evaluation time, unix seconds
cases:
  - name: coder may read public docs
    user: { subject: alice, issuer: https://idp.example, attributes: { mfa: true } }
    chain: [assistant, coder]       # agent ids, root first
    call:
      server: github
      tool: read_file
      arguments: { repo: alice/public-docs, path: README.md }
    expect: allow                   # or deny
    reason: policy_allow            # optional: policy_allow | policy_deny | approval_required |
                                    # capability_denied | input_type_mismatch | policy_error |
                                    # argument_case_mismatch
    policy_ids: [read_file_public_repos_only]   # optional; the policies that decided it, as a set
```

An inline catalog looks like the server's:

```yaml
catalog:
  github:
    read_file: { readonly: true, inputs: { repo: string } }
    delete_repo: { sensitive: true }
```

The harness builds a real `DelegationChain` and calls the same `PolicyEngine::authorize` the server calls, so both stages run.

- **Capabilities.** A hop with no `capabilities` inherits the previous hop's, and the first hop gets exactly the call's `server:tool`. So by default the capability stage passes and you are testing your policies. To test a capability denial, give hops explicit capabilities (strings like `github:*` or full capability objects with argument constraints):

  ```yaml
  chain:
    - { agent: assistant, capabilities: ["github:*"] }
    - { agent: coder, capabilities: ["github:read_file"] }
  ```

  A full capability object takes any constraint kind, a `range` included:

  ```yaml
  chain:
    - agent: payer
      capabilities:
        - server: banking
          tool: send_money
          constraints: { amount: { op: range, value: { min: 1, max: 2000 } } }
  ```

- **Valid chains only.** The chain is validated like a received one. A child wider than its parent, for example, is reported as a failed case with the reason, so a test cannot describe a delegation the server would refuse to issue.
- **Defaults.** User `alice` at `https://idp.example`, authenticated a minute before `now`; time fixed at 1760000000; each hop lives an hour; lease ids are random. `policy_ids: []` asserts that no policy matched (a default deny).
- **Output labels.** A case's `session: { tainted_by: [web/fetch] }` evaluates the call as part of a run that has read that source; `tainted: true` with no sources is a run whose taint state could not be read. Without `session` the run is untainted. `reason` also accepts `approval_required`. `approval: { by: user }` evaluates the call as a retry that carries a granted approval (`by` is `user` or `operator`); without it there is none. `session: { untrusted_args: [body] }` sets `context.untrusted_args`, and `args_contain_untrusted` defaults to whether that list is non-empty (it can also be set `true` alone); without them the call has no matched arguments.
- **Run limits.** The harness keeps no counters. `budget: { calls_remaining: 1 }` sets `context.budget` for the case (`limited` defaults to `true` there; the other members default to an unlimited call's values). Capabilities in `chain` may carry `limits`, which are checked for narrowing like any other part of a capability. Offline, those limits are not enforced: a case whose chain carries a limit and whose `budget` says it is spent sees the figures in Cedar but is not refused. Through `--via admin-evaluate` the server does enforce them (`budget_exhausted` before Cedar, as for a live call), so write such a case for the server arm, or leave `limits` out of the chain to test the policy alone.
- **Run usage.** `usage: { calls: 1, amount: 10, destination_seen: true }` sets `context.usage` for the case, as if the run had made those calls of the tool before (each member optional, 0 or false). Without it the call is the run's first. `usage: { user_window: { day: { calls: 3, amount: 4900 } } }` sets the user's windows the same way (`hour` and `day`, each optional, members default 0). The inline catalog takes `amount` and `destination` like the server's.
- **Mistakes in the file** (unknown keys, a missing `expect`, duplicate case names, an empty `cases`) are errors, not silent passes.

### Running

```sh
attenuo policy test policy_test.yaml [more.yaml ...] [--fail-on-unexercised] [--schema-file F] [--watch] [--json]
```

For example, with a policy `loose_read` that permits every `read_file` appended to the demo's `policy.cedar`, and the four-agent case taken out of its `policy_test.yaml` (the first lines of the run):

```text
examples/github-leak-demo/policy_test.yaml
  ✗ coder may read a public repo  (allow: policy_allow [loose_read, read_file_public_repos_only])
      expected policy_ids [read_file_public_repos_only], got [loose_read, read_file_public_repos_only]
  ✗ the injected read of a private repo is denied  (allow: policy_allow [loose_read])
      expected deny, got allow (policy_allow)
      expected reason policy_deny, got policy_allow
  ...

7 passed, 3 failed (10 cases in 1 file)
1 of 6 policies not exercised:
  examples/github-leak-demo/policy.cedar:37  forbid_deep_chains
```

Exit status: `0` all cases pass, `2` some case fails, `1` a file could not be run (unreadable, malformed, policy that does not parse or validate). `--json` prints one object with every case, the actual decision, the policy ids that decided it and any diagnostics, for tooling.

#### Unexercised policies

The last lines of a run list the policies that no case exercised, with the file and the line the policy starts on (its first annotation, or `permit`/`forbid`), named by `@id` or, without one, by Cedar's `policy<N>` (the N-th statement of the file, counting from 0). A policy is exercised when it decided at least one evaluated case: it is in that case's `policy_ids`, whether the case passed or not. Cases denied before Cedar runs (`capability_denied`, `tool_not_in_catalog`) exercise nothing, and neither does a default deny (no `permit` matched). A `permit` that matched only calls a `forbid` also matched is not exercised either, since the `forbid` decided them. When several test files name the same policy file, a case in any of them counts.

`--fail-on-unexercised` turns the list into a failure (exit `2`) for CI. With `--json` the same information is in `coverage`: `{"policies": 5, "exercised": 4, "unexercised": [{"id": "forbid_deep_chains", "file": "...", "line": 37}]}`.

#### Against a running server

The offline run proves the policy file. To check what a deployed server actually decides (its loaded policies, its catalog, its configuration), send the same cases to it. `--via` picks how:

| `--via` | Decided by | Credential | Chain | Runs | Skips | Audited |
| --- | --- | --- | --- | --- | --- | --- |
| `local` (default) | the engine built from the test file, offline | none | the case's | every case | nothing | no |
| `authzen` | `POST /access/v1/evaluation`, as a PEP would ask | a delegation token | the token's | cases that match the token | `session`, `approval`, `budget`, `usage`, `user.authenticated_at_unix`, another `user` or `chain` | yes, one record per case |
| `admin-evaluate` | `POST /admin/policies/evaluate`, the admin dry run | the admin token | the case's | every case | nothing | no |

`authzen` checks the path an enforcement point takes, lease check included, for one real token. `admin-evaluate` replays the whole suite against the server's policies, catalog and schema, with no token and nothing left in the audit log, so it is the one to run after a deploy or a policy reload.

The AuthZEN arm:

```sh
attenuo --server https://attenuo.internal policy test --via authzen --token-file coder.jwt policy_test.yaml
```

Each case's call goes to `POST /access/v1/evaluation` with the token as the bearer, and the answer is compared with the case's `expect`, `reason` and `policy_ids` exactly as offline; the output and exit status are the same. The server takes the chain from the token, not from the case, and keeps the run's labels, approvals, budgets and usage itself. So a case runs only when what it describes is what the token is:

- no `session`, `approval`, `budget`, `usage` or `user.authenticated_at_unix`;
- a `user`, if the case sets one, equal to the token's user (subject, issuer and exactly the same attributes);
- a `chain`, if the case sets one, naming the token's agents in order, with any explicit `capabilities` equal to that hop's capabilities in the token.

Other cases are listed as skipped, with the reason, and do not fail the run. The file's `catalog`, `unknown_tools` and `now` are ignored, since the server uses its own. Every evaluation is a real decision, so each case leaves an audit record on that server; use a test token and a test run, not a production agent's token. The unexercised list still comes from the test file's local `policies` file, which may differ from what the server has loaded.

The admin dry-run arm:

```sh
attenuo --server https://attenuo.internal --admin-token-file /run/secrets/attenuo-admin \
  policy test --via admin-evaluate policy_test.yaml
```

Each case is sent with the chain it describes, and with its `session`, `approval`, `usage` and `budget` as the run's state (a case without them is an untainted run with no usage; without `budget` the server reads the run limits' counters, which for a case's chain are empty). The server checks the chain's shape and its own `max_depth`, not that it issued the chain, runs the capability stage and Cedar, and answers without a lease check, a charge or an audit record. A case's `budget` is sent as written: when the chain carries limits that match the call, the server turns the figures into counters and runs its own limit check, so a spent limit is `budget_exhausted` as on a live call; when it carries none, Cedar sees the figures as given, as offline. Nothing is skipped. The chain is stamped at the current time and the server evaluates at its own clock, so `now` is not sent (a `note:` says so); `user.authenticated_at_unix` keeps its distance from the file's `now`. A case the server refuses (a chain deeper than its `max_depth`, say) fails with the server's reason; a wrong admin token stops the file. The file's `catalog`, `unknown_tools` and `--schema-file` do not apply, as with `authzen`.

#### While editing

`attenuo policy test --watch policy_test.yaml` runs the suite, then runs it again every time you save the test file, its policy file, its catalog or server config, or the base schema file. It polls every 250 ms and waits until the files have been quiet for 200 ms, so an editor that writes in several steps causes one run. Each run clears the screen first. Stop it with Ctrl-C.

The same runner is available as a library, `attenuo_policy::testing`, for tests written in Rust.

### Linting

```sh
attenuo policy lint policy.cedar --config server.toml [--schema] [--json]
```

Parses the file, flags bare (not server-scoped) actions, and validates it against the schema generated from the catalog in `--config`, printing each problem as `file:line:col: error[stage]: message`. Exit `0` clean, `2` errors. `--schema` also prints the schema it validated against, which is the quickest way to see which actions and argument names are declared. Without `--config` the tools are declared from the policy's own `<server>/<tool>` action names, so a correct policy passes; `context.input` and the user attributes are not declared, so "impossible policy" warnings are dropped for policies that read them, and a `note:` says that `resource.readonly`, `resource.sensitive` and input types were not checked, and bare or malformed action names are listed as not declared. Pass `--config` for the full check of the policy. It does not run the server's start-up checks on the configuration, so a configuration that passes can still refuse to start ([CLI reference](../reference/cli.md#policy-lint-policy)).

### In CI

Run the tests and lint on every change to policies. A GitHub Actions job:

```yaml
name: policy
on:
  pull_request:
    paths: ["policy/**", "config/**"]
jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Install the attenuo CLI
        run: cargo install --locked --git https://github.com/attenuo-dev/attenuo attenuo-cli
      - name: Lint
        run: attenuo policy lint policy/policy.cedar --config config/server.toml
      - name: Test
        run: attenuo policy test policy/policy_test.yaml
```

Pin the install to a tag or `--rev` once releases exist, so a CLI change cannot break your pipeline. Because the exit status distinguishes failing cases (`2`) from a broken setup (`1`), you can treat them differently if you want.

### What to test

- One allow case and one deny case per `permit`, including the near miss: `alice/public-docs` allowed, `alice/publicity` and `bob/public-docs` denied.
- Every `forbid`, with the exact policy id: `policy_ids: [forbid_sensitive_without_mfa]`.
- The missing-argument case. A call with no `repo` must be denied, not an error.
- A capability denial, to prove the chain is narrower than the policy.
- The boundary of numeric limits (`depth > 3`: three agents pass, four do not).

[`config/policies/default_test.yaml`](https://github.com/attenuo-dev/attenuo/blob/main/config/policies/default_test.yaml) does each of these for the starter policy set, `default.cedar`.

A `forbid` that never appears in a passing test is a `forbid` you have not shown works. The unexercised list at the end of every run names the ones no case reached at all.
