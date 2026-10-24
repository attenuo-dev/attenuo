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
| `context.args_contain_untrusted`, `context.untrusted_args` | `false` and an empty set for now; argument matching is not built yet |
| `context.approval` | `present` (bool) and `by` (`"user"`, `"operator"`, or `""` without an approval): whether this call carries a granted approval for its exact hash; see [Asking for approval after untrusted output](#asking-for-approval-after-untrusted-output) |
| `context.budget` | what the token's run limits matching this call have left: `limited` (bool), `calls_remaining`, `amount_remaining` (Long; the largest Long when no such limit applies) and `destination_new` (bool); see [Run limits](#run-limits) |

The action names the server as well as the tool. `action == Action::"github/read_file"` matches `read_file` on the upstream mounted as `github` and nothing else: a second upstream that also has a `read_file` tool (a malicious one, say) is not covered by that permit. To write a rule for every tool of one server, use the resource: `resource in Server::"github"`. To write one for every tool everywhere, leave `action` unconstrained or use `action in Action::"invoke"`.

The principal is an `Agent`, and an agent is `in` the originating `User` and in every earlier agent of the chain. So `principal in User::"alice"` and `principal in Agent::"planner"` both work, the latter matching `planner` and anything it delegated to.

`resource` carries `readonly`, `sensitive` and `destructive`, taken from the catalog (below). `principal.chain_depth` is the 1-based position of the agent in the chain.

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

It does two jobs:

1. **Tool attributes** (`readonly`, `sensitive`, `destructive`) become `resource.readonly`, `resource.sensitive` and `resource.destructive`. `destructive` defaults to the opposite of `readonly`. `output` (`untrusted` by default, or `trusted`) says whether the tool's results taint the run; it is not a Cedar attribute. A tool that is not in the catalog is denied before Cedar runs, with reason `tool_not_in_catalog`, unless `[policy] unknown_tools` is `sensitive` (evaluated as `sensitive = true`) or `allow` (evaluated as neither, so a `forbid` keyed on `sensitive` silently skips it). Register every tool the server exposes (MCP `tools/list` is the natural source).
2. **Schema generation.** Each catalog entry becomes a declared action, `Action::"<server>/<tool>"`, and each `inputs` entry a typed, optional attribute of `context.input`. Policies are validated against this schema at load time, so a typo in an argument name or a comparison of a string to a number fails the load instead of misbehaving on a call. A policy that names `Action::"github/x"` validates only if the catalog has a tool `x` under `github`. Argument types are `string`, `long`, `bool`, or `{ set = "string" }`.

Server names (the `[[upstreams]]` names and the catalog's server keys) and tool names may not contain `/`, so `"<server>/<tool>"` always splits one way. The one exception is on the tool side: the proxy authorizes MCP methods other than `tools/call` under their method name (`resources/read`, `prompts/get`), so those catalog entries are `[policy.catalog.github."resources/read"]` and their action is `Action::"github/resources/read"`. A `tools/call` can never carry a `/` in its tool name, so a tool cannot pose as one of these methods. The server refuses to start with a catalog entry that breaks these rules.

### User attributes

The schema declares four optional attributes of `context.originating_user.attributes`: `mfa` (bool), `roles` (set of strings), `tenant` (string) and `email` (string). A policy that tests any other attribute, `groups` for example, is reported as impossible when it loads (a validation warning in the server log and in `attenuo policy lint`), because the validator has no such attribute to type-check. Declare the extra attributes in the config:

```toml
[policy]
user_attributes = { groups = "set<string>", department = "string" }
```

Types are `string`, `long`, `bool` and `set<T>` (for example `set<string>`). The declarations are merged over the built-in four, so you can also re-type one of them. Then guard every use, since attributes are optional:

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

## Patterns

All of these assume the catalog above.

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

The run's originating user grants the approval with their own ID token (`POST /approvals/{id}`), or an operator does (`attenuo approval grant`, or the console). The agent then retries the identical call, same server, tool and arguments, with a token of the same hop. That one retry sees `context.approval.present == true` and `context.approval.by` set to `"user"` or `"operator"`, so the forbid above no longer applies; a second retry asks again. An approval expires after `[approvals] ttl_seconds` (default 120) or with the hop's lease, whichever comes first. To accept only the user's own approval, test `context.approval.by == "user"` instead of `present`.

The grant also returns a signed approval token (`approval_token`, `typ: attenuo-approval+jwt`). An agent may send it with the retry in `params._meta["dev.attenuo/approval"]` (the SDK helpers do); the server then uses exactly the approval the token names, after checking that it is for this call, this hop, this run and, for a DPoP-bound agent, this key. Policy sees the same `context.approval`. A token that fails those checks, or whose approval was already used or declined, denies the call with `approval_invalid` whatever the policy says. Because the token is signed with the issuer key, an external PEP can check it offline; see [Approval tokens](../reference/http-api.md#approval-tokens).

[`config/policies/output-labels.cedar`](../../config/policies/output-labels.cedar) has this rule and the mail rule from the design, with tests in `output-labels_test.yaml` next to it.

### Run limits

A capability in a token can carry `limits`: `calls` (at most this many calls), `sum: {arg, max}` (a total over one integer argument) and `calls_per: {arg, max}` (at most `max` calls per value of one argument). The server enforces them before Cedar, against every hop of the chain: a call over a limit is denied with `budget_exhausted`, and no policy or approval passes it. A policy cannot raise a limit, only explain or ask earlier, through `context.budget`:

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

`calls_remaining` and `amount_remaining` are what is left before this call, the smallest over every matching limit. `destination_new` is false once the call's `calls_per` value has been used in an earlier allowed call. [`config/policies/run-limits.cedar`](../../config/policies/run-limits.cedar) has this rule and a repeat-payee rule, with tests in `run-limits_test.yaml`.

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

**Warning: agent identity is only as strong as actor authentication.** The agent ids in a chain are whatever the token exchange recorded. With `[token] require_actor_auth = true` (the default) an exchange must authenticate as its `actor`, with that agent's `[[agents]]` client secret or with an `actor_token` from an `[[actor_trust]]` issuer (`[token] actor_auth`). With a secret, an id in the chain means "someone holding that agent's secret"; with an actor token, "a workload the identity system vouched for", which is only as strong as that system and its `subject_to_agent` mapping. An operator who turns the setting off makes the `actor` an assertion again. Treat agent-keyed rules as defence in depth. Put the real boundary in things the holder cannot change: the capabilities in the token (attenuation only narrows), attributes of the originating user, and chain depth.

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
                                    # capability_denied | policy_error
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

- **Valid chains only.** The chain is validated like a received one. A child wider than its parent, for example, is reported as a failed case with the reason, so a test cannot describe a delegation the server would refuse to issue.
- **Defaults.** User `alice` at `https://idp.example`, authenticated a minute before `now`; time fixed at 1760000000; each hop lives an hour; lease ids are random. `policy_ids: []` asserts that no policy matched (a default deny).
- **Output labels.** A case's `session: { tainted_by: [web/fetch] }` evaluates the call as part of a run that has read that source; `tainted: true` with no sources is a run whose taint state could not be read. Without `session` the run is untainted. `reason` also accepts `approval_required`. `approval: { by: user }` evaluates the call as a retry that carries a granted approval (`by` is `user` or `operator`); without it there is none.
- **Run limits.** The harness keeps no counters. `budget: { calls_remaining: 1 }` sets `context.budget` for the case (`limited` defaults to `true` there; the other members default to an unlimited call's values). Capabilities in `chain` may carry `limits`, which are checked for narrowing like any other part of a capability.
- **Mistakes in the file** (unknown keys, a missing `expect`, duplicate case names, an empty `cases`) are errors, not silent passes.

### Running

```sh
attenuo policy test policy_test.yaml [more.yaml ...] [--json]
```

```
examples/github-leak-demo/policy_test.yaml
  ✓ coder may read a public repo  (allow: policy_allow [read_file_public_repos_only])
  ✗ the injected read of a private repo is denied  (allow: policy_allow [loose_read])
      expected deny, got allow (policy_allow)

8 passed, 1 failed (9 cases in 1 file)
```

Exit status: `0` all cases pass, `2` some case fails, `1` a file could not be run (unreadable, malformed, policy that does not parse or validate). `--json` prints one object with every case, the actual decision, the policy ids that decided it and any diagnostics, for tooling.

The same runner is available as a library, `attenuo_policy::testing`, for tests written in Rust.

### Linting

```sh
attenuo policy lint policy.cedar --config server.toml [--schema] [--json]
```

Parses the file, flags bare (not server-scoped) actions, and validates it against the schema generated from the catalog in `--config`, printing each problem as `file:line:col: error[stage]: message`. Exit `0` clean, `2` errors. `--schema` also prints the schema it validated against, which is the quickest way to see which actions and argument names are declared. Without `--config` the tools are declared from the policy's own `<server>/<tool>` action names, so a correct policy passes; `context.input` and the user attributes are not declared, so "impossible policy" warnings are dropped for policies that read them, and a `note:` says that `resource.readonly`, `resource.sensitive` and input types were not checked, and bare or malformed action names are listed as not declared. Pass `--config` for the full check.

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

A `forbid` that never appears in a passing test is a `forbid` you have not shown works.
