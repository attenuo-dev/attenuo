# Cedar-aware list filtering: design

- Status: proposed; the first slice (section 4) is built on branch `feat/cedar-list-filter` (2026-11-05), measured in [bench/2026-11-05-vm-list-screen.md](bench/2026-11-05-vm-list-screen.md) and described in [server pipeline, list filtering](server.md#list-filtering). The decision is [ADR-0011](../decisions/0011-cedar-aware-list-filtering.md) (proposed); the maintainer decides.
- Date: 2026-10-25. Base: `main` at 76cff3a.
- Related: [server pipeline, list filtering](server.md#list-filtering), [decision pipeline](server.md#the-decision-pipeline), [capabilities](../concepts/capabilities-and-attenuation.md), [ADR-0005](../decisions/0005-policy-decision-point.md), [ADR-0009](../decisions/0009-output-labelling.md), [ADR-0010](../decisions/0010-run-limits.md), [listen-stream filter bench](bench/2026-10-24-vm-listen-stream-filter.md).

## 1. Problem

The proxy filters `tools/list`, `resources/list`, `resources/templates/list` and `prompts/list` by capability shape alone (`filter::could_permit_tool` and its siblings in `crates/attenuo-proxy/src/filter.rs`): an entry stays when some capability's server and tool patterns match it, constraints mostly ignored. Cedar is not consulted, because a Cedar decision needs a concrete call and every decision writes an audit record. So an agent is shown tools that no call can get through:

- a tool no permit applies to, for example `github/update_issue` under the starter policy, which permits read-only tools, `create_issue` and `delete_repo` only;
- a sensitive tool for a user without MFA (`forbid_sensitive_without_mfa` decides on facts fixed in the token);
- every tool, for a chain deeper than three hops (`forbid_deep_chains`);
- a tool the catalog does not hold, under `[policy] unknown_tools = "deny"` (`tool_not_in_catalog`, stage 1b);
- a tool whose hard run limit is spent (`budget_exhausted`).

The agent wastes calls on them, and the model reads descriptions of tools it cannot use. The board carries "consider Cedar-aware list filtering" twice ([board](../tasks/board.md)). The difficulty is that a `tools/call` decision depends on things that do not exist at list time: the arguments (`context.input`), the run's taint (`context.session`, `args_contain_untrusted`), a taken approval (`context.approval`), run usage and budgets (`context.budget`, `context.usage`), and the clock (`now_unix`). What is known at list time is the principal and its chain (`originating_user`, `chain`), the action and the tool's catalog attributes.

Nothing here may change a `tools/call` decision. Every call is still decided by the full pipeline. Hiding an entry is a usability property, not a security one: an agent that calls a hidden tool by name is decided as today.

## 2. Options

### 2.1 Hide only when Cedar denies for every possible input

Evaluate each entry with the known parts concrete and the call-time parts unknown, and hide it only when the answer is deny whatever the unknowns turn out to be. This is sound by construction: a hidden entry is one no call could use.

What Cedar can do today (cedar-policy 4.14.0, the version in `Cargo.lock`), both behind experimental features excluded from Cedar's stability guarantees:

- **`partial-eval`** (`Authorizer::is_authorized_partial`). Context values can be unknowns (`RestrictedExpression::new_unknown`), so `input`, `session`, `args_contain_untrusted`, `untrusted_args`, `approval`, `budget`, `usage` and `now_unix` can be unknown while `originating_user` and `chain` stay concrete. `PartialResponse::decision()` returns `Some(Deny)` when no permit can be satisfied or a forbid is satisfied on the known parts alone, `Some(Allow)` when the answer is fixed the other way, and `None` with residual policies otherwise. Unknowns are untyped and residuals are not checked for satisfiability: `context.input.n > 5 && context.input.n < 3` stays a residual, so the screen is incomplete (some always-denied entries stay listed), never unsound.
- **`tpe`** (type-aware partial evaluation, `PolicySet::tpe`). Uses the schema to type unknowns, but its `PartialRequest` takes a context that is either fully known or fully unknown. With the whole context unknown, `forbid_deep_chains` and `forbid_sensitive_without_mfa` become residuals and the screen loses its best cases. Not usable as is.

Approval obligations need care. A call denied only by `@obligation("approval")` forbids is `approval_required`, and the pending approval is created by that denied call (pipeline step 7). Hiding such a tool would make the approval flow unreachable from a client that only calls listed tools. So the screen evaluates the policy set with the approval forbids lifted (the engine already builds it, `Obligations::without_approval`) and hides only when that set is denied. Since the relaxed set keeps every other forbid, this also covers a non-approval forbid that is satisfied on known parts.

Two non-Cedar stages decide on list-time facts too and can be screened exactly without any Cedar feature: the catalog stage (`PolicyEngine::effective_attrs` returns `None` under `unknown_tools = "deny"`), and, at the price of a store read, a spent hard token limit. The second depends on run state and goes stale (section 4), so it is left out.

### 2.2 Evaluate with an empty or default input and hide on deny

Build a concrete request with `context.input = {}` and default values for the rest (untainted, no approval, unlimited budget), and hide on deny. Cheap and needs no experimental feature, but wrong both ways. It hides usable tools: `permit_create_issue_in_acme` needs `context.input has repo`, so `create_issue` is denied with an empty input and would vanish although `acme/x` is allowed; with "no approval" every approval-gated tool vanishes. And the defaults decide on state the call will not have: an allow under "untainted" says nothing about a tainted run, so an `allow` answer cannot be shown to the agent either. Rejected.

### 2.3 Annotate instead of hide

Keep every entry and add a hint to its `_meta` (MCP allows `_meta` on a `Tool`, with reverse-DNS prefixes), for example `"dev.attenuo/decision": "denied" | "needs_approval"`, from the same partial evaluation: `denied` when the relaxed set is `Some(Deny)`, `needs_approval` when it is not and an approval forbid is a residual or satisfied. Nothing disappears, so caching clients and the approval flow are unaffected. But no MCP client reads such a key today, so the model sees it only if the client passes `_meta` through, and it tells an untrusted agent more of the policy than hiding does (section 5).

### 2.4 Do nothing, document it

The status quo. Every call is decided, so the only cost is wasted calls and context. [Server pipeline](server.md#list-filtering) already says "a listed entry can still be denied when used". The argument for it is that hiding is a UX property with a security-looking name, and the proxy's list path stays free of Cedar.

## 3. Cost on the hot path

The floor: the list filter costs 0.6 to 0.7 ms per 85 KB, 200-tool `tools/list` answer in the stage (parse, filter, serialize) and 1.1 to 1.3 ms end to end ([bench](bench/2026-10-24-vm-listen-stream-filter.md)); the name match per entry is negligible in that.

| Option | Per entry | 200 tools, warm | 200 tools, first list of a chain |
|---|---|---|---|
| 2.4 status quo | pattern match | 0 added | 0 added |
| catalog stage only | one catalog lookup | well under 0.1 ms | same |
| 2.1 / 2.3 partial eval | request build (about 6 us) plus evaluation (about 5.5 us concrete, partial not measured); twice when approval obligations exist | about 2 to 5 ms if partial costs one to two times concrete | about 25 ms: the per-tool entity store costs 110 to 150 us to build ([performance](performance.md#after-the-policy-stage-and-wal-work)) |
| 2.2 empty input | as 2.1 with concrete evaluation | about 2 ms | about 25 ms |

So a Cedar screen costs three to eight times the list filter it extends when warm, and twenty or more times on a chain's first list. Three things follow. The screen must run on the blocking pool, not on the async worker. It should not fill the engine's request cache (4,096 entries shared with `tools/call`) with 200 tools a chain may never call; building the principal and user entities once per list and one `Tool` entity per entry is cheaper than the cache's per-tool build. And its result should be memoized per (chain cache key, server, tool, policy generation), because clients re-list often: LangChain's adapter opens a session per call. With the memo a repeated list costs one lookup per entry. A policy reload or a new narrowing from `import_annotations` invalidates it.

## 4. Chosen design (proposed)

Option 2.1, opt in, tools only in the first slice.

- `[proxy] list_filter = "capabilities"` (default, today's behaviour) or `"policy"`: capabilities first, then hide an entry when the catalog stage denies it, or when partial evaluation of the policy set without approval forbids is `Some(Deny)` with `input`, `session`, `args_contain_untrusted`, `untrusted_args`, `approval`, `budget`, `usage` and `now_unix` unknown. `now_unix` is unknown because the call comes later; run state is unknown because it changes during the run and a client may cache the list.
- A new `Authorizer::screen_list(chain, server, names) -> Vec<bool>` (keep or hide), whose default keeps everything, so authorizers other than the server's are unaffected. `ServerAuthorizer` calls a new `PolicyEngine::screen_tool`, which never appends a record, takes an approval, charges a counter or reads the lease store.
- Names are still learned for `require_listed_tools` (SR-25) and annotations still imported before any screening, as now.
- A failed screen (engine lock poisoned, an evaluation error on known parts, a timeout) keeps the entry. This is fail-open on purpose: the list is advisory and every call is still decided.
- Hidden entries are counted (`proxy_list_entries_hidden_total{reason}`, reasons `not_in_catalog` and `policy`), not audited: a record per list would flood the log and record nothing that was decided.
- `cedar-policy` gains the `partial-eval` feature in `attenuo-policy` only. The existing policy suites run with it on, to show concrete evaluation is unchanged.

**First slice and its tests.** Tools only, JSON, SSE, batch and listen-stream answers alike (one code path, `ListFilter`). Resources, templates and prompts later: their key is a concrete argument (`uri`, `name`), so `context.input` is partly known there, which needs its own tests.

- `policy_screen_hides_tools_no_permit_can_allow` (`update_issue` hidden, `create_issue` kept under the starter policy).
- `policy_screen_hides_sensitive_tools_for_users_without_mfa` and keeps them with MFA.
- `policy_screen_keeps_approval_gated_tools` (an `@obligation("approval")` forbid on destructive tools on a tainted run).
- `policy_screen_keeps_tools_whose_permit_depends_on_input` and `..._on_time`.
- `policy_screen_hides_uncatalogued_tools_only_under_unknown_tools_deny`.
- `hidden_tools_are_still_decided_when_called` (a hidden tool called by name gets the same `policy_deny` record as with `list_filter = "capabilities"`).
- A soundness proptest in `attenuo-policy`: for generated chains, catalog attributes and contexts (inputs, taint, approval, usage, time) over the starter and suite policies, every tool `screen_tool` hides is denied by `authorize_labelled`.
- `list_filter_defaults_to_capabilities` (config), and a failed screen keeps the entry.

## 5. Security

- **No `tools/call` decision changes.** The screen is a separate read-only function on the engine; the call path does not read its memo. The proptest above and `hidden_tools_are_still_decided_when_called` pin it.
- **Hiding is not enforcement.** A hidden tool can still be named (from docs, an earlier list, another agent) and is decided as today. Nobody should read `list_filter = "policy"` as protection.
- **What it tells an untrusted agent.** Today an agent learns that a tool is denied by calling it, and each probe leaves a `deny` record. A screened list gives the same one bit per tool for all tools at once, with no record: an injected agent learns where not to try, for free. Hiding reveals only "always denied for you"; annotation also reveals which tools are approval-gated, and an annotation computed from run state would reveal the run's taint. This is the main argument against annotation in the first slice and for keeping the key opt-in.
- **Caching clients.** The result depends on the token, the policy text, the catalog and imported narrowing, none of which changes within a run except by an operator's reload. After a reload a client may hold a list that is stale either way: a newly allowed tool stays hidden until it re-lists (a utility loss), a newly denied one stays listed (as today). The proxy sends no `notifications/tools/list_changed` of its own. Pages may become empty and keep their `nextCursor`, as with today's filter.
- **An experimental Cedar feature.** A bug in partial evaluation can at worst hide a usable tool or keep an unusable one; it cannot allow a call, because calls are evaluated concretely. The cost is extra code and an API that may change between Cedar minor versions.

## 6. Measuring it

The [injection suite](../evaluation/injection-suite.md) replays call sequences through the pipeline with no model, so it cannot show agents trying fewer denied tools. What it can measure, without changing its decisions:

- **Utility:** for each case and arm, the benign calls whose tool the screen would hide. The target is zero; a non-zero count is either a screen bug or a benign call the suite policy already denies (3 dev, 3 test today).
- **List size:** tools listed per case with and without the screen, as a stand-in for context saved.
- **Attack:** attack calls allowed and denied are unchanged by construction; a run shows that, and counts the attack calls aimed at tools the screen hides (calls a model-in-the-loop agent might never have made).

These need a screen entry point in the harness; nothing under `evaluation/` changes in this note.

## 7. Open questions

1. Is an experimental Cedar feature acceptable in the server's dependency tree, or should the first slice be the catalog stage alone (no Cedar), with partial evaluation after Cedar stabilises it?
2. Should a spent hard token limit hide a tool? It is exact at list time and wrong a moment later only if an operator refunds a charge; it costs a counter read per limited capability.
3. Should the proxy send `notifications/tools/list_changed` on open listen streams after a policy reload?
4. Is `"annotate"` worth adding once a client reads `_meta` hints, and if so, from token and policy facts only, never run state?
5. Partial evaluation cost: measured on 2026-11-05 ([bench](bench/2026-11-05-vm-list-screen.md)), 4.9 to 5.9 ms per uncached 200-tool list and 80 to 91 us memoised, with and without approval obligations alike. Two differences from section 4 in what was built: `session_id` is a ninth unknown, evaluated absent as well when a policy reads it (it is optional in a call's context, so an unknown alone would make `context has session_id` true); and an evaluation error keeps the entry, as section 4 says, while a chain that cannot be translated keeps every entry. The trait method is `Authorizer::screen_tools`, not `screen_list`; there is no timeout on the screen (it runs on the blocking pool like a decision); and an originating-user attribute of the wrong type, which denies every call with `attribute_type_mismatch`, hides every tool.
