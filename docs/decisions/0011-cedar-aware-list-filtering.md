---
status: proposed
date: 2026-10-25
decision-makers: [7Mudit]
consulted: []
informed: []
---

# ADR-0011. Cedar-aware list filtering: opt in, hide a tool only when the policy denies it for every possible call, with approval-gated tools always kept

## Context and Problem Statement

The proxy filters list results by capability shape only, so an agent is shown tools that no call can get through: a tool no permit applies to, a sensitive tool for a user without MFA, every tool for a chain deeper than the policy allows, a tool missing from the catalog under `unknown_tools = "deny"`. Every call is still decided, so this costs wasted calls and model context, not security. Should the proxy also consult the policy when it filters lists, and how, given that a `tools/call` decision depends on arguments, run taint, approvals, run usage and the clock, none of which exists at list time? Design: [design/cedar-aware-list-filtering.md](../design/cedar-aware-list-filtering.md).

## Decision Drivers

- No `tools/call` decision may change; the screen must not write audit records, take approvals, charge counters or read run state.
- A hidden entry must be one no call could use (sound), even if some unusable entries stay listed (incomplete).
- The approval flow must stay reachable: a pending approval is created by a denied call, so an approval-gated tool must stay listed.
- The added cost per list must be small next to the list filter itself (0.6 to 0.7 ms per 85 KB, 200-tool answer).
- An untrusted agent should learn as little about the policy as it does today.
- Default behaviour stays as it is.

## Considered Options

- Hide only when the policy denies for every possible input: Cedar partial evaluation with call-time context unknown, approval forbids lifted, plus the catalog stage.
- Evaluate with an empty or default input and hide on deny.
- Annotate entries (`_meta` key `dev.attenuo/decision`: `denied` or `needs_approval`) instead of hiding.
- Do nothing and document that a listed tool can still be denied.

## Decision Outcome

Proposed: "Hide only when the policy denies for every possible input", behind `[proxy] list_filter = "policy"` with `"capabilities"` (today's behaviour) as the default, because it is the only option that is sound and keeps approval-gated tools. It needs cedar-policy's experimental `partial-eval` feature in `attenuo-policy`; Cedar's type-aware `tpe` cannot be used, since it takes the context only fully known or fully unknown and would lose the chain and user facts that make the screen useful. The first slice covers `tools/list` only, wherever the answer arrives, with the tests listed in [design section 4](../design/cedar-aware-list-filtering.md#4-chosen-design-proposed). If the experimental feature is not acceptable, the fallback is the catalog stage alone, which needs no Cedar change (design open question 1).

### Consequences

- Good, because the agent stops seeing tools that no call can use under facts fixed in its token, which saves calls and context, most of all with large upstream catalogues.
- Good, because the call path is untouched; a soundness proptest checks that every hidden tool is denied by `authorize_labelled` for generated contexts.
- Bad, because it puts an experimental Cedar API in the dependency tree, which may change between minor versions. A bug in it can hide a usable tool, not allow a call.
- Bad, because it is incomplete: anything that depends on arguments, taint, approvals, usage or time stays listed, since partial evaluation leaves those as residuals and does not check them for satisfiability.
- Bad, because it costs an estimated 2 to 5 ms per warm 200-tool list and about 25 ms on a chain's first list, against 0.6 to 0.7 ms for the filter today (estimate; partial evaluation is not measured). It needs the blocking pool and a memo per chain, tool and policy generation.
- Bad, because a screened list tells an injected agent, without an audit record, which tools are always denied for it; today it learns that one call, and one `deny` record, at a time.
- Neutral, because clients that cache lists can hold a stale list after a policy reload; the loss is utility, either way.

### Confirmation

Not built. Before acceptance: a criterion bench of partial evaluation for 200 tools next to `policy_stage`. With the slice: the design's tests, including `hidden_tools_are_still_decided_when_called` and the soundness proptest, and an injection-suite count of benign calls to hidden tools (target zero), with attack figures unchanged by construction.

## Pros and Cons of the Options

### Partial evaluation with call-time context unknown

- Good, because a `Some(Deny)` from Cedar with those unknowns holds for every value they can take.
- Good, because lifting the approval forbids (the engine's existing relaxed set) keeps approval-gated tools listed.
- Bad, because of the experimental feature, the cost and the incompleteness above.

### Empty or default input

- Good, because it needs only concrete evaluation.
- Bad, because it hides usable tools (a permit that needs `context.input has repo`, every approval-gated tool) and its allows say nothing about a tainted or approved call.

### Annotate instead of hide

- Good, because nothing disappears, so caching clients and the approval flow are unaffected.
- Bad, because no MCP client reads such a key today, and it reveals more of the policy (which tools need approval) than hiding does.

### Do nothing

- Good, because the list path stays free of Cedar and of any cost.
- Bad, because the agent keeps spending calls and context on tools it cannot use.

## More Information

- Board: the two "consider Cedar-aware list filtering" items in [docs/tasks/board.md](../tasks/board.md) point here.
- Related: [ADR-0005](0005-policy-decision-point.md) (capabilities first, then Cedar), [ADR-0009](0009-output-labelling.md) (approval obligations, run taint), [ADR-0010](0010-run-limits.md) (run usage and budgets in context), [server pipeline, list filtering](../design/server.md#list-filtering).
- Cedar experimental features: [cedar-policy RFCs](https://github.com/cedar-policy/rfcs/blob/main/README.md#experimental-features).
