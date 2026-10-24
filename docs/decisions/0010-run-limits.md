---
status: accepted
date: 2026-10-24
decision-makers: [7Mudit]
consulted: []
informed: []
---

# ADR-0010. Run limits: count and amount budgets declared per token hop, charged against every hop of the chain in the decision's transaction, and exposed to Cedar as context

## Context and Problem Statement

A delegation token bounds which tools an agent may call and with which argument values, but not how often or for how much in total. The [injection suite](../evaluation/injection-suite.md) has attacks that use that gap: a second payment to the right payee (`banking-11`, `t-banking-05`), a larger amount under the policy's per-call cap (`banking-04`, `t-banking-05`), a second message or comment to the right place. Output labelling ([ADR-0009](0009-output-labelling.md)) turns these into approval requests, but its approve-all bound stays at 10 of 60 dev and 7 of 38 test attack calls: the protection depends on the approver saying no. How should attenuo bound repetition and amount, so that the bound holds across every agent of a run, narrows per hop like the rest of a capability, and needs no person in the loop? Design: [design/run-limits.md](../design/run-limits.md).

## Decision Drivers

- P2 must hold for budgets: a child hop can never be given, or spend, more than its parent has.
- A sub-agent must not be able to reset a budget by delegating again, and concurrent sub-agents must not jointly overspend.
- The budget decrement, the decision and its audit record must commit together, as approvals are consumed in ADR-0009.
- Fail closed: unreadable counters deny; an allowed call whose upstream failed is still counted.
- Cedar stays stateless; the server computes figures and passes them in, as with run labels.
- Nothing the agent, a PEP or an MCP annotation supplies may raise a budget.
- The benefit and the benign cost must be measurable on the injection suite.

## Considered Options

- Limits declared per token hop (`calls`, `sum`, `calls_per`, later `distinct`), counted per lease, and charged against every limited capability in every hop that matches the call.
- Per-run budgets only, keyed by `chain_id`, set in server configuration or policy, with nothing in the token.
- Per-hop budgets with reservation: a child's share is carved out of the parent's counter at exchange.
- Per-user rate windows across runs, at the proxy or at a gateway.
- No new mechanism: pin amounts with the existing `equals` constraint and rely on revocation and approvals.

## Decision Outcome

Chosen option: "Limits declared per token hop, charged against every matching hop", because it is the only option that lets a parent hand a sub-agent a smaller share and still bounds the whole run: hop 0's lease is the `chain_id`, so a root limit is the run budget, and charging every ancestor stops both laundering by re-delegation and overspending by concurrent siblings. Per-run defaults from the second option were kept as a policy input over run usage, not as a replacement for token limits.

What was built, all on 2026-10-24 (details and deviations in [design section 6](../design/run-limits.md#6-phased-plan)):

1. A capability has optional `limits`: `calls` (count), `sum` (total of a non-negative integer argument), `calls_per` (count per distinct value of an argument) and `distinct` (number of distinct values). `calls_per` and `distinct` may count the host of a URL argument instead of the whole value (`"derive": "host"`). Maxima are static numbers in the token; used amounts are server state in the lease store, with argument values stored as keyed hashes.
2. Narrowing: in `covers`, a child under a limited parent must carry the same limit with a `max` no larger (static, checked by `validate_at`); exchange clamps a child's `calls` and `sum` to the parent's remaining budget, and `calls_per` and `distinct` to the parent's `max`; at call time every ancestor is charged too. Siblings may be promised more in total than the parent has; they cannot spend it.
3. The limit check runs in the capability stage, before Cedar, with reasons `budget_exhausted`, `budget_error` (unreadable counters) and `limit_arg_invalid` (a missing, non-integer or negative summed argument, or a value with no URL host under a host limit). Denied calls cost nothing; allowed calls are counted even if the upstream fails; only an operator can refund one decision's charge, through the admin API or `attenuo budget refund`, audited. The charge commits in its own transaction just before the decision's audit append and is refunded if the append fails; a crash between the two over-counts.
4. Cedar sees `context.budget.{limited, calls_remaining, amount_remaining, destination_new}` and per-run usage of destructive tools, `context.usage.{calls, amount, destination_seen}`, all always present. Usage is kept only when a loaded policy or the catalog can read it. Token limits are hard and cannot be approved past. Policy limits over `context.usage` deny, or ask with `@obligation("approval")`; an approval passes one call, with no top-up.
5. Decision records carry the budgets a call drew on and the usage Cedar saw; the console's lease page and `attenuo lease tree` show each hop's limits and what is left.

Phase 3 of the design (per-user windows, RAR amount mapping, reservation) was not built and is not part of this decision.

### Consequences

Measured on the injection suite with frozen rules, not per-task figures. Synthetic call sequences with no model in the loop; the cases, policies and rules were written by the same agent family. Latest run of every arm on both splits ([browsing-v1](../../evaluation/injection-suite/results/2026-10-24-browsing-v1.md), 77 attack and 130 benign calls on dev, 38 and 29 on test). Attack allowed counts calls allowed without an approval; benign denied includes the 3 dev and 3 test calls the suite policy already denies.

| Arm | Frozen rule | Dev attack allowed | Dev benign denied | Dev approval asks | Test attack allowed | Test benign denied | Test approval asks |
|---|---|---:|---:|---:|---:|---:|---:|
| `attenuo` | none | 15/77 | 3/130 | 0 | 7/38 | 3/29 | 0 |
| `attenuo_labels` | session taint (ADR-0009) | 1/77 | 3/130 | 71 | 1/38 | 3/29 | 8 |
| `attenuo_limits` | `calls: 1` on non-read capabilities | 8/77 | 13/130 | 0 | 2/38 | 3/29 | 0 |
| `attenuo_labels_limits` | taint plus `calls: 1` | 1/77 | 13/130 | 54 | 1/38 | 3/29 | 3 |
| `attenuo_usage_soft` | ask on the 2nd call of a destructive tool | 6/77 | 3/130 | 29 | 2/38 | 3/29 | 5 |
| `attenuo_usage_host` | as above, web fetches asked per new host | 6/77 | 3/130 | 25 | 2/38 | 3/29 | 5 |
| `attenuo_distinct_host` | `distinct` URL hosts, `max: 1` | 13/77 | 7/130 | 0 | 7/38 | 3/29 | 0 |
| `attenuo_distinct_host2` | `distinct` URL hosts, `max: 2` | 14/77 | 3/130 | 0 | 7/38 | 3/29 | 0 |
| `attenuo_distinct_recipient` | `distinct` recipients, `max: 1` | 15/77 | 5/130 | 0 | 6/38 | 3/29 | 0 |

- Good, because repetition and amount attacks inside a permitted call stop without a person. `calls: 1` refuses all three repetition attacks of the multi-call cases and 5 of the 7 test attack calls `attenuo` allows, and the approve-all bound with labels falls from 15/77 to 8/77 on dev and from 7/38 to 2/38 on test.
- Good, because soft limits over run usage keep benign multi-call tasks whole: the soft rule loses no benign call that `attenuo` keeps, in any group of cases, asks and declines every repetition attack, and asks 29 times on dev against 71 for session taint.
- Good, because a sub-agent's share is a token fact that narrows like every other, and a run budget cannot be reset by delegating.
- Good, because every allowed call's record says which budgets it drew on and what was left.
- Bad, because a uniform hard count loses benign work: `calls: 1` refuses 10 of the 39 benign calls of the 11 multi-call dev cases, and 9 of those 11 tasks lose a call. A hard limit needs the figure the task names, set by the hop that issues the token.
- Bad, because hard limits are order-dependent: they bound how many, not which, and keep whichever call comes first. `slack-17` (`slack-08` with the exfiltrating fetch first) has its attack allowed and its article refused under the host limit. The frozen figures were fitted to cases of the same family: `max: 2` is the most hosts a benign browsing case needs, by construction, and the recipient rule was written after the test split was read.
- Bad, because `distinct` on recipients costs benign calls and misses repeats: it refuses the second recipient of two benign dev tasks (`workspace-13`, `slack-11`) and never counts `slack-11`'s repeat DM to Bob, a value already seen.
- Bad, because first-call attacks are not addressed by any limit: when the injected call is the first or only one of its kind (`github-02`, `travel-02`, `workspace-06`, `workspace-11`, `slack-17`, `t-workspace-05`), a count, sum or host limit allows it. Reads (`github-07`, `t-banking-04`) are not addressed either.
- Bad, because soft limits depend on the approver: their approve-all bound is `attenuo`'s (15/77 dev, 7/38 test), since they deny nothing new.
- Bad, because limited calls cost latency. Added client p50 from one client on the file store, 2-hop token ([performance](../design/performance.md#output-labelling-and-run-limits-on-the-hot-path-2026-10-24)): about 120 to 190 us with a `calls` limit; about 0.8 to 1.0 ms with a `sum` limit, almost all one `fsync` per call, which since #56 rides the decision append and is shared under concurrency; +98 to +144 us for the run-usage write when usage is tracked ([performance](../design/performance.md#run-usage-write-2026-10-24)). `calls_per` and `distinct` charges were not measured separately.
- Bad, because the number is only as good as the hop that sets it. A planner that has already read injected content can mint a generous budget.
- Bad, because the charge and the decision's append commit in separate transactions; a crash between them over-counts (fails closed), design open question 8.
- Neutral, because per-user windows across runs, and rate limits in general, stay out of scope (RFC-0001 section 8) until a later decision.

### Confirmation

Done on 2026-10-24. Suite arms `attenuo_limits` and `attenuo_labels_limits` with the frozen rule ([limits-v1](../../evaluation/injection-suite/results/2026-10-24-limits-v1.md)), eleven multi-call benign dev cases written after the rule was frozen ([limits-v2](../../evaluation/injection-suite/results/2026-10-24-limits-v2.md)), the soft and host arms ([usage-soft-v1](../../evaluation/injection-suite/results/2026-10-24-usage-soft-v1.md), [usage-host-v1](../../evaluation/injection-suite/results/2026-10-24-usage-host-v1.md)) and six browsing cases with the two-host and recipient arms ([browsing-v1](../../evaluation/injection-suite/results/2026-10-24-browsing-v1.md)); the table above is the last of these. The test split did not change across these runs, so it is not held out for rules written after it was read. The named properties are tests: `child_limit_never_exceeds_parent_limit` and `exchange_clamps_child_budget_to_parent_remaining` (proptests in `attenuo-core`), `call_is_charged_to_every_ancestor_hop_and_redelegation_does_not_reset_budget`, `concurrent_siblings_cannot_overspend_parent`, `upstream_failure_is_still_charged` and `refund_is_admin_only_and_once_per_decision` (`attenuo-server` integration tests), `denied_call_is_not_charged`, `charge_and_audit_append_commit_together` (the charge is refunded when the append fails), `unreadable_counters_deny` and `negative_or_string_amount_is_refused` (pipeline unit tests), and `token_budget_cannot_be_approved_past` (`attenuo-policy`).

## Pros and Cons of the Options

### Limits per token hop, charged against every matching hop

- Good, because one mechanism gives run budgets (limits on hop 0), sub-agent shares (limits on later hops) and protection against re-delegation.
- Good, because maxima are in the signed token, so a PEP or auditor can see what a hop was allowed without asking the server.
- Bad, because charging every ancestor means one write per limited hop per call, and every exchange under a limited parent reads the parent's counters.
- Bad, because overbooking means a child can be refused although its own figure is not spent, when a sibling spent the parent's budget first.

### Per-run budgets only, in configuration or policy

- Good, because it needs no token change and can apply defaults to every run.
- Bad, because a parent cannot give a sub-agent less than the whole run's budget, which is the case the RFC's narrowing is for.
- Bad, because the figure is a deployment constant, not something the user states for this task. It survives in the chosen design as phase 2's `context.usage` policy input, for defaults.

### Per-hop budgets with reservation

- Good, because each child has a guaranteed share and siblings never refuse each other.
- Bad, because budget is stranded in children that never spend, every exchange writes the parent's counter, and ending or revoking a child's lease needs a return path. Can be added later as an opt-in without changing the call path.

### Per-user rate windows

- Good, because it bounds a user's agents across runs, which per-run budgets do not.
- Bad, because it is rate limiting, which RFC-0001 section 8 leaves to gateways, and the corpus has no time dimension to measure it on. It is about the user, not the delegation.

### No new mechanism

- Good, because `equals` on `amount` already catches `banking-04`'s inflated first transfer when the grant pins it.
- Bad, because a pin cannot catch an identical repeat (`t-banking-05`, `banking-11`), and revocation stops a repeat only when the user notices.

## More Information

- Design, corpus table and open questions: [design/run-limits.md](../design/run-limits.md).
- Accepted 2026-10-24, after phases 1 and 2 were built and measured. Decision Outcome and Consequences were rewritten in the accepting change to state what was built and measured; Considered Options and Pros and Cons are as proposed.
- Implementation, all 2026-10-24: phase 1 (#50), the `sum` sync follow-up (#56), run usage and soft limits (#59), usage kept only when something reads it (#60), `distinct`, URL-host destinations, SDK limits and console budgets (#61), and the CLI's refund and lease-tree budgets (#64). Deviations from the design text: [design section 6](../design/run-limits.md#6-phased-plan). Suite runs: #51, #57, #59, #62 and #63, summarised in [design section 7](../design/run-limits.md#7-measured).
- Related: [ADR-0005](0005-policy-decision-point.md) (capabilities before Cedar), [ADR-0006](0006-lease-based-in-flight-revocation.md) (leases, where counters live), [ADR-0009](0009-output-labelling.md) (approvals, `@obligation("approval")`, run state keyed by `chain_id`), RFC-0001 sections 2, 3, 3.1, 8 and 9.
- Prior work: AgentGate's budget-limited capability tokens and AWS AgentCore Policy's Dogwood ([related work](../research/related-work.md)), [AP2 Intent Mandates](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol), [Macaroons](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/), [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html).
- Revisit after phase 1 is measured: if the new multi-call cases show benign losses under the frozen rule, phase 2's per-destination and soft limits move ahead of any default; if order dependence dominates on a model-in-the-loop run, combine counts with taint (count only after an untrusted read). Outcome at acceptance: the multi-call cases showed the loss, and the design now recommends soft limits over run usage and no default `max` ([what an operator should set](../design/run-limits.md#what-an-operator-should-set)). No model-in-the-loop run has been made, so combining counts with taint stays open (design open question 1).
