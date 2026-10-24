---
status: proposed
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

Chosen option: "Limits declared per token hop, charged against every matching hop", because it is the only option that lets a parent hand a sub-agent a smaller share and still bounds the whole run: hop 0's lease is the `chain_id`, so a root limit is the run budget, and charging every ancestor stops both laundering by re-delegation and overspending by concurrent siblings. By a reading of the cases it denies 5 of the 10 dev and 5 of the 7 test attack calls allowed today, with no benign call lost on either split.

The mechanism, in outline (details in the design):

1. A capability gains optional `limits`: `calls` (count), `sum` (total of a non-negative integer argument), `calls_per` (count per distinct value of an argument), and in phase 2 `distinct` (number of distinct values). Maxima are static numbers in the token; used amounts are server state in the lease store.
2. Narrowing: in `covers`, a child under a limited parent must carry the same limit with a `max` no larger (static, checked by `validate_at`); `Issuer::exchange` clamps the child's figure to the parent's remaining budget at exchange time; at call time every ancestor is charged too. Siblings may be promised more in total than the parent has; they cannot spend it.
3. The limit check runs in the capability stage, before Cedar, with reason `budget_exhausted` (also `budget_error` for unreadable counters and `limit_arg_invalid` for a missing, non-integer or negative summed argument). Re-check, increment and the decision's audit append are one transaction. Denied calls cost nothing; allowed calls are counted even if the upstream fails; only an operator can refund one decision's charge, through the admin API, audited.
4. Cedar sees `context.budget.{limited, calls_remaining, amount_remaining, destination_new}` and, from phase 2, per-run usage `context.usage.{calls, amount, destination_seen}`, all always present. Token limits are hard and cannot be approved past. Policy limits over `context.usage` deny by default and may ask with `@obligation("approval")`; an approval passes one call, with no top-up.

### Consequences

- Good, because repetition and amount attacks inside a permitted call stop without a person: the approve-all bound with labels and limits drops from 10/60 to 5/60 dev and from 7/38 to 2/38 test, and approval requests from 27 to 22 and 8 to 3, by a reading of the cases.
- Good, because a sub-agent's share is a token fact that narrows like every other, and a run budget cannot be reset by delegating.
- Good, because every allowed call's record says which budgets it drew on and what was left.
- Bad, because a count bounds how many, not which: 6 of the 10 calls caught depend on the benign call coming first in the script. With the attack first, the attack passes and the legitimate call is refused.
- Bad, because a limited call adds a counter write to the decision transaction, which today spans two connections, and a `sum` charge should sync to disk like a revocation; both cost latency that needs measuring.
- Bad, because the number is only as good as the hop that sets it. A planner that has already read injected content can mint a generous budget.
- Neutral, because the corpus cannot measure the benign cost: no case has a task that needs two allowed calls of one destructive tool. Cases that do are added before phase 1 is measured.
- Neutral, because per-user windows across runs, and rate limits in general, stay out of scope (RFC-0001 section 8) until a later decision.

### Confirmation

When implemented: new injection-suite arms `attenuo_limits` and `attenuo_labels_limits` that apply a frozen rule (`calls: 1` on every non-read-only capability of a grant) instead of per-case values, with new multi-call benign cases on dev and new test cases written after the rule is frozen; report attack calls allowed, the approve-all bound, approval requests and benign calls denied per split. Integration and property tests to name the properties: `child_limit_never_exceeds_parent_limit` (proptest over `covers`), `exchange_clamps_child_budget_to_parent_remaining`, `call_is_charged_to_every_ancestor_hop`, `redelegation_does_not_reset_budget`, `concurrent_siblings_cannot_overspend_parent`, `denied_call_is_not_charged`, `upstream_failure_is_still_charged`, `charge_and_audit_append_commit_together`, `unreadable_counters_deny`, `negative_or_string_amount_is_refused`, `refund_is_admin_only_and_once_per_decision`, `token_budget_cannot_be_approved_past`.

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
- Related: [ADR-0005](0005-policy-decision-point.md) (capabilities before Cedar), [ADR-0006](0006-lease-based-in-flight-revocation.md) (leases, where counters live), [ADR-0009](0009-output-labelling.md) (approvals, `@obligation("approval")`, run state keyed by `chain_id`), RFC-0001 sections 2, 3, 3.1, 8 and 9.
- Prior work: AgentGate's budget-limited capability tokens and AWS AgentCore Policy's Dogwood ([related work](../research/related-work.md)), [AP2 Intent Mandates](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol), [Macaroons](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/), [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html).
- Revisit after phase 1 is measured: if the new multi-call cases show benign losses under the frozen rule, phase 2's per-destination and soft limits move ahead of any default; if order dependence dominates on a model-in-the-loop run, combine counts with taint (count only after an untrusted read).
