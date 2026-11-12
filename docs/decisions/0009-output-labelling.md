---
status: accepted
date: 2026-10-24
decision-makers: [7Mudit]
consulted: []
informed: []
---

# ADR-0009. Output labelling: the proxy labels every upstream result untrusted, taints the delegation run, and policy can require a call-bound approval for destructive tools

## Context and Problem Statement

The [injection suite](../evaluation/injection-suite.md) leaves 10 of 60 dev and 7 of 38 test attack calls allowed under full enforcement. They are "allowed tool, harmful intent" calls: the tool and arguments are ones the task needs, so neither the token's capabilities nor a static Cedar policy can separate them (`workspace-06`, `travel-02`, `t-workspace-05`). What they share is provenance: the harmful decision or value came from a tool result the proxy relayed earlier. attenuo keeps no link between a result and later calls. How should attenuo use what it sees of tool results to constrain later destructive calls, given that it cannot see inside the model and most agents will be unmodified MCP clients? Design: [design/output-labelling.md](../design/output-labelling.md).

## Decision Drivers

- Must work for agents that use no attenuo SDK (the proxy sees results and calls, nothing else).
- Must fail closed: a lost label or unreadable taint state must not make a call look clean.
- Must not let anything the agent controls exempt a call. Agent-supplied labels and MCP annotations from untrusted servers may only add restrictions.
- The decision stays in Cedar, after the capability and lease stages, and an approval never widens a token.
- Every label and approval must be auditable with provenance (audit `seq`), consistent with RFC-0001 section 7.
- The benefit and the cost (approval requests on benign calls) must be measurable on the injection suite.

## Considered Options

- Session-level taint per delegation run, enforced at the proxy, with call-bound approvals (option a of the design).
- Argument-level taint only: match destructive-call arguments against fingerprints of recent results (option b).
- SDK-side labelled values only, enforced in the agent and reported to the proxy (option c).
- No labelling: keep information flow out of scope (RFC-0001 open question 5) and rely on count limits and per-task policy.

## Decision Outcome

Chosen option: "Session-level taint per delegation run, with call-bound approvals", as phase 1, with argument-level matching as phase 2 and SDK labelled values as phase 3, because it is the only option that needs nothing from the agent, it fails closed by construction (taint is monotone, missing state counts as tainted), and by a reading of the cases it gates 9 of the 10 dev misses. Options b and c refine it and are layered on it, not chosen instead of it.

The mechanism, in outline (details in the design):

1. Every response to a mediated method is recorded as a `tool_result` audit entry (digest, not content) and adds an `untrusted` label `{source, decision_id, seq}` to the run's taint state, keyed by `chain_id`. A catalog entry can mark a tool's output trusted. If the label cannot be recorded, the result is not delivered (`label_error`).
2. The catalog gains `destructive` (default `!readonly`, matching MCP's default `destructiveHint`). MCP annotations may be imported only to narrow.
3. Cedar gains `resource.destructive`, `context.session.tainted`, `context.session.tainted_by`, `context.args_contain_untrusted`, `context.untrusted_args` and `context.approval`. A forbid annotated `@obligation("approval")` yields `approval_required` instead of `policy_deny` when it is the only kind of forbid that applied.
4. An approval is bound to `SHA-256(JCS({server, tool, arguments}))`, the run and the calling hop's lease. It is granted by the originating user through their IdP or by an operator through the admin console, never through the agent; it is single use, expires within 120 s or with the lease, and is bound to the agent's DPoP key when the token is bound.

### Consequences

- Good, because class N calls that follow an untrusted read stop running on the model's say-so, for any MCP client, with no agent change.
- Good, because every destructive call's decision record says which results the run had read and who approved it.
- Bad, because approvals land on benign calls too: about 18 of the 66 allowed dev benign calls by a reading of the cases. The gain is only as good as the approver; an approver who approves everything restores today's behaviour.
- Bad, because every allowed call that returns adds an audit append and a taint update to the hot path.
- Bad, because run-scoped taint misses flows across runs (data written in one run and read in the next) and does nothing for harmful reads or covert channels.
- Neutral, because count and rate limits, not labels, are what the repeated-payment and inflated-amount misses need; that stays a separate item.
- Neutral, because confidentiality labels (where private data may flow) use the same machinery and are left to a later decision.

### Confirmation

When implemented: a new injection-suite arm `attenuo+labels` with per-call upstream outputs and a scripted approver, reporting attack calls allowed without approval and the benign approval rate per split, with policies frozen before the run. Integration tests to name the properties: `denied_call_result_does_not_taint`, `taint_is_shared_across_hops_of_a_run`, `unrecordable_label_withholds_the_result`, `approval_is_bound_to_the_exact_arguments`, `approval_is_single_use`, `revoked_lease_kills_pending_and_granted_approvals`, `agent_supplied_labels_cannot_exempt_a_call`, `annotation_import_only_narrows`.

## Pros and Cons of the Options

### Session-level taint per run, with call-bound approvals

- Good, because it needs only the results and calls the proxy already relays.
- Good, because it is simple to state and to verify: once tainted, destructive calls need approval.
- Bad, because it is coarse: every destructive call after any read asks, including the ones the task plainly needs.
- Bad, because exempting calls with a token-pinned destination, the obvious way to cut the asks, also exempts most class N attacks, whose destination is right by construction.

### Argument-level taint only

- Good, because it asks only when an argument carries a verbatim span of untrusted output, about 10 of 66 dev benign calls by a reading of the cases, and names the source.
- Bad, because a miss means "no verbatim copy", not "clean": paraphrase and decisions taken from data (which hotel to book) leave no trace, so on its own it would fail open.
- Bad, because the span index adds per-run state and tuning parameters (minimum length, k-gram size, entity patterns).

### SDK-side labelled values only

- Good, because labels on values are precise where values pass through agent code, in the style of CaMeL and FIDES.
- Bad, because it covers only agents built on the SDK, and labels are lost whenever text passes through the model.
- Bad, because the proxy cannot verify SDK labels; they can add restrictions but cannot be the only control.

### No labelling

- Good, because it adds no state, cost or user interaction.
- Bad, because the class N misses stay allowed, and the threat model's "needs information-flow labels" stays a sentence with no design behind it.

## More Information

- Design and false-positive analysis: [design/output-labelling.md](../design/output-labelling.md).
- Related: [ADR-0005](0005-policy-decision-point.md) (capabilities before Cedar), [ADR-0006](0006-lease-based-in-flight-revocation.md) (leases, which bound approvals), [ADR-0008](0008-admin-console.md) (operator approval surface), RFC-0001 sections 4.1, 7 and 9.
- Prior work: [CaMeL](https://arxiv.org/abs/2503.18813), [FIDES](https://arxiv.org/abs/2505.23643), [f-secure LLM system](https://arxiv.org/abs/2409.19091), [Flume](https://www.read.seas.harvard.edu/~kohler/pubs/krohn07information.pdf), [MCP tool annotations](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/).
- The title predates the catalog's `output = "trusted"` setting, which exempts a tool's results from the untrusted label.
- Revisit after phase 1 is measured: if the benign approval rate on a model-in-the-loop run is far above the corpus estimate, phase 2 moves ahead of any rollout; if MCP standardises trust or sensitivity annotations, map them narrowing-only.
- Amended 2026-11-06 (`feat/outbound-catalog-flag`): decision item 3's list gains `resource.outbound` (the catalog names an `outbound` input for the tool) and `context.untrusted_outbound` (an argument in `context.untrusted_args` is outbound, `unreadable` included), both always present. A policy that reads `context.untrusted_outbound` turns on matching for every call as the other two argument-taint members do. `openWorldHint` is not imported. See the [read-side exfiltration design](../design/read-side-exfiltration.md#d-a-catalog-flag-that-marks-an-argument-outbound).
