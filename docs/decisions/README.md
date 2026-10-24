# Architecture Decision Records

An ADR records one architecturally significant decision: the problem, the options that were on the table, what was chosen, and why. ADRs are short and they are never rewritten once accepted; if a decision changes, a new ADR supersedes the old one.

We use the [MADR 4](https://adr.github.io/madr/) template. Start from [`0000-adr-template.md`](0000-adr-template.md).

## When to write one

Write an ADR when a choice is hard to reverse or affects more than one crate: a dependency that becomes part of the public surface (policy engine, token format, storage), a security invariant and how it is enforced, a change to the module boundaries, a convention everyone must follow. Small, local, easily reversible choices go in the PR description instead.

Anything that changes the wire format or public API needs an RFC first (see [`../spec/README.md`](../spec/)). An RFC often produces one or more ADRs for the decisions made along the way.

## Process

1. Pick the next free number. Numbers are sequential, four digits, zero-padded. Check open PRs so two ADRs do not claim the same number; if they collide, the second one to merge renumbers.
2. Copy the template to `NNNN-short-title-with-dashes.md`. The title is a noun phrase that names the decision, for example `0003-use-cedar-for-policy-evaluation.md`.
3. Open one pull request per ADR with status `proposed`. Discussion happens on that PR. Keep implementation out of the same PR unless the ADR is trivially small and the code is the only way to evaluate it.
4. When the maintainers agree, set `status: accepted`, update `date`, and merge. If the decision is turned down, set `status: rejected` and still merge: a rejected ADR is useful history.
5. Reference the ADR number in commits and PRs that implement it (`Refs: ADR-0003`).

## Status lifecycle

```
proposed ──► accepted ──► deprecated
    │            │
    │            └──► superseded by ADR-NNNN
    └──► rejected
```

- `proposed`: open for discussion, not yet binding.
- `accepted`: binding. Code that contradicts it needs a superseding ADR.
- `rejected`: considered and declined; kept for the record.
- `deprecated`: no longer relevant (the component it concerned is gone) and nothing replaced it.
- `superseded by ADR-NNNN`: replaced by a newer decision. The new ADR links back under More Information.

Only the `status` and `date` fields and the More Information section of an accepted ADR may be edited afterwards. Everything else is frozen.

## Index

| ADR | Title | Status |
| --- | --- | --- |
| 0000 | ADR template | n/a |
| [0001](0001-separate-enforcement-layer.md) | Enforce delegation and per-call authorization in a separate layer | accepted |
| [0002](0002-cedar-for-policy.md) | Cedar as the policy language, with ReBAC composed from outside | accepted |
| [0003](0003-apache-2-license.md) | Apache License 2.0 | accepted |
| [0004](0004-rust-workspace-layout.md) | Rust workspace layout | accepted |
| [0005](0005-policy-decision-point.md) | Policy decision point: capabilities first, then Cedar with a generated schema | proposed |
| [0006](0006-lease-based-in-flight-revocation.md) | Lease-based in-flight revocation | proposed |
| [0007](0007-actor-authentication.md) | Actor authentication: RFC 8693 `actor_token` from a workload-identity issuer, with `may_act` | proposed |
| [0008](0008-admin-console.md) | Admin console: vanilla static files embedded in `attenuo-server`, on a separate opt-in listener, admin token held in page memory | proposed |
| [0009](0009-output-labelling.md) | Output labelling: the proxy labels every upstream result untrusted, taints the delegation run, and policy can require a call-bound approval for destructive tools | proposed |
| [0010](0010-run-limits.md) | Run limits: count and amount budgets declared per token hop, charged against every hop of the chain in the decision's transaction, and exposed to Cedar as context | accepted |

Add a row for each new ADR.
