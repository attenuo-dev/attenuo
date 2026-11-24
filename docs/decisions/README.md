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
| [0004](0004-rust-workspace-layout.md) | Rust workspace layout | accepted (amended 2026-11-06) |
| [0005](0005-policy-decision-point.md) | Policy decision point: capabilities first, then Cedar with a generated schema | accepted |
| [0006](0006-lease-based-in-flight-revocation.md) | Lease-based in-flight revocation | accepted |
| [0007](0007-actor-authentication.md) | Actor authentication: RFC 8693 `actor_token` from a workload-identity issuer, with `may_act` | accepted |
| [0008](0008-admin-console.md) | Admin console: vanilla static files embedded in `attenuo-server`, on a separate opt-in listener, admin token held in page memory | accepted |
| [0009](0009-output-labelling.md) | Output labelling: the proxy labels every upstream result untrusted, taints the delegation run, and policy can require a call-bound approval for destructive tools | accepted |
| [0010](0010-run-limits.md) | Run limits: count and amount budgets declared per token hop, charged against every hop of the chain in the decision's transaction, and exposed to Cedar as context | accepted |
| [0011](0011-cedar-aware-list-filtering.md) | Cedar-aware list filtering: opt in, hide a tool only when the policy denies it for every possible call, with approval-gated tools always kept | accepted |
| [0012](0012-opentelemetry-export.md) | OpenTelemetry export: allow-listed decision spans over OTLP/HTTP, off by default, linked not adopted, joined to the signed record by decision id | accepted |
| [0013](0013-admin-api-listener.md) | Admin API listener: `/admin/*` on an opt-in listener of its own, and refused on a main listener off loopback unless the operator opts in | proposed |
| [0014](0014-request-limits.md) | Request limits: an in-flight cap and deadlines on by default, per-run and per-agent rate limits in process and off by default | proposed |
| [0015](0015-audit-retention.md) | Audit retention: archive a prefix of the log at a signed checkpoint, prune it in the server behind a signed anchor, off by default | accepted |
| [0016](0016-admin-operators.md) | Admin operators: named admin bearer tokens stored as SHA-256 digests, three fixed roles checked from one route table, and the operator recorded as the actor | proposed |
| [0017](0017-private-key-jwt.md) | Client authentication with `private_key_jwt`: public keys inline in `[[agents]]` and `[[peps]]`, `aud` fixed to the issuer identifier, and every assertion used once | proposed |
| [0018](0018-native-tls-listener.md) | Native TLS on the main listener: optional `[server.tls]`, TLS 1.3 only, read at start, no client certificates yet | proposed |

Add a row for each new ADR.
