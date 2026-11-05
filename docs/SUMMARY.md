# Summary

[Overview](README.md)

# Getting started

- [Guides](guides/README.md)
  - [Getting started](guides/getting-started.md)
  - [Integrating MCP clients](guides/integrating-mcp-clients.md)
  - [Binding tokens to keys](guides/binding-tokens-to-keys.md)
  - [Admin console](guides/admin-console.md)
- [Codebase walkthrough](guide/codebase-walkthrough.md)

# Concepts

- [Concepts](concepts/README.md)
  - [Delegation chain](concepts/delegation-chain.md)
  - [Capabilities and attenuation](concepts/capabilities-and-attenuation.md)
  - [Leases and revocation](concepts/leases-and-revocation.md)
  - [Audit log](concepts/audit-log.md)
  - [Enforcement points](concepts/enforcement-points.md)

# Specification

- [Specs and the RFC process](spec/README.md)
  - [RFC-0001: attenuo](spec/rfc-0001-attenuo.md)
  - [Threat model](spec/threat-model.md)

# Design

- [Server request pipeline](design/server.md)
- [Performance](design/performance.md)
  - [End-to-end benchmark, 2026-10-23](design/bench/2026-10-23-vm.md)
- [Fuzzing](design/fuzzing.md)
  - [Fuzzing, round 2](research/fuzzing-2026-10-24-round2.md)
- [Admin console](design/admin-console.md)
- [Output labelling (proposed)](design/output-labelling.md)
- [Run limits](design/run-limits.md)
- [Cedar-aware list filtering (proposed)](design/cedar-aware-list-filtering.md)

# Policy

- [Writing and testing policies](guides/writing-policies.md)

# Operations

- [Deploying](guides/deploying.md)
- [Identity providers](guides/identity-providers.md)

# Reference

- [Reference](reference/README.md)
  - [CLI commands](reference/cli.md)
  - [Configuration keys](reference/config.md)
  - [HTTP endpoints](reference/http-api.md)
  - [AuthZEN conformance](reference/authzen.md)

# Decisions

- [Architecture decision records](decisions/README.md)
  - [ADR template](decisions/0000-adr-template.md)
  - [ADR-0001: Separate enforcement layer](decisions/0001-separate-enforcement-layer.md)
  - [ADR-0002: Cedar for policy](decisions/0002-cedar-for-policy.md)
  - [ADR-0003: Apache License 2.0](decisions/0003-apache-2-license.md)
  - [ADR-0004: Rust workspace layout](decisions/0004-rust-workspace-layout.md)
  - [ADR-0005: Policy decision point](decisions/0005-policy-decision-point.md)
  - [ADR-0006: Lease-based revocation](decisions/0006-lease-based-in-flight-revocation.md)
  - [ADR-0007: Actor authentication](decisions/0007-actor-authentication.md)
  - [ADR-0008: Admin console](decisions/0008-admin-console.md)
  - [ADR-0009: Output labelling](decisions/0009-output-labelling.md)
  - [ADR-0010: Run limits](decisions/0010-run-limits.md)
  - [ADR-0011: Cedar-aware list filtering](decisions/0011-cedar-aware-list-filtering.md)

# Research

- [Standards](research/standards.md)
- [Incidents 2025-2026](research/incidents-2025-2026.md)
- [Related work](research/related-work.md)
- [Evaluation plan](research/evaluation-plan.md)
  - [Injection suite, first results](evaluation/injection-suite.md)
- [Security review, pass 1](research/security-review-2026-10-22.md)
  - [Security review, pass 3](research/security-review-2026-10-23.md)
  - [Security review, pass 4](research/security-review-2026-10-23-pass4.md)
  - [Security review, pass 5](research/security-review-2026-10-24-pass5.md)
- [Open-source project practices](research/oss-project-practices.md)
- [Secret scan of the full history, 2026-11-05](research/secret-scan-2026-11-05.md)

# Project

- [FAQ](faq.md)
- [Comparison with alternatives](comparison.md)
- [Launch checklist](launch-checklist.md)
  - [Release 0.1.0](release/0.1.0.md)
- [Changelog](project/changelog.md)
- [Security policy](project/security.md)
- [Task board](tasks/board.md)
- [Milestones](tasks/milestones.md)
- [Engineering log: 2026-10-22](log/2026-10-22.md)
- [Engineering log: 2026-10-23](log/2026-10-23.md)
- [Engineering log: 2026-10-24](log/2026-10-24.md)
- [Engineering log: 2026-10-25](log/2026-10-25.md)
- [Engineering log: 2026-11-05](log/2026-11-05.md)
