# Summary

[Overview](README.md)

# Getting started

- [Guides](guides/README.md)
  - [Getting started](guides/getting-started.md)
  - [Integrating MCP clients](guides/integrating-mcp-clients.md)
  - [Binding tokens to keys](guides/binding-tokens-to-keys.md)
  - [Admin console](guides/admin-console.md)
  - [Observability](guides/observability.md)
- [Demo recordings](demo/README.md)

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
  - [Fuzzing, round 3](research/fuzz-round-3-2026-10-25.md)
- [Lean proof of the covering rule](design/lean-proof.md)
- [Admin console](design/admin-console.md)
- [Output labelling](design/output-labelling.md)
- [Run limits](design/run-limits.md)
- [Cedar-aware list filtering (built, opt-in)](design/cedar-aware-list-filtering.md)
- [Multi-replica readiness (proposed)](design/multi-replica.md)
- [OpenTelemetry export (built, off by default)](design/otel-export.md)
- [Run limits phase 3 (proposed, step 1 built)](design/run-limits-phase3.md)
- [Read-side exfiltration (proposed, steps 1 and 2 built)](design/read-side-exfiltration.md)
- [Audit retention (proposed)](design/audit-retention.md)

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
  - [API compatibility](reference/api-compatibility.md)

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
  - [ADR-0012: OpenTelemetry export](decisions/0012-opentelemetry-export.md)
  - [ADR-0013: Admin API listener](decisions/0013-admin-api-listener.md)
  - [ADR-0014: Request limits](decisions/0014-request-limits.md)
  - [ADR-0015: Audit retention](decisions/0015-audit-retention.md)
  - [ADR-0016: Admin operators](decisions/0016-admin-operators.md)
  - [ADR-0017: Client authentication with private_key_jwt](decisions/0017-private-key-jwt.md)

# Research

- [Standards](research/standards.md)
- [Incidents 2025-2026](research/incidents-2025-2026.md)
- [Related work](research/related-work.md)
- [Evaluation plan](research/evaluation-plan.md)
  - [Injection suite, first results](evaluation/injection-suite.md)
  - [Reproducing the numbers](evaluation/reproduce.md)
  - [AgentDojo evaluation plan](research/agentdojo-plan-2026-11-05.md)
  - [AgentDojo with planner-written grants](evaluation/agentdojo-planner-grants.md)
  - [AgentDojo with a local open-weight model](evaluation/agentdojo-local-model.md)
- [Security review, pass 1](research/security-review-2026-10-22.md)
  - [Security review, pass 3](research/security-review-2026-10-23.md)
  - [Security review, pass 4](research/security-review-2026-10-23-pass4.md)
  - [Security review, pass 5](research/security-review-2026-10-24-pass5.md)
  - [Security review, pass 6](research/security-review-2026-10-25-pass6.md)
  - [Security review, pass 7](research/security-review-2026-10-25-pass7.md)
  - [Security review, pass 8](research/security-review-2026-11-05-pass8.md)
  - [Security review, pass 9](research/security-review-2026-11-06-pass9.md)
  - [Security review, pass 10](research/security-review-2026-11-06-pass10.md)
  - [Security review, pass 11](research/security-review-2026-11-12-pass11.md)
  - [Security review, pass 12](research/security-review-2026-11-13-pass12.md)
  - [Security review, pass 13](research/security-review-2026-11-13-pass13.md)
  - [Security review, pass 14](research/security-review-2026-11-14-pass14.md)
  - [Security review, pass 15](research/security-review-2026-11-14-pass15.md)
  - [Security review, pass 16](research/security-review-2026-11-14-pass16.md)
  - [Security review, pass 17](research/security-review-2026-11-14-pass17.md)
  - [Security review, pass 18](research/security-review-2026-11-15-pass18.md)
- [Open-source project practices](research/oss-project-practices.md)
- [Secret scan of the full history, 2026-11-05](research/secret-scan-2026-11-05.md)
- [CI minutes, 2026-11-05](research/ci-minutes-2026-11-05.md)
- [Code-quality pass, 2026-11-05](research/code-quality-2026-11-05.md)
- [Spec and reference audit, 2026-11-05](research/spec-audit-2026-11-05.md)

# Report

- [Technical report, 2026-11](report/attenuo-2026-11.md)

# Project

- [FAQ](faq.md)
- [Comparison with alternatives](comparison.md)
- [Release 0.1.0](release/0.1.0.md)
- [Changelog](project/changelog.md)
- [Security policy](project/security.md)
