# ADR-0003: Apache License 2.0

- Status: accepted
- Date: 2026-10-22

## Context

onbehalf is security infrastructure meant to be embedded in gateways, deployed self-hosted in regulated environments, and used as a reference implementation against evolving standards. The licence shapes who can adopt it, which foundations can host it, and whether it can be composed with the building blocks it depends on.

- The pieces onbehalf composes with are Apache 2.0: Cedar, AgentGateway (a Linux Foundation project), SPIFFE, Firecracker and the other microVMs that a later sandbox layer would sit on ([agentgateway](https://github.com/agentgateway/agentgateway), [Linux Foundation](https://www.linuxfoundation.org/press/linux-foundation-welcomes-agentgateway-project-to-accelerate-ai-agent-adoption-while-maintaining-security-observability-and-governance), [emirb.github.io](https://emirb.github.io/blog/microvm-2026/)).
- Recent licence changes away from permissive terms in identity and infrastructure projects (Zitadel Apache to AGPL, the Redis and HashiCorp source-available moves) created the gaps that neutral replacements then filled ([Zitadel](https://zitadel.com/blog/apache-to-agpl), [ttlab](https://ttlab.hopto.org/blog/culture/2026-05-16-open-source-license-shifts-2026-bsl-wave-elastic-redis-hashicorp-sentry-valkey-opentofu-deep-dive?lang=en)).
- Foundation governance paths (for example Apache Incubator, which Iggy used) require a permissive, foundation-compatible licence ([Apache Incubator proposal](https://cwiki.apache.org/confluence/display/INCUBATOR/Iggy+Proposal)).
- Apache 2.0 includes an express patent grant and a patent-retaliation clause, which matters for a project in a space with active vendor consolidation ([NHI timeline](https://nhigovernance.com/market/nhi-market-timeline.html)).

## Decision

License the whole repository under the Apache License, Version 2.0. Contributions are accepted under the same licence (inbound = outbound); no CLA for now. Every crate declares `license = "Apache-2.0"`; the `LICENSE` file at the root is the only licence text.

## Consequences

- Positive: compatible with every dependency and host project in scope; usable in proprietary gateways and air-gapped deployments without legal review friction; eligible for foundation hosting.
- Positive: explicit patent grant.
- Negative: a hosted provider can run onbehalf as a service without contributing back. Accepted; the value of a reference monitor is adoption and interop, and a copyleft licence would reduce both.
- Negative: no CLA means relicensing later is impractical. Accepted deliberately; it is a commitment that the licence will not change.

## Alternatives considered

- **AGPL-3.0**: strongest protection against hosted forks, but blocks embedding in Apache-licensed gateways and foundation hosting, and is the move that recently pushed users away from other identity projects.
- **MIT / BSD-2**: equally permissive but without the explicit patent grant; Apache 2.0 is the norm for the ecosystem onbehalf joins.
- **BSL / source-available**: incompatible with being a neutral reference implementation.
- **MPL-2.0**: file-level copyleft adds review friction for embedders with little practical benefit here.
