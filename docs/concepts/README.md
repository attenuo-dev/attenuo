# Concepts

Five short pages that explain the ideas behind attenuo. Read them in order if you are new. Each one points to the spec section and the design note that hold the full detail.

| Page | What it explains |
| --- | --- |
| [Delegation chain](delegation-chain.md) | How a token records who the agent acts for, and every agent between that person and the call |
| [Capabilities and attenuation](capabilities-and-attenuation.md) | What a token lets its holder do, and why a sub-agent can only get less |
| [Leases and revocation](leases-and-revocation.md) | How authority that was already handed out is withdrawn |
| [Audit log](audit-log.md) | What is recorded for every decision and how tampering is detected |
| [Enforcement points](enforcement-points.md) | The two ways a call reaches the decision: the MCP proxy and the AuthZEN endpoint |

attenuo is pre-alpha. These pages describe what the code does today. Where the RFC describes something that is not built, the page says so.
