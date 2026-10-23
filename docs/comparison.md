# onbehalf compared with the alternatives

Last reviewed 2026-10-23.

This page puts onbehalf next to the things people usually weigh it against. It is built only from the public sources collected in [related work](research/related-work.md) and [standards](research/standards.md), as of the dates in those files. We did not test the other products. Where those notes do not say, the cell says "unknown". These tools change, and corrections are welcome as issues.

Most of these are not competitors. A gateway, a policy engine, an IdP and a workload identity system each do a different job, and several of them fit together with onbehalf. The last section says how.

## The table

Legend: **Yes** is a built-in feature. **No** means the category does not do this by design or scope. **Partial** means some of it, or it depends on configuration. **n/a** means the question does not apply. **Unknown** means our sources do not say.

| | onbehalf (v0) | OAuth scopes alone | API and MCP gateways | Policy engines used directly | IdP agent features | Workload identity |
| --- | --- | --- | --- | --- | --- | --- |
| Examples | this project | OAuth 2.1 as MCP uses it | AgentGateway, Pomerium, Envoy `ext_authz`, Kong | Cedar, OPA, Cerbos, OpenFGA, SpiceDB | Okta Cross App Access (ID-JAG), Microsoft Entra Agent ID, Auth0 for AI agents | SPIFFE, SPIRE |
| Delegation chain with attenuation | Yes: the verified user and every agent in each token, each hop only narrower | No: scopes carry nothing about hops (RFC 8693 `act` claims can record actors, but say nothing about narrowing) | No | No | Unknown. ID-JAG is one hop in one trust domain | No: identifies the workload, not the user or the delegation |
| Per-call policy on arguments | Yes: capability check, then Cedar with the call's arguments | No: scopes are fixed at issue time and cannot see arguments | Partial: Envoy can call an external authorizer on each request, and AgentGateway has CEL-based RBAC. Pomerium: unknown | Yes: this is what they do. You supply the request and the enforcement point | Unknown | No |
| In-flight revocation | Yes: leases, checked on every call, cascading to descendants | Partial: short expiry, and token revocation where the server supports it | Unknown: depends on the authorizer behind it | Partial for OpenFGA and SpiceDB (a deleted relationship applies at the next check, with no notion of a run). No for Cerbos and OPA | Unknown | Partial: short-lived credentials |
| Verifiable audit | Yes: hash chain, signed checkpoints. Catching truncation needs a checkpoint copied off the host | No | No for Kong and Envoy. Unknown for AgentGateway and Pomerium | Unknown: Cerbos and OPA have decision logs, but tamper evidence is not known | Unknown | No |
| IdP neutrality | Yes: any OIDC issuer (tested only against locally signed tokens) | Yes | Yes: JWT and OAuth for AgentGateway; Kong and Envoy are generic | Yes | No: each works with its own IdP | n/a: workload identity, not user login |
| Self-hosted | Yes | n/a | Yes | Yes | No: hosted products | Yes |
| MCP-native | Yes for tool calls, through its proxy or the AuthZEN endpoint | Yes at the transport: MCP servers are OAuth 2.1 resource servers. Per-call decisions are left to the server or a gateway | AgentGateway: yes, an MCP and A2A proxy. Envoy and Kong: generic HTTP | No: not in the request path | Partial: ID-JAG was folded into MCP as an enterprise authorization extension. Others: unknown | No: not MCP-specific |

## Reading the columns

**OAuth scopes alone.** MCP's authorization model is OAuth 2.1, and onbehalf keeps it: it uses RFC 8693 token exchange and your IdP for login. What scopes lack is a slot for the human across hops, argument-level control, and a way to pull back a token mid-run. See the [FAQ](faq.md#why-not-just-use-oauth-scopes).

**Gateways.** A gateway authenticates and routes. Envoy's `ext_authz` and similar hooks let it ask an external authorizer per request, so a gateway can enforce what onbehalf decides. onbehalf speaks AuthZEN, not the `ext_authz` protocol, so an adapter would be needed and has not been built or tried. AgentGateway is an MCP and A2A proxy under the Linux Foundation with CEL-based RBAC; our sources show no per-hop narrowing in it. Pomerium is not covered in our research notes, so its cells are unknown.

**Policy engines.** Cedar, OPA, Cerbos and the relationship stores OpenFGA and SpiceDB answer "may this happen". onbehalf uses Cedar for that step. They do not issue delegation tokens, check attenuation, hold leases or sit in the request path, and onbehalf adds those.

**IdP agent features.** Okta ships ID-JAG (its Cross App Access); in our sources Microsoft Entra Agent ID does not. These products issue and manage agent identities. We could not confirm what any of them enforce per call or how they revoke mid-run, so those cells are unknown. onbehalf accepts an ID-JAG or an OIDC ID token as the first credential in a chain, and has been run only against assertions its own tests sign.

**Workload identity.** SPIFFE and SPIRE give each workload a verifiable identity. They say who the caller is, not whom it acts for. v0 takes an agent's `actor` from a client secret; an actor token from a SPIFFE issuer is supported but not exercised in the demo.

## How they fit together

- Keep your IdP and OAuth. onbehalf starts from the ID token or ID-JAG it issues.
- Keep your gateway. Put onbehalf behind it as the decision point over AuthZEN once someone writes the adapter, or use onbehalf's own proxy where there is no gateway.
- Your existing policy engine does not carry over: onbehalf's policy stage is Cedar and nothing else today.
- Add workload identity to prove which agent is calling.

Further reading: [FAQ](faq.md), [related work](research/related-work.md), [standards](research/standards.md), [RFC-0001](spec/rfc-0001-onbehalf.md).
