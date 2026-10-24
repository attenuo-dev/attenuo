# FAQ

Short answers to the questions people ask first. Each links to where the long answer lives. attenuo is pre-alpha, and the answers describe what the code in this repository does today, not what is planned.

Statements about other products are our understanding from their public documentation. We have not run most of them. If one is wrong, please open an issue.

## Why not just use OAuth scopes?

Scopes are fixed when the token is issued, and they are coarse: `repo` or `issues:write`, not "create issues in `acme/api` only". They cannot see the arguments of a call. The token names the agent, and there is no standard place in it for the human the agent works for across several hops. And once a token is out, taking it back mid-run depends on the authorization server and on how long the token lives.

attenuo keeps OAuth where OAuth works. It uses RFC 8693 token exchange as the wire protocol and your IdP for login. It adds the pieces scopes lack: a verified originating user on every hop, capabilities that can only shrink at each hop, a policy check on the arguments of every call, and a lease you can revoke while the run is going. The long version is in [RFC-0001 section 1](spec/rfc-0001-attenuo.md#1-problem) and [the standards note](research/standards.md).

## Why a proxy, and not a change to an MCP SDK?

Because the enforcement point has to be somewhere the agent cannot edit. An SDK runs inside the agent's process. A prompt-injected or buggy agent controls that process, so a check there is advice. A proxy is a separate process with its own key and its own log, and the agent can only reach the tool through it.

A proxy also works for every client and server at once, in any language, with no change to either. The MCP specification does not say what a server should do about per-call authorization. A proxy does not have to wait for it to.

The cost is one more hop on the path, and that you must close the other routes to the tool. If the agent holds a direct API key, the proxy sees nothing. See [what attenuo does not prevent](spec/threat-model.md#what-attenuo-does-not-prevent).

## How is this different from an API gateway?

A gateway such as Kong or Envoy authenticates a caller and routes the request. It can call an external authorizer on each request (Envoy's `ext_authz` is one such hook). What it does not do by itself is understand who the agent is working for, how many agents the authority has passed through, or what each of them was allowed to hand on. It sees one bearer and applies rules to it.

attenuo is the part that answers those questions. It can sit behind a gateway as the policy decision point: it speaks the OpenID AuthZEN evaluation API at `POST /access/v1/evaluation`. Wiring a particular gateway to it would need an adapter that we have not written or tested. It also ships its own MCP proxy, for setups without a gateway. See [Using the AuthZEN endpoint](guides/integrating-mcp-clients.md#using-the-authzen-endpoint-from-a-non-mcp-pep).

## How is it different from Teleport or SPIRE?

Those two answer "who or what is this workload, and may it reach this system?". Teleport is an identity-aware access layer for infrastructure and issues short-lived credentials to people and machines. SPIRE issues cryptographic identities (SVIDs) to workloads. Both identify the caller.

attenuo answers a different question: "this caller is acting for Alice, through two other agents, with this much of Alice's authority, and may it make this call with these arguments right now?". The two layers fit together. SPIRE or similar could identify each agent, which would fix a gap in v0: the `actor` of an exchange is a name the caller asserts, not proven (see [known limits](design/server.md#known-limits-v0)). That integration is not built. Teleport's MCP Access does enforce per tool: roles list the tools a user or bot may call, by name, glob or regex. Its docs do not describe checks on a call's arguments or a narrowing chain across agents; its Delegated Identity for agents is in public beta. Details and sources are in the [comparison](comparison.md#product-notes) (checked 2026-10-24).

## How is it different from OpenFGA, SpiceDB, Cerbos or OPA?

Those are policy and authorization engines. You ask them a question and they answer. They are good at it, and attenuo uses one: Cedar, in-process, for the policy stage.

What an engine does not give you is everything around the question. It does not mint the tokens that carry a delegation chain, check that each hop only narrowed the one above, hold leases, sit in the request path, or keep a hash-chained log of the answers. attenuo supplies those, and calls the policy engine for the "may this call pass" step. A relationship store like OpenFGA or SpiceDB could later feed facts into the policy (who owns which repo). That is on the [task board](tasks/board.md) as later work, not built. A comparison table is in [related work](research/related-work.md#positioning-table).

## How is it different from Microsoft Agent 365 or other agent governance products?

Managed agent-governance products, from Microsoft (Entra Agent ID, Agent 365), Okta and Auth0, and others, give you agent identity, registries, policy and reporting inside a vendor's platform and tied to that vendor's identity system. As we understand them, they are hosted services.

attenuo is self-hosted, open source (Apache-2.0) and neutral about the IdP: it takes OIDC ID tokens from Keycloak, Okta, Entra, Google and others. It enforces at the tool call, not only at sign-in. You can run both: let the vendor own agent identity and registration, and let attenuo be the monitor in front of the tools. Which of these products enforce per tool call, or revoke in flight, we could not confirm from their documentation (checked 2026-10-24); the [comparison](comparison.md#product-notes) has what each documents, with sources.

## Does it slow calls down?

A little. On a shared 4-core development container the proxy adds about 0.4 to 0.8 ms per call at the median from one client; the breakdown is below.

The micro-benchmarks in [design/performance.md](design/performance.md) put the policy decision at about 12 to 13 microseconds when the per-chain request cache hits and 122 to 163 microseconds when it does not (the first call of a chain; one and three hops, [criterion output](design/bench/2026-10-23-vm-criterion-policy_stage.txt)), on a shared 4-core dev container. Checking an attenuation takes tens of nanoseconds to a few microseconds, and it happens at exchange time, not per call.

Those numbers leave out token verification, the lease lookup, the audit write and the hop to the tool server. The [end-to-end benchmark](design/performance.md#after-the-policy-stage-and-wal-work) measures them: from a single client, a `tools/call` through the proxy to a local echo upstream takes about 0.4 ms longer at p50 than calling the upstream directly for a one-hop token with the audit log in memory, and about 0.8 ms longer for a three-hop token with the log in a SQLite file at the default durability (425 to 771 microseconds across the four cells). Under [open-loop load](design/performance.md#exchange-throughput-lease-renewal-and-open-loop-arrivals-2026-10-23) at 500 to 2,000 calls per second the added p50 is 0.6 to 0.8 ms. Sustained closed-loop throughput on that container was about 860 to 1,770 allowed calls per second from one client and 4,000 to 6,650 at 8 to 32 clients at one hop, with the file store 6 to 30 percent below memory; p99 at 8 clients was 4 to 10 ms. Read every figure as plus or minus 20 percent, and see [Time by stage](design/performance.md#time-by-stage-of-a-proxied-call-2026-10-23) for where the time goes.

The caveats matter. The numbers come from a shared dev container with the load generator on the same cores, one run per cell and mostly closed-loop load, so read them as an order of magnitude, plus or minus 20 percent per cell. The audit write used to be the big one: before WAL mode and group commit, a file-backed log managed a few hundred calls per second. It now runs close to the in-memory store at `[audit] durability = "normal"`, which can lose the newest decisions on a power failure (never on a process crash). `durability = "full"` syncs every commit and costs throughput that depends on your disk; see the [deploy guide](guides/deploying.md). For an agent calling LLM-speed tools a millisecond is unlikely to be what you notice. Measure your own path with `scripts/bench-e2e.sh`.

## What happens when attenuo is down?

Calls fail. That is on purpose.

The proxy is the only route to the tool, so if it is down, nothing gets through. If it is up but cannot do its job, the answer is a deny: a lease store it cannot read, a policy error, or an audit write that fails (a full disk, for example) each turn into a denied call (`lease_error`, `policy_error`, `audit_error`). An action that cannot be recorded does not happen.

There is no high availability in v0. It is one process with one SQLite file. See [Deploying](guides/deploying.md#what-v0-is-and-is-not). Agents should treat a connection error to attenuo as "stop and tell someone", not as a reason to find another way in.

## Can I use it without MCP?

Yes, in two ways, one of which exists today.

`POST /access/v1/evaluation` is a plain AuthZEN endpoint. Any service that guards its own actions can send it the delegation token and a description of the action, and enforce the true or false that comes back. It uses the same lease check, capability check, Cedar policy and audit log as the MCP path. See [the AuthZEN section of the client guide](guides/integrating-mcp-clients.md#using-the-authzen-endpoint-from-a-non-mcp-pep).

The proxy itself only speaks MCP over Streamable HTTP. Local STDIO MCP servers are not covered. There is no proxy for plain REST or gRPC APIs. If you want one, the AuthZEN endpoint is the building block.

## Is Cedar required?

Cedar is the policy language in v0 and there is no other. It runs inside the server. The reasons are in [ADR-0002](decisions/0002-cedar-for-policy.md).

You do not need to write much of it. Before Cedar runs, a capability check in plain code decides whether the token allows the tool and arguments at all. For many setups the policy is a few lines, or the starter policy in `config/policies/default.cedar`. Cedar denies by default, so with no policy file nothing is allowed. Cedar can only narrow what a chain already allows. It cannot widen it.

## How do I rotate keys?

Point `private_key_pem_path` at a new key, list the old one in `previous_key_paths`, and restart. Tokens signed with the old key keep verifying (they carry a `kid`, and the JWKS lists both keys) until you remove it. The steps are in [Deploying](guides/deploying.md#key-rotation).

Rotating the signing key does not touch the audit log, which is not signed with it. Rotating the admin token and agent secrets also means editing the config and restarting.

## How is the audit log tamper-evident?

Every decision, token issuance and lease renewal is a row in an append-only SQLite table. Each row stores its sequence number, the hash of the previous row, the record, and a SHA-256 hash over those three. `attenuo audit verify` (or `GET /admin/audit/verify`) walks the chain from the first row and reports the first row that does not match. Changing, deleting or reordering a row in the middle breaks the chain, and the test suite checks those cases.

That has limits, and they matter:

- Whoever can write the database file can rewrite the whole chain from the point they edit, recomputing every hash after it. The chain alone does not stop that.
- Truncating the end of the log is not detectable by the chain alone.

The server closes both with signed checkpoints: every 1000 entries and every 300 seconds it signs `(seq, head_hash)` with the issuer key, and `attenuo audit verify` rejects a log that is shorter than a checkpoint or has a different hash at its `seq`. The key is the server's own, so checkpoints must also be kept somewhere the host cannot write. Set `[audit.sink]` and the server ships each checkpoint as it is signed (to a webhook, a file on another mount, or S3), or copy `GET /admin/audit/checkpoint` and exports yourself. See [Deploying](guides/deploying.md#sqlite-file-placement-and-backup).

The log stores a digest of each call's arguments, not the arguments.

## What is a lease?

A lease is a short-lived "this hop is still allowed" record. Every hop in a delegation chain has one, identified by an id inside the token. On every call the server checks that every lease in the chain is active: not revoked, not expired, and known to it.

Two things follow. Revoking a lease revokes everything delegated from it, so you can stop a whole run by revoking its root, and the next call is refused, even if the JWT would verify for another ten minutes. And an agent that crashes stops renewing, so its access ends on its own within one lease interval (300 seconds by default).

The holder renews its lease with `POST /token/renew`. See [ADR-0006](decisions/0006-lease-based-in-flight-revocation.md), [Integrating MCP clients](guides/integrating-mcp-clients.md#renewing-leases) and [Deploying](guides/deploying.md#leases-tuning-the-interval).

## What is ID-JAG?

ID-JAG is the Identity Assertion JWT Authorization Grant, an IETF OAuth draft (`draft-ietf-oauth-identity-assertion-authz-grant`). It is a JWT that an IdP issues to say: this client is allowed to act for this user toward this resource. It is the basis of Okta's Cross App Access and was folded into MCP as an enterprise authorization extension.

attenuo accepts an ID-JAG, or a plain OIDC ID token, as the credential at hop 0 and builds the first token of a chain from it. It follows draft -04, and drafts change, so treat that part as the least stable. It has been tested only against assertions the server's own tests sign. See [Identity providers](guides/identity-providers.md#id-jag) and [the standards note](research/standards.md).

## Does it stop prompt injection?

No. It does not detect injected instructions, and does not try to. It assumes the agent can be talked into anything and limits what the agent can do when that happens: the sub-agent that reads untrusted text holds only the tools it needs, a policy checks the arguments, and a lease lets you pull the plug. The [GitHub leak demo](https://github.com/attenuo-dev/attenuo/blob/main/examples/github-leak-demo/README.md) shows this on a replay of a real incident.

Two features reach further, into calls the agent is allowed to make. Output labelling marks every tool result as untrusted, so a policy can ask a person before a destructive call on a run that has read one ([Writing policies](guides/writing-policies.md#asking-for-approval-after-untrusted-output)). Run limits cap how many calls, how much in total or how many destinations a run may use ([run limits](design/run-limits.md)). Both depend on someone choosing well: the approver has to say no, and a limit has to fit the task.

Without those, it cannot stop an agent from misusing something it is legitimately allowed to do. See the [threat model](spec/threat-model.md).

## Is it ready for production?

No. It is pre-alpha. Formats will change before 1.0, there is one node and one SQLite file, admin authentication is a single static token, and the four security review passes were done by the project itself with no outside audit (every finding from them is fixed or accepted; see [Status](../README.md#status)). Use it to evaluate the model, in staging, or in a closed pilot where you accept those limits. [Deploying](guides/deploying.md) lists what to harden.
