# Standards onbehalf builds on

<!-- renamed-note -->
> Note (2026-10-23): this project was renamed from `onbehalf` to `attenuo`. This historical document keeps the old name.

- Date: 2026-10-22, updated 2026-11-12 and 2026-11-13 (sections marked "added 2026-11-12" or "added 2026-11-13" use the current name)
- Related: [RFC-0001](../spec/rfc-0001-attenuo.md), [related work](related-work.md)

> Update (2026-11-12): MCP's DPoP profile is now an experimental extension, Enterprise-Managed Authorization (ID-JAG) is marked stable on MCP's auth roadmap, ID-JAG is at -06, `draft-ietf-wimse-aims` at -01 has been read in part, and three IETF drafts were added: [attenuating agent tokens](#attenuating-authorization-tokens-for-agentic-delegation-chains), the [OAuth actor profile](#oauth-actor-profile-for-delegation) and the AuthZEN profiles. The closing section no longer says the composition is unowned.
>
> Update (2026-11-13): the ID-JAG validator was checked against the text of -04, -05 and -06, with a [conformance table](#id-jag-conformance-against--06), and four gaps were fixed. `act.iss` was analysed and is not emitted yet ([actor profile](#oauth-actor-profile-for-delegation)).

Each entry: what it is, what it gives onbehalf, what gap remains. Status as reported in the cited sources on the date above; drafts move, so re-check before quoting.

## MCP authorization, revision 2026-07-28

Release candidate 21 May 2026, final 28 Jul 2026; maintainers called it "the largest revision of the protocol since launch." MCP servers are formally OAuth 2.1 resource servers and MUST implement Protected Resource Metadata (RFC 9728); clients MUST implement Resource Indicators (RFC 8707); Client ID Metadata Documents replace Dynamic Client Registration, which is "deprecated and retained only for backward compatibility"; also issuer verification per RFC 9207, refresh-token guidance, scope accumulation during step-up, and `application_type` declaration ([WorkOS](https://workos.com/blog/mcp-2026-spec-agent-authentication)). Sampling was removed from core ([Archestra](https://archestra.ai/blog/state-of-mcp-2026)). Enterprise-Managed Authorization (built on ID-JAG) is an enterprise extension ([Archestra](https://archestra.ai/blog/state-of-mcp-2026)).

Added 2026-11-12:

- **Enterprise-Managed Authorization** is marked stable on MCP's auth roadmap, as reported from AGNTCon + MCPCon, 22-23 October 2026 ([InfoQ](https://www.infoq.com/news/2026/10/agntcon-mcpcon-2026/)). The same report places proof-of-possession tokens and workload identity federation in draft.
- **DPoP for MCP is experimental.** ext-auth PR #38, "Mark DPoP as experimental extension" (open, dated 23 October 2026), moves the DPoP profile to `specification/experimental/` under the extension lifecycle (SEP-3392). A reviewer asked for `jti` replay tracking to be RECOMMENDED rather than optional ([PR #38](https://github.com/modelcontextprotocol/ext-auth/pull/38)). attenuo's DPoP is RFC 9449 on its own routes and already refuses a replayed `jti` ([HTTP endpoints](../reference/http-api.md#dpop-sender-constrained-tokens)); interoperation with MCP's profile, including its `dpop_jkt` binding, has not been checked.
- **Delegated authority for MCP.** ext-auth issue #32, "Delegated / attenuated authority for MCP agent tool calls", presents an external framework that checks delegated authority before MCP's normal authorization and asks whether maintainers would take it as an optional extension ([issue #32](https://github.com/modelcontextprotocol/ext-auth/issues/32)). It is the discussion closest to attenuo's model. Title and request checked on 2026-11-12; the page we fetched did not show whether the issue is still open.
- **Open SEPs that map onto attenuo features**, not read: SEP-2643 (structured authorization denials), SEP-2848 (asynchronous approval of tool calls), SEP-2817 (audit context in `_meta`), SEP-2793 (tool risk metadata) [verify: numbers and titles from a secondary summary]. attenuo's refusal reasons, approvals and decision ids would map onto the first three if they are adopted.

- **Gives us:** a settled token-on-the-wire model. onbehalf's proxy can assume a bearer token with a resource indicator, and can itself be the "resource" the client targets.
- **Gap:** authorization is optional and server-level; "whether a specific tool call is allowed for a specific user is left to the server or a gateway" ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)). No slot for the originating user across hops ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)). OAuth 2.1 itself is still an IETF draft (draft-ietf-oauth-v2-1-13) ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)).

## RFC 8693, OAuth 2.0 Token Exchange

Defines the `urn:ietf:params:oauth:grant-type:token-exchange` grant, `subject_token`/`actor_token`, and the `act` (nested actor chain) and `may_act` (who may later act for this subject) JWT claims. Cerbos calls it "the right primitive" for delegation that "does not fully close the gap" ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)). AWS's multi-agent sample issues a scoped on-behalf-of token per hop with it ([AWS Security Blog](https://aws.amazon.com/blogs/security/enforce-least-privilege-authorization-in-multi-agent-ai-chains-using-cedar/)). Spec text: [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693).

- **Gives us:** the exchange endpoint shape and the `act` chain, used as-is in [RFC-0001 §4](../spec/rfc-0001-attenuo.md#4-token-exchange).
- **Gap:** says nothing about what claims the exchanged token may carry relative to its parent. Attenuation (`cap` narrowing), the originating-user block (`obo`) and leases are onbehalf additions layered on it.

## ID-JAG (Identity Assertion JWT Authorization Grant) and Cross-App Access

Okta's Cross-App Access was adopted by the IETF OAuth WG in September 2025 and folded into MCP as an enterprise authorization extension; Okta Agent SSO (GA 24 Aug 2026) and Descope (15 Oct 2026) ship it; Microsoft Entra Agent ID and ServiceNow do not ([Forkast](https://forkast.news/six-vendors-are-shipping-agent-identity-products-the-ietf-has-not-finished-the-standard/)). The draft was at -04 on 2026-10-22, expiring 22 Nov 2026; the IETF agentproto WG is "active but contested"; vendors build on different subsets (ID-JAG, AIMS, WIMSE), "so no single standards-compliant stack is guaranteed to interoperate" ([Forkast](https://forkast.news/six-vendors-are-shipping-agent-identity-products-the-ietf-has-not-finished-the-standard/)).

- **Gives us:** an IdP-issued assertion that names the user and the target resource, which is the cleanest hop-0 input for `originating_user`.
- **Gap:** single hop, single trust domain, issued by the IdP for one resource; nothing about hops after the first, attenuation, or revocation. onbehalf treats ID-JAG as one of several hop-0 credential types and must track the draft as it changes.
- **Update (2026-11-12):** the draft is at -06, dated 31 October 2026 on its cover page ([datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)). Per our secondary summary, -05 and -06 add a refresh token as `subject_token`, an optional `sub_id`, multi-tenant issuer rules and an `access_denied` error. Corrected on 2026-11-13 against the draft text: the refresh token as `subject_token` and `sub_id` were already in -04; the rule that the authorization server must require `tenant` from a multi-tenant issuer and the `access_denied` error are new in -05.

### ID-JAG conformance against -06

Added 2026-11-13. Read from the draft text: [-04](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-04.txt) (21 May 2026), [-05](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-05.txt) (30 October 2026) and [-06](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-06.txt) (31 October 2026; [HTML](https://www.ietf.org/archive/id/draft-ietf-oauth-identity-assertion-authz-grant-06.html)). The datatracker [history](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/history/) shows -05 and -06 both posted on 30 October 2026, with no change notes.

What was not read: the tool used to read the drafts cuts each text at about 100,000 characters, so the end of -05 and -06 (from section 9.6 on, which holds the DPoP section 9.11, the IANA considerations and the document history) and the references of -04 were not read, and no line-by-line diff was made. Every point below comes from sections 3 to 9.5 of each revision. -05 and -06 agree on every point checked here.

**Changes from -04 to -06 that touch what attenuo does** (attenuo is the Resource Authorization Server of the draft; the IdP-side rules of section 4.3 do not apply to it):

| Section (-06) | -04 | -06 |
| --- | --- | --- |
| 3.1 claims | `iss`, `sub`, `aud`, `client_id`, `jti`, `exp`, `iat` REQUIRED; `typ` MUST be `oauth-id-jag+jwt` | unchanged |
| 4.3 token types | `urn:ietf:params:oauth:token-type:id-jag` | unchanged |
| 4.4 grant type | `urn:ietf:params:oauth:grant-type:jwt-bearer` (`jwt-dpop` only in a 9.8.1.2.1 example) | `jwt-bearer`, or `urn:ietf:params:oauth:grant-type:jwt-dpop` for a DPoP-bound ID-JAG, defined in another individual draft, `draft-parecki-oauth-jwt-dpop-grant` |
| 4.4 client authentication | no rule at the token endpoint (9.1: "SHOULD only be supported for confidential clients") | "SHOULD require client authentication"; "MUST reject a request that has neither client authentication nor a sender-constrained ID-JAG", with `invalid_client` |
| 4.4.1 issuer | 4.1: the server "MUST be configured to recognize that issuer" | MUST reject with `invalid_grant` if `iss` is not a trusted IdP, "accepting only the algorithms it allows for that issuer" |
| 4.4.1 `aud` | string or one-element array: "If the aud claim is an array, it MUST contain exactly one element" | unchanged |
| 4.4.1 `tenant` | only an IdP duty (6.1: include `tenant` for a multi-tenant issuer) | new: for a multi-tenant issuer, MUST reject with `invalid_grant` unless `tenant` is present and trusted together with `iss` |
| 4.4.1 `client_id` | MUST match the authenticated client | unchanged; without client authentication, proof of possession of the `cnf` key takes its place |
| 4.4.1 `cnf` | 9.8.1.2: with `cnf.jkt`, a DPoP proof whose key thumbprint matches "MUST" be presented, else `invalid_grant` | a bullet in 4.4.1 points to 9.11 (not read) |
| 4.4.1 `resource` | "MUST process it according to Section 2 of RFC 8707" | each value MUST be a resource this server governs, else `invalid_grant`; `access_denied` if none is acceptable |
| 4.4.3 errors | `invalid_grant` only | adds `access_denied` (valid ID-JAG, user or client not authorized); `invalid_grant` lists "cnf binding" |
| 4.4.4 replay | no rule (4.4.3 lets the client re-send the ID-JAG until it expires) | the server "can reject an ID-JAG with an exp longer than its policy allows, or accept each ID-JAG only once by tracking its jti" |
| 4.4.4 refresh tokens | "SHOULD NOT return a Refresh Token" | unchanged |
| 3.1, 4.3.3 `act` | no normative processing of `actor_token` or `act` | unchanged |

**Conformance, attenuo as the Resource Authorization Server** (main at `7493efb` before this check; "now" is after the fixes of 2026-11-13):

| -06 requirement | attenuo | Status |
| --- | --- | --- |
| `typ` is `oauth-id-jag+jwt` (3, 4.4.1) | checked, case-insensitive; now also accepts `application/oauth-id-jag+jwt` (RFC 7515 §4.1.9) | conformant |
| `iss` trusted, allowed algorithms, signature (4.4.1) | `[[idps]]` issuer and `allowed_algs` (asymmetric only), key by `kid` | conformant |
| `aud` is this server, array of exactly one (4.4.1) | was: an array was accepted if it contained `[issuer] issuer` among others. Now refused (`audience_mismatch`) | conformant now (was not, already against -04) |
| REQUIRED claims (3.1) | `iss`, `sub`, `aud`, `client_id`, `exp`, `iat` were required; `jti` was not (the replay key fell back to a hash). Now `jti` is required (`missing_claim`) | conformant now |
| `exp`, `iat` | checked with `clock_skew_seconds`; the root token never outlives `exp` | conformant |
| `client_id` is the authenticated client (4.4.1) | equals the agent id (`client_id_mismatch`) | conformant |
| client authentication (4.4) | always required, even for a bound ID-JAG (stricter than the SHOULD). With `[token] actor_auth = "actor_token"` and no credential at all, the answer is `400 invalid_request` / `actor_token_required`, not `invalid_client` | conformant except that error code |
| `tenant` for a multi-tenant issuer (4.4.1) | was not checked. Now `[[idps]] tenant`, optional: when set, `tenant` must be present and equal (`missing_claim`, `tenant_mismatch`). attenuo cannot tell on its own that an issuer is multi-tenant, so the operator says so | conformant when configured |
| `cnf` proof of possession (4.4.1, -04 9.8.1.2) | was ignored: a bound ID-JAG was accepted as a bearer one. Now `cnf.jkt` needs a DPoP proof by that key on the request (`credential_pop_required`, `credential_pop_mismatch`) and the root token is bound to it; any other `cnf` is refused | conformant to -04 9.8.1.2; -06 9.11 not read |
| `jwt-dpop` grant type (4.4) | not supported (`unsupported_grant_type`); a bound ID-JAG is sent as `jwt-bearer` with a `DPoP` header | open |
| `resource` (4.4.1) | ignored; the root token is bounded by `[[root_grants]]` and the request only | not conformant, open |
| `scope`, `authorization_details` (4.4.1) | the request's are attenuated against `[[root_grants]]`; the ID-JAG's own claims are ignored | partly; open |
| `access_denied` for a valid ID-JAG the user or client may not use (4.4.3) | `400 invalid_scope` / `no_root_grant` or `scope_exceeds_grant` | not conformant, open |
| replay (4.4.4) | each (`iss`, `jti`) is used once, and the root token is capped at `exp` | conformant (the stricter of the two options) |
| no refresh token (4.4.4) | none is issued | conformant |
| `sub_id`, `aud_tenant`, `aud_sub`, `acr`, `email` | ignored; `auth_time` and `amr` feed the user block | not applicable (OPTIONAL) |
| `subject_token_type` `...:id-jag` in a token exchange | an attenuo extension next to `jwt-bearer`; not in the draft | not applicable |
| IdP rules (4.3, 6) | attenuo is not the IdP | not applicable |

**Open items**, not implemented because they are larger or the draft leaves them open: honour the ID-JAG's `resource`, `scope` and `authorization_details` as a ceiling under `[[root_grants]]` (needs a mapping from resource identifiers to attenuo's upstream servers); answer `access_denied` instead of `invalid_scope` for a missing root grant (changes the error a client sees, so it needs a release note); accept `jwt-dpop` once its draft settles; read -06 section 9.11 and check the DPoP rules against it; answer `invalid_client` when `actor_auth = "actor_token"` and no credential was sent; trust several tenants of one issuer (needs `tenant` in `[[root_grants]]`).

## RFC 9396, Rich Authorization Requests (RAR)

Replaces flat scope strings with a structured `authorization_details` array. Named by Anthropic's MCP auth lead as one of the candidate pieces for granularity, together with draft RAR metadata extensions, with the caveat that "none of these fully solve the problem alone" ([QCon London](https://qconlondon.com/presentation/mar2026/your-agent-sandbox-doesnt-know-my-authz-model-standard-shaped-hole)). Spec text: [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396).

- **Gives us:** the wire shape for requesting a capability set at exchange time (`type: "mcp_tool"`, server, tool, constraints).
- **Gap:** no semantics for subset or narrowing between requests; onbehalf defines `⊑` over the `mcp_tool` type itself.

## OpenID AuthZEN Authorization API and the COAZ-MCP binding

AuthZEN reached final specification status in January 2026. It standardises a PEP-to-PDP request of subject, action, resource, context. A draft "COAZ Binding for the Model Context Protocol - Draft 1" profiles it for MCP tool authorization ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)). As of 2026-11-07 the COAZ-MCP binding and the access request and approval (AARP) and Obligations profiles are still drafts [verify: from a secondary summary]; attenuo's endpoint has not been mapped onto any of them.

- **Gives us:** the request/response shape for `/access/v1/evaluation`, so any gateway or server that speaks AuthZEN can call onbehalf as a PDP without a custom client. Also the frame for putting arguments, originating user, depth and session in `context`.
- **Gap:** no obligations/withdrawal semantics in most implementations ([Cerbos](https://www.cerbos.dev/blog/mcp-authorization-standards)); nothing about delegation chains. The MCP binding is Draft 1; field names may move. No OSS implementation of AuthZEN + COAZ-MCP end to end was found in the notes.

## Cedar

Rust-implemented authorization language with a sound-and-complete logical encoding enabling precise analysis; modelled in Lean with proven properties; principal/action/resource/context model with default deny and `forbid` overriding `permit` ([arXiv 2403.04651](https://arxiv.org/abs/2403.04651v2)). Used by AWS AgentCore Policy (GA 3 Mar 2026) with the tool name as action and arguments as `context.input` ([Ajay Kumar](https://www.ajayk.sh/blog/policy-as-code-guardrails-ai-agents-2026/)).

- **Gives us:** in-process argument-aware policy evaluation and a path to policy analysis. See [ADR-0002](../decisions/0002-cedar-for-policy.md).
- **Gap:** no native ReBAC; temporal/session constraints led AWS to a second language (Dogwood); no notion of delegation depth or attenuation. These are handled outside the language in onbehalf.

## SPIFFE / SPIRE

Workload identity: each workload gets a SPIFFE ID and an X.509 or JWT SVID from a local agent. Named at QCon as a candidate piece for agent attribution ([QCon London](https://qconlondon.com/presentation/mar2026/your-agent-sandbox-doesnt-know-my-authz-model-standard-shaped-hole)); Descope's gateway uses SPIFFE workload identity and mTLS ([Forkast](https://forkast.news/six-vendors-are-shipping-agent-identity-products-the-ietf-has-not-finished-the-standard/)).

- **Gives us:** a stable, verifiable `actor` identity for each agent and sub-agent (the `actor_token` in an exchange), and a possible `cnf` binding for hop tokens.
- **Gap:** identifies the workload, not the human or the delegation. Many agent runtimes do not run a SPIRE agent, so onbehalf must also accept other actor credentials (OAuth client credentials, signed client assertions).

## IETF agent identity drafts: `draft-ietf-wimse-aims` (replaces `draft-klrc-aiagent-auth`)

`draft-klrc-aiagent-auth` ("AI Agent Authentication and Authorization", last revision -03 of 2026-07-06) has expired. The IETF datatracker lists it as "no longer active" with the IESG state "Replaced by draft-ietf-wimse-aims" (AI Identity Management System), a WIMSE working group document. Checked on 2026-10-23: [datatracker.ietf.org/doc/draft-klrc-aiagent-auth/](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/), successor at [datatracker.ietf.org/doc/draft-ietf-wimse-aims/](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/). Cite the successor, not the expired draft, and re-check its status before quoting.

Update (2026-11-12): `draft-ietf-wimse-aims-01`, "AI Identity Management System", dated 2 November 2026, is a WIMSE working group document with intended status Informational. Read in part (the datatracker text, not every section). Three points bear on attenuo:

- Its transaction-token section says the scope of a token obtained by exchange "can never exceed that of the token presented to obtain it". That is stated for the exchanges that section describes, not for token exchange in general, and it is the same rule as attenuo's `⊑` at each exchange.
- It calls it "an anti-pattern for Tools to forward access tokens it received from the Agent to Services or Resources", which is why attenuo's proxy never forwards the delegation token upstream.
- An authorization server "MAY conclude that the level of access requested by an Agent requires explicit user confirmation". This is permission, not a requirement for human approval.

- **Gives us:** a working-group text that agrees with narrowing at exchange and with not forwarding tokens. The "AIMS" that the vendor survey above lists among the subsets vendors build on ([Forkast](https://forkast.news/six-vendors-are-shipping-agent-identity-products-the-ietf-has-not-finished-the-standard/)) is presumably this line of work; that mapping is not verified.
- **Gap:** not yet assessed in full against attenuo's leases, run limits and audit.

## Attenuating Authorization Tokens for Agentic Delegation Chains

Added 2026-11-12. `draft-niyikiza-oauth-attenuating-agent-tokens-02`, 26 October 2026, an individual Internet-Draft, not adopted by a working group ([datatracker](https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-02)). It profiles RFC 9396 into a signed token that lists the tools an agent may call and constraints on their arguments. A holder derives a narrower child offline, within the parent's depth and lifetime; each child is signed by the key its parent names and carries the parent's hash, so an enforcement point with the root issuer's key verifies the whole chain without contacting the issuer. Every tool call also needs a proof-of-possession JWT from the leaf holder over the tool and its exact arguments. Its core constraint types (section 3.4) are `exact`, `range`, `one_of`, `not_one_of`, `contains`, `subset`, `wildcard`, `all` and `any`, with further types allowed through an IANA registry, and an enforcement point "MUST deny authorization" when it meets a constraint type it does not recognize. It leaves revocation to deployments or companion specifications, since revocation would bring back the online dependency that offline verification avoids. Checked against the -02 text on 2026-11-12; -02 is the latest revision on the datatracker.

- **Relation to attenuo:** it is the closest standards text to attenuo's token model, and it does the same job offline where attenuo does it online. attenuo derives every child at the server (RFC 8693), which costs a round trip per hop and buys revocation that reaches running chains, an audit record of every delegation and an authenticated actor at each hop. See [online versus offline attenuation](related-work.md#online-versus-offline-attenuation). attenuo's constraints (`equals`, `one_of`, `prefix`, `path_prefix`, `range`) overlap AAT's `exact`, `one_of` and `range`, and attenuo also refuses an unknown constraint kind. A mapping from AAT constraints to attenuo capabilities and Cedar has not been written.
- **Gap:** as an individual draft it may change or lapse; cite it by revision.

## OAuth Actor Profile for Delegation

Added 2026-11-12. `draft-mcguinness-oauth-actor-profile-01`, dated 9 October 2026, an individual Internet-Draft, not a working-group document and not a standard ([datatracker](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-actor-profile/)). It requires `act.iss` and `act.sub` in an `act` object and recommends `sub_profile`, a list of entity profile values (its examples use `ai_agent`) defined by a companion entity-profiles draft.

- **Relation to attenuo:** attenuo carries the human in a signed `obo` block and the agents in `act` and `chain`. It does not emit `act.iss` or `sub_profile`.
- **`act.iss` (analysed 2026-11-13, not emitted).** Section 3.4 defines `act.iss` as "the issuer or namespace context for act.sub" and says it "MUST identify the context used when assigning or asserting that identifier", and that implementations MUST NOT read it as the current token issuer or the credential issuer. In attenuo `act.sub` is an agent id from `[[agents]]`: a client secret authenticates that id directly, and an actor token (a SPIFFE JWT-SVID or another workload JWT) is only mapped onto it by `subject_to_agent`. The namespace would therefore be attenuo's own `[issuer] issuer` at every level, whatever the authentication method; the SPIFFE trust domain or the actor token's issuer would be the credential issuer the draft rules out. A chain never crosses issuers (an exchange verifies the parent against this server's `iss`), so all levels would share it. Emitting it would be additive for verifiers that ignore unknown `act` members (the Python and TypeScript SDKs), at about 40 bytes per hop. It is not done yet for two reasons: the profile is an individual draft that may change, and the profile says an issuer that extends an inbound chain "MUST NOT change any inherited actor field", which a first rollout would break for parents issued before the change. An implementation exists as a proposal and waits for a maintainer decision. The profile's other rules: one linear chain, outermost actor first (attenuo already does this); and a local depth limit, refused with `invalid_request` (attenuo has `[issuer] max_depth` but answers `invalid_scope`, a difference left as is).
- **`sub_profile` not emitted.** Its values "MUST be registered with the 'Actor Profile' usage location in the OAuth Entity Profiles registry" (section 3.4), a registry defined by another individual draft, `draft-mora-oauth-entity-profiles`; `ai_agent` appears only in examples, and the registry contents were not read. Emitting it would mean guessing a value.
- **Gap:** individual draft; the profile values live in another draft.

## IETF 127 (14-20 November 2026)

Not yet held at the time of writing. Our secondary summary lists the agentproto working group's first meeting on 16 November and a proposed AUDIT BoF on delegation-chain audit records on 17 November, whose status is unclear (the datatracker and the IETF blog disagree) [verify]. Relevant to attenuo's audit log if it goes ahead.

## What the composition adds

Carrying a verified originating user across N hops, monotonic attenuation of structured capabilities per hop, per-call argument policy reachable by any PEP, revocation that reaches in-flight runs, and an audit record that names agent and user separately. Each standard above supplies one piece. As of 2026-11-12 the AAT draft specifies narrowing across hops with argument constraints in one token format, offline, and `draft-ietf-wimse-aims` states the no-widening rule for the exchanges it covers; neither specifies online revocation or an audit record. [RFC-0001](../spec/rfc-0001-attenuo.md) is attenuo's composition, built from the standards above rather than a new protocol.
