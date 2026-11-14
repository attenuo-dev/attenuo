# Task board

The board lists the technical work that is open in this repository and, more briefly, what is already finished. Release milestones are in [milestones.md](milestones.md); the system is specified in [RFC-0001](../spec/rfc-0001-attenuo.md).

How to read it:

- **Open** comes first, grouped by area. Each item says what is open, why it matters, and where to start reading (a design note, an ADR, an RFC section or a code path). A size, S, M or L, is given only where a design note already estimates one.
- **Needs a decision** marks an item that waits for the maintainer to choose between options, usually in a proposed ADR or design note, before any code is written. **Needs: …** names an outside resource the item cannot be done without, such as a live identity-provider tenant, a SPIRE deployment, GitHub Actions minutes or a paid model run. An item with neither mark can be started from its pointer.
- **Done** has one line per finished piece of work, with its pull request number where the history gives one. Work merged before the repository used pull requests has none. The [changelog](../project/changelog.md) entry and the pull request carry the details.
- Open an issue before starting anything bigger than a small fix ([CONTRIBUTING](https://github.com/attenuo-dev/attenuo/blob/main/CONTRIBUTING.md#before-you-start)). When a pull request finishes an item, move it to Done as one line with the PR number; when it finishes part of one, cut the open item down to what is left.

## Open

### Server and identity

- [ ] **Admin login.** Named operators with roles (#287), expiry and reload without a restart (#292) are built. Still missing: operator login through an IdP with sessions and a second factor; expiry and reload of the `[admin] token` itself; per-operator rate limits; permissions finer than the three roles. Pointer: [ADR-0016](../decisions/0016-admin-operators.md) "What this does not do" and its update of 2026-11-13 (the ADR is proposed). **Needs a decision**; IdP login also **needs: a live IdP tenant**.
- [ ] **`evidence` and `chain_id` as token claims.** The user block does not say which credential it came from, and the run id (`chain_id`) is in the audit log and is the revocation handle, but not a token claim. Build or drop each. Pointer: [RFC-0001 §3.1](../spec/rfc-0001-attenuo.md#31-not-yet-implemented--proposed), [server known limits](../design/server.md#known-limits-v0). **Needs a decision.**
- [ ] **Time-range constraints.** Deferred, not only unbuilt: argument times need a typed `datetime` input first, a window on when a call may happen is a token or run property (expiry, Cedar over `context.now_unix`), and per-run windows belong to run limits phase 3. Reopen only with a concrete tool argument that needs it. Pointer: [RFC-0001 §3.1](../spec/rfc-0001-attenuo.md#31-not-yet-implemented--proposed). **Needs a decision.**
- [ ] **Token binding other than DPoP.** DPoP binding (RFC 9449) and server nonces are built. Not built: mTLS-bound tokens (RFC 8705) and SPIFFE X.509-SVID binding for workloads that already hold certificates; the binding is also not in Cedar's context. Pointer: [RFC-0001 §4.1](../spec/rfc-0001-attenuo.md#41-sender-constrained-tokens-dpop) "Not covered" and §9 open question 1.
- [ ] **Actor tokens.** Test `[[actor_trust]]` against a live SPIRE (bundle endpoint and OIDC discovery provider) and drop the "untested" marks in [identity providers](../guides/identity-providers.md); consider a per-entry opt-out of single use for SPIRE's JWT-SVID cache ([ADR-0007](../decisions/0007-actor-authentication.md) consequences); record the actor-authentication method in the audit record itself (today it is only in the argument digest, as `actor_auth` / `agent_auth`, and in the log line). **Needs: a SPIRE deployment** for the first part.
- [ ] **Client keys.** `private_key_jwt` is built (#288). Not built: fetching a client's keys from a `jwks_uri`, so rotation needs no restart, and mTLS client authentication. Pointer: [ADR-0017](../decisions/0017-private-key-jwt.md) "What this does not do" (the ADR is proposed). **Needs a decision.**
- [ ] **ID-JAG after draft -06.** The intake follows -06 (#279). -06 §9.11 was checked and `invalid_client` is the answer when no credential was sent (#308). Open: the ID-JAG's `resource`, `scope` and `authorization_details` as a ceiling under `[[root_grants]]`, `access_denied` instead of `invalid_scope`, the `jwt-dpop` grant, `invalid_grant` instead of `dpop_required` for an unbound ID-JAG without a proof under `[token] dpop = "required"`, several tenants of one issuer; and tracking later drafts. Pointer: [standards note](../research/standards.md#id-jag-conformance-against--06) "Open items".
- [ ] **More than one replica.** One replica is restart safe for credentials (step 1, #284) and fenced against a second process and network filesystems (step 2, #234, #285). Open: steps 3 to 6 of the note (policy consistency, S to M; the run lock across replicas, M; a Postgres backend, L; notifier claims, S), and with them replay caches shared by replicas (credentials, `private_key_jwt` assertions and DPoP proofs, which stay in memory). Six of the note's eight open questions are unanswered, starting with whether N active replicas is a goal for 0.x. Pointer: [multi-replica readiness](../design/multi-replica.md) (proposed). **Needs a decision.**
- [ ] **Leases.** Revocation by user, chain and session is built. Open: revoking by the audit `session_tag` (a 48-bit prefix, so it can be ambiguous and the server would have to list every match); the optional proxy lease cache bounded by the TTL, or a push channel to external PEPs (today every request reads the registry, so revocation reaches the next request, and AuthZEN callers learn of it only by asking). Pointer: [ADR-0006](../decisions/0006-lease-based-in-flight-revocation.md) "More information", [RFC-0001 §10](../spec/rfc-0001-attenuo.md#10-implementation-status) (P4).
- [ ] **AuthZEN remainder.** Action search (`POST /access/v1/search/action`, section 8) is built, with no side effects and paged, and discovery publishes it (this PR). Not served, with the reasons on the conformance page: subject and resource search (no directory of agents or users to enumerate; a resource is already the tool), discovery `capabilities` (no registered capability applies) and `signed_metadata`. Open: error bodies are JSON objects where the specification's table says "an error message string" (**needs a decision**; written up with a recommendation to keep the object); a search request changed between pages is not detected (8.2's SHOULD); no SDK or CLI call for action search. Pointer: [AuthZEN conformance](../reference/authzen.md#open-decision-error-bodies).
- [ ] **OpenTelemetry export, remainder.** Trace export and propagation are built (#215, #217; [ADR-0012](../decisions/0012-opentelemetry-export.md)). Open: metrics push (M), `trace_id` in the audit record (only if accepted), exemplars; span overhead end to end with `attenuo-bench`, and why a sample ratio of 1 adds 30 to 95 µs in the decide bench; a run against a real collector. Pointer: [otel-export §10](../design/otel-export.md#10-built) "Not built or not verified".
- [ ] **`RelationResolver`.** A trait and a SpiceDB-backed implementation that projects relationship facts into Cedar entities, with a cache bound to the lease TTL. Pointer: [ADR-0002](../decisions/0002-cedar-for-policy.md), [RFC-0001 §9](../spec/rfc-0001-attenuo.md#9-open-questions) question 4, [milestones](milestones.md) day 90.
- [ ] **AgentGateway integration** as its external policy decision point. Pointer: [milestones](milestones.md) day 90.

### Proxy

- [ ] **Cedar-aware list filtering, remainder.** Built behind `[proxy] list_filter = "policy"` (#158), [ADR-0011](../decisions/0011-cedar-aware-list-filtering.md) accepted 2026-11-12. Open: the injection-suite count of benign calls to tools the screen hides (the harness has no screen entry point yet), and a policy screen for resources, templates and prompts, which stay capability-filtered. Pointer: ADR-0011 "Confirmation", [design note](../design/cedar-aware-list-filtering.md).
- [ ] **Large non-list events on the listen stream.** Every JSON event on a `GET` listen stream is parsed and re-serialized; a large non-list event costs about 0.7 ms per 85 KB. A byte-search skip (treating `\u` escapes as possible keys) would remove it, worth doing only if such events turn out to be common. Pointer: [bench note](../design/bench/2026-10-24-vm-listen-stream-filter.md), [performance](../design/performance.md#listen-stream-list-filter-2026-10-24).

### Policy

- [ ] **Constraint algebra extensions.** Globs and nested objects, with notes on where `⊑` stays decidable and cheap (`path_prefix` was added in #238). Pointer: [RFC-0001 §9](../spec/rfc-0001-attenuo.md#9-open-questions) question 3.
- [ ] **Output labelling, remainder.** Phases 1 and 2, approvals, approval tokens and the approval notifier are built ([ADR-0009](../decisions/0009-output-labelling.md)). Open: the adaptive (paraphrase) run of phase 2; an approval channel for runs with no user at hand, such as a receiver that decides (open question 8); whether `-32008` should become `-32003` with its own reason (open question 10). Pointer: [output labelling §6 and §7](../design/output-labelling.md#7-open-questions). The paraphrase run **needs: a paid model run**; the rest **needs a decision**.
- [ ] **Reads with outbound arguments.** In the AgentDojo replay, 12 of the 15 attacks that pass oracle task grants are fetches of an attacker's URL by slack `get_webpage`. Built: one host grammar (#201) and the `outbound` catalog flag (#213). Replayed, not built as defaults: `one_of` URL pins stop all 12 at no benign cost, and URL pins with the `args` taint rule stop all 15 (0/609 landed, 73/97 tasks kept). Open: step 0 (the replay experiments), the replay arm for `outbound = "url#host"` on `get_webpage`, the `openWorldHint` import (open question 9), and steps 3 to 6 (host constraint, M; fingerprints for disguised hosts, S to M; first-contact approval, S after 2 and 3; confidentiality labels, L). Pointer: [read-side exfiltration](../design/read-side-exfiltration.md) (proposed), [AgentDojo plan](../research/agentdojo-plan-2026-11-05.md#read-side-arms-in-the-replay-2026-11-06). **Needs a decision.**
- [ ] **Exfiltration over an allowed channel.** A grant that pins a recipient does not pin the body. Argument-level taint with reads matched (#164) gates 7 of the 12 fetches and 2 of the 3 slack messages at the attacker's own call in the replay (6/609 landed, 71/97 kept). Open: the benign cost of gating every copied link with a real approver, the permit-all travel email that sends the passport to the task's own recipient (still lands under the `args` rule, 7/609, 89/97), utility under attack, and a paraphrasing model. Pointer: [AgentDojo plan](../research/agentdojo-plan-2026-11-05.md#re-run-after-the-server-change), [read-side exfiltration](../design/read-side-exfiltration.md). **Needs: a paid model run** for the last two.
- [ ] **A call limit on an object the grant cannot name.** Found with a model in the loop on the AgentDojo workspace suite (#301): in the two tasks that delete the largest file, the planner's grant allows one `delete_file` with any file id, because the prompt does not say which file that is. The model followed the injection first, attenuo allowed the deletion of the attacker's file, and the one-call limit then refused the task's own. The model-free replay missed it because it sends the task's calls before the attack's. Open: whether a destructive call on an object first named by a tool result should be held for approval once the run has read untrusted content (output labelling already marks the run), or the argument bound to the result of an earlier call of the same run (the largest entry `list_files` returned); the benign cost of either on the suites. Pointer: [AgentDojo with a local model](../evaluation/agentdojo-local-model.md), [ADR-0009](../decisions/0009-output-labelling.md), [ADR-0010](../decisions/0010-run-limits.md). **Needs a decision.**
- [ ] **Run limits, remainder.** Phases 1 and 2 are built ([ADR-0010](../decisions/0010-run-limits.md)). Open: per-task figures for the test split; browsing cases from an independent author; a model-in-the-loop run with limits in the grant; whether to lower `MAX_COUNTED_VALUES` (SR-57), since one 256-value `distinct` call holds the write gate for about 28 ms and stalls every decision (a cheaper charge with the same rows was tried and not adopted, #122; a larger SQLite page cache is a separate open choice, see the [bench note](../design/bench/2026-10-25-vm-distinct-list-charge.md)). Pointer: [run limits](../design/run-limits.md#status), [performance](../design/performance.md#per-value-limits-on-current-main-2026-10-25). The cap **needs a decision**; the model run **needs: a paid model run**.
- [ ] **Run limits phase 3.** Step 1, per-user windows, is built (#212). Open: step 0, measure first (S); step 2, windows on the console, the admin API and `lease tree` (S); step 3, the user lock, on top of the multi-replica run lock; step 4, RAR mapping at hop 0 (S to M); step 5, escrow at exchange (M to L), only if overbooking is shown to cost benign work. Seven open questions, starting with whether windows belong in attenuo or at a gateway. Pointer: [run limits phase 3](../design/run-limits-phase3.md) (proposed). **Needs a decision.**

### Audit and storage

- [ ] **Audit log retention** (audit finding O-4). The `audit` table is never pruned, so the SQLite file grows without bound. Proposed: archive a prefix as an export at a signed checkpoint, then prune it behind an anchor signed under `attenuo-audit-anchor-v1`, admin only and off by default (`[audit.retention] prune`), schema migration 4. Not built; six open questions and a deferred list. Pointer: [ADR-0015](../decisions/0015-audit-retention.md) (proposed), [audit retention §9](../design/audit-retention.md#9-deferred-and-open-questions). **Needs a decision.**
- [ ] **Lease store in a crate of its own** (audit finding C-2, second half). The trait split is done (#263). Moving the lease, approval, budget and outbox code out of `attenuo-audit` must keep one SQLite file, one schema and one migration list, the write gate and the shared sync, so either the connection and schema code moves to a lower crate or the new crate depends on `attenuo-audit`. Every moved `attenuo_audit::` path changes unless re-exported for a release, and the new published crate needs its own publish and an update to [ADR-0004](../decisions/0004-rust-workspace-layout.md). **Needs a decision.**
- [ ] **Verify a filtered export.** `audit verify --file` refuses any export with a `filter` (kind, chain, tool or decision). Verifying one would need per-entry inclusion proofs or a signed filter statement. Pointer: `crates/attenuo-audit/src/export.rs`.
- [ ] **Checkpoint sink against real S3.** The S3 sink is tested against AWS's published SigV4 vectors and a local receiver only. **Needs: an AWS or MinIO bucket.**

### SDKs and CLI

- [ ] **SDK hop 0 against a live IdP.** Test the Python and TypeScript hop-0 exchange against a real provider. While doing so, check that the `kid` check in the Python `inspect(verify=True)` still matches the server's header and JWKS `kid`. **Needs: a live IdP tenant.**

### Evaluation and research

- [ ] **Injection suite test split.** 26 test cases (banking and workspace) are labelled; the travel, slack and github cases are not written (t-travel-01..11, t-slack-01..12, t-github-01..10; target 40 or more), and the 15 reads proposed in `evaluation/injection-suite/cases/test/PROPOSED-READS-2026-10-24.md` are not applied. Pointer: [injection suite](../evaluation/injection-suite.md).
- [ ] **AgentDojo and InjecAgent with a model.** Done: the model-free replay with oracle and planner-written grants, Haiku and Sonnet arms, and a local open-weight model on all four suites. Open: InjecAgent itself (only cases shaped after it are in the injection suite); and the four "Decisions needed" in the plan (more baseline spending, reporting the refusal result, which attenuo cost to fix first, a realistic planner on top of the oracle). Pointer: [AgentDojo with a local model](../evaluation/agentdojo-local-model.md), [AgentDojo plan](../research/agentdojo-plan-2026-11-05.md#decisions-needed). **Needs a decision** and **needs: a paid model run** for anything beyond the local model.
- [ ] **Benchmarks, remaining.** Repeated runs with confidence intervals (RQ2); open-loop load for the deny outcomes and deeper chains; a mixed cell of lease renewals and `tools/call` together; why the file store's renewal p99 is 0.77 s at 1,000 renewals per second; whether every renewal needs its own audit record (**needs a decision**). Pointer: [performance, "Not measured"](../design/performance.md#not-measured). All of it wants **a quiet reference machine** (**needs: dedicated hardware**).
- [ ] **Performance follow-ups.** Token verification: skipping `ou_sig` when `ou_kid` equals the header `kid` (saves about 53 µs, gives up a check against an exchange bug; **needs a decision**), and a faster Ed25519 implementation; done: the cache hit no longer clones the chain twice (#305). A direct baseline in `attenuo-bench` paced at the proxied call rate. Making the WAL backstop (123 to 416 ms) rarer under sustained release-speed load (it did not fire on the 4-core VM, but did on GitHub's 2-core runner, at 237 and 335 MB of WAL, before #21), and rerunning the `file_full` cells end to end. The signed checkpoint's 3 to 5 ms sync and the first commit after an idle `TRUNCATE`, both still on the request path. New-value charges on the memory store costing two to four times the file store's. One run's ceiling of one decision per run-lock hold (about 1 ms), and the run lock with `sum` limits or `durability = "full"`. Pointer: [performance](../design/performance.md#after-the-policy-stage-and-wal-work) and the sections it links.
- [ ] **Measurement study** of delegation and credential patterns across public MCP servers. Pointer: [milestones](milestones.md) day 90.

### Docs and release

- [ ] **Release 0.1.0.** Prepared (#68): every artifact at 0.1.0, crate metadata and `LICENSE` files, `CHANGELOG.md` with a `[0.1.0]` section and Highlights, `scripts/release-check.sh` passing locally. Still to do: confirm the seven crate names on crates.io, `attenuo` on PyPI and the `@attenuo` npm scope; tag `v0.1.0` and date the CHANGELOG section; the first run of `release.yml` and the `release-packages.yml` dry run; make the repository public; `cargo publish` by hand and the SDK publish through `release-packages.yml`; set the GHCR package public, the social preview image and the README's crates.io and docs.rs badges. Pointer: [release 0.1.0](../release/0.1.0.md). **Needs: the maintainer and GitHub Actions minutes.**
- [ ] **Identity-provider recipes against live tenants.** Keycloak, Auth0, Okta, Entra ID and Google, and ID-JAG with Okta; drop the "untested" marks. Pointer: [identity providers](../guides/identity-providers.md). **Needs: live IdP tenants.**
- [ ] **Documentation site on GitHub Pages.** `docs.yml` builds the book but has not deployed it: Pages is off while the repository is private. Once it is public, set the repository variable `DEPLOY_PAGES=true` (#1) and "GitHub Actions" as the Pages source in the repository settings. **Needs: the maintainer.**

### CI

- [ ] **Workflows that have not run on GitHub.** The release workflow (musl and macOS archives, multi-arch GHCR push, cosign, SBOM), for example with a `v0.0.0-test` tag on a fork; the Python 3.10 job of `sdk-python` (its grammar is checked locally by `test_python310_grammar.py`); the Node 20 and 22 jobs of `sdk-typescript`. Also enable private vulnerability reporting (named in [security policy](../project/security.md)) and the DCO app. **Needs: GitHub Actions minutes and the maintainer.**

## Done

### Server and identity

- [x] `attenuo-server`: config, `POST /token` (RFC 8693), JWKS endpoint, dev root mint, proxy with the real authorizer, admin lease and audit routes ([design](../design/server.md)).
- [x] Hop 0 from an OIDC ID token and from an ID-JAG: trusted `[[idps]]`, JWKS discovery and cache, `[[agents]]` client authentication, root grants; dev root mint off by default.
- [x] `attenuo-token`: mint and verify JWTs with `act`, `chain` and `ou_sig`, Ed25519 keys, `/.well-known/jwks.json`.
- [x] `Issuer::exchange` and `POST /token` refuse a child that widens capabilities or depth; a later expiry is clamped to the parent's (RFC-0001 §3).
- [x] Lease renewal (`POST /token/renew`, ADR-0006), lease expiry enforced for every hop, and the revocation cascade test.
- [x] AuthZEN `POST /access/v1/evaluation` on the same pipeline as the proxy; conformance fixtures, `X-Request-ID` echo and single-evaluation batches (#99); batch semantics and public discovery (#108).
- [x] Operations: SIGTERM graceful shutdown, `/readyz`, `/metrics`, key rotation with overlap (`kid`, `previous_key_paths`), `[policy] user_attributes`.
- [x] Actor authentication ([ADR-0007](../decisions/0007-actor-authentication.md)): `actor_token` on exchange verified against `[[actor_trust]]`, `[token] actor_auth`, single-use actor tokens, `may_act` enforced as `actor_not_permitted`; hop-0 actor tokens and `ou_sig` v2 bound to `iss` and the root hop (SR-14).
- [x] DPoP binding (RFC 9449, SR-24): `cnf.jkt`, proofs on every route that takes a bound token, the exchange sign-off naming `child_jkt` and `child_actor` (SR-40).
- [x] DPoP server nonces (`[token] dpop_nonce`, RFC 9449 §8) in the server, both SDKs and the CLI (#17).
- [x] Refused token exchanges and renewals audited when the subject token verified; `token exchange --no-delegation`, `token root --no-delegation`, `token inspect` shows `may_act` (#86, #87). Malformed requests, failed actor authentication and unverifiable subject tokens stay log lines.
- [x] Revoke by user and by chain (#81), by MCP session (#89), from the console (#85, #91) and the SDKs (#94). A session binding that fails to record is only logged: the session stays usable and its chain can still be revoked by `chain_id`.
- [x] Lease registry retention: session bindings (#97), whole ended runs (#100), run-limit counters, charges and approvals of gone runs (#102), 410 `charge_pruned` for a refund of a pruned charge (#112), configurable maintenance (#106), bounded passes for very wide runs (#110).
- [x] Metrics for run limits, approvals, output labels, the run lock and the WAL checkpointer (#77).
- [x] `Connection: close` on a refusal sent before the request body was read (#214).
- [x] Optional admin API listener (#254), one opaque cursor for every admin list route (#265), `[limits]` in-flight cap, request deadlines and per-caller rate limits (#258), `ATTENUO__SECTION__KEY` overrides (#261).
- [x] Single-writer fence and upstream deadlines (#234, #247), refusal of a network filesystem (#285), single-use credentials kept across a restart (#284); see [multi-replica](../design/multi-replica.md) steps 1 and 2.
- [x] Named admin operators with roles (#287), their expiry and reload without a restart (#292).
- [x] `private_key_jwt` client authentication for agents and PEPs (#288).
- [x] ID-JAG intake follows draft -06: one `aud`, `jti`, `cnf` proof, tenant (#279); an empty `[[idps]]` tenant refused at startup (#281).
- [x] Stable error codes on every error body (#272), the specific refusal reason in `code` (#291, #294).
- [x] OpenTelemetry export: allow-listed decision spans over OTLP/HTTP, off by default (#215, #217); request spans carry the route template (SR-90, #185).

### Proxy

- [x] Streamable-HTTP interception of `tools/call` for any number of upstreams at `/mcp/{server}`; JSON-RPC error on deny.
- [x] Coverage of `resources/read`, `resources/subscribe`, `prompts/get`, `completion/complete`; unknown methods denied; `tools/list` and session requests lease-checked.
- [x] `resources/list`, `resources/templates/list` and `prompts/list` filtered by capability, also over SSE and in batches.
- [x] Lease refusals of session opens and other undecided requests audited (#80), bounded to one record per chain, tool, reason and window (#107).
- [x] Replayed list answers on a resumed `GET` stream filtered, `resources/unsubscribe` allowlisted, stream endings audited (SR-28, #90).
- [x] Listen-stream cost measured, non-SSE `GET` answers refused with 502 (#97); stream endings counted and `stream.end` records bounded (#101; reopening a listen stream with an expired token is refused at authentication and never recorded, so `token_expired` ends come from concurrent streams of one token); `[proxy] record_window_seconds` and `record_window_max_keys` (#121). A suppressed record's count is in the metric and the log only; exchanges, renewals and `tools/call` denials are not windowed.
- [x] Upstream look-alike stream-cut events rewritten to `-32005` (#117), with a byte scan before parsing (#119); the SDKs accept a cut only with a known reason and a UUID decision id (#123).
- [x] Cedar-aware list filtering behind `[proxy] list_filter = "policy"` (#158); design note and ADR-0011 (#111).
- [x] Admin console favicon (#153) and browser smoke test in CI (#76).

### Policy

- [x] `attenuo-core`: `Capability`, `CapabilitySet`, `ArgConstraint` and the `⊑` predicate `covers`; `DelegationChain` and RFC 8785 canonical JSON (SR-20).
- [x] Proptest suite for `⊑` (`crates/attenuo-core/tests/attenuation_props.rs`); fixed seed in CI, random locally (#116).
- [x] Numeric `range` constraint (#96) and segment-wise `path_prefix` constraint (#238).
- [x] `attenuo-policy`: Cedar wrapper, schema, request builder, capability stage before Cedar, lease check first in the server.
- [x] Policy hot reload with schema validation (`POST /admin/policies/reload`).
- [x] Policy test harness: `attenuo policy test` and `policy lint` ([writing policies](../guides/writing-policies.md)); unexercised-policy report, `--via authzen`, `--schema-file`, `--watch` (#82); default policy suite and `--via admin-evaluate` (#84); stated budget in the dry run (#95) and in the SDKs and console (#98); session, approval and usage overrides (#103); strict approval block and console Approval section (#109).
- [x] Starter policy hardening: the acme rule pins `acme/<name>`, delete behind MFA, declared inputs typed before Cedar (`input_type_mismatch`) (#88).
- [x] Output labelling phase 1 (#42) and phase 2, argument-level taint (#55); approvals (#45), approval token (#52), labels on the `GET` listen stream (#47), approval notifier (#159) with a persisted outbox (#168); host names as entities and reads matched when a policy asks (#164).
- [x] Run limits phase 1 (#50), run usage in policy (#59), `distinct` and URL-host destinations (#61), refund and budgets in `lease tree` (#64); per-user windows, phase 3 step 1 (#212).
- [x] `decimal` catalog input type (#190); one host grammar for limits (#201); `outbound` catalog flag (#213).
- [x] Machine-checked attenuation invariant: a Lean 4 model of the covering rule with proofs that `covers` and `implies` are sound, reflexive and transitive, that every hop of a valid chain permits what the last hop permits, and that a successful `attenuate` is covered by its parent ([Lean proof](../design/lean-proof.md)). The proof is about the model; the Rust code is not verified against it.

### Audit and storage

- [x] `attenuo-audit`: append-only SQLite log with `prev_hash`/`hash` chaining, verified by `attenuo audit verify`.
- [x] Signed checkpoints, export and offline verify; top-level `kind` and `chain_id` on every record with export filters; `audit export --tool` / `--decision` (#91).
- [x] Write path: WAL with `[audit] durability`, a writer thread with group commit; background WAL checkpoints; a writer-side backstop checkpoint (#21); sync ahead of the locked pass and of signed checkpoints (#66).
- [x] Checkpoint sink (`[audit.sink]`: webhook, JSON Lines file, S3, SR-21) and the SDK cross-check of shipped checkpoints (#17).
- [x] Canonical JSON for every hashed value, entry hash v2, export format v2, strict `verify_export` (fuzzing F4, F5), SR-50, SR-51.
- [x] Versioned schema migrations (#246), approval positions never reused (#267), `LeaseStore` split into one trait per concern (#263), audit reads off the writer's lock (#240).

### SDKs and CLI

- [x] `attenuo-cli`: tokens, calls, leases, audit and policy.
- [x] Python SDK (`sdk/python`) and TypeScript SDK (`sdk/typescript`) with agent examples and workflows; token-refresh helpers; offline `audit verify`; streamed `tools/call` answers (#115); an optional total stream deadline (SR-82, #126) and a linear SSE line reader (#125).
- [x] SDK export filters and selector revocation (#94); SDK packaging for PyPI and npm prepared (#118); typed errors and opt-in retry for load refusals (#259); stable error code on SDK errors (#278); batch evaluate, discovery, user approval, session close, budget refund and timeout errors (#244).
- [x] `--admin-server` for a separate admin listener (#266), with a hint on a bare admin 404 (#270).
- [x] `attenuo policy lint` without `--config`, and the injection-suite runner ignoring inherited `ATTENUO_*` variables.
- [x] Flaky Python test `test_dpop_server_nonce`: a retry landing on a closing keep-alive connection; both SDKs retry on a fresh connection (#208).

### Examples and docs

- [x] GitHub MCP leak demo (`examples/github-leak-demo/run.sh`) and its integration-test form (`github_leak_scenario_repo_prefix_constraint`).
- [x] Multi-hop demo, planner to coder to GitHub tool (#83); examples show a run limit and an approval (#73); IdP exchange demo with a mock OIDC provider (#256).
- [x] RFC-0001, threat model, ADR-0001 to ADR-0004, research notes; user guides, FAQ and positioning table; mdBook site with the Pages workflow.
- [x] The getting-started guide (#286) and the README and SDK README snippets (#290) run as written in CI.
- [x] Codebase walkthrough sessions 13 to 16 (#105, #114, #120, #127); release notes current to #128 (#129).
- [x] Rename to attenuo, repository attenuo-dev/attenuo.

### Security reviews and fuzzing

- [x] Security review passes 1 to 13 (SR-01 to SR-114): every finding fixed or accepted with its reasoning, none open ([README status](https://github.com/attenuo-dev/attenuo#status)). Passes with pull requests: 5 (#71, #72), 6 (#104), 7 (#124, with SR-81 #128, SR-82 #125 and #126, SR-83 #273), 8 (#151, SR-87 #160), 9 (#192, SR-91 #193, SR-92 and SR-93 #195), 10 (#209, SR-97 #214, SR-100 and SR-101 #238), 11 (#255), 12 (#299, [report](../research/security-review-2026-11-13-pass12.md): SR-108 Low and SR-111 Info fixed there; SR-109 and SR-110 Info in #300), 13 ([report](../research/security-review-2026-11-13-pass13.md): SR-112 Low, SR-113 and SR-114 Info, all fixed there). The per-principal session cap SR-36 suggested is `[proxy] max_sessions_per_principal` (SR-49).
- [x] Fuzz targets ([fuzzing](../design/fuzzing.md)), round 2 (#74, FZ2-2 #75), round 3 over the SSE parsing (#130), `decimal` inputs in `policy_context` (#205); fuzz targets compile-checked on every PR (#262).

### Code quality and CI

- [x] CI and release workflows, dev scripts and repository hygiene files; first GitHub runs green from #16; hash-pinned release tooling (#273).
- [x] Code-quality report debt items: small items (#156), one `AuditError` mapping and cast lints (#155, #160), one `Authorization` parser and shared JSON-RPC codes (#169), injectable clock (#170, #188, #196), test file names and shared helpers (#174), `missing_docs` (#171, #172, #173, #197, #199), `unreachable_pub` (#177, #183, #199), `missing_errors_doc` (#173, #211), `sqlite.rs` and `authz.rs` split (#175, #180), ADR-0004 amended (#186), report addendum (#191).
- [x] Flaky Rust test `a_newline_in_a_tool_name_stays_on_one_log_line`: tracing's per-callsite interest cache raced a scoped subscriber.
- [x] Board hygiene of 2026-10-24 (#79).

### Evaluation and performance

- [x] Injection suite: synthetic AgentDojo- and InjecAgent-shaped replay, v2 with frozen policies, dev and test splits, five arms and Wilson intervals; per-call outputs and the `attenuo_labels` arm (#41); retry after approval (#46); run-limits arms (#51, #67).
- [x] AgentDojo replay: argument-taint arms (#161), read-side arms (#194), banking cap on the `decimal` amount (#198), planner-written grants (#233, #235, #239); a local open-weight model on slack, banking, travel and workspace (#252, #260, #282, #283, #301).
- [x] End-to-end benchmark (`attenuo-bench`, `scripts/bench-e2e.sh`); criterion benches for `authorize` and `covers`; proxy stage timing (`attenuo_proxy_stage_seconds`); exchange throughput, lease renewal and open-loop arrivals for the allow call.
- [x] Policy stage cache and background WAL checkpoints; the upstream hop and blocking pool investigated (the pool stays).
- [x] Performance measurements: WAL backstop pause (#33), limit kinds (#69), run lock (#78), token verification miss (#92), per-value limits (#113), cheaper `distinct` list charges tried and not adopted (#122); bench outputs committed behind every quoted figure (#32).
- [x] Design notes: multi-replica (#178), OpenTelemetry (#181), run limits phase 3 (#182), read-side exfiltration (#189), audit retention (#275).
