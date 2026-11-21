# API compatibility before 1.0

attenuo is pre-alpha at version 0.1.0. Versions follow SemVer 2.0, and before 1.0 a minor release may break things ([CONTRIBUTING](https://github.com/attenuo-dev/attenuo/blob/main/CONTRIBUTING.md#releases)). This page says what that means for each surface a client, a policy author or an operator codes against: what we try not to break, what may still change, how a change is announced, and what is not versioned at all yet. It describes what the code does on `main`, and where the code and this page disagree, the code is right.

## The rules

1. **Additive changes are not breaking.** A new route, a new optional request member, a new response member, a new metric series or label value, a new audit record member, a new optional config key, or a new `reason` string can appear in any release. Clients must ignore response members they do not know and must treat an unknown `reason` as a refusal of that kind (an unknown JSON-RPC `-32003` reason is still a denial). The Python and TypeScript SDKs read members by name and keep the rest in `raw`, so they already behave this way.
2. **The wire format changes additively only, within a version.** Renaming or removing a member, changing a member's type or meaning, changing a status code, JSON-RPC code or `reason` for an existing case, or tightening what a request may contain is a breaking change. It follows the announcement rule below.
3. **A signed or hashed construction never changes in place.** When its bytes change, its version string or number changes too, and the verifier refuses the old one with an error that names both. This is already how `ou_sig_v`, the audit entry hash and the export format work (see [Versioned today](#versioned-today)).
4. **Breaking changes are announced.** Each one gets an entry under `### Changed` or `### Removed` in `CHANGELOG.md` that says what breaks and what to do, and a `BREAKING CHANGE:` footer in the commit ([CONTRIBUTING](https://github.com/attenuo-dev/attenuo/blob/main/CONTRIBUTING.md)). Where the old form can keep working next to the new one, it is first listed under `### Deprecated`, logs a warning when used, and is removed no earlier than the next minor release. `[policy] legacy_bare_actions` and `audience` in `[[idps]]` are the two deprecations so far; both still load and log a warning ([config](config.md)).
5. **Some changes cannot have a deprecation period.** A security fix that must refuse what was accepted before ships at once, marked `BREAKING` in its changelog entry. SR-14 and SR-20 did this: each moved `ou_sig` to a new version (2, then 3), and tokens minted before were refused and had to be re-issued from the root. SR-20 also changed the audit entry hash, which is why that construction is at `v2`.

Before 1.0 these are the project's intentions, checked in review, not a promise backed by tests. No compatibility test suite compares one release's wire format with the next.

## Surface by surface

| Surface | Where it is defined | Before 1.0 |
| --- | --- | --- |
| HTTP routes | [HTTP endpoints](http-api.md), route table in `crates/attenuo-server/src/lib.rs` | Paths kept; additions allowed. Unversioned except `/access/v1/*`, whose prefix comes from the AuthZEN specification. See [the `/v1` decision](#routes-and-the-v1-prefix). |
| REST error codes | `{"error", "code", "detail"}` shape, with `error_description` where there is one; every code in [Errors](http-api.md#errors) | `error` and `code` are stable (that page already says so); `detail` is prose and may change at any time. Three error shapes exist (REST, JSON-RPC, AuthZEN) and may be unified before 1.0, which would be announced as breaking. |
| JSON-RPC errors at the proxy | `-32001`, `-32003` to `-32008` and their `data.reason` strings ([HTTP endpoints](http-api.md#mcp-proxy)) | Codes and existing `reason` strings kept; new reasons may appear (rule 1). Members of `data` (`decision_id`, `limit`, `usage`, `untrusted_args`, ...) may be added, not renamed. |
| `reason` codes in decisions and metrics | `decisions_total` label values ([Metrics](http-api.md#metrics)), audit records | Same as above: the set grows, existing strings keep their meaning. |
| Delegation token claims | [RFC-0001 section 3](../spec/rfc-0001-attenuo.md), `crates/attenuo-token/src/claims.rs` | Not stable. The verifier ignores claims it does not know, so new claims are additive for this server. Changing an existing claim (`chain`, `cap`, `obo`, `ou_sig`) is breaking for every token in flight; tokens are short-lived, so such a change is announced and takes effect at upgrade. The header and claim `typ` (`attenuo+jwt`) is checked and is the place a new token format would announce itself. |
| Capability and constraint format | `cap` in tokens and exchange requests, [RFC-0001 section 3](../spec/rfc-0001-attenuo.md) | Not stable. Constraint kinds (`equals`, `one_of`, `prefix`, `path_prefix`, `range`) and limit kinds are tagged, and an unknown `op` or kind is refused, never read as looser. A new kind is therefore additive for requests but a token carrying it fails at an older server, so servers must be upgraded before clients use it. |
| Approval tokens | `typ: attenuo-approval+jwt` ([Approval tokens](http-api.md#approval-tokens)) | Not stable; `typ` is checked. The `_meta` key `dev.attenuo/approval` is kept. |
| Audit record schema | `DecisionRecord`, [RFC-0001 section 7](../spec/rfc-0001-attenuo.md) | Members may be added. The record is hashed as stored, so an added member does not affect verification of older entries; a reader of the JSON must ignore members it does not know. A `kind` may be added too (`search` was); a reader must not count a record of a kind it does not know as a decision. An older build of the server or the CLI cannot verify a log that holds a newer record: it reports a record with a kind or a member it does not know as corrupt. Upgrade the readers before the server, and do not downgrade a server onto a newer log. Renaming or removing a member is breaking. |
| Audit hash and signature constructions | `attenuo-audit-entry-v2`, `attenuo-checkpoint-v1`, `attenuo-audit-export-v2`, `attenuo-shipped-checkpoint-v1` | Versioned (rule 3). A database written with another entry-hash construction is refused at start, and there is no migration tool. |
| Configuration keys | [Configuration keys](config.md), `config/example.toml` | Unknown keys are rejected at start-up, so adding a key is safe and removing or renaming one breaks existing files. Removal goes through `### Deprecated` first (rule 4). |
| Prometheus metrics | [Metrics](http-api.md#metrics) | Names and label names kept; label values and series may be added. Every series is prefixed `attenuo_`. |
| Cedar request shape | `Action::"<server>/<tool>"`, `context.input`, `context.usage`, ... ([Writing policies](../guides/writing-policies.md)) | Not stable, but changes go through deprecation, as the move from bare action ids did. |
| OpenTelemetry span and attribute names | `attenuo.*` spans ([design/otel-export.md](../design/otel-export.md)) | Not stable. |
| CLI commands, flags and output | [CLI commands](cli.md) | Not stable. Scripts should use `--json` output where it exists, not the text form. |
| Python and TypeScript SDK public API | `sdk/python`, `sdk/typescript` | Not stable. Versioned with the server (`scripts/release-check.sh` fails when the three versions differ). Their integration tests (opt-in, `ATTENUO_INTEGRATION=1`) build and run the server from the same checkout; no other pairing is tested. |
| Rust crates | `attenuo-core`, `attenuo-token`, ... | Not stable and not yet published to crates.io. |

## Versioned today

These constructions carry a version, and a verifier refuses any other value:

| Construction | Version marker | Where |
| --- | --- | --- |
| Originating-user signature | claim `ou_sig_v` = 3, domain string `attenuo-ou-v3` | `crates/attenuo-token/src/claims.rs` (`OU_SIG_VERSION`, `OU_SIG_CONTEXT`); a missing `ou_sig_v` means version 1 and is refused |
| Audit entry hash | `attenuo-audit-entry-v2`, the first element of the hashed array; also stored in the SQLite `audit_meta` table | `crates/attenuo-audit/src/log.rs` (`ENTRY_HASH_VERSION`); the SDKs carry the same constant |
| Signed checkpoint | domain string `attenuo-checkpoint-v1` | `crates/attenuo-audit/src/checkpoint.rs` |
| Audit export | header `format: attenuo-audit-export-v2`; a `v1` export is refused with a message saying why | `crates/attenuo-audit/src/export.rs` |
| Shipped checkpoint | `format: attenuo-shipped-checkpoint-v1` | `crates/attenuo-audit/src/shipped.rs` |
| Token type | `typ: attenuo+jwt`, `typ: attenuo-approval+jwt` | `crates/attenuo-token` |
| AuthZEN routes | `/access/v1/evaluation(s)`, `/access/v1/search/action` | prefix from AuthZEN 1.0 |

## Not versioned yet

Being honest about the gaps:

- **Routes.** Every route except AuthZEN's has no version in its path, and the server has no other way to say which API version it speaks. `GET /healthz` returns the package version, which is the nearest thing.
- **Token payload.** Apart from `typ` and `ou_sig_v`, nothing in a delegation token says which format it uses. A change to `chain` or `cap` cannot be told apart from a malformed token.
- **Digests.** The chain digest, the argument digest in audit records, the approval call hash (`ch`, SHA-256 of the RFC 8785 JSON of `{server, tool, arguments}`) and the session tag are plain SHA-256 values with no version tag. SR-20 changed the bytes of the chain and argument digests without a marker; a future change would need a new member name or a version next to them.
- **Audit record schema.** The hash construction is versioned; the shape of `record` inside it is not.
- **Config file.** There is no schema version key.
- **Error envelope.** Every error carries a stable machine-readable `code` (`code` in a REST body, `data.code` in the proxy's JSON-RPC errors; [the list](http-api.md#errors)). Branch on it. Before it existed, sub-codes were sent in `error_description`, a member RFC 6749 meant for people, and on some 401s in `detail`; both keep their current values at least until the next minor release, and their removal will be announced here first. `code` is the refusal's specific reason; `error` is only its OAuth class. Before 0.1.0 a few refusals still sent the class as `code` and the reason only in `detail` or the message (a refused renewal's `lease_revoked`, for one); they now send the reason as `code`, with `error`, `detail` and `error_description` unchanged. That changed the value of a field documented as stable, which is allowed only because nothing had been released; the `### Changed` entry of the changelog lists each one.
- **No machine-readable contract.** There is no OpenAPI document or JSON Schema; the reference pages and the SDK types are written by hand.

## Routes and the `/v1` prefix

Routes stay as they are until this is decided, and the decision is due before 1.0. The options:

1. **Keep unversioned paths and version in a header or media type.** No route changes. Clients cannot tell versions apart from a URL, proxies and logs cannot either, and every client must send the header.
2. **Add `/v1` to the project's own routes at 1.0 and keep the old paths as aliases for one minor release.** `/token` becomes `/v1/token`, `/admin/...` becomes `/v1/admin/...`, `/approvals/{id}` becomes `/v1/approvals/{id}`, and `/mcp/{server}` becomes `/v1/mcp/{server}`. Paths fixed by other specifications stay where those specifications put them: `/access/v1/*`, `/.well-known/jwks.json`, `/.well-known/authzen-configuration`, and the probes `/healthz`, `/readyz` and `/metrics`. The aliases log a deprecation warning and are removed in the next minor release.
3. **Add `/v1` now, before 0.1.0 is tagged.** Same mapping as option 2 with no alias period, since there are no released clients. It touches every client, SDK, example and doc at once, while the API is still expected to change.

**Recommended: option 2.** It puts the version where every proxy, log and reader can see it, keeps the paths that standards fix, and gives the one existing set of clients a release to move. Option 3 pays the same cost earlier, before the API has settled enough for "v1" to mean anything. The decision will be recorded as an ADR; nothing here changes a route.

## When you upgrade

Read the release's `CHANGELOG.md` entries under `Changed`, `Removed`, `Deprecated` and `Security`. Upgrade the server before its clients when a release adds a capability or constraint kind. Tokens are short-lived and leases expire within one lease interval (300 seconds by default), so restarting into a release that changes the token format ends running sessions; plan for that. An audit database written with another entry-hash construction is refused at start: export and verify it with the old release first.
