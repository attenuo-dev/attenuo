# Rename plan

- Date: 2026-10-23
- Status: tooling ready, name not decided (candidates: Creance, Attenuo, Plenipo)
- Tool: `scripts/rename.py` (`python3 scripts/rename.py --to <name> --dry-run`, then `--apply`)

The working name `onbehalf` is taken on crates.io, PyPI and npm. This page records what the rename script does, which strings change the wire formats, what must keep working for data that already exists, and the steps that happen outside the repository. The page itself, `scripts/rename.py` and `scripts/test_rename.py` keep the old name on purpose: they describe it.

## What the script does

One case-aware replacement over file contents and over file and directory names: `onbehalf` becomes `<name>`, `Onbehalf` becomes `<Name>`, `ONBEHALF` becomes `<NAME>`. That covers the eight crate directories and their `onbehalf_*` module paths, the binaries, `sdk/python/src/onbehalf`, `@onbehalf/sdk`, `OnbehalfClient` and `OnbehalfError`, `ONBEHALF_*` environment variables, Docker image and user names, `urn:onbehalf:` URNs, the signing contexts, `x-onbehalf-decision-id`, the `onbehalf: ` JSON-RPC message prefix, `onbehalf_*` metric names, the mdBook title and `site-url`, and the slug `7Mudit/onbehalf` in URLs. "On behalf of" with spaces is English and is not touched.

Policy:

| Area | Treatment |
|---|---|
| Everything not listed below | Rewritten. |
| `docs/log/**`, `docs/research/**` | History. Text kept; a one-line note goes under the title; only Markdown link targets are rewritten so links to renamed files do not break. |
| `CHANGELOG.md` | Rewritten (nothing is released, the whole file is `[Unreleased]`) and a BREAKING "renamed from" entry is added. Once a release exists, sections of released versions must stay as they were; the script would need a cut-off for that. |
| Lockfiles (`Cargo.lock`, both `package-lock.json`) | Not edited. Regenerate: `cargo update -w`, `npm install --package-lock-only` in `sdk/typescript` and `examples/typescript-agent`. No Python lock exists. |
| `.git`, `target`, `node_modules`, `dist`, `.bin`, `.claude`, `book`, caches, git-ignored files | Skipped. |
| `scripts/rename.py`, `scripts/test_rename.py`, this page | Keep the old name. |

After `--apply`: `cargo fmt --all` (import order and line widths change), `cargo update -w`, the full test run (Rust, Python SDK with its integration flag, now named `<NAME>_INTEGRATION`, and the TypeScript SDK), `python3 scripts/check-links.py`, and update the launch drafts. The script refuses to apply on a dirty git tree unless `--force`.

## Compatibility decisions

### State of the world

Nothing has been released or deployed: the workspace is `0.1.0`, the Python SDK `0.0.1`, the TypeScript SDK `0.0.0`, and the CHANGELOG records that "nothing was deployed" with the previous `ou_sig` version. The decisions below follow from that and should be revisited if anyone has run a server with a persistent audit database or issued long-lived tokens before the rename ships.

### Strings that identify old data

| String | Where it lives | Recommendation |
|---|---|---|
| `onbehalf-checkpoint-v1` | Signature framing of audit checkpoints, stored in the `checkpoints` table and in exports | Rename to `<name>-checkpoint-v1` (no version bump), because no signed checkpoint exists outside development databases. If a database that matters exists, do not rewrite it: add a second verifier context and accept both (`CHECKPOINT_CONTEXTS: [&str; 2]`), keep signing new checkpoints with the new one only, and keep the legacy value for as long as old rows exist. `--keep-legacy-contexts` leaves the strings untouched for that interim, but the code must be changed to accept both before it is used. |
| `onbehalf-ou-v2` / reserved prefix `onbehalf-ou-` | `ou_sig` in tokens | Rename to `<name>-ou-v2`. Tokens are short-lived (TTL-bound), so old ones expire; there is nothing to migrate. Keep `DetachedSigner` refusing both `<name>-ou-` and, during a transition, `onbehalf-ou-`, so nobody can sign a message in a reserved legacy context. Do not bump to v3: the version number tracks the construction, which does not change. |
| `onbehalf-audit-export-v1` | `format` in the header of JSON Lines exports | Rename; `parse_export` should accept the old id for one release if any export was archived. Exports are verified with the JWKS, so an archived file also needs the legacy checkpoint context. |
| `urn:onbehalf:` (`urn:onbehalf:admin`) | `originating_subject` of admin actions in audit entries; reserved prefix at IdP intake and the dev root mint | Rename for new entries. Existing entries keep their subject and their hashes (the hash chain covers the stored string, so rewriting rows would break verification: never rewrite audit rows). Reserve both prefixes, `urn:<name>:` and `urn:onbehalf:`, for one release so an IdP `sub` cannot impersonate old admin entries, and let audit filters match both. |
| `typ` `onbehalf+jwt` | JWT header | Rename to `<name>+jwt`. Verifiers accept the old `typ` for one release only if tokens outlive the rollout (they do not at the default TTLs). |
| `aud` / `audience = "onbehalf"` | Default audience in config and example, hard-coded in a few tests | Changes with the rename. Operators who set an explicit audience are unaffected; those on the default must update config and any IdP registration. |
| Reserved name `onbehalf` (server name, agent id, SR-34) | Startup validation | Becomes `<name>`. Keep `onbehalf` reserved as well for one release. |
| `authorization_details` type `onbehalf_capabilities` | Token exchange request | Renamed. Accept the old type for one release in the server (cheap, one match arm), because it is typed by hand in client code. |

Rule of thumb: strings that were signed or hashed into stored records are accepted in both spellings until the stores are known to be empty of old data; strings that only name things at runtime are renamed cleanly. Neither case needs a version bump of the construction itself.

### Wire format and operational changes

All of these are breaking for clients and operators and happen in one step.

| Surface | Change |
|---|---|
| Environment variables | `ONBEHALF_*` to `<NAME>_*` (`ADMIN_TOKEN`, `TOKEN`, `SERVER`, `CONFIG`, `CLIENT_SECRET`, `ROOT_TOKEN`, `ROOT_LEASE`, `INTEGRATION`, `BIN_DIR`). Recommended: read the old name as a fallback with a deprecation warning for one release in the server and CLI; SDKs do not need a fallback beyond `ADMIN_TOKEN`/`SERVER`/`TOKEN` they read. |
| HTTP headers | `X-Onbehalf-Decision-Id` to `X-<Name>-Decision-Id`. The SDKs use it to tell a policy denial from an upstream `-32003` (SR-32), so an old SDK against a new server downgrades every denial to a generic `RpcError`, and a new SDK against an old server never sees a `Denied`. Version-lock server and SDKs; the server could emit both headers for one release. |
| JSON-RPC messages | `onbehalf: denied: ...`, `onbehalf: unauthorized: ...`, `onbehalf: upstream unreachable` become `<name>: ...`. Code and `data.reason` are unchanged; clients matching on the message text break, those matching on `code`/`data.reason` do not. |
| Metrics | `onbehalf_*` series (`onbehalf_decisions_total`, `onbehalf_audit_*`, `onbehalf_http_requests_total`, ...) get new names. Dashboards and alerts must be edited; there is no alias. |
| Packaging | Binaries `onbehalf`, `onbehalf-server` (and Docker entrypoint, user, `/etc/onbehalf`, `/var/lib/onbehalf`, default `data/onbehalf.sqlite`) are renamed. An existing SQLite file must be moved by the operator or pinned with `sqlite_path`. |
| `.well-known` | The paths (`/.well-known/jwks.json`, `/.well-known/authzen-configuration`) are standard and contain no project name: unchanged. Only the `issuer`/`public_url` host in examples changes. |
| Rust API | `onbehalf_*` crates become `<name>_*`; downstream Cargo dependencies and `use` paths change. Pre-1.0, so a minor bump. |

### SDK versions

- Python: the import package changes (`import <name>`), so this is a new distribution, not an upgrade: publish as `0.1.0` under the new PyPI name. Optionally publish a final `onbehalf` release that depends on the new name and re-exports it with a `DeprecationWarning` (only worthwhile if `onbehalf` was ever uploaded, which it was not).
- TypeScript: new scoped name; first publish at `0.1.0`. Old `@onbehalf/sdk` was never published, so nothing to deprecate.
- Server and CLI workspace: bump `0.1.0` to `0.2.0` for the breaking wire changes, with the CHANGELOG entry the script adds. SDK minimum server versions must be stated in each README, since header and message prefixes are matched.

## Post-rename checklist (outside the script)

Before the rename, check availability of the chosen name on crates.io (all eight crates, `<name>-core` etc.), PyPI, npm (including the scope `@<name>`), GitHub, a domain, and a trademark search.

- [ ] Reserve names: crates.io (publish `0.0.0` placeholders for each crate, in dependency order), PyPI project, npm scope/org and package.
- [ ] GitHub: rename the repository `7Mudit/onbehalf` (GitHub redirects the old URL), move to an organisation if one is wanted, update the remote URL in clones, check that the release workflow's cosign identity regex (`.github/workflows/release.yml`, includes the repo slug) matches the new slug, and that branch protection and required status checks survive.
- [ ] Docs site: `book.toml` `title`, `authors`, `git-repository-url`, `edit-url-template`, `site-url` (`/<name>/` while on GitHub Pages project pages); confirm Pages is set to "GitHub Actions"; custom domain and redirect from the old Pages path if it was ever live.
- [ ] Container image: `ghcr.io/7mudit/<name>`; repoint the signed-image verification in the docs; republish the SBOM; delete the old package once empty.
- [ ] Badges in `README.md` and the SDK READMEs (CI, crates.io, PyPI, npm, docs) and the shields.io slugs.
- [ ] `.github/CODEOWNERS` (today a single `* @7Mudit` line: nothing to rewrite, but add a team handle if the repository moves to an organisation), `.github/FUNDING.yml`, issue templates, `dependabot.yml` directories (`/sdk/python`, `/crates/...`).
- [ ] `SECURITY.md`: the private advisory URL (`github.com/<owner>/<name>/security/advisories/new`), the contact address and domain, the PGP/key fingerprint if any, and the product name in the policy text. Check the same in `CODE_OF_CONDUCT.md`, `SUPPORT.md`, `GOVERNANCE.md`, `MAINTAINERS.md`.
- [ ] `docs/` leftovers: `docs/log/**` and `docs/research/**` keep the old name with a note; check `docs/SUMMARY.md`, the RFC file name (`rfc-0001-<name>.md`) and the ADR links.
- [ ] Regenerate lockfiles, run `cargo fmt --all`, the full test run, `cargo deny check`, `python3 scripts/check-links.py`, `mdbook build`.
- [ ] Registries: `Cargo.toml` `repository`/`homepage`/`documentation`, `pyproject.toml` `[project.urls]`, `package.json` `repository`/`bugs`/`homepage`.
- [ ] Operators: release note listing the env var, header, metric and file path changes; Grafana/alert updates; move `onbehalf.sqlite`; update IdP registrations if the audience changed.
- [ ] Launch drafts (posts, announcement, demo transcript in `examples/github-leak-demo/`): rename or re-record the transcript, which contains the old binary name and message prefixes.
- [ ] Remove the rename item from `docs/tasks/board.md` and add a log entry.
