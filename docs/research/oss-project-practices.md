# Open-source project practices: what we adopt and why

- Date: 2026-10-22
- Scope: repository hygiene and process conventions for an infrastructure project in Rust. This is not about the protocol design; see `docs/spec/`.

## Method

Short survey (about 25 web lookups) of how a handful of well-run infrastructure projects structure their repositories: SpiceDB (authzed), Cedar, OpenFGA, Restate, Agentgateway, Meilisearch, the Rust RFC process, and the MADR convention for ADRs. Where a project's page could not be fetched, the entry says so rather than guessing.

## Findings by topic

### ADR format

- MADR ("Markdown Any Decision Records") is the de facto template. The MADR 4 full template has these headings: Context and Problem Statement; Decision Drivers (optional); Considered Options; Decision Outcome with Consequences and Confirmation (optional); Pros and Cons of the Options; More Information (optional). Status and date live in YAML front matter together with decision-makers / consulted / informed. Files are named `NNNN-title-with-dashes.md` under `decisions/`. Status examples: proposed, rejected, accepted, deprecated, superseded by ADR-NNNN. Source: [MADR](https://adr.github.io/madr/).
- JabRef and other projects keep an ADR-0000 "use MADR" record as the first entry ([example](https://devdocs.jabref.org/decisions/0000-use-markdown-architectural-decision-records.html)).

**We adopt:** MADR 4 headings verbatim, YAML front matter for status/date/deciders, sequential numbering, one PR per ADR. See `docs/decisions/README.md`.

### RFC process

- Rust: an RFC is required for "substantial" changes; the PR number becomes the RFC number; lifecycle is PR, final comment period (10 days), merged/active, implemented, or closed/postponed. Accepted RFCs change only minimally afterwards. Source: [rust-lang/rfcs README](https://github.com/rust-lang/rfcs/blob/master/README.md).
- Cedar: same shape with a 7-day FCP and statuses pending, final comment period, unstable (accepted), stable (implemented and stabilised), rejected. Rejected RFCs move to an archive folder. Source: [cedar-policy/rfcs](https://github.com/cedar-policy/rfcs).
- OpenFGA: RFC needed for anything touching models, tuples, supported interfaces (HTTP API) or packaging; date-prefixed file names (`YYYYMMDD-name.md`); FCP of 7 days; supermajority of core team. Source: [openfga/rfcs](https://github.com/openfga/rfcs).

**We adopt:** the Rust/Cedar shape scaled to a one-maintainer project: RFC required for changes to the token format, policy request shape, audit schema or public API; sequential numbering; statuses draft, accepted, implemented, superseded (plus rejected). A seven-day comment window once the project has more than one maintainer. See `docs/spec/README.md`.

### CHANGELOG

- Keep a Changelog 1.1.0: a human-written `CHANGELOG.md`, newest first, an `Unreleased` section at the top, entries grouped under Added / Changed / Deprecated / Removed / Fixed / Security, link references to compare views. Source: [keepachangelog.com](https://keepachangelog.com/en/1.1.0/).
- git-cliff generates a changelog from conventional commits and can emit Keep-a-Changelog style output; release-plz uses git-cliff under the hood. Sources: [git-cliff configuration](https://git-cliff.org/docs/configuration), [release-plz docs](https://release-plz.dev/docs).

**We adopt:** Keep a Changelog as the format of record. `cliff.toml` is configured to produce the same groups from conventional commits so the generated draft can be pasted into the Unreleased section and edited by hand. Security-relevant entries always go under `Security`.

### SECURITY.md and vulnerability disclosure

- GitHub picks up a root `SECURITY.md` and shows it under the repo's Security tab; private vulnerability reporting can be enabled per repo. Source: [GitHub docs](https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository).
- SpiceDB: email `security@authzed.com`, embargo until affected parties have patched, and an explicit statement that incorrect API responses count as vulnerabilities because callers make security decisions on them. Source: [SpiceDB SECURITY.md](https://github.com/authzed/spicedb/blob/main/SECURITY.md).
- Meilisearch: email channel, 72-hour acknowledgement, only the latest stable release receives security fixes, a checklist of what to include in a report. Source: [Meilisearch SECURITY.md](https://github.com/meilisearch/meilisearch/blob/main/SECURITY.md).

**We adopt:** a `security@<domain>` mailbox placeholder plus GitHub private vulnerability reporting, 72-hour acknowledgement, 90-day coordinated disclosure window (the industry default from Project Zero onwards), supported-versions table, and a severity statement borrowed from SpiceDB's framing: an incorrect authorization answer, an attenuation violation, or audit-chain tampering is the highest severity class for this project.

### Code of conduct

- Contributor Covenant 2.1 is the standard text (used by Agentgateway, Zephyr, and most CNCF/LF projects). It includes an enforcement ladder (Correction, Warning, Temporary Ban, Permanent Ban). Source: [contributor-covenant.org](https://www.contributor-covenant.org/).

**We adopt:** Contributor Covenant 2.1 verbatim with the enforcement contact set to the security/conduct mailbox placeholder.

### CODEOWNERS, GOVERNANCE, MAINTAINERS

- Agentgateway (Linux Foundation) ships `CHARTER.md`, `CODEOWNERS`, `CODE_OF_CONDUCT.md`, `SECURITY.md`. Source: [agentgateway/agentgateway](https://github.com/agentgateway/agentgateway).
- SpiceDB is an OpenSSF Best Practices badge holder, which requires documented contribution process, vulnerability reporting, and release notes. Source: [bestpractices.dev entry](https://www.bestpractices.dev/es/projects/6348).
- CNCF-style projects separate the *rules* (GOVERNANCE.md: how decisions are made, how maintainers are added/removed) from the *roster* (MAINTAINERS.md).

**We adopt:** a `.github/CODEOWNERS` with a single owner for now, a `GOVERNANCE.md` that is honest about being a single-maintainer project and spells out the path to a multi-maintainer model, and a `MAINTAINERS.md` roster. Aim for the OpenSSF Best Practices passing badge once the first release is out.

### Issue and PR templates

- GitHub issue forms (`.github/ISSUE_TEMPLATE/*.yml`) give structured bug reports; a `config.yml` can disable blank issues and link to the security policy. Security reports should never be filed as issues; the standard pattern is a markdown template that only points at `SECURITY.md`.

**We adopt:** YAML forms for bug and feature, a markdown stub for security that redirects, and `blank_issues_enabled: false`.

### Release process

- Semantic versioning with `v`-prefixed tags is universal among the surveyed projects.
- Conventional Commits drive both changelog generation and version bumping in release-plz; cargo-release is the manual alternative (bump, tag, publish from a developer machine). release-plz opens a release PR, updates versions and changelog via git-cliff, publishes to crates.io, creates tags and GitHub releases, and runs cargo-semver-checks. Source: [release-plz docs](https://release-plz.dev/docs).
- Binary distribution: `taiki-e/upload-rust-binary-action` builds and attaches archives plus checksums to a GitHub release per target; `taiki-e/setup-cross-toolchain-action` handles Linux cross builds; `taiki-e/create-gh-release-action` creates the release from `CHANGELOG.md`. Source: [upload-rust-binary-action README](https://github.com/taiki-e/upload-rust-binary-action).

**We adopt:** semver, `v*` tags, Conventional Commits, a draft `release.yml` using the taiki-e actions for Linux x86_64 / aarch64 and macOS arm64. Crate publishing via release-plz is deferred until the crates have a stable public API; until then releases are manual tag pushes.

### Supply chain checks

- `cargo-deny` (Embark) checks advisories (RustSec), licenses, bans and sources in one tool. In the current config format the `[licenses]` section is allow-list only (`deny`, `copyleft`, `allow-osi-fsf-free`, `default` were removed) and `[advisories]` no longer has a `vulnerability` knob: every vulnerability is an error, `yanked` and `unmaintained` are configurable. Sources: [licenses cfg](https://embarkstudios.github.io/cargo-deny/checks/licenses/cfg.html), [advisories cfg](https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html).
- Dependabot supports the `cargo` and `github-actions` ecosystems with weekly schedules.

**We adopt:** `deny.toml` allowing Apache-2.0 / MIT / BSD-2 / BSD-3 / ISC / Unicode-3.0 / Zlib / MPL-2.0, a `supply-chain` CI job running `cargo deny check` and `cargo audit`, and weekly Dependabot for cargo and actions.

### DCO vs CLA

- DCO: a one-line `Signed-off-by` added with `git commit -s`, asserting the contributor has the right to submit the work under the project licence. Used by the Linux kernel, CNCF and most Linux Foundation projects. A CLA needs a signing flow and legal review, and is mostly needed when a company wants the right to relicense. Sources: [LF best practices](https://bestpractices.linuxfoundation.org/ip/contribution-mechanisms-dco.html), [opensource.com comparison](https://opensource.com/article/18/3/cla-vs-dco-whats-difference), [Drew DeVault on DCO](https://drewdevault.com/blog/DCO/).

**We adopt:** DCO. Apache-2.0 already carries an explicit patent grant in section 3 and a contribution clause in section 5, so a CLA adds friction without adding much. Enforce with the `dco` GitHub App once the repo is public.

### Docs site conventions

- Cedar, OpenFGA and Rust keep RFC text in the repo (`text/` or `docs/`) and render it with a static site later; the markdown is the source of truth. SpiceDB and Meilisearch keep the user docs in a separate repo.

**We adopt:** keep everything under `docs/` as plain markdown that is also an Obsidian vault. A rendered site (mdBook is the natural fit for a Rust project) is a later task; nothing in the layout should block it.

## Summary of decisions

| Topic | Decision | Where |
| --- | --- | --- |
| ADRs | MADR 4, sequential numbers, one PR each | `docs/decisions/` |
| RFCs | Required for wire/API changes, draft/accepted/implemented/superseded | `docs/spec/` |
| Changelog | Keep a Changelog, hand-edited, git-cliff drafts | `CHANGELOG.md`, `cliff.toml` |
| Security | Private email + GitHub PVR, 72h ack, 90-day CD | `SECURITY.md` |
| Conduct | Contributor Covenant 2.1 | `CODE_OF_CONDUCT.md` |
| Governance | Single maintainer, documented path to a maintainer group | `GOVERNANCE.md`, `MAINTAINERS.md`, `.github/CODEOWNERS` |
| Contributions | Conventional Commits, DCO sign-off, branch prefixes | `CONTRIBUTING.md` |
| Releases | semver, `v*` tags, taiki-e binary upload | `.github/workflows/release.yml` |
| Supply chain | cargo-deny, cargo-audit, Dependabot weekly | `deny.toml`, `.github/dependabot.yml`, CI |
