# Launch checklist

Engineering checklist for the first public release. It lists what to check and set up, and none of it has been done yet unless a line says so. Maintainers only. Each item points at the file or workflow it concerns, so you can see what exists before you tick the box.

The first release is 0.1.0. Its notes draft, what is already prepared and the exact steps to tag and publish it, including a manual fallback while GitHub Actions are blocked, are in [Release 0.1.0](release/0.1.0.md). `scripts/release-check.sh` runs every local check it needs.

## Repository settings

- [ ] Branch protection on `main`: pull request required, CI checks required, no direct pushes, as [CONTRIBUTING](https://github.com/attenuo-dev/attenuo/blob/main/CONTRIBUTING.md) and [GOVERNANCE](https://github.com/attenuo-dev/attenuo/blob/main/GOVERNANCE.md) already promise. The one required check is `ci-ok` in `.github/workflows/ci.yml`: it waits for `fmt`, `clippy`, `test`, `msrv`, `deny`, `audit`, `demo`, `console-browser`, `policy-tests`, `fuzz-build` and `docs`, passes when each passed or was skipped on purpose (documentation-only pull requests, the fuzz build on most pull requests), and fails otherwise. Do not mark the individual jobs as required: branch protection counts a skipped job as passed, so a failed `changes` job would skip every Rust job and still look green ([details](research/ci-minutes-2026-11-05.md#branch-protection)). `.github/CODEOWNERS` says code-owner approval satisfies the rule.
- [ ] Discussions switched on, then point `SUPPORT.md` and the "Ask a question" link in `.github/ISSUE_TEMPLATE/config.yml` at `/discussions` (both point at SUPPORT.md until then).
- [ ] Private vulnerability reporting switched on. [SECURITY.md](https://github.com/attenuo-dev/attenuo/blob/main/SECURITY.md) points reporters at `github.com/attenuo-dev/attenuo/security/advisories/new`.
- [ ] Issue templates render: open the "New issue" page and confirm the bug report, feature request and security links appear, and that blank issues are off (`.github/ISSUE_TEMPLATE/`).
- [ ] Pull request template appears on a test PR (`.github/pull_request_template.md`).
- [ ] Dependabot enabled (`.github/dependabot.yml`) and the repository has a description, topics and the Apache-2.0 licence detected.

## SECURITY.md contact

- [x] The `security@<domain>` placeholder is gone from SECURITY.md (2026-11-05); GitHub private vulnerability reporting is the only channel. Switch it on in the repository's security settings once the repo is public (the feature exists only for public repositories), and add a mailbox later if a project domain exists.
- [ ] Check the response times SECURITY.md promises are ones a single maintainer can keep.

## Documentation site

- [ ] In Settings, Pages, set the source to "GitHub Actions". `.github/workflows/docs.yml` builds the mdBook site from `docs/` and deploys it to the `github-pages` environment.
- [ ] Run the docs workflow on `main` and open the deployed URL. Click through the sidebar, check that Mermaid diagrams render (they load from a CDN), and check that the new pages ([comparison](comparison.md) and this one) are listed in `docs/SUMMARY.md`.
- [ ] Run `python3 scripts/check-links.py` and fix anything it reports.
- [ ] Fill in the `TODO` in the README for the crates.io and docs.rs badges once crates are published.

## Release workflow dry run

`.github/workflows/release.yml` says in its header that it has not been exercised: no tag has been pushed.

- [ ] On a fork, push a `v0.0.0-test` tag and watch the run. Expect four archives (Linux musl x86_64 and aarch64, macOS arm64 and x86_64), the multi-arch image to GHCR, the cosign signature, the SPDX SBOM, `SHA256SUMS`, and a draft release.
- [ ] Download an archive, run `attenuo --help` and `attenuo-server --help`, and check the checksum against `SHA256SUMS`.
- [ ] Delete the test tag, the draft release and the test image.
- [ ] After the first real push, set the GHCR package to public.

## Signing and SBOM

- [ ] Verify the signature of the test image with the command from the workflow header, using the real identity `https://github.com/attenuo-dev/attenuo/.github/workflows/release.yml@` and the issuer `https://token.actions.githubusercontent.com`:

  ```sh
  cosign verify ghcr.io/attenuo-dev/attenuo:<version> \
    --certificate-identity-regexp '^https://github.com/attenuo-dev/attenuo/\.github/workflows/release\.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

- [ ] Verify the SBOM attestation (`cosign verify-attestation --type spdxjson`, same identity flags) and check that the SPDX file lists the dependencies you expect.
- [ ] Write the verification command into the release notes so readers can copy it. If the repository is renamed or moved, the identity regexp changes with it.

## Crates

Crate publishing is manual for now (see "Releases" in CONTRIBUTING). The crates are `attenuo-core`, `attenuo-token`, `attenuo-audit`, `attenuo-policy`, `attenuo-proxy`, `attenuo-server` and `attenuo-cli`. `attenuo-bench` has `publish = false`.

- [ ] Check that each crate name is free on crates.io before announcing anything.
- [ ] Dry-run in dependency order, from the leaves up, and read each warning:

  ```sh
  cargo publish --dry-run -p attenuo-core
  cargo publish --dry-run -p attenuo-token
  cargo publish --dry-run -p attenuo-audit
  cargo publish --dry-run -p attenuo-policy
  cargo publish --dry-run -p attenuo-proxy
  cargo publish --dry-run -p attenuo-server
  cargo publish --dry-run -p attenuo-cli
  ```

  A dry run for a crate whose dependencies are not yet on crates.io fails at the resolve step. Expect that for everything above `attenuo-core` until the earlier crates are published. `cargo publish --dry-run --workspace --locked` (Cargo 1.90+) verifies all seven against each other through a temporary local registry instead; it passed for 0.1.0 on 2026-10-24 and is a step of `scripts/release-check.sh`.
- [x] Each crate has a description, licence, repository and `rust-version` (they inherit from the workspace), plus `homepage`, `readme` (each crate's own `README.md`), `keywords`, `categories` and a `LICENSE` file. Done for 0.1.0 on `release/0.1.0-prep`.
- [ ] The SDKs (`sdk/python`, `sdk/typescript`) are at 0.1.0, build and pass `twine check` and `npm pack --dry-run`, and say in their READMEs that they are not on PyPI or npm until the release is published. Decide whether the first release publishes them. If it does, check the package names and the `@attenuo` npm scope are yours first.

## Release notes and changelog

- [ ] `CHANGELOG.md` `Unreleased` is complete. Compare it with `git cliff --unreleased`, using `cliff.toml`.
- [ ] Open the `chore(release): vX.Y.Z` PR described in CONTRIBUTING: bump `workspace.package.version`, move `Unreleased` to a dated heading, add a fresh empty `Unreleased`.
- [ ] Tag, wait for the draft release, and read the git-cliff section the workflow rendered. Edit the first public release's notes by hand: say it is pre-alpha, link the [README status section](https://github.com/attenuo-dev/attenuo#status), and list the untested areas (identity provider recipes, Docker, production use).
- [ ] Publish the draft by hand.

## Before the announcement

- [ ] Clone the repository fresh into an empty directory and run `examples/github-leak-demo/run.sh`. It should finish and print one upstream call.
- [ ] Follow [getting started](guides/getting-started.md) on a second machine or a clean container.
- [ ] Re-read the README numbers against [performance](design/performance.md) and the [injection suite](evaluation/injection-suite.md), and re-run the suite and the benchmark if the code has changed since they were taken. Done for main @ de3cf75 on 2026-10-24 (see [Numbers audit 2026-10-24](#numbers-audit-2026-10-24)); repeat if main moves before launch.
- [ ] Re-check [comparison](comparison.md) against the other products' current documentation. It is dated, and these products change.
- [ ] Look at the task board for findings still open, and decide which to list in the release notes (see [security review, pass 4](research/security-review-2026-10-23-pass4.md)).
- [ ] Scrub `docs/log/` of process notes that are not about the code before the repo goes public: lines about usage-limit pauses, agent or worker scheduling, laptop sync and session restarts (grep for `usage limit`, `laptop`, `session restart`, `agents`). Keep the per-merge technical history. Owner: Claude.

### Numbers audit 2026-10-24

Every quantitative claim in the README, `docs/` (outside `docs/log/`, `docs/design/bench/` and the research notes, which quote outside sources), SECURITY.md, CONTRIBUTING.md, the SDK and example READMEs, checked against main @ de3cf75. No crate has its own README. "Fixed" means the text now carries the sourced figure and a link.

| File:line | Claim | Source of truth | Verdict |
| --- | --- | --- | --- |
| README.md:71 | 10 of 60 dev attack calls still went through | [results v2](https://github.com/attenuo-dev/attenuo/blob/main/evaluation/injection-suite/results/2026-10-23-v2.md), re-run on de3cf75 with the same tables | ok |
| README.md:78 | dev 46 cases, 60 attack / 69 benign; 60, 41, 10 allowed; 3 benign refused; test 26 cases (72 in all), 7/38, 3/29 | results v2 | ok |
| README.md:79 | added p50 0.4 to 0.8 ms (425 to 771 us) | [performance](design/performance.md#after-the-policy-stage-and-wal-work), [policy-stage run](design/bench/2026-10-23-vm-policy-stage.md) | ok |
| README.md:80 | Cedar 13 us on a cache hit, 125 to 175 us on a miss | [criterion policy_stage](design/bench/2026-10-23-vm-criterion-policy_stage.txt): 11.8 to 13.0 and 122 to 163; 125/175 is marked unrecorded | stale, fixed |
| README.md:81 | 1,252 / 4,049 / 6,254 req/s; loss window 5 s or 256 commits | policy-stage run; performance | ok, link added |
| README.md:81 | open-loop load listed as not measured | performance: open-loop measured for the allow call at one hop and for exchange | stale, fixed |
| README.md:87 | 4 passes; 26, 13, 15 findings; 5 High in pass 1; 1 Medium in pass 4; 2 Info accepted (SR-52, SR-54) | the three review reports | ok, "54 in all" added |
| README.md:88 | 669 Rust, 157 Python (10 skipped), 150 TS (7 skipped) on 1a00055; suite 19 checks; demo | de3cf75: 748; 175 (10 skipped); 158 (7 skipped); suite 15 passed, 4 skipped | stale, fixed; demo claim dropped (not re-run on de3cf75) |
| README.md:88 | 12 fuzz targets; 5 bugs, all fixed | [fuzzing](design/fuzzing.md) | ok; second campaign added (10 min each, about 282M inputs, 0 crashes) |
| docs/faq.md:47 | 0.4 to 0.8 ms added at the median | performance | ok |
| docs/faq.md:49 | policy 13 us hit, 125 to 175 us miss | criterion policy_stage | stale, fixed |
| docs/faq.md:49 | attenuation check tens of ns to a few us | [criterion attenuation](design/bench/2026-10-23-vm-criterion-attenuation.txt): 15.9 ns to 5.06 us | ok |
| docs/faq.md:51 | 425 to 771 us; open loop 0.6 to 0.8 ms at 500 to 2,000/s; 860 to 1,770 and 4,000 to 6,650 req/s; file 6 to 30 percent below memory; p99 at 8 clients 4 to 10 ms | performance tables | ok, open-loop link added |
| docs/faq.md:53 | "closed-loop load" | open-loop cells exist | stale, now "mostly closed-loop" |
| docs/faq.md:53 | a few hundred calls/s before WAL mode | performance (the "before" column, 460 to 490, unrecorded) | ok, qualitative |
| docs/evaluation/injection-suite.md:8-58 | all tables and counts | results v2 | ok |
| docs/guide/codebase-walkthrough.md:6 | sessions of 45 to 60 minutes | an estimate, not a measurement | ok |
| docs/guide/codebase-walkthrough.md:245-443 | Lines column for `lease.rs`, `sqlite.rs`, server `main.rs`/`lib.rs`, `state.rs`, `routes/admin.rs`, CLI `cli.rs`, `main.rs`, `jwt.rs` and three others, Python `admin.py` | `wc -l` on de3cf75: 19 to 131 percent off | stale, fixed; every other row within 10 percent |
| docs/guide/codebase-walkthrough.md:206, 222; docs/guides/writing-policies.md:226; examples/github-leak-demo/README.md:46 | nine policy tests | `policy_test.yaml` has 9 cases | ok |
| docs/guide/codebase-walkthrough.md:488 | TS 150 passed, 7 skipped | 158 passed, 7 skipped | stale, fixed |
| docs/guide/codebase-walkthrough.md:516 | suite 15 passed, 4 skipped | `pytest evaluation/injection-suite` on de3cf75 | ok |
| docs/guide/codebase-walkthrough.md:526 | full bench run about 9 minutes | performance, "How to run" | ok |
| CHANGELOG.md:86-101 | performance and eval figures | performance, bench files, results v2 | ok (dated entries, not edited) |
| docs/tasks/board.md:76-83 | pass 3 and 4 counts, policy-stage figures | review reports, performance | ok |
| docs/decisions/0004-rust-workspace-layout.md:14, 37 | seven crates | eight today (`attenuo-bench` added later) | ok as the ADR's original text, not edited |
| docs/design/rename-plan.md:69 | all eight crates | `crates/` | ok |
| SECURITY.md:28-33 | 72 hours, 7 days, 90 days | commitments, not measurements | ok |
| docs/faq.md:92; docs/guides/deploying.md:166, 233; docs/guides/admin-console.md:41 | 1,000 entries / 300 s checkpoints, 300 s leases, 10 s drain, 15 min idle lock | config defaults (`config/example.toml`), spot-checked | ok |
| CONTRIBUTING.md, comparison.md, SDK and example READMEs | no quantitative claims beyond the above | | n/a |
