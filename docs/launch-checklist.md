# Launch checklist

Engineering checklist for the first public release. It lists what to check and set up, and none of it has been done yet unless a line says so. Maintainers only. Each item points at the file or workflow it concerns, so you can see what exists before you tick the box.

## Repository settings

- [ ] Branch protection on `main`: pull request required, CI checks required, no direct pushes, as [CONTRIBUTING](https://github.com/7Mudit/onbehalf/blob/main/CONTRIBUTING.md) and [GOVERNANCE](https://github.com/7Mudit/onbehalf/blob/main/GOVERNANCE.md) already promise. The required checks are the jobs in `.github/workflows/ci.yml`: `fmt`, `clippy`, `test`, `msrv`, `deny`, `audit`, `demo`, `policy-tests`, `fuzz-build`, `docs`. `.github/CODEOWNERS` says code-owner approval satisfies the rule.
- [ ] Discussions switched on. `.github/ISSUE_TEMPLATE/config.yml` already links to `/discussions` for questions and early design ideas, so the link is dead until this is enabled.
- [ ] Private vulnerability reporting switched on. [SECURITY.md](https://github.com/7Mudit/onbehalf/blob/main/SECURITY.md) points reporters at `github.com/7Mudit/onbehalf/security/advisories/new`.
- [ ] Issue templates render: open the "New issue" page and confirm the bug report, feature request and security links appear, and that blank issues are off (`.github/ISSUE_TEMPLATE/`).
- [ ] Pull request template appears on a test PR (`.github/pull_request_template.md`).
- [ ] Dependabot enabled (`.github/dependabot.yml`) and the repository has a description, topics and the Apache-2.0 licence detected.

## SECURITY.md contact

- [ ] Replace the `security@<domain>` placeholder in SECURITY.md with a real mailbox, or remove the email line and keep GitHub private reporting as the only channel. Check that the mailbox receives mail.
- [ ] Check the response times SECURITY.md promises are ones a single maintainer can keep.

## Documentation site

- [ ] In Settings, Pages, set the source to "GitHub Actions". `.github/workflows/docs.yml` builds the mdBook site from `docs/` and deploys it to the `github-pages` environment.
- [ ] Run the docs workflow on `main` and open the deployed URL. Click through the sidebar, check that Mermaid diagrams render (they load from a CDN), and check that the new pages ([comparison](comparison.md) and this one) are listed in `docs/SUMMARY.md`.
- [ ] Run `python3 scripts/check-links.py` and fix anything it reports.
- [ ] Fill in the `TODO` in the README for the crates.io and docs.rs badges once crates are published.

## Release workflow dry run

`.github/workflows/release.yml` says in its header that it has not been exercised: no tag has been pushed.

- [ ] On a fork, push a `v0.0.0-test` tag and watch the run. Expect four archives (Linux musl x86_64 and aarch64, macOS arm64 and x86_64), the multi-arch image to GHCR, the cosign signature, the SPDX SBOM, `SHA256SUMS`, and a draft release.
- [ ] Download an archive, run `onbehalf --help` and `onbehalf-server --help`, and check the checksum against `SHA256SUMS`.
- [ ] Delete the test tag, the draft release and the test image.
- [ ] After the first real push, set the GHCR package to public.

## Signing and SBOM

- [ ] Verify the signature of the test image with the command from the workflow header, using the real identity `https://github.com/7Mudit/onbehalf/.github/workflows/release.yml@` and the issuer `https://token.actions.githubusercontent.com`:

  ```sh
  cosign verify ghcr.io/7mudit/onbehalf:<version> \
    --certificate-identity-regexp '^https://github.com/7Mudit/onbehalf/\.github/workflows/release\.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

- [ ] Verify the SBOM attestation (`cosign verify-attestation --type spdxjson`, same identity flags) and check that the SPDX file lists the dependencies you expect.
- [ ] Write the verification command into the release notes so readers can copy it. If the repository is renamed or moved, the identity regexp changes with it.

## Crates

Crate publishing is manual for now (see "Releases" in CONTRIBUTING). The crates are `onbehalf-core`, `onbehalf-token`, `onbehalf-audit`, `onbehalf-policy`, `onbehalf-proxy`, `onbehalf-server` and `onbehalf-cli`. `onbehalf-bench` has `publish = false`.

- [ ] Check that each crate name is free on crates.io before announcing anything.
- [ ] Dry-run in dependency order, from the leaves up, and read each warning:

  ```sh
  cargo publish --dry-run -p onbehalf-core
  cargo publish --dry-run -p onbehalf-token
  cargo publish --dry-run -p onbehalf-audit
  cargo publish --dry-run -p onbehalf-policy
  cargo publish --dry-run -p onbehalf-proxy
  cargo publish --dry-run -p onbehalf-server
  cargo publish --dry-run -p onbehalf-cli
  ```

  A dry run for a crate whose dependencies are not yet on crates.io fails at the resolve step. Expect that for everything above `onbehalf-core` until the earlier crates are published, and decide whether to publish in order or to publish only the libraries.
- [ ] Each crate has a description, licence, repository and `rust-version` (they inherit from the workspace). Add `readme`, `keywords` and `categories` if you want them on the crate page.
- [ ] The SDKs (`sdk/python`, `sdk/typescript`) are not published to PyPI or npm today and say so in their READMEs. Decide whether the first release publishes them. If it does, check the package names and the `@onbehalf` npm scope are yours first.

## Release notes and changelog

- [ ] `CHANGELOG.md` `Unreleased` is complete. Compare it with `git cliff --unreleased`, using `cliff.toml`.
- [ ] Open the `chore(release): vX.Y.Z` PR described in CONTRIBUTING: bump `workspace.package.version`, move `Unreleased` to a dated heading, add a fresh empty `Unreleased`.
- [ ] Tag, wait for the draft release, and read the git-cliff section the workflow rendered. Edit the first public release's notes by hand: say it is pre-alpha, link the [README status section](https://github.com/7Mudit/onbehalf#status), and list the untested areas (identity provider recipes, Docker, production use).
- [ ] Publish the draft by hand.

## Before the announcement

- [ ] Clone the repository fresh into an empty directory and run `examples/github-leak-demo/run.sh`. It should finish and print one upstream call.
- [ ] Follow [getting started](guides/getting-started.md) on a second machine or a clean container.
- [ ] Re-read the README numbers against [performance](design/performance.md) and the [injection suite](evaluation/injection-suite.md), and re-run the suite and the benchmark if the code has changed since they were taken.
- [ ] Re-check [comparison](comparison.md) against the other products' current documentation. It is dated, and these products change.
- [ ] Look at the task board for findings still open, and decide which to list in the release notes (see [security review, pass 4](research/security-review-2026-10-23-pass4.md)).
