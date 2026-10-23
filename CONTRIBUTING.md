# Contributing

Thank you for considering a contribution. This document is the whole process; if something here is unclear or wrong, a PR fixing it is welcome too.

## Ground rules

- `main` is protected: no direct pushes. Every change goes through a branch and a pull request.
- A PR is mergeable when fmt, clippy (`-D warnings`), the full test suite and the supply-chain checks pass, and new behaviour has tests.
- Design decisions are recorded as ADRs in `docs/decisions/` (one file per decision, numbered). See [docs/decisions/README.md](docs/decisions/README.md).
- Changes to the token format, policy request shape, audit schema or public API need an RFC first. See [docs/spec/README.md](docs/spec/README.md).
- The `docs/` folder is an Obsidian vault. Open it with "Open folder as vault".
- Security-relevant invariants (attenuation, revocation, audit chain) must have a property or integration test, not only a unit test.
- Security bugs are reported privately, never as issues or PRs. See [SECURITY.md](SECURITY.md).
- Everyone participating is bound by the [code of conduct](CODE_OF_CONDUCT.md).

## Before you start

Open an issue for anything bigger than a small fix so the approach can be agreed before you spend time on it. Use the bug or feature templates; they ask for what we need. For a change that needs an RFC, the issue is where you get the go-ahead to write one.

## Running the checks locally

CI runs exactly these. Run them before pushing.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check          # cargo install cargo-deny
cargo audit               # cargo install cargo-audit (optional locally; CI runs it)
```

`scripts/dev.sh` runs fmt, clippy, the tests and the GitHub leak demo in one go (`scripts/dev.sh policy docs links deny` runs the other CI steps). The `justfile` has the same targets if you use [just](https://github.com/casey/just): `just dev`, `just ci`, `just demo`, `just policy`. `scripts/gen-admin-token.sh` prints a random admin token for a local server config. The MSRV (`rust-version` in `Cargo.toml`) is checked in CI only.

`rustfmt.toml` and `clippy.toml` in the repo root carry the project settings, so `cargo fmt` and `cargo clippy` pick them up without flags. The toolchain is pinned by `rust-toolchain.toml`.

## Branches

Branch from `main`. Name the branch with a type prefix and a short slug:

| Prefix | Use |
| --- | --- |
| `feat/` | new behaviour |
| `fix/` | bug fixes |
| `docs/` | documentation, ADRs, RFCs |
| `chore/` | tooling, CI, dependencies, repo hygiene |
| `refactor/`, `test/`, `perf/` | also accepted, same meaning as the commit types |

Example: `feat/token-caveats`, `fix/audit-chain-reorder`.

## Commits

### Conventional Commits

Commit messages follow [Conventional Commits 1.0](https://www.conventionalcommits.org/en/v1.0.0/). The changelog and version bumps are derived from them, so this is checked in review.

```
<type>(<scope>): <short summary in imperative mood>

<body: what and why, not how>

<footer: BREAKING CHANGE:, Refs:, Fixes:, Signed-off-by:>
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `perf`, `build`, `ci`, `revert`. Scope is the crate without the `onbehalf-` prefix (`core`, `token`, `policy`, `audit`, `proxy`, `server`) or an area (`ci`, `docs`, `deps`). A breaking change carries `!` after the type/scope and a `BREAKING CHANGE:` footer explaining the migration.

```
feat(token)!: require audience claim on every token

Tokens without `aud` were accepted and could be replayed against any
service. Verification now rejects them.

BREAKING CHANGE: tokens minted before this change fail verification.
Refs: ADR-0004
Signed-off-by: Jane Doe <jane@example.com>
```

### Developer Certificate of Origin

We use the [DCO](https://developercertificate.org/) instead of a CLA. By signing off a commit you certify that you wrote the change or otherwise have the right to submit it under the project's Apache-2.0 licence. Sign off every commit:

```sh
git commit -s
```

This appends `Signed-off-by: Your Name <you@example.com>` using your git identity. The name and email must be real and must match the commit author. A PR with unsigned commits will be asked to rebase with `git rebase --signoff`. (When the DCO GitHub App is enabled on the repository, it enforces this automatically.)

## Pull requests

- One logical change per PR. Split large work into a sequence of reviewable PRs; an RFC or ADR can go first on its own.
- Fill in the PR template: what, why, how it was verified, and which docs changed.
- Keep the PR title in conventional commit form too; it becomes the squash commit message if the PR is squashed.
- Link the issue, RFC or ADR the PR implements (`Fixes #12`, `Refs: ADR-0003`).
- Respond to review with new commits rather than force-pushing while review is in progress, so comments keep their context. Squash or tidy at the end if asked.
- CI must be green. Do not add `#[allow(...)]` or ignore a cargo-deny finding to get there without saying why in the PR.

## Definition of done

A change is done when all of the following hold:

1. The behaviour is implemented and covered by tests at the right level: unit tests for logic, property tests for invariants (attenuation only narrows, chains verify, audit records chain), integration tests for anything that crosses a crate or process boundary.
2. `cargo fmt`, `cargo clippy -D warnings`, `cargo test --workspace` and `cargo deny check` pass locally and in CI.
3. Public items have doc comments; new configuration or CLI flags are documented.
4. `CHANGELOG.md` has an entry under `Unreleased` if the change is visible to users (new feature, behaviour change, fix, security fix).
5. An ADR or RFC exists for any design decision the change embodies, and its status is updated if the change implements it.
6. The task is moved on `docs/tasks/board.md` and, if you keep one, a line is added to today's file in `docs/log/`.
7. Commits are signed off and in conventional form; the PR has at least one maintainer approval.

## Releases

Maintainers only. Versions follow [SemVer 2.0](https://semver.org/). Pre-1.0, a minor bump may break; every breaking change is marked in the changelog.

1. Make sure `main` is green and `CHANGELOG.md`'s `Unreleased` section is complete. `git cliff --unreleased` gives a draft to compare against.
2. Open a `chore(release): vX.Y.Z` PR that bumps `workspace.package.version` in `Cargo.toml`, moves `Unreleased` to a dated `[X.Y.Z]` heading with a compare link, and adds a fresh empty `Unreleased`.
3. Merge, then tag the merge commit `vX.Y.Z` (annotated, signed if you have a key) and push the tag. `.github/workflows/release.yml` builds `onbehalf` and `onbehalf-server` for Linux (musl, x86_64 and aarch64) and macOS (arm64, x86_64), pushes a signed multi-arch image to GHCR (cosign keyless, SBOM attached), and opens a **draft** GitHub release with the archives, `SHA256SUMS` and the git-cliff changelog section. Review the draft and publish it by hand. It needs only the automatic `GITHUB_TOKEN`; set the GHCR package to public after the first push.
4. Crate publishing to crates.io is manual until the public API settles; the plan is to adopt release-plz once it does.

## Licence

By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), as certified by your DCO sign-off.
