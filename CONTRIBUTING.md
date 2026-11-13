# Contributing

Thank you for considering a contribution. This document is the whole process; if something here is unclear or wrong, a PR fixing it is welcome too.

## Ground rules

- No direct pushes to `main`. Every change goes through a branch and a pull request. Branch protection enforces this once the repository is public; before that it was kept by practice.
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

`scripts/dev.sh` runs fmt, clippy, the tests and the three scripted demos (the GitHub leak demo, the multi-hop delegation demo and the IdP exchange demo) in one go (`scripts/dev.sh policy docs links deny` runs the other CI steps). The `justfile` has the same targets if you use [just](https://github.com/casey/just): `just dev`, `just ci`, `just demo`, `just policy`. `scripts/gen-admin-token.sh` prints a random admin token for a local server config.

`scripts/check-getting-started.sh` (`scripts/dev.sh guide`, `just guide`, and the `getting-started` CI job) runs every `sh` block of [the getting-started guide](docs/guides/getting-started.md) in order, in one shell with a scratch `HOME` and free ports, and fails when a command fails or its output differs from the `text` or `json` block that follows it (times, UUIDs and key ids are masked). It reads the commands from the guide, so when you change a command or an output there, run it. A few blocks carry an HTML comment on the line before the fence (`<!-- check: build -->`, `<!-- check: background -->`, `<!-- check: exit 2 -->`, `<!-- check: skip REASON -->` for a block that needs Docker, the network or a long build) that says how to run them; the header of `scripts/check-doc-commands.sh`, which does the work, explains each. It takes a few seconds after the build. The same check runs the README's "Run the server yourself" and "Command line" sections: `scripts/check-doc-commands.sh README.md` (`scripts/dev.sh readme`, `just readme`, the same CI job), which prints every skipped block with its reason. When you change a command or an output in the README, run it.

The SDK READMEs' snippets are tested as code: `sdk/python/tests/test_readme_snippets.py` compiles and type-checks (mypy) every `python` block of `sdk/python/README.md` and of the README's Python SDK section, and `sdk/typescript/test/readme.test.ts` type-checks every `ts` block of `sdk/typescript/README.md` and of the README's TypeScript SDK section against the built SDK types (`npm run build` first). Both run with the SDK's unit tests (`pytest`, `npm test`); with `ATTENUO_INTEGRATION=1` they also run the self-contained snippets, the quick starts among them, against a server on `config/example.toml` with the dev root mint on. `scripts/dev.sh snippets` (`just snippets`) runs both type checks.

The MSRV (`rust-version` in `Cargo.toml`) is checked in CI only.

### Property tests

The property tests (`crates/attenuo-core/tests/*_props.rs`, `crates/attenuo-audit/tests/budget_props.rs`) take their settings from two environment variables, read by the `proptest_config` helper in each crate's `tests/proptest_seed/mod.rs`:

- Locally the seed is random, so every run explores new cases. The seed is printed in the test's captured output, which `cargo test` shows when the test fails: `proptest: random seed, replay with PROPTEST_RNG_SEED=<n>`.
- `PROPTEST_RNG_SEED=<n>` (a decimal u64, proptest's own variable) replays that exact sequence: `PROPTEST_RNG_SEED=<n> cargo test -p attenuo-core --test attenuation_props <name>`.
- `PROPTEST_CASES=<n>` runs more (or fewer) cases per property than the per-test default (512 for attenuation, 1024 for limits, 256 for budgets; the file-store budget test runs an eighth of that).
- CI pins both in the `test` job of `.github/workflows/ci.yml`: `PROPTEST_RNG_SEED=20261024` and `PROPTEST_CASES=1024`, so a red run is reproducible and a green one is not luck. Changing the seed there is how CI explores a new sequence.

A bad value of either variable fails the test with a message naming it. Failure persistence is off and `proptest-regressions/` is gitignored: keep a failure you have understood as a deterministic regression test next to the properties, not as a regressions file.

Fuzz targets for the parsers and checks an attacker can reach live in `fuzz/` (cargo-fuzz, nightly, outside the workspace). CI only builds them and runs their seeds; run one for a few minutes when you change a parser, a token or proof check, capability coverage, the proxy's JSON-RPC or SSE handling, or audit verification: `cargo +nightly fuzz run <target> -- -max_total_time=120`. See [fuzz/README.md](fuzz/README.md) and [docs/design/fuzzing.md](docs/design/fuzzing.md).

If you change the admin console (`crates/attenuo-server/ui/`), run `scripts/console-smoke.sh`. It builds and starts the server with the leak demo's config and an `[admin_ui]` listener, fills the log through the CLI, and opens every console page in headless Chromium in the dark and the light theme with Playwright. It fails on any console error, page error, failed request or CSP violation, on text below 4.5:1 contrast, and when the lease page's revoke preview differs from `attenuo lease tree`. It also configures four `[[admin.operators]]` (a viewer, an operator, an operator with a future `expires_at` and an expired viewer) and logs in as each in a fresh page (`tests/console/roles.test.cjs`): the header names the operator, role and expiry, the buttons a role cannot use (revoke, grant and decline, policy reload) are disabled, and an expired token gets the expired message at login. It needs Node 20 or later: run `npm ci` and `npx playwright install --with-deps chromium` in `tests/console/` once (Playwright is pinned to 1.56.1 there). Set `CONSOLE_SMOKE_SHOTS=DIR` to keep the screenshots, one per page and theme. It takes about 10 seconds after the build.

The Python SDK tests (`cd sdk/python && pytest -rf`, and `ATTENUO_INTEGRATION=1 pytest -rf -m integration` for the real-server tests) are run with `-rf` so that the name of a failing test is in the summary; see [sdk/python/README.md](sdk/python/README.md).

`rustfmt.toml` and `clippy.toml` in the repo root carry the project settings, so `cargo fmt` and `cargo clippy` pick them up without flags. `rust-toolchain.toml` pins the exact stable release CI, the release builds and the Dockerfile use (1.99.1), with `rustfmt` and `clippy`; rustup installs it on first use in the repository. A new stable is adopted in its own pull request that bumps `channel` there, the `RUST_VERSION` of the Dockerfile's base image, and fixes what the new clippy and rustdoc find. Nightly-only work names its toolchain (`cargo +nightly fuzz ...`), which overrides the file; so does the MSRV check (`cargo +1.89 check`).

## Previewing the documentation site

The pages in `docs/` are published as an [mdBook](https://rust-lang.github.io/mdBook/) site by `.github/workflows/docs.yml`. The book is configured in `book.toml` and its table of contents is `docs/SUMMARY.md`. A new page appears on the site only once it is listed there.

```sh
cargo install mdbook --locked --version 0.4.52   # the version CI uses
mdbook serve --open                              # http://localhost:3000, rebuilds on save
mdbook build                                     # one-off build into book/ (ignored by git)
python3 scripts/check-links.py                   # relative links, anchors, links out of the book
python3 scripts/check-public-hygiene.py          # no machine paths, personal notes, old name or placeholders
```

Keep the pages readable on GitHub and in Obsidian as well. Link to other pages with relative `.md` paths. Link to files outside `docs/` (for example `config/example.toml`) with a full GitHub URL (`https://github.com/attenuo-dev/attenuo/blob/main/<path>`, or `tree/main/` for a folder), because the book only contains `docs/`; `scripts/check-links.py` refuses a relative link out of `docs/` from a page listed in `docs/SUMMARY.md` (its tests: `python3 -m pytest scripts/test_check_links.py`). Pages not in the book may keep relative links. To link to a folder's `README.md`, link the folder (`../spec/`), since the book renders it as `index.html`. Mermaid diagrams render on the site through a script that loads mermaid from a CDN, so they need network access when you preview.

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

Pull request titles follow [Conventional Commits 1.0](https://www.conventionalcommits.org/en/v1.0.0/), and pull requests are squash-merged, so each one lands on `main` as a single commit with that title. The changelog and version bumps are derived from them, so this is checked in review. Commits inside a branch should follow the same form, but only the squashed commit has to. History from before the first public release does not follow this consistently and is not rewritten.

```
<type>(<scope>): <short summary in imperative mood>

<body: what and why, not how>

<footer: BREAKING CHANGE:, Refs:, Fixes:, Signed-off-by:>
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `perf`, `build`, `ci`, `revert`. Scope is the crate without the `attenuo-` prefix (`core`, `token`, `policy`, `audit`, `proxy`, `server`) or an area (`ci`, `docs`, `deps`). A breaking change carries `!` after the type/scope and a `BREAKING CHANGE:` footer explaining the migration.

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

Sign-off is required from the first public release on; earlier history is exempt. This appends `Signed-off-by: Your Name <you@example.com>` using your git identity. The name and email must be real and must match the commit author. A PR with unsigned commits will be asked to rebase with `git rebase --signoff`. (When the DCO GitHub App is enabled on the repository, it enforces this automatically.)

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
6. If the task is on `docs/tasks/board.md`, it moves from Open to Done there as one line with the pull request number (or is cut down to what is left). The durable record of a change is its `CHANGELOG.md` entry and its pull request description, so say there what changed and why.
7. Commits are signed off and in conventional form; the PR has at least one maintainer approval.

## Releases

Maintainers only. Versions follow [SemVer 2.0](https://semver.org/). Pre-1.0, a minor bump may break; every breaking change is marked in the changelog. What counts as breaking for each surface (routes, error codes, token claims, audit constructions, config keys, metrics, SDKs) and how it is deprecated first is in [API compatibility](docs/reference/api-compatibility.md); a change to the wire format is additive unless it follows those rules.

1. Make sure `main` is green and `CHANGELOG.md`'s `Unreleased` section is complete. `git cliff --unreleased` gives a draft to compare against. `scripts/release-check.sh` runs every local check a release needs, including the crates, PyPI and npm dry runs; the 0.1.0 steps are in [docs/release/0.1.0.md](docs/release/0.1.0.md).
2. Open a `chore(release): vX.Y.Z` PR that sets the new version in every place the `versions` step of `scripts/release-check.sh` compares, and that step fails when any of them differs from the workspace version:
   - `Cargo.toml`: `[workspace.package] version`, and the `version` of each `attenuo-*` entry under `[workspace.dependencies]` (`attenuo-core`, `attenuo-token`, `attenuo-policy`, `attenuo-audit`, `attenuo-proxy`);
   - `sdk/python/pyproject.toml`: `[project] version`;
   - `sdk/typescript/package.json`: `version`;
   - `sdk/typescript/package-lock.json`: the top-level `version` (run `npm install --package-lock-only` in `sdk/typescript` so the lockfile's `packages[""]` entry matches too);
   - `CHANGELOG.md`: move `Unreleased` to a `## [X.Y.Z] - YYYY-MM-DD` heading (the step looks for exactly that form) with a compare link, and add a fresh empty `Unreleased`.

   Also update `Cargo.lock` (`cargo update --workspace`): the step does not compare it, but the later steps build with `--locked` and fail on a stale lockfile.
3. Merge, then tag the merge commit `vX.Y.Z` (annotated, signed if you have a key) and push the tag. `.github/workflows/release.yml` builds `attenuo` and `attenuo-server` for Linux (musl, x86_64 and aarch64) and macOS (arm64, x86_64), pushes a signed multi-arch image to GHCR (cosign keyless, SBOM attached), and opens a **draft** GitHub release with the archives, `SHA256SUMS` and the git-cliff changelog section. Review the draft and publish it by hand. It needs only the automatic `GITHUB_TOKEN`; set the GHCR package to public after the first push.
4. Crate publishing to crates.io is manual until the public API settles; the plan is to adopt release-plz once it does.

### Release tooling

The Python package that PyPI receives is built only with the tools in `sdk/python/release-requirements.txt`: `build`, `twine` and the build backend `hatchling` with their dependencies, each pinned to a version and its sha256 hashes. `.github/workflows/release-packages.yml` installs the file with `pip install --require-hashes --only-binary :all:` into a fresh venv and runs `python -m build --no-isolation`, so nothing is resolved from the index at release time (SR-83). The file is compiled from `sdk/python/release-requirements.in` for Python 3.12 on Linux, the workflow's interpreter and runner. The hashes cover every wheel and sdist PyPI has for each pinned version; the set of packages is the one Linux needs (Windows-only dependencies of `twine` are left out).

Dependabot (the `pip` entry for `/sdk/python` in `.github/dependabot.yml`) checks weekly and opens a PR that recompiles the file when a pinned tool has a newer release. To do it by hand, or after changing the `.in` file or the `[build-system] requires` in `pyproject.toml`, run in `sdk/python` with Python 3.12:

```sh
python3.12 -m venv /tmp/piptools && /tmp/piptools/bin/pip install pip-tools
/tmp/piptools/bin/pip-compile --upgrade --generate-hashes --allow-unsafe --strip-extras \
  --no-emit-index-url --output-file=release-requirements.txt release-requirements.in
```

Then check it the way the workflow uses it: in a fresh Python 3.12 venv, `pip install --require-hashes --only-binary :all: -r release-requirements.txt`, then `python -m build --no-isolation --outdir dist .` and `twine check --strict dist/*`. A Dependabot PR's header line must still say "with Python 3.12"; if it names another version, recompile by hand. The npm jobs need no file of their own: `package-lock.json` pins every package by integrity hash, and both jobs run `npm ci --ignore-scripts`, so no dependency's install script runs in the job that holds the publish token; a dependency that gains one shows up as a lockfile change in review.

## AI-assisted contributions

AI coding tools are welcome; most of this repository was written with them (see [How this project is built](README.md#how-this-project-is-built)). The rules are the same as for any change: you are responsible for every line you submit, you must understand it well enough to answer review questions about it, and it must pass the same tests and review. Say in the pull request description which parts a tool wrote. Do not paste output you have not read, and do not submit code a tool generated from sources whose licence you cannot check. A `Co-Authored-By:` trailer for the tool is welcome; links to private tool sessions (such as `Claude-Session:` URLs) do not belong in commit messages.

## Licence

By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), as certified by your DCO sign-off.
