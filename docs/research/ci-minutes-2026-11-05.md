# CI minutes, 2026-11-05

The repository is private on the GitHub Free plan: 2,000 Actions minutes a month, Linux billed at 1x, Windows at 2x, macOS at 10x, and every job rounded up to a whole minute. On 2026-11-05 the `CI` workflow ran 33 times (18 pull requests, 15 pushes to main) and the project merges many small pull requests a day, so the CI bill is mostly a function of how many minutes one run costs. This page records what one run cost before branch `ci/faster`, what changed, and what one run should cost after it.

## Before

Wall time per job on the latest run on main (run 42084513100, `ci.yml` at `bd4f8dd`), and the mean over every job that ran on 2026-11-05:

| Job | Latest main run (min) | Mean on 2026-11-05 (min) | Where it ran |
|---|---|---|---|
| rustfmt | 0.2 | 0.2 | PR and main |
| GitHub leak demo | 1.0 | 1.3 | PR and main |
| docs (rustdoc and links) | 1.2 | 0.7 | PR and main |
| clippy | 0.8 | 0.9 | PR and main |
| test (ubuntu-latest, stable) | 3.0 | 3.5 | PR and main |
| msrv (rust-version from Cargo.toml) | 0.9 | 1.0 | PR and main |
| cargo audit | 5.2 | 4.9 | PR and main |
| cargo deny | 0.8 | 0.9 | PR and main |
| policy tests | 0.5 | 0.8 | PR and main |
| admin console in a browser | 1.9 | 3.4 | PR and main |
| test (macos-latest, stable) | 15.0, never started | 1.9 when it started | main only |
| fuzz targets build | 4.9 | 5.1 | PR and main |

### What the 15 minutes of macOS were

The macOS leg was already off pull requests: `ci.yml` built its matrix as `["ubuntu-latest"]` on `pull_request` and added `macos-latest` only on pushes to main and manual dispatch. On main it was a problem of a different kind. In runs 42084513100 and 42068167069 the macOS job has no runner, no steps and no log: its annotations read "The job was not acquired by Runner of type hosted even after multiple attempts" and "Due to capacity constraints, jobs targeting macOS arm64 runners may experience longer queue times". GitHub gave up after 15.0 minutes and marked the job cancelled and the run failed, while every Linux job had passed. Of the 15 CI runs on main that day, 10 were cancelled by a newer push, 3 failed this way, and 2 passed; in those 2 the macOS job ran in 1.7 and 2.6 minutes.

So the 15 minutes were queue time, not runner time. Actions bills from the moment a runner picks a job up, and these jobs were never picked up, so they most likely cost nothing; the cost was a red main. When the job did run it cost 2 to 3 minutes, billed as 20 to 30. (This could not be confirmed from the API: the run `timing` endpoint now returns 0 for every job, and the billing endpoints are organisation-level, which this environment cannot read.)

### What a run cost

Adding up the jobs that a runner actually ran on 2026-11-05, each rounded up to a whole minute and macOS at 10x: 475 minutes for the 18 pull request runs (about 26 a run) and 483 for the 15 main runs (about 32 a run, including about 100 for the four macOS jobs that started, and the partial minutes of cancelled runs). About 960 billed minutes in one day, nearly half the monthly allowance. Two Linux jobs carried a third of it: `cargo audit` (about 5 minutes, compiling cargo-audit from source inside `rustsec/audit-check`) and `fuzz targets build` (about 5 minutes on nightly), on every run.

## Changes on `ci/faster`

`ci.yml`:

1. **macOS** is its own job, `test (macos, stable)`, and runs only on a weekly schedule (Mondays 05:23 UTC) and on `workflow_dispatch`. It is not on pull requests and no longer on every push to main. The dispatch form has a `macos-runner` choice, `macos-latest` (arm64, what most users run) or `macos-15-intel` (x86_64, usually more capacity), for when the arm64 pool keeps queuing the job out. No other job needs it and `ci-ok` does not wait for it, so a queued-out or red macOS run shows up as its own red job and never hides or blocks the Linux result. Its `timeout-minutes: 45` counts from when a runner starts it; queue time is outside it and is not billed. macOS coverage is still worth having for the SDKs and the CLI, which people run on Macs, but a weekly signal is enough for code that is tested on Linux on every change; `release.yml` also builds the macOS archives on every release tag.
2. **fuzz targets build** runs on pushes to main, weekly, on dispatch, and on a pull request that changes `fuzz/**` or `ci.yml`. A library change that stops a fuzz target compiling is caught on the main push after the merge instead of on the pull request.
3. **Documentation-only pull requests** skip the Rust jobs. A first job, `changes`, uses `dorny/paths-filter` (pinned to the v4.0.3 commit) to list the pull request's files through the API, without a checkout. If every changed file is under `docs/**`, `assets/**`, `book-theme/**`, `.github/ISSUE_TEMPLATE/**`, is `book.toml`, or ends in `.md`, the Rust jobs are skipped. No Rust code reads those files at build or test time (checked with a search for `include_str!`, `include_bytes!` and `CARGO_MANIFEST_DIR` paths). The `docs (rustdoc and links)` job still runs and checks the Markdown links; only its `cargo doc` steps are skipped. Pushes to main, the weekly run and dispatch always run everything.
4. **cargo audit** installs the upstream cargo-audit 0.22.2 release binary with `taiki-e/install-action` (pinned to the v2.87.28 commit; it verifies the download's checksum) and runs `cargo audit`. The result is in the job log; the separate "Security audit" check run that `rustsec/audit-check` created is gone, and the job no longer needs `checks: write`. A vulnerability still fails the job and unmaintained or yanked crates are still warnings. `cargo deny` already used a prebuilt container image and stays as it was.
5. **One cargo cache for four jobs.** `test`, `GitHub leak demo`, `policy tests` and `admin console in a browser` build the same debug dependencies with the same flags, so they restore one `Swatinem/rust-cache` entry (`shared-key: debug`) that only `test` writes. Every cache in the workflow is now written on main only (`save-if`); a pull request restores main's cache and spends no time uploading one that no other branch can read.
6. **Flags once.** `RUSTFLAGS=-D warnings` is set at the top of the workflow, which also keeps the shared cache key identical across jobs. The MSRV check, the nightly fuzz build and the macOS job reset it to empty, which is how they ran before: an older or newer compiler warns differently, and cargo-fuzz sets its own flags. `CARGO_INCREMENTAL=0` and `CARGO_PROFILE_DEV_DEBUG=0` were already set. `clippy` now builds with `--locked` like the other jobs. The `test` job compiles in its own step (`cargo test --no-run`) before running, so the log shows build and test time apart.
7. **Concurrency.** A new push to a pull request or to main still cancels the run in progress; the event name is now part of the group, so a push to main no longer cancels the weekly or a dispatched run.
8. **`timeout-minutes`** on every job, between 5 and 45.
9. **`ci-ok`**, a last job with `if: always()` that needs every per-change job and fails unless each one passed or was skipped (see [Branch protection](#branch-protection)).

Not done: `cargo nextest`. It would run the tests faster, but it does not run doctests (they would need a separate `cargo test --doc`) and it runs each test in its own process, which changes behaviour for tests that share state inside one binary. Worth a branch of its own with a local run first; this branch builds nothing.

Every check that ran before still runs: all of them on every pull request that touches code, except the macOS tests (weekly and dispatch) and the fuzz build (main, weekly, dispatch, and pull requests touching `fuzz/`).

The other workflows got smaller changes. `sdk-python.yml` and `sdk-typescript.yml` gain a concurrency group (pull request runs cancel each other, main runs do not), the same `CARGO_*` settings, cargo caches written on main only, and `--locked` on the TypeScript integration build; the two TypeScript integration legs (Node 20 and 22) share one cache. `docs.yml`, `release.yml` and `release-packages.yml` gain `timeout-minutes` on every job (90 for the release build, which is a cold thin-LTO build on four targets). They already ran only on their paths or on tags.

## After: expected billed minutes

Each job rounded up to a whole minute, at the means above. The new `changes` and `ci-ok` jobs take seconds but are billed a minute each.

| Job | Before: PR | Before: main push | After: PR (code) | After: PR (docs only) | After: main push | After: weekly |
|---|---|---|---|---|---|---|
| changes | | | 1 | 1 | 1 | 1 |
| rustfmt | 1 | 1 | 1 | skipped | 1 | 1 |
| clippy | 1 | 1 | 1 | skipped | 1 | 1 |
| test (ubuntu-latest, stable) | 4 | 4 | 4 | skipped | 4 | 4 |
| test (macos-latest, stable) | | 20 to 30 when it started | | | | 20 to 30 |
| msrv (rust-version from Cargo.toml) | 1 | 1 | 1 | skipped | 1 | 1 |
| cargo deny | 1 | 1 | 1 | skipped | 1 | 1 |
| cargo audit | 5 | 5 | 1 | skipped | 1 | 1 |
| GitHub leak demo | 2 | 2 | 2 | skipped | 2 | 2 |
| admin console in a browser | 4 | 4 | 4 | skipped | 4 | 4 |
| policy tests | 1 | 1 | 1 | skipped | 1 | 1 |
| fuzz targets build | 6 | 6 | skipped | skipped | 6 | 6 |
| docs (rustdoc and links) | 1 | 1 | 1 | 1 | 1 | 1 |
| ci-ok | | | 1 | 1 | 1 | 1 |
| **Total** | **about 27** | **about 27, plus 20 to 30 for macOS** | **about 19** | **3** | **about 25** | **about 50** |

At the volume of 2026-11-05 (18 pull request runs, 15 main runs), that is about 18 x 19 + 15 x 25 = roughly 720 billed minutes a day instead of about 960, before counting docs-only pull requests (3 minutes instead of about 27) and the shared cache. Pull request wall time drops from about 6 minutes (`cargo audit` was the longest job) to about 4 to 5 (the `test` job). Main no longer goes red because the macOS pool is short.

That is a quarter to a third off, not 20 times. At about 20 billed Linux minutes for each run that touches code, a day of 30 or more runs still costs 600 or more minutes, so the Free plan's 2,000 lasts about three days. The levers that are left are not workflow tuning:

- Fewer runs: batch small documentation and log changes into fewer pull requests, or drop the full CI run on the push to main for a pull request that was up to date with main when it merged (its tree was already tested; keep the fuzz build and audit there). Both are a decision about coverage for the maintainers, not made here.
- A public repository: standard GitHub-hosted runners are free and unmetered for public repositories, macOS included.
- A paid plan or a spending limit above zero, if the repository stays private.

## Branch protection

The repository has no branch protection yet (writing settings is refused in this environment). When it is switched on, mark only `ci-ok` as a required status check, not the individual jobs.

The rule behind that: a job skipped by its `if:` reports the status "skipped", and branch protection counts a skipped required check as passed. So if the individual jobs were required and the `changes` job failed, every Rust job would be skipped and the pull request would look green. A whole workflow skipped by `paths` or `paths-ignore` is worse the other way: it reports nothing, and a required check from it stays pending forever. `ci-ok` runs on every pull request (`if: always()`), needs every per-change job, and fails if any of them failed or was cancelled, while treating a skip on purpose as a pass. The macOS job is not in its `needs`, so it is never a required check.

## Not validated

- The new workflow has not run yet. `actionlint` 1.7.12 (from the `actionlint-py` package, without shellcheck) and a YAML parse of all six workflows are clean; the pull request's own run is the first real test, and it exercises the fuzz job because the pull request changes `ci.yml`.
- The macOS job runs only on schedule and dispatch, so the pull request does not exercise it; a `workflow_dispatch` on the branch does, and lets you try `macos-15-intel`.
- The documentation-only skip is exercised only by a pull request that touches documentation alone.
- The after figures are estimates from the job means above, not measurements. The shared cache should make `GitHub leak demo`, `policy tests` and `admin console in a browser` faster on a cache hit; that is not counted.
