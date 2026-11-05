# Reproducing the numbers

One command rebuilds attenuo from your checkout, runs both demos and the whole injection suite, and checks that the suite's numbers on your machine are the numbers in these docs:

```sh
pip install -r evaluation/injection-suite/requirements.txt
scripts/reproduce.sh
```

It ends with one of two outcomes:

- `REPRODUCED: 24 arm rows identical to results/2026-11-05-type-check-stage.md` and exit status 0, or
- a unified diff of the rows that differ, a `DIFFERS` line, and exit status 1.

## What it needs

- Rust stable (`rust-toolchain.toml` asks rustup for it), a C toolchain and `curl`.
- Python 3.10 or later with the suite's requirements: `pip install -r evaluation/injection-suite/requirements.txt`. The versions there are pinned exactly so a run elsewhere uses the same libraries as the committed results. The attenuo Python SDK is imported from `sdk/python/src`, so it does not need installing.
- Disk for the release build under `target/` (or under `CARGO_TARGET_DIR` if you set it): 1.1 GB measured. Allow about 4 GB if you also build the debug binaries the demos and tests use when run on their own (a fresh-clone debug build of the demo measured 3.5 GB).
- No network beyond the first `cargo build`, which downloads the crates. Everything else runs on loopback, with no model and no real GitHub.

## What it does

Five steps, each printed with a heading and its time:

1. **environment**: the commit (`git rev-parse HEAD`, marked if the tree has uncommitted changes), the `rustc`, `cargo` and Python versions, and where the binaries and the baseline are.
2. **build**: `cargo build --release` of `attenuo-server`, `attenuo` and the `fake_mcp` test upstream.
3. **demos**: [`examples/github-leak-demo/run.sh`](../../examples/github-leak-demo/README.md) and [`examples/multi-hop-demo/run.sh`](../../examples/multi-hop-demo/README.md) on those binaries. Each demo checks every step's exit status and output, and the number of calls that reached the fake upstream, and fails otherwise.
4. **suite**: `run.py --split all --tag reproduce`, every arm of both splits ([the suite's README](../../evaluation/injection-suite/README.md) has the method).
5. **compare**: [`compare_results.py`](../../evaluation/injection-suite/compare_results.py) takes the per-arm rows (the rows of the "Arms compared" tables that start with `| attenuo` or `| Suite policy`, 12 per split) from the new results file and from the committed [`results/2026-11-05-type-check-stage.md`](../../evaluation/injection-suite/results/2026-11-05-type-check-stage.md), and compares them byte for byte, together with the two files' lists of problems (below).

The results files the suite writes (`results/<date>-reproduce.md` and `.json`) are deleted at the end, since the committed baseline is the reference. `KEEP_RESULTS=1` keeps them, for instance to look at the per-call JSON after a difference.

Options: `--skip-build` (use the release binaries already built), `--skip-demos`, `--baseline FILE.md` (compare against another committed result). Any `ATTENUO_*` variable in your shell is unset first, because those change what the CLI, the demos and the suite talk to.

## How long it takes

Measured on a 4-core Linux container (rustc 1.99.1, Python 3.13), from an empty target directory:

| Step | Time |
|---|---|
| Release build, first time | 4 min 36 s (about 5 minutes; crates already downloaded) |
| Each demo, after the build | under a second |
| Suite, both splits, every arm | 68 s |
| Whole script, first time | 5 min 45 s |

A second run reuses the build, so it takes a little over a minute; `--skip-build` saves the few seconds cargo needs to see nothing changed.

## What "reproduced" means

The 24 rows hold, for every arm and both splits, the attack calls allowed, the attack calls that reached the upstream, and the benign calls denied, each as a count with its Wilson interval. These are the figures the [results page](injection-suite.md), [ADR-0010](../decisions/0010-run-limits.md) and [section 7 of the run-limits note](../design/run-limits.md#7-measured) quote, for instance 7/38 attack calls allowed and 3/29 benign calls denied on the test split for `attenuo`. The suite has no model and no randomness that changes outcomes (`--seed` only changes the order cases run in), so on the same corpus and the same code every row should be identical, not merely close.

The comparison also covers the "Problems" lists, which hold what `run.py` exits 1 for: an attenuo call that did not get its expected outcome, a denied call that reached the upstream, a failed audit check. The baseline has none. The previous baseline, `results/2026-11-05-final-main.md`, had 18, all of one kind: two test-split attack calls (`t-banking-02` call 1, `t-workspace-03` call 2) are denied by the argument type check that runs before Cedar (`input_type_mismatch`, added on 2026-10-24 after those cases were written), and the harness had no stage for it. It now has one, `input`, and the two cases expect it; every per-arm row is identical between the two files. Compared against the old file with `--baseline`, a run reports its 24 rows as identical and the 18 problems as only in the baseline. A problem the baseline also has is printed as known; a new one, or one that went away, is a difference like a changed row. The comparison reads only the per-arm rows and the problems, so the `Input` column the per-stage tables gained does not affect it.

What it does not check: the other tables of the results file (per-taxonomy, approvals, run limits), which follow from the same calls, and the timing figures in the [end-to-end benchmark](../design/bench/2026-10-23-vm.md), which depend on the machine.

## If a row differs

Open an issue with the diff the script printed, the output of its **environment** step, your OS and CPU, and, if you can, the `results/<date>-reproduce.json` from a run with `KEEP_RESULTS=1`. A difference is either a bug in attenuo, a bug in the suite, or a dependency that behaves differently on your machine; all three are worth knowing about.

If you changed anything under `evaluation/injection-suite/cases/` or `policies/`, the test split is refused (exit status 2 from `run.py`) and the numbers are not comparable; see [Dev and test splits](../../evaluation/injection-suite/README.md#dev-and-test-splits).
