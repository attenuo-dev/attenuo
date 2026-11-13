#!/usr/bin/env bash
# Differential test of the Lean model of the covering rule (proofs/lean) against the Rust code:
# the Rust test crates/attenuo-core/tests/lean_differential.rs draws cases (a fixed seed) and
# writes them with Rust's answers, the Lean executable `differential` evaluates the model on
# the same cases, and this script fails on any case where the two answers differ, printing the
# first ones. Agreement on these cases is evidence, not proof; see proofs/lean/README.md.
#
#   scripts/check-lean-differential.sh                  # fails when Lean is not installed
#   scripts/check-lean-differential.sh --if-installed   # skips with a note when it is not
#
# Needs cargo and Lean (elan; the toolchain is pinned in proofs/lean/lean-toolchain).
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if_installed=0
case "${1:-}" in
  --if-installed) if_installed=1 ;;
  "") ;;
  *) echo "usage: scripts/check-lean-differential.sh [--if-installed]" >&2; exit 2 ;;
esac

if ! command -v lake >/dev/null 2>&1; then
  if [ "$if_installed" -eq 1 ]; then
    echo "skipped: lean not installed (no lake on PATH; see proofs/lean/README.md)"
    exit 0
  fi
  echo "error: lean not installed (no lake on PATH; see proofs/lean/README.md)" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cases="$work/cases.txt"

# 1. The cases and Rust's answers.
ATTENUO_LEAN_CASES="$cases" cargo test --locked -q -p attenuo-core --test lean_differential \
  writes_the_differential_cases >/dev/null
[ -s "$cases" ] || { echo "error: the Rust test wrote no cases" >&2; exit 1; }

# 2. The model's answers.
(cd proofs/lean && lake build --wfail differential)
proofs/lean/.lake/build/bin/differential "$cases" >"$work/lean.txt"

# 3. The comparison: line N of the Lean output answers line N of the case file.
awk -v max_shown=10 '
  NR == FNR { lean[FNR] = $0; nlean = FNR; next }
  {
    split($0, parts, " = ")
    rust = parts[2]
    fn = $1
    total[fn]++
    if (lean[FNR] == rust) { agree[fn]++; next }
    bad++
    if (bad <= max_shown) {
      printf "disagreement on case %d (%s): rust says %s, lean says %s\n  %s\n", FNR, fn, rust, lean[FNR], parts[1]
    }
  }
  END {
    if (nlean != FNR) {
      printf "error: %d cases but %d Lean answers\n", FNR, nlean
      exit 1
    }
    n = split("sat implies pmatch pcovers cpermits ccovers spermits scovers atten", fns, " ")
    for (i = 1; i <= n; i++) {
      printf "%-9s %6d cases, %6d agree\n", fns[i], total[fns[i]], agree[fns[i]] + 0
    }
    if (bad > 0) { printf "error: %d disagreements\n", bad; exit 1 }
    printf "lean differential: the model and the Rust code agree on all %d cases\n", nlean
  }
' "$work/lean.txt" "$cases"
