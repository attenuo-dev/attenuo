#!/usr/bin/env bash
# Builds the Lean model and proof of the covering rule (proofs/lean) and checks that it rests on
# nothing unproven: no `sorry`, `admit`, new `axiom`, `native_decide` or `implemented_by` in the
# sources, no warning in the build, and only Lean's standard axioms (propext, Quot.sound,
# Classical.choice) under the main theorems.
#
#   scripts/check-lean.sh                  # fails when Lean is not installed
#   scripts/check-lean.sh --if-installed   # skips with a note when Lean is not installed
#
# Lean is installed with elan; the toolchain is pinned in proofs/lean/lean-toolchain. See
# proofs/lean/README.md.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/proofs/lean"

if_installed=0
case "${1:-}" in
  --if-installed) if_installed=1 ;;
  "") ;;
  *) echo "usage: scripts/check-lean.sh [--if-installed]" >&2; exit 2 ;;
esac

if ! command -v lake >/dev/null 2>&1; then
  if [ "$if_installed" -eq 1 ]; then
    echo "skipped: lean not installed (no lake on PATH; see proofs/lean/README.md)"
    exit 0
  fi
  echo "error: lean not installed (no lake on PATH; see proofs/lean/README.md)" >&2
  exit 1
fi

fail() { echo "error: $*" >&2; exit 1; }

sources=(Attenuo.lean PrintAxioms.lean Differential.lean $(find Attenuo -name '*.lean' | sort))

# 1. Nothing in the sources that skips a proof or adds an assumption.
if grep -nE '\b(sorry|admit|native_decide|implemented_by)\b|^\s*(@\[[^]]*\]\s*)?((private|protected|noncomputable|unsafe)\s+)*(axiom|opaque)\b|@\[extern' \
    "${sources[@]}"; then
  fail "the Lean sources above hold sorry, admit, an axiom or another escape hatch"
fi

# 2. The build, with warnings as errors (a `sorry` the grep missed is a warning): the library
# and the `differential` executable (scripts/check-lean-differential.sh runs it).
lake build --wfail

# 3. The axioms under the main theorems: only Lean's standard three.
out=$(lake env lean PrintAxioms.lean)
printf '%s\n' "$out"
expected=$(grep -c '^#print axioms' PrintAxioms.lean)
got=$(printf '%s\n' "$out" | grep -cE "depends on axioms|does not depend on any axioms" || true)
[ "$got" -eq "$expected" ] || fail "expected $expected '#print axioms' results, got $got"
bad=$(printf '%s\n' "$out" | grep -oE 'depends on axioms: \[[^]]*\]' \
  | sed -e 's/.*\[//' -e 's/\]//' | tr ',' '\n' | tr -d ' ' \
  | grep -vxE 'propext|Quot\.sound|Classical\.choice' || true)
[ -z "$bad" ] || fail "non-standard axioms: $bad"

echo "lean: proof builds; no sorry; only standard axioms ($expected theorems checked)"
