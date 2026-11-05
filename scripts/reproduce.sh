#!/usr/bin/env bash
# Rebuild everything from this checkout, run both demos and the injection suite, and check
# that the suite's per-arm numbers match the committed results. Exits 0 with a REPRODUCED
# line when every arm row (and the list of problems run.py reports) is identical, 1 with a
# unified diff when anything differs.
#
#   scripts/reproduce.sh                       # build, demos, suite, compare
#   scripts/reproduce.sh --skip-build          # use the release binaries already built
#   scripts/reproduce.sh --skip-demos          # suite and compare only
#   scripts/reproduce.sh --baseline FILE.md    # compare against another committed result
#
# Steps: environment, build, demos, suite, compare. Each is printed with a heading and timed.
# What it needs and how long it takes: docs/evaluation/reproduce.md.
#
# Environment:
#   PYTHON            interpreter with evaluation/injection-suite/requirements.txt installed
#                     (default: python3)
#   CARGO_TARGET_DIR  where cargo builds (default: the repository's target/); the binaries
#                     are taken from its release/ directory
#   KEEP_RESULTS=1    keep the results/<date>-reproduce.{json,md} the suite writes (by
#                     default they are deleted at the end: the committed baseline is the
#                     reference, the new files are regenerated on every run)
#
# Any ATTENUO_* variable from your shell is unset first: they change what the CLI, the demos
# and the suite talk to.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT=$PWD
PYTHON=${PYTHON:-python3}
SUITE=evaluation/injection-suite
BASELINE=$SUITE/results/2026-11-05-type-check-stage.md
SKIP_BUILD=0
SKIP_DEMOS=0

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; }
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-build) SKIP_BUILD=1 ;;
    --skip-demos) SKIP_DEMOS=1 ;;
    --baseline)
      [ $# -ge 2 ] || { echo "--baseline needs a file" >&2; exit 2; }
      BASELINE=$2; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done
[ -f "$BASELINE" ] || { echo "baseline not found: $BASELINE" >&2; exit 2; }

while IFS= read -r var; do unset "$var"; done < <(compgen -e | grep '^ATTENUO_' || true)

TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
BIN=$TARGET/release
DATE=$(date -u +%Y-%m-%d)
NEW=$SUITE/results/$DATE-reproduce.md
T0=$SECONDS

cleanup() {
  local rc=$?
  if [ "${KEEP_RESULTS:-0}" != 1 ]; then
    rm -f "$SUITE/results/$DATE-reproduce.md" "$SUITE/results/$DATE-reproduce.json"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

STEP=""; STEP_T0=0
begin() { STEP=$1; STEP_T0=$SECONDS; printf '\n==> %s\n' "$STEP"; }
end()   { printf '<== %s: %ds\n' "$STEP" $((SECONDS - STEP_T0)); }

begin environment
echo "commit   $(git rev-parse HEAD)$(git diff --quiet HEAD -- 2>/dev/null || echo ' (uncommitted changes)')"
echo "rustc    $(rustc --version)"
echo "cargo    $(cargo --version)"
echo "python   $("$PYTHON" --version 2>&1) ($(command -v "$PYTHON"))"
echo "binaries $BIN"
echo "baseline $BASELINE"
end

begin build
if [ "$SKIP_BUILD" = 1 ]; then
  echo "skipped (--skip-build)"
else
  cargo build --release -p attenuo-server -p attenuo-cli
  cargo build --release -p attenuo-proxy --features testing --example fake_mcp
fi
for b in attenuo-server attenuo examples/fake_mcp; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b (run without --skip-build)" >&2; exit 1; }
done
end

begin demos
if [ "$SKIP_DEMOS" = 1 ]; then
  echo "skipped (--skip-demos)"
else
  for demo in github-leak-demo multi-hop-demo; do
    echo "--- examples/$demo/run.sh"
    t=$SECONDS
    ATTENUO_BIN_DIR=$BIN "examples/$demo/run.sh" > "${TMPDIR:-/tmp}/attenuo-reproduce-$demo.log" 2>&1 || {
      cat "${TMPDIR:-/tmp}/attenuo-reproduce-$demo.log" >&2
      echo "!! examples/$demo/run.sh failed" >&2
      exit 1
    }
    tail -n 2 "${TMPDIR:-/tmp}/attenuo-reproduce-$demo.log"
    rm -f "${TMPDIR:-/tmp}/attenuo-reproduce-$demo.log"
    echo "    passed in $((SECONDS - t))s"
  done
fi
end

begin suite
SUITE_RC=0
ATTENUO_BIN_DIR=$BIN "$PYTHON" "$SUITE/run.py" --split all --tag reproduce --date "$DATE" \
  > /dev/null || SUITE_RC=$?
[ -f "$NEW" ] || { echo "!! the suite wrote no $NEW (exit $SUITE_RC)" >&2; exit 1; }
# run.py exits 1 when it reports a problem. The committed baseline has none (the argument
# type check before Cedar, input_type_mismatch, has its own stage, input, since
# 2026-11-05), but an older baseline given with --baseline may list some, so the compare
# step decides: the same problems pass, a new or a missing one is a difference. Any other
# exit status is a failure.
case "$SUITE_RC" in
  0) ;;
  1) echo "run.py exited 1 (PROBLEM lines above); the compare step checks them against the baseline" ;;
  *) echo "!! run.py exited $SUITE_RC" >&2; exit 1 ;;
esac
echo "wrote $NEW"
end

begin compare
CMP_RC=0
"$PYTHON" "$SUITE/compare_results.py" "$BASELINE" "$NEW" \
  --label "results/$(basename "$BASELINE")" || CMP_RC=$?
end

printf '\ntotal: %ds\n' $((SECONDS - T0))
[ "$CMP_RC" = 0 ] || exit 1
