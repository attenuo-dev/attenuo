#!/usr/bin/env bash
# End-to-end latency and throughput benchmark: builds release binaries, runs the matrix with
# onbehalf-bench, and writes docs/design/bench/<date>-<host>.json plus a markdown summary.
#
#   scripts/bench-e2e.sh                 full matrix (about 9 minutes)
#   DURATION=10 WARMUP=2 scripts/bench-e2e.sh
#   scripts/bench-e2e.sh --concurrency 8 --depths 3     extra arguments go to onbehalf-bench
#
# Environment:
#   DURATION, WARMUP   seconds per cell (default 5 and 2)
#   OUT_DIR            output directory (default docs/design/bench)
#   NOTE               free text recorded in the markdown (for example "shared dev container")
#
# The run fails if the audit chain does not verify or a call is answered unexpectedly. Run it
# on an otherwise idle machine; the load generator, proxy and upstream share the same cores.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DURATION="${DURATION:-5}"
WARMUP="${WARMUP:-2}"
OUT_DIR="${OUT_DIR:-docs/design/bench}"
HOST="$(hostname | tr -c 'A-Za-z0-9\n' '-')"
DATE="$(date -u +%F)"
BASE="$OUT_DIR/$DATE-$HOST"
mkdir -p "$OUT_DIR"

echo "building release binaries..." >&2
cargo build --release -q -p onbehalf-bench -p onbehalf-server
cargo build --release -q -p onbehalf-proxy --features testing --example fake_mcp
TARGET="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
BIN="$TARGET/release"

# The target dir may be shared with other checkouts; run copies of what was just built.
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/onbehalf-bench-bin.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
cp "$BIN/onbehalf-bench" "$BIN/onbehalf-server" "$STAGE/"
cp "$BIN/examples/fake_mcp" "$STAGE/"

"$STAGE/onbehalf-bench" --bin-dir "$STAGE" --duration "$DURATION" --warmup "$WARMUP" \
  --json "$BASE.json" --markdown "$BASE.tables.md" "$@" >/dev/null

{
  echo "# End-to-end benchmark, $DATE, $HOST"
  echo
  echo "Commit \`$(git rev-parse --short HEAD)\`, release profile, $(rustc --version)."
  echo "Per cell: ${WARMUP} s warm-up (discarded), ${DURATION} s measured, closed loop."
  [ -n "${NOTE:-}" ] && { echo; echo "$NOTE"; }
  echo
  echo "## Hardware"
  echo
  echo '```'
  echo "\$ nproc"; nproc
  echo "\$ lscpu | head -15"; lscpu | head -15
  echo "\$ uname -sr"; uname -sr
  echo '```'
  echo
  echo "## Results"
  echo
  cat "$BASE.tables.md"
} > "$BASE.md"
rm -f "$BASE.tables.md"

echo "wrote $BASE.json and $BASE.md" >&2
