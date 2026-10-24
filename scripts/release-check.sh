#!/usr/bin/env bash
# Every local check a release needs, in order. Stops at the first failure with a non-zero exit.
#
#   scripts/release-check.sh                 # all steps
#   scripts/release-check.sh --from <step>   # start at a step (after fixing a failure)
#   scripts/release-check.sh --list          # print the steps
#
# Steps: versions, fmt, clippy, doc, test, links, book, policy, suite, sdk-python,
# sdk-typescript, crates-dry-run, python-dist, npm-pack. `book` is skipped with a note when
# mdbook is not installed.
#
# Environment:
#   PYTHON       interpreter with the Python SDK's dev extras, the suite's needs, build and
#                twine installed (default: python3). For example a venv made with
#                `pip install -e 'sdk/python[dev]' -r evaluation/injection-suite/requirements.txt mcp build twine`.
#   ALLOW_DIRTY  set to 1 to pass --allow-dirty to the crates dry run. Leave it unset for the
#                real pre-tag run, so the crates are packaged from committed files only.
#
# It needs cargo, node 20+ and npm. It publishes nothing: the crates step is
# `cargo publish --dry-run --workspace`, which verifies every publishable crate against the
# others through a temporary local registry, so the crates need not be on crates.io yet. The
# SDK integration tests (ATTENUO_INTEGRATION=1) are not run here; see the SDK READMEs.
# What to do after it passes: docs/release/0.1.0.md.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT=$PWD
PYTHON=${PYTHON:-python3}
STEPS=(versions fmt clippy doc test links book policy suite sdk-python sdk-typescript crates-dry-run python-dist npm-pack)

# Variables from a real deployment change what the CLI and the tests talk to.
unset ATTENUO_TOKEN ATTENUO_SERVER ATTENUO_ADMIN_TOKEN

versions() {
  # Every published artifact carries the workspace version, and the changelog has its section.
  "$PYTHON" - <<'EOF'
import json, re, sys, tomllib
ws = tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"]
found = {
    "sdk/python/pyproject.toml": tomllib.load(open("sdk/python/pyproject.toml", "rb"))["project"]["version"],
    "sdk/typescript/package.json": json.load(open("sdk/typescript/package.json"))["version"],
    "sdk/typescript/package-lock.json": json.load(open("sdk/typescript/package-lock.json"))["version"],
}
deps = tomllib.load(open("Cargo.toml", "rb"))["workspace"]["dependencies"]
for name, spec in deps.items():
    if name.startswith("attenuo-"):
        found[f"Cargo.toml [workspace.dependencies] {name}"] = spec.get("version", "<none>") if isinstance(spec, dict) else spec
bad = {k: v for k, v in found.items() if v != ws}
if not re.search(rf"^## \[{re.escape(ws)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", open("CHANGELOG.md").read(), re.M):
    bad["CHANGELOG.md"] = f"no '## [{ws}] - YYYY-MM-DD' heading"
for k, v in bad.items():
    print(f"version mismatch: {k}: {v} (workspace {ws})", file=sys.stderr)
sys.exit(1 if bad else 0)
EOF
}
fmt()     { cargo fmt --all -- --check; }
clippy()  { cargo clippy --workspace --all-targets --locked -- -D warnings; }
doc()     { RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked; }
test_()   { cargo test --workspace --locked; }
links()   { python3 scripts/check-links.py; }
book() {
  if ! command -v mdbook >/dev/null 2>&1; then
    echo "mdbook not installed; skipped (the docs workflow builds the site)"
    return 0
  fi
  local out
  out=$(mktemp -d)
  mdbook build -d "$out"
  rm -rf "$out"
}
policy()  { cargo run -q --locked -p attenuo-cli -- policy test examples/github-leak-demo/policy_test.yaml; }
suite()   { "$PYTHON" -m pytest evaluation/injection-suite -q -rf; }
sdk_python() {
  (
    cd sdk/python
    "$PYTHON" -m ruff check --config pyproject.toml . ../../examples/python-agent
    "$PYTHON" -m ruff format --check --config pyproject.toml . ../../examples/python-agent
    "$PYTHON" -m mypy --strict src tests ../../examples/python-agent
    "$PYTHON" -m pytest -q -rf
  )
}
sdk_typescript() {
  (
    cd sdk/typescript
    npm ci --no-audit --no-fund
    npm run lint
    npm run build
    npm test
    node -e "const s = require('./dist/index.cjs'); if (typeof s.AttenuoClient !== 'function') process.exit(1)"
    node --input-type=module -e "import('./dist/index.js').then((s) => { if (typeof s.AttenuoClient !== 'function') process.exit(1) })"
  )
}
crates_dry_run() {
  local dirty=()
  if [[ "${ALLOW_DIRTY:-}" == 1 ]]; then dirty=(--allow-dirty); fi
  cargo publish --dry-run --workspace --locked "${dirty[@]}"
  # The .crate files and unpacked copies are not needed afterwards.
  rm -rf "${CARGO_TARGET_DIR:-$ROOT/target}/package"
}
python_dist() {
  local out
  out=$(mktemp -d)
  "$PYTHON" -m build --outdir "$out" sdk/python
  "$PYTHON" -m twine check --strict "$out"/*
  rm -rf "$out"
}
npm_pack() { (cd sdk/typescript && npm pack --dry-run); }

# A step runs with errexit in force (not as an `if` condition, where bash would ignore it), so
# the first failing command ends the script; the EXIT trap names the step.
current=""
trap 'rc=$?; if [[ $rc -ne 0 && -n $current ]]; then printf "==> %s: FAILED (exit %d; resume with: scripts/release-check.sh --from %s)\n" "$current" "$rc" "$current" >&2; fi' EXIT
run() {
  local fn=${1//-/_}
  [[ $fn == test ]] && fn=test_
  current=$1
  printf '\n==> %s\n' "$1"
  "$fn"
  printf '==> %s: ok\n' "$1"
  current=""
}

from=${STEPS[0]}
case "${1:-}" in
  --list) printf '%s\n' "${STEPS[@]}"; exit 0 ;;
  --from) from=${2:?--from needs a step name}; shift 2 ;;
  "") ;;
  *) sed -n '2,/^set -euo/{/^#/p;}' "$0"; exit 2 ;;
esac
started=0
for s in "${STEPS[@]}"; do
  [[ $s == "$from" ]] && started=1
  [[ $started == 1 ]] && run "$s"
done
if [[ $started == 0 ]]; then
  echo "unknown step: $from (see --list)" >&2
  exit 2
fi
printf '\nrelease-check: all %d steps passed from %s\n' "${#STEPS[@]}" "$from"
