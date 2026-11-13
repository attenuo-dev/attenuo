#!/usr/bin/env bash
# Local pre-push checks: fmt, clippy, tests, and the three scripted demos.
#
#   scripts/dev.sh            # everything
#   scripts/dev.sh fmt|clippy|test|demo|guide|readme|snippets|policy|docs|deny|links|fuzz   # one step
#
# Mirrors .github/workflows/ci.yml. Steps whose tool is not installed (cargo-deny) are skipped
# with a note rather than failing.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fmt()    { cargo fmt --all -- --check; }
clippy() { cargo clippy --workspace --all-targets -- -D warnings; }
test_()  { cargo test --workspace; }
demo()   {
  bash examples/github-leak-demo/run.sh && bash examples/multi-hop-demo/run.sh \
    && bash examples/idp-exchange-demo/run.sh
}
guide()  { bash scripts/check-getting-started.sh; }
readme() { bash scripts/check-doc-commands.sh README.md; }
# The SDK READMEs' snippets: compiled and type-checked (sdk/python/tests/test_readme_snippets.py,
# sdk/typescript/test/readme.test.ts). Each half is skipped with a note when its tools are not
# installed (pip install -e 'sdk/python[dev]'; npm ci in sdk/typescript).
snippets() {
  if python3 -c 'import pytest, httpx, mypy' 2>/dev/null; then
    (cd sdk/python && python3 -m pytest -q tests/test_readme_snippets.py)
  else echo "pytest, httpx or mypy not installed, skipping the Python snippets"; fi
  if [ -d sdk/typescript/node_modules ]; then
    (cd sdk/typescript && npm run -s build && npx vitest run test/readme.test.ts)
  else echo "sdk/typescript/node_modules missing (npm ci), skipping the TypeScript snippets"; fi
}
policy() {
  cargo run -q -p attenuo-cli -- policy test examples/github-leak-demo/policy_test.yaml examples/multi-hop-demo/policy_test.yaml
  cargo run -q -p attenuo-cli -- policy test --fail-on-unexercised config/policies/*_test.yaml
}
docs()   { RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps; }
links()  { python3 scripts/check-links.py; }
fuzz()   { RUSTFLAGS="--cfg fuzzing" cargo check --manifest-path fuzz/Cargo.toml --bins --examples --locked; }
deny() {
  if cargo deny --version >/dev/null 2>&1; then cargo deny check
  else echo "cargo-deny not installed, skipping (cargo install cargo-deny)"; fi
}

run() {
  printf '\n==> %s\n' "$1"
  case "$1" in test) test_ ;; *) "$1" ;; esac
}

if [ "$#" -eq 0 ]; then
  for step in fmt clippy test demo; do run "$step"; done
  printf '\nfmt, clippy, test and demo passed. CI also runs: guide readme snippets policy docs links deny fuzz\n'
else
  for step in "$@"; do
    case "$step" in
      fmt|clippy|test|demo|guide|readme|snippets|policy|docs|links|deny|fuzz) run "$step" ;;
      *) echo "unknown step: $step" >&2; exit 2 ;;
    esac
  done
fi
