#!/usr/bin/env bash
# Local pre-push checks: fmt, clippy, tests, and the two scripted demos.
#
#   scripts/dev.sh            # everything
#   scripts/dev.sh fmt|clippy|test|demo|policy|docs|deny|links|fuzz   # one step
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
  printf '\nfmt, clippy, test and demo passed. CI also runs: policy docs links deny fuzz\n'
else
  for step in "$@"; do
    case "$step" in
      fmt|clippy|test|demo|policy|docs|links|deny|fuzz) run "$step" ;;
      *) echo "unknown step: $step" >&2; exit 2 ;;
    esac
  done
fi
