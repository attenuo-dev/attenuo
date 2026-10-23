# Task runner. `just` lists targets; each one is a thin wrapper over cargo or scripts/.
# Install: https://github.com/casey/just

default:
    @just --list

# fmt + clippy + test + demo (what to run before pushing)
dev:
    scripts/dev.sh

fmt:
    cargo fmt --all -- --check

# apply formatting
fmt-fix:
    cargo fmt --all

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

# the GitHub MCP leak demo, end to end
demo:
    bash examples/github-leak-demo/run.sh

# the demo's Cedar policy tests, offline
policy:
    cargo run -q -p attenuo-cli -- policy test examples/github-leak-demo/policy_test.yaml

# rustdoc with warnings as errors
docs:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# relative links in Markdown
links:
    python3 scripts/check-links.py

# cargo-deny (cargo install cargo-deny)
deny:
    cargo deny check

# everything CI runs that can run locally
ci: fmt clippy test demo policy docs links deny

# print a random admin token
admin-token:
    scripts/gen-admin-token.sh
