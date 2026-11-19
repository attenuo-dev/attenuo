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

# the GitHub MCP leak demo, the multi-hop delegation demo and the IdP exchange demo, end to end
demo:
    bash examples/github-leak-demo/run.sh
    bash examples/multi-hop-demo/run.sh
    bash examples/idp-exchange-demo/run.sh

# run docs/guides/getting-started.md as written and check its outputs
guide:
    bash scripts/check-getting-started.sh

# run the README's server, curl and CLI commands as written and check their outputs
readme:
    bash scripts/check-doc-commands.sh README.md

# compile and type-check the SDK READMEs' Python and TypeScript snippets
snippets:
    bash scripts/dev.sh snippets

# the Cedar policy tests (both demos' and config/policies/), offline
policy:
    cargo run -q -p attenuo-cli -- policy test examples/github-leak-demo/policy_test.yaml examples/multi-hop-demo/policy_test.yaml
    cargo run -q -p attenuo-cli -- policy test --fail-on-unexercised config/policies/*_test.yaml

# rustdoc with warnings as errors
docs:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# relative links in Markdown
links:
    python3 scripts/check-links.py

# nothing private, stale or machine-specific in the tracked tree
hygiene:
    python3 scripts/check-public-hygiene.py

# the fuzz targets compile on stable against fuzz/Cargo.lock (no fuzzing; see fuzz/README.md)
fuzz-check:
    RUSTFLAGS="--cfg fuzzing -D warnings" cargo check --manifest-path fuzz/Cargo.toml --bins --examples --locked

# the Lean proof of the covering rule: build, no sorry, standard axioms only; then the model
# against the Rust code on generated cases (proofs/lean/README.md)
lean:
    bash scripts/check-lean.sh
    bash scripts/check-lean-differential.sh

# cargo-deny (cargo install cargo-deny)
deny:
    cargo deny check

# everything CI runs that can run locally
ci: fmt clippy test demo guide readme snippets policy docs links hygiene deny fuzz-check lean

# print a random admin token
admin-token:
    scripts/gen-admin-token.sh
