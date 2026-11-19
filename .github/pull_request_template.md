<!-- This description and the CHANGELOG entry are the lasting record of the change: say what changed and why. -->

## What

## Why

<!-- Link the issue, RFC or ADR: Fixes #NN / Refs: ADR-NNNN / Implements RFC-NNNN -->

## How verified
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo deny check`
- [ ] New behaviour has tests (property/integration tests for security invariants)

## Docs
- [ ] `CHANGELOG.md` updated under Unreleased, if user-visible
- [ ] ADR added/updated if a design decision was made (docs/decisions/)
- [ ] RFC status updated if this implements one (docs/spec/)
- [ ] Reference docs (docs/reference/) and any page that described the old behaviour updated

## Process
- [ ] Commits follow Conventional Commits and are signed off (`git commit -s`, DCO)
- [ ] Breaking changes are marked with `!` and a `BREAKING CHANGE:` footer
