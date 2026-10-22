# Contributing

- `main` is protected: no direct pushes. Every change goes through a branch and a pull request.
- A PR is mergeable when fmt, clippy (`-D warnings`) and the full test suite pass, and new behaviour has tests.
- Design decisions are recorded as ADRs in `docs/decisions/` (one file per decision, numbered).
- The `docs/` folder is an Obsidian vault. Open it with "Open folder as vault".
- Security-relevant invariants (attenuation, revocation, audit chain) must have a property or integration test, not only a unit test.
