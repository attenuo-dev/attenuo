# Secret scan of the full history, 2026-11-05

**Question.** Does any commit in the repository's history hold a credential, a private key, or a name that should not be public? Asked before the repository goes public and before it is shown to people outside the project.

**Method.** [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.0 over every commit (`gitleaks git .`, 572 commits, 32.7 MB of diffs) with its default rules and no allowlist, then over the working tree (`gitleaks dir .`), then `git log --all -p -i -S<word>` for two words that must not appear.

**Result: no credential in any commit.** The default rules report 39 findings, every one of them demo or test material whose plaintext is documented beside it:

| What the rule matched | Where | Why it is not a secret |
|---|---|---|
| UUIDs (`generic-api-key`) | `examples/*/transcript.md`, `examples/*/README.md`, `docs/design/bench/*.md` | Decision ids and lease ids of recorded demo runs. |
| SHA-256 hex strings (`generic-api-key`) | `examples/*/config*.toml`, `config/example.toml`, `docs/guides/identity-providers.md` | `secret_sha256` of the demo client secrets; the comment above each one names the plaintext (`demo-coder-secret`, `planner-secret-change-me`). The hashes are published on purpose so the demos run unchanged. |
| `curl -u planner:planner-secret-change-me` (`curl-auth-user`) | `README.md` | The documented placeholder secret of the example config. |
| A PEM private key (`private-key`) | `crates/attenuo-token/src/approval.rs` | A pinned Ed25519 test key inside `#[test] wire_format_is_pinned_for_the_sdks`; the SDK test fixtures verify a token signed with it. It signs nothing outside the tests. |
| An `alg: none` JWT (`jwt`) | `crates/attenuo-proxy/tests/proxy.rs` | A token the proxy must reject. |
| `Ed25519PrivateKey`, `attenuo+jwt`, `onbehalf+jwt` (`generic-api-key`) | SDK sources and tests | A class name and the project's JWT `typ` value. |

The working-tree scan adds only the local, git-ignored fuzz corpus (generated tokens), which is not in the repository.

**Words.** `FICO` appears in no file of any commit and in no commit message. `Invisible` appears only as the ordinary English word (the Code of Conduct's "visible or invisible disability", two threat-model sentences, one bench note).

**Kept.** [`.gitleaks.toml`](https://github.com/attenuo-dev/attenuo/blob/main/.gitleaks.toml) allowlists exactly the paths and shapes above, so `gitleaks git .` now reports `no leaks found` and a future real secret would still be reported. Run it before each release and before the repository changes visibility.

**Not done.** No history rewrite, because nothing needs one. Commit messages were not scanned by gitleaks (it scans diffs); they were grepped for the two words only.
