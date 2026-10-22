# onbehalf docs

This folder is an Obsidian vault (open it with "Open folder as vault") and the project's public-safe knowledge base.

- [spec/](spec/) — the RFC, threat model, and protocol/API specifications
- [design/](design/) — architecture notes and component designs
- [decisions/](decisions/) — Architecture Decision Records (ADRs), numbered
- [research/](research/) — technical research with citations (standards, papers, incidents)
- [tasks/](tasks/) — the task board and milestone plans
- [log/](log/) — engineering log, one file per day

Process documents live at the repository root: [CONTRIBUTING](../CONTRIBUTING.md), [SECURITY](../SECURITY.md), [GOVERNANCE](../GOVERNANCE.md), [CHANGELOG](../CHANGELOG.md). How ADRs and RFCs are written is in [decisions/README.md](decisions/README.md) and [spec/README.md](spec/README.md).

## Engineering log convention

`log/` is the running record of what was done and why, written for whoever picks the work up next (including the author in three months).

- One file per day, named `YYYY-MM-DD.md`, with the date as the H1. No file on days with nothing to record.
- Entries are bullets, newest at the bottom. Each bullet is one thing done, decided, learned or blocked, in a sentence or two.
- Link what the bullet refers to: the PR (`#42`), the ADR (`ADR-0003`), the RFC, the issue, the research note. A bullet without a link should be the exception.
- Decisions go in an ADR, not only in the log; the log entry links to the ADR. Open questions are marked `Open:` so they can be grepped.
- Keep it public-safe: no credentials, no customer or personal details, no commercially sensitive plans. Those belong in the private vault.

Example:

```markdown
# 2026-10-22

- Switched the ADR template to MADR 4 and wrote the ADR/RFC process notes (#7, docs/decisions/README.md, docs/spec/README.md).
- Added cargo-deny and cargo-audit to CI; openssl is banned in favour of rustls (deny.toml, #7).
- Open: whether the audit chain should use a Merkle tree or a plain hash chain. Research note to follow in research/.
```

Anything strategic, personal, or commercially sensitive lives in a separate private vault, not here.
