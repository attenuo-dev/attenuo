# Technical report

[`attenuo-2026-11.md`](attenuo-2026-11.md) is the first full draft of a technical report on attenuo, in the arXiv style, for researchers in agent security, authorization and systems. It covers the threat model, the design (delegation chain, the `⊑` narrowing relation, leases, per-call Cedar policy, DPoP and actor authentication, the audit log, output labelling and run limits), the implementation, the evaluation (injection suite, performance, fuzzing and security review, reproducibility), limitations, related work, open questions and a conclusion. Every number in it names the repository file it comes from.

It is a draft and has not been submitted anywhere. Places marked `[verify]` are claims that no file in the repository establishes.

## Building

```sh
docs/report/build.sh
```

This writes `attenuo-2026-11.html` (pandoc, standalone, numbered sections, embedded CSS) and `attenuo-2026-11.pdf` (A4, printed by Chromium through Playwright) next to the Markdown. It needs pandoc 3 and Node with the `playwright` package and its Chromium. No LaTeX is used. Both outputs are git-ignored. The Mermaid figure renders as a diagram in the mdBook site, and as its source text in the PDF.

