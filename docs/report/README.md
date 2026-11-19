# Technical report

[`attenuo-2026-11.md`](attenuo-2026-11.md) is the first full draft of a technical report on attenuo, in the arXiv style, for researchers in agent security, authorization and systems. It covers the threat model, the design (delegation chain, the `⊑` narrowing relation, leases, per-call Cedar policy, DPoP and actor authentication, the audit log, output labelling and run limits), the implementation, the evaluation (injection suite, performance, fuzzing and security review, reproducibility), limitations, related work, open questions and a conclusion. The main text is written to be read front to back; four appendices hold the detail (design details, the further AgentDojo runs, the injection suite re-check, and the security review pass by pass). Every number in it names the repository file it comes from.

It is a draft and has not been submitted anywhere. Places marked `[verify]` are claims that no file in the repository establishes.

## Building

```sh
docs/report/build.sh
```

This writes `attenuo-2026-11.html` (pandoc, standalone, numbered sections, embedded CSS) and `attenuo-2026-11.pdf` (A4, printed by Chromium through Playwright) next to the Markdown. It needs pandoc 3 and Node with the `playwright` package and its Chromium. No LaTeX is used. Both outputs are git-ignored. The four figures are SVG files in `figures/`, written by `figures/make_figures.py` (no dependencies); the numbers in the two charts are copied from the report's tables, so change both together. Relative links to other docs are rewritten to the repository on GitHub in the HTML and the PDF, since those are read on their own.

