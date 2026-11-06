# Research-readiness plan, week of 2026-11-05

**Goal.** By 2026-11-12 a researcher who gets one email about attenuo can, in under an hour: read a short technical report, run the demo from a fresh clone, reproduce every evaluation number in the report with one script, and find a repository that looks maintained. Nothing on this list adds a feature; everything makes what exists checkable by a stranger.

**Why now.** The owner's graduate applications are in and the next step is contacting researchers (agent security, authorization, systems) in Canada and Australia. The repository has 120 merged pull requests, 1,700 tests, seven security review passes and an injection suite, but all of it was verified by the people who wrote it. A researcher will ask three things: can I run it, can I reproduce the numbers, and what exactly is claimed.

## Day 0 (2026-11-05): hygiene and a fresh baseline

Done or in flight on `chore/research-ready-hygiene`:
- Logs cleaned of environment notes; full-history secret scan ([result](../research/secret-scan-2026-11-05.md)); SECURITY.md and SUPPORT.md without placeholders or dead links; `docs/guide/flight-guide-*` git-ignored.
- Injection suite rerun on final `main` with release binaries; the committed numbers (7/38 and 3/29 on the test split for the `attenuo` arm) either confirmed or reported before any document changes.
- `examples/github-leak-demo/run.sh` from a fresh clone in an empty directory, output recorded in the daily log.
- Needs the owner (repository settings cannot be written from here): description, topics, Discussions. Commands in the pull request.

## Days 1 to 2: reproducibility

1. `scripts/reproduce.sh`: one command that builds release binaries, runs both demos, runs the injection suite on both splits, and diffs the per-arm tables against the committed results for the same commit. Exit 0 means "the numbers in the report are the numbers on your machine". Documented in a new `docs/evaluation/reproduce.md` with the expected run time and disk use.
2. Pin what the report cites: a results file named after the commit (`results/<date>-main-<sha>.md`), the Rust toolchain in `rust-toolchain.toml` (already `rust-version` in Cargo.toml; the pin makes the build identical), and `requirements.txt` with exact versions for the suite.
3. Demo recordings: an asciinema cast of the GitHub leak demo and the multi-hop demo (text, not video, so it is searchable and small), plus a GIF for the README. The cast is made from the fresh clone, not a developer checkout.

## Days 2 to 4: the technical report

4. `docs/report/attenuo-2026-11.md`, built to PDF with pandoc, 10 to 14 pages in the arXiv two-column style. Sections: problem and threat model; design (delegation chain, the `⊑` narrowing relation, leases and revocation, per-call Cedar policy, sender-constrained tokens, the hash-chained signed audit log); implementation (crates, line counts, test counts); evaluation (the injection suite with Wilson intervals and the honest caveat that cases and policies were written by the same people, the end-to-end latency and throughput numbers, fuzzing rounds, the seven security passes with their counts); limitations; related work (AgentDojo, InjecAgent, CaMeL, Biscuit, Macaroons, SPIFFE, OAuth RAR, ZCAP, the WIMSE drafts); availability.
5. The owner is the author. The draft comes from the existing design notes, ADRs and results, every number with a link to the file it comes from; the owner reads and edits it (that reading is also the walkthrough of the project he wanted). arXiv cs.CR needs an endorsement for a first submission; a researcher contact can give one, which is itself a reason to write to them.

## Days 4 to 5: outreach material

6. A one-page researcher brief (PDF): the problem in three sentences, one figure (the proxied-call path), the headline numbers with their caveats, three open research questions the project cannot answer alone (independent attack corpus, the approver-in-the-loop measurement, Cedar-aware list filtering), links.
7. The outreach email template and the list of researchers stay in the private vault, not in the repository.
8. Release: tag `v0.1.0` and make the repository public, which is the owner's call ([steps](../release/0.1.0.md)). A private repository cannot be cited; a public one also gets free CI minutes, which closes the "CI is red" problem. Branch protection, private vulnerability reporting and Discussions get switched on the same day ([launch checklist](../launch-checklist.md)).

## Stretch, if the week allows: an external benchmark

9. Run attenuo under an existing public benchmark, AgentDojo or InjecAgent, with a real model in the loop: a no-enforcement baseline and an attenuo-enforced run, reporting attack success and task utility. This is the one result a researcher cannot get from the repository's own suite, and the strongest evidence for the report. It needs an LLM API budget (roughly a few tens of dollars per full run) and two to three days; the decision is the owner's.

   **Done, for AgentDojo** ([AgentDojo plan](../research/agentdojo-plan-2026-11-05.md); report section 5.2). A Haiku baseline over all 949 pairs, a four-model sample without attenuo, attenuo-enforced runs with oracle grants on workspace (all 40 tasks on Haiku, a 10-task sample on Sonnet), and a model-free replay of the attacks' own calls on all four suites. No attack succeeded on any model with or without attenuo, so the enforced runs measure the cost of enforcement and not its benefit. Planner grants and InjecAgent were not run.

## Not in this week

- No new enforcement features (run limits phase 3, ADR-0011 list filtering, real admin authentication) unless a reviewer asks for one.
- No benchmark number is changed by hand; every table in the report is generated from a results file in the repository.
