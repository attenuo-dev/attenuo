# Storyboard

## X / Twitter cut (39 s)

| # | Time | Scene | On screen |
|---|---|---|---|
| 1 | 0–5 s | Hook | "Your agent holds one broad token." One injected GitHub issue was enough to make an assistant publish a user's private repositories. Nothing outside the agent said **no**. |
| 2 | 5–8.5 s | Reveal | Narrowing-chain mark builds, wordmark, "Every tool call your agent makes, checked against what the user delegated." |
| 3 | 8.5–15.2 s | Chain | alice (github, email, calendar) → assistant (github:*) → coder (github:read_file). Boxes shrink. "Each hand-off can only give away less." RFC 8693. |
| 4 | 15.2–23.8 s | Calls | Terminal: read_file public → ALLOWED; read_file private-salaries → DENIED policy_deny; create_issue → DENIED capability_denied. "1 call reached the upstream server." |
| 5 | 23.8–29.3 s | Revoke | assistant → coder → reviewer flip ACTIVE to REVOKED. "Revoke one lease. Every agent below it stops." |
| 6 | 29.3–35 s | Numbers | Bars: 38/38 direct vs 7/38 behind attenuo. 3/29 benign denied, 0.4–0.8 ms. Fine print: synthetic cases written by the authors. |
| 7 | 35–39 s | Outro | Mark + attenuo, tags (self-hosted, Rust, Cedar, MCP proxy, Apache-2.0), "Open source soon", @mudit_builds. |

## LinkedIn cut (71 s)

Same spine, slower, plus three scenes for a technical audience:

1. Hook with "16 MCP incidents, 2025 to 2026" and the source line (8 s)
2. Reveal (4 s)
3. Chain (7.5 s)
4. Calls, slower typing (10 s)
5. Revoke (6.2 s)
6. **Audit**: hash-chained entries, "attenuo audit verify ✓ chain verified" (6 s)
7. **Console**: slow zoom over the admin console audit log (7 s)
8. Numbers, adds the 1/38 row with labels and a one-call limit (7.3 s)
9. **Research**: AgentDojo 0/212 without attenuo but up to 92 runs lost to refusals; open problems (read-side leaks, approver fatigue, independent corpus) (10 s)
10. Outro (5.3 s)

## GIF (7.7 s)

The Calls scene alone, faster typing, 960 px, 15 fps.

## Suggested post copy (drafts, not posted)

**X:** AI agents get one broad token, and one injected issue is enough to leak private repos. I built attenuo: every tool call is checked against what the user actually delegated, and every hand-off can only narrow. Self-hosted, Rust, Cedar. Open source soon.

**LinkedIn:** lead with the incident, then the research framing (delegation narrowing, per-call policy, revocation, signed audit), the honest numbers with their caveat, and the open questions. Ask researchers working on agent security for feedback.
