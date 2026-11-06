# Launch videos

Remotion project for the attenuo launch clips. Nothing here is published; the rendered files stay out of git (`out/` is ignored).

| Composition | Length | Size (rendered) | For |
|---|---|---|---|
| `X-16x9` | 39.0 s | 3840x2160 | X / Twitter, landscape |
| `X-1x1` | 39.0 s | 2160x2160 | X / Twitter, square feed |
| `LinkedIn-16x9` | 71.3 s | 3840x2160 | LinkedIn, landscape |
| `LinkedIn-1x1` | 71.3 s | 2160x2160 | LinkedIn, square feed |
| `Gif` | 7.7 s | 960 px GIF | README, replies, DMs |

Compositions are laid out at 1920x1080 and 1080x1080 and rendered with `--scale=2`, so text stays sharp at 4K.

```bash
npm ci
npx remotion studio          # preview
./render.sh                  # all cuts: 4K masters, 1080p copies, GIF into out/
CUTS="X-16x9" ./render.sh    # one cut
```

If Remotion cannot download its headless browser, point `REMOTION_BROWSER` at a local Chrome Headless Shell.

## Sources for what is on screen

Every claim comes from a merged document; change the source first, then the video.

| On screen | Source |
|---|---|
| Injected GitHub issue that published private repositories (May 2025); 16 MCP incidents | `docs/brief/attenuo-one-page.md`, Problem; `docs/report/attenuo-2026-11.md`, Introduction |
| The three calls and their decisions (`policy_allow`, `policy_deny`, `capability_denied`), revoke cascade, "revoked 2 lease(s)" | `docs/demo/github-leak-demo.cast` |
| 38/38 vs 7/38 attack calls; 1/38 with labels and a one-call limit; 3/29 benign denied | `docs/brief/attenuo-one-page.md`, Evidence; `docs/report/attenuo-2026-11.md`, Table 2 |
| 0.4 to 0.8 ms median added latency | `docs/brief/attenuo-one-page.md`; `docs/design/performance.md` |
| AgentDojo 0/212 on four models without attenuo; up to 92 refused runs | `docs/research/agentdojo-plan-2026-11-05.md`, "Four models on one sample" |
| Admin console | `public/shots/dark-02-audit.png` (console screenshot) |

The 0/212 figure is the models' own baseline with no attenuo in front, so the video presents it as a research finding, not as an attenuo result.

Fonts in `public/fonts` are OFL 1.1 (see `OFL-NOTE.md`). Colours and type follow `assets/brand/README.md`.

There is no audio track; add music or voice-over in the editor of your choice before posting.
