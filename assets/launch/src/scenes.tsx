import React from "react";
import {
  CanvasImage,
  interpolate,
  spring,
  staticFile,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { C, display, mono } from "./theme";
import {
  H,
  Kicker,
  Mark,
  Panel,
  Pill,
  Rise,
  Scene,
  prog,
  typed,
  useSquare,
} from "./ui";

/* 1. Hook ------------------------------------------------------------- */
export const Hook: React.FC<{ long?: boolean }> = ({ long }) => {
  const sq = useSquare();
  const f = useCurrentFrame();
  const strike = prog(f, long ? 120 : 84, long ? 140 : 104);
  return (
    <Scene>
      {long ? (
        <Kicker>16 MCP incidents, 2025 to 2026</Kicker>
      ) : (
        <Kicker>AI agents with tools</Kicker>
      )}
      <Rise at={4}>
        <H size={sq ? 76 : 96}>
          Your agent holds{" "}
          <span style={{ color: C.accent }}>one broad token</span>.
        </H>
      </Rise>
      <Rise at={long ? 50 : 36} style={{ marginTop: 40 }}>
        <div
          style={{
            fontSize: sq ? 38 : 46,
            color: C.muted,
            maxWidth: 1400,
            lineHeight: 1.3,
          }}
        >
          One injected GitHub issue was enough to make an assistant publish a
          user's{" "}
          <span style={{ color: C.fg, position: "relative" }}>
            private repositories
            <span
              style={{
                position: "absolute",
                left: 0,
                right: 0,
                bottom: -6,
                height: 4,
                background: C.deny,
                scale: `${strike} 1`,
                transformOrigin: "left",
              }}
            />
          </span>
          .
        </div>
      </Rise>
      <Rise at={long ? 150 : 110} style={{ marginTop: 44 }}>
        <div style={{ fontSize: sq ? 34 : 40, color: C.fg }}>
          Nothing outside the agent said <Pill kind="deny" size={sq ? 30 : 34}>no</Pill>
        </div>
      </Rise>
      {long ? (
        <Rise at={175} style={{ marginTop: 50 }}>
          <div style={{ fontFamily: mono, fontSize: 22, color: C.muted }}>
            GitHub MCP prompt-injection leak, May 2025
          </div>
        </Rise>
      ) : null}
    </Scene>
  );
};

/* 2. Brand reveal ----------------------------------------------------- */
export const Reveal: React.FC = () => {
  const sq = useSquare();
  return (
    <Scene>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          textAlign: "center",
        }}
      >
        <Mark size={sq ? 200 : 240} at={4} />
        <Rise at={18} style={{ marginTop: 30 }}>
          <H size={sq ? 140 : 168}>attenuo</H>
        </Rise>
        <Rise at={34} style={{ marginTop: 24 }}>
          <div
            style={{
              fontSize: sq ? 36 : 44,
              color: C.muted,
              maxWidth: sq ? 860 : 1500,
              lineHeight: 1.3,
            }}
          >
            Every tool call your agent makes, checked against{" "}
            <span style={{ color: C.fg }}>what the user delegated</span>.
          </div>
        </Rise>
      </div>
    </Scene>
  );
};

/* 3. Delegation chain narrows ------------------------------------------ */
const hops = [
  { who: "alice", role: "user", caps: ["github:*", "email:*", "calendar:*"], w: 1 },
  { who: "assistant", role: "agent", caps: ["github:*"], w: 0.72 },
  { who: "coder", role: "sub-agent", caps: ["github:read_file"], w: 0.5 },
];

export const Chain: React.FC = () => {
  const f = useCurrentFrame();
  const { fps } = useVideoConfig();
  const sq = useSquare();
  const full = sq ? 900 : 1080;
  return (
    <Scene>
      <div
        style={{
          display: "flex",
          flexDirection: sq ? "column" : "row",
          gap: sq ? 30 : 90,
          alignItems: sq ? "flex-start" : "center",
        }}
      >
        <div style={{ flex: sq ? undefined : "0 0 600px" }}>
          <Kicker>{sq ? "RFC 8693 delegation" : "Delegation that only narrows"}</Kicker>
          <Rise at={6}>
            <H size={sq ? 54 : 76}>Each hand-off can only give away less.</H>
          </Rise>
          <Rise at={24} style={{ marginTop: 28, display: sq ? "none" : undefined }}>
            <div style={{ fontSize: sq ? 28 : 32, color: C.muted, lineHeight: 1.35 }}>
              RFC 8693 token exchange. Capabilities, argument limits, lifetime
              and depth shrink at every hop.
            </div>
          </Rise>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: sq ? 16 : 22, flex: 1 }}>
          {hops.map((h, i) => {
            const at = 20 + i * 22;
            const p = spring({ frame: f - at, fps, config: { damping: 18 } });
            const w = interpolate(p, [0, 1], [hops[Math.max(0, i - 1)].w, h.w]);
            return (
              <div
                key={h.who}
                style={{
                  opacity: Math.min(1, p * 1.4),
                  width: full * w,
                  marginLeft: i * (sq ? 36 : 44),
                  background: C.surface,
                  border: `2px solid ${i === 0 ? C.border : C.accent}${i === 0 ? "" : "88"}`,
                  borderRadius: 16,
                  padding: sq ? "16px 22px" : "22px 26px",
                }}
              >
                <div style={{ display: "flex", alignItems: "baseline", gap: 14 }}>
                  <span style={{ fontFamily: display, fontWeight: 700, fontSize: 38 }}>
                    {h.who}
                  </span>
                  <span style={{ fontSize: 24, color: C.muted, whiteSpace: "nowrap" }}>{h.role}</span>
                </div>
                <div style={{ display: "flex", gap: 10, marginTop: 14, flexWrap: "wrap" }}>
                  {h.caps.map((c) => (
                    <Pill key={c} kind="accent" size={22}>
                      {c}
                    </Pill>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </Scene>
  );
};

/* 4. Per-call decisions (lines from docs/demo/github-leak-demo.cast) ----- */
const calls = [
  {
    cmd: "read_file  repo=alice/public-docs",
    note: "the task",
    kind: "allow" as const,
    verdict: "ALLOWED",
    why: "policy_allow",
  },
  {
    cmd: "read_file  repo=alice/private-salaries",
    note: "injected",
    kind: "deny" as const,
    verdict: "DENIED",
    why: "policy_deny",
  },
  {
    cmd: "create_issue  title=leak",
    note: "injected",
    kind: "deny" as const,
    verdict: "DENIED",
    why: "capability_denied",
  },
];

export const Calls: React.FC<{ step?: number }> = ({ step = 62 }) => {
  const f = useCurrentFrame();
  const sq = useSquare();
  return (
    <Scene>
      <Kicker>Every call, checked</Kicker>
      <Rise at={4}>
        <H size={sq ? 58 : 70}>
          The coder reads a malicious issue.{" "}
          <span style={{ color: C.muted }}>Here's what reaches GitHub.</span>
        </H>
      </Rise>
      <Rise at={18} style={{ marginTop: 44 }}>
        <Panel title="coder → attenuo → github  (Cedar policy + lease + chain)">
          <div style={{ padding: sq ? "26px 28px" : "30px 36px", display: "flex", flexDirection: "column", gap: 22 }}>
            {calls.map((c, i) => {
              const at = 30 + i * step;
              const shown = typed(c.cmd, f, at, 60);
              const vp = prog(f, at + 26, at + 36);
              return (
                <div
                  key={i}
                  style={{
                    opacity: f >= at ? 1 : 0,
                    display: "flex",
                    alignItems: sq ? "flex-start" : "center",
                    flexDirection: sq ? "column" : "row",
                    gap: sq ? 12 : 24,
                    fontFamily: mono,
                    fontSize: sq ? 26 : 30,
                  }}
                >
                  <span style={{ flex: 1, whiteSpace: "pre" }}>
                    <span style={{ color: C.accent }}>$ </span>
                    {shown}
                    <span style={{ color: C.muted, fontSize: sq ? 20 : 22 }}>
                      {shown.length === c.cmd.length ? `   # ${c.note}` : "▍"}
                    </span>
                  </span>
                  <span
                    style={{
                      opacity: vp,
                      scale: `${0.85 + 0.15 * vp}`,
                      display: "flex",
                      gap: 14,
                      alignItems: "center",
                    }}
                  >
                    <Pill kind={c.kind} size={sq ? 24 : 26}>
                      {c.verdict}
                    </Pill>
                    <span style={{ color: C.muted, fontSize: sq ? 22 : 24 }}>{c.why}</span>
                  </span>
                </div>
              );
            })}
          </div>
        </Panel>
      </Rise>
      <Rise at={30 + 3 * step - 10} style={{ marginTop: 34 }}>
        <div style={{ fontSize: sq ? 28 : 32, color: C.muted }}>
          <span style={{ color: C.fg }}>1</span> call reached the upstream server. The
          injection got nothing.
        </div>
      </Rise>
    </Scene>
  );
};

/* 5. Revocation cascades ----------------------------------------------- */
export const Revoke: React.FC = () => {
  const f = useCurrentFrame();
  const sq = useSquare();
  const cut = 70;
  const nodes = [
    { who: "assistant", depth: 0, at: cut },
    { who: "coder", depth: 1, at: cut + 12 },
    { who: "reviewer", depth: 2, at: cut + 24 },
  ];
  return (
    <Scene>
      <div
        style={{
          display: "flex",
          flexDirection: sq ? "column" : "row",
          gap: sq ? 50 : 100,
          alignItems: sq ? "flex-start" : "center",
        }}
      >
        <div style={{ flex: sq ? undefined : "0 0 640px" }}>
          <Kicker>Leases and revocation</Kicker>
          <Rise at={6}>
            <H size={sq ? 64 : 76}>Revoke one lease. Every agent below it stops.</H>
          </Rise>
          <Rise at={24} style={{ marginTop: 28 }}>
            <div style={{ fontSize: sq ? 28 : 32, color: C.muted, lineHeight: 1.35 }}>
              On their very next call. Even the legitimate ones.
            </div>
          </Rise>
        </div>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 20 }}>
          {nodes.map((n) => {
            const r = prog(f, n.at, n.at + 10);
            const col = r > 0.5 ? C.deny : C.allow;
            return (
              <Rise key={n.who} at={14 + n.depth * 8}>
                <div
                  style={{
                    marginLeft: n.depth * 56,
                    display: "flex",
                    alignItems: "center",
                    gap: 20,
                    background: C.surface,
                    border: `2px solid ${r > 0.5 ? C.deny + "88" : C.border}`,
                    borderRadius: 14,
                    padding: "20px 26px",
                  }}
                >
                  <span style={{ fontFamily: display, fontWeight: 700, fontSize: 34, flex: 1, opacity: 1 - r * 0.4 }}>
                    {n.depth > 0 ? <span style={{ color: C.muted }}>└─ </span> : null}
                    {n.who}
                  </span>
                  <Pill kind={r > 0.5 ? "deny" : "allow"} size={22} style={{ color: col }}>
                    {r > 0.5 ? "REVOKED" : "ACTIVE"}
                  </Pill>
                </div>
              </Rise>
            );
          })}
          <Rise at={cut + 40} style={{ marginTop: 10 }}>
            <div style={{ fontFamily: mono, fontSize: sq ? 22 : 24, color: C.muted }}>
              <span style={{ color: C.accent }}>$</span> attenuo lease revoke …{" "}
              <span style={{ color: C.fg }}>revoked 2 lease(s)</span>
            </div>
          </Rise>
        </div>
      </div>
    </Scene>
  );
};

/* 6. Audit chain -------------------------------------------------------- */
export const Audit: React.FC = () => {
  const f = useCurrentFrame();
  const sq = useSquare();
  const entries = sq ? 5 : 7;
  return (
    <Scene>
      <Kicker>Tamper-evident audit</Kicker>
      <Rise at={4}>
        <H size={sq ? 62 : 76}>Every decision lands in a hash-chained log.</H>
      </Rise>
      <Rise at={20} style={{ marginTop: 22 }}>
        <div style={{ fontSize: sq ? 28 : 32, color: C.muted }}>
          Signed checkpoints that anyone can verify offline.
        </div>
      </Rise>
      <div style={{ display: "flex", alignItems: "center", marginTop: 60 }}>
        {Array.from({ length: entries }).map((_, i) => {
          const p = prog(f, 30 + i * 7, 44 + i * 7);
          const deny = i === 2 || i === 3;
          return (
            <React.Fragment key={i}>
              {i > 0 ? (
                <div style={{ width: 34, height: 3, background: C.accent, opacity: p, scale: `${p} 1`, transformOrigin: "left" }} />
              ) : null}
              <div
                style={{
                  opacity: p,
                  translate: `0px ${(1 - p) * 20}px`,
                  background: C.surface,
                  border: `2px solid ${C.border}`,
                  borderRadius: 12,
                  padding: "16px 18px",
                  width: sq ? 150 : 190,
                  fontFamily: mono,
                }}
              >
                <div style={{ fontSize: 18, color: C.muted }}>seq {i + 1}</div>
                <div style={{ fontSize: 20, marginTop: 8, color: deny ? C.deny : C.allow }}>
                  {deny ? "DENY" : "ALLOW"}
                </div>
                <div style={{ fontSize: 16, color: C.muted, marginTop: 8 }}>
                  {["b57b76", "6741904", "617b70", "26c2e3", "6ada24", "9f02c1", "c3b858"][i]}…
                </div>
              </div>
            </React.Fragment>
          );
        })}
      </div>
      <Rise at={30 + entries * 7 + 20} style={{ marginTop: 40 }}>
        <div style={{ fontFamily: mono, fontSize: sq ? 24 : 28 }}>
          <span style={{ color: C.accent }}>$</span> attenuo audit verify{"   "}
          <span style={{ color: C.allow }}>✓ chain verified</span>
        </div>
      </Rise>
    </Scene>
  );
};

/* 7. Admin console ------------------------------------------------------ */
export const Console: React.FC = () => {
  const f = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const sq = useSquare();
  const z = interpolate(f, [0, durationInFrames], [1.0, 1.12]);
  return (
    <Scene>
      <Kicker>Admin console</Kicker>
      <Rise at={4}>
        <H size={sq ? 56 : 64}>See every allow and deny, by agent and chain.</H>
      </Rise>
      <Rise at={18} style={{ marginTop: 40 }}>
        <Panel style={{ height: sq ? 560 : 600 }}>
          <div style={{ scale: `${z}`, transformOrigin: "0% 0%" }}>
            <CanvasImage
              src={staticFile("shots/dark-02-audit.png")}
              style={{ width: sq ? 1200 : 1680, display: "block" }}
            />
          </div>
        </Panel>
      </Rise>
    </Scene>
  );
};

/* 8. Numbers ------------------------------------------------------------ */
const Bar: React.FC<{ label: string; n: number; of: number; col: string; at: number }> = ({
  label,
  n,
  of,
  col,
  at,
}) => {
  const f = useCurrentFrame();
  const sq = useSquare();
  const p = prog(f, at, at + 30);
  const shown = Math.round(n * p);
  return (
    <div style={{ marginTop: 26 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: sq ? 26 : 30, marginBottom: 12 }}>
        <span style={{ color: C.muted }}>{label}</span>
        <span style={{ fontFamily: mono, color: col }}>
          {shown}/{of}
        </span>
      </div>
      <div style={{ height: 22, background: C.surface2, borderRadius: 99, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${(n / of) * 100 * p}%`, background: col, borderRadius: 99 }} />
      </div>
    </div>
  );
};

export const Numbers: React.FC<{ long?: boolean }> = ({ long }) => {
  const sq = useSquare();
  return (
    <Scene>
      <Kicker>Injection suite, held-out test split</Kicker>
      <Rise at={4}>
        <H size={sq ? 60 : 74}>Attack calls that got through</H>
      </Rise>
      <div style={{ maxWidth: 1500 }}>
        <Bar label="Agent calls tools directly" n={38} of={38} col={C.deny} at={20} />
        <Bar label="Behind attenuo" n={7} of={38} col={C.accent} at={40} />
        {long ? (
          <Bar label="attenuo + output labels + one-call limit" n={1} of={38} col={C.allow} at={60} />
        ) : null}
      </div>
      <Rise at={long ? 90 : 70} style={{ marginTop: 34 }}>
        <div style={{ fontSize: sq ? 26 : 30, color: C.fg }}>
          Benign calls denied: <span style={{ fontFamily: mono }}>3/29</span>
          <span style={{ color: C.muted }}>{"   ·   "}0.4 to 0.8 ms median added per call</span>
        </div>
      </Rise>
      <Rise at={long ? 105 : 85} style={{ marginTop: 26 }}>
        <div style={{ fontSize: sq ? 21 : 23, color: C.muted, maxWidth: 1500, lineHeight: 1.4 }}>
          26 synthetic cases replayed without a model. Cases and policies were written by the
          same people who built attenuo: this checks the implementation, not real-world catch rates.
        </div>
      </Rise>
    </Scene>
  );
};

/* 9. Honest research notes (LinkedIn) ----------------------------------- */
export const Research: React.FC = () => {
  const sq = useSquare();
  const items = [
    ["AgentDojo, four frontier models", "Stock attacks landed 0/212 even without attenuo. But injected text still stopped up to 92 runs through refusals: a denial of service the attack-success metric hides."],
    ["Still open", "Reads that leak data through an allowed URL fetch. Approvers who click yes unread. An independent attack corpus."],
  ];
  return (
    <Scene>
      <Kicker>What the research says, honestly</Kicker>
      <Rise at={4}>
        <H size={sq ? 58 : 70}>Built like a research project, with the gaps written down.</H>
      </Rise>
      <div style={{ display: "flex", flexDirection: sq ? "column" : "row", gap: 28, marginTop: 50 }}>
        {items.map(([t, b], i) => (
          <Rise key={t} at={26 + i * 30} style={{ flex: 1 }}>
            <div style={{ background: C.surface, border: `1.5px solid ${C.border}`, borderRadius: 16, padding: sq ? "26px 30px" : "34px 38px", height: "100%" }}>
              <div style={{ fontFamily: display, fontWeight: 700, fontSize: sq ? 30 : 36, color: C.accent }}>{t}</div>
              <div style={{ fontSize: sq ? 25 : 29, color: C.fg, marginTop: 16, lineHeight: 1.4 }}>{b}</div>
            </div>
          </Rise>
        ))}
      </div>
      <Rise at={90} style={{ marginTop: 34 }}>
        <div style={{ fontSize: sq ? 24 : 28, color: C.muted }}>
          ADRs, a spec, repeated security review passes and a technical report, all in the repo.
        </div>
      </Rise>
    </Scene>
  );
};

/* 10. Outro ------------------------------------------------------------- */
export const Outro: React.FC = () => {
  const sq = useSquare();
  return (
    <Scene>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 28 }}>
          <Mark size={sq ? 110 : 130} at={2} />
          <Rise at={10}>
            <H size={sq ? 104 : 124}>attenuo</H>
          </Rise>
        </div>
        <Rise at={24} style={{ marginTop: 34 }}>
          <div style={{ display: "flex", gap: 14, flexWrap: "wrap", justifyContent: "center" }}>
            {["self-hosted", "Rust", "Cedar", "MCP proxy", "Apache-2.0"].map((t) => (
              <Pill key={t} kind="accent" size={sq ? 24 : 28}>
                {t}
              </Pill>
            ))}
          </div>
        </Rise>
        <Rise at={40} style={{ marginTop: 50 }}>
          <div style={{ fontSize: sq ? 34 : 40, color: C.fg }}>Open source soon.</div>
        </Rise>
        <Rise at={52} style={{ marginTop: 18 }}>
          <div style={{ fontFamily: mono, fontSize: sq ? 28 : 32, color: C.muted }}>
            building in public · <span style={{ color: C.accent }}>@mudit_builds</span>
          </div>
        </Rise>
      </div>
    </Scene>
  );
};

