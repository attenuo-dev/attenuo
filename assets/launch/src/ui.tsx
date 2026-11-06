import React from "react";
import {
  AbsoluteFill,
  Easing,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { C, display, mono, sans } from "./theme";

const clamp = {
  extrapolateLeft: "clamp",
  extrapolateRight: "clamp",
} as const;
export const ease = Easing.bezier(0.16, 1, 0.3, 1);

/** 0..1 progress between two frames, eased. */
export const prog = (f: number, a: number, b: number) =>
  interpolate(f, [a, b], [0, 1], { ...clamp, easing: ease });

/** Is the canvas square (1:1 cut)? */
export const useSquare = () => {
  const { width, height } = useVideoConfig();
  return width / height < 1.3;
};

/** Fade a whole scene in and out over its own duration. */
export const Scene: React.FC<{
  children: React.ReactNode;
  pad?: number;
}> = ({ children, pad }) => {
  const f = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const sq = useSquare();
  const opacity = Math.min(
    prog(f, 0, 10),
    1 - prog(f, durationInFrames - 10, durationInFrames),
  );
  return (
    <AbsoluteFill
      style={{
        opacity,
        padding: pad ?? (sq ? 80 : 120),
        justifyContent: "center",
        fontFamily: sans,
        color: C.fg,
      }}
    >
      {children}
    </AbsoluteFill>
  );
};

/** Text that rises and fades in at frame `at`. */
export const Rise: React.FC<{
  at: number;
  children: React.ReactNode;
  style?: React.CSSProperties;
  dist?: number;
}> = ({ at, children, style, dist = 28 }) => {
  const f = useCurrentFrame();
  const p = prog(f, at, at + 18);
  return (
    <div
      style={{
        opacity: p,
        translate: `0px ${(1 - p) * dist}px`,
        ...style,
      }}
    >
      {children}
    </div>
  );
};

export const Kicker: React.FC<{ children: React.ReactNode; at?: number }> = ({
  children,
  at = 0,
}) => (
  <Rise
    at={at}
    style={{
      fontFamily: mono,
      fontSize: 28,
      letterSpacing: "0.08em",
      textTransform: "uppercase",
      color: C.accent,
      marginBottom: 28,
    }}
  >
    {children}
  </Rise>
);

export const H: React.FC<{
  children: React.ReactNode;
  size?: number;
  style?: React.CSSProperties;
}> = ({ children, size = 84, style }) => (
  <div
    style={{
      fontFamily: display,
      fontWeight: 700,
      fontSize: size,
      lineHeight: 1.06,
      letterSpacing: "-0.02em",
      ...style,
    }}
  >
    {children}
  </div>
);

export const Pill: React.FC<{
  kind: "allow" | "deny" | "warn" | "accent";
  children: React.ReactNode;
  size?: number;
  style?: React.CSSProperties;
}> = ({ kind, children, size = 26, style }) => {
  const col = { allow: C.allow, deny: C.deny, warn: C.warn, accent: C.accent }[
    kind
  ];
  return (
    <span
      style={{
        fontFamily: mono,
        fontWeight: 500,
        fontSize: size,
        color: col,
        background:
          kind === "allow" ? C.allowBg : kind === "deny" ? C.denyBg : "rgba(63,193,176,0.12)",
        border: `1.5px solid ${col}55`,
        padding: `${size * 0.22}px ${size * 0.6}px`,
        borderRadius: 999,
        letterSpacing: "0.04em",
        whiteSpace: "nowrap",
        ...style,
      }}
    >
      {children}
    </span>
  );
};

/** The narrowing-chain mark, each square springing in. */
export const Mark: React.FC<{ size: number; at?: number; color?: string }> = ({
  size,
  at = 0,
  color = C.accent,
}) => {
  const f = useCurrentFrame();
  const { fps } = useVideoConfig();
  const sq = [
    { x: 2, y: 17, s: 30, r: 6 },
    { x: 36, y: 23, s: 18, r: 4 },
    { x: 57, y: 28, s: 8, r: 2 },
  ];
  return (
    <svg viewBox="0 0 66 64" width={size} height={(size * 64) / 66}>
      {sq.map((q, i) => {
        const p = spring({
          frame: f - at - i * 5,
          fps,
          config: { damping: 14, stiffness: 140 },
        });
        const cx = q.x + q.s / 2;
        const cy = q.y + q.s / 2;
        return (
          <rect
            key={i}
            x={q.x}
            y={q.y}
            width={q.s}
            height={q.s}
            rx={q.r}
            fill={color}
            style={{
              transformOrigin: `${cx}px ${cy}px`,
              transform: `scale(${p})`,
            }}
          />
        );
      })}
    </svg>
  );
};

/** Background: brand bg, faint grid and a slow teal glow. */
export const Backdrop: React.FC = () => {
  const f = useCurrentFrame();
  const { width, height } = useVideoConfig();
  return (
    <AbsoluteFill style={{ background: C.bg }}>
      <AbsoluteFill
        style={{
          backgroundImage: `linear-gradient(${C.border}55 1px, transparent 1px), linear-gradient(90deg, ${C.border}55 1px, transparent 1px)`,
          backgroundSize: "64px 64px",
          maskImage:
            "radial-gradient(ellipse at 50% 45%, black 10%, transparent 72%)",
          opacity: 0.55,
        }}
      />
      <div
        style={{
          position: "absolute",
          width: width * 0.9,
          height: width * 0.9,
          left: width * 0.05 + Math.sin(f / 90) * 60,
          top: height * 0.5 - width * 0.45 + Math.cos(f / 110) * 40,
          background:
            "radial-gradient(circle, rgba(63,193,176,0.10) 0%, rgba(63,193,176,0) 60%)",
        }}
      />
    </AbsoluteFill>
  );
};

/** Small persistent brand corner. */
export const Corner: React.FC = () => {
  const sq = useSquare();
  return (
    <div
      style={{
        position: "absolute",
        left: sq ? 56 : 72,
        top: sq ? 48 : 56,
        display: "flex",
        alignItems: "center",
        gap: 14,
        opacity: 0.85,
      }}
    >
      <Mark size={34} at={-100} />
      <span
        style={{
          fontFamily: display,
          fontWeight: 700,
          fontSize: 28,
          letterSpacing: "-0.02em",
          color: C.fg,
        }}
      >
        attenuo
      </span>
    </div>
  );
};

/** A terminal-styled panel. */
export const Panel: React.FC<{
  children: React.ReactNode;
  title?: string;
  style?: React.CSSProperties;
}> = ({ children, title, style }) => (
  <div
    style={{
      background: C.surface,
      border: `1.5px solid ${C.border}`,
      borderRadius: 14,
      overflow: "hidden",
      boxShadow: "0 30px 80px rgba(0,0,0,0.45)",
      ...style,
    }}
  >
    {title ? (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "16px 22px",
          borderBottom: `1.5px solid ${C.border}`,
          background: C.surface2,
        }}
      >
        {[0, 1, 2].map((i) => (
          <span
            key={i}
            style={{
              width: 13,
              height: 13,
              borderRadius: 99,
              background: C.border,
            }}
          />
        ))}
        <span
          style={{
            fontFamily: mono,
            fontSize: 20,
            color: C.muted,
            marginLeft: 12,
          }}
        >
          {title}
        </span>
      </div>
    ) : null}
    {children}
  </div>
);

/** Typewriter: reveal characters of `text` starting at `at`. */
export const typed = (text: string, f: number, at: number, cps = 45) => {
  const n = Math.max(0, Math.floor(((f - at) / 30) * cps));
  return text.slice(0, n);
};
