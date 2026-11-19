import { loadFont } from "@remotion/fonts";
import { staticFile } from "remotion";

// Tokens from assets/brand/README.md (the approved design system).
export const C = {
  bg: "#0e1416",
  surface: "#141c1f",
  surface2: "#1a2427",
  border: "#25333a",
  fg: "#dce5e7",
  muted: "#8d9ea3",
  accent: "#3fc1b0",
  allow: "#5ccf8a",
  allowBg: "rgba(92,207,138,0.12)",
  deny: "#f2777a",
  denyBg: "rgba(242,119,122,0.12)",
  warn: "#e6b450",
};

// Fonts are bundled in public/fonts (OFL 1.1) so renders work offline.
const faces: [string, string, string][] = [
  ["Bricolage Grotesque", "BricolageGrotesque.woff2", "200 800"],
  ["IBM Plex Sans", "IBMPlexSans.woff2", "400"],
  ["IBM Plex Sans", "IBMPlexSans.woff2", "500"],
  ["IBM Plex Sans", "IBMPlexSans.woff2", "600"],
  ["IBM Plex Mono", "IBMPlexMono-400.woff2", "400"],
  ["IBM Plex Mono", "IBMPlexMono-500.woff2", "500"],
];
for (const [family, file, weight] of faces) {
  loadFont({ family, url: staticFile(`fonts/${file}`), weight, format: "woff2" });
}
export const display = "'Bricolage Grotesque', sans-serif";
export const sans = "'IBM Plex Sans', sans-serif";
export const mono = "'IBM Plex Mono', monospace";

export const FPS = 30;
