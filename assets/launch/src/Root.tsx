import React from "react";
import { AbsoluteFill, Composition, Sequence } from "remotion";
import { Backdrop, Corner } from "./ui";
import {
  Audit,
  Calls,
  Chain,
  Console,
  Hook,
  Numbers,
  Outro,
  Research,
  Reveal,
  Revoke,
} from "./scenes";
import { FPS } from "./theme";

type Shot = { el: React.ReactNode; frames: number; corner?: boolean };

const xCut: Shot[] = [
  { el: <Hook />, frames: 150, corner: true },
  { el: <Reveal />, frames: 105 },
  { el: <Chain />, frames: 200, corner: true },
  { el: <Calls />, frames: 260, corner: true },
  { el: <Revoke />, frames: 165, corner: true },
  { el: <Numbers />, frames: 170, corner: true },
  { el: <Outro />, frames: 120 },
];

const linkedInCut: Shot[] = [
  { el: <Hook long />, frames: 240, corner: true },
  { el: <Reveal />, frames: 120 },
  { el: <Chain />, frames: 225, corner: true },
  { el: <Calls step={75} />, frames: 300, corner: true },
  { el: <Revoke />, frames: 185, corner: true },
  { el: <Audit />, frames: 180, corner: true },
  { el: <Console />, frames: 210, corner: true },
  { el: <Numbers long />, frames: 220, corner: true },
  { el: <Research />, frames: 300, corner: true },
  { el: <Outro />, frames: 160 },
];

const gifCut: Shot[] = [{ el: <Calls step={48} />, frames: 230, corner: true }];

const total = (s: Shot[]) => s.reduce((a, b) => a + b.frames, 0);

const Cut: React.FC<{ shots: Shot[] }> = ({ shots }) => {
  let from = 0;
  return (
    <AbsoluteFill>
      <Backdrop />
      {shots.map((s, i) => {
        const seq = (
          <Sequence key={i} from={from} durationInFrames={s.frames}>
            {s.corner ? <Corner /> : null}
            {s.el}
          </Sequence>
        );
        from += s.frames;
        return seq;
      })}
    </AbsoluteFill>
  );
};

const X = () => <Cut shots={xCut} />;
const LinkedIn = () => <Cut shots={linkedInCut} />;
const Gif = () => <Cut shots={gifCut} />;

// Designed at 1080p / 1080 square; render with --scale=2 for 4K (3840x2160, 2160x2160).
export const RemotionRoot: React.FC = () => (
  <>
    <Composition id="X-16x9" component={X} durationInFrames={total(xCut)} fps={FPS} width={1920} height={1080} />
    <Composition id="X-1x1" component={X} durationInFrames={total(xCut)} fps={FPS} width={1080} height={1080} />
    <Composition id="LinkedIn-16x9" component={LinkedIn} durationInFrames={total(linkedInCut)} fps={FPS} width={1920} height={1080} />
    <Composition id="LinkedIn-1x1" component={LinkedIn} durationInFrames={total(linkedInCut)} fps={FPS} width={1080} height={1080} />
    <Composition id="Gif" component={Gif} durationInFrames={total(gifCut)} fps={FPS} width={1920} height={1080} />
  </>
);
