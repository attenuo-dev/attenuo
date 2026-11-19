#!/usr/bin/env bash
# Render every cut. Designed at 1080p / 1080 square, rendered at --scale=2:
# 3840x2160 (16:9) and 2160x2160 (1:1) masters, plus 1080p copies and a GIF.
# Set REMOTION_BROWSER to a local Chrome Headless Shell if Remotion cannot download one.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out
BROWSER=()
if [ -n "${REMOTION_BROWSER:-}" ]; then BROWSER=(--browser-executable="$REMOTION_BROWSER"); fi

for id in ${CUTS:-X-16x9 X-1x1 LinkedIn-16x9 LinkedIn-1x1}; do
  npx remotion render src/index.ts "$id" "out/attenuo-$id-4k.mp4" \
    --scale=2 --codec=h264 --crf=16 --x264-preset=slow --pixel-format=yuv420p \
    "${BROWSER[@]}"
  # 1080p copy for quick review and for platforms that downscale anyway.
  case "$id" in
    *16x9) size=1920:1080 ;;
    *) size=1080:1080 ;;
  esac
  ffmpeg -y -loglevel error -i "out/attenuo-$id-4k.mp4" -vf "scale=$size:flags=lanczos" \
    -c:v libx264 -crf 18 -preset slow -pix_fmt yuv420p -movflags +faststart "out/attenuo-$id-1080p.mp4"
done

# GIF: the per-call decision scene, 960 px wide, 15 fps.
npx remotion render src/index.ts Gif out/gif-src.mp4 --codec=h264 --crf=14 "${BROWSER[@]}"
ffmpeg -y -loglevel error -i out/gif-src.mp4 \
  -vf "fps=15,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=sierra2_4a" \
  out/attenuo-calls.gif
rm -f out/gif-src.mp4
ls -lh out
