#!/usr/bin/env bash
# Render the one-page researcher brief to HTML (pandoc) and then to PDF (Chromium via Playwright).
#
#   docs/brief/build.sh            # writes attenuo-one-page.html and attenuo-one-page.pdf here
#
# Needs pandoc (3.x), Node with the `playwright` package and its Chromium installed, and
# network access to Google Fonts (without it the page falls back to sans-serif).
# The outputs are git-ignored; only the Markdown and this script are committed.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
name="attenuo-one-page"
src="$here/$name.md"
html="$here/$name.html"
pdf="$here/$name.pdf"
css="$(mktemp --suffix=.css)"
head="$(mktemp --suffix=.html)"
trap 'rm -f "$css" "$head"' EXIT

# Attenuo design system, print variant: white background, #111 text, light-theme brand teal.
cat >"$head" <<'HTML'
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@600;700&family=IBM+Plex+Mono:wght@400&family=IBM+Plex+Sans:ital,wght@0,400;0,600;1,400&display=swap">
HTML

cat >"$css" <<'CSS'
:root { --text: #111; --accent: #0d7468; --rule: #c9d6d4; --muted: #444; }
@page { size: A4; }
html { font-size: 9.5pt; }
body {
  font-family: "IBM Plex Sans", sans-serif;
  line-height: 1.36; color: var(--text); background: #fff;
  max-width: none; margin: 0; padding: 0;
}
h1 {
  font-family: "Bricolage Grotesque", sans-serif; font-weight: 700;
  font-size: 2.1em; line-height: 1.1; color: var(--accent);
  margin: 0 0 0.15em; padding-bottom: 0.2em; border-bottom: 2px solid var(--accent);
}
p.tagline { font-size: 1.12em; margin: 0.35em 0 0.1em; }
p.author { color: var(--muted); margin: 0 0 0.4em; }
h2 {
  font-family: "IBM Plex Sans", sans-serif; font-weight: 600;
  font-size: 1.12em; color: var(--accent); margin: 0.85em 0 0.25em; break-after: avoid;
}
p { margin: 0.3em 0; }
ul { margin: 0.3em 0; padding-left: 1.3em; }
li { margin: 0.2em 0; }
strong { font-weight: 600; }
code { font-family: "IBM Plex Mono", monospace; font-size: 0.9em; }
table { border-collapse: collapse; width: 100%; margin: 0.4em 0; font-size: 0.95em; break-inside: avoid; }
thead th { background: var(--accent); color: #fff; font-weight: 600; text-align: left; }
th, td { padding: 0.2em 0.5em; border-bottom: 1px solid var(--rule); vertical-align: top; }
td:first-child { width: 48%; }
a { color: var(--accent); text-decoration: none; }
CSS

pandoc "$src" \
  --from markdown \
  --to html5 \
  --standalone \
  --embed-resources \
  --css "$css" \
  --include-in-header "$head" \
  --metadata title="attenuo: researcher brief" \
  --metadata lang=en \
  --variable pagetitle="attenuo: researcher brief" \
  --output "$html"
# pandoc prints the metadata title as a header block; the Markdown's own H1 is the title.
sed -i '/<header id="title-block-header">/,/<\/header>/d' "$html"
echo "wrote $html"

HTML="$html" PDF="$pdf" node -e '
const { chromium } = require("playwright");
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto("file://" + process.env.HTML, { waitUntil: "networkidle" });
  await page.evaluate(() => document.fonts.ready);
  await page.pdf({
    path: process.env.PDF,
    format: "A4",
    printBackground: true,
    margin: { top: "16mm", bottom: "16mm", left: "18mm", right: "18mm" },
  });
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
'
echo "wrote $pdf"
