#!/usr/bin/env bash
# Render the technical report to HTML (pandoc) and then to PDF (Chromium via Playwright).
#
#   docs/report/build.sh            # writes attenuo-2026-11.html and attenuo-2026-11.pdf here
#
# Needs pandoc (3.x) and Node with the `playwright` package and its Chromium installed.
# No LaTeX. The outputs are git-ignored; only the Markdown and this script are committed.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
name="attenuo-2026-11"
src="$here/$name.md"
html="$here/$name.html"
pdf="$here/$name.pdf"
css="$(mktemp --suffix=.css)"
links="$(mktemp --suffix=.lua)"
trap 'rm -f "$css" "$links"' EXIT

# The Markdown links to other docs relatively (../research/x.md), which the mdBook site
# resolves. A PDF is read on its own, so point those links at the repository instead.
cat >"$links" <<'LUA'
local base = "https://github.com/attenuo-dev/attenuo/blob/main/docs/"
function Link(el)
  local rest = el.target:match("^%.%./(.*)$")
  if rest then el.target = base .. rest end
  return el
end
LUA

cat >"$css" <<'CSS'
@page { size: A4; }
html { font-size: 10pt; }
body {
  font-family: "Charter", "Bitstream Charter", "Georgia", "DejaVu Serif", serif;
  line-height: 1.34; color: #111; background: #fff;
  max-width: none; margin: 0; padding: 0;
  text-align: justify; hyphens: auto;
}
header#title-block-header { text-align: center; margin-bottom: 1.4em; }
h1.title { font-size: 1.55em; line-height: 1.25; margin: 0 0 0.5em; }
p.author, p.date { margin: 0.15em 0; font-size: 1.05em; }
.abstract { margin: 1.2em 2.2em 0; text-align: justify; font-size: 0.95em; }
.abstract-title { font-weight: bold; text-align: center; margin-bottom: 0.3em; }
h1 { font-size: 1.22em; margin: 1.3em 0 0.45em; break-after: avoid; }
h2 { font-size: 1.05em; margin: 1.05em 0 0.35em; break-after: avoid; }
h1 .header-section-number, h2 .header-section-number { margin-right: 0.5em; }
p { margin: 0.45em 0; orphans: 3; widows: 3; }
ul, ol { margin: 0.4em 0; padding-left: 1.6em; }
li { margin: 0.15em 0; }
code { font-family: "DejaVu Sans Mono", "Menlo", monospace; font-size: 0.84em; }
pre {
  font-size: 0.8em; line-height: 1.3; background: #f5f5f5; border: 1px solid #ddd;
  padding: 0.5em 0.7em; white-space: pre-wrap; text-align: left;
}
pre code { font-size: 1em; }
table {
  border-collapse: collapse; margin: 0.8em auto; font-size: 0.82em; width: 100%;
  text-align: left;
}
tr { break-inside: avoid; }
thead { display: table-header-group; }
img { break-inside: avoid; }
caption { caption-side: bottom; font-size: 0.95em; padding-top: 0.4em; text-align: left; }
th, td { padding: 0.18em 0.5em; border-bottom: 1px solid #ccc; vertical-align: top; }
thead th { border-bottom: 1.5px solid #444; }
img { display: block; max-width: 100%; height: auto; margin: 0.9em auto 0.3em; }
h3 { font-size: 1em; margin: 0.9em 0 0.3em; break-after: avoid; }
a { color: #1a4d8f; text-decoration: none; word-break: break-word; }
section.footnotes, ol li { word-break: break-word; }
h1#references ~ ol { font-size: 0.86em; text-align: left; }
h1#references ~ ol li { margin: 0.05em 0; }
CSS

pandoc "$src" \
  --from markdown \
  --to html5 \
  --standalone \
  --number-sections \
  --embed-resources \
  --resource-path "$here" \
  --css "$css" \
  --lua-filter "$links" \
  --metadata lang=en \
  --output "$html"
echo "wrote $html"

HTML="$html" PDF="$pdf" node -e '
const { chromium } = require("playwright");
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto("file://" + process.env.HTML, { waitUntil: "load" });
  await page.pdf({
    path: process.env.PDF,
    format: "A4",
    printBackground: true,
    margin: { top: "18mm", bottom: "18mm", left: "19mm", right: "19mm" },
    displayHeaderFooter: true,
    headerTemplate: "<span></span>",
    footerTemplate: "<div style=\"font-size:8pt;width:100%;text-align:center;color:#555\"><span class=\"pageNumber\"></span></div>",
  });
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
'
echo "wrote $pdf"
