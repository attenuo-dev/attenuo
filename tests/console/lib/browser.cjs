// The browser side of the console smoke test: one Chromium page that records every console
// error, page error, CSP violation and failed request for the whole run, plus helpers to
// switch theme, check text contrast and take screenshots.
'use strict';

const path = require('node:path');
const { chromium } = require('playwright');

// Installed before any page script runs. Playwright evaluates it outside the page's CSP, so
// it is not itself a violation; it only listens. The record lives on window so the test can
// read it back, and the node it is kept on is not exposed to page code by any other name.
function violationRecorder() {
  window.__cspViolations = [];
  document.addEventListener('securitypolicyviolation', (ev) => {
    window.__cspViolations.push({
      directive: ev.effectiveDirective || ev.violatedDirective,
      blocked: ev.blockedURI,
      source: ev.sourceFile,
      line: ev.lineNumber,
      sample: ev.sample,
    });
  });
}

class Console {
  constructor(browser, context, page) {
    this.browser = browser;
    this.context = context;
    this.page = page;
    this.problems = [];
    this.requests = [];
    page.on('request', (req) => this.requests.push(`${req.method()} ${new URL(req.url()).pathname}`));
    page.on('console', (msg) => {
      if (msg.type() === 'error' || msg.type() === 'warning') {
        this.problems.push(`console.${msg.type()}: ${msg.text()} (${msg.location().url || 'no url'})`);
      }
    });
    page.on('pageerror', (err) => this.problems.push(`pageerror: ${err.message}`));
    page.on('requestfailed', (req) => this.problems.push(`request failed: ${req.method()} ${req.url()} ${req.failure()?.errorText}`));
    page.on('response', (resp) => {
      if (resp.status() >= 400) this.problems.push(`HTTP ${resp.status()}: ${resp.request().method()} ${resp.url()}`);
    });
  }

  static async open(ui, { colorScheme = 'dark' } = {}) {
    const browser = await chromium.launch();
    // Reduced motion: no colour transitions, so a contrast reading right after a theme switch
    // sees the final colours.
    const context = await browser.newContext({ colorScheme, reducedMotion: 'reduce', viewport: { width: 1280, height: 900 } });
    await context.addInitScript(violationRecorder);
    const page = await context.newPage();
    const c = new Console(browser, context, page);
    await page.goto(`${ui}/admin/ui/`);
    return c;
  }

  async close() {
    await this.browser.close();
  }

  async cspViolations() {
    return this.page.evaluate(() => window.__cspViolations.slice());
  }

  /** Everything that went wrong so far: console errors and warnings, page errors, failed or
   * 4xx/5xx requests, and CSP violations. */
  async allProblems() {
    const csp = (await this.cspViolations()).map((v) => `CSP violation: ${JSON.stringify(v)}`);
    return this.problems.concat(csp);
  }

  async login(token) {
    const p = this.page;
    await p.locator('#admin-token').fill(token);
    await p.getByRole('button', { name: 'Log in' }).click();
    await p.locator('#nav:not([hidden])').waitFor();
  }

  /** Navigate inside the console without reloading (a reload forgets the admin token). */
  async go(hash) {
    await this.page.evaluate((h) => { location.hash = h; }, hash);
  }

  async theme() {
    return this.page.evaluate(() => {
      const set = document.documentElement.getAttribute('data-theme');
      if (set) return set;
      return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    });
  }

  /**
   * Switch to `want` with the toggle button, the way an operator would. A modal dialog makes
   * the rest of the page inert, so while one is open the attribute the toggle sets is set
   * directly instead.
   */
  async setTheme(want) {
    if ((await this.theme()) !== want) {
      if (await this.page.locator('dialog[open]').count()) {
        await this.page.evaluate((t) => document.documentElement.setAttribute('data-theme', t), want);
      } else {
        await this.page.locator('#theme-toggle').click();
      }
    }
    const now = await this.theme();
    if (now !== want) throw new Error(`theme toggle left the page in ${now}, want ${want}`);
  }

  async screenshot(dir, name) {
    const file = path.join(dir, `${name}.png`);
    // From the top, so the sticky header is drawn where it belongs in a full-page capture.
    await this.page.evaluate(() => window.scrollTo(0, 0));
    await this.page.screenshot({ path: file, fullPage: true });
    return file;
  }

  /** Body background and text colour, as computed. */
  async bodyColours() {
    return this.page.evaluate(() => {
      const s = getComputedStyle(document.body);
      return { bg: s.backgroundColor, fg: s.color };
    });
  }

  /**
   * Text whose contrast against the background it is drawn on is below `min` (WCAG 2 ratio).
   * Every visible element with its own text is checked; the background is the nearest
   * ancestor-or-self with an opaque-enough background colour. Disabled controls are skipped
   * (WCAG exempts them).
   */
  async lowContrast(min = 4.5) {
    return this.page.evaluate((min) => {
      const parse = (c) => {
        const m = c.match(/rgba?\(([^)]+)\)/);
        if (!m) return null;
        const parts = m[1].split(/[\s,/]+/).filter(Boolean).map(Number);
        return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
      };
      const lum = ({ r, g, b }) => {
        const f = (v) => {
          const s = v / 255;
          return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
        };
        return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
      };
      const blend = (top, under) => ({
        r: top.r * top.a + under.r * (1 - top.a),
        g: top.g * top.a + under.g * (1 - top.a),
        b: top.b * top.a + under.b * (1 - top.a),
        a: 1,
      });
      // Composite the background colours from the root down to el.
      const background = (el) => {
        const chain = [];
        for (let n = el; n && n.nodeType === 1; n = n.parentElement) chain.push(n);
        let bg = { r: 255, g: 255, b: 255, a: 1 };
        for (const n of chain.reverse()) {
          const c = parse(getComputedStyle(n).backgroundColor);
          if (c && c.a > 0) bg = blend(c, bg);
        }
        return bg;
      };
      const out = [];
      for (const el of document.querySelectorAll('body *')) {
        if (el.closest('[hidden], dialog:not([open]), details:not([open]) > :not(summary)')) continue;
        if (el.disabled || el.closest('noscript, script, style')) continue;
        const ownText = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
        const isField = el.matches('input:not([type=checkbox]):not([type=radio]), textarea, select');
        if (!ownText && !isField) continue;
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) continue;
        const s = getComputedStyle(el);
        if (s.visibility === 'hidden' || Number(s.opacity) === 0) continue;
        const bg = background(el);
        const fgRaw = parse(s.color);
        if (!fgRaw) continue;
        const fg = blend(fgRaw, bg);
        const [l1, l2] = [lum(fg), lum(bg)].sort((a, b) => b - a);
        const ratio = (l1 + 0.05) / (l2 + 0.05);
        if (ratio < min) {
          const text = (el.value || el.textContent || el.placeholder || '').trim().slice(0, 40);
          out.push(`${el.tagName.toLowerCase()}.${[...el.classList].join('.')} "${text}": ${ratio.toFixed(2)} (${s.color} on rgb(${Math.round(bg.r)}, ${Math.round(bg.g)}, ${Math.round(bg.b)}))`);
        }
      }
      return out;
    }, min);
  }
}

module.exports = { Console };
