// Browser smoke test of the embedded admin console. Run it with scripts/console-smoke.sh,
// which builds and starts the server and passes its addresses in CONSOLE_SMOKE_* variables.
//
// One headless Chromium page logs in once and visits every console page. On each page the
// test waits for the data, checks the elements that carry it, then, in the dark and the light
// theme, checks text contrast and that nothing scrolls sideways, and takes a screenshot. At the
// end it asserts that the whole run produced no console error or warning, no page error, no
// failed or 4xx/5xx request and no CSP violation.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { env, cli, cliJson, populate } = require('./lib/populate.cjs');
const { Console } = require('./lib/browser.cjs');

const E = env();
const THEMES = ['dark', 'light'];
let data;
let c;

async function admin(path) {
  const resp = await fetch(`${E.ui}${path}`, { headers: { Authorization: `Bearer ${E.adminToken}`, Accept: 'application/json' } });
  assert.equal(resp.status, 200, `GET ${path}`);
  return resp.json();
}

/** The text of a <dl class="kv"> value, by its label, inside `scope`. */
async function kvValue(scope, label) {
  return scope.locator('dl.kv dt', { hasText: label }).first().locator('xpath=following-sibling::dd[1]').innerText();
}

/** In both themes: contrast, no sideways scroll, a screenshot. */
async function bothThemes(name) {
  const colours = {};
  for (const theme of THEMES) {
    await c.setTheme(theme);
    colours[theme] = await c.bodyColours();
    const low = await c.lowContrast(4.5);
    assert.deepEqual(low, [], `${name}, ${theme} theme: text below 4.5:1 contrast`);
    const overflow = await c.page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    assert.ok(overflow <= 0, `${name}, ${theme} theme: the page scrolls sideways by ${overflow}px`);
    await c.screenshot(E.shots, `${name}-${theme}`);
  }
  assert.notEqual(colours.dark.bg, colours.light.bg, `${name}: the theme toggle did not change the background`);
  assert.notEqual(colours.dark.fg, colours.light.fg, `${name}: the theme toggle did not change the text colour`);
}

test.before(async () => {
  data = populate(E);
  c = await Console.open(E.ui);
});

test.after(async () => {
  if (c) await c.close();
});

test('login screen, then log in with the admin token', async () => {
  await c.page.locator('#admin-token').waitFor();
  assert.equal(await c.page.locator('#nav').isHidden(), true, 'the page nav shows before login');
  await bothThemes('login');
  await c.setTheme('dark');
  await c.login(E.adminToken);
  assert.equal(await c.page.evaluate(() => location.hash), '#/audit');
});

test('audit explorer lists every entry', async () => {
  await c.go('#/audit');
  const head = (await admin('/admin/audit?order=desc&limit=1')).head;
  const rows = c.page.locator('#main table tbody tr');
  await rows.first().waitFor();
  assert.equal(await rows.count(), head, 'one row per entry (the log is under one page)');
  assert.equal(await rows.first().locator('td').first().innerText(), String(head), 'newest first');
  for (const reason of ['policy_allow', 'policy_deny', 'budget_exhausted', 'capability_denied', 'approval_required', 'approval_granted', 'token_issued']) {
    assert.ok(await c.page.locator('#main td span.mono', { hasText: new RegExp(`^${reason}$`) }).count() > 0, `a ${reason} row`);
  }
  assert.match(await c.page.locator('.pager .muted').innerText(), new RegExp(`head ${head}`));
  await bothThemes('audit');
});

test('audit explorer filters by decision through the hash', async () => {
  await c.go('#/audit?decision=deny');
  await c.page.locator('details.panel summary', { hasText: 'Filters (1 active)' }).waitFor();
  const rows = c.page.locator('#main table tbody tr');
  await rows.first().waitFor();
  const want = (await admin('/admin/audit?decision=deny&limit=1000')).entries.length;
  assert.equal(await rows.count(), want);
  const pills = await c.page.locator('#main table tbody tr td:nth-child(4) .pill').allTextContents();
  assert.ok(pills.length > 0 && pills.every((p) => p === 'deny'), `only denials: ${pills}`);
  await bothThemes('audit-filtered');
});

test('decision view of the budget_exhausted denial: verdict and delegation chain', async () => {
  await c.go(`#/record/${data.budgetExhaustedDecision}`);
  const verdict = c.page.locator('.verdict');
  await verdict.waitFor();
  assert.equal(await verdict.locator('.pill').textContent(), 'deny');
  assert.equal(await verdict.locator('.reason').innerText(), 'budget_exhausted');
  assert.match(await verdict.locator('.explain').innerText(), /run limit/);
  const chain = c.page.locator('ol.chain > li');
  assert.equal(await chain.count(), 3, 'user and two hops');
  assert.match(await chain.nth(0).innerText(), /alice/);
  assert.match(await chain.nth(1).innerText(), /hop 0[\s\S]*assistant[\s\S]*active/i);
  assert.match(await chain.nth(2).innerText(), /hop 1[\s\S]*coder[\s\S]*active/i);
  // The timeline of the same chain lists the run's records.
  await c.page.locator('section.panel', { hasText: 'Same chain' }).locator('tbody tr').first().waitFor();
  await bothThemes('decision-denied');
});

test('decision view of the allowed limited call: run-limit panel and token decoder', async () => {
  const page = await admin('/admin/audit?kind=decision&agent=coder&reason=policy_allow&limit=10');
  assert.equal(page.entries.length, 1, 'one allowed coder call');
  const seq = page.entries[0].seq;
  await c.go(`#/entry/${seq}`);
  const panel = c.page.locator('section.panel', { has: c.page.locator('h2', { hasText: 'Run limits and usage' }) });
  await panel.waitFor();
  const cells = await panel.locator('tbody tr').first().locator('td').allInnerTexts();
  // Hop, Capability, Kind, Argument, Used after, Max, Left.
  assert.deepEqual(cells.slice(2), ['distinct', 'repo', '1', '1', '0']);
  assert.match(cells[0], /^hop 1/);

  // The local token decoder: paste the coder's token, decode, read the claims back.
  const notLogged = c.page.locator('section.panel', { hasText: 'Not in the log' });
  await notLogged.locator('summary').click();
  await c.page.locator('#jwt-input').fill(data.coderToken);
  await notLogged.getByRole('button', { name: 'Decode' }).click();
  const decoded = notLogged.locator('ul.tree.top');
  await decoded.nth(1).waitFor();
  const header = await decoded.nth(0).innerText();
  const claims = await decoded.nth(1).innerText();
  assert.match(header, /alg: "EdDSA"/);
  assert.match(claims, /"coder"/);
  assert.match(claims, /distinct/);
  assert.match(claims, /exp: \d+/);
  await bothThemes('decision-allowed');
});

/** `attenuo lease tree` as {nodes: ["id agent state"], wouldRevoke, limits: {id: [lines]}}. */
function cliLeaseTree(id) {
  const { stdout } = cli(E, ['lease', 'tree', id]);
  const nodes = [];
  const limits = {};
  let last = null;
  let wouldRevoke = null;
  let inAncestors = false;
  for (const line of stdout.split('\n')) {
    if (line.startsWith('ancestors')) inAncestors = true;
    const m = line.match(/([0-9a-f-]{36})  (\S+)  (active|revoked|expired)/i);
    if (m) {
      // Ancestors are indented by two spaces; the subtree starts at column 0.
      if (!line.startsWith('  ')) inAncestors = false;
      last = m[1];
      if (!inAncestors) nodes.push(`${m[1]} ${m[2]} ${m[3].toLowerCase()}`);
      continue;
    }
    const l = line.match(/limit (\S+) (\S+) (\S+) (\d+)\/(\d+) \((\d+) left\)/);
    if (l && last) (limits[last] ||= []).push({ target: l[1], kind: l[2], arg: l[3], used: Number(l[4]), max: Number(l[5]), left: Number(l[6]) });
    const w = line.match(/^would revoke (\d+) lease/);
    if (w) wouldRevoke = Number(w[1]);
  }
  return { nodes, wouldRevoke, limits, text: stdout };
}

test('lease tree of the run and its revoke preview match `attenuo lease tree`', async () => {
  await c.go(`#/lease/${data.rootLease}`);
  const subtree = c.page.locator('ul.leases');
  await subtree.waitFor();
  const want = cliLeaseTree(data.rootLease);
  assert.equal(want.nodes.length, 3, `the CLI lists the run, the coder and the tester:\n${want.text}`);

  const nodes = [];
  for (const n of await c.page.locator('.lease-node').all()) {
    const id = (await n.locator('.mono').first().innerText()).trim();
    const agent = await n.locator('strong').first().innerText();
    const state = await n.locator('.pill').first().textContent();
    nodes.push(`${id} ${agent} ${state}`);
  }
  assert.deepEqual(nodes.slice().sort(), want.nodes.slice().sort(), 'the same leases, agents and states');

  const changes = await kvValue(c.page.locator('section.panel').first(), 'A revoke now would change');
  assert.equal(changes, `${want.wouldRevoke} leases`, `console says "${changes}", CLI: would revoke ${want.wouldRevoke}`);

  // The coder's node summarises its limit the way the CLI's limit line does.
  const coderNode = c.page.locator('.lease-node', { hasText: data.coderLease });
  const [lim] = want.limits[data.coderLease];
  assert.match(await coderNode.innerText(), new RegExp(`${lim.kind} ${lim.arg} ${lim.used}/${lim.max}`));

  // The revoke dialog's preview: the same count and the agents of the active leases.
  await c.page.getByRole('button', { name: 'Revoke…' }).click();
  const dialog = c.page.locator('dialog[open]');
  await dialog.waitFor();
  assert.equal(await kvValue(dialog, 'Leases that change'), String(want.wouldRevoke));
  const activeAgents = want.nodes.filter((n) => n.endsWith(' active')).map((n) => n.split(' ')[1]);
  assert.equal(await kvValue(dialog, 'Active agents affected'), activeAgents.join(', '));
  assert.equal(await dialog.getByRole('button', { name: 'Revoke', exact: true }).isDisabled(), true, 'Revoke is disabled until the id tail and a reason are typed');
  await bothThemes('lease-revoke-preview');
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  assert.equal(await c.page.locator('dialog').count(), 0, 'Cancel removes the dialog');
  await bothThemes('lease-tree');
});

test('leaving the page closes an open revoke dialog', async () => {
  await c.go(`#/lease/${data.rootLease}`);
  await c.page.locator('ul.leases').waitFor();
  await c.page.getByRole('button', { name: 'Revoke…' }).click();
  await c.page.locator('dialog[open]').waitFor();
  // Back, a typed URL or the idle lock change the page under a modal dialog. The dialog must
  // not outlive its page: its Revoke would still act on the lease of the page it came from.
  await c.go('#/audit');
  await c.page.locator('#main table tbody tr').first().waitFor();
  assert.equal(await c.page.locator('dialog').count(), 0, 'the revoke dialog stayed open over the audit page');
});

test('lease page of the coder: run limits match `attenuo lease tree`', async () => {
  await c.go(`#/lease/${data.coderLease}`);
  const panel = c.page.locator('section.panel', { has: c.page.locator('h2', { hasText: 'Run limits' }) });
  await panel.waitFor();
  const want = cliLeaseTree(data.coderLease);
  const [lim] = want.limits[data.coderLease];
  const row = panel.locator('tbody tr', { hasText: lim.kind }).first();
  const cells = await row.locator('td').allInnerTexts();
  // Hop, Capability, Kind, Argument, Used, Max, Left.
  assert.match(cells[1], new RegExp(lim.target.replace('/', ' / ')));
  assert.deepEqual(cells.slice(2), [lim.kind, lim.arg, String(lim.used), String(lim.max), String(lim.left)]);
  assert.match(await c.page.locator('.path').innerText(), /Delegated from[\s\S]*\(assistant\)/);
  await bothThemes('lease-coder');
});

test('approvals: the list, a consumed approval, and granting the pending one', async () => {
  await c.go('#/approvals');
  const rows = c.page.locator('#main table tbody tr');
  await rows.first().waitFor();
  assert.equal(await rows.count(), 2);
  const states = (await c.page.locator('#main table tbody td:nth-child(2) .pill').allTextContents()).sort();
  assert.deepEqual(states, ['consumed', 'pending']);
  await bothThemes('approvals');

  await c.go(`#/approval/${data.consumedApproval}`);
  const title = c.page.locator('#approval-title');
  await title.waitFor();
  assert.equal(await c.page.locator('section.panel .row .pill').first().textContent(), 'consumed');
  assert.match(await kvValue(c.page.locator('section.panel').first(), 'Used by'), /^[0-9a-f-]{36}$/);
  assert.match(await kvValue(c.page.locator('section.panel').first(), 'Decided'), /operator/);
  assert.match(await c.page.locator('ul.tree.top').innerText(), /title: "README: fix typo"/);
  await bothThemes('approval-consumed');

  await c.go(`#/approval/${data.pendingApproval}`);
  await c.page.locator('#approval-title').waitFor();
  assert.equal(await c.page.locator('section.panel .row .pill').first().textContent(), 'pending');
  await bothThemes('approval-pending');
  await c.page.getByRole('button', { name: 'Grant' }).click();
  await c.page.locator('section.panel .row .pill', { hasText: /^granted$/ }).waitFor();
  assert.match(await c.page.locator('#status').innerText(), /Granted/);
  const shown = cliJson(E, ['approval', 'show', data.pendingApproval]).json;
  assert.equal(shown.state, 'granted', 'the CLI sees the grant made in the browser');
  assert.equal(await c.page.getByRole('button', { name: 'Grant' }).count(), 0, 'no Grant button on a decided approval');
  await bothThemes('approval-granted');
});

test('policy page: loaded set, file check and a dry-run evaluation', async () => {
  await c.go('#/policy');
  const items = c.page.locator('.policy-item h3');
  await items.first().waitFor();
  const ids = (await items.allInnerTexts()).sort();
  const loaded = (await admin('/admin/policies')).policies.map((p) => p.id).sort();
  assert.deepEqual(ids, loaded);
  assert.ok(ids.includes('read_file_public_repos_only'));

  await c.page.getByRole('button', { name: 'Check file on disk' }).click();
  const check = c.page.locator('section.panel', { has: c.page.locator('h2', { hasText: 'Check and reload' }) });
  await check.locator('.pill.big').waitFor();
  assert.equal(await check.locator('.pill.big').textContent(), 'ok');
  assert.match(await check.innerText(), /0 errors/);
  assert.match(await check.innerText(), /same as loaded/i);
  assert.equal(await c.page.getByRole('button', { name: 'Reload' }).isEnabled(), true);

  // Dry runs read the run-limit counters without charging them. The coder's one repo is
  // used up, so a second repo is over the limit, while the repo it already read still passes.
  const evalPanel = c.page.locator('section.panel', { has: c.page.locator('h2', { hasText: 'Evaluate this call' }) });
  const evaluate = async (token, repo) => {
    await c.page.locator('#ev-token').fill(token);
    await c.page.locator('#ev-server').fill('github');
    await c.page.locator('#ev-tool').fill('read_file');
    await c.page.locator('#ev-args').fill(JSON.stringify({ repo, path: 'README.md' }));
    const previous = await evalPanel.locator('.verdict').elementHandle({ timeout: 1 }).catch(() => null);
    await c.page.getByRole('button', { name: 'Evaluate' }).click();
    // Wait for this answer, not the previous one still on screen.
    if (previous) await previous.waitForElementState('hidden');
    await evalPanel.locator('.verdict .reason').waitFor();
    return [await evalPanel.locator('.verdict .pill').textContent(), await evalPanel.locator('.verdict .reason').innerText()];
  };
  assert.deepEqual(await evaluate(data.coderToken, 'alice/public-site'), ['deny', 'budget_exhausted']);
  assert.deepEqual(await evaluate(data.coderToken, 'alice/public-docs'), ['allow', 'policy_allow']);
  assert.deepEqual(await evaluate(data.rootToken, 'alice/private-salaries'), ['deny', 'policy_deny']);
  await bothThemes('policy');
});

test('verify panel: chain ok, then sign a checkpoint of the head', async () => {
  await c.go('#/verify');
  const head = (await admin('/admin/audit?order=desc&limit=1')).head;
  const headPanel = c.page.locator('section.panel', { has: c.page.locator('h2', { hasText: 'Log head' }) });
  await headPanel.locator('dl.kv').waitFor();
  assert.equal(await kvValue(headPanel, 'Head seq'), String(head));

  await c.page.getByRole('button', { name: 'Verify now' }).click();
  const out = c.page.locator('section.panel', { has: c.page.locator('h2', { hasText: 'Verification' }) });
  await out.locator('.pill.big').waitFor();
  assert.equal(await out.locator('.pill.big').textContent(), 'chain ok');
  assert.equal(await kvValue(out, 'Entries'), String(head));
  assert.equal(await kvValue(out, 'First bad seq'), 'none');

  await c.page.getByRole('button', { name: 'Sign head now…' }).click();
  await c.page.locator('dialog[open]').getByRole('button', { name: 'Sign checkpoint' }).click();
  const cps = c.page.locator('section.panel', { has: c.page.locator('h2', { hasText: 'Newest checkpoints' }) });
  await cps.locator('tbody tr').first().waitFor();
  assert.match(await c.page.locator('#status').innerText(), /Checkpoint at seq \d+ signed/);
  assert.equal(await kvValue(headPanel, 'Unsigned entries'), '0');
  // Regression: the page used to probe /readyz, which the console listener never serves, so
  // every visit logged a 404 console error. It now says where readiness lives instead.
  assert.match(await headPanel.innerText(), /Readiness \(\/readyz\) is served on the main listener/);
  assert.ok(!c.requests.includes('GET /readyz'), 'the Verify page requested /readyz');
  await bothThemes('verify');
});

test('an unknown route shows Not found', async () => {
  await c.go('#/nothing-here');
  await c.page.locator('h1', { hasText: 'Not found' }).waitFor();
  await bothThemes('not-found');
});

test('a system light preference starts the console in the light theme', async () => {
  const light = await Console.open(E.ui, { colorScheme: 'light' });
  try {
    await light.page.locator('#admin-token').waitFor();
    assert.equal(await light.theme(), 'light');
    assert.equal(await light.page.locator('#theme-toggle').innerText(), 'Dark theme');
    await light.login(E.adminToken);
    await light.page.locator('#main table tbody tr').first().waitFor();
    assert.deepEqual(await light.lowContrast(4.5), []);
    await light.setTheme('dark');
    assert.deepEqual(await light.lowContrast(4.5), []);
    assert.deepEqual(await light.allProblems(), []);
  } finally {
    await light.close();
  }
});

test('the CSP violation recorder works (a deliberate inline style is reported)', async () => {
  const probe = await Console.open(E.ui);
  try {
    await probe.page.locator('#admin-token').waitFor();
    await probe.page.evaluate(() => {
      const s = document.createElement('style');
      s.textContent = 'body { outline: 1px solid red; }';
      document.head.append(s);
    });
    await probe.page.waitForFunction(() => window.__cspViolations.length > 0);
    const [v] = await probe.cspViolations();
    assert.match(v.directive, /^style-src/);
  } finally {
    await probe.close();
  }
});

test('no console error, page error, failed request or CSP violation in the whole run', async () => {
  assert.deepEqual(await c.allProblems(), []);
});
