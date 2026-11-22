// Browser smoke test of the embedded admin console. Run it with scripts/console-smoke.sh,
// which builds and starts the server and passes its addresses in CONSOLE_SMOKE_* variables.
//
// One headless Chromium page logs in once and visits every console page. On each page the
// test waits for the data, checks the elements that carry it, then, in the dark and the light
// theme, checks text contrast and that nothing scrolls sideways, and takes a screenshot. At the
// end it asserts that the whole run produced no console error or warning, no page error, no
// failed or 4xx/5xx request and no CSP violation.
'use strict';

const fs = require('node:fs');
const nodePath = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const { env, operatorEnv, cli, cliJson, populate, populateReadOnly } = require('./lib/populate.cjs');
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

/** In both themes: contrast, no sideways scroll, a screenshot. `on` is the main page unless
 * given. */
async function bothThemes(name, on = c) {
  const colours = {};
  for (const theme of THEMES) {
    await on.setTheme(theme);
    colours[theme] = await on.bodyColours();
    const low = await on.lowContrast(4.5);
    assert.deepEqual(low, [], `${name}, ${theme} theme: text below 4.5:1 contrast`);
    const overflow = await on.page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    assert.ok(overflow <= 0, `${name}, ${theme} theme: the page scrolls sideways by ${overflow}px`);
    await on.screenshot(E.shots, `${name}-${theme}`);
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

test('the favicon link resolves to the embedded SVG and loads under the CSP', async () => {
  const icon = await c.page.evaluate(async () => {
    const link = document.querySelector('link[rel="icon"]');
    if (!link) return null;
    const resp = await fetch(link.href);
    const text = await resp.text();
    // As an image, so img-src 'self' is exercised the way a browser tab icon would be.
    const img = new Image();
    const loaded = await new Promise((resolve) => {
      img.onload = () => resolve(true);
      img.onerror = () => resolve(false);
      img.src = link.href;
    });
    return {
      attr: link.getAttribute('href'),
      type: link.type,
      path: new URL(link.href).pathname,
      status: resp.status,
      contentType: resp.headers.get('content-type'),
      isSvg: text.startsWith('<svg'),
      loaded,
      width: img.naturalWidth,
    };
  });
  assert.ok(icon, 'no <link rel="icon"> in the console page');
  assert.deepEqual(icon, {
    attr: 'favicon.svg',
    type: 'image/svg+xml',
    path: '/admin/ui/favicon.svg',
    status: 200,
    contentType: 'image/svg+xml',
    isSvg: true,
    loaded: true,
    width: 64,
  });
  const root = await fetch(`${E.ui}/favicon.svg`);
  assert.equal(root.status, 200);
  assert.equal(root.headers.get('content-type'), 'image/svg+xml');
  assert.deepEqual(await c.cspViolations(), [], 'the favicon caused a CSP violation');
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
  assert.equal(await c.page.locator('#audit-pruned').count(), 0, 'a log never pruned shows no pruned line');
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

test('audit explorer: a search record shows a dash, an approval record its pill', async () => {
  // An AuthZEN action search decides nothing and writes one `search` record with `allow`.
  const resp = await fetch(`${E.server}/access/v1/search/action`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${data.rootToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject: { type: 'agent', id: '' }, resource: { type: 'mcp_server', id: 'github' } }),
  });
  assert.equal(resp.status, 200, await resp.text());
  const cell = (kind) => c.page.locator('#main table tbody tr', { has: c.page.locator('td:nth-child(3) .tag', { hasText: new RegExp(`^${kind}$`) }) })
    .first().locator('td:nth-child(4)');

  await c.go('#/audit?kind=search');
  await cell('search').waitFor();
  assert.equal(await cell('search').locator('.pill').count(), 0, 'a search record has no decision pill');
  assert.equal((await cell('search').innerText()).trim(), '—');

  // The request refused the call until approved, so it is a deny and stays a pill.
  await c.go('#/audit?kind=approval_request');
  await cell('approval_request').waitFor();
  assert.equal(await cell('approval_request').locator('.pill').textContent(), 'deny');
  await c.go('#/audit?kind=approval_grant');
  await cell('approval_grant').waitFor();
  assert.equal(await cell('approval_grant').locator('.pill').textContent(), 'allow');
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

test('lease page of the run: user windows match `attenuo lease tree`', async () => {
  await c.go(`#/lease/${data.rootLease}`);
  const panel = c.page.locator('section.panel', { has: c.page.locator('h2', { hasText: 'User windows' }) });
  await panel.waitFor();
  const { stdout } = cli(E, ['lease', 'tree', data.rootLease]);
  const want = [...stdout.matchAll(/window (\S+) (\S+) (\S+): (\d+) calls, amount (\d+)/g)]
    .map((m) => [m[3], m[1], m[2], m[4], m[5]]);
  // The approved create_issue of alice's run was charged to her day window.
  assert.ok(want.some((w) => w[0] === 'github/create_issue' && w[1] === 'day' && Number(w[3]) >= 1),
    `the CLI shows alice's day window of create_issue:\n${stdout}`);
  const got = [];
  for (const row of await panel.locator('tbody tr').all()) got.push(await row.locator('td').allInnerTexts());
  // Tool, Window, Start (UTC), Calls, Amount: the same lines as the CLI's.
  assert.deepEqual(got, want);
  await bothThemes('lease-user-windows');
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

/** GET /admin/leases/{id}: is it revoked, and why. */
async function leaseRow(id) {
  return admin(`/admin/leases/${encodeURIComponent(id)}`);
}

/** The audit record page of `auditId` (from the dialog's link) shows the revocation. */
async function auditRecordShown(dialog, auditId) {
  await dialog.getByRole('link', { name: auditId }).click();
  await c.page.waitForFunction((id) => location.hash === `#/record/${id}`, auditId);
  await c.page.locator('.verdict').waitFor();
  assert.equal(await c.page.locator('dialog').count(), 0, 'the dialog outlived the page change');
  assert.match(await c.page.locator('#main').innerText(), /admin\.lease\.revoke/);
  const rec = await admin(`/admin/audit/records/${auditId}`);
  assert.equal(rec.entry.record.tool, 'admin.lease.revoke');
  assert.equal(rec.entry.record.kind, 'lease_revoke');
  return rec;
}

test('lease page: revoke the whole chain through the preview dialog', async () => {
  const chainId = data.carolRootLease;
  await c.go(`#/lease/${data.carolChildLease}`);
  await c.page.locator('ul.leases').waitFor();
  assert.equal(await kvValue(c.page.locator('section.panel').first(), 'Originating user'), 'carol');
  const want = cliJson(E, ['lease', 'revoke', '--chain-id', chainId, '--preview']).json;
  assert.equal(want.revoked_count, 2, 'the CLI previews carol\'s root and coder hop');

  await c.page.getByRole('button', { name: 'Revoke chain…' }).click();
  const dialog = c.page.locator('dialog[open]');
  await dialog.locator('#selector-reason').waitFor();
  // Focus lands on the reason once the preview is in.
  assert.equal(await c.page.evaluate(() => document.activeElement.id), 'selector-reason');
  assert.match(await kvValue(dialog, 'Selector'), new RegExp(`chain_id\\s+${chainId}`));
  assert.equal(await kvValue(dialog, 'Leases matched'), String(want.matched_count));
  assert.equal(await kvValue(dialog, 'Leases that change'), String(want.revoked_count));
  const listed = (await dialog.locator('ul.idlist').last().locator('li').allInnerTexts()).map((t) => t.trim());
  assert.deepEqual(listed, want.revoked, 'the preview lists what the CLI lists');
  assert.equal(await dialog.locator('#selector-reason').inputValue(), 'revoked by admin');
  const go = dialog.getByRole('button', { name: 'Revoke', exact: true });
  assert.equal(await go.isDisabled(), true, 'Revoke is disabled until the chain id tail is typed');
  await bothThemes('lease-revoke-chain-preview');

  await dialog.locator('#selector-reason').fill('smoke test: carol chain');
  await dialog.locator('#selector-confirm').fill('wrong');
  assert.equal(await go.isDisabled(), true);
  await dialog.locator('#selector-confirm').fill(chainId.slice(-6));
  await go.click();
  const close = dialog.locator('#selector-close');
  await close.waitFor();
  assert.equal(await c.page.evaluate(() => document.activeElement.id), 'selector-close');
  assert.equal(await kvValue(dialog, 'Leases revoked'), '2');
  const auditId = (await kvValue(dialog, 'Audit record')).trim();
  assert.match(auditId, /^[0-9a-f-]{36}$/);
  assert.match(await c.page.locator('#status').innerText(), /Revoked 2 leases \(the preview said 2\)/);
  await bothThemes('lease-revoke-chain-done');

  // The page behind the dialog reloaded: this lease's node is revoked, with the reason.
  const node = c.page.locator('.lease-node.focus');
  await node.locator('.pill', { hasText: /^revoked$/ }).waitFor();
  assert.match(await node.innerText(), /smoke test: carol chain/);
  for (const id of [data.carolRootLease, data.carolChildLease]) {
    const row = await leaseRow(id);
    assert.equal(row.active, false, `${id} is still active`);
    assert.equal(row.revoke_reason, 'smoke test: carol chain');
  }
  assert.equal((await leaseRow(data.rootLease)).active, true, 'alice\'s run was touched');

  const rec = await auditRecordShown(dialog, auditId);
  assert.deepEqual(rec.entry.record.leases.slice().sort(), [data.carolRootLease, data.carolChildLease].sort());
  // Back on the lease page, the root is revoked too and a second preview finds nothing.
  await c.go(`#/lease/${data.carolRootLease}`);
  await c.page.locator('.lease-node.focus .pill', { hasText: /^revoked$/ }).waitFor();
  assert.equal(await c.page.locator('.lease-node .pill', { hasText: /^active$/ }).count(), 0);
});

test('lease page: revoke every lease of the originating user', async () => {
  const [bobRoot, bobChild, bobSecond] = data.bobLeases;
  await c.go(`#/lease/${bobRoot}`);
  await c.page.locator('ul.leases').waitFor();
  const want = cliJson(E, ['lease', 'revoke', '--user', 'bob', '--preview']).json;
  assert.deepEqual(want.matched.slice().sort(), data.bobLeases.slice().sort());

  await c.page.getByRole('button', { name: 'Revoke all for bob…' }).click();
  const dialog = c.page.locator('dialog[open]');
  await dialog.locator('#selector-reason').waitFor();
  assert.match(await kvValue(dialog, 'Selector'), /user\s+bob/);
  assert.equal(await kvValue(dialog, 'Leases matched'), '3');
  assert.equal(await kvValue(dialog, 'Leases that change'), '3');
  const matched = (await dialog.locator('ul.idlist').first().locator('li').allInnerTexts()).map((t) => t.trim());
  assert.deepEqual(matched, want.matched);
  await bothThemes('lease-revoke-user-preview');

  const go = dialog.getByRole('button', { name: 'Revoke', exact: true });
  await dialog.locator('#selector-confirm').fill('2');
  assert.equal(await go.isDisabled(), true, 'the confirmation is the number of leases that change');
  await dialog.locator('#selector-confirm').fill('3');
  await go.click();
  await dialog.locator('#selector-close').waitFor();
  assert.equal(await kvValue(dialog, 'Leases revoked'), '3');
  assert.equal(await kvValue(dialog, 'Reason'), 'revoked by admin');
  const auditId = (await kvValue(dialog, 'Audit record')).trim();
  await c.page.locator('.lease-node.focus .pill', { hasText: /^revoked$/ }).waitFor();
  for (const id of [bobRoot, bobChild, bobSecond]) {
    assert.equal((await leaseRow(id)).active, false, `${id} is still active`);
  }
  assert.equal((await leaseRow(data.coderLease)).active, true, 'alice\'s coder was touched');
  await auditRecordShown(dialog, auditId);
});

test('selector dialog: Escape and leaving the page close it', async () => {
  // The run's root: a preview only, nothing is revoked.
  await c.go(`#/lease/${data.rootLease}`);
  await c.page.locator('ul.leases').waitFor();
  assert.equal(await c.page.getByRole('button', { name: 'Revoke all for alice…' }).count(), 1);
  await c.page.getByRole('button', { name: 'Revoke chain…' }).click();
  await c.page.locator('dialog[open] #selector-reason').waitFor();
  await c.page.keyboard.press('Escape');
  await c.page.waitForFunction(() => document.querySelectorAll('dialog').length === 0);

  await c.page.getByRole('button', { name: 'Revoke all for alice…' }).click();
  await c.page.locator('dialog[open] #selector-reason').waitFor();
  await c.go('#/audit');
  await c.page.locator('#main table tbody tr').first().waitFor();
  assert.equal(await c.page.locator('dialog').count(), 0, 'the selector dialog stayed open over the audit page');
  assert.equal((await leaseRow(data.rootLease)).active, true, 'a preview revoked something');
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
  assert.equal(await c.page.getByRole('button', { name: 'Reload…', exact: true }).isEnabled(), true);

  // Dry runs read the run-limit counters without charging them. The coder's one repo is
  // used up, so a second repo is over the limit, while the repo it already read still passes.
  const evalPanel = c.page.locator('section.panel', { has: c.page.locator('h2', { hasText: 'Evaluate this call' }) });
  const evaluate = async (token, repo, tool = 'read_file', args = { repo, path: 'README.md' }) => {
    await c.page.locator('#ev-token').fill(token);
    await c.page.locator('#ev-server').fill('github');
    await c.page.locator('#ev-tool').fill(tool);
    await c.page.locator('#ev-args').fill(JSON.stringify(args));
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
  const budgetBox = evalPanel.locator('.budget-result');
  assert.match(await budgetBox.locator('h3 .pill').textContent(), /^read from the store$/);
  assert.equal(await kvValue(budgetBox, 'Limited'), 'no (no limit of the chain matches the call)');
  assert.equal(await kvValue(budgetBox, 'Calls remaining'), 'no limit');

  // A stated budget instead of the store. The store holds public-docs as the coder's one repo
  // (allowed above); stated counters that say the limit has seen one value, and not this one,
  // refuse it, with the limit hit in the budget block.
  await evalPanel.locator('details.budget-form summary').click();
  await c.page.locator('#ev-budget-limits').fill(JSON.stringify([{ hop: 1, kind: 'distinct', arg: 'repo', used: 1 }]));
  assert.deepEqual(await evaluate(data.coderToken, 'alice/public-docs'), ['deny', 'budget_exhausted']);
  assert.match(await budgetBox.locator('h3 .pill').textContent(), /^stated in the request$/);
  assert.equal(await kvValue(budgetBox, 'Limited'), 'yes');
  assert.equal(await kvValue(budgetBox, 'Destination new'), 'yes');
  assert.deepEqual(await budgetBox.locator('tbody tr td').allInnerTexts(), ['1', 'distinct', 'repo', '1', '1']);
  // The same counters with the value already counted: public-site, over the limit in the
  // store, passes, and nothing is exceeded.
  await c.page.locator('#ev-budget-dest').selectOption('false');
  assert.deepEqual(await evaluate(data.coderToken, 'alice/public-site'), ['allow', 'policy_allow']);
  assert.equal(await kvValue(budgetBox, 'Destination new'), 'no');
  assert.match(await budgetBox.innerText(), /No limit would be exceeded/);
  // Input the form can tell is wrong never reaches the server.
  await c.page.locator('#ev-budget-calls').fill('-1');
  await c.page.getByRole('button', { name: 'Evaluate' }).click();
  await evalPanel.locator('.callout.bad', { hasText: 'Calls remaining must be a whole number' }).waitFor();
  await c.page.locator('#ev-budget-calls').fill('');
  assert.deepEqual(await evaluate(data.coderToken, 'alice/public-site'), ['allow', 'policy_allow']);

  // Stated run labels instead of the store. Bob's second root never called a tool, so the
  // store holds no taint for its run, and the smoke policy (scripts/console-smoke.sh) allows
  // the destructive add_label outright; a stated taint makes the same call ask for approval.
  await c.page.locator('#ev-budget-limits').fill('');
  await c.page.locator('#ev-budget-dest').selectOption('');
  const labelsBox = evalPanel.locator('.labels-result');
  const usageBox = evalPanel.locator('.usage-result');
  const addLabel = (token) => evaluate(token, null, 'add_label', { repo: 'bob/public-site', label: 'bug' });
  assert.deepEqual(await addLabel(data.bobSecondToken), ['allow', 'policy_allow']);
  assert.equal(await labelsBox.locator('h3 .pill').textContent(), 'read from the store');
  assert.equal(await kvValue(labelsBox, 'Tainted'), 'no');
  await evalPanel.locator('details.session-form summary').click();
  await c.page.locator('#ev-session-tainted-by').fill('github/read_file');
  assert.deepEqual(await addLabel(data.bobSecondToken), ['deny', 'approval_required']);
  assert.equal(await labelsBox.locator('h3 .pill').textContent(), 'stated in the request');
  assert.equal(await kvValue(labelsBox, 'Tainted'), 'yes');
  assert.equal(await kvValue(labelsBox, 'Tainted by'), 'github/read_file');
  // Stated usage is shown as stated; it does not change this decision.
  await evalPanel.locator('details.usage-form summary').click();
  await c.page.locator('#ev-usage-calls').fill('2');
  assert.deepEqual(await addLabel(data.bobSecondToken), ['deny', 'approval_required']);
  assert.equal(await usageBox.locator('h3 .pill').textContent(), 'stated in the request');
  assert.equal(await kvValue(usageBox, 'Calls'), '2');
  await c.page.locator('#ev-usage-calls').fill('x');
  await c.page.getByRole('button', { name: 'Evaluate' }).click();
  await evalPanel.locator('.callout.bad', { hasText: 'Calls so far must be a whole number' }).waitFor();
  await c.page.locator('#ev-usage-calls').fill('2');
  // Shown in both themes with the forms open and a stated answer on screen.
  assert.deepEqual(await addLabel(data.bobSecondToken), ['deny', 'approval_required']);
  await bothThemes('policy');
});

test('policy page: a dry run with a stated approval', async () => {
  // A fresh form: leave the page and come back, so nothing stated by the test above is left.
  // Wait for the other page's data, so no request is cut off.
  await c.go('#/approvals');
  await c.page.locator('#main table tbody tr').first().waitFor();
  await c.go('#/policy');
  await c.page.locator('.policy-item h3').first().waitFor();
  const evalPanel = c.page.locator('section.panel', { has: c.page.locator('h2', { hasText: 'Evaluate this call' }) });
  await evalPanel.waitFor();
  assert.equal(await c.page.locator('#ev-session-tainted-by').inputValue(), '');
  const approvalBox = evalPanel.locator('.approval-result');
  const sent = [];
  const record = (req) => {
    if (req.url().endsWith('/admin/policies/evaluate')) sent.push(req.postDataJSON());
  };
  c.page.on('request', record);
  const addLabel = async () => {
    await c.page.locator('#ev-token').fill(data.bobSecondToken);
    await c.page.locator('#ev-server').fill('github');
    await c.page.locator('#ev-tool').fill('add_label');
    await c.page.locator('#ev-args').fill(JSON.stringify({ repo: 'bob/public-site', label: 'bug' }));
    const previous = await evalPanel.locator('.verdict').elementHandle({ timeout: 1 }).catch(() => null);
    await c.page.getByRole('button', { name: 'Evaluate' }).click();
    if (previous) await previous.waitForElementState('hidden');
    await evalPanel.locator('.verdict .reason').waitFor();
    return [await evalPanel.locator('.verdict .pill').textContent(), await evalPanel.locator('.verdict .reason').innerText()];
  };
  try {
    // On a stated tainted run the smoke policy asks before add_label unless the call carries
    // an approval (`!context.approval.present`, scripts/console-smoke.sh).
    await evalPanel.locator('details.session-form summary').click();
    await c.page.locator('#ev-session-tainted-by').fill('github/read_file');
    assert.deepEqual(await addLabel(), ['deny', 'approval_required']);
    assert.equal(await approvalBox.locator('h3 .pill').textContent(), 'none stated');
    assert.equal(await kvValue(approvalBox, 'Granted'), 'no (the call is decided as a first attempt)');
    assert.equal(sent.at(-1).approval, undefined, 'no approval block without a stated approval');

    await evalPanel.locator('details.approval-form summary').click();
    await c.page.locator('#ev-approval-by').selectOption('operator');
    assert.deepEqual(await addLabel(), ['allow', 'policy_allow']);
    assert.deepEqual(sent.at(-1).approval, { by: 'operator' });
    assert.equal(await approvalBox.locator('h3 .pill').textContent(), 'stated in the request');
    assert.equal(await kvValue(approvalBox, 'Granted'), 'yes');
    assert.equal(await kvValue(approvalBox, 'By'), 'operator');
    assert.deepEqual(
      (await c.page.locator('#ev-approval-by option').allInnerTexts()),
      ['not stated (no approval)', 'user', 'operator', 'policy'],
    );
    await bothThemes('policy-approval');

    // Back to not stated: nothing is sent and the call asks again.
    await c.page.locator('#ev-approval-by').selectOption('');
    assert.deepEqual(await addLabel(), ['deny', 'approval_required']);
    assert.equal(sent.at(-1).approval, undefined);
  } finally {
    c.page.off('request', record);
  }
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
  assert.equal(await kvValue(out, 'Pruned through'), 'not pruned');
  assert.equal(await kvValue(out, 'Anchors'), '0');
  assert.equal(await kvValue(out, 'Bad anchors'), 'none');
  assert.match(await kvValue(headPanel, 'First retained seq'), /^1 not pruned$/);

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
  // This server does not prune (`prune = "off"`): no automatic prune section, and the page
  // never asks for the prune plan, which would answer 409.
  assert.equal(await c.page.locator('#auto-prune').count(), 0, 'an automatic prune section on a server that does not prune');
  assert.ok(!c.requests.some((r) => r.includes('/admin/audit/prune')), 'the Verify page asked for the prune plan');
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

/** Neither the page nor its URL holds `secret`. */
async function notShown(page, secret, where) {
  const { html, url } = await page.evaluate(() => ({ html: document.documentElement.outerHTML, url: location.href }));
  assert.ok(!html.includes(secret), `${where}: the raw session id is in the DOM`);
  assert.ok(!url.includes(secret), `${where}: the raw session id is in the URL`);
}

/** Open "Revoke by session…" on the current lease page, type `id` and preview it. */
async function previewSession(page, id) {
  await page.getByRole('button', { name: 'Revoke by session…' }).click();
  const dialog = page.locator('dialog[open]');
  await dialog.locator('#session-id').waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.id), 'session-id');
  const preview = dialog.getByRole('button', { name: 'Preview' });
  assert.equal(await preview.isDisabled(), true, 'Preview is disabled until an id is typed');
  await dialog.locator('#session-id').fill(id);
  await preview.click();
  await dialog.locator('#selector-reason').waitFor();
  return dialog;
}

// Runs last among the lease tests: the session the fake upstream assigned is bound to alice's
// run, which this revokes.
test('lease page: revoke by session, previewing an unknown id first', async () => {
  await c.go(`#/lease/${data.rootLease}`);
  await c.page.locator('ul.leases').waitFor();

  // An id the server never recorded: no chains, nothing to revoke, and the id is not shown.
  const unknown = 'smoke-unknown-session-id';
  const dialog = await previewSession(c.page, unknown);
  await dialog.locator('#selector-again').waitFor();
  assert.equal(await c.page.evaluate(() => document.activeElement.id), 'selector-again');
  assert.match(await dialog.locator('.callout:not(.bad)').innerText(), /No chains are recorded for this session id/);
  assert.equal(await kvValue(dialog, 'Chains'), 'none');
  assert.equal(await kvValue(dialog, 'Leases matched'), '0');
  assert.equal(await dialog.getByRole('button', { name: 'Revoke', exact: true }).isDisabled(), true);
  await notShown(c.page, unknown, 'unknown session preview');
  await bothThemes('lease-revoke-session-none');

  // The session alice's coder opened: the same tag, chains and counts as the CLI's preview.
  const want = cliJson(E, ['lease', 'revoke', '--session', data.session, '--preview']).json;
  assert.deepEqual(want.selector.chain_ids, [data.rootLease], 'the fake upstream\'s session is bound to alice\'s run');
  await dialog.getByRole('button', { name: 'Another session id' }).click();
  await dialog.locator('#session-id').fill(data.session);
  await dialog.getByRole('button', { name: 'Preview' }).click();
  await dialog.locator('#selector-reason').waitFor();
  assert.match(await kvValue(dialog, 'Selector'), new RegExp(`session\\s+${want.selector.session_tag}`));
  const chains = (await dialog.locator('ul.idlist').first().locator('li').allInnerTexts()).map((t) => t.trim());
  assert.deepEqual(chains, want.selector.chain_ids);
  assert.equal(await kvValue(dialog, 'Leases matched'), String(want.matched_count));
  assert.equal(await kvValue(dialog, 'Leases that change'), String(want.revoked_count));
  assert.ok(want.revoked_count >= 2, 'alice\'s root and coder are live');
  await notShown(c.page, data.session, 'session preview');
  await bothThemes('lease-revoke-session-preview');

  const go = dialog.getByRole('button', { name: 'Revoke', exact: true });
  await dialog.locator('#selector-reason').fill('smoke test: session hijacked');
  await dialog.locator('#selector-confirm').fill(String(want.revoked_count + 1));
  assert.equal(await go.isDisabled(), true, 'the confirmation is the number of leases that change');
  await dialog.locator('#selector-confirm').fill(String(want.revoked_count));
  await go.click();
  await dialog.locator('#selector-close').waitFor();
  assert.equal(await kvValue(dialog, 'Leases revoked'), String(want.revoked_count));
  assert.match(await kvValue(dialog, 'Selector'), new RegExp(`session\\s+${want.selector.session_tag}`));
  const auditId = (await kvValue(dialog, 'Audit record')).trim();
  await notShown(c.page, data.session, 'session result');
  await c.page.locator('.lease-node.focus .pill', { hasText: /^revoked$/ }).waitFor();
  for (const id of [data.rootLease, data.coderLease]) {
    const row = await leaseRow(id);
    assert.equal(row.active, false, `${id} is still active`);
    assert.equal(row.revoke_reason, 'smoke test: session hijacked');
  }
  const rec = await auditRecordShown(dialog, auditId);
  assert.ok(!JSON.stringify(rec).includes(data.session), 'the audit record holds the raw session id');
  await notShown(c.page, data.session, 'audit record page');
});

test('revoke by session on a console without allow_write: preview yes, revoke refused', async () => {
  const ro = populateReadOnly(E);
  const roAdmin = async (path) => {
    const resp = await fetch(`${E.roUi}${path}`, { headers: { Authorization: `Bearer ${E.adminToken}`, Accept: 'application/json' } });
    assert.equal(resp.status, 200, `GET ${path}`);
    return resp.json();
  };
  const probe = await Console.open(E.roUi);
  try {
    await probe.login(E.adminToken);
    await probe.go(`#/lease/${ro.lease}`);
    await probe.page.locator('ul.leases').waitFor();
    const dialog = await previewSession(probe.page, ro.session);
    assert.deepEqual((await dialog.locator('ul.idlist').first().locator('li').allInnerTexts()).map((t) => t.trim()), [ro.lease]);
    const count = await kvValue(dialog, 'Leases that change');
    assert.equal(count, '1');
    await dialog.locator('#selector-confirm').fill(count);
    await dialog.getByRole('button', { name: 'Revoke', exact: true }).click();
    const err = dialog.locator('.callout.bad');
    await err.waitFor();
    assert.match(await err.innerText(), /Writes are disabled on this listener/);
    await notShown(probe.page, ro.session, 'refused revoke');
    assert.equal((await roAdmin(`/admin/leases/${encodeURIComponent(ro.lease)}`)).active, true, 'the lease was revoked');
    // The only problem is the refused revocation itself (the 404, and Chromium's console line
    // about it).
    const problems = await probe.allProblems();
    assert.ok(problems.some((p) => /^HTTP 404: POST .*\/admin\/leases\/revoke$/.test(p)), problems.join('\n'));
    assert.deepEqual(problems.filter((p) => !/\b404\b/.test(p)), []);
  } finally {
    await probe.close();
  }
});

test('audit explorer pages back and forward through the cursor without gaps', async () => {
  // Grow the log past two pages (100 each): every policy reload appends one admin record.
  let head = (await admin('/admin/audit?order=desc&limit=1')).head;
  for (; head < 230; head++) {
    const r = await fetch(`${E.server}/admin/policies/reload`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${E.adminToken}`, 'Content-Type': 'application/json' },
      body: '{}',
    });
    assert.equal(r.status, 200, 'policy reload');
  }
  head = (await admin('/admin/audit?order=desc&limit=1')).head;
  const seqCells = c.page.locator('#main table tbody tr td:first-child');
  const seqs = async () => (await seqCells.allInnerTexts()).map(Number);
  const range = (hi, n) => Array.from({ length: n }, (_, i) => hi - i);
  const topIs = (seq) => c.page.locator('#main table tbody tr:first-child td:first-child', { hasText: new RegExp(`^${seq}$`) }).waitFor();
  const button = (name) => c.page.getByRole('button', { name, exact: true });

  await c.go('#/audit');
  await topIs(head);
  const newest = await seqs();
  assert.deepEqual(newest, range(head, 100), 'the newest page');
  assert.equal(await button('Newer').isDisabled(), true, 'nothing newer than the head');
  await button('Older').click();
  await topIs(head - 100);
  assert.deepEqual(await seqs(), range(head - 100, 100), 'the next older page, no gap and no repeat');
  await button('Older').click();
  await topIs(head - 200);
  assert.deepEqual(await seqs(), range(head - 200, head - 200), 'the oldest page reaches seq 1');
  assert.equal(await button('Older').isDisabled(), true, 'nothing older than seq 1');
  await button('Newer').click();
  await topIs(head - 100);
  assert.deepEqual(await seqs(), range(head - 100, 100), 'Newer comes back to the page above');
  await button('Newest').click();
  await topIs(head);
  assert.deepEqual(await seqs(), newest);
  await bothThemes('audit-paged');
});

// The smoke server cannot prune: `[audit.retention] prune = "manual"` needs `min_age_seconds`
// at or above the run-state retentions, so no entry is old enough during a run, and start-up
// refuses a smaller value. These tests answer the console's audit reads in the browser instead
// (a Playwright route) with a pruned log, so the pruned views run in the real console code.
// The stub serves seqs FIRST..HEAD built from real records, renumbered, with odd seqs denied
// and the reason `rare_reason` on seqs RARE; the prune's own record is at PRUNE_SEQ, above the
// boundary FIRST - 1. It honours what the console asks for: `order`, `from`, `to`, `limit`,
// `cursor` and exact filters on the record. Like the server, a filtered page reads at most
// `scan` seqs and may come back short, even empty, with `next_cursor` set.
const FIRST = 21;
const PRUNE_SEQ = 24;
const RARE = [30, 40];

async function prunedStub(probe, { head = 250, scan = Infinity } = {}) {
  const real = (await admin('/admin/audit?order=desc&limit=10')).entries;
  const adminRec = (await admin('/admin/audit?kind=admin&order=desc&limit=1')).entries[0];
  const cp = (await admin('/admin/audit/checkpoints?limit=1')).checkpoints[0];
  assert.ok(real.length === 10 && adminRec && cp, 'the log holds ten entries, an admin record and a checkpoint');
  const view = await admin(`/admin/audit/entries/${adminRec.seq}`);
  const at = (seq) => {
    if (seq === PRUNE_SEQ) return { ...adminRec, seq, record: { ...adminRec.record, kind: 'admin', tool: 'admin.audit.prune', reason: 'admin_action', decision: 'allow' } };
    const e = real[seq % real.length];
    const reason = seq >= RARE[0] && seq <= RARE[1] ? 'rare_reason' : e.record.reason;
    return { ...e, seq, record: { ...e.record, decision: seq % 2 ? 'deny' : 'allow', reason } };
  };
  const stub = {
    head,
    log: new Map(),
    verify: null,
    asked: [],
    append(n) {
      for (let i = 0; i < n; i++) {
        stub.head += 1;
        stub.log.set(stub.head, { ...at(stub.head), record: { ...at(stub.head).record, decision: 'allow' } });
      }
    },
  };
  for (let seq = FIRST; seq <= head; seq++) stub.log.set(seq, at(seq));
  const json = (route, status, body) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  const RECORD_FILTERS = ['kind', 'decision', 'tool', 'server', 'reason', 'chain_id'];

  await probe.page.route('**/admin/audit**', (route) => {
    const url = new URL(route.request().url());
    const q = url.searchParams;
    stub.asked.push(`${url.pathname}${url.search}`);
    if (url.pathname === '/admin/audit') {
      const desc = q.get('order') === 'desc';
      const limit = Number(q.get('limit') || 100);
      let lo = Math.max(Number(q.get('from') || 1), FIRST);
      let hi = Math.min(Number(q.get('to') || stub.head), stub.head);
      const cursor = q.get('cursor');
      // A cursor is a seq: the first one of the page (oldest first) or the one every entry of
      // the page is below (newest first).
      if (cursor !== null) {
        if (desc) hi = Math.min(hi, Number(cursor) - 1);
        else lo = Math.max(lo, Number(cursor));
      }
      const match = (e) => RECORD_FILTERS.every((k) => !q.has(k) || String(e.record[k]) === q.get(k));
      const filtered = RECORD_FILTERS.some((k) => q.has(k));
      // The window this page reads: all of lo..hi, or `scan` seqs of it when filtered.
      const span = filtered ? scan : Infinity;
      const [wlo, whi] = desc ? [Math.max(lo, hi - span + 1), hi] : [lo, Math.min(hi, lo + span - 1)];
      const seqs = [];
      for (let seq = wlo; seq <= whi; seq++) seqs.push(seq);
      if (desc) seqs.reverse();
      const hits = seqs.map((seq) => stub.log.get(seq)).filter(match);
      const entries = hits.slice(0, limit);
      let next = null;
      if (hits.length > limit) next = String(desc ? entries[entries.length - 1].seq : entries[entries.length - 1].seq + 1);
      else if (desc && wlo > lo) next = String(wlo);
      else if (!desc && whi < hi) next = String(whi + 1);
      return json(route, 200, { entries, next_cursor: next, head: stub.head, first: FIRST });
    }
    const m = url.pathname.match(/^\/admin\/audit\/entries\/(\d+)$/);
    if (m) {
      const seq = Number(m[1]);
      if (seq < FIRST) {
        return json(route, 410, {
          error: 'audit_pruned', code: 'audit_pruned', detail: `the audit entry at seq ${seq} was pruned`,
          pruned_through: FIRST - 1, prune_seq: PRUNE_SEQ, first: FIRST,
        });
      }
      if (stub.log.has(seq)) return json(route, 200, { ...view, entry: stub.log.get(seq), policy_reloaded_after: null });
      return json(route, 404, { error: 'not_found', code: 'not_found', detail: `no audit entry at seq ${seq}` });
    }
    if (url.pathname === '/admin/audit/checkpoints') {
      return json(route, 200, { checkpoints: [{ ...cp, seq: stub.head }], next_cursor: null });
    }
    if (url.pathname === '/admin/audit/verify') return json(route, 200, stub.verify);
    return route.continue();
  });
  return stub;
}

/** Only the stubbed 410s of pruned seqs (and Chromium's console lines about them). */
async function onlyPruned410s(probe) {
  const problems = await probe.allProblems();
  assert.ok(problems.some((p) => /^HTTP 410: GET .*\/admin\/audit\/entries\/\d+$/.test(p)), problems.join('\n'));
  assert.deepEqual(problems.filter((p) => !/\b410\b/.test(p)), []);
}

test('a pruned log, from stubbed answers: the explorer line, a pruned seq, the prune record and the verify panel', async () => {
  const probe = await Console.open(E.ui);
  try {
    const stub = await prunedStub(probe);
    await probe.login(E.adminToken);
    const seqCells = probe.page.locator('#main table tbody tr td:first-child');
    const seqs = async () => (await seqCells.allInnerTexts()).map(Number);
    const range = (hi, lo) => Array.from({ length: hi - lo + 1 }, (_, i) => hi - i);
    const button = (name) => probe.page.getByRole('button', { name, exact: true });
    const topIs = (seq) => probe.page.locator('#main table tbody tr:first-child td:first-child', { hasText: new RegExp(`^${seq}$`) }).waitFor();

    // The explorer: one quiet line naming the boundary, with the link to the prune record
    // filled in once the one-request lookup (the entry at FIRST - 1) answers.
    await probe.go('#/audit');
    const line = probe.page.locator('#audit-pruned');
    await line.locator('a').waitFor();
    assert.equal(await line.innerText(), 'Entries before seq 21 were pruned by the prune recorded at seq 24. An archive of them, if one was kept, is outside the server.');
    assert.equal(await line.locator('a').getAttribute('href'), '#/entry/24');
    assert.ok(stub.asked.includes('/admin/audit/entries/20'), stub.asked.join('\n'));
    assert.ok(!stub.asked.some((u) => u.includes('tool=admin.audit.prune')), 'the prune is found without a filtered scan');
    assert.deepEqual(await seqs(), range(250, 151));
    // Paging back stops cleanly at the first retained entry.
    await button('Older').click();
    await topIs(150);
    await button('Older').click();
    await topIs(50);
    assert.deepEqual(await seqs(), range(50, FIRST));
    assert.equal(await button('Older').isDisabled(), true, 'nothing older than the first retained entry');
    await bothThemes('audit-pruned', probe);

    // A pruned seq: its own message, with the boundary and links to the prune record and the
    // first retained entry, which are different seqs.
    await probe.go('#/entry/5');
    const gone = probe.page.locator('section.panel', { has: probe.page.locator('h1', { hasText: 'was pruned' }) });
    await gone.waitFor();
    assert.match(await gone.locator('h1').innerText(), /^Entry #5 was pruned$/);
    assert.match(await gone.locator('.callout.warn').innerText(), /This entry was pruned: the server deleted the start of the audit log through seq 20\. attenuo audit prune archives the entries before it prunes, and the automatic prune does when \[audit\.retention\] archive_dir is set; a prune made another way may have kept no copy\./);
    assert.equal(await kvValue(gone, 'Pruned through'), '20');
    assert.equal(await kvValue(gone, 'Prune record'), 'seq 24');
    assert.equal(await kvValue(gone, 'First retained seq'), 'seq 21');
    assert.equal(await gone.locator('dl.kv a', { hasText: 'seq 24' }).getAttribute('href'), '#/entry/24');
    assert.equal(await gone.locator('dl.kv a', { hasText: 'seq 21' }).getAttribute('href'), '#/entry/21');
    await bothThemes('entry-pruned', probe);

    // The prune record reads as a prune, and names the boundary of the newest prune.
    await gone.locator('dl.kv a', { hasText: 'seq 24' }).click();
    const verdictPanel = probe.page.locator('section.panel', { has: probe.page.locator('#entry-title') });
    await verdictPanel.locator('dd', { hasText: 'the newest prune' }).waitFor();
    assert.match(await verdictPanel.locator('#entry-title').innerText(), /#24/);
    assert.match(await verdictPanel.locator('.explain').innerText(), /^A prune of the start of the audit log, made by an admin/);
    assert.equal(await kvValue(verdictPanel, 'Prune'), 'the newest prune: entries through seq 20 were pruned; the log now starts at seq 21');
    await bothThemes('entry-prune-record', probe);

    // The record of an automatic prune names the server's own subject, and says that a copy
    // was kept only with archive_dir.
    const pruneRec = stub.log.get(PRUNE_SEQ);
    stub.log.set(PRUNE_SEQ, { ...pruneRec, record: { ...pruneRec.record, originating_subject: 'urn:attenuo:retention' } });
    await probe.go(`#/entry/${FIRST}`);
    await probe.go(`#/entry/${PRUNE_SEQ}`);
    await verdictPanel.locator('.explain', { hasText: 'An automatic prune' }).waitFor();
    assert.match(await verdictPanel.locator('.explain').innerText(), /^An automatic prune of the start of the audit log .* With \[audit\.retention\] archive_dir set, the server wrote them to an archive file there first; without it, no copy was kept\./);
    stub.log.set(PRUNE_SEQ, pruneRec);

    // The verify panel, a good walk from the anchor: the boundary, the anchors, and a bad
    // older anchor as visible as a bad checkpoint.
    stub.verify = {
      ok: false, entries: 230, first_bad_seq: null, checkpoints: 1, last_signed_seq: 250, unsigned_tail: 0,
      bad_checkpoints: [], pruned_through: FIRST - 1, anchors: 2,
      bad_anchors: [{ through_seq: 10, reason: 'the anchor signature does not verify' }],
    };
    await probe.go('#/verify');
    const head = probe.page.locator('section.panel', { has: probe.page.locator('h2', { hasText: 'Log head' }) });
    await head.locator('dl.kv').waitFor();
    assert.equal(await kvValue(head, 'Head seq'), '250');
    assert.equal(await kvValue(head, 'Unsigned entries'), '0');
    assert.match(await kvValue(head, 'First retained seq'), /^21 entries before it were pruned$/);
    const out = probe.page.locator('section.panel', { has: probe.page.locator('h2', { hasText: 'Verification' }) });
    await button('Verify now').click();
    await out.locator('.pill.big').waitFor();
    assert.equal(await out.locator('.pill.big').textContent(), 'chain broken');
    assert.equal(await kvValue(out, 'Pruned through'), '20');
    assert.equal(await kvValue(out, 'Anchors'), '2');
    assert.equal(await out.locator('dl.kv dt', { hasText: 'Bad anchors' }).locator('xpath=following-sibling::dd[1]').locator('.pill.bad').innerText(), '1');
    assert.deepEqual(await out.locator('table tbody tr td').allInnerTexts(), ['10', 'the anchor signature does not verify']);
    await bothThemes('verify-pruned', probe);

    // The tamper case: the newest anchor is bad, so the server walked without it and answers
    // no `pruned_through`. The panel must not say "not pruned".
    stub.verify = {
      ok: false, entries: 230, first_bad_seq: FIRST, checkpoints: 1, last_signed_seq: 250, unsigned_tail: 0,
      bad_checkpoints: [], pruned_through: null, anchors: 1,
      bad_anchors: [{ through_seq: FIRST - 1, reason: 'the anchor signature does not verify' }],
    };
    await button('Verify now').click();
    await out.locator('dl.kv dt', { hasText: 'First bad seq' }).locator('xpath=following-sibling::dd[1]', { hasText: '21' }).waitFor();
    // The pill is drawn in capitals (CSS); its text is lower case.
    assert.match(await kvValue(out, 'Pruned through'), /^none verified \(walked from the first retained entry\)$/i);
    assert.equal(await out.locator('dl.kv dt', { hasText: 'Pruned through' }).locator('xpath=following-sibling::dd[1]').locator('.pill.bad').textContent(), 'none verified');
    assert.match(await out.locator('p.callout.bad').innerText(), /no prune anchor verified/);
    assert.deepEqual(await out.locator('table tbody tr td').allInnerTexts(), ['20', 'the anchor signature does not verify']);
    await bothThemes('verify-pruned-bad-anchor', probe);

    await onlyPruned410s(probe);
  } finally {
    await probe.close();
  }
});

test('Follow on a filtered page of a pruned log keeps Older working when nothing new matches', async () => {
  const probe = await Console.open(E.ui);
  try {
    // A filtered page reads 10 seqs here, so the console's 20 hops reach only 250..51 and the
    // first page is empty with a cursor; the matches (RARE) are below it.
    const stub = await prunedStub(probe, { scan: 10 });
    await probe.login(E.adminToken);
    const seqCells = probe.page.locator('#main table tbody tr td:first-child');
    const seqs = async () => (await seqCells.allInnerTexts()).map(Number);
    const button = (name) => probe.page.getByRole('button', { name, exact: true });
    await probe.go('#/audit?reason=rare_reason');
    await probe.page.locator('#main', { hasText: 'No entries match these filters in this range' }).waitFor();
    assert.equal(await button('Older').isDisabled(), false, 'an empty filtered page still has its cursor');

    await button('Follow').click();
    await probe.page.locator('button[aria-pressed="true"]', { hasText: 'Following' }).waitFor();
    // The log grows by entries the filter does not match; wait for the poll that reads them.
    stub.append(3);
    await probe.page.locator('.pager .muted', { hasText: 'head 253' }).waitFor();
    assert.ok(stub.asked.some((u) => u.includes('order=asc') && u.includes('from=251')), 'Follow read the new entries');
    assert.equal(await button('Older').isDisabled(), false, 'Older keeps its cursor after a poll that matched nothing');

    await button('Older').click();
    await probe.page.locator('#main table tbody tr:first-child td:first-child', { hasText: /^40$/ }).waitFor();
    assert.deepEqual(await seqs(), [40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30], 'Older continues from the cursor to the matches');
    assert.equal(await button('Older').isDisabled(), true, 'and stops at the first retained entry');
    await onlyPruned410s(probe);
  } finally {
    await probe.close();
  }
});

// ---- reloads and the automatic prune (the auto and read-only servers) ---------------------

const AUTO_CONFIG = () => nodePath.join(E.autoDir, 'config.toml');

/** GET on another console listener as the admin, answering 200. */
async function adminAt(ui, path) {
  const resp = await fetch(`${ui}${path}`, { headers: { Authorization: `Bearer ${E.adminToken}`, Accept: 'application/json' } });
  assert.equal(resp.status, 200, `GET ${ui}${path}`);
  return resp.json();
}

/** Run `body` with the auto server's config file changed by `edit`, then put it back. */
async function withConfig(edit, body) {
  const file = AUTO_CONFIG();
  const before = fs.readFileSync(file, 'utf8');
  const after = edit(before);
  assert.notEqual(after, before, 'the config edit changed nothing');
  fs.writeFileSync(file, after);
  try {
    return await body();
  } finally {
    fs.writeFileSync(file, before);
  }
}

/** A fresh page on `ui` at device scale factor 2, logged in with `token`, at `hash`. */
async function openAt(ui, token, hash) {
  const p = await Console.open(ui, { deviceScaleFactor: 2 });
  await p.login(token);
  await p.go(hash);
  return p;
}

/** The problems of a page apart from the refused requests a test made on purpose. */
async function problemsBut(p, statuses) {
  const re = new RegExp(`\\b(${statuses.join('|')})\\b`);
  return (await p.allProblems()).filter((x) => !re.test(x));
}

/** Open the reload dialog of panel `id`, optionally tick `options`, press Reload. */
async function runReload(p, id, button, options = []) {
  await p.page.locator(`#reload-${id}`).getByRole('button', { name: button }).click();
  const dialog = p.page.locator('dialog[open]');
  await dialog.locator('h2').waitFor();
  for (const o of options) await dialog.locator(`#reload-opt-${o}`).check();
  await dialog.getByRole('button', { name: 'Reload', exact: true }).click();
  return dialog;
}

/** Wait until the dialog shows a refusal, and return its text. */
async function refusalText(dialog, id) {
  const err = dialog.locator(`#reload-${id}-error:not([hidden])`);
  await err.waitFor();
  return err.innerText();
}

/** The kv value `label` in the result box of panel `id`, once the result is drawn. */
async function resultValue(p, id, label) {
  const box = p.page.locator(`#reload-${id}-result`);
  await box.locator('dl.kv').first().waitFor();
  return kvValue(box, label);
}

test('reload page: reload the admin operators, then a refusal shows its code and message', async () => {
  const p = await openAt(E.autoUi, E.adminToken, '#/reload');
  try {
    const panel = p.page.locator('#reload-operators');
    await panel.waitFor();
    assert.match(await panel.innerText(), /\[\[admin\.operators\]\] entries, and nothing else/);
    assert.equal(await p.page.locator('#reload-writes-off').count(), 0, 'the writes-off note on a console with writes');
    assert.match(await p.page.locator('#reload-policies').innerText(), /Check and reload the policies/);

    // The confirmation says what the reload does; Cancel sends nothing.
    await panel.getByRole('button', { name: 'Reload operators…' }).click();
    const dialog = p.page.locator('dialog[open]');
    assert.match(await dialog.locator('h2').innerText(), /^Reload the admin operators\?$/);
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await p.page.waitForFunction(() => document.querySelectorAll('dialog').length === 0);
    assert.ok(!p.requests.includes('POST /admin/operators/reload'), 'Cancel sent the reload');

    // Happy path: the file is as at startup, so nothing changes, and the record is written.
    await runReload(p, 'operators', 'Reload operators…');
    assert.equal(await resultValue(p, 'operators', 'Added'), 'none');
    assert.equal(await resultValue(p, 'operators', 'Removed'), 'none');
    assert.equal(await resultValue(p, 'operators', 'Changed'), 'none');
    const auditId = (await resultValue(p, 'operators', 'Audit record')).trim();
    const rec = await adminAt(E.autoUi, `/admin/audit/records/${auditId}`);
    assert.equal(rec.entry.record.tool, 'admin.operators.reload');
    assert.equal(rec.entry.record.decision, 'allow');
    assert.match(await p.page.locator('#status').innerText(), /Operators reloaded: 0 added, 0 removed, 0 changed/);

    // A refusal: an entry with a role that does not exist. The dialog stays open with the
    // server's code and message; the operators in force are unchanged.
    await withConfig((t) => `${t}\n[[admin.operators]]\nname = "bad"\nrole = "root"\ntoken_sha256 = "${'0'.repeat(64)}"\n`, async () => {
      const d = await runReload(p, 'operators', 'Reload operators…');
      const text = await refusalText(d, 'operators');
      assert.match(text, /Refused: operators_invalid \(HTTP 422\)/);
      assert.match(text, /the operators in force are unchanged/);
      assert.match(text, /Nothing was changed\./);
      await bothThemes('reload-operators-refused', p);
      await d.getByRole('button', { name: 'Cancel' }).click();
    });
    assert.deepEqual(await problemsBut(p, [422]), []);
  } finally {
    await p.close();
  }
});

test('reload page: agents and PEPs, with the risky options off by default, a refusal, then the option', async () => {
  const p = await openAt(E.autoUi, E.adminToken, '#/reload');
  const bodies = [];
  p.page.on('request', (r) => { if (r.url().endsWith('/admin/agents/reload')) bodies.push(r.postData()); });
  try {
    await p.page.locator('#reload-agents').waitFor();
    await p.page.locator('#reload-agents').getByRole('button', { name: 'Reload agents and PEPs…' }).click();
    const dialog = p.page.locator('dialog[open]');
    for (const o of ['allow_empty', 'allow_mismatch']) {
      assert.equal(await dialog.locator(`#reload-opt-${o}`).isChecked(), false, `${o} starts checked`);
    }
    const text = await dialog.innerText();
    assert.match(text, /Off: a file with no \[\[agents\]\] or no \[\[peps\]\] entries is refused/);
    assert.match(text, /Off: a file whose \[issuer\] or \[audit\] differs from the running config is refused/);
    assert.equal(await dialog.locator('.callout.warn').isHidden(), true, 'the safety warning shows with every check on');
    await dialog.getByRole('button', { name: 'Reload', exact: true }).click();

    // The file is as at startup: both lists, their digests, nothing added, no restart needed.
    const rows = p.page.locator('#reload-agents-result tbody tr');
    await rows.first().waitFor();
    // textContent: the row header is upper-cased by the style sheet.
    const cells = async (i) => (await rows.nth(i).locator('th, td').allTextContents()).map((t) => t.trim());
    const agents = await cells(0);
    assert.deepEqual([agents[0], agents[1], agents[3], agents[4], agents[5]], ['[[agents]]', '2', 'none', 'none', 'none']);
    assert.match(agents[2], /^[0-9a-f]{16}…$/);
    assert.deepEqual((await cells(1)).slice(0, 2), ['[[peps]]', '0']);
    assert.equal(await resultValue(p, 'agents', 'Needs a restart'), 'none');
    assert.equal(bodies.shift(), '{}', 'a reload with every check on sends no option');

    // Another server's [issuer]: refused with its code and message, in the open dialog.
    await withConfig((t) => t.replace('audience = "attenuo"', 'audience = "another-server"'), async () => {
      const d = await runReload(p, 'agents', 'Reload agents and PEPs…');
      const refused = await refusalText(d, 'agents');
      assert.match(refused, /Refused: config_file_mismatch \(HTTP 422\)/);
      assert.match(refused, /the file's \[issuer\] differs from the running config/);
      assert.equal(bodies.shift(), '{}');
      // Turning the check off is a deliberate step: the warning shows, and the option is sent.
      await d.locator('#reload-opt-allow_mismatch').check();
      assert.equal(await d.locator('.callout.warn').isVisible(), true);
      await bothThemes('reload-agents-option', p);
      await d.getByRole('button', { name: 'Reload', exact: true }).click();
      await p.page.waitForFunction(() => document.querySelectorAll('dialog').length === 0);
      assert.deepEqual(JSON.parse(bodies.shift()), { allow_mismatch: true });
      await p.page.waitForFunction(() => /\[issuer\]/.test(document.querySelector('#reload-agents-result')?.innerText ?? ''));
      assert.match(await resultValue(p, 'agents', 'Needs a restart'), /\[issuer\]/);
    });
    await bothThemes('reload-agents-result', p);
    assert.deepEqual(await problemsBut(p, [422]), []);
  } finally {
    await p.close();
  }
});

test('reload page: issuer keys, a refused rotation, then a rotation with an overlap', async () => {
  const p = await openAt(E.autoUi, E.adminToken, '#/reload');
  try {
    await p.page.locator('#reload-keys').waitFor();
    const jwks = async () => (await (await fetch(`${E.autoServer}/.well-known/jwks.json`)).json()).keys.map((k) => k.kid);
    const [k1] = await jwks();

    // The files are as at startup: the same key signs, nothing changed.
    const d0 = await runReload(p, 'keys', 'Reload issuer keys…');
    await p.page.waitForFunction(() => document.querySelectorAll('dialog').length === 0);
    assert.equal(await d0.count(), 0);
    assert.equal(await resultValue(p, 'keys', 'Changed'), 'no: the same keys are in force');
    assert.equal(await resultValue(p, 'keys', 'Signing key'), k1);
    assert.equal(await resultValue(p, 'keys', 'Previous signing key'), k1);
    assert.equal(await resultValue(p, 'keys', 'Added'), 'none');

    // A new signing key without the current one: refused, every check on.
    const k2File = nodePath.join(E.autoDir, 'k2.pem');
    fs.copyFileSync(E.roKey, k2File);
    const k1Line = `private_key_pem_path = "${nodePath.join(E.autoDir, 'k1.pem')}"`;
    assert.ok(fs.readFileSync(AUTO_CONFIG(), 'utf8').includes(k1Line));
    const d = await withConfig((t) => t.replace(k1Line, `private_key_pem_path = "${k2File}"`), async () => {
      const dialog = await runReload(p, 'keys', 'Reload issuer keys…');
      for (const o of ['allow_drop_current', 'allow_drop_audit_key', 'allow_mismatch']) {
        assert.equal(await dialog.locator(`#reload-opt-${o}`).isChecked(), false, `${o} starts checked`);
      }
      const refused = await refusalText(dialog, 'keys');
      assert.match(refused, /Refused: keys_reload_drops_current \(HTTP 422\)/);
      assert.match(refused, new RegExp(`the current one, kid \`${k1}\`, is not in \\[issuer\\] previous_key_paths`));
      // Turning one check off leaves the next one on: the audit log was signed by k1.
      await dialog.locator('#reload-opt-allow_drop_current').check();
      await dialog.getByRole('button', { name: 'Reload', exact: true }).click();
      await dialog.locator('#reload-keys-error', { hasText: 'keys_reload_drops_audit_key' }).waitFor();
      assert.match(await refusalText(dialog, 'keys'), /which signed audit checkpoints or anchors the log holds/);
      await bothThemes('reload-keys-refused', p);
      await dialog.getByRole('button', { name: 'Cancel' }).click();
      return dialog;
    });
    assert.equal(await d.count(), 0);
    assert.deepEqual(await jwks(), [k1], 'a refused reload changed the JWKS');

    // With the current key kept for an overlap: no option needed, k2 signs, k1 still verifies.
    await withConfig((t) => t.replace(k1Line, `private_key_pem_path = "${k2File}"\nprevious_key_paths = ["${nodePath.join(E.autoDir, 'k1.pem')}"]`), async () => {
      await runReload(p, 'keys', 'Reload issuer keys…');
      await p.page.waitForFunction(() => document.querySelectorAll('dialog').length === 0);
      await p.page.waitForFunction(() => /^yes$/.test(document.querySelector('#reload-keys-result dl.kv dd')?.innerText ?? ''));
      const kids = await jwks();
      assert.equal(kids.length, 2);
      const k2 = kids.find((k) => k !== k1);
      assert.equal(await resultValue(p, 'keys', 'Signing key'), k2);
      assert.equal(await resultValue(p, 'keys', 'Previous signing key'), k1);
      assert.equal(await resultValue(p, 'keys', 'Verifying keys'), `${k2}, ${k1}`);
      assert.equal(await resultValue(p, 'keys', 'Added'), k2);
      assert.equal(await resultValue(p, 'keys', 'Removed'), 'none');
      assert.equal(await resultValue(p, 'keys', 'Audit signing key'), k2);
      await bothThemes('reload-keys-result', p);
    });
    assert.deepEqual(await problemsBut(p, [422]), []);
  } finally {
    await p.close();
  }
});

test('reload dialogs: Cancel has the focus, a reload in flight cannot be dismissed, and its outcome is always shown', async () => {
  const p = await openAt(E.autoUi, E.adminToken, '#/reload');
  const route = '**/admin/operators/reload';
  /** Hold the next reload request until the returned function is called with what to do. */
  const hold = async () => {
    let release;
    const held = new Promise((r) => { release = r; });
    await p.page.route(route, async (r) => {
      const act = await held;
      await act(r);
    }, { times: 1 });
    return release;
  };
  const open = async () => {
    await p.page.locator('#reload-operators').getByRole('button', { name: 'Reload operators…' }).click();
    const dialog = p.page.locator('dialog[open]');
    await dialog.locator('h2').waitFor();
    return dialog;
  };
  try {
    await p.page.locator('#reload-operators').waitFor();
    let dialog = await open();
    assert.equal(await p.page.evaluate(() => document.activeElement?.textContent), 'Cancel', 'Cancel does not have the focus');

    // In flight: Cancel is disabled and Escape (twice) leaves the dialog open; the answer then
    // closes it and draws the result.
    let release = await hold();
    await dialog.getByRole('button', { name: 'Reload', exact: true }).click();
    await p.page.waitForFunction(() => [...document.querySelectorAll('dialog[open] button')].find((b) => b.textContent === 'Cancel')?.disabled);
    await p.page.keyboard.press('Escape');
    await p.page.keyboard.press('Escape');
    // Chromium may close a dialog on a repeated Escape without a cancelable event; the console
    // then shows it again at once, so it is open (and still in the page) a moment later.
    await p.page.waitForFunction(() => document.querySelectorAll('dialog[open]').length === 1, null, { timeout: 2000 });
    assert.equal(await p.page.locator('dialog').count(), 1, 'Escape removed a dialog whose reload is in flight');
    assert.equal(await dialog.getByRole('button', { name: 'Reload', exact: true }).isDisabled(), true, 'a second reload can start');
    release((r) => r.continue());
    await p.page.waitForFunction(() => document.querySelectorAll('dialog').length === 0);
    assert.equal(await resultValue(p, 'operators', 'Added'), 'none');

    // The page changes while a reload runs: the router removes the dialog, and the outcome
    // still reaches the status line.
    dialog = await open();
    release = await hold();
    await dialog.getByRole('button', { name: 'Reload', exact: true }).click();
    await p.page.waitForFunction(() => [...document.querySelectorAll('dialog[open] button')].find((b) => b.textContent === 'Cancel')?.disabled);
    await p.go('#/audit');
    await p.page.waitForFunction(() => document.querySelectorAll('dialog').length === 0);
    release((r) => r.fulfill({ status: 422, contentType: 'application/json', body: JSON.stringify({ error: 'invalid_request', code: 'operators_invalid', detail: 'stubbed refusal' }) }));
    await p.page.locator('#status', { hasText: 'Admin operators reload: refused, operators_invalid: stubbed refusal. Nothing was changed.' }).waitFor();

    // No answer, and a 5xx: the outcome is unknown, not "nothing changed".
    await p.go('#/reload');
    dialog = await open();
    await p.page.route(route, (r) => r.abort('connectionreset'), { times: 1 });
    await dialog.getByRole('button', { name: 'Reload', exact: true }).click();
    let text = await refusalText(dialog, 'operators');
    assert.match(text, /No answer: network/);
    assert.match(text, /The result is unknown: the reload may or may not have happened\. The audit log shows whether it did/);
    assert.doesNotMatch(text, /Nothing was changed/);
    await p.page.route(route, (r) => r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'server_error', code: 'server_error', detail: 'stubbed failure' }) }), { times: 1 });
    await dialog.getByRole('button', { name: 'Reload', exact: true }).click();
    await dialog.locator('#reload-operators-error', { hasText: 'HTTP 500' }).waitFor();
    text = await refusalText(dialog, 'operators');
    assert.match(text, /No answer: server_error \(HTTP 500\)/);
    assert.match(text, /stubbed failure/);
    assert.match(text, /The result is unknown/);
    assert.doesNotMatch(text, /Nothing was changed/);
    await bothThemes('reload-unknown-outcome', p);
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    // Only the stubbed failures: the 422 and 500 answers and the reset connection.
    assert.deepEqual((await p.allProblems()).filter((x) => !/\b(422|500)\b|ERR_CONNECTION_RESET|request failed/.test(x)), []);
  } finally {
    await p.close();
  }
});

test('policy page: reload through the confirmation, then a file that does not load is refused', async () => {
  const p = await openAt(E.autoUi, E.adminToken, '#/policy');
  const policyFile = nodePath.join(E.autoDir, 'policy.cedar');
  const original = fs.readFileSync(policyFile, 'utf8');
  try {
    const check = async () => {
      await p.page.getByRole('button', { name: 'Check file on disk' }).click();
      await p.page.locator('.pill.big', { hasText: /^ok$/ }).waitFor();
    };
    await check();
    const reload = p.page.getByRole('button', { name: 'Reload…', exact: true });
    await reload.click();
    let dialog = p.page.locator('dialog[open]');
    await dialog.locator('h2').waitFor();
    assert.equal(await p.page.evaluate(() => document.activeElement?.textContent), 'Cancel', 'Cancel does not have the focus');
    assert.match(await dialog.locator('h2').innerText(), /^Reload the policy file\?$/);
    assert.match(await dialog.innerText(), /If it does not load, the old policies stay in force/);
    await dialog.getByRole('button', { name: 'Reload', exact: true }).click();
    const result = p.page.locator('#policy-reload-result');
    await result.locator('dl.kv').waitFor();
    const loaded = await adminAt(E.autoUi, '/admin/policies');
    // A reload waits for the next check, as before the confirmation existed.
    assert.equal(await reload.isDisabled(), true, 'Reload… is enabled right after a reload');
    assert.match(await kvValue(result, 'Policies'), new RegExp(`^${loaded.policies.length}: `));
    assert.equal(await kvValue(result, 'sha256'), loaded.sha256);
    const auditId = (await kvValue(result, 'Audit record')).trim();
    assert.equal((await adminAt(E.autoUi, `/admin/audit/records/${auditId}`)).entry.record.tool, 'admin.policies.reload');

    // The file breaks after a clean check: the reload is refused and the old set stays.
    await check();
    fs.writeFileSync(policyFile, `${original}\npermit(principal, action, resource) when { nonsense };\n`);
    await reload.click();
    dialog = p.page.locator('dialog[open]');
    await dialog.getByRole('button', { name: 'Reload', exact: true }).click();
    const err = dialog.locator('#policy-reload-error:not([hidden])');
    await err.waitFor();
    assert.match(await err.innerText(), /Refused: policy_invalid \(HTTP 422\)/);
    assert.match(await err.innerText(), /The old policies stay in force\./);
    assert.equal((await adminAt(E.autoUi, '/admin/policies')).sha256, loaded.sha256, 'a refused reload changed the policies');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    assert.deepEqual(await problemsBut(p, [422]), []);
  } finally {
    fs.writeFileSync(policyFile, original);
    await p.close();
  }
});

test('a read-only console offers no reload, and shows the automatic prune without an archive', async () => {
  const p = await openAt(E.roUi, E.adminToken, '#/reload');
  try {
    await p.page.locator('#reload-writes-off').waitFor();
    assert.match(await p.page.locator('#reload-writes-off').innerText(), /Writes are disabled on this listener/);
    for (const id of ['operators', 'agents', 'keys']) {
      assert.equal(await p.page.locator(`#reload-${id} button`).count(), 0, `a ${id} reload button on a read-only console`);
    }
    assert.match(await p.page.locator('#reload-keys').innerText(), /From a shell: attenuo admin key reload/);
    await p.go('#/policy');
    await p.page.getByRole('button', { name: 'Check file on disk' }).click();
    await p.page.locator('.pill.big', { hasText: /^ok$/ }).waitFor();
    assert.equal(await p.page.getByRole('button', { name: 'Reload…' }).count(), 0, 'a policy Reload on a read-only console');
    assert.match(await p.page.locator('section.panel', { hasText: 'Check and reload' }).innerText(), /Writes are disabled on this listener/);

    // The automatic prune is on, with no archive directory: a warning says what that means.
    await p.go('#/verify');
    const auto = p.page.locator('#auto-prune');
    await auto.locator('dl.kv').waitFor();
    assert.match(await auto.innerText(), /The server prunes the audit log on its own/);
    assert.equal(await kvValue(auto, 'Keeps'), '90 days (7776000 s)');
    assert.equal(await kvValue(auto, 'Checks every'), '1 hour (3600 s)');
    // Pills are upper-cased by the style sheet.
    assert.equal((await kvValue(auto, 'Archive directory')).toLowerCase(), 'not set');
    assert.match(await p.page.locator('#auto-prune-no-archive').innerText(), /deletes the entries it removes and keeps no copy/);
    assert.match(await p.page.locator('#auto-prune-no-run').innerText(), /No run yet since the server started/);
    await bothThemes('auto-prune-no-archive', p);
    assert.ok(!p.requests.some((r) => r.startsWith('POST ')), 'the read-only console sent a write');
    assert.deepEqual(await p.allProblems(), []);
  } finally {
    await p.close();
  }
});

test('verify page: the automatic prune with an archive directory and its last run', async () => {
  // The auto server checks every second; nothing is old enough, so each run is skipped.
  let plan;
  for (let i = 0; i < 100; i++) {
    plan = await adminAt(E.autoUi, '/admin/audit/prune/plan');
    if (plan.auto.last_run) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.ok(plan.auto.last_run, 'no automatic run within 10 s');
  const p = await openAt(E.autoUi, E.adminToken, '#/verify');
  try {
    const auto = p.page.locator('#auto-prune');
    await auto.locator('#auto-prune-last-run').waitFor();
    assert.equal(await kvValue(auto, 'Keeps'), '90 days (7776000 s)');
    assert.equal(await kvValue(auto, 'Checks every'), '1 second (1 s)');
    assert.equal(await kvValue(auto, 'At most per run'), '1,000,000 entries');
    assert.equal(await kvValue(auto, 'Archive directory'), nodePath.join(E.autoDir, 'archive'));
    assert.equal(await p.page.locator('#auto-prune-no-archive').count(), 0, 'the no-archive warning with an archive directory');
    assert.equal((await kvValue(auto, 'Outcome')).toLowerCase(), 'skipped');
    assert.match(await kvValue(auto, 'Reason'), /^(prune_too_recent|nothing_to_prune|sink_behind|prune_live_run) \S/);
    assert.equal(await kvValue(auto, 'Prune record'), 'none');
    assert.equal(await kvValue(auto, 'Archive file'), 'none');

    // A run that pruned, from a stubbed plan (the smoke log has nothing 90 days old): the
    // boundary, the prune record and the archive file name.
    const at = new Date(Date.now() - 60_000).toISOString().replace(/\.\d+Z$/, 'Z');
    await p.page.route('**/admin/audit/prune/plan', (route) => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        ...plan,
        auto: {
          ...plan.auto,
          last_run: {
            at, outcome: 'pruned', reason: 'ok', through: 120, prune_seq: 125, detail: null,
            archive: 'audit-00000000000000000001-00000000000000000120.jsonl',
          },
        },
      }),
    }));
    await p.go('#/audit');
    await p.go('#/verify');
    await auto.locator('#auto-prune-last-run').waitFor();
    await p.page.waitForFunction(() => /Pruned through/.test(document.querySelector('#auto-prune-last-run')?.innerText ?? ''));
    assert.equal((await kvValue(auto, 'Outcome')).toLowerCase(), 'pruned');
    assert.match(await kvValue(auto, 'Reason'), /^ok The run pruned the log\.$/);
    assert.equal(await kvValue(auto, 'Pruned through'), '120');
    assert.equal(await auto.getByRole('link', { name: 'seq 125' }).getAttribute('href'), '#/entry/125');
    assert.equal(await kvValue(auto, 'Archive file'), 'audit-00000000000000000001-00000000000000000120.jsonl');
    assert.equal(await auto.locator('time').getAttribute('datetime'), at);
    await bothThemes('auto-prune-archive', p);
    assert.deepEqual(await p.allProblems(), []);
  } finally {
    await p.close();
  }
});

test('a viewer sees no automatic prune section and asks for no plan; the reload buttons are disabled', async () => {
  const p = await openAt(E.autoUi, operatorEnv().viewer, '#/verify');
  try {
    await p.page.locator('section.panel', { hasText: 'Log head' }).locator('dl.kv').waitFor();
    assert.equal(await p.page.locator('#auto-prune').count(), 0, 'the automatic prune section for a viewer');
    assert.ok(!p.requests.some((r) => r.includes('/admin/audit/prune')), 'a viewer asked for the prune plan');
    await p.go('#/reload');
    for (const [id, name] of [['operators', 'Reload operators…'], ['agents', 'Reload agents and PEPs…'], ['keys', 'Reload issuer keys…']]) {
      const b = p.page.locator(`#reload-${id}`).getByRole('button', { name });
      assert.equal(await b.isDisabled(), true, `${name} is enabled for a viewer`);
      assert.equal(await b.getAttribute('title'), 'Needs the admin role; you are viewer.');
    }
    assert.match(await p.page.locator('#reload-keys').innerText(), /Reloading needs the admin role/);
    assert.deepEqual(await p.allProblems(), []);
  } finally {
    await p.close();
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
