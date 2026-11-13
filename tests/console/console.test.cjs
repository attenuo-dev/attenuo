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
const { env, cli, cliJson, populate, populateReadOnly } = require('./lib/populate.cjs');
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
  assert.equal(await c.page.getByRole('button', { name: 'Reload' }).isEnabled(), true);

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
