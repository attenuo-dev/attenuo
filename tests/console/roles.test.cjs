// Browser smoke test of the console's named operators (ADR-0016): who is logged in, what the
// role allows (the lease, approval, policy and Reload page buttons), the expiry in the header, and the login error for an expired token. Run it with
// scripts/console-smoke.sh, which configures the `[[admin.operators]]` these tests log in as
// and passes their tokens in CONSOLE_SMOKE_* variables. It runs after console.test.cjs, on the
// same server.
//
// Every scenario opens its own Chromium page (a fresh page has no token), logs in once, checks
// the header and the action buttons, checks contrast and sideways scroll in both themes, takes
// one screenshot at device scale factor 2 and asserts that the page logged no console error or
// warning, no page error, no failed or 4xx/5xx request and no CSP violation. The buttons a role
// cannot use are disabled by the console; the server refuses those requests on its own
// (crates/attenuo-server tests), which is not what these tests check.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { env, operatorEnv, cliJson, populateRoles } = require('./lib/populate.cjs');
const { Console } = require('./lib/browser.cjs');

const E = env();
const OPS = operatorEnv();
let data;

const LEASE_ACTIONS = ['Revoke…', 'Revoke chain…', 'Revoke all for alice…', 'Revoke by session…'];

test.before(() => {
  data = populateRoles(E);
});

/** Open a fresh page, run `body` with it, then require a clean run and close it. */
async function scenario(body, { expectProblems = [] } = {}) {
  const c = await Console.open(E.ui, { deviceScaleFactor: 2 });
  try {
    await c.page.locator('#admin-token').waitFor();
    await body(c);
    const problems = await c.allProblems();
    const unexpected = problems.filter((p) => !expectProblems.some((re) => re.test(p)));
    assert.deepEqual(unexpected, [], 'console errors, failed requests or CSP violations');
    assert.deepEqual(await c.cspViolations(), [], 'CSP violations');
  } finally {
    await c.close();
  }
}

/** Contrast and sideways scroll in both themes, back to dark, then one screenshot. */
async function checkPage(c, name) {
  for (const theme of ['light', 'dark']) {
    await c.setTheme(theme);
    assert.deepEqual(await c.lowContrast(4.5), [], `${name}, ${theme} theme: text below 4.5:1 contrast`);
    const overflow = await c.page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    assert.ok(overflow <= 0, `${name}, ${theme} theme: the page scrolls sideways by ${overflow}px`);
  }
  await c.screenshot(E.shots, name);
}

async function whoami(c) {
  const el = c.page.locator('#whoami');
  assert.equal(await el.isVisible(), true, 'the header does not name the operator');
  return { text: await el.innerText(), title: await el.getAttribute('title') };
}

/** The lease page's revoke buttons, as {label: disabled}. */
async function leaseButtons(c) {
  await c.go(`#/lease/${data.lease}`);
  await c.page.locator('ul.leases').waitFor();
  const out = {};
  for (const name of LEASE_ACTIONS) {
    out[name] = await c.page.getByRole('button', { name, exact: true }).isDisabled();
  }
  return out;
}

/** The pending approval's Grant and Decline buttons, as {label: disabled}. */
async function approvalButtons(c) {
  await c.go(`#/approval/${data.pendingApproval}`);
  await c.page.locator('#approval-title').waitFor();
  assert.equal(await c.page.locator('section.panel .row .pill').first().textContent(), 'pending');
  const out = {};
  for (const name of ['Grant', 'Decline']) {
    out[name] = await c.page.getByRole('button', { name, exact: true }).isDisabled();
  }
  return out;
}

/** The policy page after a clean file check: whether Reload is disabled, and its note. */
async function reloadButton(c) {
  await c.go('#/policy');
  const check = c.page.getByRole('button', { name: 'Check file on disk' });
  await check.waitFor();
  await check.click();
  await c.page.locator('.pill.big', { hasText: /^ok$/ }).waitFor();
  const panel = c.page.locator('section.panel', { has: c.page.locator('h2', { hasText: 'Check and reload' }) });
  const reload = panel.getByRole('button', { name: 'Reload…', exact: true });
  return { disabled: await reload.isDisabled(), title: await reload.getAttribute('title'), note: await panel.innerText() };
}

const RELOADS = { operators: 'Reload operators…', agents: 'Reload agents and PEPs…', keys: 'Reload issuer keys…' };

/** The Reload page's buttons, as {panel: [disabled, title]}. Nothing is pressed. */
async function reloadPage(c) {
  await c.go('#/reload');
  await c.page.locator('#reload-keys').waitFor();
  const out = {};
  for (const [id, name] of Object.entries(RELOADS)) {
    const b = c.page.locator(`#reload-${id}`).getByRole('button', { name, exact: true });
    out[id] = [await b.isDisabled(), await b.getAttribute('title')];
  }
  return out;
}

const all = (obj, v) => Object.fromEntries(Object.keys(obj).map((k) => [k, v]));

test('the [admin] token logs in as admin · admin with every action enabled', async () => {
  await scenario(async (c) => {
    await c.login(E.adminToken);
    const who = await whoami(c);
    assert.equal(who.text, 'admin · admin');
    assert.equal(who.title, 'Logged in as the operator admin, role admin');
    const lease = await leaseButtons(c);
    assert.deepEqual(lease, all(lease, false));
    const approval = await approvalButtons(c);
    assert.deepEqual(approval, { Grant: false, Decline: false });
    const reload = await reloadButton(c);
    assert.equal(reload.disabled, false, 'Reload is disabled for admin after a clean check');
    assert.match(reload.note, /Reload is enabled after a check with no errors/);
    await checkPage(c, 'role-admin-policy');
    assert.deepEqual(await reloadPage(c), { operators: [false, null], agents: [false, null], keys: [false, null] });
  });
});

test('a viewer sees its name and role, and every action button is disabled', async () => {
  await scenario(async (c) => {
    await c.login(OPS.viewer);
    const who = await whoami(c);
    assert.equal(who.text, 'vera · viewer');
    assert.equal(who.title, 'Logged in as the operator vera, role viewer');

    const approval = await approvalButtons(c);
    assert.deepEqual(approval, { Grant: true, Decline: true });
    assert.equal(await c.page.getByRole('button', { name: 'Grant', exact: true }).getAttribute('title'),
      'Needs the operator role; you are viewer.');

    const reload = await reloadButton(c);
    assert.equal(reload.disabled, true, 'Reload is enabled for a viewer');
    assert.match(reload.note, /Reloading needs the admin role/);
    const viewerReloads = await reloadPage(c);
    assert.deepEqual(viewerReloads, all(viewerReloads, [true, 'Needs the admin role; you are viewer.']));
    await checkPage(c, 'role-viewer-reload');

    const lease = await leaseButtons(c);
    assert.deepEqual(lease, all(lease, true));
    await checkPage(c, 'role-viewer-lease');
  });
  // Nothing the viewer saw was decided or revoked.
  assert.equal(cliJson(E, ['approval', 'show', data.pendingApproval]).json.state, 'pending');
});

test('an operator may revoke and decide approvals, but not reload the policy', async () => {
  await scenario(async (c) => {
    await c.login(OPS.operator);
    const who = await whoami(c);
    assert.equal(who.text, 'otto · operator');

    const reload = await reloadButton(c);
    assert.equal(reload.disabled, true, 'Reload is enabled for an operator');
    assert.match(reload.note, /Reloading needs the admin role/);
    const operatorReloads = await reloadPage(c);
    assert.deepEqual(operatorReloads, all(operatorReloads, [true, 'Needs the admin role; you are operator.']));

    const lease = await leaseButtons(c);
    assert.deepEqual(lease, all(lease, false));
    // The selector preview is an operator route: it answers, and nothing is revoked.
    await c.page.getByRole('button', { name: 'Revoke chain…' }).click();
    await c.page.locator('dialog[open] #selector-reason').waitFor();
    await c.page.keyboard.press('Escape');
    await c.page.waitForFunction(() => document.querySelectorAll('dialog').length === 0);

    const approval = await approvalButtons(c);
    assert.deepEqual(approval, { Grant: false, Decline: false });
    await checkPage(c, 'role-operator-approval');
    await c.page.getByRole('button', { name: 'Grant', exact: true }).click();
    await c.page.locator('section.panel .row .pill', { hasText: /^granted$/ }).waitFor();
    assert.match(await c.page.locator('section.panel').first().innerText(), /by urn:attenuo:admin:otto \(operator, admin_token\)/);
  });
  const shown = cliJson(E, ['approval', 'show', data.pendingApproval]).json;
  assert.equal(shown.state, 'granted');
  assert.equal(shown.approver.subject, 'urn:attenuo:admin:otto', 'the approval names the operator who granted it');
});

test('an operator whose entry has expires_at shows the expiry in the header', async () => {
  await scenario(async (c) => {
    await c.login(OPS.expiring);
    const who = await whoami(c);
    assert.equal(who.text, `tara · operator · expires ${OPS.expiringAt.slice(0, 10)}`);
    assert.equal(who.title, `Logged in as the operator tara, role operator; the token expires at ${OPS.expiringAt}`);
    await c.page.locator('#main table tbody tr').first().waitFor();
    await checkPage(c, 'role-expiring-audit');
  });
});

test('an expired operator token is refused at login with the expired message', async () => {
  // The refused logins are the only problems allowed: one 401 from /admin/whoami each, which
  // Chromium also reports as a failed resource load on the console.
  const expected = [
    /^HTTP 401: GET http:\/\/127\.0\.0\.1:\d+\/admin\/whoami$/,
    /^console\.error: Failed to load resource: the server responded with a status of 401 \(Unauthorized\) \(http:\/\/127\.0\.0\.1:\d+\/admin\/whoami\)$/,
  ];
  await scenario(async (c) => {
    const p = c.page;
    const alert = p.locator('#main p.callout.bad[role="alert"]');
    // A token no credential matches: the generic refusal.
    await p.locator('#admin-token').fill('not-a-configured-token');
    await p.getByRole('button', { name: 'Log in' }).click();
    await p.locator('#main p.callout.bad[role="alert"]:not([hidden])').waitFor();
    assert.equal(await alert.innerText(), 'That token was refused.');

    await p.locator('#admin-token').fill(OPS.expired);
    await p.getByRole('button', { name: 'Log in' }).click();
    await p.waitForFunction(() => document.querySelector('#main p.callout.bad[role="alert"]')?.textContent === 'That token has expired.');
    assert.equal(await alert.isVisible(), true);
    assert.equal(await p.locator('#nav').isHidden(), true, 'the nav shows after a refused login');
    assert.equal(await p.locator('#whoami').isHidden(), true, 'the header names an operator after a refused login');
    await checkPage(c, 'role-expired-login');
    const refused = (await c.allProblems()).filter((x) => expected[0].test(x));
    assert.equal(refused.length, 2, `two refused logins: ${refused}`);
  }, { expectProblems: expected });
});
