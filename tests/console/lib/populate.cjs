// Fills a fresh server (the GitHub leak demo config) with enough history that every console
// page has something to show, using the `attenuo` CLI against the main listener:
//
//   - alice's assistant gets a root token (github:*); it delegates read_file to `coder` with a
//     `distinct` run limit of one `repo` (as examples/python-agent does) and read_file to
//     `tester`, whose lease is then revoked, so the lease tree has a revoked node;
//   - the coder reads a private repo (policy_deny), a public one (allowed, charges the limit),
//     a second public one (budget_exhausted) and tries create_issue (capability_denied);
//   - the assistant opens an issue (approval_required), the operator grants it with the CLI and
//     the identical retry is allowed (the approval is consumed); a second issue is left
//     pending for the browser to grant;
//   - carol gets a chain of two leases (root and a coder hop) and bob two chains (one with a
//     coder hop), for the lease page's "Revoke chain…" and "Revoke all for <user>…" actions;
//   - the fake upstream gives every response the session id `fake-session-1`, so the coder's
//     first call that reaches it binds that session to alice's chain, for "Revoke by session…".
'use strict';

const { execFileSync } = require('node:child_process');

const CODER_SECRET = 'demo-coder-secret';
const TESTER_SECRET = 'demo-tester-secret';
const FAKE_SESSION = 'fake-session-1';

function env() {
  const need = (k) => {
    const v = process.env[k];
    if (!v) throw new Error(`${k} is not set; run the smoke test with scripts/console-smoke.sh`);
    return v;
  };
  return {
    server: need('CONSOLE_SMOKE_SERVER'),
    ui: need('CONSOLE_SMOKE_UI'),
    roServer: need('CONSOLE_SMOKE_RO_SERVER'),
    roUi: need('CONSOLE_SMOKE_RO_UI'),
    adminToken: need('CONSOLE_SMOKE_ADMIN_TOKEN'),
    cli: need('CONSOLE_SMOKE_CLI'),
    shots: need('CONSOLE_SMOKE_SHOTS'),
  };
}

/**
 * Run the CLI. Returns {status, stdout}. `token` goes in ATTENUO_TOKEN and `stdin` on standard
 * input, never in argv (as the CLI asks).
 */
function cli(e, args, { token, stdin, expect = [0] } = {}) {
  const childEnv = {
    ...process.env,
    ATTENUO_SERVER: e.server,
    ATTENUO_ADMIN_TOKEN: e.adminToken,
  };
  delete childEnv.ATTENUO_TOKEN;
  if (token) childEnv.ATTENUO_TOKEN = token;
  let status = 0;
  let stdout;
  try {
    stdout = execFileSync(e.cli, args, { env: childEnv, input: stdin ?? '', encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (err) {
    if (typeof err.status !== 'number') throw err;
    status = err.status;
    stdout = err.stdout;
    if (!expect.includes(status)) {
      throw new Error(`attenuo ${args.join(' ')} exited ${status}, want ${expect.join(' or ')}\n${err.stdout}\n${err.stderr}`);
    }
  }
  if (!expect.includes(status)) throw new Error(`attenuo ${args.join(' ')} exited ${status}, want ${expect.join(' or ')}`);
  return { status, stdout };
}

function cliJson(e, args, opts) {
  const { status, stdout } = cli(e, ['--json', ...args], opts);
  return { status, json: JSON.parse(stdout) };
}

/** A tools/call through the proxy; returns the JSON-RPC response and the exit status. */
function call(e, token, tool, args, expect) {
  const argv = ['call', '--server', 'github', '--tool', tool];
  for (const [k, v] of Object.entries(args)) argv.push('--arg', `${k}=${v}`);
  return cliJson(e, argv, { token, expect });
}

function populate(e) {
  const root = cliJson(e, ['token', 'root', '--subject', 'alice', '--agent', 'assistant', '--cap', 'github:*']).json;
  const coderCap = JSON.stringify({ server: 'github', tool: 'read_file', limits: { distinct: { arg: 'repo', max: 1 } } });
  const coder = cliJson(e, ['token', 'exchange', '--actor', 'coder', '--client-secret-stdin', '--cap', coderCap],
    { token: root.access_token, stdin: `${CODER_SECRET}\n` }).json;
  const tester = cliJson(e, ['token', 'exchange', '--actor', 'tester', '--client-secret-stdin', '--cap', 'github:read_file'],
    { token: root.access_token, stdin: `${TESTER_SECRET}\n` }).json;
  cli(e, ['lease', 'revoke', tester.lease, '--reason', 'smoke test: tester finished']);

  const denied = call(e, coder.access_token, 'read_file', { repo: 'alice/private-salaries', path: '2025.csv' }, [2]).json;
  const allowed = call(e, coder.access_token, 'read_file', { repo: 'alice/public-docs', path: 'README.md' }, [0]).json;
  const exhausted = call(e, coder.access_token, 'read_file', { repo: 'alice/public-site', path: 'index.html' }, [2]).json;
  const undelegated = call(e, coder.access_token, 'create_issue', { repo: 'alice/public-docs', title: 'leak' }, [2]).json;

  const gated = call(e, root.access_token, 'create_issue', { repo: 'alice/public-docs', title: 'README: fix typo' }, [2]).json;
  const consumedId = gated.error.data.approval_id;
  cli(e, ['approval', 'grant', consumedId]);
  const retried = call(e, root.access_token, 'create_issue', { repo: 'alice/public-docs', title: 'README: fix typo' }, [0]).json;

  const pendingGate = call(e, root.access_token, 'create_issue', { repo: 'alice/public-docs', title: 'second issue' }, [2]).json;
  const pendingId = pendingGate.error.data.approval_id;

  // Chains the selector revocations in the lease page act on, apart from alice's run: carol's
  // chain (root and a coder hop) is revoked as a chain; bob's two chains are revoked by user.
  const exchangeCoder = (parent) => cliJson(e, ['token', 'exchange', '--actor', 'coder', '--client-secret-stdin', '--cap', 'github:read_file'],
    { token: parent.access_token, stdin: `${CODER_SECRET}\n` }).json;
  const carolRoot = cliJson(e, ['token', 'root', '--subject', 'carol', '--agent', 'assistant', '--cap', 'github:*']).json;
  const carolChild = exchangeCoder(carolRoot);
  const bobRoot = cliJson(e, ['token', 'root', '--subject', 'bob', '--agent', 'assistant', '--cap', 'github:*']).json;
  const bobChild = exchangeCoder(bobRoot);
  const bobSecond = cliJson(e, ['token', 'root', '--subject', 'bob', '--agent', 'assistant', '--cap', 'github:*']).json;

  const reasons = {
    policyDeny: denied.error.data.reason,
    budgetExhausted: exhausted.error.data.reason,
    capabilityDenied: undelegated.error.data.reason,
    approvalRequired: gated.error.data.reason,
  };
  const want = { policyDeny: 'policy_deny', budgetExhausted: 'budget_exhausted', capabilityDenied: 'capability_denied', approvalRequired: 'approval_required' };
  for (const [k, v] of Object.entries(want)) {
    if (reasons[k] !== v) throw new Error(`setup: expected ${v} for ${k}, got ${reasons[k]}`);
  }
  if (allowed.error || retried.error) throw new Error('setup: an allowed call was refused');

  return {
    rootToken: root.access_token,
    rootLease: root.lease,
    coderToken: coder.access_token,
    coderLease: coder.lease,
    testerLease: tester.lease,
    consumedApproval: consumedId,
    pendingApproval: pendingId,
    budgetExhaustedDecision: exhausted.error.data.decision_id,
    policyDenyDecision: denied.error.data.decision_id,
    carolRootLease: carolRoot.lease,
    carolChildLease: carolChild.lease,
    bobLeases: [bobRoot.lease, bobChild.lease, bobSecond.lease],
    // A root whose run never called a tool, so the store holds no taint for it.
    bobSecondToken: bobSecond.access_token,
    // The id the fake upstream assigns (crates/attenuo-proxy/src/testing.rs).
    session: FAKE_SESSION,
  };
}

/**
 * On the read-only server: alice's root token and one allowed call, which binds the fake
 * upstream's session to that chain there. Returns {lease, session}.
 */
function populateReadOnly(e) {
  const ro = { ...e, server: e.roServer };
  const root = cliJson(ro, ['token', 'root', '--subject', 'alice', '--agent', 'assistant', '--cap', 'github:*']).json;
  const res = call(ro, root.access_token, 'read_file', { repo: 'alice/public-docs', path: 'README.md' }, [0]).json;
  if (res.error) throw new Error('setup: the read-only server refused an allowed call');
  return { lease: root.lease, session: FAKE_SESSION };
}

module.exports = { env, cli, cliJson, populate, populateReadOnly };
