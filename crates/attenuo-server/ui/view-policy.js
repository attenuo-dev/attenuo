// Policy page (#/policy): the policy set in force, a lint of the file on disk, reload after a
// clean check, and a dry-run "evaluate this call" form with an optional stated budget, run
// labels (taint), run usage and approval.
'use strict';

import {
  h, append, replace, mono, time, pill, decisionPill, table, empty, loading, kv, explainReason, jsonTree, modal,
} from './dom.js';
import { api, showNotice, roleAllows, writesAllowed } from './api.js';
import { refusal, auditLink } from './view-reload.js';

// GET /admin/policies, fetched once per login. Lock forgets it with the token.
let cached = null;

export function loadPolicies() {
  if (!cached) {
    cached = api('/admin/policies').catch((e) => {
      cached = null;
      throw e;
    });
  }
  return cached;
}

export function forgetPolicyCache() {
  cached = null;
}

export async function policyView(root) {
  const loaded = h('section', { class: 'panel' }, loading());
  append(root, [
    h('div', { class: 'page-head' }, h('h1', null, 'Policy'),
      h('span', { class: 'sub' }, 'What is loaded, whether the file on disk would load, and what the policies say about a call.')),
    loaded,
    checkPanel(() => {
      forgetPolicyCache();
      showLoaded(loaded);
    }),
    evaluatePanel(),
  ]);
  await showLoaded(loaded);
}

async function showLoaded(box) {
  replace(box, loading());
  const p = await loadPolicies();
  replace(box,
    h('header', null, h('h2', null, 'Loaded policies'),
      h('span', { class: 'small muted' }, `${p.policies.length} polic${p.policies.length === 1 ? 'y' : 'ies'}`)),
    kv([
      ['File', p.path ? mono(p.path) : h('span', { class: 'muted' }, 'none configured (the built-in set is in force)')],
      ['sha256', p.sha256 ? mono(p.sha256) : null],
      ['Loaded at', time(p.loaded_at)],
    ]),
    p.warnings.length
      ? h('div', { class: 'callout warn' }, h('p', null, 'Validation warnings:'), h('ul', null, p.warnings.map((w) => h('li', null, String(w)))))
      : null,
    p.policies.length
      ? p.policies.map((x) => h('div', { class: 'policy-item' }, h('h3', null, mono(x.id)), h('pre', null, x.text)))
      : empty('No policies are loaded, so every call that reaches the policy stage is denied.'));
}

function checkPanel(afterReload) {
  const out = h('div', { class: 'stack' });
  const result = h('div', { class: 'stack', id: 'policy-reload-result' });
  const writes = writesAllowed();
  const reloadNote = h('span', { class: 'small muted' }, writes === false
    ? 'Writes are disabled on this listener ([admin_ui] allow_write is off), so the console does not offer Reload. Reload with the attenuo CLI against the admin API.'
    : roleAllows('admin')
      ? 'Reload is enabled after a check with no errors.'
      : 'Reloading needs the admin role.');
  const reloadBtn = writes === false
    ? null
    : h('button', { type: 'button', class: 'primary', disabled: true, on: { click: () => confirmReload(checked, done) } }, 'Reload…');
  const checkBtn = h('button', { type: 'button', on: { click: check } }, 'Check file on disk');
  // The answer of the last check, which the confirmation shows.
  let checked = null;

  function done(r) {
    replace(result, h('h3', null, 'Last reload'), reloadResult(r));
    afterReload();
  }

  async function check() {
    checkBtn.disabled = true;
    if (reloadBtn) reloadBtn.disabled = true;
    replace(out, loading());
    try {
      const c = await api('/admin/policies/check', { quiet: [409] });
      checked = c;
      const issues = c.issues.map((i) => h('tr', null,
        h('td', null, pill(i.severity, i.severity === 'error' ? 'error' : 'warning')),
        h('td', { class: 'num' }, mono(i.line ?? '—')),
        h('td', { class: 'num' }, mono(i.column ?? '—')),
        h('td', null, i.policy_id ? mono(i.policy_id) : '—'),
        h('td', null, i.stage ?? ''),
        h('td', { class: 'wrap' }, i.message)));
      replace(out,
        h('div', { class: 'row' },
          pill(c.ok ? 'ok' : 'errors', c.ok ? 'ok' : 'error', true),
          h('span', null, `${c.error_count} error${c.error_count === 1 ? '' : 's'}, ${c.warning_count} warning${c.warning_count === 1 ? '' : 's'}`),
          c.differs_from_loaded
            ? pill('differs from loaded', 'warn')
            : pill('same as loaded', '')),
        kv([['File', mono(c.path)], ['sha256 on disk', mono(c.sha256)], ['sha256 loaded', c.loaded_sha256 ? mono(c.loaded_sha256) : null]]),
        issues.length ? table(['Severity', 'Line', 'Col', 'Policy', 'Stage', 'Message'], issues, { short: true }) : null);
      if (reloadBtn) reloadBtn.disabled = !c.ok || !roleAllows('admin');
    } catch (e) {
      if (e.status === 401) return;
      replace(out, h('p', { class: 'callout' }, e.status === 409
        ? 'No policy file is configured (policy.policies_path), so there is nothing to check or reload.'
        : `The check failed: ${e.message}`));
    } finally {
      checkBtn.disabled = false;
    }
  }

  return h('section', { class: 'panel' },
    h('header', null, h('h2', null, 'Check and reload'), checkBtn, reloadBtn),
    reloadNote,
    out,
    result);
}

/** The confirmation of a policy reload, after a clean check (`c`), then the reload itself. */
function confirmReload(c, done) {
  const err = h('div', { class: 'callout bad', role: 'alert', id: 'policy-reload-error' });
  err.hidden = true;
  const go = h('button', { type: 'submit', class: 'primary' }, 'Reload');
  let close = () => {};
  let dialog = null;
  const form = h('form', {
    on: {
      submit: async (ev) => {
        ev.preventDefault();
        go.disabled = true;
        err.hidden = true;
        let r;
        try {
          r = await api('/admin/policies/reload', { method: 'POST', body: {}, quiet: [403, 404, 409, 422, 500] });
        } catch (e) {
          if (e.status === 401 || !dialog.isConnected) return;
          replace(err, refusal(e));
          if (e.code === 'policy_invalid') append(err, [h('p', { class: 'small' }, 'The old policies stay in force.')]);
          err.hidden = false;
          go.disabled = false;
          return;
        }
        close();
        showNotice(`Reloaded: ${r.policy_ids.length} polic${r.policy_ids.length === 1 ? 'y' : 'ies'}, sha256 ${r.sha256.slice(0, 12)}…`);
        done(r);
      },
    },
  },
  h('h2', { id: 'policy-reload-title' }, 'Reload the policy file?'),
  h('p', null, 'Reads the policy file again and, if it parses and validates against the running schema, puts the new policies in force at once for every later decision. If it does not load, the old policies stay in force. The reload is recorded in the audit log.'),
  c ? kv([['File', mono(c.path)], ['sha256 checked', mono(c.sha256)]]) : null,
  h('p', { class: 'small muted' }, 'The server reads the file again when you press Reload: if it changed after the check, the new content is what loads.'),
  err,
  h('div', { class: 'buttons' }, h('button', { type: 'button', on: { click: () => close() } }, 'Cancel'), go));
  ({ dialog, close } = modal('policy-reload-title', form));
  go.focus();
}

/** What a policy reload answered: the policy ids, the file's digest, warnings, the record. */
function reloadResult(r) {
  return h('div', { class: 'stack' },
    kv([
      ['Policies', h('span', null, `${r.policy_ids.length}: `, r.policy_ids.map((id, i) => [i ? ', ' : '', mono(id)]))],
      ['sha256', mono(r.sha256)],
      ['Audit record', auditLink(r.audit_id)],
    ]),
    r.warnings && r.warnings.length
      ? h('div', { class: 'callout warn' }, h('p', null, 'Validation warnings:'), h('ul', null, r.warnings.map((w) => h('li', null, String(w)))))
      : null);
}

// ---- dry-run evaluation -----------------------------------------------------------------

function evaluatePanel() {
  const field = (id, label, input, wide) => h('div', { class: `field${wide ? ' wide' : ''}` }, h('label', { for: id }, label), input);
  const tokenIn = h('textarea', { id: 'ev-token', rows: 3, spellcheck: 'false', autocomplete: 'off', placeholder: 'eyJhbGciOi… (optional; expired tokens are accepted)' });
  const chainIn = h('textarea', { id: 'ev-chain', rows: 4, spellcheck: 'false', placeholder: '{"originating_user": {...}, "hops": [...]}  (used only without a token)' });
  const serverIn = h('input', { id: 'ev-server', required: true, placeholder: 'github', autocomplete: 'off' });
  const toolIn = h('input', { id: 'ev-tool', required: true, placeholder: 'read_file', autocomplete: 'off' });
  const argsIn = h('textarea', { id: 'ev-args', rows: 3, spellcheck: 'false', placeholder: '{"repo": "alice/public-docs"}' });
  const budget = budgetFields(field);
  const session = sessionFields(field);
  const usage = usageFields(field);
  const approval = approvalFields(field);
  const out = h('div', { class: 'stack' });

  const form = h('form', {
    class: 'eval-form',
    on: {
      submit: async (ev) => {
        ev.preventDefault();
        let body;
        try {
          body = buildRequest(tokenIn.value.trim(), chainIn.value.trim(), serverIn.value.trim(), toolIn.value.trim(), argsIn.value.trim());
          const stated = budget.read();
          if (stated) body.budget = stated;
          const labels = session.read();
          if (labels) body.session = labels;
          const used = usage.read();
          if (used) body.usage = used;
          const approved = approval.read();
          if (approved) body.approval = approved;
        } catch (e) {
          replace(out, h('p', { class: 'callout bad' }, e.message));
          return;
        }
        replace(out, loading());
        try {
          const r = await api('/admin/policies/evaluate', { method: 'POST', body, quiet: [400] });
          replace(out, evalResult(r));
        } catch (e) {
          if (e.status === 401) return;
          replace(out, h('p', { class: 'callout bad' }, `${e.code}: ${e.message}`));
        }
      },
    },
  },
  field('ev-token', 'Delegation token', tokenIn, true),
  field('ev-chain', 'Or a chain (JSON)', chainIn, true),
  field('ev-server', 'Server', serverIn),
  field('ev-tool', 'Tool', toolIn),
  field('ev-args', 'Arguments (JSON object)', argsIn, true),
  budget.node,
  session.node,
  usage.node,
  approval.node,
  h('div', { class: 'wide row' },
    h('button', { type: 'submit', class: 'primary' }, 'Evaluate'),
    h('span', { class: 'small muted' }, 'A dry run: no lease check, no audit record, no metrics. The token is sent to this server only.')));

  return h('section', { class: 'panel' },
    h('header', null, h('h2', null, 'Evaluate this call')),
    form,
    out);
}

/** The AuthZEN evaluation request of POST /admin/policies/evaluate. */
function buildRequest(token, chainText, server, tool, argsText) {
  if (!server || !tool) throw new Error('Server and tool are required.');
  let input = {};
  if (argsText) {
    try {
      input = JSON.parse(argsText);
    } catch (e) {
      throw new Error(`The arguments are not valid JSON: ${e.message}`);
    }
    if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new Error('The arguments must be a JSON object.');
  }
  const req = {
    subject: { type: 'agent', id: '' },
    action: { name: tool },
    resource: { type: 'tool', id: `${server}/${tool}`, properties: { server } },
    context: { input },
  };
  if (token) {
    req.token = token;
  } else {
    if (!chainText) throw new Error('Give either a token or a chain.');
    let chain;
    try {
      chain = JSON.parse(chainText);
    } catch (e) {
      throw new Error(`The chain is not valid JSON: ${e.message}`);
    }
    const hops = chain && Array.isArray(chain.hops) ? chain.hops : [];
    // subject.id must name the chain's current (last) agent.
    req.subject.id = hops.length ? String(hops[hops.length - 1].agent ?? '') : '';
    req.subject.properties = { chain };
  }
  return req;
}

// Text inputs, not type=number: a number input hides what it cannot parse, and its native
// validation would block the submit without saying which field is wrong.
const numInput = (id, placeholder) => h('input', { id, inputmode: 'numeric', autocomplete: 'off', spellcheck: 'false', placeholder });

/** A tri-state flag: not stated, true or false. */
const flagSelect = (id, unset) => h('select', { id },
  h('option', { value: '' }, unset),
  h('option', { value: 'true' }, 'true'),
  h('option', { value: 'false' }, 'false'));

/** A whole number of 0 or more from a text input, undefined when empty. */
function figure(input, name) {
  const v = input.value.trim();
  if (!v) return undefined;
  if (!/^\d+$/.test(v)) throw new Error(`${name} must be a whole number of 0 or more.`);
  return Number(v);
}

/** A comma-separated list of names, empty entries dropped. */
function nameList(input) {
  return input.value.split(',').map((x) => x.trim()).filter(Boolean);
}

// The optional `budget` block: the run-limit counters to decide the call in instead of the
// store's. Left empty, nothing is sent and the dry run reads the store.
function budgetFields(field) {
  const num = numInput;
  const flag = flagSelect;
  const callsIn = num('ev-budget-calls', 'not stated');
  const amountIn = num('ev-budget-amount', 'not stated');
  const destIn = flag('ev-budget-dest', 'not stated (new)');
  const limitedIn = flag('ev-budget-limited', 'not stated (true)');
  const limitsIn = h('textarea', {
    id: 'ev-budget-limits', rows: 3, spellcheck: 'false',
    placeholder: '[{"hop": 1, "kind": "distinct", "arg": "repo", "used": 1}]  (a refusal\'s limit can be pasted back)',
  });
  const node = h('details', { class: 'wide override-form budget-form' },
    h('summary', null, 'Budget (optional): state the run-limit counters instead of reading the store'),
    h('div', { class: 'eval-form' },
      field('ev-budget-calls', 'Calls remaining', callsIn),
      field('ev-budget-amount', 'Amount remaining', amountIn),
      field('ev-budget-dest', 'Destination new', destIn),
      field('ev-budget-limited', 'Limited (no matching limit)', limitedIn),
      field('ev-budget-limits', 'Single counters (JSON list of {hop, kind, arg, used, max})', limitsIn, true),
      h('p', { class: 'wide small muted' }, 'Leave every field empty to read the run\'s counters from the store. A stated budget is checked by the same code a live call goes through and never touches the store.')));

  /** The block to send, or null when nothing is stated. Throws on input the form can tell is wrong. */
  function read() {
    const b = {};
    const calls = figure(callsIn, 'Calls remaining');
    const amount = figure(amountIn, 'Amount remaining');
    if (calls !== undefined) b.calls_remaining = calls;
    if (amount !== undefined) b.amount_remaining = amount;
    if (destIn.value) b.destination_new = destIn.value === 'true';
    if (limitedIn.value) b.limited = limitedIn.value === 'true';
    const text = limitsIn.value.trim();
    if (text) {
      let limits;
      try {
        limits = JSON.parse(text);
      } catch (e) {
        throw new Error(`The single counters are not valid JSON: ${e.message}`);
      }
      // One pasted `limit` object is taken as a list of one.
      if (limits !== null && typeof limits === 'object' && !Array.isArray(limits)) limits = [limits];
      if (!Array.isArray(limits)) throw new Error('The single counters must be a JSON list of objects.');
      b.limits = limits;
    }
    return Object.keys(b).length ? b : null;
  }

  return { node, read };
}

// The optional `session` block: the run's output labels (ADR-0009) to decide the call with
// instead of the store's. Left empty, nothing is sent and the dry run reads the run's labels.
function sessionFields(field) {
  const taintedByIn = h('input', { id: 'ev-session-tainted-by', autocomplete: 'off', spellcheck: 'false', placeholder: 'web/fetch, github/read_file' });
  const taintedIn = flagSelect('ev-session-tainted', 'not stated');
  const untrustedIn = h('input', { id: 'ev-session-untrusted-args', autocomplete: 'off', spellcheck: 'false', placeholder: 'title, body' });
  const argsIn = flagSelect('ev-session-args', 'not stated');
  const node = h('details', { class: 'wide override-form session-form' },
    h('summary', null, 'Run labels (optional): state the taint instead of reading the store'),
    h('div', { class: 'eval-form' },
      field('ev-session-tainted-by', 'Tainted by (comma-separated server/tool)', taintedByIn),
      field('ev-session-tainted', 'Tainted', taintedIn),
      field('ev-session-untrusted-args', 'Untrusted arguments (comma-separated)', untrustedIn),
      field('ev-session-args', 'Arguments contain untrusted', argsIn),
      h('p', { class: 'wide small muted' }, 'Not stated, Tainted follows whether a source is named and Arguments contain untrusted whether an argument is. Leave every field empty to read the run\'s taint state from the store and match the arguments against its untrusted output.')));

  /** The block to send, or null when nothing is stated. */
  function read() {
    const b = {};
    const by = nameList(taintedByIn);
    const args = nameList(untrustedIn);
    if (by.length) b.tainted_by = by;
    if (taintedIn.value) b.tainted = taintedIn.value === 'true';
    if (args.length) b.untrusted_args = args;
    if (argsIn.value) b.args_contain_untrusted = argsIn.value === 'true';
    return Object.keys(b).length ? b : null;
  }

  return { node, read };
}

// The optional `usage` block: `context.usage` to decide the call with instead of the store's.
function usageFields(field) {
  const callsIn = numInput('ev-usage-calls', 'not stated (0)');
  const amountIn = numInput('ev-usage-amount', 'not stated (0)');
  const seenIn = flagSelect('ev-usage-seen', 'not stated (false)');
  const node = h('details', { class: 'wide override-form usage-form' },
    h('summary', null, 'Run usage (optional): state context.usage instead of reading the store'),
    h('div', { class: 'eval-form' },
      field('ev-usage-calls', 'Calls so far', callsIn),
      field('ev-usage-amount', 'Amount so far', amountIn),
      field('ev-usage-seen', 'Destination seen', seenIn),
      h('p', { class: 'wide small muted' }, 'Leave every field empty to read the run\'s usage from the store (with a stated budget and no usage, the figures are zero).')));

  /** The block to send, or null when nothing is stated. Throws on input the form can tell is wrong. */
  function read() {
    const b = {};
    const calls = figure(callsIn, 'Calls so far');
    const amount = figure(amountIn, 'Amount so far');
    if (calls !== undefined) b.calls = calls;
    if (amount !== undefined) b.amount = amount;
    if (seenIn.value) b.destination_seen = seenIn.value === 'true';
    return Object.keys(b).length ? b : null;
  }

  return { node, read };
}

// The optional `approval` block: decide the call as a retry that carries an approval granted
// by this party. The dry run never looks a stored approval up, so the route takes only `by`.
const APPROVAL_BY = ['user', 'operator', 'policy'];

function approvalFields(field) {
  const byIn = h('select', { id: 'ev-approval-by' },
    h('option', { value: '' }, 'not stated (no approval)'),
    APPROVAL_BY.map((by) => h('option', { value: by }, by)));
  const node = h('details', { class: 'wide override-form approval-form' },
    h('summary', null, 'Approval (optional): decide the call as if it carried a granted approval'),
    h('div', { class: 'eval-form' },
      field('ev-approval-by', 'Approved by', byIn),
      h('p', { class: 'wide small muted' }, 'Sets context.approval as a retry after the approval was granted would. Nothing is looked up or used: no approval id or token is needed.')));

  /** The block to send, or null when nothing is stated. */
  function read() {
    return APPROVAL_BY.includes(byIn.value) ? { by: byIn.value } : null;
  }

  return { node, read };
}

const I64_MAX = 9223372036854775807;

/** A remaining figure; the server's 2^63 - 1 means no limit of that kind matches. */
function remainingText(v) {
  return typeof v === 'number' && v >= I64_MAX ? h('span', { class: 'muted' }, 'no limit') : mono(String(v));
}

/** The answer's `budget` (context.budget) and, on budget_exhausted, the `limit` it hit. */
function budgetResult(b, limit) {
  if (!b) return null;
  const rows = limit ? [h('tr', null,
    h('td', { class: 'num' }, mono(limit.hop)),
    h('td', null, mono(limit.kind)),
    h('td', null, limit.arg ? mono(limit.arg) : '—'),
    h('td', { class: 'num' }, mono(limit.used)),
    h('td', { class: 'num' }, mono(limit.max ?? '—')))] : [];
  return h('section', { class: 'stack budget-result' },
    h('h3', null, 'Budget ', pill(b.source === 'request' ? 'stated in the request' : 'read from the store', b.source === 'request' ? 'warn' : '')),
    kv([
      ['Limited', b.limited ? 'yes' : 'no (no limit of the chain matches the call)'],
      ['Calls remaining', remainingText(b.calls_remaining)],
      ['Amount remaining', remainingText(b.amount_remaining)],
      ['Destination new', b.destination_new ? 'yes' : 'no'],
    ]),
    rows.length
      ? h('div', null,
        h('p', { class: 'small' }, 'The call would take this limit past its maximum:'),
        table(['Hop', 'Kind', 'Argument', 'Used', 'Max'], rows, { short: true }))
      : h('p', { class: 'small muted' }, 'No limit would be exceeded.'));
}

const SOURCE_TEXT = { request: 'stated in the request', store: 'read from the store', untracked: 'not tracked' };

/** A source pill: request (stated), store (read) or untracked. */
function sourcePill(source) {
  return pill(SOURCE_TEXT[source] || String(source ?? '?'), source === 'request' ? 'warn' : '');
}

const names = (list) => (list && list.length ? list.map((x, i) => [i ? ', ' : null, mono(x)]) : h('span', { class: 'muted' }, 'none'));

/** The answer's `session` (the run's output labels the call was decided with). */
function labelsResult(s) {
  if (!s) return null;
  return h('section', { class: 'stack labels-result' },
    h('h3', null, 'Run labels ', sourcePill(s.source)),
    kv([
      ['Tainted', s.tainted ? 'yes' : 'no'],
      ['Tainted by', names(s.tainted_by)],
      ['Arguments contain untrusted', s.args_contain_untrusted ? 'yes' : 'no'],
      ['Untrusted arguments', names(s.untrusted_args)],
    ]));
}

/** The answer's `usage` (context.usage). */
function usageResult(u) {
  if (!u) return null;
  return h('section', { class: 'stack usage-result' },
    h('h3', null, 'Run usage ', sourcePill(u.source)),
    kv([
      ['Calls', mono(String(u.calls))],
      ['Amount', mono(String(u.amount))],
      ['Destination seen', u.destination_seen ? 'yes' : 'no'],
    ]));
}

/** The answer's `approval` (context.approval). Only a request states one; the dry run reads none. */
function approvalResult(a) {
  if (!a) return null;
  return h('section', { class: 'stack approval-result' },
    h('h3', null, 'Approval ', a.present ? sourcePill('request') : pill('none stated', '')),
    kv([
      ['Granted', a.present ? 'yes' : 'no (the call is decided as a first attempt)'],
      ['By', a.present ? mono(a.by) : h('span', { class: 'muted' }, 'none')],
    ]));
}

function evalResult(r) {
  return h('div', { class: 'stack' },
    h('div', { class: 'verdict' },
      decisionPill(r.decision, true),
      h('span', { class: 'reason' }, r.reason),
      h('span', { class: 'explain' }, explainReason(r.reason) || 'No description for this reason code.')),
    r.token_expired ? h('p', { class: 'callout warn' }, 'The token has expired. This is what the policy says; the real call would be refused.') : null,
    kv([
      ['Policy ids', r.policy_ids.length ? r.policy_ids.map((p, i) => [i ? ', ' : null, mono(p)]) : h('span', { class: 'muted' }, 'none')],
      ['Lease check', mono(r.lease_check)],
      ['Chain source', h('span', null, mono(r.chain_source), r.chain_source === 'admin_supplied' ? ' (not checked to be issued by this server)' : '')],
      ['Token expired', r.token_expired ? 'yes' : 'no'],
    ]),
    budgetResult(r.budget, r.limit),
    labelsResult(r.session),
    usageResult(r.usage),
    approvalResult(r.approval),
    r.diagnostics && r.diagnostics.length
      ? h('div', null, h('h3', null, 'Diagnostics'), jsonTree(r.diagnostics, true))
      : h('p', { class: 'small muted' }, 'No diagnostics.'));
}
