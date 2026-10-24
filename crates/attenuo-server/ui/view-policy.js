// Policy page (#/policy): the policy set in force, a lint of the file on disk, reload after a
// clean check, and a dry-run "evaluate this call" form with an optional stated budget.
'use strict';

import {
  h, append, replace, mono, time, pill, decisionPill, table, empty, loading, kv, explainReason, jsonTree,
} from './dom.js';
import { api, showNotice } from './api.js';

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
  const reloadNote = h('span', { class: 'small muted' }, 'Reload is enabled after a check with no errors.');
  const reloadBtn = h('button', { type: 'button', class: 'primary', disabled: true, on: { click: reload } }, 'Reload');
  const checkBtn = h('button', { type: 'button', on: { click: check } }, 'Check file on disk');

  async function check() {
    checkBtn.disabled = true;
    reloadBtn.disabled = true;
    replace(out, loading());
    try {
      const c = await api('/admin/policies/check', { quiet: [409] });
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
      reloadBtn.disabled = !c.ok;
    } catch (e) {
      if (e.status === 401) return;
      replace(out, h('p', { class: 'callout' }, e.status === 409
        ? 'No policy file is configured (policy.policies_path), so there is nothing to check or reload.'
        : `The check failed: ${e.message}`));
    } finally {
      checkBtn.disabled = false;
    }
  }

  async function reload() {
    reloadBtn.disabled = true;
    try {
      const r = await api('/admin/policies/reload', { method: 'POST', body: {}, quiet: [404, 422] });
      showNotice(`Reloaded: ${r.policy_ids.length} polic${r.policy_ids.length === 1 ? 'y' : 'ies'}, sha256 ${r.sha256.slice(0, 12)}…`);
      afterReload();
    } catch (e) {
      if (e.status === 401) return;
      if (e.status === 404) {
        reloadNote.textContent = 'Writes are disabled on this listener ([admin_ui] allow_write). Reload with the CLI against the main listener.';
      } else {
        reloadNote.textContent = `The reload was refused and the old policies stay in force: ${e.message}`;
      }
    }
  }

  return h('section', { class: 'panel' },
    h('header', null, h('h2', null, 'Check and reload'), checkBtn, reloadBtn),
    reloadNote,
    out);
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

// The optional `budget` block: the run-limit counters to decide the call in instead of the
// store's. Left empty, nothing is sent and the dry run reads the store.
function budgetFields(field) {
  // Text inputs, not type=number: a number input hides what it cannot parse, and its native
  // validation would block the submit without saying which field is wrong.
  const num = (id, placeholder) => h('input', { id, inputmode: 'numeric', autocomplete: 'off', spellcheck: 'false', placeholder });
  const flag = (id, unset) => h('select', { id },
    h('option', { value: '' }, unset),
    h('option', { value: 'true' }, 'true'),
    h('option', { value: 'false' }, 'false'));
  const callsIn = num('ev-budget-calls', 'not stated');
  const amountIn = num('ev-budget-amount', 'not stated');
  const destIn = flag('ev-budget-dest', 'not stated (new)');
  const limitedIn = flag('ev-budget-limited', 'not stated (true)');
  const limitsIn = h('textarea', {
    id: 'ev-budget-limits', rows: 3, spellcheck: 'false',
    placeholder: '[{"hop": 1, "kind": "distinct", "arg": "repo", "used": 1}]  (a refusal\'s limit can be pasted back)',
  });
  const node = h('details', { class: 'wide budget-form' },
    h('summary', null, 'Budget (optional): state the run-limit counters instead of reading the store'),
    h('div', { class: 'eval-form' },
      field('ev-budget-calls', 'Calls remaining', callsIn),
      field('ev-budget-amount', 'Amount remaining', amountIn),
      field('ev-budget-dest', 'Destination new', destIn),
      field('ev-budget-limited', 'Limited (no matching limit)', limitedIn),
      field('ev-budget-limits', 'Single counters (JSON list of {hop, kind, arg, used, max})', limitsIn, true),
      h('p', { class: 'wide small muted' }, 'Leave every field empty to read the run\'s counters from the store. A stated budget is checked by the same code a live call goes through and never touches the store.')));

  const figure = (input, name) => {
    const v = input.value.trim();
    if (!v) return undefined;
    if (!/^\d+$/.test(v)) throw new Error(`${name} must be a whole number of 0 or more.`);
    return Number(v);
  };

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
    r.diagnostics && r.diagnostics.length
      ? h('div', null, h('h3', null, 'Diagnostics'), jsonTree(r.diagnostics, true))
      : h('p', { class: 'small muted' }, 'No diagnostics.'));
}
