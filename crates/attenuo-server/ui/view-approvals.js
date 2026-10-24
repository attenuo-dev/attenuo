// Approvals (#/approvals[?chain_id=&state=], #/approval/{id}): calls a policy gated with
// @obligation("approval"), the exact call each one is for, and (when the listener allows
// writes) grant or decline as the operator. Everything shown comes from the agent's call, so
// it is rendered as text nodes only (h() never parses HTML).
'use strict';

import {
  h, append, replace, link, mono, time, pill, empty, loading, kv, table, jsonTree,
} from './dom.js';
import { api, qs, showNotice } from './api.js';
import { untrustedArgs } from './view-entry.js';

const STATE_KIND = { pending: 'expired', granted: 'allow', declined: 'deny', consumed: 'active' };

function statePill(a) {
  const label = a.expired && (a.state === 'pending' || a.state === 'granted')
    ? `${a.state}, expired` : a.state;
  return pill(label, STATE_KIND[a.state] || '');
}

export async function approvalsView(root, params) {
  const chainId = params.get('chain_id') || '';
  const state = params.get('state') || '';
  const chainInput = h('input', { id: 'appr-chain', name: 'chain_id', value: chainId, autocomplete: 'off', spellcheck: 'false', placeholder: 'any run' });
  const stateSelect = h('select', { id: 'appr-state', name: 'state' },
    ['', 'pending', 'granted', 'declined', 'consumed'].map((s) => h('option', { value: s, selected: s === state }, s || 'any state')));
  const form = h('form', {
    class: 'row',
    on: {
      submit: (ev) => {
        ev.preventDefault();
        location.hash = `#/approvals${qs({ chain_id: chainInput.value.trim(), state: stateSelect.value })}`;
      },
    },
  },
  h('div', { class: 'field' }, h('label', { for: 'appr-chain' }, 'Run (chain id)'), chainInput),
  h('div', { class: 'field' }, h('label', { for: 'appr-state' }, 'State'), stateSelect),
  h('button', { type: 'submit' }, 'Show'));
  const list = h('div', null, loading());
  append(root, [
    h('section', { class: 'panel', 'aria-labelledby': 'appr-title' },
      h('header', null, h('h1', { id: 'appr-title' }, 'Approvals')),
      h('p', { class: 'small muted' }, 'Calls a policy gated with @obligation("approval"). The agent gets JSON-RPC -32008 with the approval id and may retry the identical call once it is granted.'),
      form,
      list),
  ]);
  const page = await api(`/admin/approvals${qs({ chain_id: chainId, state, limit: 200 })}`);
  if (!page.approvals.length) {
    replace(list, empty('No approvals match.'));
    return;
  }
  replace(list, table(['Approval', 'State', 'Call', 'User', 'Run', 'Expires'], page.approvals.map((a) => h('tr', null,
    h('td', null, link(['approval', a.approval_id], mono(a.approval_id.slice(0, 8) + '…'), { title: a.approval_id })),
    h('td', null, statePill(a)),
    h('td', null, mono(`${a.call.server}/${a.call.tool}`)),
    h('td', null, a.subject),
    h('td', null, link(['lease', a.chain_id], mono(a.chain_id.slice(0, 10) + '…'), { title: a.chain_id })),
    h('td', null, time(a.expires_at))))));
}

export async function approvalView(root, id) {
  append(root, loading());
  let a;
  try {
    a = await api(`/admin/approvals/${encodeURIComponent(id)}`, { quiet: [404] });
  } catch (e) {
    if (e.status === 401) throw e;
    replace(root, h('section', { class: 'panel' },
      h('h1', null, 'Unknown approval'),
      h('p', null, 'There is no approval ', mono(id), '.'),
      h('a', { href: '#/approvals' }, 'Back to approvals')));
    return;
  }
  render(root, a);
}

function render(root, a) {
  const err = h('p', { class: 'callout bad', role: 'alert' });
  err.hidden = true;
  const open = a.state === 'pending' && !a.expired;
  const decide = (decision) => async () => {
    err.hidden = true;
    for (const b of buttons) b.disabled = true;
    try {
      const next = await api(`/admin/approvals/${encodeURIComponent(a.approval_id)}`, {
        method: 'POST', body: { decision }, quiet: [404, 409],
      });
      showNotice(decision === 'grant' ? 'Granted. The agent’s identical retry will run once.' : 'Declined.');
      render(root, next);
    } catch (e) {
      if (e.status === 401) return;
      err.textContent = e.status === 404
        ? 'Writes are disabled on this listener. Set [admin_ui] allow_write = true to decide from the console, or use `attenuo approval grant` against the main listener.'
        : `Could not ${decision}: ${e.message}`;
      err.hidden = false;
      for (const b of buttons) b.disabled = false;
    }
  };
  const buttons = open ? [
    h('button', { type: 'button', class: 'primary', on: { click: decide('grant') } }, 'Grant'),
    h('button', { type: 'button', class: 'danger', on: { click: decide('decline') } }, 'Decline'),
  ] : [];
  const labels = a.labels.length
    ? h('ul', null, a.labels.map((l) => h('li', null, mono(l.source), ' ', link(['entry', l.seq], `tool_result at seq ${l.seq}`))))
    : h('span', { class: 'muted' }, 'none');
  replace(root,
    h('section', { class: 'panel', 'aria-labelledby': 'approval-title' },
      h('header', null,
        h('h1', { id: 'approval-title' }, 'Approval ', mono(a.approval_id)),
        h('div', { class: 'row' }, buttons)),
      h('div', { class: 'row' }, statePill(a)),
      err,
      kv([
        ['Call', mono(`${a.call.server}/${a.call.tool}`)],
        ['Call hash', mono(a.call_hash)],
        ['User', h('span', null, a.subject, h('span', { class: 'muted' }, ` (${a.issuer})`))],
        ['Agents', a.agents.join(' > ')],
        ['Run', link(['lease', a.chain_id], mono(a.chain_id))],
        ['Calling hop lease', link(['lease', a.lease], mono(a.lease))],
        ['Labels the run carried', labels],
        ['Arguments that matched an untrusted result', untrustedArgs(a.untrusted_args)],
        ['Gated decision', link(['record', a.decision_id], mono(a.decision_id))],
        ['Created', time(a.created_at)],
        ['Expires', time(a.expires_at)],
        ['Decided', a.approver ? h('span', null, time(a.decided_at), ` by ${a.approver.subject} (${a.approver.by}, ${a.approver.method})`) : undefined],
        ['Used by', a.consumed_by ? link(['record', a.consumed_by], mono(a.consumed_by)) : undefined],
      ])),
    h('section', { class: 'panel' },
      h('header', null, h('h2', null, 'Arguments, exactly as the agent sent them')),
      jsonTree(a.call.arguments, true)),
    h('p', null, h('a', { href: `#/approvals${qs({ chain_id: a.chain_id })}` }, 'Every approval of this run')));
}
