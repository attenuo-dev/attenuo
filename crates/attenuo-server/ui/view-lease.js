// Lease tree (#/lease/{id}): where a lease sits in its delegation tree, what a revoke would
// reach, and (when the listener allows writes) the revoke itself behind a typed confirmation.
'use strict';

import {
  h, append, replace, link, mono, time, leaseState, leaseStatePill, empty, loading, kv,
} from './dom.js';
import { api, qs, showNotice } from './api.js';

const CONFIRM_CHARS = 6;

export async function leaseView(root, leaseId) {
  append(root, loading());
  let tree;
  try {
    tree = await api(`/admin/leases/${encodeURIComponent(leaseId)}/tree`, { quiet: [404] });
  } catch (e) {
    if (e.status === 401) throw e;
    replace(root, h('section', { class: 'panel' },
      h('h1', null, 'Unknown lease'),
      h('p', null, 'The lease registry has no lease ', mono(leaseId), '.'),
      h('a', { href: '#/audit' }, 'Back to the audit log')));
    return;
  }
  render(root, leaseId, tree);
}

function render(root, leaseId, tree) {
  const self = tree.nodes[0];
  const revokeBtn = h('button', {
    type: 'button', class: 'danger', disabled: tree.would_revoke === 0,
    title: tree.would_revoke === 0 ? 'Nothing left to revoke in this subtree' : null,
    on: { click: () => openRevoke(leaseId, tree, () => reload(root, leaseId)) },
  }, 'Revoke…');

  replace(root,
    h('section', { class: 'panel', 'aria-labelledby': 'lease-title' },
      h('header', null,
        h('h1', { id: 'lease-title' }, 'Lease ', mono(leaseId)),
        revokeBtn),
      h('div', { class: 'row' }, leaseStatePill(self), self.agent ? h('span', null, 'issued to ', h('strong', null, self.agent)) : null),
      ancestorsPath(tree),
      kv([
        ['Chain (root lease)', link(['lease', tree.root], mono(tree.root))],
        ['Expires', time(self.expires_at)],
        ['Issued', self.issued_seq !== null ? h('span', null, time(self.issued_at), ' at ', link(['entry', self.issued_seq], `seq ${self.issued_seq}`)) : h('span', { class: 'muted' }, 'no issuance record found')],
        ['A revoke now would change', h('strong', null, `${tree.would_revoke} lease${tree.would_revoke === 1 ? '' : 's'}`)],
        ['History', h('a', { href: `#/audit${qs({ lease: leaseId })}` }, 'Every record naming this lease')],
      ])),
    h('section', { class: 'panel' },
      h('header', null, h('h2', null, 'Subtree'),
        h('span', { class: 'small muted' }, `${tree.nodes.length} lease${tree.nodes.length === 1 ? '' : 's'} listed`)),
      tree.truncated ? h('p', { class: 'callout warn' }, 'The list is cut short at the server’s node cap. The revoke count above covers the whole subtree.') : null,
      subtree(tree)));
}

async function reload(root, leaseId) {
  const tree = await api(`/admin/leases/${encodeURIComponent(leaseId)}/tree`);
  render(root, leaseId, tree);
}

/** Root first, down to this lease's parent. `ancestors` comes nearest first. */
function ancestorsPath(tree) {
  if (!tree.ancestors.length) return h('p', { class: 'small muted' }, 'This is a root lease (hop 0).');
  const path = h('div', { class: 'path' }, h('span', { class: 'muted' }, 'Delegated from'));
  const chain = tree.ancestors.slice().reverse();
  chain.forEach((a, i) => {
    append(path, [
      i ? h('span', { class: 'sep' }, '>') : null,
      link(['lease', a.lease_id], mono(a.lease_id.slice(0, 10) + '…'), { title: a.lease_id }),
      a.agent ? h('span', null, `(${a.agent})`) : null,
    ]);
  });
  return path;
}

/** Nested lists, parent then children; `nodes` is breadth-first with `parent` set. */
function subtree(tree) {
  const kids = new Map();
  for (const n of tree.nodes.slice(1)) {
    if (!kids.has(n.parent)) kids.set(n.parent, []);
    kids.get(n.parent).push(n);
  }
  const build = (node, focus) => {
    const li = h('li', null, nodeRow(node, tree.root, focus));
    const children = kids.get(node.lease_id) || [];
    if (children.length) append(li, [h('ul', null, children.map((c) => build(c, false)))]);
    return li;
  };
  return h('ul', { class: 'leases' }, build(tree.nodes[0], true));
}

function nodeRow(n, root, focus) {
  const s = leaseState(n);
  const renewals = h('div', { class: 'renewals' });
  renewals.hidden = true;
  const toggle = h('button', {
    type: 'button', class: 'linkish', 'aria-expanded': 'false',
    on: {
      click: async () => {
        const open = toggle.getAttribute('aria-expanded') === 'true';
        toggle.setAttribute('aria-expanded', String(!open));
        renewals.hidden = open;
        if (!open && !renewals.dataset.loaded) {
          renewals.dataset.loaded = '1';
          await loadRenewals(renewals, n.lease_id, root);
        }
      },
    },
  }, 'renewals');
  return h('div', null,
    h('div', { class: `lease-node${focus ? ' focus' : ''}` },
      focus ? mono(n.lease_id) : link(['lease', n.lease_id], mono(n.lease_id)),
      h('strong', null, n.agent ?? '—'),
      leaseStatePill(n),
      s.label === 'revoked'
        ? h('span', { class: 'muted' }, time(n.revoked_at), n.revoke_reason ? ` · ${n.revoke_reason}` : '')
        : h('span', { class: 'muted' }, 'expires ', time(n.expires_at)),
      n.issued_seq !== null ? link(['entry', n.issued_seq], `issued at seq ${n.issued_seq}`) : h('span', { class: 'muted' }, 'issuance not found'),
      toggle),
    renewals);
}

// Renewal records name the whole chain in `leases`; the renewed lease is the last one.
async function loadRenewals(box, leaseId, root) {
  replace(box, loading());
  try {
    const page = await api(`/admin/audit${qs({ kind: 'lease_renew', lease: leaseId, chain_id: root, order: 'desc', limit: 100 })}`);
    const mine = page.entries.filter((e) => e.record.leases[e.record.leases.length - 1] === leaseId);
    if (!mine.length) {
      replace(box, h('span', { class: 'muted' }, 'Never renewed.'));
      return;
    }
    replace(box, h('ul', null, mine.map((e) => h('li', null,
      link(['entry', e.seq], `seq ${e.seq}`), ' ', time(e.record.at), ' ', mono(e.record.reason)))),
    page.prev !== null ? h('p', { class: 'muted' }, 'Older renewals exist; see the audit explorer.') : null);
  } catch (e) {
    replace(box, h('span', { class: 'muted' }, `Could not load renewals: ${e.message}`));
  }
}

// ---- revoke -------------------------------------------------------------------------------

function openRevoke(leaseId, tree, done) {
  const tail = leaseId.slice(-CONFIRM_CHARS);
  const activeAgents = [...new Set(tree.nodes.filter((n) => n.active).map((n) => n.agent || 'unknown agent'))];
  const confirmInput = h('input', { id: 'revoke-confirm', autocomplete: 'off', spellcheck: 'false', maxlength: 64, required: true });
  const reasonInput = h('input', { id: 'revoke-reason', autocomplete: 'off', required: true, placeholder: 'agent session compromised' });
  const go = h('button', { type: 'submit', class: 'danger', disabled: true }, 'Revoke');
  const err = h('p', { class: 'callout bad', role: 'alert' });
  err.hidden = true;
  const check = () => {
    go.disabled = !(confirmInput.value === tail && reasonInput.value.trim());
  };
  confirmInput.addEventListener('input', check);
  reasonInput.addEventListener('input', check);

  const dialog = h('dialog', { 'aria-labelledby': 'revoke-title' });
  const close = () => {
    dialog.close();
    dialog.remove();
  };
  const form = h('form', {
    on: {
      submit: async (ev) => {
        ev.preventDefault();
        if (go.disabled) return;
        go.disabled = true;
        err.hidden = true;
        try {
          const res = await api(`/admin/leases/${encodeURIComponent(leaseId)}/revoke`, {
            method: 'POST', body: { reason: reasonInput.value.trim() }, quiet: [404],
          });
          close();
          showNotice(`Revoked ${res.revoked} lease${res.revoked === 1 ? '' : 's'} (the preview said ${tree.would_revoke}).`);
          await done();
        } catch (e) {
          if (e.status === 401) return;
          err.textContent = e.status === 404
            ? 'Writes are disabled on this listener. Set [admin_ui] allow_write = true to revoke from the console, or use the CLI against the main listener.'
            : `The revoke failed: ${e.message}`;
          err.hidden = false;
          check();
        }
      },
    },
  },
  h('h2', { id: 'revoke-title' }, 'Revoke lease'),
  h('p', null, 'This revokes ', mono(leaseId), ' and every lease delegated from it. Agents holding them are refused on their next call. It cannot be undone.'),
  kv([
    ['Leases that change', h('strong', null, String(tree.would_revoke))],
    ['Active agents affected', activeAgents.length ? activeAgents.join(', ') : h('span', { class: 'muted' }, 'none')],
  ]),
  h('div', { class: 'field' }, h('label', { for: 'revoke-reason' }, 'Reason (recorded in the audit log)'), reasonInput),
  h('div', { class: 'field' }, h('label', { for: 'revoke-confirm' }, `Type the last ${CONFIRM_CHARS} characters of the lease id (${tail})`), confirmInput),
  err,
  h('div', { class: 'buttons' }, h('button', { type: 'button', on: { click: close } }, 'Cancel'), go));
  append(dialog, [form]);
  dialog.addEventListener('cancel', () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();
  reasonInput.focus();
}
