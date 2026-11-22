// Lease tree (#/lease/{id}): where a lease sits in its delegation tree, what a revoke would
// reach, and (when the listener allows writes) the revoke itself behind a typed confirmation:
// of this lease and its subtree, of the whole chain, of every lease of the originating user, or
// of the chains that opened one MCP session (the last three through `POST /admin/leases/revoke`,
// previewed first).
'use strict';

import {
  h, append, replace, link, mono, time, leaseState, leaseStatePill, empty, loading, kv, table, modal,
} from './dom.js';
import { api, qs, showNotice, needsRole } from './api.js';

const CONFIRM_CHARS = 6;
// Ids of each list a selector preview shows; the counts are always complete.
const PREVIEW_IDS = 8;
// Characters of a subject shown on a button; the whole subject is in its title.
const SUBJECT_CHARS = 32;

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
  const done = () => reload(root, leaseId);
  const revokeBtn = needsRole(h('button', {
    type: 'button', class: 'danger', disabled: tree.would_revoke === 0,
    title: tree.would_revoke === 0 ? 'Nothing left to revoke in this subtree' : null,
    on: { click: () => openRevoke(leaseId, tree, done) },
  }, 'Revoke…'), 'operator');
  // An older server sends no chain_id; the tree's root is the same lease.
  const chainId = self.chain_id ?? tree.root;
  const chainBtn = needsRole(h('button', {
    type: 'button', class: 'danger', title: `Revoke every lease of the chain ${chainId}`,
    on: { click: () => openSelectorRevoke({ chain_id: chainId }, done) },
  }, 'Revoke chain…'), 'operator');
  // Only a lease whose originating user was recorded at issue gets the user action; leases
  // registered before the server kept subjects have none. The subject is caller-controlled
  // text: it only ever becomes text nodes and attribute values (h() never parses HTML).
  const subject = typeof self.subject === 'string' && self.subject !== '' ? self.subject : null;
  const userBtn = subject !== null ? needsRole(h('button', {
    type: 'button', class: 'danger', title: `Revoke every lease issued for ${subject}`,
    on: { click: () => openSelectorRevoke({ user: subject }, done) },
  }, `Revoke all for ${clip(subject)}…`), 'operator') : null;
  // Not tied to this lease: the session id is typed in, and may resolve to any chain.
  const sessionBtn = needsRole(h('button', {
    type: 'button', class: 'danger', title: 'Revoke the chains that opened an MCP session, by its Mcp-Session-Id',
    on: { click: () => openSessionRevoke(done) },
  }, 'Revoke by session…'), 'operator');

  replace(root,
    h('section', { class: 'panel', 'aria-labelledby': 'lease-title' },
      h('header', null,
        h('h1', { id: 'lease-title' }, 'Lease ', mono(leaseId)),
        h('div', { class: 'row lease-actions' }, revokeBtn, chainBtn, userBtn, sessionBtn)),
      h('div', { class: 'row' }, leaseStatePill(self), self.agent ? h('span', null, 'issued to ', h('strong', null, self.agent)) : null),
      ancestorsPath(tree),
      kv([
        ['Chain (root lease)', link(['lease', tree.root], mono(tree.root))],
        ['Originating user', subject !== null
          ? h('strong', { class: 'subject' }, subject)
          : h('span', { class: 'muted' }, 'not recorded (issued before the server kept subjects)')],
        ['Expires', time(self.expires_at)],
        ['Issued', self.issued_seq !== null ? h('span', null, time(self.issued_at), ' at ', link(['entry', self.issued_seq], `seq ${self.issued_seq}`)) : h('span', { class: 'muted' }, 'no issuance record found')],
        ['A revoke now would change', h('strong', null, `${tree.would_revoke} lease${tree.would_revoke === 1 ? '' : 's'}`)],
        ['History', h('a', { href: `#/audit${qs({ lease: leaseId })}` }, 'Every record naming this lease')],
      ])),
    limitsPanel(tree),
    userWindowsPanel(tree),
    h('section', { class: 'panel' },
      h('header', null, h('h2', null, 'Subtree'),
        h('span', { class: 'small muted' }, `${tree.nodes.length} lease${tree.nodes.length === 1 ? '' : 's'} listed`)),
      tree.truncated ? h('p', { class: 'callout warn' }, 'The list is cut short at the server’s node cap. The revoke count above covers the whole subtree.') : null,
      subtree(tree)));
}

// ---- run limits (ADR-0010) ----------------------------------------------------------------

/**
 * Each hop of this lease's chain (root first, ending at this lease) with its run limits and
 * what is left, from the `budget` member of the tree's nodes. Charges go to every hop, so the
 * smallest `left` along the chain is what this lease can still spend. `null` when no hop has
 * limits or usage.
 */
function limitsPanel(tree) {
  const hops = tree.ancestors.slice().reverse().concat([tree.nodes[0]]);
  if (!hops.some((n) => n.budget)) return null;
  const rows = [];
  hops.forEach((n, i) => {
    const b = n.budget;
    if (!b || !b.limits.length) return;
    for (const l of b.limits) {
      rows.push(h('tr', null,
        h('td', null, `hop ${i} `, i === hops.length - 1 ? mono(n.lease_id.slice(0, 10) + '…') : link(['lease', n.lease_id], mono(n.lease_id.slice(0, 10) + '…'), { title: n.lease_id })),
        h('td', { class: 'wrap' }, l.server !== null ? mono(`${l.server} / ${l.tool}`) : h('span', { class: 'muted' }, `capability ${l.cap}`)),
        h('td', null, h('span', { class: 'tag' }, l.kind)),
        h('td', null, l.arg !== null ? mono(l.arg) : h('span', { class: 'muted' }, '—')),
        h('td', { class: 'num' }, usedText(l)),
        h('td', { class: 'num' }, l.max !== null ? mono(l.max) : h('span', { class: 'muted' }, 'not recorded')),
        h('td', { class: 'num' }, l.remaining !== null ? mono(l.remaining) : h('span', { class: 'muted' }, '—'))));
    }
  });
  const usage = (tree.ancestors.length ? tree.ancestors[tree.ancestors.length - 1] : tree.nodes[0]).budget;
  const usageRows = usage ? usage.usage.map((u) => h('tr', null,
    h('td', { class: 'wrap' }, mono(u.tool)),
    h('td', { class: 'num' }, mono(u.calls)),
    h('td', { class: 'num' }, mono(u.amount)),
    h('td', { class: 'num' }, mono(u.destinations)))) : [];
  return h('section', { class: 'panel' },
    h('header', null, h('h2', null, 'Run limits')),
    rows.length
      ? h('div', null,
        h('p', { class: 'small muted' }, 'The limits each hop of this chain was issued with, root first, and what their counters hold now. A call is charged to every hop it passes through, so the smallest figure left along the chain is what this lease can still spend.'),
        table(['Hop', 'Capability', 'Kind', 'Argument', 'Used', 'Max', 'Left'], rows, { short: true }))
      : h('p', { class: 'muted small' }, 'No hop of this chain carries run limits.'),
    usageRows.length
      ? h('div', null,
        h('h3', null, 'Run usage'),
        h('p', { class: 'small muted' }, 'Allowed calls of each destructive tool across the whole run, as policies see them in ', mono('context.usage'), '.'),
        table(['Tool', 'Calls', 'Amount', 'Destinations'], usageRows, { short: true }))
      : null,
    hops.some((n) => n.budget && !n.budget.recorded)
      ? h('p', { class: 'small muted' }, 'Some hops were issued before the server kept their limits: their counters are shown without a maximum.')
      : null);
}

/**
 * The run's originating user's per-user windows (run limits phase 3) for the tools this run
 * used, from the tree's `user_windows`: every run of the user counts in them, this one and
 * others. Read only. `null` from the server means the run's root lease was issued before the
 * server kept the user's issuer, and the windows cannot be found; an older server sends no
 * member, and a run with no window to show gets no panel.
 */
function userWindowsPanel(tree) {
  const w = tree.user_windows;
  if (w === undefined) return null;
  const head = h('header', null, h('h2', null, 'User windows'));
  if (w === null) {
    return h('section', { class: 'panel' }, head,
      h('p', { class: 'muted small' }, 'Not recorded: this run was issued before the server kept the originating user’s issuer, which a window is keyed by.'));
  }
  if (!w.windows.length) return null;
  const rows = w.windows.map((e) => h('tr', null,
    h('td', { class: 'wrap' }, mono(e.tool)),
    h('td', null, h('span', { class: 'tag' }, e.kind)),
    h('td', null, mono(e.start)),
    h('td', { class: 'num' }, mono(e.calls)),
    h('td', { class: 'num' }, mono(e.amount))));
  return h('section', { class: 'panel' }, head,
    h('p', { class: 'small muted' }, 'Allowed calls of each destructive tool this run used, by every run of its originating user in the current UTC window, as policies see them in ', mono('context.usage.user_window'), '.'),
    table(['Tool', 'Window', 'Start (UTC)', 'Calls', 'Amount'], rows, { short: true }),
    w.truncated ? h('p', { class: 'callout warn' }, 'The list is cut short at the server’s cap.') : null);
}

/** `used`, with how many values a `calls_per` limit has seen. */
function usedText(l) {
  if (l.kind === 'calls_per') {
    return h('span', null, mono(l.used), h('span', { class: 'muted small' }, ` most per value, ${l.values} value${l.values === 1 ? '' : 's'}`));
  }
  return mono(l.used);
}

/** One line for a tree node: each limit as `kind used/max`. */
function limitsSummary(n) {
  const b = n.budget;
  if (!b || !b.limits.length) return null;
  const parts = b.limits.map((l) => `${l.kind}${l.arg !== null ? ` ${l.arg}` : ''} ${l.used}/${l.max !== null ? l.max : '?'}`);
  return h('span', { class: 'small muted', title: 'Run limits of this hop: used/max' }, parts.join(' · '));
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
      limitsSummary(n),
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
    page.next_cursor !== null ? h('p', { class: 'muted' }, 'Older renewals exist; see the audit explorer.') : null);
  } catch (e) {
    replace(box, h('span', { class: 'muted' }, `Could not load renewals: ${e.message}`));
  }
}

// ---- revoke -------------------------------------------------------------------------------

/** A subject cut to SUBJECT_CHARS for a button label. */
function clip(text) {
  return text.length > SUBJECT_CHARS ? `${text.slice(0, SUBJECT_CHARS)}…` : text;
}

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

  let close = () => {};
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
  h('div', { class: 'buttons' }, h('button', { type: 'button', on: { click: () => close() } }, 'Cancel'), go));
  ({ close } = modal('revoke-title', form));
  reasonInput.focus();
}

// ---- revoke by chain or by user (POST /admin/leases/revoke) -------------------------------

/**
 * A selector as the dialog shows it: `chain_id`, `user` or `session`, then its value, as text.
 * A session selector is shown as the server answers it, by its tag (`session_tag`); the raw id
 * never comes back.
 */
function selectorText(selector) {
  if ('session_tag' in selector) {
    return h('span', null, h('span', { class: 'muted' }, 'session '), mono(selector.session_tag));
  }
  return 'chain_id' in selector
    ? h('span', null, h('span', { class: 'muted' }, 'chain_id '), mono(selector.chain_id))
    : h('span', null, h('span', { class: 'muted' }, 'user '), h('strong', { class: 'subject' }, selector.user));
}

/** What a selector is called in the dialog's text: `chain`, `user` or `session`. */
function selectorKind(selector) {
  if ('session' in selector) return 'session';
  return 'chain_id' in selector ? 'chain' : 'user';
}

/** The first PREVIEW_IDS ids of a response list, each a link to its lease page. */
function idList(ids, count, truncated) {
  if (!count) return h('span', { class: 'muted' }, 'none');
  const shown = ids.slice(0, PREVIEW_IDS);
  const more = count - shown.length;
  return h('div', null,
    h('ul', { class: 'idlist' }, shown.map((id) => h('li', null, link(['lease', id], mono(id))))),
    more > 0 ? h('p', { class: 'small muted' }, `and ${more} more`) : null,
    truncated ? h('p', { class: 'small muted' }, 'The server cut its id lists short; the counts are complete.') : null);
}

/**
 * Revoke a whole chain ({chain_id}) or every lease of one originating user ({user}) through
 * `POST /admin/leases/revoke`, in three steps inside one dialog: the preview
 * (`?preview=true`, which writes nothing) with what the selector matched and what would
 * change; a reason and a typed confirmation; then the result with the audit record it wrote.
 */
function openSelectorRevoke(selector, done) {
  const isChain = 'chain_id' in selector;
  const title = isChain ? 'Revoke chain' : 'Revoke all leases of a user';
  const box = h('div', { class: 'stack' });
  let close = () => {};
  let dialog = null;
  const ctx = { selector, shown: selector, title, box, done, close: () => close(), live: () => dialog.isConnected };
  const cancel = h('button', { type: 'button', on: { click: () => close() } }, 'Cancel');
  const status = h('div', { class: 'stack', 'aria-live': 'polite' }, loading());
  append(box, [
    h('h2', { id: 'selector-title' }, title),
    intro(selectorKind(selector)),
    kv([['Selector', selectorText(selector)]]),
    status,
    h('div', { class: 'buttons' }, cancel),
  ]);
  ({ dialog, close } = modal('selector-title', box));
  cancel.focus();

  api(`/admin/leases/revoke${qs({ preview: true })}`, { method: 'POST', body: selector, quiet: [400, 404] })
    .then((preview) => {
      if (!ctx.live()) return;
      replace(box, confirmForm(preview, ctx));
      box.querySelector('#selector-reason').focus();
    })
    .catch((e) => {
      if (!ctx.live() || e.status === 401) return;
      replace(status, h('p', { class: 'callout bad', role: 'alert' }, `Could not preview the revocation: ${e.message}`));
    });
}

const INTRO = {
  chain: 'This revokes every lease of the delegation chain: its first hop and everything delegated from it.',
  user: 'This revokes every lease issued for this originating user, under any issuer, each with everything delegated from it.',
  session: 'This revokes every lease of each delegation chain that opened this MCP session through the proxy: the whole run, not only the session.',
};

function intro(kind) {
  return h('p', null, INTRO[kind], ' Agents holding them are refused on their next call. It cannot be undone.');
}

/**
 * Revoke by MCP session (`{"session": "<Mcp-Session-Id>"}`), in four steps inside one dialog:
 * the session id, typed in; the preview, which shows the session's tag, the chains it resolves
 * to and the leases they hold; a reason and a typed confirmation; then the result. The raw id
 * is a secret that grants use of the session, so once it is submitted it lives only in this
 * closure, for the request bodies: the field is removed, and the dialog and its result show the
 * `session_tag` the server answers with. It never goes into a URL.
 */
function openSessionRevoke(done) {
  const title = 'Revoke by session';
  const box = h('div', { class: 'stack' });
  let close = () => {};
  let dialog = null;
  const ctx = { selector: null, shown: null, title, box, done, close: () => close(), live: () => dialog.isConnected };
  const entry = (problem) => {
    const input = h('input', { id: 'session-id', autocomplete: 'off', spellcheck: 'false', maxlength: 1024, required: true });
    const go = h('button', { type: 'submit', class: 'primary', disabled: true }, 'Preview');
    input.addEventListener('input', () => { go.disabled = !input.value.trim(); });
    const err = h('p', { class: 'callout bad', role: 'alert' }, problem ?? '');
    err.hidden = !problem;
    const form = h('form', {
      on: {
        submit: (ev) => {
          ev.preventDefault();
          const raw = input.value.trim();
          if (!raw) return;
          // Drop the id from the DOM before anything else happens.
          input.value = '';
          preview({ session: raw });
        },
      },
    },
    h('h2', { id: 'selector-title' }, title),
    intro('session'),
    h('div', { class: 'field' },
      h('label', { for: 'session-id' }, 'MCP session id (the Mcp-Session-Id header)'),
      input,
      h('p', { class: 'small muted' }, 'The id itself, not the 12-character tag that audit records show. The preview writes nothing.')),
    err,
    h('div', { class: 'buttons' }, h('button', { type: 'button', on: { click: () => close() } }, 'Cancel'), go));
    replace(box, form);
    input.focus();
  };
  const preview = (selector) => {
    const cancel = h('button', { type: 'button', on: { click: () => close() } }, 'Cancel');
    replace(box,
      h('h2', { id: 'selector-title' }, title),
      intro('session'),
      h('div', { class: 'stack', 'aria-live': 'polite' }, loading()),
      h('div', { class: 'buttons' }, cancel));
    cancel.focus();
    api(`/admin/leases/revoke${qs({ preview: true })}`, { method: 'POST', body: selector, quiet: [400, 404] })
      .then((p) => {
        if (!ctx.live()) return;
        ctx.selector = selector;
        ctx.shown = p.selector;
        replace(box, confirmForm(p, ctx));
        const focus = box.querySelector(p.revoked_count ? '#selector-reason' : '#selector-again');
        if (focus) focus.focus();
      })
      .catch((e) => {
        if (!ctx.live() || e.status === 401) return;
        entry(`Could not preview the revocation: ${e.message}`);
      });
  };
  ({ dialog, close } = modal('selector-title', box));
  ctx.again = () => entry();
  entry();
}

/** Step two: the preview, the reason and confirmation fields, and the Revoke button. */
function confirmForm(preview, ctx) {
  const { selector } = ctx;
  const kind = selectorKind(selector);
  const isChain = kind === 'chain';
  const isSession = kind === 'session';
  const chainIds = isSession && Array.isArray(ctx.shown.chain_ids) ? ctx.shown.chain_ids : [];
  const want = isChain ? selector.chain_id.slice(-CONFIRM_CHARS) : String(preview.revoked_count);
  const reasonInput = h('input', { id: 'selector-reason', autocomplete: 'off', required: true, maxlength: 500, value: 'revoked by admin' });
  const confirmInput = h('input', { id: 'selector-confirm', autocomplete: 'off', spellcheck: 'false', inputmode: isChain ? null : 'numeric', maxlength: 64, required: true });
  const nothing = preview.revoked_count === 0;
  const go = h('button', { type: 'submit', class: 'danger', disabled: true }, 'Revoke');
  const err = h('p', { class: 'callout bad', role: 'alert' });
  err.hidden = true;
  const check = () => {
    go.disabled = nothing || !(confirmInput.value.trim() === want && reasonInput.value.trim());
  };
  confirmInput.addEventListener('input', check);
  reasonInput.addEventListener('input', check);

  return h('form', {
    on: {
      submit: async (ev) => {
        ev.preventDefault();
        if (go.disabled) return;
        go.disabled = true;
        err.hidden = true;
        let res;
        try {
          res = await api('/admin/leases/revoke', {
            method: 'POST', body: { ...selector, reason: reasonInput.value.trim() }, quiet: [400, 404],
          });
        } catch (e) {
          if (e.status === 401 || !ctx.live()) return;
          err.textContent = e.status === 404
            ? 'Writes are disabled on this listener. Set [admin_ui] allow_write = true to revoke from the console, or use attenuo lease revoke against the main listener.'
            : `The revoke failed: ${e.message}`;
          err.hidden = false;
          check();
          return;
        }
        // The page changed while the revocation ran: the router has removed the dialog.
        if (!ctx.live()) return;
        replace(ctx.box, resultView(preview, res, ctx));
        ctx.box.querySelector('#selector-close').focus();
        showNotice(`Revoked ${res.revoked_count} lease${res.revoked_count === 1 ? '' : 's'} (the preview said ${preview.revoked_count}).`);
        // Refresh the page behind the dialog so the tree shows the revoked leases.
        await ctx.done();
      },
    },
  },
  h('h2', { id: 'selector-title' }, ctx.title),
  intro(kind),
  kv([
    ['Selector', selectorText(ctx.shown)],
    ...(isSession ? [['Chains', idList(chainIds, chainIds.length, false)]] : []),
    ['Leases matched', h('strong', null, String(preview.matched_count))],
    ['Leases that change', h('strong', null, String(preview.revoked_count))],
    ['Matched', idList(preview.matched, preview.matched_count, preview.truncated)],
    ['Would change', idList(preview.revoked, preview.revoked_count, preview.truncated)],
  ]),
  h('p', { class: 'small muted' }, 'This is a preview: nothing is revoked yet. Leases already revoked are not counted; expired ones are, since a renewal could bring them back.'),
  isSession && !chainIds.length
    ? h('p', { class: 'callout' }, 'No chains are recorded for this session id: it was never opened through this proxy by a verified token, or the id is mistyped. Nothing would be revoked.')
    : nothing ? h('p', { class: 'callout' }, 'Nothing is left to revoke for this selector.') : null,
  h('div', { class: 'field' }, h('label', { for: 'selector-reason' }, 'Reason (recorded in the audit log)'), reasonInput),
  h('div', { class: 'field' }, h('label', { for: 'selector-confirm' }, isChain
    ? `Type the last ${CONFIRM_CHARS} characters of the chain id (${want})`
    : `Type the number of leases that change (${want})`), confirmInput),
  err,
  h('div', { class: 'buttons' },
    isSession ? h('button', { id: 'selector-again', type: 'button', on: { click: ctx.again } }, 'Another session id') : null,
    h('button', { type: 'button', on: { click: ctx.close } }, 'Cancel'), go));
}

/** Step three: what the revocation did, and a link to the audit record it wrote. */
function resultView(preview, res, ctx) {
  return h('div', { class: 'stack' },
    h('h2', { id: 'selector-title' }, `${ctx.title}: done`),
    h('p', { class: 'callout good', role: 'status' },
      `Revoked ${res.revoked_count} lease${res.revoked_count === 1 ? '' : 's'}.`),
    kv([
      ['Selector', selectorText(res.selector ?? ctx.shown)],
      ...('chain_ids' in ctx.shown ? [['Chains', idList(ctx.shown.chain_ids, ctx.shown.chain_ids.length, false)]] : []),
      ['Reason', res.reason ?? ''],
      ['Leases matched', h('strong', null, String(res.matched_count))],
      ['Leases revoked', h('strong', null, String(res.revoked_count))],
      ['The preview said', String(preview.revoked_count)],
      ['Revoked', idList(res.revoked, res.revoked_count, res.truncated)],
      ['Audit record', res.audit_id
        ? link(['record', res.audit_id], mono(res.audit_id), { title: 'Open the audit record of this revocation' })
        : h('span', null, 'not written: the revocation stands, but the server could not record it (see its log)')],
    ]),
    h('div', { class: 'buttons' }, h('button', { id: 'selector-close', type: 'button', class: 'primary', on: { click: ctx.close } }, 'Close')));
}
