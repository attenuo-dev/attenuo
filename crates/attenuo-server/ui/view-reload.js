// Reload page (#/reload): put an edited config file in force without a restart. One panel per
// reload route: the admin operators, the agents and PEPs, and the issuer keys, each behind a
// confirmation dialog whose risky options start unchecked; the policy file is reloaded from the
// Policy page, after a check. The result shows what changed, as the server answered it; a
// refusal (4xx) shows the server's code and message, and nothing changed; a network error or a
// 5xx says the outcome is unknown. While a reload is in flight its dialog cannot be dismissed,
// and only one reload of a kind runs at a time.
//
// The routes need the admin role and `[admin_ui] allow_write`. Without the role the buttons
// are disabled; on a listener without writes they are not shown at all.
'use strict';

import { h, append, replace, link, mono, short, kv, table, time, modal } from './dom.js';
import { api, showNotice, showError, needsRole, roleAllows, writesAllowed } from './api.js';

/** The reloads this page offers, in the order shown. */
const RELOADS = [
  {
    id: 'operators',
    title: 'Admin operators',
    button: 'Reload operators…',
    path: '/admin/operators/reload',
    cli: 'attenuo admin operator reload',
    what: [
      'Reads the [[admin.operators]] entries, and nothing else, from the config file the server was started with, checks them as at startup, and puts them in force at once. [admin] token is never reloaded.',
      'A list that would leave no unexpired admin credential is refused, so a typo cannot lock everyone out. If the new list removes or demotes you, your next request is checked against it.',
    ],
    options: [],
    result: operatorsResult,
    summary: (r) => `Operators reloaded: ${r.added.length} added, ${r.removed.length} removed, ${r.changed.length} changed.`,
  },
  {
    id: 'agents',
    title: 'Agents and PEPs',
    button: 'Reload agents and PEPs…',
    path: '/admin/agents/reload',
    cli: 'attenuo admin agent reload',
    what: [
      'Reads the [[agents]] and [[peps]] entries from the config file the server was started with, checks them as at startup, and puts both lists in force at once. A removed agent, or an old secret or key, is refused from the next request on.',
      'Nothing else in the file is applied: the answer names the sections that differ and need a restart. Tokens and leases already issued are not revoked; revoke them from a lease page.',
    ],
    options: [
      {
        name: 'allow_empty',
        label: 'Allow a list to become empty',
        help: 'Off: a file with no [[agents]] or no [[peps]] entries is refused while the server has some, because an empty or cut-off file reads that way.',
      },
      {
        name: 'allow_mismatch',
        label: 'Allow a file that looks like another server’s',
        help: 'Off: a file whose [issuer] or [audit] differs from the running config is refused, because it may be another server’s file. Even with it, only the two lists are applied.',
      },
    ],
    result: agentsResult,
    summary: (r) => `Agents and PEPs reloaded: ${r.agents.count} agent${r.agents.count === 1 ? '' : 's'} and ${r.peps.count} PEP${r.peps.count === 1 ? '' : 's'} in force.`,
  },
  {
    id: 'keys',
    title: 'Issuer keys',
    button: 'Reload issuer keys…',
    path: '/admin/keys/reload',
    cli: 'attenuo admin key reload',
    what: [
      'Reads [issuer] private_key_pem_path and previous_key_paths from the config file, reads those key files, and puts the new signing key and the new verifying keys in force at once. New tokens, approval tokens, audit checkpoints and prune anchors are signed with the new key, and the JWKS lists the new set.',
      'Tokens signed by a key that stays among the verifying keys keep working. To rotate without breaking anything, list the current key file in previous_key_paths. The other [issuer] settings need a restart.',
    ],
    options: [
      {
        name: 'allow_drop_current',
        label: 'Allow dropping the current signing key',
        help: 'Off: a new signing key is refused while the current one is not kept in previous_key_paths, because every token it signed would stop working at once.',
      },
      {
        name: 'allow_drop_audit_key',
        label: 'Allow dropping a key that signed the audit log',
        help: 'Off: verifying keys that leave out a key that signed checkpoints or prune anchors the log still holds are refused, because audit verify would then report those as signed by an unknown key.',
      },
      {
        name: 'allow_mismatch',
        label: 'Allow a file that looks like another server’s',
        help: 'Off: a file whose [issuer] (its key files aside) or [audit] differs from the running config is refused. Even with it, only the keys are applied.',
      },
    ],
    result: keysResult,
    summary: (r) => (r.changed
      ? `Issuer keys reloaded: signing with ${r.signing_kid}, ${r.added.length} key${r.added.length === 1 ? '' : 's'} added, ${r.removed.length} removed.`
      : `Issuer keys reloaded: no key changed (signing with ${r.signing_kid}).`),
  },
];

export async function reloadView(root) {
  const writes = writesAllowed();
  append(root, [
    h('div', { class: 'page-head' }, h('h1', null, 'Reload'),
      h('span', { class: 'sub' }, 'Put an edited config file in force without a restart. Each reload reads one part of the file and changes nothing else.')),
    writes === false
      ? h('p', { class: 'callout', id: 'reload-writes-off' },
        'Writes are disabled on this listener ([admin_ui] allow_write is off), so the console does not offer the reloads. Run them with the attenuo CLI against the admin API, or set allow_write = true.')
      : null,
    policyPanel(),
    RELOADS.map((spec) => reloadPanel(spec, writes)),
  ]);
}

/** The policy file is reloaded on the Policy page, after a check of the file on disk. */
function policyPanel() {
  return h('section', { class: 'panel', id: 'reload-policies' },
    h('header', null, h('h2', null, 'Policies')),
    h('p', null, 'Reloading the policy file starts on the Policy page: check the file on disk first, then reload it. A file that does not load leaves the old policies in force.'),
    h('p', null, link(['policy'], 'Check and reload the policies')));
}

function reloadPanel(spec, writes) {
  const out = h('div', { class: 'stack', id: `reload-${spec.id}-result` });
  let button = null;
  let note = null;
  if (writes !== false) {
    button = needsRole(h('button', {
      type: 'button', class: 'primary', on: { click: () => openReload(spec, out, button) },
    }), 'admin');
    append(button, [spec.button]);
    note = roleAllows('admin') ? null : h('p', { class: 'small muted' }, 'Reloading needs the admin role.');
  } else {
    note = h('p', { class: 'small muted' }, `From a shell: ${spec.cli}`);
  }
  return h('section', { class: 'panel', id: `reload-${spec.id}` },
    h('header', null, h('h2', null, spec.title), button),
    spec.what.map((p) => h('p', null, p)),
    spec.options.length && writes !== false
      ? h('p', { class: 'small muted' }, `${spec.options.length} safety check${spec.options.length === 1 ? '' : 's'} can be turned off in the confirmation, one reload at a time.`)
      : null,
    note,
    out);
}

/** The kinds of reload with a request in flight: one of each kind at a time. */
export const inFlight = new Set();

/** The confirmation: what the reload does, its options (all off), then Reload or Cancel. */
function openReload(spec, out, opener) {
  if (inFlight.has(spec.id)) return;
  const boxes = spec.options.map((o) => {
    const id = `reload-opt-${o.name}`;
    const helpId = `${id}-help`;
    const input = h('input', { type: 'checkbox', id, name: o.name, 'aria-describedby': helpId });
    return {
      name: o.name,
      input,
      node: h('div', { class: 'reload-option' },
        h('label', { class: 'check', for: id }, input, o.label, ' ', mono(o.name)),
        h('p', { class: 'small muted', id: helpId }, o.help)),
    };
  });
  const risky = h('p', { class: 'callout warn' }, 'A safety check is off for this reload: the server will not refuse what that check catches.');
  risky.hidden = true;
  for (const b of boxes) {
    b.input.addEventListener('change', () => { risky.hidden = !boxes.some((x) => x.input.checked); });
  }
  const err = h('div', { class: 'callout bad', role: 'alert', id: `reload-${spec.id}-error` });
  err.hidden = true;
  const go = h('button', { type: 'submit', class: 'primary' }, 'Reload');
  const cancel = h('button', { type: 'button', on: { click: () => { if (!inFlight.has(spec.id)) close(); } } }, 'Cancel');
  const titleId = `reload-${spec.id}-title`;
  const busy = (on) => {
    if (on) inFlight.add(spec.id);
    else inFlight.delete(spec.id);
    go.disabled = on;
    cancel.disabled = on;
    if (opener && !opener.dataset.role) opener.disabled = on;
    for (const b of boxes) b.input.disabled = on;
  };

  let close = () => {};
  let dialog = null;
  const form = h('form', {
    on: {
      submit: async (ev) => {
        ev.preventDefault();
        if (inFlight.has(spec.id)) return;
        busy(true);
        err.hidden = true;
        const body = {};
        for (const b of boxes) if (b.input.checked) body[b.name] = true;
        let r;
        try {
          r = await api(spec.path, { method: 'POST', body, quiet: QUIET });
        } catch (e) {
          busy(false);
          if (e.status === 401) return;
          if (dialog.isConnected) {
            replace(err, refusal(e));
            err.hidden = false;
          } else {
            // The page changed while the request ran: the outcome still reaches the operator.
            showError(`${spec.title} reload: ${refusalLine(e)}`);
          }
          return;
        }
        busy(false);
        close();
        replace(out, h('h3', null, 'Last reload ', h('span', { class: 'small muted' }, time(new Date().toISOString()))),
          spec.result(r));
        showNotice(spec.summary(r));
      },
    },
  },
  h('h2', { id: titleId }, `Reload the ${spec.title.toLowerCase()}?`),
  spec.what.map((p) => h('p', null, p)),
  boxes.length ? h('fieldset', { class: 'reload-options' }, h('legend', null, 'Safety checks you may turn off'), boxes.map((b) => b.node)) : null,
  risky,
  err,
  h('div', { class: 'buttons' }, cancel, go));
  ({ dialog, close } = modal(titleId, form, { busy: () => inFlight.has(spec.id) }));
  // Cancel, not Reload, has the focus: a held Enter must not confirm.
  cancel.focus();
}

/** The statuses a reload shows in its dialog instead of the status line. */
export const QUIET = [400, 403, 404, 409, 422, 500, 502, 503, 504];

/** Whether the server's answer is a refusal (nothing changed), not an unknown outcome. */
function refused(e) {
  return e.status >= 400 && e.status < 500;
}

/** A failed reload in one line, for the status line. */
export function refusalLine(e) {
  return refused(e)
    ? `refused, ${e.code}: ${e.message}. Nothing was changed.`
    : `${e.code}: ${e.message}. The result is unknown: check the audit log to see whether the reload happened.`;
}

/**
 * A failed reload. A 4xx is a refusal: the server's code and message, and nothing changed.
 * A network error (status 0) or a 5xx leaves the outcome unknown, and says so. A 404 is
 * explained as writes being off only when this listener said so at login.
 */
export function refusal(e) {
  if (e.status === 404 && writesAllowed() === false) {
    return h('p', null, 'Writes are disabled on this listener ([admin_ui] allow_write is off). Use the attenuo CLI against the admin API.');
  }
  if (!refused(e)) {
    return [
      h('p', null, h('strong', null, 'No answer: '), mono(e.code), e.status ? ` (HTTP ${e.status})` : ''),
      h('p', null, e.message),
      h('p', { class: 'small' }, 'The result is unknown: the reload may or may not have happened. The audit log shows whether it did; check it before trying again.'),
    ];
  }
  return [
    h('p', null, h('strong', null, 'Refused: '), mono(e.code), ` (HTTP ${e.status})`),
    h('p', null, e.message),
    h('p', { class: 'small' }, 'Nothing was changed.'),
  ];
}

// ---- results ----------------------------------------------------------------------------

/** Ids as a comma-separated list of monospace names, or "none". */
function ids(list) {
  if (!Array.isArray(list) || !list.length) return h('span', { class: 'muted' }, 'none');
  const out = [];
  list.forEach((x, i) => {
    if (i) out.push(', ');
    out.push(mono(String(x)));
  });
  return h('span', null, out);
}

/** Short notes from the server, one per line, or nothing. */
function notes(list, cls, title) {
  if (!Array.isArray(list) || !list.length) return null;
  return h('div', { class: `callout ${cls}` }, h('p', null, title), h('ul', null, list.map((w) => h('li', null, String(w)))));
}

export function auditLink(id) {
  return id
    ? link(['record', id], mono(id), { title: 'Open the audit record of this reload' })
    : h('span', null, 'not written: the reload stands, but the server could not record it (see its log)');
}

function operatorsResult(r) {
  return kv([
    ['Added', ids(r.added)],
    ['Removed', ids(r.removed)],
    ['Changed', ids(r.changed)],
    ['Audit record', auditLink(r.audit_id)],
  ]);
}

function agentsResult(r) {
  const row = (name, l) => h('tr', null,
    h('th', { scope: 'row' }, name),
    h('td', { class: 'num' }, mono(l.count)),
    h('td', null, short(l.sha256, 16)),
    h('td', { class: 'wrap' }, ids(l.added)),
    h('td', { class: 'wrap' }, ids(l.removed)),
    h('td', { class: 'wrap' }, ids(l.changed)));
  return h('div', { class: 'stack' },
    table(['List', 'In force', 'SHA-256', 'Added', 'Removed', 'Changed'],
      [row('[[agents]]', r.agents), row('[[peps]]', r.peps)], { short: true }),
    kv([
      ['Needs a restart', ids(r.restart_needed)],
      ['Audit record', auditLink(r.audit_id)],
    ]),
    notes(r.warnings, 'warn', 'Warnings:'),
    notes(r.restart_warnings, 'warn', 'After a restart with this file:'));
}

function keysResult(r) {
  return h('div', { class: 'stack' },
    kv([
      ['Changed', r.changed ? 'yes' : 'no: the same keys are in force'],
      ['Signing key', mono(r.signing_kid)],
      ['Previous signing key', mono(r.previous_signing_kid)],
      ['Verifying keys', ids(r.verifying_kids)],
      ['Added', ids(r.added)],
      ['Removed', ids(r.removed)],
      ['Audit signing key', r.audit_signing_kid ? mono(r.audit_signing_kid) : h('span', { class: 'muted' }, 'none')],
      ['Kept until restart', ids(r.kept_until_restart)],
      ['Needs a restart', ids(r.restart_needed)],
      ['Audit record', auditLink(r.audit_id)],
    ]),
    notes(r.warnings, 'warn', 'Warnings:'));
}
