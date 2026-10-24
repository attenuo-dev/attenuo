// Verify panel (#/verify): the head of the log, stored checkpoints, a full chain verification
// and, as a separate deliberate action, signing a checkpoint of the head.
'use strict';

import { h, append, replace, link, mono, short, time, pill, table, empty, loading, kv } from './dom.js';
import { api, showNotice, showError } from './api.js';

export async function verifyView(root) {
  const headBox = h('div', null, loading());
  const cpBox = h('div', null, loading());
  const verifyOut = h('div', { class: 'stack' });
  // /readyz is served on the main listener only, never on the console's own listener, so the
  // page says where to look instead of probing it (a probe here is always a 404, which the
  // browser logs as a console error).
  const readyBox = h('p', { class: 'small muted' }, 'Readiness (', mono('/readyz'), ') is served on the main listener, not on the console’s.');

  const verifyBtn = h('button', { type: 'button', class: 'primary', on: { click: () => runVerify(verifyBtn, verifyOut) } }, 'Verify now');
  const signBtn = h('button', { type: 'button', on: { click: () => confirmSign(refresh) } }, 'Sign head now…');

  append(root, [
    h('div', { class: 'page-head' }, h('h1', null, 'Verify'),
      h('span', { class: 'sub' }, 'Check the hash chain and the checkpoint signatures of the whole log.')),
    h('div', { class: 'grid-2' },
      h('section', { class: 'panel' }, h('header', null, h('h2', null, 'Log head'), signBtn), headBox, readyBox),
      h('section', { class: 'panel' }, h('header', null, h('h2', null, 'Verification'), verifyBtn), verifyOut,
        h('p', { class: 'small muted' }, 'Walks every entry and checks each stored checkpoint signature against the server’s keys. On a large log this takes a while.'))),
    h('section', { class: 'panel' }, h('header', null, h('h2', null, 'Newest checkpoints')), cpBox),
  ]);

  async function refresh() {
    const [top, cps] = await Promise.all([
      api('/admin/audit?order=desc&limit=1'),
      api('/admin/audit/checkpoints?limit=20'),
    ]);
    const newest = top.entries[0];
    const signed = cps.checkpoints[0];
    replace(headBox, kv([
      ['Head seq', newest ? link(['entry', newest.seq], mono(newest.seq)) : mono(0)],
      ['Head hash', newest ? mono(newest.entry_hash) : h('span', { class: 'muted' }, 'empty log')],
      ['Newest entry', newest ? time(newest.record.at) : null],
      ['Newest checkpoint', signed ? h('span', null, mono(`seq ${signed.seq}`), ' · ', time(signed.at)) : h('span', { class: 'muted' }, 'none yet')],
      ['Unsigned entries', mono(String((top.head || 0) - (signed ? signed.seq : 0)))],
    ]));
    if (!cps.checkpoints.length) {
      replace(cpBox, empty('No checkpoints are stored yet. The server signs them on its schedule, or use Sign head now.'));
    } else {
      replace(cpBox, table(['Seq', 'Signed at', 'Key id', 'Head hash', 'Signature'], cps.checkpoints.map((c) => h('tr', null,
        h('td', { class: 'num' }, link(['entry', c.seq], mono(c.seq))),
        h('td', null, time(c.at)),
        h('td', null, mono(c.kid)),
        h('td', null, short(c.head_hash, 16)),
        h('td', null, short(c.signature, 16)))), { short: true }));
    }
  }

  await refresh();
}

async function runVerify(btn, out) {
  btn.disabled = true;
  replace(out, loading());
  try {
    const r = await api('/admin/audit/verify');
    const bad = r.bad_checkpoints || [];
    replace(out,
      h('div', { class: 'row' },
        pill(r.ok ? 'chain ok' : 'chain broken', r.ok ? 'ok' : 'bad', true),
        h('span', { class: 'small muted' }, `checked at ${new Date().toLocaleTimeString()}`)),
      kv([
        ['Entries', mono(r.entries)],
        ['First bad seq', r.first_bad_seq !== null && r.first_bad_seq !== undefined ? link(['entry', r.first_bad_seq], mono(r.first_bad_seq)) : h('span', { class: 'muted' }, 'none')],
        ['Checkpoints', mono(r.checkpoints)],
        ['Last signed seq', r.last_signed_seq !== null && r.last_signed_seq !== undefined ? mono(r.last_signed_seq) : h('span', { class: 'muted' }, 'none')],
        ['Unsigned tail', mono(r.unsigned_tail)],
        ['Bad checkpoints', bad.length ? h('span', null, pill(String(bad.length), 'bad')) : h('span', { class: 'muted' }, 'none')],
      ]),
      bad.length
        ? table(['Checkpoint seq', 'Problem'], bad.map((b) => h('tr', null, h('td', { class: 'num' }, mono(b.seq)), h('td', { class: 'wrap' }, b.reason))), { short: true })
        : null,
      r.unsigned_tail > 0
        ? h('p', { class: 'callout warn' }, `${r.unsigned_tail} newest entr${r.unsigned_tail === 1 ? 'y is' : 'ies are'} not covered by a signature yet.`)
        : null);
  } catch (e) {
    if (e.status !== 401) replace(out, h('p', { class: 'callout bad' }, `Verification failed to run: ${e.message}`));
  } finally {
    btn.disabled = false;
  }
}

// GET /admin/audit/checkpoint writes a checkpoint when the head has none, so it gets its own
// button and a confirmation; nothing on this page calls it on load.
function confirmSign(after) {
  const dialog = h('dialog', { 'aria-labelledby': 'sign-title' });
  const close = () => {
    dialog.close();
    dialog.remove();
  };
  const go = h('button', { type: 'submit', class: 'primary' }, 'Sign checkpoint');
  const form = h('form', {
    on: {
      submit: async (ev) => {
        ev.preventDefault();
        go.disabled = true;
        try {
          const cp = await api('/admin/audit/checkpoint');
          close();
          showNotice(`Checkpoint at seq ${cp.seq} signed with key ${cp.kid}.`);
          await after();
        } catch (e) {
          close();
          if (e.status !== 401) showError(`Signing failed: ${e.message}`);
        }
      },
    },
  },
  h('h2', { id: 'sign-title' }, 'Sign a checkpoint of the head?'),
  h('p', null, 'This stores a new signed checkpoint covering every entry up to the current head (or returns the existing one if the head is already signed). It adds a row to the checkpoint table; it changes no audit entry.'),
  h('div', { class: 'buttons' }, h('button', { type: 'button', on: { click: close } }, 'Cancel'), go));
  append(dialog, [form]);
  dialog.addEventListener('cancel', () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();
}
