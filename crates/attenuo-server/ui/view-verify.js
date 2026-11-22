// Verify panel (#/verify): the head of the log, stored checkpoints, a full chain verification
// and, as a separate deliberate action, signing a checkpoint of the head. With
// `[audit.retention] prune = "auto"`, and for the admin role only, the state of the automatic
// prune: its settings and its last run, from the `auto` member of the prune plan.
'use strict';

import { h, append, replace, link, mono, short, time, pill, table, empty, loading, kv } from './dom.js';
import { api, showNotice, showError, roleAllows, auditPruneMode } from './api.js';

export async function verifyView(root) {
  const headBox = h('div', null, loading());
  const cpBox = h('div', null, loading());
  const verifyOut = h('div', { class: 'stack' });
  // /readyz is served on the main listener only, never on the console's own listener, so the
  // page says where to look instead of probing it (a probe here is always a 404, which the
  // browser logs as a console error).
  const readyBox = h('p', { class: 'small muted' }, 'Readiness (', mono('/readyz'), ') is served on the main listener, not on the console’s.');

  // The first retained seq the head panel shows, so the verification agrees with it.
  let first = 1;
  const verifyBtn = h('button', { type: 'button', class: 'primary', on: { click: () => runVerify(verifyBtn, verifyOut, first) } }, 'Verify now');
  const signBtn = h('button', { type: 'button', on: { click: () => confirmSign(refresh) } }, 'Sign head now…');

  append(root, [
    h('div', { class: 'page-head' }, h('h1', null, 'Verify'),
      h('span', { class: 'sub' }, 'Check the hash chain and the checkpoint signatures of the whole log.')),
    h('div', { class: 'grid-2' },
      h('section', { class: 'panel' }, h('header', null, h('h2', null, 'Log head'), signBtn), headBox, readyBox),
      h('section', { class: 'panel' }, h('header', null, h('h2', null, 'Verification'), verifyBtn), verifyOut,
        h('p', { class: 'small muted' }, 'Walks every entry and checks each stored checkpoint signature against the server’s keys. On a large log this takes a while.'))),
    autoPrunePanel(),
    h('section', { class: 'panel' }, h('header', null, h('h2', null, 'Newest checkpoints')), cpBox),
  ]);

  async function refresh() {
    const [top, cps] = await Promise.all([
      api('/admin/audit?order=desc&limit=1'),
      api('/admin/audit/checkpoints?limit=20'),
    ]);
    const newest = top.entries[0];
    first = Number.isInteger(top.first) && top.first > 1 ? top.first : 1;
    const signed = cps.checkpoints[0];
    replace(headBox, kv([
      ['Head seq', newest ? link(['entry', newest.seq], mono(newest.seq)) : mono(0)],
      ['Head hash', newest ? mono(newest.entry_hash) : h('span', { class: 'muted' }, 'empty log')],
      ['Newest entry', newest ? time(newest.record.at) : null],
      ['Newest checkpoint', signed ? h('span', null, mono(`seq ${signed.seq}`), ' · ', time(signed.at)) : h('span', { class: 'muted' }, 'none yet')],
      ['Unsigned entries', mono(String((top.head || 0) - (signed ? signed.seq : 0)))],
      ['First retained seq', first > 1
        ? h('span', null, mono(first), ' ', h('span', { class: 'muted small' }, 'entries before it were pruned'))
        : h('span', null, mono(1), ' ', h('span', { class: 'muted small' }, 'not pruned'))],
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

// `first` is the first retained seq the head panel read. A log with an anchor, or with a
// first retained seq above 1, whose report has no `pruned_through` was walked from the first
// retained entry: no anchor verified (a bad newest anchor is the tamper case), so it says so
// rather than "not pruned".
async function runVerify(btn, out, first) {
  btn.disabled = true;
  replace(out, loading());
  try {
    const r = await api('/admin/audit/verify');
    const bad = r.bad_checkpoints || [];
    const badAnchors = r.bad_anchors || [];
    const pruned = r.pruned_through !== null && r.pruned_through !== undefined;
    const unverified = !pruned && ((r.anchors ?? 0) > 0 || first > 1);
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
        ['Pruned through', pruned
          ? mono(r.pruned_through)
          : unverified
            ? h('span', null, pill('none verified', 'bad'), ' (walked from the first retained entry)')
            : h('span', { class: 'muted' }, 'not pruned')],
        ['Anchors', mono(r.anchors ?? 0)],
        ['Bad anchors', badAnchors.length ? h('span', null, pill(String(badAnchors.length), 'bad')) : h('span', { class: 'muted' }, 'none')],
      ]),
      bad.length
        ? table(['Checkpoint seq', 'Problem'], bad.map((b) => h('tr', null, h('td', { class: 'num' }, mono(b.seq)), h('td', { class: 'wrap' }, b.reason))), { short: true })
        : null,
      badAnchors.length
        ? table(['Anchor through seq', 'Problem'], badAnchors.map((b) => h('tr', null, h('td', { class: 'num' }, mono(b.through_seq)), h('td', { class: 'wrap' }, b.reason))), { short: true })
        : null,
      pruned
        ? h('p', { class: 'small muted' }, `Entries counts the retained entries only. The walk started at the prune anchor through seq ${r.pruned_through}, whose signature was checked; the pruned entries are in the archives.`)
        : null,
      unverified
        ? h('p', { class: 'callout bad' }, 'The log does not start at seq 1, but no prune anchor verified, so the walk started at the first retained entry with nothing to vouch for the entries before it. Check the bad anchors above, and the archives with ', h('span', { class: 'mono' }, 'attenuo audit verify --file'), '.')
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

// ---- automatic prune --------------------------------------------------------------------

/** What each reason of an automatic run means, in one line. */
const RUN_REASONS = {
  ok: 'The run pruned the log.',
  nothing_to_prune: 'Nothing past the last boundary is at a signed checkpoint yet.',
  prune_too_recent: 'No signed checkpoint is old enough: everything newer than keep_seconds stays.',
  sink_behind: 'The audit sink has not delivered a checkpoint at or past the boundary yet, or the last anchor.',
  prune_live_run: 'A run that is still live started at or before the boundary.',
  prune_in_progress: 'The rows of an earlier prune are still being deleted.',
  prune_not_at_checkpoint: 'The boundary is not at a signed checkpoint.',
  concurrent_prune: 'Another prune changed the log while this run worked.',
  clock_jump: 'The wall clock moved more than an hour away from the monotonic clock, so the run did nothing.',
  verify_failed: 'The entries it would prune do not verify, so nothing was pruned.',
  archive_write_failed: 'The archive file could not be written, so nothing was pruned.',
  archive_exists: 'archive_dir already holds a different file of the archive’s name; the server never replaces it.',
  archive_verify_failed: 'The archive file, read back, does not verify, so nothing was pruned.',
  error: 'The store failed, so nothing was pruned.',
  panic: 'The run stopped on an internal error, so nothing was pruned.',
};

/** Seconds in the largest whole unit (`90 days`), or `N seconds`. */
export function humanSeconds(s) {
  if (!Number.isInteger(s) || s < 0) return String(s);
  const units = [[86400, 'day'], [3600, 'hour'], [60, 'minute'], [1, 'second']];
  for (const [n, name] of units) {
    if (s >= n && s % n === 0) {
      const v = s / n;
      return `${v.toLocaleString('en')} ${name}${v === 1 ? '' : 's'}`;
    }
  }
  return '0 seconds';
}

function seconds(s) {
  return h('span', null, humanSeconds(s), ' ', h('span', { class: 'muted small' }, `(${s} s)`));
}

/**
 * The automatic prune: shown only when the server prunes on its own and the operator has the
 * admin role, which `GET /admin/audit/prune/plan` needs. Otherwise nothing is drawn and nothing
 * is asked, so a server without it logs no refused request.
 */
function autoPrunePanel() {
  if (auditPruneMode() !== 'auto' || !roleAllows('admin')) return null;
  const box = h('div', { class: 'stack' }, loading());
  const panel = h('section', { class: 'panel', id: 'auto-prune', 'aria-labelledby': 'auto-prune-title' },
    h('header', null, h('h2', { id: 'auto-prune-title' }, 'Automatic prune')), box);
  api('/admin/audit/prune/plan', { quiet: [403, 409, 500] })
    .then((plan) => replace(box, autoPruneState(plan.auto)))
    .catch((e) => {
      if (e.status === 401) return;
      replace(box, h('p', { class: 'callout bad' }, `The prune plan could not be read: `, mono(e.code), ` ${e.message}`));
    });
  return panel;
}

/** The `auto` member of the plan: null unless `prune = "auto"`. */
export function autoPruneState(auto) {
  if (!auto || typeof auto !== 'object') {
    return h('p', { class: 'muted' }, 'The server does not prune the audit log on its own.');
  }
  return [
    h('div', { class: 'row' }, pill('on', 'ok', true),
      h('span', null, 'The server prunes the audit log on its own ([audit.retention] prune = "auto").')),
    kv([
      ['Keeps', seconds(auto.keep_seconds)],
      ['Checks every', seconds(auto.interval_seconds)],
      ['At most per run', Number.isInteger(auto.max_entries_per_run) ? `${auto.max_entries_per_run.toLocaleString('en')} entries` : undefined],
      ['Archive directory', auto.archive_dir ? mono(auto.archive_dir) : pill('not set', 'warn')],
    ]),
    auto.archive_dir
      ? h('p', { class: 'small muted' }, 'Each prune first writes the entries it removes to a file in this directory, checks it, and signs its digest into the prune anchor.')
      : h('p', { class: 'callout warn', id: 'auto-prune-no-archive' },
        'No archive directory is set ([audit.retention] archive_dir): the automatic prune deletes the entries it removes and keeps no copy. The shipped checkpoints and anchors prove what was pruned, but not what the entries said.'),
    h('h3', null, 'Last run'),
    lastRun(auto.last_run),
  ];
}

function lastRun(run) {
  if (!run) {
    return h('p', { class: 'muted', id: 'auto-prune-no-run' }, 'No run yet since the server started. The first run is one interval after start, and the last run is not kept across a restart.');
  }
  const kind = run.outcome === 'pruned' ? 'ok' : run.outcome === 'failed' ? 'bad' : '';
  const explain = Object.prototype.hasOwnProperty.call(RUN_REASONS, run.reason) ? RUN_REASONS[run.reason] : null;
  const through = Number.isInteger(run.through) ? run.through : null;
  return h('div', { class: 'stack', id: 'auto-prune-last-run' },
    kv([
      ['Time', time(run.at)],
      ['Outcome', pill(run.outcome, kind)],
      ['Reason', h('span', null, mono(run.reason), explain ? h('span', { class: 'muted small' }, ` ${explain}`) : null)],
      [run.outcome === 'pruned' ? 'Pruned through' : 'Boundary tried', through !== null ? mono(through) : h('span', { class: 'muted' }, 'none')],
      ['Prune record', Number.isInteger(run.prune_seq) ? link(['entry', run.prune_seq], `seq ${run.prune_seq}`) : h('span', { class: 'muted' }, 'none')],
      ['Archive file', run.archive ? mono(run.archive) : h('span', { class: 'muted' }, 'none')],
      ['Detail', run.detail ? h('span', null, run.detail) : undefined],
    ]));
}
