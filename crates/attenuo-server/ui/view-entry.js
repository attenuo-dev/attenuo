// Decision view (#/entry/{seq} and #/record/{id}): one audit entry with the context needed to
// understand it: why, for whom and through which agents, which policies, whether a signed
// checkpoint covers it, and the rest of its delegation chain.
'use strict';

import {
  h, append, replace, link, mono, short, time, recordPill, leaseStatePill, table,
  empty, loading, kv, explainReason, jsonTree,
} from './dom.js';
import { api, qs } from './api.js';
import { loadPolicies } from './view-policy.js';
import { newestPruneSeq, PRUNE_TOOL } from './view-audit.js';

const TIMELINE_LIMIT = 200;

export async function entryView(root, { seq, id }) {
  const path = seq !== undefined
    ? `/admin/audit/entries/${encodeURIComponent(seq)}`
    : `/admin/audit/records/${encodeURIComponent(id)}`;
  append(root, loading());
  let view;
  try {
    view = await api(path, { quiet: [404, 400, 410] });
  } catch (e) {
    if (e.status === 401) throw e;
    if (e.status === 410 && e.code === 'audit_pruned') {
      replace(root, prunedPanel(seq, e.body || {}));
      return;
    }
    replace(root, h('section', { class: 'panel' },
      h('h1', null, seq !== undefined ? `No entry at seq ${seq}` : 'No such record'),
      h('p', null, e.message),
      h('a', { href: '#/audit' }, 'Back to the audit log')));
    return;
  }
  const { entry } = view;
  const r = entry.record;

  replace(root,
    verdict(entry),
    h('div', { class: 'grid-2' }, chainPanel(r, view.lease_states), policyPanel(r, view.policy_reloaded_after)),
    budgetPanel(r),
    integrityPanel(entry, view.covered_by_checkpoint),
    timelinePanel(entry),
    notLoggedPanel());
}

// A seq at or below a prune's boundary (410 `audit_pruned`): the entry is no longer on the
// server. The answer names the boundary (`pruned_through`), the prune's own record
// (`prune_seq`) and the first retained seq (`first`).
function prunedPanel(seq, body) {
  const num = (v) => (Number.isInteger(v) ? v : null);
  const through = num(body.pruned_through);
  const pruneSeq = num(body.prune_seq);
  const first = num(body.first);
  return h('section', { class: 'panel', 'aria-labelledby': 'pruned-title' },
    h('header', null,
      h('h1', { id: 'pruned-title' }, seq !== undefined ? ['Entry ', mono(`#${seq}`), ' was pruned'] : 'This record was pruned'),
      h('a', { href: '#/audit' }, 'Audit log')),
    h('p', { class: 'callout warn' },
      'This entry was pruned: the server deleted the start of the audit log',
      through !== null ? [' through seq ', mono(through)] : null,
      ', after it was archived. The entry is in that archive, not on the server.'),
    kv([
      ['Pruned through', through !== null ? mono(through) : undefined],
      ['Prune record', pruneSeq !== null ? link(['entry', pruneSeq], `seq ${pruneSeq}`) : undefined],
      ['First retained seq', first !== null ? link(['entry', first], `seq ${first}`) : undefined],
    ]),
    h('p', { class: 'small muted' }, 'To read it, verify the archive with ', mono('attenuo audit verify --file <archive>'), ' and look it up there.'));
}

// A prune's own record (`admin`, tool `admin.audit.prune`). Its arguments are only a digest,
// like every record's; the boundary, its hash and the archive digest are in the signed anchor.
// For the newest prune the boundary is one below the first retained seq.
function pruneRecordInfo(entry) {
  const box = h('span', { class: 'muted' }, 'looking up the boundary…');
  Promise.all([api('/admin/audit?order=desc&limit=1'), newestPruneSeq()]).then(([top, newest]) => {
    const first = Number.isInteger(top.first) ? top.first : 1;
    if (newest === entry.seq && first > 1) {
      replace(box, h('span', null, 'the newest prune: entries before ',
        link(['entry', first], `seq ${first}`), ` were pruned (boundary seq ${first - 1})`));
    } else {
      replace(box, h('span', null, 'an earlier prune; its boundary is in its signed anchor (',
        mono('attenuo audit verify'), ' checks every anchor)'));
    }
  }).catch((e) => replace(box, h('span', { class: 'muted' }, `could not look it up: ${e.message}`)));
  return box;
}

const PRUNE_EXPLAIN = 'A prune of the start of the audit log, made with the admin token: the entries up to the boundary were archived, then deleted. The boundary, its hash and the archive’s SHA-256 are in the prune’s signed anchor.';

function isPruneRecord(r) {
  return r.kind === 'admin' && r.tool === PRUNE_TOOL;
}

function verdict(entry) {
  const r = entry.record;
  const why = isPruneRecord(r) ? PRUNE_EXPLAIN : explainReason(r.reason);
  return h('section', { class: 'panel', 'aria-labelledby': 'entry-title' },
    h('header', null,
      h('h1', { id: 'entry-title' }, `Entry `, mono(`#${entry.seq}`)),
      h('a', { href: '#/audit' }, 'Audit log')),
    h('div', { class: 'verdict' },
      recordPill(r, true),
      h('span', { class: 'reason' }, r.reason),
      h('span', { class: 'explain' }, why || 'No description for this reason code.')),
    kv([
      ['Time', time(r.at)],
      ['Kind', h('span', { class: 'tag' }, r.kind)],
      ['Server / tool', mono(`${r.server} / ${r.tool}`)],
      ['Record id', mono(r.id)],
      ['Session', r.session_id ? mono(r.session_id) : undefined],
      ['DPoP-bound', r.dpop_bound ? 'yes' : 'no'],
      ['Run tainted by', taintedBy(r.labels)],
      ['Untrusted arguments', untrustedArgs(r.labels && r.labels.untrusted_args)],
      ['Action search', searchCounts(r.search)],
      ['ID-JAG ceiling', ceilingClaims(r.id_jag_ceiling)],
      ['Prune', isPruneRecord(r) ? pruneRecordInfo(entry) : undefined],
    ]));
}

// search (kind `search`, SR-117): how many candidate tools one action search evaluated and
// how many it returned as permitted. Not a decision.
function searchCounts(search) {
  if (!search) return undefined;
  return `${search.evaluated} evaluated, ${search.permitted} permitted`;
}

// id_jag_ceiling (a root_token record, SR-126): the ID-JAG claims that narrowed the root
// grant and the digest of their values. Claim names come from the server's own list.
function ceilingClaims(ceiling) {
  if (!ceiling) return undefined;
  const claims = Array.isArray(ceiling.claims) ? ceiling.claims : [];
  const names = claims.length ? claims.join(', ') : 'none (the grant was kept as it is)';
  return h('span', null, names, ' ', h('span', { class: 'muted small' }, 'claims digest '), short(ceiling.claims_digest, 16));
}

// labels.tainted_by: seqs of the tool_result records that tainted the run.
function taintedBy(labels) {
  const seqs = (labels && labels.tainted_by) || [];
  if (!seqs.length) return undefined;
  return h('span', null, seqs.flatMap((s, i) => [i ? ', ' : '', link(['entry', s], `#${s}`)]));
}

// labels.untrusted_args (ADR-0009 phase 2): which argument matched which result, and how.
// Argument names come from the agent's call; h() renders them as text.
export function untrustedArgs(args) {
  if (!args || !args.length) return undefined;
  return h('ul', null, args.map((a) => h('li', null,
    mono(a.arg), ' ', h('span', { class: 'tag' }, a.kind), ' ',
    a.seq !== undefined && a.seq !== null
      ? link(['entry', a.seq], `tool_result at seq ${a.seq}`)
      : h('span', { class: 'muted' }, 'span index unreadable'))));
}

function chainPanel(r, leaseStates) {
  // Agents and leases are both root first; admin records have leases but no agents.
  const hops = Math.max(r.agents.length, r.leases.length);
  const items = [
    h('li', { class: 'subject' },
      h('span', { class: 'hop-label' }, 'user'),
      h('strong', null, r.originating_subject)),
  ];
  for (let i = 0; i < hops; i++) {
    const lease = r.leases[i];
    const state = leaseStates.find((s) => s.lease_id === lease) || leaseStates[i];
    items.push(h('li', null,
      h('span', { class: 'hop-label' }, `hop ${i}`),
      h('strong', null, r.agents[i] ?? '—'),
      lease ? link(['lease', lease], short(lease, 14)) : null,
      lease ? leaseStatePill(state) : null,
      state && state.revoked_at
        ? h('span', { class: 'muted small' }, 'revoked ', time(state.revoked_at), state.revoke_reason ? ` (${state.revoke_reason})` : '')
        : state && state.expires_at ? h('span', { class: 'muted small' }, 'expires ', time(state.expires_at)) : null));
  }
  return h('section', { class: 'panel' },
    h('header', null, h('h2', null, 'Delegation chain'),
      r.chain_id ? h('span', { class: 'small muted' }, 'chain ', short(r.chain_id, 14)) : null),
    h('ol', { class: 'chain' }, items),
    h('p', { class: 'small muted' }, 'Lease states are as the registry sees them now, not at the time of the entry.'));
}

// Run limits (ADR-0010): `budget.charged` lists every counter an allowed call drew on, with
// what it held afterwards; `usage` is the run's usage of a destructive tool as the policy saw
// it before the call. Argument names come from tokens and catalogs; h() renders them as text.
export function budgetPanel(r) {
  const charged = (r.budget && r.budget.charged) || [];
  if (!charged.length && !r.usage) return null;
  const panel = h('section', { class: 'panel' }, h('header', null, h('h2', null, 'Run limits and usage')));
  if (charged.length) {
    const rows = charged.map((c) => {
      const lease = r.leases[c.hop];
      return h('tr', null,
        h('td', null, `hop ${c.hop} `, lease ? link(['lease', lease], short(lease, 10)) : null),
        h('td', { class: 'num' }, mono(c.cap)),
        h('td', null, h('span', { class: 'tag' }, c.kind)),
        h('td', null, c.arg ? mono(c.arg) : h('span', { class: 'muted' }, '—')),
        h('td', { class: 'num' }, mono(c.used_after)),
        h('td', { class: 'num' }, mono(c.max)),
        h('td', { class: 'num' }, mono(Math.max(0, c.max - c.used_after))));
    });
    append(panel, [
      h('p', { class: 'small muted' }, 'Every limit this call was charged against, in every hop of the chain, and what its counter held afterwards. For ', mono('distinct'), ', the counter is how many values the limit has seen.'),
      table(['Hop', 'Capability', 'Kind', 'Argument', 'Used after', 'Max', 'Left'], rows, { short: true })]);
  }
  if (r.usage) {
    append(panel, [kv([
      ['Run usage of this tool before the call', h('span', null,
        `${r.usage.calls} call${r.usage.calls === 1 ? '' : 's'}, amount ${r.usage.amount}`)],
      ['Destination seen before', r.usage.destination_seen ? 'yes' : 'no'],
    ])]);
  }
  return panel;
}

function policyPanel(r, reloadedAfter) {
  const box = h('div', { class: 'stack' });
  const panel = h('section', { class: 'panel' }, h('header', null, h('h2', null, 'Policies')));
  if (reloadedAfter !== null && reloadedAfter !== undefined) {
    append(panel, [h('p', { class: 'callout warn' },
      'Policies were reloaded after this entry (',
      link(['entry', reloadedAfter], `seq ${reloadedAfter}`),
      '). The text below is what is loaded now and may not be what made this decision.')]);
  }
  if (!r.policy_ids || r.policy_ids.length === 0) {
    append(box, [h('p', { class: 'muted small' },
      'No policy ids are recorded. Either the call was decided before the policy stage (token, lease or capability checks), or no policy matched.')]);
  } else {
    append(box, [loading()]);
    loadPolicies().then((p) => {
      const texts = new Map(p.policies.map((x) => [x.id, x.text]));
      replace(box, r.policy_ids.map((pid) => h('div', { class: 'policy-item' },
        h('h3', null, mono(pid)),
        texts.has(pid) ? h('pre', null, texts.get(pid)) : h('p', { class: 'callout warn' }, 'This policy id is not in the policy set loaded now.'))));
    }).catch((e) => replace(box, h('p', { class: 'muted small' }, `Could not load the policy text: ${e.message}`)));
  }
  append(panel, [box]);
  return panel;
}

function integrityPanel(entry, cp) {
  const r = entry.record;
  return h('section', { class: 'panel' },
    h('header', null, h('h2', null, 'Integrity')),
    kv([
      ['seq', mono(entry.seq)],
      ['prev_hash', mono(entry.prev_hash)],
      ['entry_hash', mono(entry.entry_hash)],
      ['chain_digest', mono(r.chain_digest)],
      ['arguments_digest', mono(r.arguments_digest)],
      ['chain_depth', mono(r.chain_depth)],
    ]),
    cp
      ? h('div', { class: 'callout good' },
        h('p', null, 'Covered by the signed checkpoint at ', link(['entry', cp.seq], `seq ${cp.seq}`),
          ', signed ', time(cp.at), ' with key ', mono(cp.kid), '.'),
        h('p', { class: 'small muted' }, 'Shown as stored. Verify (the Verify page) checks the signature and the chain up to it.'))
      : h('p', { class: 'callout warn' }, 'Not yet covered by a signed checkpoint. The hash chain links it to earlier entries, but no signature covers it yet.'));
}

function timelinePanel(entry) {
  const r = entry.record;
  const panel = h('section', { class: 'panel' }, h('header', null, h('h2', null, 'Same chain')));
  if (!r.chain_id) {
    append(panel, [h('p', { class: 'muted small' }, 'This record belongs to no delegation chain (an admin action).')]);
    return panel;
  }
  const box = h('div', null, loading());
  append(panel, [
    h('p', { class: 'small muted' }, 'Every record of chain ', mono(r.chain_id), ', oldest first. ',
      h('a', { href: `#/audit${qs({ chain_id: r.chain_id })}` }, 'Open in the audit explorer')),
    box]);
  api(`/admin/audit${qs({ chain_id: r.chain_id, order: 'asc', limit: TIMELINE_LIMIT })}`).then((page) => {
    if (!page.entries.length) {
      replace(box, empty('No other records for this chain.'));
      return;
    }
    const rows = page.entries.map((e) => h('tr', { class: e.seq === entry.seq ? 'fresh' : null },
      h('td', { class: 'num' }, e.seq === entry.seq ? mono(e.seq) : link(['entry', e.seq], mono(e.seq))),
      h('td', null, time(e.record.at)),
      h('td', null, h('span', { class: 'tag' }, e.record.kind)),
      h('td', null, recordPill(e.record)),
      h('td', null, e.record.agents.join(' > ') || '—'),
      h('td', { class: 'wrap' }, mono(`${e.record.server} / ${e.record.tool}`)),
      h('td', null, mono(e.record.reason))));
    replace(box,
      table(['Seq', 'Time', 'Kind', 'Decision', 'Agents', 'Server / tool', 'Reason'], rows, { short: true }),
      page.next_cursor !== null ? h('p', { class: 'small muted' }, `Showing the first ${TIMELINE_LIMIT}; the explorer has the rest.`) : null);
  }).catch((e) => replace(box, empty(`Could not load the chain: ${e.message}`)));
  return panel;
}

// ---- what the log does not hold, and a local token decoder --------------------------------

function notLoggedPanel() {
  const input = h('textarea', { id: 'jwt-input', rows: 4, spellcheck: 'false', autocomplete: 'off', placeholder: 'eyJhbGciOi…' });
  const out = h('div', { class: 'stack' });
  const decode = () => {
    const raw = input.value.trim();
    if (!raw) {
      replace(out);
      return;
    }
    try {
      const parts = raw.split('.');
      if (parts.length < 2) throw new Error('a JWT has at least two dot-separated parts');
      const header = JSON.parse(b64urlDecode(parts[0]));
      const claims = JSON.parse(b64urlDecode(parts[1]));
      replace(out,
        h('h3', null, 'Header'), jsonTree(header, true),
        h('h3', null, 'Claims'), jsonTree(claims, true),
        h('p', { class: 'small muted' }, 'Decoded only. The signature is not checked here.'));
    } catch (e) {
      replace(out, h('p', { class: 'callout bad' }, `Not a readable JWT: ${e.message}`));
    }
  };
  return h('section', { class: 'panel' },
    h('header', null, h('h2', null, 'Not in the log')),
    h('p', { class: 'small' },
      'The log stores digests, not contents: the tool arguments are only ', mono('arguments_digest'),
      ' and the capabilities each hop held are only part of ', mono('chain_digest'),
      '. To see what a token granted, decode it here.'),
    h('details', null,
      h('summary', null, 'Decode a token locally'),
      h('div', { class: 'stack' },
        h('label', { for: 'jwt-input' }, 'Delegation token (JWT)'),
        input,
        h('p', { class: 'small muted' }, 'Decoded in this browser tab. The token is never sent to the server or anywhere else.'),
        h('div', { class: 'row' },
          h('button', { type: 'button', on: { click: decode } }, 'Decode'),
          h('button', { type: 'button', on: { click: () => { input.value = ''; replace(out); } } }, 'Clear')),
        out)));
}

/** base64url (no padding) to a UTF-8 string. */
function b64urlDecode(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=');
  const bin = atob(b64);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}
