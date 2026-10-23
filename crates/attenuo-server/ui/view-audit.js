// Audit explorer (#/audit): the log newest first, with filters, paging both ways, a "follow"
// mode and export of the range on screen.
//
// Filters live in the hash query (#/audit?decision=deny&chain_id=...), so Back works and a
// filtered view can be bookmarked. The admin token never goes in the URL.
'use strict';

import {
  h, append, replace, link, mono, short, time, decisionPill, table, empty, loading,
  explainReason,
} from './dom.js';
import { api, download, qs } from './api.js';

const PAGE = 100;
// A filtered page reads at most 50,000 seqs and may come back short; keep following the
// cursor this many times before showing what we have.
const MAX_HOPS = 20;
const FOLLOW_MS = 2000;
// Follow mode keeps at most this many rows on screen.
const FOLLOW_CAP = 500;

export const KINDS = ['decision', 'exchange', 'root_token', 'lease_renew', 'lease_revoke', 'admin'];
const TEXT_FILTERS = [
  ['reason', 'Reason', 'policy_deny'],
  ['subject', 'Subject', 'alice'],
  ['agent', 'Agent', 'coder'],
  ['server', 'Server', 'github'],
  ['tool', 'Tool', 'read_file'],
  ['chain_id', 'Chain id', 'root lease id'],
  ['lease', 'Lease', 'lease id'],
];
const FILTER_KEYS = ['kind', 'decision', ...TEXT_FILTERS.map(([k]) => k), 'since', 'until'];

/** Read the filters out of the hash query. */
function filtersFrom(params) {
  const f = {};
  for (const k of FILTER_KEYS) {
    const v = params.get(k);
    if (v) f[k] = v;
  }
  return f;
}

/** Navigate to the audit view with these filters (the router re-renders). */
function goWithFilters(filters) {
  const target = `#/audit${qs(filters)}`;
  if (location.hash === target) window.dispatchEvent(new HashChangeEvent('hashchange'));
  else location.hash = target;
}

// datetime-local values are local wall-clock time; the API wants RFC 3339 UTC.
function localToRfc3339(value) {
  if (!value) return '';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? '' : d.toISOString();
}

function rfc3339ToLocal(value) {
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// ---- fetching -----------------------------------------------------------------------------

/** Newest first, below `before` (or from the head), following short filtered pages. */
async function fetchOlder(filters, before) {
  let entries = [];
  let cursor = before;
  let first = null;
  let last = null;
  for (let hop = 0; hop < MAX_HOPS; hop++) {
    const page = await api(`/admin/audit${qs({ ...filters, order: 'desc', limit: PAGE - entries.length, before: cursor })}`);
    first = first || page;
    last = page;
    entries = entries.concat(page.entries);
    if (entries.length >= PAGE || page.prev === null) break;
    cursor = page.prev;
  }
  return { entries, prev: last.prev, next: first.next, head: first.head };
}

/** Oldest first from `from`, following short filtered pages; returns at most `limit`. */
async function fetchNewer(filters, from, limit = PAGE) {
  let entries = [];
  let cursor = from;
  let last = null;
  for (let hop = 0; hop < MAX_HOPS; hop++) {
    const page = await api(`/admin/audit${qs({ ...filters, order: 'asc', limit: limit - entries.length, from: cursor })}`);
    last = page;
    entries = entries.concat(page.entries);
    if (entries.length >= limit || page.next === null) break;
    cursor = page.next;
  }
  return { entries, next: last.next, head: last.head };
}

// ---- rendering ----------------------------------------------------------------------------

function row(entry, onChain, fresh) {
  const r = entry.record;
  const reason = explainReason(r.reason);
  const agents = r.agents && r.agents.length ? r.agents.join(' > ') : '—';
  const leases = (r.leases || []).map((l, i) => [i ? ' ' : null, link(['lease', l], short(l, 8))]);
  return h('tr', { class: fresh ? 'fresh' : null },
    h('td', { class: 'num' }, link(['entry', entry.seq], mono(entry.seq))),
    h('td', null, time(r.at)),
    h('td', null, h('span', { class: 'tag' }, r.kind)),
    h('td', null, decisionPill(r.decision)),
    h('td', { class: 'wrap' }, mono(`${r.server} / ${r.tool}`)),
    h('td', { class: 'wrap' }, agents),
    h('td', { class: 'wrap' }, r.originating_subject),
    h('td', null, mono(r.reason, { title: reason || 'no description for this code' })),
    h('td', null, r.chain_id
      ? h('button', { type: 'button', class: 'linkish', title: `Show only chain ${r.chain_id}`, on: { click: () => onChain(r.chain_id) } }, short(r.chain_id, 8))
      : h('span', { class: 'muted' }, '—')),
    h('td', null, leases.length ? leases : h('span', { class: 'muted' }, '—')));
}

const HEADERS = ['Seq', 'Time', 'Kind', 'Decision', 'Server / tool', 'Agents', 'Subject', 'Reason', 'Chain', 'Leases'];

function filterForm(filters) {
  const kinds = new Set((filters.kind || '').split(',').filter(Boolean));
  const kindBoxes = KINDS.map((k) => h('label', { class: 'check' },
    h('input', { type: 'checkbox', name: 'kind', value: k, checked: kinds.has(k) }), k));
  const decision = h('select', { id: 'f-decision', name: 'decision' },
    h('option', { value: '' }, 'any'),
    h('option', { value: 'allow', selected: filters.decision === 'allow' }, 'allow'),
    h('option', { value: 'deny', selected: filters.decision === 'deny' }, 'deny'));
  const texts = TEXT_FILTERS.map(([k, label, ph]) => h('div', { class: 'field' },
    h('label', { for: `f-${k}` }, label),
    h('input', { id: `f-${k}`, name: k, value: filters[k] || '', placeholder: ph, autocomplete: 'off', spellcheck: 'false' })));
  const since = h('input', { id: 'f-since', name: 'since', type: 'datetime-local', step: 1, value: rfc3339ToLocal(filters.since) });
  const until = h('input', { id: 'f-until', name: 'until', type: 'datetime-local', step: 1, value: rfc3339ToLocal(filters.until) });

  const form = h('form', {
    class: 'filters',
    on: {
      submit: (ev) => {
        ev.preventDefault();
        const data = new FormData(form);
        const next = {};
        const ks = data.getAll('kind');
        if (ks.length) next.kind = ks.join(',');
        if (data.get('decision')) next.decision = data.get('decision');
        for (const [k] of TEXT_FILTERS) {
          const v = String(data.get(k) || '').trim();
          if (v) next[k] = v;
        }
        const s = localToRfc3339(since.value);
        const u = localToRfc3339(until.value);
        if (s) next.since = s;
        if (u) next.until = u;
        goWithFilters(next);
      },
    },
  },
  h('fieldset', null, h('legend', null, 'Kind'), kindBoxes),
  h('div', { class: 'field' }, h('label', { for: 'f-decision' }, 'Decision'), decision),
  texts,
  h('div', { class: 'field' }, h('label', { for: 'f-since' }, 'Since (local time)'), since),
  h('div', { class: 'field' }, h('label', { for: 'f-until' }, 'Until (local time)'), until),
  h('div', { class: 'actions' },
    h('button', { type: 'submit', class: 'primary' }, 'Apply filters'),
    h('button', { type: 'button', on: { click: () => goWithFilters({}) } }, 'Clear')));
  return form;
}

export async function auditView(root, params) {
  const filters = filtersFrom(params);
  const active = Object.keys(filters).length;

  const state = {
    entries: [], // newest first, as shown
    prev: null, // `before` for older entries
    next: null, // `from` for newer entries; null when the page reaches the head
    head: 0,
    timer: null,
    polling: false,
    fresh: new Set(),
  };

  const tableBox = h('div', null, loading());
  const info = h('span', { class: 'muted small' });
  const olderBtn = h('button', { type: 'button', on: { click: () => load('older') } }, 'Older');
  const newerBtn = h('button', { type: 'button', on: { click: () => load('newer') } }, 'Newer');
  const newestBtn = h('button', { type: 'button', on: { click: () => load('newest') } }, 'Newest');
  const followBtn = h('button', { type: 'button', 'aria-pressed': 'false', title: 'Check for new entries every 2 seconds', on: { click: toggleFollow } }, 'Follow');
  const exportBtn = h('button', { type: 'button', on: { click: exportRange } }, 'Export this range');

  append(root, [
    h('div', { class: 'page-head' }, h('h1', null, 'Audit log'),
      h('span', { class: 'sub' }, 'Every decision, token issuance, renewal and admin action, newest first.')),
    h('details', { class: 'panel', open: active > 0 },
      h('summary', null, active ? `Filters (${active} active)` : 'Filters'),
      filterForm(filters)),
    h('div', { class: 'pager' }, newestBtn, newerBtn, olderBtn, followBtn, h('span', { class: 'spacer' }), info, exportBtn),
    tableBox,
  ]);

  function onChain(id) {
    goWithFilters({ ...filters, chain_id: id });
  }

  function render() {
    olderBtn.disabled = state.prev === null;
    newerBtn.disabled = state.next === null;
    newestBtn.disabled = state.next === null;
    exportBtn.disabled = state.entries.length === 0;
    const n = state.entries.length;
    info.textContent = n
      ? `seq ${state.entries[n - 1].seq}–${state.entries[0].seq} · head ${state.head}`
      : `head ${state.head}`;
    if (!n) {
      replace(tableBox, empty(active
        ? 'No entries match these filters in this range. Try Older, or clear the filters.'
        : 'The audit log is empty. Decisions appear here once agents start calling tools.'));
      return;
    }
    replace(tableBox, table(HEADERS, state.entries.map((e) => row(e, onChain, state.fresh.has(e.seq)))));
  }

  async function load(which) {
    stopFollow();
    replace(tableBox, loading());
    try {
      if (which === 'newer' && state.next !== null) {
        const res = await fetchNewer(filters, state.next);
        if (res.entries.length === 0) return load('newest');
        state.entries = res.entries.slice().reverse();
        state.next = res.next;
        state.head = res.head;
        const lowest = state.entries[state.entries.length - 1].seq;
        state.prev = lowest > 1 ? lowest : null;
      } else {
        const res = await fetchOlder(filters, which === 'older' ? state.prev : undefined);
        state.entries = res.entries;
        state.prev = res.prev;
        state.next = res.next;
        state.head = res.head;
      }
      state.fresh.clear();
      render();
    } catch (e) {
      replace(tableBox, empty(`Could not load the log: ${e.message}`));
      if (e.status === 401) throw e;
    }
  }

  // ---- follow ---------------------------------------------------------------------------

  function stopFollow() {
    clearInterval(state.timer);
    state.timer = null;
    followBtn.setAttribute('aria-pressed', 'false');
    followBtn.textContent = 'Follow';
  }

  async function toggleFollow() {
    if (state.timer) {
      stopFollow();
      return;
    }
    if (state.next !== null) await load('newest');
    followBtn.setAttribute('aria-pressed', 'true');
    followBtn.textContent = 'Following';
    state.timer = setInterval(poll, FOLLOW_MS);
  }

  // Reads only `head` (a one-entry read, which signs nothing), and fetches the new entries
  // only when it moved.
  async function poll() {
    if (state.polling) return;
    state.polling = true;
    try {
      const top = await api('/admin/audit?order=desc&limit=1');
      if (top.head > state.head) {
        const res = await fetchNewer(filters, state.head + 1, FOLLOW_CAP);
        state.head = res.head;
        if (res.entries.length) {
          for (const e of res.entries) state.fresh.add(e.seq);
          state.entries = res.entries.slice().reverse().concat(state.entries).slice(0, FOLLOW_CAP);
          const lowest = state.entries[state.entries.length - 1].seq;
          state.prev = lowest > 1 ? lowest : null;
        }
        render();
      }
    } catch {
      stopFollow();
    } finally {
      state.polling = false;
    }
  }

  async function exportRange() {
    const n = state.entries.length;
    if (!n) return;
    const from = state.entries[n - 1].seq;
    const to = state.entries[0].seq;
    exportBtn.disabled = true;
    try {
      await download(`/admin/audit/export${qs({ from, to })}`, `attenuo-audit-${from}-${to}.ndjson`);
    } finally {
      exportBtn.disabled = false;
    }
  }

  exportBtn.title = 'Download every entry between the oldest and newest seq on screen, unfiltered, with the checkpoints in that range';
  await load('newest');
  return stopFollow;
}
