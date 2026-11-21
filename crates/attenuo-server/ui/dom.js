// DOM building and formatting helpers shared by every view.
//
// Every node the console shows is made here with createElement, textContent and setAttribute.
// No HTML string is ever parsed: record fields (tool names, subjects, reasons) come from agents
// and upstreams the operator does not control, so they must only ever become text. The page's
// CSP also enforces Trusted Types, so a string handed to an HTML sink would throw.
'use strict';

// Attributes h() will set. Anything else (event handler attributes, style, src) throws, so a
// typo or a careless edit fails loudly in development instead of opening a hole.
const ALLOWED_ATTRS = new Set([
  'class', 'id', 'href', 'title', 'type', 'name', 'value', 'for', 'placeholder', 'rows',
  'role', 'tabindex', 'datetime', 'colspan', 'autocomplete', 'spellcheck', 'min', 'max',
  'step', 'readonly', 'required', 'disabled', 'checked', 'multiple', 'selected', 'open',
  'scope', 'lang', 'inputmode', 'maxlength', 'aria-label', 'aria-current', 'aria-pressed',
  'aria-expanded', 'aria-controls', 'aria-describedby', 'aria-live', 'aria-busy',
  'aria-labelledby', 'data-page', 'autocapitalize', 'autofocus', 'download',
]);

// Links may only point inside the console (hash routes) or at the same-origin admin API.
function safeHref(value) {
  const v = String(value);
  if (v.startsWith('#/') || v.startsWith('/admin/')) return v;
  throw new Error(`refusing href ${JSON.stringify(v)}`);
}

/**
 * h(tag, attrs, ...children): create an element.
 *
 * attrs: plain attributes (allowlisted), boolean attributes as true/false, `on: {event: fn}`
 * for listeners (added with addEventListener, never as attributes). Children are nodes,
 * strings (become text nodes), numbers, arrays (flattened), or null/undefined/false (skipped).
 */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === 'on') {
      for (const [ev, fn] of Object.entries(value)) el.addEventListener(ev, fn);
      continue;
    }
    if (!ALLOWED_ATTRS.has(key)) throw new Error(`attribute ${key} is not allowed`);
    if (value === false || value === null || value === undefined) continue;
    if (value === true) {
      el.setAttribute(key, '');
    } else if (key === 'href') {
      el.setAttribute('href', safeHref(value));
    } else {
      el.setAttribute(key, String(value));
    }
  }
  append(el, children);
  return el;
}

/** Append children (same rules as h(); one child or an array) to el. */
export function append(el, children) {
  for (const c of [children].flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

/** Remove every child of el, then append the given ones. */
export function replace(el, ...children) {
  el.replaceChildren();
  return append(el, children);
}

/** An in-console link; each path segment is URL-encoded so ids cannot change the route. */
export function link(segments, text, attrs = {}) {
  const href = '#/' + segments.map((s) => encodeURIComponent(String(s))).join('/');
  return h('a', { ...attrs, href }, text);
}

/** A monospace span, for ids, hashes and seqs. */
export function mono(text, attrs = {}) {
  return h('span', { ...attrs, class: `mono ${attrs.class || ''}`.trim() }, text ?? '');
}

/** Shorten a long id or hash for a table cell; the full value goes in the title. */
export function short(text, keep = 12) {
  const s = String(text ?? '');
  if (s.length <= keep + 1) return mono(s);
  return mono(s.slice(0, keep) + '…', { title: s });
}

/** An RFC 3339 time shown in local time, with the UTC value as a tooltip. */
export function time(rfc3339) {
  if (!rfc3339) return h('span', { class: 'muted' }, '—');
  const d = new Date(rfc3339);
  if (Number.isNaN(d.getTime())) return mono(rfc3339);
  const local = d.toLocaleString(undefined, {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
  return h('time', { datetime: rfc3339, title: `${d.toISOString()} (UTC)` }, local);
}

/** A coloured pill. kind picks the colour class (allow, deny, active, expired, ...). */
export function pill(text, kind = '', big = false) {
  return h('span', { class: `pill ${kind}${big ? ' big' : ''}` }, text);
}

export function decisionPill(decision, big = false) {
  return pill(decision || '?', decision === 'allow' ? 'allow' : decision === 'deny' ? 'deny' : '', big);
}

// Records that always carry `allow` without deciding anything. Approval records
// stay pills: a request is a deny, and a grant is an allow or a deny.
const NOT_DECISIONS = new Set(['tool_result', 'search']);

/** The decision cell of an audit row: a pill for a decision, a dash for a record that is none. */
export function recordPill(record, big = false) {
  if (NOT_DECISIONS.has(record.kind)) {
    return h('span', { class: 'muted', title: `A ${record.kind} record is not a decision` }, '—');
  }
  return decisionPill(record.decision, big);
}

/** Lease state from a registry row or tree node: active, revoked or expired. */
export function leaseState(row) {
  if (!row || row.known === false) return { label: 'unknown', kind: '' };
  if (row.revoked_at) return { label: 'revoked', kind: 'revoked' };
  if (row.active) return { label: 'active', kind: 'active' };
  return { label: 'expired', kind: 'expired' };
}

export function leaseStatePill(row) {
  const s = leaseState(row);
  return pill(s.label, s.kind);
}

/** A table inside a horizontally scrolling wrapper, with sticky headers (CSS). */
export function table(headers, rows, opts = {}) {
  const thead = h('thead', null, h('tr', null, headers.map((t) => h('th', { scope: 'col' }, t))));
  const tbody = h('tbody', null, rows);
  return h('div', { class: `table-wrap${opts.short ? ' short' : ''}` }, h('table', null, thead, tbody));
}

export function empty(text) {
  return h('div', { class: 'empty' }, text);
}

export function loading() {
  return h('div', { class: 'loading', 'aria-busy': 'true' });
}

/** Label/value pairs as a <dl>. pairs: [[label, value], ...]; null values are skipped. */
export function kv(pairs) {
  const dl = h('dl', { class: 'kv' });
  for (const [k, v] of pairs) {
    if (v === undefined) continue;
    append(dl, [h('dt', null, k), h('dd', null, v === null ? h('span', { class: 'muted' }, 'null') : v)]);
  }
  return dl;
}

/**
 * Reason codes and what they mean in one line. Covers every REASON_* constant in the
 * workspace plus `policy_invalid` (a failed policy reload). Unknown codes show the code only.
 */
export const REASONS = {
  // Policy engine (attenuo-policy).
  policy_allow: 'A Cedar policy permitted the call.',
  policy_deny: 'Cedar denied the call: a forbid matched or no permit did.',
  policy_error: 'The request could not be evaluated safely, so it was denied.',
  capability_denied: 'The tool is not among the capabilities delegated to the calling agent.',
  tool_not_in_catalog: 'The tool is not in the policy catalog and unknown tools are denied.',
  invalid_name: 'The server or tool name is not a valid name.',
  attribute_type_mismatch: 'A user attribute did not have the type the catalog declares.',
  input_type_mismatch: 'A call argument did not have the type the catalog declares.',
  // Token checks at the proxy (attenuo-proxy auth).
  missing_token: 'The request carried no delegation token.',
  invalid_token: 'The token failed verification (signature, issuer, audience or chain).',
  token_expired: 'The token had expired.',
  dpop_required: 'The token is bound to a key, but the request had no DPoP proof.',
  invalid_dpop_proof: 'The DPoP proof did not verify for this token and request.',
  use_dpop_nonce: 'The DPoP proof lacked the current server nonce; the client should retry.',
  // Proxy limits and upstream (attenuo-proxy).
  session_mismatch: 'The MCP session id is bound to a different principal.',
  session_registry_full: 'Every slot in the session registry is taken.',
  too_many_sessions: 'This principal already holds its maximum number of live sessions.',
  request_too_large: 'The request body was over the configured limit.',
  upstream_body_too_large: 'The upstream response was over the configured limit.',
  upstream_unreachable: 'The upstream MCP server could not be reached.',
  upstream_timeout: 'The upstream MCP server did not answer in time; it may have acted on the request.',
  tool_not_listed: 'The upstream never listed this tool and the catalog does not know it.',
  // Lease and audit stages (attenuo-server).
  lease_revoked: 'A lease in the chain, or one of its ancestors, was revoked.',
  lease_expired: 'A lease in the chain had expired.',
  lease_unknown: 'A lease in the chain is not in the registry, so the call failed closed.',
  lease_error: 'The lease registry could not be read, so the call failed closed.',
  audit_error: 'The decision could not be written to the audit log, so the call failed closed.',
  // Issuance and admin records.
  token_issued: 'A token was issued (root mint or exchange).',
  lease_renewed: 'A lease was renewed.',
  admin_action: 'An action taken with the admin token.',
  search_answered: 'An AuthZEN action search was answered. Not a decision: nothing was allowed, charged or approved.',
  policy_invalid: 'A policy reload was refused because the file did not load.',
  // Approvals (ADR-0009).
  approval_required: 'A policy gated the call on an approval; the agent got JSON-RPC -32008.',
  approval_requested: 'An approval was opened for this exact call.',
  approval_granted: 'A user or the operator granted the approval; one identical retry may run.',
  approval_declined: 'A user or the operator declined the approval.',
  // Run limits (ADR-0010).
  budget_exhausted: 'The call would take a run limit in the token past its maximum; no approval passes it.',
  budget_error: 'The run-limit counters could not be read or written, so the call failed closed.',
  limit_arg_invalid: 'A run limit could not count the call: its argument was missing or not a value it can count.',
};

export function explainReason(code) {
  return Object.prototype.hasOwnProperty.call(REASONS, code) ? REASONS[code] : null;
}

// Claims that are Unix times get a readable time next to them.
const TIME_CLAIMS = new Set(['exp', 'iat', 'nbf', 'auth_time']);

/** A JSON value as a nested list of text nodes. */
export function jsonTree(value, top = false) {
  const ul = h('ul', { class: `tree${top ? ' top' : ''}` });
  const entries = Array.isArray(value) ? value.map((v, i) => [i, v]) : Object.entries(value);
  for (const [k, v] of entries) {
    const label = h('span', { class: 'k' }, `${k}: `);
    if (v !== null && typeof v === 'object') {
      const kids = Array.isArray(v) ? `[${v.length}]` : '{…}';
      append(ul, [h('li', null, label, h('span', { class: 'muted' }, kids), jsonTree(v))]);
    } else {
      const cls = typeof v === 'string' ? 'str' : typeof v === 'number' ? 'numv' : '';
      const shown = typeof v === 'string' ? JSON.stringify(v) : String(v);
      const extra = TIME_CLAIMS.has(k) && typeof v === 'number'
        ? h('span', { class: 'muted' }, '  ', time(new Date(v * 1000).toISOString()))
        : null;
      append(ul, [h('li', null, label, h('span', { class: cls }, shown), extra)]);
    }
  }
  if (!entries.length) append(ul, [h('li', { class: 'muted' }, Array.isArray(value) ? '[]' : '{}')]);
  return ul;
}

