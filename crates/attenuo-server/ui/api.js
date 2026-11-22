// The one fetch wrapper the console uses, and the admin token it carries.
//
// The token lives in a module-scoped variable and nowhere else: not in localStorage,
// sessionStorage, a cookie or the URL. Reloading the page, pressing Lock or 15 minutes without
// user input forget it. Every request is same-origin (the console listener serves both the page
// and the API), so the browser never sends the token anywhere else.
'use strict';

import { h, replace } from './dom.js';

let token = null;
// `GET /admin/whoami` of the token: {name, role, expires_at}. The server enforces roles (ADR-0016); the
// console only uses this to name the operator and to disable buttons the role cannot use.
let identity = null;
let onUnauthorized = () => {};

const ROLE_RANK = { viewer: 0, operator: 1, admin: 2 };

/** Install the callback that shows the login screen after a 401. */
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn;
}

export function setToken(t) {
  token = t;
}

export function hasToken() {
  return token !== null;
}

export function forgetToken() {
  token = null;
  identity = null;
}

export function setIdentity(who) {
  identity = who && typeof who.name === 'string' && typeof who.role === 'string' ? who : null;
}

export function getIdentity() {
  return identity;
}

/** Whether the logged-in operator's role reaches `min` (`viewer`, `operator` or `admin`). */
export function roleAllows(min) {
  if (identity === null) return true;
  return (ROLE_RANK[identity.role] ?? -1) >= ROLE_RANK[min];
}

/**
 * Disable `btn` for good when the operator's role is below `min`, and say why in its title.
 * Returns `btn`, so it wraps an h('button', ...) call. A disabled button only saves a 403:
 * the server checks the role on every request.
 */
export function needsRole(btn, min) {
  if (btn && !roleAllows(min)) {
    btn.disabled = true;
    btn.dataset.role = min;
    btn.title = `Needs the ${min} role; you are ${identity.role}.`;
  }
  return btn;
}

/**
 * An error answer from the admin API: status, the API's stable `code` (its `error` for a server
 * that sends no `code`), its human-readable message, and the answer's JSON object (`body`, or
 * null), for the codes that carry more members (a 410 `audit_pruned` names the boundary).
 */
export class ApiError extends Error {
  constructor(status, code, message, body = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

function headers(extra = {}) {
  const hdrs = { Accept: 'application/json', ...extra };
  if (token !== null) hdrs.Authorization = `Bearer ${token}`;
  return hdrs;
}

async function errorFrom(resp) {
  let code = `http_${resp.status}`;
  let message = resp.statusText || `HTTP ${resp.status}`;
  let obj = null;
  try {
    const body = await resp.json();
    if (body && typeof body === 'object') {
      obj = body;
      // `code` is the stable machine code; `detail` is text for people. `error_description`
      // is a deprecated copy of the code, read only from a server that sends neither.
      code = body.code || body.error_description || body.error || code;
      message = body.detail || body.message || body.error_description || message;
    }
  } catch {
    // Not JSON: keep the status text.
  }
  return new ApiError(resp.status, code, message, obj);
}

/**
 * api(path, {method, body, quiet}): call the admin API and return the parsed JSON.
 *
 * - Adds the bearer, `Accept: application/json`, and `Content-Type: application/json` on POST
 *   (the console listener refuses a POST without it, which is what stops cross-site forms).
 * - 401: forgets the token, shows the login screen, throws.
 * - Any other error: shown in the status line unless its status is in `quiet`, then thrown as
 *   an ApiError so the caller can render it in place too.
 */
export async function api(path, opts = {}) {
  const method = opts.method || 'GET';
  const init = { method, headers: headers(), cache: 'no-store', credentials: 'omit' };
  if (method === 'POST') {
    init.headers = headers({ 'Content-Type': 'application/json' });
    init.body = JSON.stringify(opts.body ?? {});
  }
  let resp;
  try {
    resp = await fetch(path, init);
  } catch (e) {
    const err = new ApiError(0, 'network', `Could not reach the server: ${e.message}`);
    showError(err.message);
    throw err;
  }
  if (resp.status === 401 && !opts.loginCheck) {
    forgetToken();
    onUnauthorized('The server refused the admin token. Log in again.');
    throw new ApiError(401, 'unauthorized', 'admin token refused');
  }
  if (!resp.ok) {
    const err = await errorFrom(resp);
    if (!(opts.quiet || []).includes(resp.status)) showError(`${path}: ${err.message} (${err.status} ${err.code})`);
    throw err;
  }
  return resp.json();
}

/**
 * Fetch `path` with the bearer and save the body as a file. A plain link cannot carry the
 * Authorization header, so the console downloads into a Blob and clicks a temporary
 * blob: link with a `download` name.
 */
export async function download(path, filename) {
  const resp = await fetch(path, { headers: headers({ Accept: 'application/x-ndjson' }), cache: 'no-store', credentials: 'omit' });
  if (resp.status === 401) {
    forgetToken();
    onUnauthorized('The server refused the admin token. Log in again.');
    return;
  }
  if (!resp.ok) {
    const err = await errorFrom(resp);
    showError(`${path}: ${err.message} (${err.status})`);
    throw err;
  }
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.setAttribute('href', url);
  a.setAttribute('download', filename);
  document.body.append(a);
  a.click();
  a.remove();
  // Give the browser a moment to start the download before the URL is released.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

// ---- audit retention -----------------------------------------------------------------

/** The tool of a prune's own audit record. */
export const PRUNE_TOOL = 'admin.audit.prune';

/**
 * The newest prune of a log whose first retained seq is `first`: `{pruned_through, prune_seq,
 * first}`, or null when it cannot be read. One request: the entry at `first - 1` is at the
 * newest prune's boundary, so the server answers it with 410 `audit_pruned` and those members.
 * Quiet: a failure puts nothing in the status line (a 401 still logs out, and is thrown).
 */
export async function newestPrune(first) {
  if (!Number.isInteger(first) || first <= 1) return null;
  try {
    await api(`/admin/audit/entries/${first - 1}`, { quiet: [400, 404, 410, 429, 500, 502, 503, 504] });
  } catch (e) {
    if (e.status === 401) throw e;
    const b = e.body;
    if (e.status === 410 && e.code === 'audit_pruned' && b && Number.isInteger(b.prune_seq) && Number.isInteger(b.pruned_through)) {
      return { pruned_through: b.pruned_through, prune_seq: b.prune_seq, first: Number.isInteger(b.first) ? b.first : first };
    }
  }
  return null;
}

/** Build a query string from an object, skipping empty values. */
export function qs(params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : '';
}

// ---- status line ------------------------------------------------------------------------

function statusEl() {
  return document.getElementById('status');
}

function show(text, ok) {
  const msg = h('div', { class: `status-msg${ok ? ' ok' : ''}` },
    h('span', null, text),
    h('button', { type: 'button', class: 'linkish', on: { click: clearStatus } }, 'Dismiss'));
  replace(statusEl(), msg);
}

export function showError(text) {
  show(text, false);
}

export function showNotice(text) {
  show(text, true);
}

export function clearStatus() {
  replace(statusEl());
}
