// The one fetch wrapper the console uses, and the admin token it carries.
//
// The token lives in a module-scoped variable and nowhere else: not in localStorage,
// sessionStorage, a cookie or the URL. Reloading the page, pressing Lock or 15 minutes without
// user input forget it. Every request is same-origin (the console listener serves both the page
// and the API), so the browser never sends the token anywhere else.
'use strict';

import { h, replace } from './dom.js';

let token = null;
let onUnauthorized = () => {};

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
}

/** An error answer from the admin API: status, the API's `error` code and its message. */
export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
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
  try {
    const body = await resp.json();
    if (body && typeof body === 'object') {
      code = body.error || code;
      message = body.error_description || body.message || body.detail || message;
    }
  } catch {
    // Not JSON: keep the status text.
  }
  return new ApiError(resp.status, code, message);
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
