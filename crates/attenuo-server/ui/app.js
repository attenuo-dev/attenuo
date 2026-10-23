// Entry point: the shell, login, idle lock, theme toggle and the hash router.
//
// Routes: #/audit[?filters], #/entry/{seq}, #/record/{id}, #/lease/{id}, #/policy, #/verify.
// Each view is a function (main, params) => Promise that fills `main` and may return a cleanup
// function, which the router calls before the next view (the audit view uses it to stop
// following the log).
'use strict';

import { h, replace } from './dom.js';
import {
  api, setToken, forgetToken, hasToken, setUnauthorizedHandler, clearStatus, showError,
} from './api.js';
import { auditView } from './view-audit.js';
import { entryView } from './view-entry.js';
import { leaseView } from './view-lease.js';
import { policyView, forgetPolicyCache } from './view-policy.js';
import { verifyView } from './view-verify.js';

const IDLE_MS = 15 * 60 * 1000;

const main = document.getElementById('main');
const nav = document.getElementById('nav');
const lockBtn = document.getElementById('lock');
const themeBtn = document.getElementById('theme-toggle');

let cleanup = null;
let idleTimer = null;
// Bumped on every navigation, so a slow view that finishes after the user moved on can tell
// its result is stale and must not touch the page.
let generation = 0;

// ---- theme --------------------------------------------------------------------------------

// Dark is the default; the system may ask for light. The toggle sets data-theme on <html> for
// this page load only.
function currentTheme() {
  const set = document.documentElement.getAttribute('data-theme');
  if (set) return set;
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function syncThemeButton() {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  themeBtn.textContent = next === 'light' ? 'Light theme' : 'Dark theme';
  themeBtn.setAttribute('aria-label', `Switch to the ${next} theme`);
}

themeBtn.addEventListener('click', () => {
  document.documentElement.setAttribute('data-theme', currentTheme() === 'dark' ? 'light' : 'dark');
  syncThemeButton();
});
window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', syncThemeButton);
syncThemeButton();

// ---- lock and idle timeout ----------------------------------------------------------------

function stopView() {
  if (cleanup) {
    try { cleanup(); } catch { /* a failing cleanup must not keep the old view alive */ }
    cleanup = null;
  }
}

/** Forget the token and everything cached with it, then show the login screen. */
function lock(message) {
  generation++;
  stopView();
  forgetToken();
  forgetPolicyCache();
  clearTimeout(idleTimer);
  idleTimer = null;
  nav.hidden = true;
  lockBtn.hidden = true;
  clearStatus();
  showLogin(message);
}

function resetIdle() {
  if (!hasToken()) return;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => lock('Locked after 15 minutes without activity.'), IDLE_MS);
}

// Any user input counts as activity. Background polling does not, on purpose.
for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart', 'mousemove']) {
  window.addEventListener(ev, resetIdle, { passive: true });
}

lockBtn.addEventListener('click', () => lock('Locked. The token was forgotten.'));
setUnauthorizedHandler((msg) => lock(msg));

// ---- login --------------------------------------------------------------------------------

function showLogin(message) {
  const input = h('input', {
    type: 'password', id: 'admin-token', name: 'admin-token', autocomplete: 'off',
    spellcheck: 'false', required: true, autofocus: true,
  });
  const error = h('p', { class: 'callout bad', role: 'alert' });
  error.hidden = true;
  const submit = h('button', { type: 'submit', class: 'primary' }, 'Log in');

  const form = h('form', {
    on: {
      submit: async (ev) => {
        ev.preventDefault();
        submit.disabled = true;
        error.hidden = true;
        const ok = await tryLogin(input.value.trim(), error);
        submit.disabled = false;
        if (ok) {
          input.value = '';
          enterConsole();
        } else {
          input.select();
        }
      },
    },
  },
  h('div', { class: 'field' }, h('label', { for: 'admin-token' }, 'Admin token'), input),
  error,
  submit);

  const card = h('section', { class: 'login', 'aria-labelledby': 'login-title' },
    h('h1', { id: 'login-title' }, 'Log in'),
    message ? h('p', { class: 'callout' }, message) : null,
    form,
    h('p', { class: 'note' },
      'The token is the server’s [admin] token. It stays in this tab’s memory only: ',
      'reloading, Lock, or 15 minutes without activity forget it.'));
  replace(main, card);
  input.focus();
}

/** Check a token with a one-entry audit read; keep it only if the server accepts it. */
async function tryLogin(candidate, errorEl) {
  if (!candidate) return false;
  setToken(candidate);
  try {
    await api('/admin/audit?limit=1', { loginCheck: true, quiet: [401, 403] });
    return true;
  } catch (e) {
    forgetToken();
    errorEl.textContent = e.status === 401
      ? 'That token was refused.'
      : e.status === 403
        ? 'The server has no [admin] token configured, so the admin API is disabled.'
        : `Could not log in: ${e.message}`;
    errorEl.hidden = false;
    return false;
  }
}

function enterConsole() {
  nav.hidden = false;
  lockBtn.hidden = false;
  clearStatus();
  resetIdle();
  if (!location.hash || location.hash === '#' || location.hash === '#/') {
    location.hash = '#/audit';
  } else {
    route();
  }
}

// ---- router -------------------------------------------------------------------------------

/** Split the hash into decoded path segments and query parameters. */
function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [path, query = ''] = raw.split('?');
  const segments = path.split('/').filter(Boolean).map((s) => {
    try { return decodeURIComponent(s); } catch { return s; }
  });
  return { segments, params: new URLSearchParams(query) };
}

const ROUTES = {
  audit: (m, s, p) => auditView(m, p),
  entry: (m, s) => entryView(m, { seq: s[1] }),
  record: (m, s) => entryView(m, { id: s[1] }),
  lease: (m, s) => leaseView(m, s[1]),
  policy: (m) => policyView(m),
  verify: (m) => verifyView(m),
};

const NAV_FOR = { audit: 'audit', entry: 'audit', record: 'audit', lease: 'audit', policy: 'policy', verify: 'verify' };

async function route() {
  if (!hasToken()) return;
  stopView();
  // A message belongs to the page it was shown on.
  clearStatus();
  const gen = ++generation;
  const { segments, params } = parseHash();
  const name = segments[0] || 'audit';
  const view = ROUTES[name];
  for (const a of nav.querySelectorAll('a')) {
    if (a.dataset.page === NAV_FOR[name]) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  if (!view || (name !== 'audit' && name !== 'policy' && name !== 'verify' && !segments[1])) {
    replace(main, h('section', { class: 'panel' }, h('h1', null, 'Not found'),
      h('p', null, 'There is no such page. '), h('a', { href: '#/audit' }, 'Go to the audit log')));
    return;
  }
  // A view gets its own container, so a stale view finishing late writes into a detached node.
  const container = h('div', { class: 'stack' });
  replace(main, container);
  try {
    const result = await view(container, segments, params);
    if (gen !== generation) {
      if (typeof result === 'function') result();
      return;
    }
    if (typeof result === 'function') cleanup = result;
  } catch (e) {
    if (gen !== generation || e.status === 401) return;
    // api() has already shown API errors in the status line.
    if (!e.status) showError(`Could not show this page: ${e.message}`);
  }
}

window.addEventListener('hashchange', route);
showLogin();
