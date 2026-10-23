---
status: proposed
date: 2026-10-23
decision-makers: [7Mudit]
consulted: []
informed: []
---

# ADR-0008. Admin console: vanilla static files embedded in attenuo-server, on a separate opt-in listener, with the admin token held in page memory

## Context and Problem Statement

Operators administer attenuo through the CLI and the `/admin/*` REST routes. Reading the audit log, following a delegation chain, finding the leases under a run and checking a policy all take several commands and some knowledge of the record format. An admin console in the browser would make these tasks quicker and harder to get wrong, but it brings a browser into the admin trust boundary: stored audit strings become a script-injection vector, the static admin bearer has to live somewhere in the page, and a write such as a lease revocation becomes reachable from other origins unless something stops it. How should the console be built, served and authenticated so that it adds no authority, few dependencies and little attack surface? The design is in `docs/design/admin-console.md`.

## Decision Drivers

- Least privilege: the console must not be able to do anything the admin bearer cannot do already, and it must never grant tokens.
- Small dependency surface for a security product: `cargo build` from source must keep working with the Rust toolchain alone.
- One maintainer must be able to read and explain every file that ships.
- The strictest practical Content-Security-Policy, so stored audit strings cannot run as script.
- No new ambient credential, so CSRF does not arise.
- The console must not share an origin with the MCP proxy, which forwards upstream `Content-Type` for responses it does not filter.
- Exposure rules consistent with `/metrics`: off by default, loopback by default, refusal to start on a public address without an explicit setting (SR-38).

## Considered Options

- Vanilla HTML, JS and CSS with no build step, embedded in `attenuo-server` with `include_bytes!`, served on a separate opt-in listener.
- A TypeScript app under `ui/`, built with Node in CI and embedded in `attenuo-server`.
- A separate console process that calls the admin API across origins.

Sub-decisions made with the chosen option:

- Where to serve it: a dedicated `[admin_ui]` listener, or `/admin/ui/` on the main listener.
- How the browser holds the admin token: in page memory and sent as a header, or a server session in a cookie.

## Decision Outcome

Chosen option: "Vanilla HTML, JS and CSS embedded with `include_bytes!`, on a separate opt-in listener", because it is the only option that adds no dependency and no second toolchain while allowing a CSP with `script-src 'self'` and Trusted Types, and the separate listener keeps the console same-origin with its API (no CORS) and off the proxy's origin.

- Assets live in `crates/attenuo-server/ui/` and are compiled in through a hand-written table of `(path, content type, bytes)`. No `rust-embed` or `include_dir`.
- `[admin_ui] enabled` (default `false`), `listen` (default `127.0.0.1:9101`), `allow_public` (default `false`; off loopback the server refuses to start without it and warns with it), `allow_write` (default `false`; revoke and reload are mounted on this listener only when `true`).
- The listener serves `/admin/ui/` and the admin API under `/admin/*` with the same `require_admin` layer. It never mounts `/admin/root-token`. The main listener keeps `/admin/*` for the CLI, unchanged.
- The page keeps the admin token in a JS closure, sends it as `Authorization: Bearer`, and never writes it to Web Storage, cookies or URLs. It forgets it after 15 minutes idle and on "Lock".
- Every response on the console listener carries `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and API responses carry `Cache-Control: no-store`. No CORS headers are sent.
- The page renders with `textContent` and `createElement` only.

### Consequences

- Good, because no crate and no npm package is added, and `cargo build` stays self-contained.
- Good, because header-only auth has no ambient credential, so cross-site requests cannot authenticate and no CSRF token or session store is needed.
- Good, because "read-only by default" is enforced by the server (`allow_write = false`), not only by the page.
- Good, because the console is a client of documented JSON endpoints, so it can later be rewritten without server changes.
- Bad, because a script injected into the page could read the static admin token, which an `HttpOnly` cookie would have hidden. The CSP, Trusted Types, the `textContent`-only rule with a build-time scan, and the idle timeout are what stand between stored audit strings and that outcome.
- Bad, because the operator re-enters the token on every page load and in every tab.
- Bad, because plain JS has no type checking; the console must stay small enough to review by reading.
- Neutral, because a second listener is one more port to document, firewall and test, in the same way as `[metrics]`.
- Neutral, because adding a cookie session later is conditional: it must use a `__Host-` cookie with `HttpOnly`, `Secure`, `SameSite=Strict`, an `Origin` check and a CSRF header token. That change belongs with per-operator admin authentication and gets its own ADR.

### Confirmation

- Router tests in `crates/attenuo-server/tests/admin_ui.rs`: the exact CSP and other headers on the page, the assets and an API response; no `Access-Control-*` headers for a cross-origin `Origin`; write routes absent with `allow_write = false`; `/admin/root-token` absent whatever `[dev]` says; admin API on the console listener refuses a missing or wrong bearer.
- Config unit tests: disabled by default; refusal to start off loopback without `allow_public`.
- A unit test that scans every embedded JS and HTML asset for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval(`, `new Function`, `javascript:` and inline `on*=` handlers.
- `scripts/admin-ui-smoke.sh` in CI: start the server, `curl` the page and the admin endpoints with and without the token.
- Review checklist item for any PR touching `crates/attenuo-server/ui/`: no new storage of the token, no new HTML sink, no external origin.

## Pros and Cons of the Options

### Vanilla static files embedded with `include_bytes!`

- Good, because there is nothing to install, build or audit beyond the files themselves.
- Good, because a strict CSP is easy: no inline script, no bundler output to accommodate.
- Good, because the shipped files are the source files.
- Neutral, because `rust-embed` or `include_dir` would save a few lines but add a dependency; with five or so files the table is short.
- Bad, because larger UIs get unwieldy without components and types.

### TypeScript app under `ui/`, built in CI and embedded

- Good, because types and components scale better as the console grows.
- Good, because Node is already used in CI for the TypeScript SDK.
- Bad, because building from source then needs Node, or a committed build output that must be kept in sync and reviewed as generated code.
- Bad, because the npm dependency tree becomes part of the supply chain of the server binary.
- Bad, because every UI change spans two toolchains.

### Separate console process

- Good, because it could manage several attenuo servers.
- Bad, because the admin API would need CORS, with preflights and an allow-list, which it has never had.
- Bad, because the admin token lives in a second process and deployment.
- Bad, because it is another service to run, version and secure, for a feature one operator uses.

### Sub-decision: serving location

- Dedicated listener. Good, because it is a separate origin from `/mcp/{server}` and `/token`, it can be kept on loopback independently of the main listener, and the server can omit write routes on it. Bad, because it is one more port.
- `/admin/ui/` on the main listener. Good, because no new port. Bad, because the page shares an origin with proxied upstream responses whose `Content-Type` is forwarded, and read-only mode could be enforced only in the page.

### Sub-decision: token holding

- In page memory, header only. Good, because there is no ambient credential and no server-side session code. Bad, because script injection could read the token.
- Session cookie minted from the admin token. Good, because the static token is not reachable from script. Bad, because it needs a session store, expiry, logout, CSRF tokens and an Origin check, and `__Host-` cookies need HTTPS, which a loopback listener usually does not have.

## More Information

- Design: `docs/design/admin-console.md` (screens, API gaps, threat model deltas, PR plan).
- Precedent for the listener rules: `[metrics]`, `MetricsSection::check_listen` in `crates/attenuo-server/src/config.rs`, SR-38.
- Admin authentication today: `admin::require_admin` and `AdminSection` (static bearer, v0); ADR-0007 for agent authentication, which this decision does not change.
- Revisit when admin authentication becomes per-operator, when the console needs to serve more than one server, or when its JS outgrows review by reading (rough signal: about 2 000 lines).
