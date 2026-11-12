---
status: proposed
date: 2026-11-12
decision-makers: []
consulted: []
informed: []
---

# ADR-0013. Admin API listener: `/admin/*` on an opt-in listener of its own, and refused on a main listener off loopback unless the operator opts in

## Context and Problem Statement

The admin API (`/admin/*`: revoke, policy reload, approve as the operator, audit export, the development root mint) has been served on the same listener as the routes agents call (`/mcp/{server}`, `/token`, AuthZEN), and could not be turned off there (audit finding S-1). On a server bound to `0.0.0.0`, one static bearer is then all that stands between the agents' network and the operator's actions, and every agent that can reach the proxy can also find, probe and brute-force the admin API. The deploying guide asked operators to hide `/admin/` at a reverse proxy, which nothing enforced. How should the admin API be separated from the agent-facing listener without breaking local use, the demos and existing deployments silently?

## Decision Drivers

- Least exposure: an operator plane should not be reachable on the port agents use, and that port should not reveal that one exists.
- Safe by default off loopback, consistent with the startup refusals of #241 (`[dev] allow_root_mint_off_loopback`, `[server] allow_insecure_http`): an unsafe posture needs an explicit key, never only a log line.
- No change for loopback use (`cargo run`, the demos, tests): the admin API stays on the main listener there.
- The same authentication (the `[admin] token` bearer), the same request logging and the same shutdown path (stop signal, drain, awaited, single-writer fence released) as every other listener (`run`, #247).
- The admin console (`[admin_ui]`, ADR-0008) keeps working in every combination.

## Considered Options

- An optional `[admin] listen`; without it the admin API stays on the main listener, and off loopback the server refuses to start unless `[admin] serve_on_main_listener = true`.
- The same `[admin] listen`, but off loopback without it the server starts with a loud warning.
- A new `[admin_api]` section shaped like `[metrics]` and `[admin_ui]` (`enabled`, `listen` with a default port, `allow_public`).
- Always serve the admin API on its own listener (default `127.0.0.1:9102`), even on loopback.

## Decision Outcome

Chosen option: "`[admin] listen`, with a refusal off loopback unless `serve_on_main_listener`", because it is the only option that both makes the unsafe posture an explicit choice (as #241 did for the dev mint and plain-HTTP public URLs) and leaves loopback use and the demos as they are.

- `[admin] listen` (unset by default): when set, the admin routes are mounted on that listener only, behind the same `require_admin` layer, response headers, request span, metrics and `DPoP-Nonce` layer as before. The main listener does not mount them at all, so it answers `/admin/...` exactly as any unknown path (axum's default 404 with an empty body, for every method, with or without a bearer). The admin listener serves `/admin/*` only; `/healthz`, `/readyz`, discovery and JWKS stay on the main listener.
- Without `[admin] listen`: on a loopback `[server] listen` the admin API is on the main listener, as before. Off loopback the server refuses to start, naming both ways out, unless `[admin] serve_on_main_listener = true`, which starts it with a warning. Setting both keys is refused as a contradiction; `[admin] listen` equal to `[server] listen` is refused.
- `[admin] listen` off loopback starts with a warning and no extra key: unlike `/metrics` and the console, the admin API is authenticated, and SR-15's token strength check now counts `[admin] listen` as exposure, as it counts `[server] listen` and `[admin_ui] listen`.
- `[dev] allow_root_mint` is judged by the address the route is mounted on: `[admin] listen` when set, else `[server] listen`.
- `run` binds the admin listener next to the metrics and console listeners before anything starts, serves it with `serve_and_release` under the same stop, drains it with the others and awaits it before the fence is released.
- The console listener serves its own copy of the admin routes it needs (ADR-0008), so it is unaffected by where the admin API is: it works with and without `[admin] listen`.

### Consequences

- Good, because a server bound off loopback no longer exposes revoke, reload, approve and export on the agents' port unless its operator wrote a key saying so, and with `[admin] listen` the agents' port does not reveal that the admin API exists.
- Good, because the admin plane can be firewalled, tunnelled or bound to a private interface on its own, which a path rule at a reverse proxy could only approximate.
- Bad, because it is a breaking change for anyone running off loopback today: such a server refuses to start until the operator sets `[admin] listen` (recommended) or `[admin] serve_on_main_listener = true`. The error message names both.
- Bad, because operators now use two URLs: the CLI's `--server` and the SDKs' `AdminClient` point at the admin listener for admin commands and at the main one for the rest. The CLI has no separate admin URL option yet.
- Neutral, because a DPoP-bound dev root mint on the admin listener of a server with `[server] public_url` set expects proofs for `public_url` + path, which a client of the admin listener does not send; the dev mint is a loopback development feature, so this is left as it is.
- Neutral, because it is one more port to document and test, as with `[metrics]` and `[admin_ui]`.

### Confirmation

- `crates/attenuo-server/tests/admin_listener.rs`: every admin path (and a wrong method on one) on the main listener answers byte for byte as an unknown path of the same shape, with and without the bearer; the admin listener serves the admin API behind the bearer and nothing else; `run` serves it next to the main listener and the console, whose own admin API keeps answering; off loopback the server refuses to start without one of the two keys and refuses both at once; loopback defaults are unchanged.
- `shutdown_tests` in `crates/attenuo-server/src/lib.rs`: stop and restart on the same file twenty times, on one and on several threads, with the admin listener on and a connection to it held across the stop.
- Config unit tests in `crates/attenuo-server/src/config.rs`: the check itself, the token strength rule for `[admin] listen`, and that every shipped config still starts.

## Pros and Cons of the Options

### `[admin] listen`, refused off loopback without `serve_on_main_listener`

- Good, because the unsafe posture is a written, reviewable key, like the other startup refusals.
- Good, because nothing changes on loopback.
- Bad, because existing off-loopback deployments must change their config before upgrading.

### `[admin] listen`, warning only off loopback

- Good, because nothing breaks on upgrade.
- Bad, because a warning in a log nobody reads leaves the admin API on the agents' port, which is what the audit asked to stop; #241 moved two similar warnings to refusals for that reason.

### A new `[admin_api]` section like `[metrics]`

- Good, because it mirrors the two existing listener sections.
- Bad, because `enabled` plus a default `listen` makes two switches for one choice, and `allow_public` adds a third key for a listener that, unlike `/metrics` and the console, is authenticated; `[admin]` already holds the admin API's token, so its address belongs there too.

### Always on its own listener

- Good, because there is one way to run the server.
- Bad, because every local setup, demo script, SDK example and test would need a second URL for no gain on loopback, where both listeners are equally reachable.

## More Information

- Audit finding S-1 (admin plane on the agent listener); precedents: SR-38 (`[metrics] allow_public`), ADR-0008 (`[admin_ui]`), S-3 and S-9 (#241).
- Configuration: `docs/reference/config.md#admin`; deployment: `docs/guides/deploying.md#network-exposure`.
- Revisit with per-operator admin authentication (audit finding S-2), which may change what the admin listener authenticates, and if the CLI gains a separate admin URL.
