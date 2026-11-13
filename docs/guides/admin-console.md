# Admin console

The admin console is a set of pages built into `attenuo-server` for reading what the server decided and why: the audit log, one decision with its delegation chain and policies, a lease and everything delegated from it, the loaded policies, and the signatures over the log. With writes allowed, it can also revoke a lease and reload the policy file.

It calls the same admin API as the `attenuo` CLI, with the same admin token. Everything it shows, you can also get with `curl`; the [HTTP reference](../reference/http-api.md#admin) has the routes.

## Turn it on

The console has a listener of its own, off by default. Add to the server config:

```toml
[admin_ui]
enabled = true
# listen = "127.0.0.1:9101"   # the default
# allow_write = false         # the default: read-only
```

Restart the server. The log says `admin console listening at /admin/ui/`, and `http://127.0.0.1:9101/` redirects to the console.

The server refuses to start when `listen` is not a loopback address, unless you also set `allow_public = true`, and then `[admin] token` must pass the strength check a public listener needs. Keep it on loopback. All keys are in [the configuration reference](../reference/config.md#adminui).

The listener needs an admin credential: `[admin] token` or an `[[admin.operators]]` entry. Without one, every admin route answers 403 and the login screen says the admin API is disabled.

## Reach it from your laptop

On a server, keep the console on loopback and forward the port over SSH:

```console
$ ssh -N -L 9101:127.0.0.1:9101 you@attenuo-host
```

Then open `http://127.0.0.1:9101/` on your laptop. The page and the API it calls come from that one address.

## Log in

The login screen asks for an admin token: the value of `[admin] token`, or an operator's token from `attenuo admin operator new` ([admin operators](deploying.md#admin-operators)). The console checks it with `GET /admin/whoami` and keeps it only if the server accepts it. The header then shows the operator's name and role (`alice · operator`; `admin · admin` for `[admin] token`), followed by `expires <date>` when the token has an `expires_at` (an expired token is refused at login with "That token has expired."), and the buttons the role cannot use are disabled: revoking and deciding approvals need `operator`, reloading the policy needs `admin`. The server checks the role on every request either way; a disabled button only saves a refused request.

The token stays in the memory of that browser tab. It is not written to `localStorage`, `sessionStorage`, a cookie or the URL. It is forgotten when you:

- press **Lock**,
- leave the tab without any keyboard, mouse or touch input for 15 minutes,
- reload the page or close the tab,
- or when the server answers 401 (for example after the token was changed).

Each of these brings back the login screen.

## The screens

### Audit

The log, newest first, 100 entries a page: seq, local time (hover for UTC), kind, decision, server and tool, the agents of the chain root first, the user, the reason code, the chain and the leases.

- **Filters**: kind (several), decision, reason, subject, agent, server, tool, chain id, lease, and a time window in local time. Every filter is an exact match. The filters go in the page address (`#/audit?decision=deny`), so Back works and you can bookmark a filtered view. The admin token never goes there.
- **Older**, **Newer**, **Newest** page through the log. A filtered page can come back shorter than 100 entries; the server stops reading after 50,000 entries per request, and the console keeps asking until it has a page or reaches the end.
- **Follow** checks every 2 seconds whether the log grew and adds new entries at the top. It reads the head only; it never signs a checkpoint.
- A chain id narrows the view to that chain. A lease id opens its lease tree. A seq opens the decision.
- **Export this range** downloads the entries between the oldest and newest seq on screen, unfiltered, with the checkpoints in that range, as `attenuo-audit-{from}-{to}.ndjson`. Check it offline with `attenuo audit verify --file`.

### Decision

Open from a seq (`#/entry/42`) or from the `decision_id` a denial returns (`#/record/<uuid>`). It shows:

- the decision, the reason code and one line on what the code means;
- for a decision on a tainted run, the `tool_result` entries that tainted it (`labels.tainted_by`) and, when an argument copied an untrusted result, each such argument with the match kind (`leaf`, `entity`, `kgram` or `unreadable`) and a link to the result it matched (`labels.untrusted_args`);
- the delegation chain, the user first, then each hop's agent and lease, with the lease's state **now** (active, expired, or revoked with its reason and time);
- the ids of the policies that decided, with their current text. If the policies were reloaded after the decision, a warning says so: the text shown may not be the text that decided;
- for a call that drew on run limits, **Run limits and usage**: each limit it was charged against (hop and lease, capability index, kind, argument, what the counter held afterwards, the maximum and what was left; for `distinct` the counter is the number of values seen, and a host-derived argument shows as `url#host`), from the record's `budget` member; and for a destructive tool, the run's usage of it before the call (`usage`: calls, amount, whether the destination was seen before);
- the hash fields (`seq`, `prev_hash`, `entry_hash`, `chain_digest`, `arguments_digest`) and the signed checkpoint that covers the entry, or "not yet covered by a signed checkpoint";
- every other record of the same chain, oldest first.

What it cannot show: the tool arguments and the capabilities each hop held. The log stores only their digests. If you have the token, **Decode a token locally** shows its header and claims, decoded in the browser tab. The token is not sent to the server or anywhere else, and its signature is not checked there.

### Lease tree

`#/lease/<id>` shows the leases the lease was delegated from (root first), and the lease with everything delegated from it as an indented tree: lease id, agent, expiry, state (with revocation reason and time), and the seq of the record that issued it. **renewals** lists the renewals of one lease. **Revoke…** opens a confirmation (below).

**Run limits** lists the limits each hop of the chain was issued with, root first down to this lease: the capability, the kind (`calls`, `sum`, `calls_per`, `distinct`), the argument (`url#host` when a limit counts URL hosts), what is used now, the maximum and what is left. For `calls_per` the used figure is the most calls any one value has had, with the number of values seen. Every call is charged to every hop it passes through, so the smallest figure left along the chain is what this lease can still spend. On a run's root lease, **Run usage** shows the run's calls, amount and number of destinations per destructive tool (`context.usage`). Each node of the tree also shows its limits on one line as `kind used/max`. The figures are what the counters hold when the page loads; reload for fresh ones. A hop issued by a server older than this console has counters but no recorded maximum, shown as "not recorded".

### Approvals

`#/approvals` lists approvals of gated calls, newest first: id, state (with `expired` when past `expires_at`), call, user, run and expiry. Filter by run (chain id) or state. `#/approval/<id>` shows one: the call with its arguments exactly as the agent sent them, the call hash, the user and agents, the run and the calling hop's lease, the labels the run carried (each links to its `tool_result` entry), the arguments that matched an untrusted result of the run with the match kind and result, the gated decision, the times, and who decided and which decision used it. A pending approval has **Grant** and **Decline**; they need `allow_write` (below) and record the operator as approver (`by = "operator"`). The user can also decide with their own ID token at `POST /approvals/{id}`, which the console does not do.

### Policy

- The loaded policies: file path, its SHA-256, when it was loaded, warnings, and the text of each policy.
- **Check file on disk** lints the file as it is on disk now against the running schema: errors and warnings with line and column, and whether the file differs from what is loaded. It loads nothing.
- **Reload** becomes available after a check with no errors (see writes below).
- **Evaluate this call** is a dry run: give a delegation token (an expired one works) or a chain as JSON, a server, a tool and the arguments, and the console shows what the loaded policies decide, the reason, the policy ids and any diagnostics. It skips the lease check and writes no audit record. The token is sent to this server only. Four sections, closed until opened, state what the dry run would otherwise read from the store or leave out: **Budget** (the run-limit counters), **Run labels** (the run's taint and untrusted arguments), **Run usage** (`context.usage`) and **Approval** (decide the call as a retry that carries an approval granted by `user`, `operator` or `policy`). A section left empty sends nothing. The answer shows the budget, labels, usage and approval the call was decided with, each marked as stated in the request or read from the store (an approval is never read: without one stated, there is none).

### Verify

- The head of the log and the newest stored checkpoints.
- **Verify now** walks the whole hash chain and checks every checkpoint signature against the server's keys: `ok`, the first bad seq, the last signed seq, how many newest entries no signature covers yet, and any checkpoint that failed. On a large log this takes a while.
- **Sign head now** stores a signed checkpoint of the current head, after a confirmation. It is the only button on this page that writes, and it changes no audit entry.

## Writes and `allow_write`

By default the console listener is read-only: `POST /admin/leases/{id}/revoke`, `POST /admin/policies/reload`, `POST /admin/approvals/{id}` and `POST /admin/budgets/refund` are not mounted there (404), and `POST /admin/leases/revoke` answers only its `?preview=true` dry run. The console still shows **Revoke…**, **Reload**, **Grant** and **Decline**; pressing them explains that writes are disabled on this listener. Use the CLI against the main listener instead, or set:

```toml
[admin_ui]
allow_write = true
```

With writes on:

- **Revoke** shows how many leases a revoke would change and which active agents hold them, asks for a reason (recorded in the audit log) and the last 6 characters of the lease id, then revokes. It reports the server's count next to the preview's. It cannot be undone.
- **Reload** swaps in the policy file. If the file does not load, the old policies stay in force and the console shows the error.
- **Grant** lets the agent's identical retry run once; **Decline** ends the approval. Both are recorded in the audit log as `approval_grant` records.

One action writes even when `allow_write` is off, because it changes no lease, policy or audit entry: **Sign head now** (`GET /admin/audit/checkpoint`, which stores a checkpoint). Evaluate, check and the other reads write nothing.

## Security model

- **Separate listener.** The main listener also serves `/mcp/{server}`, where an upstream MCP server chooses the response type. If the console shared that origin, a hostile upstream could answer with HTML and run script next to the admin token. The console's own listener serves only the console files and the admin API. The files are compiled into the server: the page, its stylesheet and scripts, and the brand favicon (`assets/brand/favicon.svg`, served as `image/svg+xml` under `/admin/ui/` and at `/favicon.svg`, with the same headers as the other files).
- **Same token as the CLI.** The console has no accounts or sessions of its own. Anyone with an admin token can do with `curl` everything the console can with it, and no more: the role is checked by the server.
- **No dev mint.** `POST /admin/root-token` is never mounted on the console listener, whatever `[dev] allow_root_mint` says.
- **Strict page policy.** Every response carries a Content-Security-Policy that allows only the console's own scripts, styles and requests, no inline script, no framing and no form posts, and turns on Trusted Types. The console builds every element as text; it never turns a string into HTML. A test in the server scans the embedded files for HTML-parsing calls, `eval`, `javascript:` URLs, inline handlers and inline scripts or styles, and fails the build if one appears. So a tool name such as `<img src=x onerror=alert(1)>` in the log shows up as those characters.
- **No cross-site requests.** No CORS header is ever sent, so another site's page cannot read admin answers. Every `POST` must say `Content-Type: application/json`, which a cross-site form cannot send without a CORS preflight the listener never grants.
- **Nothing cached.** API answers carry `Cache-Control: no-store`. The console files carry `no-cache` with an ETag, so a server upgrade never leaves an old script running.
- **Nothing stored.** The token lives in the tab's memory only and is dropped on lock, idle, reload or a 401.

## Limits

- Operators log in with bearer tokens, not with an identity provider; there are no sessions, no expiry and no second factor. Admin actions are audited as the operator (`urn:attenuo:admin:<name>`), or as `urn:attenuo:admin` for the shared `[admin] token`. Reads are not audited.
- The decision view shows lease states and policy text as they are now, not as they were when the decision was made.
- The lease page shows run-limit counters as they are now. Refunding a charge is not a console action; use `POST /admin/budgets/refund` on the admin API.
- Readiness (`/readyz`) is served on the main listener only; the Verify page says so instead of showing it.
- The console is tested in current Chromium. Other browsers are untested.
