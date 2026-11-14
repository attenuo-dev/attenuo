# Deploying

This guide covers what to change between "it runs on my laptop" and "other people and other machines depend on it". Read the limits first. They decide whether v0 fits your situation.

## What v0 is and is not

attenuo is pre-alpha. Do not treat this guide as a statement that it is ready for production. It is a list of what you would have to do if you ran it anyway, for example in a staging environment or a closed pilot.

- **One node.** There is no clustering, no replication and no leader election. One server process owns one SQLite file, and the server enforces it: a second server on the same file refuses to start (see [One process per file](#one-process-per-file)).
- **SQLite only.** The audit log and the lease registry live in the same SQLite file, in WAL mode. Store calls run on the blocking pool, and audit appends go through one writer thread that commits whatever is queued in one transaction (group commit). On a shared 4-core development container a file-backed server handled about 3,000 to 4,500 calls per second at one hop (memory: about 5,000 to 6,600); see [design/performance.md](../design/performance.md) for the method and the caveats.
- **No high availability.** If the process is down, every call through the proxy fails. That is by design: attenuo fails closed. Do not start a second replica against the same file, or against a copy. Against a copy, each process keeps its own idea of which leases are revoked and how much of a run limit is spent. Against the same file, the lease registry and the counters are shared, but the state that makes a credential single use, the locks that serialise a run's budgeted decisions and a user's decisions under a per-user window, and the loaded policy set live in each process, so a credential can be redeemed once per replica and a reload reaches one replica only. Per-user windows (`context.usage.user_window`) are therefore a single-replica guarantee: against a copy each replica keeps its own windows, so a user gets the cap once per replica, and against the same file two replicas can each pass a call the window should have stopped. A window that guards money should also run at `[audit] durability = "full"`: at `"normal"` a power failure can drop the newest commits, and a lost window charge can be spent again in the same window (a call that also charges a `sum` limit already commits with a full sync). The inventory is in [multi-replica readiness](../design/multi-replica.md) (proposed).
- **No TLS.** The server speaks plain HTTP. Terminate TLS in front of it.
- **Static admin tokens.** Each operator can have a token of its own with a role (`[[admin.operators]]`, [ADR-0016](../decisions/0016-admin-operators.md)): `viewer`, `operator` (also revokes and decides approvals) or `admin`. There is no login, no expiry and no rotation short of editing the config and restarting. Admin actions (lease revocations, policy reloads, refunds, development root mints, operator approvals) are recorded in the audit log under the operator, `urn:attenuo:admin:<name>`, or `urn:attenuo:admin` for the single `[admin] token`; the `urn:attenuo:` prefix is reserved, so no identity provider can issue such a subject.
- **Metrics on a side listener only.** `GET /metrics` (Prometheus text) is served on its own loopback listener when you enable it, with no authentication. See [What to monitor](#what-to-monitor).
- **Manual key rotation with no overlap.** See [Key rotation](#key-rotation).

The full list of known gaps is at the end of [design/server.md](../design/server.md#known-limits-v0). The open security findings are on the [task board](../tasks/board.md); the thirteen review passes, from [pass 1](../research/security-review-2026-10-22.md) to [pass 13](../research/security-review-2026-11-13-pass13.md), are listed in the [README's status section](https://github.com/attenuo-dev/attenuo#status).

## Production checklist

Go through this before pointing anything real at the server.

- [ ] `[dev] allow_root_mint` is `false` or absent. With it on, anyone holding the admin token can mint a root token for any user. When the admin API's listener (`[admin] listen`, else `[server] listen`) is not loopback the server refuses to start with it; `[dev] allow_root_mint_off_loopback` exists only for the docker-compose demo and must not appear in your config.
- [ ] Root tokens come from a real identity provider: `[[idps]]`, `[[agents]]`, `[[root_grants]]`. See [Identity providers](identity-providers.md).
- [ ] Each person who operates the server has an `[[admin.operators]]` entry of their own with the least role they need (`attenuo admin operator new --name <name> --role viewer|operator|admin`), so the audit log names who acted; see [admin operators](#admin-operators). If you keep `[admin] token` (or `ATTENUO_ADMIN_TOKEN`, which overrides it), it is a long random value that is not in any example, not in version control and not shared with agents. Generate it with `openssl rand -hex 32`. Off a loopback `listen` address the server refuses to start with no admin credential at all, or with an `[admin] token` shorter than 32 bytes or a known placeholder; it cannot tell whether a token was leaked.
- [ ] Every agent that receives a token is an `[[agents]]` entry with its own secret or, to keep no shared secret on the server, its own public key (`jwks`, [`private_key_jwt`](identity-providers.md#a-key-instead-of-a-secret)): token exchanges authenticate as their `actor` (`[token] require_actor_auth`, on by default).
- [ ] `[policy] unknown_tools` is `deny` (the default) or `sensitive`, not `allow`.
- [ ] `/admin/*` is not reachable from the networks agents live on: `[admin] listen` gives it a port of its own. See [Network exposure](#network-exposure).
- [ ] TLS terminates in front of attenuo, and agents reach it over HTTPS only. `[server] public_url` is the proxy's `https://` URL, and agents, the CLI and the SDKs are given that URL itself: they follow no redirect, so a URL that redirects is an error ([TLS and a reverse proxy](#tls-and-a-reverse-proxy)). A plain `http://` `public_url` on a host that is not loopback refuses to start unless `[server] allow_insecure_http = true`, which you should not need.
- [ ] Every `[[idps]]` and `[[actor_trust]]` key URL (`jwks_url`, `spiffe_bundle_url`, or the IdP `issuer` used for discovery) is the final `https://` URL. Plain `http://` is accepted only on loopback, and redirects are not followed, so a key URL that redirects fails every ID or actor token it should verify.
- [ ] `[issuer] private_key_pem_path` is set, the file is mode 0600, owned by the service user, and backed up somewhere safe. Without the setting the server makes a new key at every start and every token dies on restart.
- [ ] `[audit] sqlite_path` is a real path on durable storage. The default is `:memory:`, which loses the audit log and every lease on exit. The server logs a warning when it is in memory.
- [ ] `[issuer] issuer` is the URL clients will use, for example `https://attenuo.example.com`. It becomes the `iss` of every token, and changing it later invalidates tokens. `[server] public_url` is set to the same base URL so the AuthZEN discovery document points at the right host. Off a loopback `listen` address the server refuses to start without it.
- [ ] `[policy] policies_path` points at your policy, and the catalog lists every tool a policy names.
- [ ] Every tool on the upstream that agents should call is in the catalog. With the default `[policy] unknown_tools = "deny"`, a tool missing from the catalog is denied with `tool_not_in_catalog`; with `"allow"` it is neither `readonly` nor `sensitive`, so rules that depend on those attributes do not see it.
- [ ] The config file is mode 0600, and only the people allowed to be admins can edit it: whoever can edit it can add an `[[admin.operators]]` entry with role `admin`. It holds secret hashes and possibly the admin token. The admin token can come from `ATTENUO_ADMIN_TOKEN` instead, `[telemetry]` reads the standard `OTEL_*` variables ([observability](observability.md)), and any scalar key can be set with an `ATTENUO__<SECTION>__<KEY>` variable ([environment overrides](../reference/config.md#environment-overrides)). The file is still read, and lists and arrays of tables (`[[agents]]`, `[[upstreams]]`, ...) come only from it. Nothing is substituted inside the file.
- [ ] You have read the [threat model](../spec/threat-model.md) section "What attenuo does not prevent" and have decided how the agents' other routes (direct API keys, local STDIO servers) are closed.
- [ ] `[limits]` fits your load: `max_in_flight` above your peak of concurrent requests, and the rate limits (off by default) set for your busiest legitimate run and agent if you want one caller kept from crowding out the rest. See [Load limits](#load-limits).
- [ ] Something checks `attenuo audit verify` on a schedule, and `[audit.sink]` ships checkpoints off the host ([audit log](../concepts/audit-log.md#shipping-checkpoints-off-the-host)). The server signs checkpoints itself (`[audit] checkpoint_every`, `checkpoint_interval_seconds`); `audit verify` reports the last signed `seq`.

## Network exposure

The default bind is `127.0.0.1:8080`. Keep it that way and put a reverse proxy in front, unless you have a reason not to.

The routes fall into three groups:

| Routes | Who should reach them |
| --- | --- |
| `POST /mcp/{server}`, `GET`/`DELETE /mcp/{server}` | Agents and MCP clients |
| `POST /token`, `POST /token/renew`, `POST /access/v1/evaluation`, `GET /.well-known/*` | Agents, and PEPs for AuthZEN |
| `/admin/*` | Operators only |
| `GET /healthz` | Your health checker |

Without `[admin] listen`, `/admin` is on the same listener as everything else. On `127.0.0.1` that is fine for local use. Off loopback the admin tokens would be the only thing between the agents' network and "revoke any lease, reload policy, read the audit log", so the server refuses to start that way. Give the admin API a listener of its own:

```toml
[server]
listen = "0.0.0.0:8080"
public_url = "https://attenuo.example.com"

[admin]
# /admin/* only here; the main listener answers it as an unknown path (404).
listen = "127.0.0.1:9102"
```

Operators then reach it on the host or over an SSH tunnel (`ssh -L 9102:127.0.0.1:9102 host`), and point the CLI's admin requests at it with `--admin-server` or `ATTENUO_ADMIN_SERVER` (`export ATTENUO_ADMIN_SERVER=http://127.0.0.1:9102`, then `attenuo lease revoke ...`), or the SDKs' `AdminClient("http://127.0.0.1:9102", token)`. The CLI sends only `/admin/*` there; everything else (`token exchange`, `call`, `tools`, `health`, the JWKS) keeps going to `--server`, the main URL, so there is no URL to switch between commands. On a private operator network, `listen` can be that interface's address; the admin token must then be a strong one, as for any listener off loopback. The admin console (`[admin_ui]`) has its own listener and is not affected.

If something in front of the server already keeps `/admin/` away from agents (the reverse proxy below, or a container whose port is published on the host's loopback only), `[admin] serve_on_main_listener = true` keeps the admin API on the main listener off loopback; the server logs a warning at startup. Prefer `[admin] listen`: it holds even when the proxy is bypassed.

Two other exposure points to think about:

- **`POST /access/v1/evaluation` without a bearer** is refused with 401 unless `[authzen] allow_unsigned_chain = true`. With it on, only `[[peps]]` clients that authenticate can send a chain in the body, and the chain must be one this server issued (each lease is bound to its chain). See [Integrating MCP clients](integrating-mcp-clients.md#using-the-authzen-endpoint-from-a-non-mcp-pep).
- **`POST /token` for hop 0** does an outbound fetch to your identity provider's discovery and JWKS URLs, but only after the agent has authenticated. Unknown issuers are rejected without a network call. These fetches, and those for `[[actor_trust]]` keys, use `https://` only (plain `http://` only to a loopback host) and follow no redirects, so neither a network attacker nor a redirect can swap in keys that would forge ID or actor tokens.

## TLS and a reverse proxy

Put anything that terminates TLS in front: Caddy, nginx, Envoy, a cloud load balancer. Two things matter for MCP:

- **Do not buffer responses.** Streamable HTTP can answer with `text/event-stream`. A proxy that buffers will hold events back.
- **Keep read timeouts long** enough for slow tools.
- **Point clients at the final URL.** The CLI and both SDKs follow no redirect (SR-112): a `307` or `308` would send a token request's body, with the agent's client secret or assertion and the subject token, again to wherever `Location` names. A 3xx is an error that names the status and the `Location` (`ApiError` `redirect_not_followed` in the SDKs, exit 1 in the CLI). So a reverse proxy that redirects `http://` to `https://`, or one host name to another, now produces that error instead of a silent second request: give clients the `https://` URL that answers without a redirect, the `[server] public_url`.

A minimal Caddy file. Untested, but small enough to check by eye:

```text
attenuo.example.com {
    @admin path /admin/*
    respond @admin 404
    reverse_proxy 127.0.0.1:8080 {
        flush_interval -1
    }
}
```

This hides `/admin` from the public name for a server that serves it on the main listener (loopback, or `serve_on_main_listener`). Operators reach it on `127.0.0.1:8080` directly. With `[admin] listen` the block is not needed, and harmless.

For nginx, the equivalent pieces are `proxy_pass http://127.0.0.1:8080;`, `proxy_buffering off;`, `proxy_http_version 1.1;` and a `location /admin/ { return 404; }` block. Untested.

attenuo builds the AuthZEN discovery document from `[server] public_url`, which is required whenever `listen` is not a loopback address, so a forged `Host` header cannot put another host's URLs into a document a shared cache might keep. Only on a loopback listener without `public_url` does it fall back to `Host`, and then it accepts only `localhost`, `127.0.0.1` or `[::1]` (with an optional port) and answers 400 `invalid_host` to anything else. It does not use `X-Forwarded-*` headers.

## Load limits

attenuo is an inline, fail-closed decision point: when it is down or swamped, every agent's calls fail. Denial of service is still outside the [threat model](../spec/threat-model.md), but `[limits]` ([reference](../reference/config.md#limits)) gives one process some basic protection, all of it in-process and per server (one replica):

- **In-flight cap.** `max_in_flight` (default 1024) requests are handled at once on the main listener; the next gets `503` `overloaded` with `Retry-After: 1` at once instead of waiting in a queue. `/healthz` and `/readyz` are never refused, so a busy server is not restarted for being busy. A streamed MCP answer stops counting once its headers are sent. The admin listener (`[admin] listen`) is not counted, which keeps revocation reachable while the main listener sheds.
- **Deadlines.** Headers must arrive within `header_read_timeout_seconds` (30), which also closes idle kept-alive connections; bodies within `request_body_timeout_seconds` (30, else `408`); every answer except `/mcp/{server}` and `/admin/*` within `request_timeout_seconds` (60, else `503`). The proxy keeps its own upstream deadlines (`[proxy] upstream_connect_timeout_seconds`, `upstream_response_timeout_seconds`), and its streams stay open for as long as their leases are live.
- **Rate limits, off by default.** `mcp_requests_per_minute` per run, `token_requests_per_minute` per authenticated agent and `token_unauthenticated_requests_per_minute` per peer address. Over the limit: `429` with `Retry-After`. Start at a few times the busiest legitimate rate, watch `requests_rate_limited_total`, and keep the per-peer limit off behind a reverse proxy, where every caller shares the proxy's address.

Your reverse proxy or load balancer is still the place for connection limits per client address and for limits across replicas; attenuo does not read `X-Forwarded-For`.

## Admin operators

Give each person who operates the server a token of their own, with the least role they need ([ADR-0016](../decisions/0016-admin-operators.md), [config](../reference/config.md#adminoperators)):

```sh
attenuo admin operator new --name alice --role operator
```

prints a new token once and the entry to add to the config file:

```toml
[[admin.operators]]
name = "alice"
token_sha256 = "<64 lowercase hex characters>"
role = "operator"
```

Then run `attenuo admin operator reload` (role `admin`): the server re-reads `[[admin.operators]]` from its config file and puts them in force without a restart (a restart works too). Hand the token to alice over a secure channel; the file keeps only its SHA-256. `viewer` reads (the audit log, its export, leases, policies, approvals), `operator` also revokes leases and decides approvals, `admin` does everything (policy and operators reload, budget refunds, the dev root mint). A role too low gets 403 `admin_role_insufficient`. `GET /admin/whoami` (and the console's header) says which operator a token is. In the audit log, each admin action and operator approval names `urn:attenuo:admin:<name>`.

- Every token is compared, as a SHA-256 digest, in constant time against every credential; with no credential configured `/admin` answers 403 rather than opening.
- `[admin] token` still works as before: it is the operator `admin` with role `admin`, recorded as `urn:attenuo:admin`, so its records do not say which person used it. It sits in the config file in clear text (or comes from `ATTENUO_ADMIN_TOKEN`). Treat the file as a secret either way: mode 0600, not in the image, not in the repository, not in a CI log. In Docker or Kubernetes, mount the whole file from a secret. Once everyone has an operator entry, remove `[admin] token`.
- Operators pass their token to the CLI with `ATTENUO_ADMIN_TOKEN`, `--admin-token-stdin` or `--admin-token-file`. `--admin-token` still works but prints a warning, since command-line arguments show up in process listings (`ps`, `/proc/<pid>/cmdline`) and shell history. The same goes for an agent's client secret (`ATTENUO_CLIENT_SECRET`, `--client-secret-stdin`, `--client-secret-file`).
- **A leaked operator token:** remove its entry from the config file (or set its `expires_at` to a time in the past) and run `attenuo admin operator reload`. The token's next request is refused (401); requests it already had in flight finish. The reload's answer and its `admin.operators.reload` audit record name the operator removed or changed. Then look in the audit log for what the token did (`attenuo audit tail --subject urn:attenuo:admin:<name>`). A leaked `[admin] token` is not reloaded: change it (or `ATTENUO_ADMIN_TOKEN`) and restart.
- **Expiry:** give a token a lifetime with `attenuo admin operator new --expires-in 30d` (or `--expires-at <RFC 3339>`), which writes `expires_at` into the entry. After it the token gets 401 `admin_credential_expired`; the entry stays harmless in the file, and the server warns about it at startup and on each reload until you remove it.
- **Rotation without a gap:** add a second entry for the same person (`alice-2`) with a new token, reload, switch, then remove the old entry and reload again.
- A reload that would leave no working `admin` credential (no `[admin] token` and no unexpired operator with role `admin`) is refused, and so is a file that does not parse or breaks a rule; the operators in force stay as they were. A server started without a config file (one that builds its configuration in code) has nothing to reload.
- Do not hand an admin token to agents. Even a `viewer` token reads every audit entry. Agents use delegation tokens only.
- Whoever can edit the config file, or set `ATTENUO_ADMIN_TOKEN` in the server's environment, can make themselves an admin. There is no login, no second factor and no per-operator rate limit; the [threat model](../spec/threat-model.md) (A8) lists what is and is not covered.

## Key rotation

The server signs every token with the Ed25519 key named by `[issuer] private_key_pem_path`. Each token's JOSE header carries a `kid`: the first 16 bytes of the SHA-256 of the key's SubjectPublicKeyInfo DER, base64url-encoded (22 characters). `/.well-known/jwks.json` lists every key the server trusts, signing key first, each with its `kid`.

Rotation has an overlap period. Retired keys listed in `[issuer] previous_key_paths` stay trusted for verification and in the JWKS, but never sign. Tokens signed before the switch keep working until they expire, and can still be exchanged for children.

```toml
[issuer]
private_key_pem_path = "/etc/attenuo/issuer-2.pem"          # signs from now on
previous_key_paths   = ["/etc/attenuo/issuer-1.pem"]        # verify only
```

To rotate:

1. Generate the new key: `openssl genpkey -algorithm ed25519 -out /etc/attenuo/issuer-2.pem`, then `chmod 600` it. (The server also generates a key if the path does not exist.)
2. Edit the config: point `private_key_pem_path` at the new file and add the old file to `previous_key_paths`. A previous key file may be the old private key or just its public key (`openssl pkey -in issuer-1.pem -pubout -out issuer-1.pub`); only the public half is used, so prefer the public file and archive the private one.
3. Restart the server. It logs the new `kid` and how many previous keys it trusts. Check `/.well-known/jwks.json` lists both.
4. Wait at least the longest token lifetime (`default_ttl_seconds`, or the largest `ttl_seconds` you allow) plus `clock_skew`. By then every token signed by the old key has expired.
5. Remove `previous_key_paths`, restart, and destroy the old private key.

Notes:

- The originating-user block of a token (`ou_sig`) is signed once, at the root, and copied to every child. A child minted after the switch is signed by the new key but still carries an old-key `ou_sig` (its `ou_kid` names the old key), so the old key must stay trusted until the whole chain has expired. That is why step 4 waits for the longest chain, not for one token.
- A token whose `kid` is not in the trusted set is rejected with `invalid_grant`, whatever its signature. Tokens issued by a version before `kid` existed carry no `kid` and are tried against every trusted key.
- Third parties that verify attenuo tokens offline should select the key by `kid` and refresh the JWKS when they see an unknown one. `attenuo token inspect --verify` fetches the JWKS and trusts every key in it.
- In an emergency (key compromise), skip the overlap: replace the key and leave `previous_key_paths` empty. Every outstanding token stops verifying; agents re-run login and exchange.

The audit log does not depend on the issuer key. It is a plain SHA-256 hash chain, so rotation does not break `audit verify`. Old leases stay in the database but belong to tokens that no longer verify.

The PEM is the most sensitive file attenuo owns. Whoever has it can mint any token for any user. Back it up apart from the database, with the same care as any signing key.

## SQLite file: placement and backup

`[audit] sqlite_path` holds two things in one file: the hash-chained audit log and the lease registry. The server creates the parent directory if it is missing.

Placement:

- Put it on local, durable storage that the service user owns. The server refuses to start when the file's directory is on a network filesystem; see [Not on a network filesystem](#not-on-a-network-filesystem).
- Keep it away from anything agents can reach. Whoever can write the file can rewrite the log and un-revoke leases.
- In a container, mount a volume. The image's working directory is `/var/lib/attenuo`, owned by the `attenuo` user (uid 10001).
- Watch free disk space. An audit append that fails turns the decision into a deny with reason `audit_error`, so a full disk stops all calls and token issuance. That is the fail-closed rule working as designed.
- The audit log is never pruned, so the file grows for as long as the server takes traffic. There is no supported prune or rotation yet: a design that archives a prefix at a signed checkpoint and then prunes it is proposed in [ADR-0015](../decisions/0015-audit-retention.md), not built. Until then, size the volume for the log you expect to keep, export ranges you want to keep elsewhere (`attenuo audit export --from --to`, checked with `audit verify --file`), and do not delete rows by hand: a log whose first entries are missing fails `audit verify`, exactly as a truncated one does. How many bytes an entry takes has not been measured.
- The file runs in SQLite's WAL mode, so next to `attenuo.sqlite` you will see `attenuo.sqlite-wal` and `attenuo.sqlite-shm`. They belong to the database: keep them on the same volume, and never copy or delete one of the three on its own. A background thread folds the WAL into the main file every `[audit] wal_checkpoint_seconds` (default 5) and empties it when the server is idle and at a clean shutdown, so after `SIGTERM` the `-wal` file is empty. Under sustained load the `-wal` file grows to roughly 64 to 100 MB before it starts over; leave room for it.

### One process per file

At start-up the server takes an exclusive lock on `<sqlite_path>.lock` (for `/var/lib/attenuo/attenuo.sqlite`, `/var/lib/attenuo/attenuo.sqlite.lock`) and holds it until it exits. A second server pointed at the same file stops before it opens the database:

```text
Error: taking the single-writer fence of /var/lib/attenuo/attenuo.sqlite

Caused by:
    /var/lib/attenuo/attenuo.sqlite.lock is locked by another process: one server process per database file; stop the other instance first (in Kubernetes, use `strategy: Recreate`). The lock file records pid 1234, the last attenuo server that took it; if that process is gone, another program holds the lock (find it with `fuser` or `lsof`).
```

The pid is the one the lock file records, not necessarily the holder: any process that can open the file can lock it without writing to it. The server creates the lock file, the database and SQLite's `-wal` and `-shm` files with mode `0600` (owner only), and the data directory with `0700` when it creates it, so on a shared host other local users can neither read the log nor hold the lock. It narrows a lock file it finds with a wider mode to `0600`. It does not change the mode of a database file that already exists, so a file you made group-readable on purpose (for a backup user) stays that way, and SQLite gives the `-wal` and `-shm` files the same mode. A directory that already exists keeps its mode too: make sure only the server's user can write to it.

The lock is released when the process exits, also on a crash, `kill -9` or OOM kill, so a leftover `.lock` file never blocks a restart; do not delete it by hand. Why it exists: two servers on one file share the lease registry and counters but not the state that makes a credential single use, the run lock that serialises a run's budgeted decisions, or the loaded policy set, so an overlap silently weakens single-use credentials and run limits (see [What v0 is and is not](#what-v0-is-and-is-not)). The CLI is not affected: `attenuo audit verify` and `audit export` read through the admin API or from an export file, never the database itself.

This changes how you roll out a new version. Anything that starts the new instance before the old one has exited now gets a start-up failure instead of a silent overlap:

- **Kubernetes:** one replica, `strategy: type: Recreate`, and a `ReadWriteOnce` volume. The default `RollingUpdate` starts the new pod before the old one is gone, and even with `maxSurge: 0` a new pod can start while the old one is still terminating; the new pod would then fail and restart until the old one has exited. `Recreate` waits until the old pods have terminated before it creates the new one. Expect a short gap in service during a rollout (the old pod drains for up to 10 seconds, then the new one starts); attenuo fails closed, so agents see errors, not unchecked calls.

  ```yaml
  apiVersion: apps/v1
  kind: Deployment
  spec:
    replicas: 1
    strategy:
      type: Recreate
    template:
      spec:
        terminationGracePeriodSeconds: 15
  ```

- **Docker Compose, systemd, a VM pair:** stop the old instance before starting the new one; a failover script must make sure the old host has let go of the volume.

The lock is a `flock` advisory lock. It is reliable on a local disk and on a `ReadWriteOnce` volume mounted by one host. It is not a cluster lock: do not put the file on NFS (SQLite's WAL mode does not work there either, and the server refuses it, below).

Durability (`[audit] durability`):

- `"normal"` (the default) does not `fsync` on each commit. A process crash, `kill -9` or OOM kill loses nothing that was answered. A power failure or kernel crash can lose the most recent decisions, those written since SQLite's last sync, which happens at each WAL checkpoint, normally no more than `[audit] wal_checkpoint_seconds` (default 5) or 256 commits apart. Lower the interval to narrow that window. The log that remains is a clean prefix: no torn entry, no corruption, and `audit verify` passes with an earlier head. Lease revocations are always synced, so a revoked lease stays revoked.
- `"full"` syncs every commit, so an answered decision is on disk. Use it when your record-keeping rules say the audit trail must survive power loss. It costs throughput, mostly for a single client (each commit waits for its `fsync`; under concurrency group commit lets one `fsync` cover a batch): on the development container one client went from about 1,000 calls per second at `normal` to between about 450 and 830 at `full`, and 32 clients from about 4,500 to between 2,200 and 5,700, depending on what else the host was doing (see [performance](../design/performance.md)). On storage with slow syncs (network block devices, some cloud disks) the gap is larger.
- Either way, ship signed checkpoints off the host (below). After a power failure they are what tells you how much of the tail was lost.

Backup:

- Use SQLite's own backup, not a plain file copy, while the server runs: `sqlite3 /var/lib/attenuo/attenuo.sqlite ".backup '/backups/attenuo-$(date +%F).sqlite'"`. This needs the `sqlite3` command-line tool. Untested here.
- Keep the PEM and the config separately from the database backup.
- Know what a restore does. Restoring an old backup rewinds the lease registry, so a lease revoked after the backup is live again, and it cuts the audit log back to that point. After a restore, revoke anything that was revoked since, and note the gap.
- Copy `GET /admin/audit/checkpoint` (`{seq, head_hash, at, kid, signature}`) somewhere the server's host cannot write, such as a ticket system or a separate log store. A hash chain proves the log was not edited in the middle. It does not prove nobody truncated the end or rebuilt the chain. The server signs a checkpoint every `[audit] checkpoint_every` entries and every `checkpoint_interval_seconds`, and `audit verify` rejects a log that is shorter than a stored checkpoint or whose hash at that `seq` differs. The signing key is the server's own, so a checkpoint stored only on the host will not help if the server process is compromised. Set `[audit.sink]` (webhook, a file on another mount, or S3) so each checkpoint leaves the host when it is signed, with credentials that can add but not overwrite; then `attenuo audit verify --file export.jsonl --jwks jwks.json --checkpoints shipped.jsonl` shows any checkpoint signed again after it was shipped. Alert on `audit_sink_dropped_total` and on `readyz` reporting `"degraded": true`.
- Keep retired signing keys in `[issuer] previous_key_paths` for as long as you want old checkpoints to verify. Without the old key in the JWKS, a checkpoint it signed is reported invalid.

### Not on a network filesystem

Before it takes the lock, the server asks the operating system which filesystem holds the database's directory (`statfs`, after symbolic links are resolved) and refuses to start on a network filesystem:

```text
Error: checking the filesystem of /mnt/nfs/attenuo/attenuo.sqlite

Caused by:
    /mnt/nfs/attenuo is on a network filesystem (nfs): SQLite in WAL mode needs every process on one host, and file locks there may not keep a second writer out, so the audit log and lease registry could be corrupted. Put sqlite_path on a local disk or a volume one host mounts (a ReadWriteOnce volume), or set `[audit] allow_network_filesystem = true` if only one host ever mounts this filesystem and its locking works.
```

SQLite in WAL mode keeps its index in shared memory, which only works when every process is on one host, and on a network filesystem file locks (the single-writer lock included) may not keep a second writer out. What goes wrong is not an error but two writers that both think they hold the lock, and a corrupt log ([multi-replica design](../design/multi-replica.md), section 3 (d)).

- **Refused.** On Linux: NFS, SMB/CIFS (SMB 1 to 3), NCP, Coda, AFS, 9p (also WSL 2's `/mnt/c` and VM shared folders), CephFS and Lustre. On macOS: `nfs`, `smbfs`, `afpfs`, `webdav`, `cifs`.
- **Warned, not refused: FUSE.** The kernel reports one type for every FUSE filesystem, remote (sshfs, s3fs, GlusterFS, ceph-fuse) or local (fuse-overlayfs, the root filesystem of rootless containers; gocryptfs). The server starts and logs `the database is on a FUSE filesystem`. If yours is remote, move the file.
- **Not checked.** When `statfs` fails, or on a platform other than Linux, Android, macOS and iOS, the server logs that it could not tell and starts. Cluster filesystems on shared block storage (GFS2, OCFS2) are not detected.
- **Override.** `[audit] allow_network_filesystem = true` starts the server anyway and logs a warning at every start. Use it only when one host ever mounts the filesystem and you know its locking works; it does not make two servers on one file safe. Not tested against a real NFS or SMB mount: the detection is covered by tests of the type numbers and names, not by a mount.

## Leases: tuning the interval

Every hop's token is bound to a lease. A call is refused if any lease in the chain is revoked, unknown or expired. A holder keeps its lease alive with `POST /token/renew`. The setting is:

```toml
[issuer]
default_ttl_seconds    = 900   # token lifetime
lease_interval_seconds = 300   # how long a lease lives after issue or renewal
```

What the interval controls:

- **An explicit revoke** is immediate, at any interval. It does not wait for expiry.
- **An agent that dies or stops renewing** keeps working until its lease runs out, at most one interval, and never past the token's `exp`.

Shorter is safer and busier. Agents should renew at about a third of the interval, so a 300 second interval means a renewal every 100 seconds per live hop. Each renewal is one row in the audit log. At 60 seconds, a hop renews every 20 seconds, which is 180 rows an hour per hop just for renewals. Longer is quieter and leaves a crashed agent's access open longer.

Tokens still end at `default_ttl_seconds` whatever the lease says, and an exchange can ask for less. Start with the defaults. Move the interval down for high-risk tools, and measure the renewal traffic before you do.

If the lease interval is longer than the token lifetime, the lease is capped by the token, so the interval has no extra effect.

## Revoking during an incident

Revoke from what you know. All of these need the admin token, take effect on the next request, and write an `admin.lease.revoke` audit record:

- A lease id (from a denial's audit record, or the console): `attenuo lease revoke <id>`, everything delegated from it goes too.
- A run (the `chain_id` of its audit records): `attenuo lease revoke --chain-id <id>`, the whole delegation chain.
- A user (the `sub` your IdP issued, as in the audit records' `originating_subject`): `attenuo lease revoke --user <sub>`, every run of that user.
- An MCP session (the `Mcp-Session-Id` from a client's or upstream's logs): `attenuo lease revoke --session <id>`, the run that opened that session through the proxy. The server keeps only a hash of the id; the output shows the session's audit tag and the resolved `chain_id`.

Run the selector forms with `--preview` first: it lists the leases that would be revoked and changes nothing. The admin console does the same from a lease page: "Revoke chain…", "Revoke by session…" (you paste the session id; the console shows only its tag) and, when the lease has a recorded user, "Revoke all for <user>…" show the preview, then revoke after you give a reason and type a confirmation, and link to the audit record. The console listener needs `[admin_ui] allow_write = true` for the revocation itself. A user is matched by subject under every trusted issuer. Leases issued before the server recorded subjects are not matched by `--user`; if you upgraded during a user's run, revoke that run by `--chain-id` as well. To stop a user getting new tokens as well, disable them at the IdP: a revocation covers the leases that exist, not the next root token.

From code, the SDKs' admin clients send the same request: Python `admin.revoke_by_selector(chain_id=run, preview=True)`, then without `preview`; TypeScript `admin.revokeBySelector({ chainId: run }, { preview: true })`. `user=` / `{ user }` and `session=` / `{ session }` work the same way.

## Logging

The server logs through `tracing` to standard output. Control it with `RUST_LOG`.

| Level | What you get |
| --- | --- |
| `info` (default) | Startup, config path, issuer public key, policy ids, one line per authorization decision, token issuance, lease revocations |
| `warn` | Also shown at `info`: the dev root mint is on, the audit log is in memory, the key is ephemeral, rejected requests |
| `debug` | Per-request detail, for diagnosing a client. Noisy. Do not leave it on |

Examples: `RUST_LOG=info`, `RUST_LOG=attenuo_server=debug,info`.

**Format.** Text lines by default. For a log shipper (Loki, Elasticsearch, CloudWatch, a Kubernetes log pipeline), set `ATTENUO_LOG_FORMAT=json` or `[logging] format = "json"`; the variable wins over the file. Each line is then one JSON object:

```json
{"timestamp":"2026-11-12T19:14:20.540106Z","level":"INFO","message":"decision","decision":"Allow","reason":"\"policy_allow\"","subject":"\"alice@example.com\"","agent":"\"coder\"","server":"\"github\"","tool":"\"read_file\"","seq":4,"target":"attenuo_server::authz::pipeline","span":{"agent":"\"coder\"","chain_depth":2,"server":"\"github\"","session":"","subject":"\"alice@example.com\"","name":"mcp_request"},"spans":[{"...":"..."}]}
```

`timestamp`, `level`, `target` and `message` are always there; the event's own fields sit next to them, and `span` and `spans` carry the request context the text format prints before the message. Strings that come from a caller (subject, agent, server, tool, reason) are written in their escaped, quoted form, as in the text format, so a newline or a quote in them cannot forge a line or a field (SR-18); strip the outer quotes in the shipper if you want the bare value. An unknown format refuses to start.

**Colour.** ANSI colour codes are written only in the text format and only when standard output is a terminal, so a container, a systemd unit or a redirect to a file gets plain text. `NO_COLOR=1` switches them off on a terminal too.

**Personal data.** Log lines name the agent, the chain depth, the tool, the decision and, by default, the user subject (the decision and rejection lines, token issuance, approval decisions, and every line inside a proxied request's `mcp_request` span). A subject is usually personal data, such as an email address. If your logs go somewhere with wider access or a longer retention than the audit log, set `[logging] redact_subjects = true`: subjects are then written as `hmac:` and 16 hex digits, the same keyed digest trace export uses for `attenuo.subject_digest` ([observability](observability.md)), so you can still group lines by user and match them to traces, and find the user in the audit log, which always keeps the subject. The digest changes when the issuer key does. Agent ids, the actor token's subject on an exchange (a workload identity) and tool names are not redacted.

Log lines are an operational aid and are not the audit record. The audit log is the record. Do not rely on stdout for forensics.

## Docker and Compose

The repository has a `Dockerfile` with two targets and a `docker-compose.yml` that runs the leak demo. The compose file is a demo, not a production layout. `scripts/compose-smoke.sh` builds both targets, starts the compose demo, waits for the health check and plays the demo's scenario; CI runs it (the `compose` job). The release workflow's multi-arch build and push have not run yet.

The release image (target `runtime`, the default):

- holds `attenuo-server` and the `attenuo` CLI, nothing else from this repository, on `debian:bookworm-slim` with no extra packages (no `curl`; TLS uses rustls with its built-in roots, not the system store);
- runs as uid 10001 (`attenuo`), working directory `/var/lib/attenuo` (mode 0700);
- expects a config at `/etc/attenuo/config.toml` (the default `CMD` is `--config /etc/attenuo/config.toml`);
- exposes 8080 and has a `HEALTHCHECK` that runs `attenuo --server http://127.0.0.1:8080 health`, which asks `GET /healthz` and exits 0 or 1 ([CLI reference](../reference/cli.md#health)). If your `[server] listen` uses another port, override the health check with that port.

The demo image (target `demo`) adds the fake MCP server the demo uses as its GitHub upstream. Never deploy it.

```sh
docker build -t attenuo:dev .                  # release image
docker build --target demo -t attenuo:demo .   # demo image
```

For anything beyond the demo, start from the demo's compose file and change these things:

```yaml
services:
  attenuo:
    image: attenuo:dev
    command: ["--config", "/etc/attenuo/config.toml"]
    ports:
      - "127.0.0.1:8080:8080"        # reverse proxy on the host or in another container
      # [admin] listen (9102 here) is not published; operators reach it from the host's
      # loopback only if you add "127.0.0.1:9102:9102", or with docker compose exec.
    volumes:
      - ./attenuo.toml:/etc/attenuo/config.toml:ro
      - ./policy.cedar:/etc/attenuo/policy.cedar:ro
      - ./issuer.pem:/etc/attenuo/issuer.pem:ro
      - attenuo-data:/var/lib/attenuo
    stop_grace_period: 15s         # the server drains for up to 10s after SIGTERM
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true

volumes:
  attenuo-data:
```

Keys that differ between deployments of the same file can come from the environment instead, as `ATTENUO__<SECTION>__<KEY>` ([environment overrides](../reference/config.md#environment-overrides)). The container-specific addresses are the usual ones:

```yaml
services:
  attenuo:
    environment:
      ATTENUO__SERVER__LISTEN: "0.0.0.0:8080"        # inside the container only
      ATTENUO__ADMIN__LISTEN: "0.0.0.0:9102"         # not published
      ATTENUO__SERVER__PUBLIC_URL: "https://attenuo.example.com"
      ATTENUO_ADMIN_TOKEN: ${ATTENUO_ADMIN_TOKEN:?set ATTENUO_ADMIN_TOKEN}
```

The server applies them before its startup checks, logs the names of the keys they set (never the values), and refuses to start on a variable it cannot apply: a misspelt name, a value of the wrong type, an empty value, a list or `[[...]]` entry, or any `[dev]` key. The same file can then run on a workstation with its loopback defaults. A plain `docker run` takes them as `-e ATTENUO__SERVER__LISTEN=0.0.0.0:8080`.

Matching settings in `attenuo.toml`: `policies_path = "/etc/attenuo/policy.cedar"`, `private_key_pem_path = "/etc/attenuo/issuer.pem"`, `sqlite_path = "/var/lib/attenuo/attenuo.sqlite"`, `listen = "0.0.0.0:8080"` (inside the container only; the published port stays on loopback), `public_url` set to the URL clients use, which a non-loopback `listen` requires, and `[admin] listen` on a port of its own (the server refuses to start with the admin API on a non-loopback main listener otherwise). The demo's `examples/github-leak-demo/config.docker.toml` binds `[admin] listen = "0.0.0.0:9102"` and does not publish it. The server then logs the start-up warning `[admin] listener is not on loopback: restrict it with network policy to the hosts operators use`, which is expected here: inside a container, `0.0.0.0` is what lets a port mapping or another container reach the listener at all, and while 9102 is not published only containers on the compose network can reach it. This production layout itself (volume, key file, restart policy) has not been run; the demo's compose file, which shares the image, ports, health check and hardening options, is what `scripts/compose-smoke.sh` tests.

Notes:

- **Signals.** The server shuts down gracefully on SIGTERM (what `docker stop` and Kubernetes send) and on SIGINT. It stops accepting connections, gives in-flight requests up to 10 seconds to finish (on the admin API, admin console and metrics listeners too), stops its timers, closes the database and releases its lock, then exits; it logs `shutdown signal received; draining`, `shutdown complete` and `single-writer fence released`. Set `stop_grace_period` (or `terminationGracePeriodSeconds`) above 10 seconds. No `stop_signal` override is needed. SQLite writes are transactional, so even a kill does not corrupt the log.
- **Read-only root.** The server only writes under the data directory and, when the key file is missing, to the key path. Keep the key file in the read-only mount, so a missing key is an error you see, not a new key you did not plan.
- **Upstreams** must be reachable from the container. `127.0.0.1` in `[[upstreams]]` means the container itself. The proxy gives an upstream `[proxy] upstream_connect_timeout_seconds` (default 5) to accept a connection and `upstream_response_timeout_seconds` (default 120) to send response headers, or a JSON answer it must read; past that the agent gets `502 upstream_unreachable` or `504 upstream_timeout`. Raise the second for tools that answer in JSON after a long run. Streams (SSE) are not cut by it.

## Health and readiness

`GET /healthz` returns `{"status":"ok","version":"..."}` with HTTP 200. It is a liveness check only. It does not open the database, check disk space or contact an identity provider. A server whose SQLite file is read-only or full still answers `ok`, and then denies every call.

`GET /readyz` is the readiness check. It reads the head of the audit log and one row of the lease store, and checks whether the last audit append failed. It answers 200 `{"ready":true,"checks":{"audit":"ok","audit_append":"ok","leases":"ok"}}` when all is well, and 503 with `"error"` on the failing check otherwise, for example `{"ready":false,"checks":{"audit":"ok","audit_append":"error","leases":"ok"}}`. A full disk is the usual cause of `audit_append`: reads still work, but every append fails and every decision is denied with `audit_error`. The check writes nothing; it clears with the next append that succeeds. Because an instance out of rotation gets no traffic, and so no append that could clear it, it also clears 30 seconds after the failure if nothing was appended since: the instance is then offered traffic again, and the next failed append takes it out again. Alert on `audit_append_errors_total` rather than on the flapping. Point a load balancer or Kubernetes `readinessProbe` at it; keep `/healthz` for the liveness probe so a full disk takes the instance out of rotation instead of restarting it. Where there is no HTTP client to probe with (the release image has no `curl`), `attenuo health` asks `/healthz` and `attenuo health --ready` asks `/readyz`, exiting 0 or 1 ([CLI reference](../reference/cli.md#health)). It needs no credentials, so the body names only the check and `ok` or `error`; the storage error (SQLite message, file path) is written to the server log at `warn` level.

Startup is quick: parse config, load the key, open SQLite, load policy. Config, policy or catalog errors stop the process with a message instead of starting a half-working server.

Reloading policy does not need a restart: `attenuo policy reload`. A bad policy file leaves the old policy in force. Changing the config file, the catalog or the key does need a restart.

## What to monitor

Enable the Prometheus endpoint with a separate listener, so it is never exposed on the proxy port by accident:

```toml
[metrics]
enabled = true
listen = "127.0.0.1:9100"
```

`GET http://127.0.0.1:9100/metrics` has no authentication. Keep it on loopback or a private network and scrape it from there. The server refuses to start when `listen` is not a loopback address, unless you also set `allow_public = true` (it then logs a warning); do that only for a private interface that network policy protects, since decision counts by reason are served to anyone who can connect. The API port does not serve `/metrics`. Every series is prefixed `attenuo_`; the full list, with types, labels and help text, is in the [HTTP API reference](../reference/http-api.md#metrics). The metrics are not pushed over OTLP: to get these series into an OpenTelemetry collector, scrape this listener with the collector's Prometheus receiver. Traces are exported over OTLP with `[telemetry]`; see [Observability](observability.md). The ones to watch first:

| Series | What it tells you |
|---|---|
| `decisions_total{decision, reason}` | Allows and denies by reason code. A jump in one reason is the first sign of a misconfigured client, an expired lease population or a prompt-injected agent. |
| `audit_append_errors_total` | Every one denied a call (`audit_error`). Should stay at 0. |
| `requests_shed_total`, `requests_rate_limited_total{limit, cause}`, `request_timeouts_total{kind}` | `[limits]` at work: requests refused because `max_in_flight` were running, refused by a rate limit (`cause="table_full"` means `rate_limit_max_keys` is too small for the number of callers), and past a deadline. A steady rise in shed requests means the server is at capacity. |
| `audit_append_shed_total{cause}` | Audit appends that failed fast instead of waiting for the writer: `timeout` (no answer within `[audit] append_timeout_seconds`, usually a stalled disk) or `queue_full`. Each denied a call with `audit_error`. Should stay at 0. |
| `authorize_duration_seconds`, `proxy_stage_seconds{stage}` | Decision time and where it goes. |
| `budget_exhausted_total{kind, at}`, `budget_charges_total{kind}`, `budget_refunds_total{source}` | Run limits (ADR-0010) being hit, spent and given back. `at="charge"` means two calls of one run raced for the last of a budget. |
| `approvals_created_total`, `approvals_decided_total{outcome, by}`, `approvals_consumed_total{by}`, `approvals_expired_total` | The approval queue: created minus decided is what people still have to answer; expired attempts mean approvals answered too late. |
| `results_recorded_total{label}`, `taint_matches_total{decision}` | Output labelling (ADR-0009): untrusted results coming in, and destructive calls that carry text copied from them. |
| `run_lock_wait_seconds` | Contention on the per-run lock (SR-55) between calls of one delegation run that has limits or keeps run usage. |
| `audit_checkpoint_last_timestamp_seconds`, `audit_wal_last_complete_timestamp_seconds`, `audit_wal_checkpoints_total{result}`, `audit_wal_backstops_total` | Signed checkpoints and the SQLite WAL checkpointer keeping up. |
| `audit_sink_dropped_total`, `audit_sink_oldest_undelivered_timestamp_seconds` | Checkpoints not leaving the host. |
| `approval_notify_dropped_total`, `approval_notify_outbox_rows` | `[approvals.notify]` notices given up, and notices stored but not yet delivered. The outbox count staying up means the receiver is down; the notices survive a restart. |

Alert on any increase of `audit_append_errors_total`, on a rising share of `reason="lease_expired"`, on `audit_sink_dropped_total` and on `readyz` returning 503. Example Prometheus rules for the newer series; tune the thresholds to your traffic:

```yaml
groups:
  - name: attenuo
    rules:
      # Run limits refusing far more calls than usual: an agent looping on a tool, or limits
      # set too low for real work.
      - alert: AttenuoBudgetExhaustedSpike
        expr: |
          sum(rate(attenuo_budget_exhausted_total[5m]))
            > 5 * sum(rate(attenuo_budget_exhausted_total[1h] offset 1h)) + 0.1
        for: 10m
      # Calls of one run waiting on each other: many concurrent calls in one limited run.
      - alert: AttenuoRunLockWaitHigh
        expr: |
          histogram_quantile(0.99, sum by (le) (rate(attenuo_run_lock_wait_seconds_bucket[5m])))
            > 0.05
        for: 10m
      # No signed checkpoint for three timer periods although decisions are being made, or
      # the WAL checkpointer stopped completing rounds (the WAL file then grows).
      - alert: AttenuoCheckpointStale
        expr: |
          (time() - attenuo_audit_checkpoint_last_timestamp_seconds > 900
            and on() sum(rate(attenuo_decisions_total[15m])) > 0)
          or (time() - attenuo_audit_wal_last_complete_timestamp_seconds > 300)
        for: 5m
```

The 900 seconds assume the default `[audit] checkpoint_interval_seconds = 300`: with entries arriving, a checkpoint is signed at least that often. The checkpoint timestamp is 0 until the process writes its first checkpoint, so a fresh process that takes traffic counts as stale until it does, which the default timer settles within five minutes. `audit_wal_backstops_total` going up means the background checkpointer fell behind the writer (a slow disk under sustained load).

Beyond the metrics, watch these:

From the process and the host:

- The process is alive, and `/healthz` answers.
- Disk space under the SQLite directory.
- The file size of the SQLite database, as a trend.

From the logs:

- `warn` lines. A rise in rejections can mean a misconfigured client or an attack.
- `503` answers from `POST /token` with `jwks_unavailable`. That is your identity provider or the network path to it.

From the audit log (`GET /admin/audit`, `attenuo audit tail`):

- The count of denies by reason. A jump in `capability_denied` or `policy_deny` for one agent often means a prompt-injected agent. A jump in `lease_expired` means agents that stopped renewing. `lease_revoked` denies after a revocation, under `initialize`, `tools/list` or a tool, mean an agent or its client is still using the revoked token.
- Any `audit_error`, `lease_error` or `policy_error`. These are internal failures and every one denied a call.
- `token.root` rows per user and agent. Root mints are the entry point of every chain.
- `audit verify` on a schedule. It exits 2 on a broken chain or an invalid checkpoint, and 1 when it could not check (server unreachable, bad admin token).
- The checkpoint `seq` should only grow. Compare each reading with the last.

If you run a second system that needs to react to revocations, such as an AuthZEN PEP, remember it learns only by asking. There is no push channel in v0.

## Upgrades

Until 1.0, minor versions can change the config, the token format and the database layout. Read the [CHANGELOG](https://github.com/attenuo-dev/attenuo/blob/main/CHANGELOG.md) before every upgrade, and back up the database and the key first. Tokens issued by one version may not verify on the next. Plan to re-mint.

### The database schema

The SQLite file carries a schema version (SQLite's `user_version`). Each build knows the newest version it can read, and upgrades the file to it when it starts. An upgrade of the database goes like this:

1. Stop the old server, and wait until it has exited (it holds the [single-writer lock](#one-process-per-file)).
2. Back up the file with `sqlite3 attenuo.sqlite ".backup '/backups/attenuo-before-upgrade.sqlite'"`, or copy `attenuo.sqlite`, `-wal` and `-shm` together while nothing runs. This backup is the only way back.
3. Start the new binary. Before it serves anything, it brings the file to its schema version, each step in one transaction, and logs it (timestamps left out):

   ```text
   INFO attenuo_server::state: database schema migrated path="/var/lib/attenuo/attenuo.sqlite" from=0 to=4
   INFO attenuo_server::state: audit store opened (WAL) path="/var/lib/attenuo/attenuo.sqlite" durability=normal wal_checkpoint_seconds=5 schema_version=4
   ```

   `from=0` is a new file or one written before schema versions existed; a file from a build whose newest version was 1, 2 or 3 shows `from=1`, `from=2` or `from=3`. Every start logs `schema_version` on the `audit store opened` line, so the version a server runs on is in its start-up log. A step that fails leaves the file at the version before it, and the server does not start; the error names the step.

Rules that follow from this:

- **There is no downgrade.** An older binary refuses a file a newer one has migrated, before it reads or writes anything:

  ```text
  Error: opening audit log /var/lib/attenuo/attenuo.sqlite

  Caused by:
      the database has schema version 2, written by a newer attenuo; this build reads schema versions up to 1. Run the newer binary, or restore the backup taken before upgrading: there is no downgrade
  ```

  To go back, restore the backup from step 2. Whatever happened after the upgrade, decisions and revocations included, is not in it (see "Know what a restore does" under [Backup](#sqlite-file-placement-and-backup)).
- **A file from before schema versions** (any build before this was added) is adopted as version 1 at the first start: tables and indexes that came later are created, the two `approvals` columns that came later are added, and no row changes, so the audit chain, its head and the signed checkpoints stay as they were. A log written before records had `kind` and `chain_id`, or hashed before RFC 8785 canonical JSON, is refused as before: move it aside and start a new file.
- **Version 2** rebuilds the `approvals` table so that an approval's position, which `GET /admin/approvals` pages by, is never given twice. Every approval keeps its values and its place in the order; the step copies the table once, which is quick for any number of approvals a server keeps. A build that reads only version 1 refuses the file afterwards, as above.
- **Version 3** adds the `used_credentials` table, which records the single-use credentials the server has accepted (ID tokens, ID-JAGs, actor tokens, exchanges, approval ID tokens) so that they stay used across a restart. It starts empty and no other table changes. The upgrade restart is the last one that forgets a credential: one redeemed by the old binary and not yet expired can be redeemed once more after it. A build that reads only version 2 refuses the file afterwards.
- **Version 4** adds a nullable `issuer` column to `lease_subjects`: the server now records the originating user's IdP issuer with the subject of each lease it issues, which the admin lease tree needs to find the run's per-user windows. Existing rows keep their subject and get no issuer; the lease tree of a run issued before the upgrade answers `user_windows: null`. A build that reads only version 3 refuses the file afterwards.
- Several servers on one file are already ruled out by the lock, so a migration never races a running server.

**Run limits need every server on 0.1.0 or later.** A `limits` block in a capability is an open field that older servers accept and ignore, so a token whose budget says "at most 2 payments" is unlimited when an older binary checks it (any build from `main` before run limits landed on 2026-10-24). Nothing fails and nothing is logged: the decision record of the old server simply has no `budget` member. Until every replica, and every external PEP that reads `limits`, runs 0.1.0 or later, do not rely on a limit for safety; use a Cedar `forbid` for the same call, or an approval, and add the limit on top. Check the mixed-version window with `attenuo audit tail --json`: a `decision` record for a limited capability without `budget` came from an old server. (The injection-suite runner probes for this before its limits arms and refuses to run them against an old server.)
