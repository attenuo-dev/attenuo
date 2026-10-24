# Deploying

This guide covers what to change between "it runs on my laptop" and "other people and other machines depend on it". Read the limits first. They decide whether v0 fits your situation.

## What v0 is and is not

attenuo is pre-alpha. Do not treat this guide as a statement that it is ready for production. It is a list of what you would have to do if you ran it anyway, for example in a staging environment or a closed pilot.

- **One node.** There is no clustering, no replication and no leader election. One server process owns one SQLite file.
- **SQLite only.** The audit log and the lease registry live in the same SQLite file, in WAL mode. Store calls run on the blocking pool, and audit appends go through one writer thread that commits whatever is queued in one transaction (group commit). On a shared 4-core development container a file-backed server handled about 3,000 to 4,500 calls per second at one hop (memory: about 5,000 to 6,600); see [design/performance.md](../design/performance.md) for the method and the caveats.
- **No high availability.** If the process is down, every call through the proxy fails. That is by design: attenuo fails closed. Do not start a second replica against the same file, or against a copy. Each process would keep its own idea of which leases are revoked.
- **No TLS.** The server speaks plain HTTP. Terminate TLS in front of it.
- **One static admin token.** There are no operator accounts or roles. Admin actions (lease revocations, policy reloads, development root mints) are recorded in the audit log as `by urn:attenuo:admin`, a subject no identity provider can issue (the `urn:attenuo:` prefix is reserved).
- **Metrics on a side listener only.** `GET /metrics` (Prometheus text) is served on its own loopback listener when you enable it, with no authentication. See [What to monitor](#what-to-monitor).
- **Manual key rotation with no overlap.** See [Key rotation](#key-rotation).

The full list of known gaps is at the end of [design/server.md](../design/server.md#known-limits-v0). The open security findings are in [the security review](../research/security-review-2026-10-22.md) and on the [task board](../tasks/board.md).

## Production checklist

Go through this before pointing anything real at the server.

- [ ] `[dev] allow_root_mint` is `false` or absent. With it on, anyone holding the admin token can mint a root token for any user.
- [ ] Root tokens come from a real identity provider: `[[idps]]`, `[[agents]]`, `[[root_grants]]`. See [Identity providers](identity-providers.md).
- [ ] The admin token (`[admin] token`, or `ATTENUO_ADMIN_TOKEN`, which overrides it) is a long random value that is not in any example, not in version control and not shared with agents. Generate it with `openssl rand -hex 32`. Off a loopback `listen` address the server refuses to start without one, with one shorter than 32 bytes, or with a known placeholder; it cannot tell whether your token was leaked.
- [ ] Every agent that receives a token is an `[[agents]]` entry with its own secret: token exchanges authenticate as their `actor` (`[token] require_actor_auth`, on by default).
- [ ] `[policy] unknown_tools` is `deny` (the default) or `sensitive`, not `allow`.
- [ ] `/admin/*` is not reachable from the networks agents live on. See [Network exposure](#network-exposure).
- [ ] TLS terminates in front of attenuo, and agents reach it over HTTPS only.
- [ ] `[issuer] private_key_pem_path` is set, the file is mode 0600, owned by the service user, and backed up somewhere safe. Without the setting the server makes a new key at every start and every token dies on restart.
- [ ] `[audit] sqlite_path` is a real path on durable storage. The default is `:memory:`, which loses the audit log and every lease on exit. The server logs a warning when it is in memory.
- [ ] `[issuer] issuer` is the URL clients will use, for example `https://attenuo.example.com`. It becomes the `iss` of every token, and changing it later invalidates tokens. `[server] public_url` is set to the same base URL so the AuthZEN discovery document points at the right host. Off a loopback `listen` address the server refuses to start without it.
- [ ] `[policy] policies_path` points at your policy, and the catalog lists every tool a policy names.
- [ ] Every tool on the upstream that agents should call is in the catalog. With the default `[policy] unknown_tools = "deny"`, a tool missing from the catalog is denied with `tool_not_in_catalog`; with `"allow"` it is neither `readonly` nor `sensitive`, so rules that depend on those attributes do not see it.
- [ ] The config file is mode 0600. It holds secret hashes and possibly the admin token. The admin token can come from `ATTENUO_ADMIN_TOKEN` instead; there is no other environment-variable substitution, so inject the file at deploy time.
- [ ] You have read the [threat model](../spec/threat-model.md) section "What attenuo does not prevent" and have decided how the agents' other routes (direct API keys, local STDIO servers) are closed.
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

Binding to `0.0.0.0` puts `/admin` on the same listener as everything else. The static admin token is then the only thing between the network and "revoke any lease, reload policy, read the audit log". Route `/admin` away from the public listener at the reverse proxy, or give operators a separate path to a loopback-only port by running the CLI on the host or over an SSH tunnel.

Two other exposure points to think about:

- **`POST /access/v1/evaluation` without a bearer** is refused with 401 unless `[authzen] allow_unsigned_chain = true`. With it on, only `[[peps]]` clients that authenticate can send a chain in the body, and the chain must be one this server issued (each lease is bound to its chain). See [Integrating MCP clients](integrating-mcp-clients.md#using-the-authzen-endpoint-from-a-non-mcp-pep).
- **`POST /token` for hop 0** does an outbound fetch to your identity provider's discovery and JWKS URLs, but only after the agent has authenticated. Unknown issuers are rejected without a network call.

## TLS and a reverse proxy

Put anything that terminates TLS in front: Caddy, nginx, Envoy, a cloud load balancer. Two things matter for MCP:

- **Do not buffer responses.** Streamable HTTP can answer with `text/event-stream`. A proxy that buffers will hold events back.
- **Keep read timeouts long** enough for slow tools.

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

This hides `/admin` from the public name. Operators reach it on `127.0.0.1:8080` directly.

For nginx, the equivalent pieces are `proxy_pass http://127.0.0.1:8080;`, `proxy_buffering off;`, `proxy_http_version 1.1;` and a `location /admin/ { return 404; }` block. Untested.

attenuo builds the AuthZEN discovery document from `[server] public_url`, which is required whenever `listen` is not a loopback address, so a forged `Host` header cannot put another host's URLs into a document a shared cache might keep. Only on a loopback listener without `public_url` does it fall back to `Host`, and then it accepts only `localhost`, `127.0.0.1` or `[::1]` (with an optional port) and answers 400 `invalid_host` to anything else. It does not use `X-Forwarded-*` headers.

## Admin token handling

- The token is compared in constant time, and a missing token disables `/admin` (403) rather than opening it.
- It sits in the config file in clear text. Treat the file as a secret: mode 0600, not in the image, not in the repository, not in a CI log. In Docker or Kubernetes, mount the whole file from a secret.
- Operators pass it to the CLI with `ATTENUO_ADMIN_TOKEN`, `--admin-token-stdin` or `--admin-token-file`. `--admin-token` still works but prints a warning, since command-line arguments show up in process listings (`ps`, `/proc/<pid>/cmdline`) and shell history. The same goes for an agent's client secret (`ATTENUO_CLIENT_SECRET`, `--client-secret-stdin`, `--client-secret-file`).
- Rotating it means editing the file and restarting. There is no overlap window and no way to have two tokens.
- Do not hand the admin token to agents. It can revoke any lease and read all audit entries. Agents use delegation tokens only.

This is the weakest part of v0. Real operator authentication is on the [task board](../tasks/board.md).

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

- Put it on local, durable storage that the service user owns. SQLite over NFS or other network file systems is a known source of locking trouble.
- Keep it away from anything agents can reach. Whoever can write the file can rewrite the log and un-revoke leases.
- In a container, mount a volume. The image's working directory is `/var/lib/attenuo`, owned by the `attenuo` user (uid 10001).
- Watch free disk space. An audit append that fails turns the decision into a deny with reason `audit_error`, so a full disk stops all calls and token issuance. That is the fail-closed rule working as designed.
- The file runs in SQLite's WAL mode, so next to `attenuo.sqlite` you will see `attenuo.sqlite-wal` and `attenuo.sqlite-shm`. They belong to the database: keep them on the same volume, and never copy or delete one of the three on its own. A background thread folds the WAL into the main file every `[audit] wal_checkpoint_seconds` (default 5) and empties it when the server is idle and at a clean shutdown, so after `SIGTERM` the `-wal` file is empty. Under sustained load the `-wal` file grows to roughly 64 to 100 MB before it starts over; leave room for it.

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

## Logging

The server logs through `tracing` to standard output. Control it with `RUST_LOG`.

| Level | What you get |
| --- | --- |
| `info` (default) | Startup, config path, issuer public key, policy ids, one line per authorization decision, token issuance, lease revocations |
| `warn` | Also shown at `info`: the dev root mint is on, the audit log is in memory, the key is ephemeral, rejected requests |
| `debug` | Per-request detail, for diagnosing a client. Noisy. Do not leave it on |

Examples: `RUST_LOG=info`, `RUST_LOG=attenuo_server=debug,info`.

Output has ANSI colour codes by default. Set `NO_COLOR=1` to switch them off for log shippers.

Log lines name the agent, the user subject, the chain depth, the tool and the decision. They are an operational aid and are not the audit record. The audit log is the record. Do not rely on stdout for forensics.

## Docker and Compose

The repository has a `Dockerfile` and a `docker-compose.yml`. Both are marked untested in the repository, and the compose file is the leak demo, not a production layout.

The image:

- builds `attenuo-server`, the `attenuo` CLI and the fake MCP server from source;
- runs as uid 10001 (`attenuo`), working directory `/var/lib/attenuo`;
- expects a config at `/etc/attenuo/config.toml` (the default `CMD` is `--config /etc/attenuo/config.toml`);
- exposes 8080 and has a `HEALTHCHECK` that calls `/healthz`;
- includes `curl` for that check.

```sh
docker build -t attenuo:dev .
```

For anything beyond the demo, start from the demo's compose file and change these things:

```yaml
services:
  attenuo:
    image: attenuo:dev
    command: ["--config", "/etc/attenuo/config.toml"]
    ports:
      - "127.0.0.1:8080:8080"        # reverse proxy on the host or in another container
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

Matching settings in `attenuo.toml`: `policies_path = "/etc/attenuo/policy.cedar"`, `private_key_pem_path = "/etc/attenuo/issuer.pem"`, `sqlite_path = "/var/lib/attenuo/attenuo.sqlite"`, `listen = "0.0.0.0:8080"` (inside the container only; the published port stays on loopback) and `public_url` set to the URL clients use, which a non-loopback `listen` requires. This layout is untested.

Notes:

- **Signals.** The server shuts down gracefully on SIGTERM (what `docker stop` and Kubernetes send) and on SIGINT. It stops accepting connections, gives in-flight requests up to 10 seconds to finish, then exits; it logs `shutdown signal received; draining` and `shutdown complete`. Set `stop_grace_period` (or `terminationGracePeriodSeconds`) above 10 seconds. No `stop_signal` override is needed. SQLite writes are transactional, so even a kill does not corrupt the log.
- **Read-only root.** The server only writes under the data directory and, when the key file is missing, to the key path. Keep the key file in the read-only mount, so a missing key is an error you see, not a new key you did not plan.
- **Upstreams** must be reachable from the container. `127.0.0.1` in `[[upstreams]]` means the container itself.

## Health and readiness

`GET /healthz` returns `{"status":"ok","version":"..."}` with HTTP 200. It is a liveness check only. It does not open the database, check disk space or contact an identity provider. A server whose SQLite file is read-only or full still answers `ok`, and then denies every call.

`GET /readyz` is the readiness check. It reads the head of the audit log and one row of the lease store. It answers 200 `{"ready":true,"checks":{"audit":"ok","leases":"ok"}}` when both work, and 503 `{"ready":false,"checks":{"audit":"error","leases":"ok"}}` when one does not. Point a load balancer or Kubernetes `readinessProbe` at it; keep `/healthz` for the liveness probe so a full disk takes the instance out of rotation instead of restarting it. It needs no credentials, so the body names only the check and `ok` or `error`; the storage error (SQLite message, file path) is written to the server log at `warn` level.

Startup is quick: parse config, load the key, open SQLite, load policy. Config, policy or catalog errors stop the process with a message instead of starting a half-working server.

Reloading policy does not need a restart: `attenuo policy reload`. A bad policy file leaves the old policy in force. Changing the config file, the catalog or the key does need a restart.

## What to monitor

Enable the Prometheus endpoint with a separate listener, so it is never exposed on the proxy port by accident:

```toml
[metrics]
enabled = true
listen = "127.0.0.1:9100"
```

`GET http://127.0.0.1:9100/metrics` has no authentication. Keep it on loopback or a private network and scrape it from there. The server refuses to start when `listen` is not a loopback address, unless you also set `allow_public = true` (it then logs a warning); do that only for a private interface that network policy protects, since decision counts by reason are served to anyone who can connect. The API port does not serve `/metrics`. Every series is prefixed `attenuo_`; the full list, with types, labels and help text, is in the [HTTP API reference](../reference/http-api.md#metrics). The ones to watch first:

| Series | What it tells you |
|---|---|
| `decisions_total{decision, reason}` | Allows and denies by reason code. A jump in one reason is the first sign of a misconfigured client, an expired lease population or a prompt-injected agent. |
| `audit_append_errors_total` | Every one denied a call (`audit_error`). Should stay at 0. |
| `authorize_duration_seconds`, `proxy_stage_seconds{stage}` | Decision time and where it goes. |
| `budget_exhausted_total{kind, at}`, `budget_charges_total{kind}`, `budget_refunds_total{source}` | Run limits (ADR-0010) being hit, spent and given back. `at="charge"` means two calls of one run raced for the last of a budget. |
| `approvals_created_total`, `approvals_decided_total{outcome, by}`, `approvals_consumed_total{by}`, `approvals_expired_total` | The approval queue: created minus decided is what people still have to answer; expired attempts mean approvals answered too late. |
| `results_recorded_total{label}`, `taint_matches_total{decision}` | Output labelling (ADR-0009): untrusted results coming in, and destructive calls that carry text copied from them. |
| `run_lock_wait_seconds` | Contention on the per-run lock (SR-55) between calls of one delegation run that has limits or keeps run usage. |
| `audit_checkpoint_last_timestamp_seconds`, `audit_wal_last_complete_timestamp_seconds`, `audit_wal_checkpoints_total{result}`, `audit_wal_backstops_total` | Signed checkpoints and the SQLite WAL checkpointer keeping up. |
| `audit_sink_dropped_total`, `audit_sink_oldest_undelivered_timestamp_seconds` | Checkpoints not leaving the host. |

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

- The count of denies by reason. A jump in `capability_denied` or `policy_deny` for one agent often means a prompt-injected agent. A jump in `lease_expired` means agents that stopped renewing.
- Any `audit_error`, `lease_error` or `policy_error`. These are internal failures and every one denied a call.
- `token.root` rows per user and agent. Root mints are the entry point of every chain.
- `audit verify` on a schedule. It exits 1 on a broken chain.
- The checkpoint `seq` should only grow. Compare each reading with the last.

If you run a second system that needs to react to revocations, such as an AuthZEN PEP, remember it learns only by asking. There is no push channel in v0.

## Upgrades

Until 1.0, minor versions can change the config, the token format and the database layout. Read the [CHANGELOG](https://github.com/attenuo-dev/attenuo/blob/main/CHANGELOG.md) before every upgrade, and back up the database and the key first. Tokens issued by one version may not verify on the next. Plan to re-mint.

**Run limits need every server on 0.1.0 or later.** A `limits` block in a capability is an open field that older servers accept and ignore, so a token whose budget says "at most 2 payments" is unlimited when an older binary checks it (any build from `main` before run limits landed on 2026-10-24). Nothing fails and nothing is logged: the decision record of the old server simply has no `budget` member. Until every replica, and every external PEP that reads `limits`, runs 0.1.0 or later, do not rely on a limit for safety; use a Cedar `forbid` for the same call, or an approval, and add the limit on top. Check the mixed-version window with `attenuo audit tail --json`: a `decision` record for a limited capability without `budget` came from an old server. (The injection-suite runner probes for this before its limits arms and refuses to run them against an old server.)
