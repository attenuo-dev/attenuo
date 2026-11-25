# Deploying

This guide covers what to change between "it runs on my laptop" and "other people and other machines depend on it". Read the limits first. They decide whether v0 fits your situation.

## What v0 is and is not

attenuo is pre-alpha. Do not treat this guide as a statement that it is ready for production. It is a list of what you would have to do if you ran it anyway, for example in a staging environment or a closed pilot.

- **One node.** There is no clustering, no replication and no leader election. One server process owns one SQLite file, and the server enforces it: a second server on the same file refuses to start (see [One process per file](#one-process-per-file)).
- **SQLite only.** The audit log and the lease registry live in the same SQLite file, in WAL mode. Store calls run on the blocking pool, and audit appends go through one writer thread that commits whatever is queued in one transaction (group commit). On a shared 4-core development container a file-backed server handled about 3,000 to 4,500 calls per second at one hop (memory: about 5,000 to 6,600); see [design/performance.md](../design/performance.md) for the method and the caveats.
- **No high availability.** If the process is down, every call through the proxy fails. That is by design: attenuo fails closed. Do not start a second replica against the same file, or against a copy. Against a copy, each process keeps its own idea of which leases are revoked and how much of a run limit is spent. Against the same file, the lease registry and the counters are shared, but the state that makes a credential single use, the locks that serialise a run's budgeted decisions and a user's decisions under a per-user window, and the loaded policy set live in each process, so a credential can be redeemed once per replica and a reload reaches one replica only. Per-user windows (`context.usage.user_window`) are therefore a single-replica guarantee: against a copy each replica keeps its own windows, so a user gets the cap once per replica, and against the same file two replicas can each pass a call the window should have stopped. A window that guards money should also run at `[audit] durability = "full"`: at `"normal"` a power failure can drop the newest commits, and a lost window charge can be spent again in the same window (a call that also charges a `sum` limit already commits with a full sync). The inventory is in [multi-replica readiness](../design/multi-replica.md) (proposed).
- **TLS on the main listener only, and off by default.** The server speaks plain HTTP unless you set `[server.tls]`. Most setups still end TLS in a reverse proxy in front of it. The admin, console and metrics listeners always speak plain HTTP. See [TLS in attenuo itself](#tls-in-attenuo-itself).
- **Static admin tokens.** Each operator can have a token of its own with a role (`[[admin.operators]]`, [ADR-0016](../decisions/0016-admin-operators.md)): `viewer`, `operator` (also revokes and decides approvals) or `admin`. There is no login, no expiry and no rotation short of editing the config and restarting. Admin actions (lease revocations, policy reloads, refunds, development root mints, operator approvals) are recorded in the audit log under the operator, `urn:attenuo:admin:<name>`, or `urn:attenuo:admin` for the single `[admin] token`; the `urn:attenuo:` prefix is reserved, so no identity provider can issue such a subject.
- **Metrics on a side listener only.** `GET /metrics` (Prometheus text) is served on its own loopback listener when you enable it, with no authentication. See [What to monitor](#what-to-monitor).
- **Manual key rotation with no overlap.** See [Key rotation](#key-rotation).

The full list of known gaps is at the end of [design/server.md](../design/server.md#known-limits-v0). The open security findings are in the threat model's [residual risks](../spec/threat-model.md#residual-risks-to-track); the twenty review passes, from [pass 1](../research/security-review-2026-10-22.md) to [pass 20](../research/security-review-2026-11-16-pass20.md), are listed in the [status page](../status.md).

## Production checklist

Go through this before pointing anything real at the server.

- [ ] `[dev] allow_root_mint` is `false` or absent. With it on, anyone holding the admin token can mint a root token for any user. When the admin API's listener (`[admin] listen`, else `[server] listen`) is not loopback the server refuses to start with it; `[dev] allow_root_mint_off_loopback` exists only for the docker-compose demo and must not appear in your config.
- [ ] Root tokens come from a real identity provider: `[[idps]]`, `[[agents]]`, `[[root_grants]]`. See [Identity providers](identity-providers.md). An entry with `[idps.id_jag_ceiling]` also has `credentials = ["id-jag"]`, or an agent that can present the issuer's ID tokens gets past the ceiling (the server warns at start).
- [ ] Each person who operates the server has an `[[admin.operators]]` entry of their own with the least role they need (`attenuo admin operator new --name <name> --role viewer|operator|admin`), so the audit log names who acted; see [admin operators](#admin-operators). If you keep `[admin] token` (or `ATTENUO_ADMIN_TOKEN`, which overrides it), it is a long random value that is not in any example, not in version control and not shared with agents. Generate it with `openssl rand -hex 32`. Off a loopback `listen` address the server refuses to start with no admin credential at all, or with an `[admin] token` shorter than 32 bytes or a known placeholder; it cannot tell whether a token was leaked.
- [ ] Every agent that receives a token is an `[[agents]]` entry with its own secret or, to keep no shared secret on the server, its own public key (`jwks`, or `jwks_url` for keys the agent publishes itself, [`private_key_jwt`](identity-providers.md#a-key-instead-of-a-secret)): token exchanges authenticate as their `actor` (`[token] require_actor_auth`, on by default).
- [ ] `[policy] unknown_tools` is `deny` (the default) or `sensitive`, not `allow`.
- [ ] `/admin/*` is not reachable from the networks agents live on: `[admin] listen` gives it a port of its own. See [Network exposure](#network-exposure).
- [ ] Agents reach attenuo over HTTPS only. TLS ends in a reverse proxy in front of it, or in attenuo itself with `[server.tls]` ([TLS in attenuo itself](#tls-in-attenuo-itself)). `[server] public_url` is the `https://` URL agents use, and agents, the CLI and the SDKs are given that URL itself: they follow no redirect, so a URL that redirects is an error ([TLS and a reverse proxy](#tls-and-a-reverse-proxy)). A plain `http://` `public_url` on a host that is not loopback refuses to start unless `[server] allow_insecure_http = true`, which you should not need.
- [ ] Every `[[idps]]`, `[[actor_trust]]`, `[[agents]]` and `[[peps]]` key URL (`jwks_url`, `spiffe_bundle_url`, or the IdP `issuer` used for discovery) is the final `https://` URL. Plain `http://` is accepted only on loopback, and redirects are not followed, so a key URL that redirects fails every ID or actor token it should verify. Its certificate chains to a root built into attenuo (the web PKI) or, for a private CA, to a CA in that entry's `ca_pem_path` ([private CAs for key URLs](identity-providers.md#private-cas-for-key-urls)).
- [ ] `[issuer] private_key_pem_path` is set, the file is mode 0600, owned by the service user, and backed up somewhere safe. Without the setting the server makes a new key at every start and every token dies on restart.
- [ ] `[audit] sqlite_path` is a real path on durable storage. The default is `:memory:`, which loses the audit log and every lease on exit. The server logs a warning when it is in memory.
- [ ] `[issuer] issuer` is the URL clients will use, for example `https://attenuo.example.com`. It becomes the `iss` of every token, and changing it later invalidates tokens. `[server] public_url` is set to the same base URL so the AuthZEN discovery document points at the right host. Off a loopback `listen` address the server refuses to start without it.
- [ ] `[policy] policies_path` points at your policy, and the catalog lists every tool a policy names.
- [ ] Every tool on the upstream that agents should call is in the catalog. With the default `[policy] unknown_tools = "deny"`, a tool missing from the catalog is denied with `tool_not_in_catalog`; with `"allow"` it is neither `readonly` nor `sensitive`, so rules that depend on those attributes do not see it.
- [ ] The config file is mode 0600, and only the people allowed to be admins can edit it: whoever can edit it can add an `[[admin.operators]]` entry with role `admin`. It holds secret hashes and possibly the admin token. The admin token can come from `ATTENUO_ADMIN_TOKEN` instead, `[telemetry]` reads the standard `OTEL_*` variables ([observability](observability.md)), and any scalar key can be set with an `ATTENUO__<SECTION>__<KEY>` variable ([environment overrides](../reference/config.md#environment-overrides)). The file is still read, and lists and arrays of tables (`[[agents]]`, `[[upstreams]]`, ...) come only from it. Nothing is substituted inside the file.
- [ ] You have read the [threat model](../spec/threat-model.md) section "What attenuo does not prevent" and have decided how the agents' other routes (direct API keys, local STDIO servers) are closed.
- [ ] `[limits]` fits your load: `max_in_flight` above your peak of concurrent requests, and the rate limits (off by default) set for your busiest legitimate run and agent if you want one caller kept from crowding out the rest. Set `authzen_search_requests_per_minute` if agents can reach AuthZEN action search, where the caller chooses the arguments to try. See [Load limits](#load-limits).
- [ ] Something checks `attenuo audit verify` on a schedule, and `[audit.sink]` ships checkpoints off the host ([audit log](../concepts/audit-log.md#shipping-checkpoints-off-the-host)). The server signs checkpoints itself (`[audit] checkpoint_every`, `checkpoint_interval_seconds`); `audit verify` reports the last signed `seq`.

## Network exposure

The default bind is `127.0.0.1:8080`. Keep it that way and put a reverse proxy in front, unless you have a reason not to. Without a proxy, set `[server.tls]` before you bind off loopback ([TLS in attenuo itself](#tls-in-attenuo-itself)).

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

### TLS in attenuo itself

A reverse proxy is still the usual setup. If you have none, the main listener (`[server] listen`) can speak TLS itself:

```toml
[server]
listen = "0.0.0.0:8443"
public_url = "https://attenuo.example.com:8443"

[admin]
# Off loopback the admin API needs a listener of its own (see above). It stays plain HTTP.
listen = "127.0.0.1:9102"

[server.tls]
# The server certificate first, then any intermediate certificates.
cert_pem_path = "/etc/attenuo/tls/server.crt"
# One private key: PKCS#8, SEC1 or PKCS#1, not encrypted. ECDSA P-256 is the cheapest to
# serve. Mode 0600 owned by the server's user, or 0640 owned by root with the server's group.
key_pem_path = "/etc/attenuo/tls/server.key"
```

What it does:

- It speaks TLS 1.3 only. A client that only speaks TLS 1.2 cannot connect.
- It offers HTTP/1.1 only (ALPN `http/1.1`). There is no HTTP/2.
- It keeps no sessions. Every connection makes a full handshake.
- It asks for no client certificate, unless you set `client_certificates = "optional"` (below).
- The handshake must finish within `[limits] header_read_timeout_seconds`. A peer that connects and sends nothing is dropped then. The request headers get the same timeout again after the handshake.
- A plain-HTTP request to this port fails its handshake, and the server goes on. Each failed handshake is counted in `tls_handshake_failures_total{reason}`. The server logs one at debug at most every 10 seconds, with the number it did not log.
- The startup line `attenuo server listening` says `tls=true`.

What it needs:

- `[server] public_url` must be set and must start with `https://`. `[server] allow_insecure_http` is refused.
- The key must belong to the first certificate in `cert_pem_path`.
- Keep the private key out of `cert_pem_path`, unless both keys name the same file. An encrypted key is refused in either file.
- The key file must be owned by the server's user or by root. It must give others no access, and its group at most read, and that only when root owns it. See [The key file's mode](#the-key-files-mode).

The server reads both files at start. At start it does not check the certificate's dates: an expired certificate is served until clients refuse it. Watch `tls_certificate_not_after_timestamp_seconds` ([what to monitor](#what-to-monitor)).

#### Renewing the certificate

A renewed certificate needs no restart:

1. Write the new certificate chain and key over the files `cert_pem_path` and `key_pem_path` name. Write each one to a temporary file in the same directory, then rename it into place, so a reload never reads half a file. Keep the key file's owner and mode.
2. Run `attenuo admin tls reload` (`POST /admin/tls/reload`, role `admin`). It prints the SHA-256 of the certificate before and after, and the new dates.
3. If it is refused, the old certificate is still in force. The error says what is wrong (`tls_key_mismatch`, `tls_certificate_expired`, ...). Fix the files and run it again.

New connections get the new certificate. Open connections keep the old one until they close. A reload reads the same paths: to use other paths, change the config and restart. A reload makes the startup checks, and also refuses a certificate that has expired or is not valid yet. It changes no other TLS setting, and it does not touch client certificates or tokens bound to them. With several replicas, run it against each one. A renewal tool can run step 2 from its hook (certbot `--deploy-hook`, for example). See [TLS certificate reload](../reference/http-api.md#tls-certificate-reload).

#### Client certificates

With `client_certificates = "optional"` in `[server.tls]`, agents and PEPs can authenticate with a TLS client certificate instead of a secret or a key: a self-signed one pinned by its thumbprint (RFC 8705 `self_signed_tls_client_auth`), or one a CA issued, such as a SPIFFE X.509-SVID (`tls_client_auth`). [Identity providers](identity-providers.md#tls-client-certificates) shows how to set up both.

- "Optional" means the server asks every client for a certificate and never requires one. A client without a certificate connects as before.
- The handshake only proves that the client holds the certificate's private key. It does not check a chain, an issuer or the dates. Each request then decides, against the lists in force, whether the certificate authenticates the client its `client_id` (or `pep_id`) names. So `attenuo admin agent reload` also applies to connections that are already open.
- The default is `"off"`: the server asks for nothing. A `tls_client_cert_sha256` or `tls_client_ca_pem_path` on an entry refuses to start unless the listener asks for certificates.
- With a CA, attenuo reads the CA file at start and at every `attenuo admin agent reload`. When SPIRE (or your CA) rotates its CA certificates, write the new bundle to the file and reload.
- **A proxy that ends TLS hides the certificate.** On this listener attenuo never reads `Client-Cert`, `X-Forwarded-Client-Cert` or any other header for it. Clients must reach attenuo's own TLS listener: directly, or through a load balancer or ingress that passes TCP through (layer 4, TLS pass-through). Or let the proxy forward the certificate to a listener of its own: see [forwarded client certificates](#forwarded-client-certificates).
- There is no CRL or OCSP check, and tokens are not bound to the certificate.
- A certificate on the connection makes a `client_id` (or `pep_id`) a client credential. So under `[token] actor_auth = "actor_token"`, a request that sends `client_id` over a connection with any certificate is refused with `client_auth_not_accepted`. Under `"either"`, a request that sends an actor token and `client_id` is refused with `client_authentication_failed` when the certificate is not pinned for that id. A client that uses an actor token should leave `client_id` out, or not present a certificate.

Only the main listener speaks TLS. `[admin] listen`, `[admin_ui]` and `[metrics]` stay plain HTTP. Keep them on loopback or a private network, and reach them over an SSH tunnel.

No `[server.tls]` key can be set from an environment variable, also when the file has the section. Every TLS setting, `client_certificates` included, is in the config file. See [ADR-0018](../decisions/0018-native-tls-listener.md) for the decision and what is not done yet.

Embedders: `attenuo_server::run` and `serve` speak TLS. `attenuo_server::serve_until` never does. A router built from a config with `[server.tls]` answers `500` to every request that did not come over TLS, so it is not served in cleartext by mistake.

#### Health checks, the image and the CLI

With `[server.tls]` the main listener answers no plain HTTP, so every check of it must change.

- **Probes and health checks** must use `https://`. A checker that verifies the certificate must use a name that is in the certificate, and must trust its CA. Kubernetes `httpGet` probes with `scheme: HTTPS` do not verify the certificate, so they work with any certificate.
- **The image's built-in `HEALTHCHECK` fails.** It runs `attenuo --server http://127.0.0.1:8080 health`, which is plain HTTP. Turn it off or replace it. With `docker run`, pass `--no-healthcheck`, or `--health-cmd` with your own check. In a compose file, set `healthcheck: { disable: true }`, or your own `test`. A replacement inside the container can only use the CLI (the image has no `curl`). See the next point for the command.
- **The `attenuo` CLI needs the CA for a private certificate.** By default it trusts the public web PKI roots built into it, so with a certificate from a public CA, give it the `https://` name in the certificate and nothing else. With a certificate from a private CA, give it that CA's certificate with `--tls-ca-cert` or `ATTENUO_TLS_CA_CERT`. It then trusts only that file for `--server`, `--admin-server` and a `--jwks` URL, not the public roots. For a JWKS on a host with a public certificate, save it to a file and pass `approval verify --jwks <file>`. The name in `--server` must still be one of the certificate's names. For a check inside the container, put `127.0.0.1` in the certificate's names, or map the certificate's name to `127.0.0.1` with `--add-host` (compose: `extra_hosts`).

  A self-signed server certificate also works as its own `--tls-ca-cert`, but only if it is not a CA certificate. A plain `openssl req -x509` makes a CA certificate (`CA:TRUE`), and the CLI refuses it as a server certificate (`CaUsedAsEndEntity`). Add the `basicConstraints` line, and the names the CLI will use:

  ```sh
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout server.key -out server.crt -days 90 -subj "/CN=attenuo" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "subjectAltName=DNS:attenuo.example.com,IP:127.0.0.1"
  chmod 600 server.key
  attenuo --server https://127.0.0.1:8443 --tls-ca-cert server.crt health
  ```

  A health check override for the `[server.tls]` example above (port 8443), with the CA mounted next to the server's own files and the same timeout as the image's own check:

  ```sh
  docker run --health-cmd \
    'attenuo --server https://127.0.0.1:8443 --tls-ca-cert /etc/attenuo/tls/ca.pem health --timeout 3' ...
  ```

  In a compose file: `healthcheck: { test: ["CMD", "attenuo", "--server", "https://127.0.0.1:8443", "--tls-ca-cert", "/etc/attenuo/tls/ca.pem", "health", "--timeout", "3"] }`. The CA file holds no secret: it is the public certificate of the CA. Admin commands also work when the server has `[admin] listen`: the CLI sends every `/admin/*` request to `--admin-server` (`ATTENUO_ADMIN_SERVER`), and that listener stays plain HTTP. An agent pinned by a client certificate passes it with `--tls-client-cert` and `--tls-client-key` ([TLS client certificates](identity-providers.md#tls-client-certificates)). If the CLI goes through an `https://` proxy (`HTTPS_PROXY=https://...`), the proxy's own certificate must also chain to `--tls-ca-cert`. The Python and TypeScript SDKs take the CA as `tls_ca_cert` and `tlsCaCert`, and trust only it for the attenuo server. Unlike the CLI, Python reaches an `https://` proxy with httpx's default roots and without the client certificate, and the TypeScript options use no proxy.
- **The Helm chart does not support `[server.tls]`.** Its startup, liveness and readiness probes use plain HTTP on the `http` port, so the pod fails its startup probe and is restarted. Use TLS at an ingress or gateway with the chart, as it documents.

#### The key file's mode

On Unix the server checks the key file's owner and mode, as read from the open file. It follows PostgreSQL's rule for `ssl_key_file`:

- The file must be owned by the user the server runs as (its effective uid) or by root. Any other owner is refused.
- Others may never have any access.
- The group may never write or execute.
- If root owns the file, the group may read it: mode `0640` or `0440` at most.
- If the server's user owns it, the group gets nothing: mode `0600` or `0400` at most.

The server refuses any other file and says which rule failed. The image runs as uid `10001`.

- **A file on the host**: `chown 10001 server.key && chmod 600 server.key`. Or let root own it with the server's group: `chown root:attenuo server.key && chmod 640 server.key`. A bind mount keeps that mode and owner.
- **Docker Swarm secrets**: set `mode: 0400` and `uid: "10001"` in the service's `secrets` entry. A Compose file outside Swarm mounts the host file as it is, so set the mode on the host.
- **Kubernetes Secrets**: set `defaultMode: 0440` on the volume (or `mode` on the item) and `fsGroup` to the server's group in the pod's `securityContext` (the image's group is `10001`). Kubernetes normally makes the Secret's files owned by root with the `fsGroup` group, so the server reads the key through its group, and the rule above accepts it. This was not tested here. Do not use `defaultMode: 0400` without `fsGroup` for a non-root server: the root-owned file is then unreadable.

#### What TLS costs

- Each new connection costs the server CPU: a key exchange and a signature. RSA keys cost much more than ECDSA. Use an ECDSA P-256 key.
- There is no session resumption, so every new connection pays the full handshake. Clients that keep connections alive pay it once.
- There is no cap on concurrent connections or handshakes, as on the plain listener. The `[limits]` in-flight cap counts requests, not connections, so it does not bound handshakes.
- A connection can be held for up to twice `header_read_timeout_seconds` before it sends a request: once for the handshake, once for the headers.
- With `client_certificates = "optional"`, a client can send up to 64 KiB of certificate data in its handshake (the largest handshake message rustls takes). The server keeps it for as long as the connection is open, whether or not the certificate authenticates anyone.

So a flood of new connections can still use up CPU and file descriptors. A front proxy or a connection limit at the network level is still the defence against that.

### Forwarded client certificates

When TLS ends at a reverse proxy, attenuo never sees the client's certificate. `[server.forwarded_client_cert]` lets the proxy pass it on in the RFC 9440 headers `Client-Cert` (the client's certificate) and `Client-Cert-Chain` (its intermediates), to a listener that does nothing else.

**Read this first.** attenuo cannot check these headers. Whoever can send `Client-Cert` to the forwarding listener can claim any certificate, and so be any agent or PEP that authenticates with one. attenuo does not see the handshake either: it trusts the proxy to have checked that the client holds the certificate's key. Use the native listener (`[server.tls] client_certificates = "optional"`, above) when clients can reach attenuo directly or through a TCP pass-through. Use forwarding only when TLS must end at the proxy.

```toml
[server]
listen = "127.0.0.1:8080"
public_url = "https://attenuo.example.com"

[server.forwarded_client_cert]
# Plain HTTP. Bind it where only the proxy can reach it.
listen = "127.0.0.1:8444"
# The proxy's own addresses. Required. Nothing wider than /8 (IPv6: /32).
trusted_peers = ["127.0.0.1/32"]
```

The fences:

- **A listener of its own.** The headers are read on `listen` only. It serves only these routes: `POST /token`, `POST /token/renew`, `POST /access/v1/evaluation`, `POST /access/v1/evaluations`, `POST /access/v1/search/action`, `/mcp/{server}`, `/approvals/{id}`, `GET /.well-known/jwks.json`, `GET /.well-known/authzen-configuration`, `GET /healthz` and `GET /readyz`. Every other path, `/admin/*` and `/ext-authz/v1/mcp/{server}` included, answers there as an unknown path (`404`). The console and metrics are never there. Point the proxy's backend at it.
- **Listed peers only.** A connection whose TCP peer address is not in `trusted_peers` gets `403 forwarded_peer_not_trusted` for every request, before routing, and is closed. `X-Forwarded-For` and similar headers are not read for this.
- **Refused everywhere else.** While the section is set, a request with either header on the main, admin, console or metrics listener is refused with `400 client_cert_header_not_accepted` and logged at warn. A client that tries to claim a certificate there, or a proxy pointed at the wrong port, shows up at once. Without the section the headers are ignored, as before.
- **One source per listener.** The forwarding listener never speaks TLS; the TLS listener never reads the headers. You may set both `[server.tls]` and this section: each request has one possible source.
- **Strict headers.** One `Client-Cert` line with one `:base64:` item, an optional `Client-Cert-Chain` line with at most 4 items, standard base64, at most 16 KiB per certificate. Anything else is `400 client_cert_header_malformed`, an empty `Client-Cert:` too: a proxy must leave the header out for a client without a certificate, or every such request is refused.
- **The same checks.** The certificate is checked exactly as one from attenuo's own handshake: `tls_client_cert_sha256` or `tls_client_ca_pem_path` on the entry, the same one answer for every refusal. Audit records say `"source": "forwarded"`.
- **Not from the environment.** No key of the section can be set by an `ATTENUO__...` variable. `listen` and `trusted_peers` are read at start only; changing them needs a restart.

**The proxy MUST** run in HTTP mode, remove every `Client-Cert` and `Client-Cert-Chain` header the client sent, and set them only from its own TLS handshake, only when the client presented a certificate. A proxy that passes on the client's copy lets anyone be anyone, and attenuo cannot tell. A proxy in TCP mode (layer 4) that ends TLS passes the client's bytes as they are, headers included: then **every client can claim any certificate**. The same is true when the lines that remove the headers are left out or do not run. attenuo cannot detect either mistake without a shared secret between the proxy and attenuo, which this design avoids: it would be one more secret to provision, rotate and leak, which is what certificates were meant to remove. A fixed marker header would not do, since a client of a TCP-mode proxy can send it too.

**What a reachable forwarding listener means.** Every process that can open a connection from a listed address can claim any certificate. With `127.0.0.1/32` that is every process on the host, not only the proxy. So run attenuo and the proxy where nothing else runs, or bind the listener to an address only the proxy reaches (a private interface, or the pod network of a sidecar proxy), and list only the proxy's address. A compromised proxy is a compromise of every certificate client.

Other things change behind a proxy:

- **Rate limits.** On the forwarding listener every client has the proxy's address, and attenuo cannot tell them apart. There `[limits] token_unauthenticated_requests_per_minute` counts the `/token` requests that authenticate nobody in one bucket per proxy address, as when the proxy pointed at the main listener (apart from that address's bucket on the other listeners). Once the bucket is over its limit, every `/token` request is refused with `429` before any work, except one that carries a forwarded certificate and a client id and no other credential (no secret, no client assertion, no Basic credentials, no actor token): it runs, and gets `429` afterwards if the certificate authenticated nobody. So guessing secrets through the proxy is limited, with or without a made-up certificate; a made-up certificate earns nothing; and a flood of failing requests does not lock out agents that authenticate by certificate. The cost: agents that authenticate by secret behind the proxy share that one bucket, as before this listener existed, and over the limit each request with a certificate costs one client authentication (a pin compare, or a CA check, which the shared cache below answers again for a known certificate). **Still limit `/token` per client address at the proxy**; the recipe below does. On every other listener the limit is per peer address, whatever certificate a request carries.
- **CA check cost.** The CA check for `tls_client_ca_pem_path` keeps its answers per certificate and intermediates, shared by the requests that forward exactly the same bytes (at most 256 certificates, the oldest dropped first), with the same rules as the native listener's per-connection cache.
- `[server] public_url` must be the proxy's `https://` URL.
- **ext_authz.** With the section set, a gateway that calls `/ext-authz/v1/mcp/{server}` on the main listener and copies the agent's `Client-Cert` header into its check request gets `400 client_cert_header_not_accepted`. Do not forward that header in the check (in agentgateway, leave it out of `includeRequestHeaders`). `/ext-authz/...` is not served on the forwarding listener.

#### HAProxy

The recipe is [`deploy/haproxy/forwarded-client-cert.cfg`](https://github.com/attenuo-dev/attenuo/blob/main/deploy/haproxy/forwarded-client-cert.cfg). Use it as it is and set its four environment variables. It is shown here in full; a test checks that this copy and the file are the same.

```haproxy
# HAProxy in front of attenuo's [server.forwarded_client_cert] listener: HAProxy ends TLS,
# asks each client for a certificate, and forwards the one from its handshake in the RFC 9440
# Client-Cert header. See docs/guides/deploying.md, "Forwarded client certificates".
#
# Use this file as it is and set these environment variables (HAProxy reads them in the
# quoted strings below):
#
#   ATTENUO_PROXY_BIND   where clients connect, for example :443
#   ATTENUO_PROXY_PEM    the proxy's own certificate and private key, in one PEM file
#   ATTENUO_CLIENT_CA    a PEM file of CA certificates: HAProxy names them to clients when it
#                        asks for a certificate. It accepts any certificate; attenuo decides
#                        whether it authenticates anyone.
#   ATTENUO_FORWARDING   attenuo's [server.forwarded_client_cert] listen address, for example
#                        127.0.0.1:8444
#
# Check it before use:  haproxy -c -f forwarded-client-cert.cfg
# A warning that "http-request" rules are ignored means the lines that remove the client's
# own Client-Cert headers are not running: then every client can claim any certificate.

global
    log stderr format short local0 info
    # No TLS session cache: a resumed session keeps the client certificate of the first
    # handshake without a new proof of the key. attenuo's own listener does not resume
    # sessions either. (no-tls-tickets on the bind line below turns off the other way.)
    tune.ssl.cachesize 0

defaults
    # HTTP mode is required. In TCP mode HAProxy passes the client's bytes as they are,
    # Client-Cert headers included, and ignores every http-request line below.
    mode http
    log global
    option httplog
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    timeout http-request 10s

frontend attenuo_tls
    mode http
    # Ask for a client certificate and require none. The handshake proves that the client
    # holds the certificate's key; attenuo checks the certificate itself.
    bind "${ATTENUO_PROXY_BIND}" ssl crt "${ATTENUO_PROXY_PEM}" alpn h2,http/1.1 verify optional ca-file "${ATTENUO_CLIENT_CA}" ca-ignore-err all crt-ignore-err all no-tls-tickets
    # Required: remove every copy of both headers the client sent itself.
    http-request del-header Client-Cert
    http-request del-header Client-Cert-Chain
    # Set Client-Cert from this connection's handshake, only when the client sent a
    # certificate. A client without one gets no Client-Cert at all: attenuo refuses an empty
    # one (400). HAProxy cannot send the intermediates as an RFC 9440 list, so no
    # Client-Cert-Chain is set: put the issuing CA itself in the agent's CA file.
    http-request set-header Client-Cert :%[ssl_c_der,base64]: if { ssl_c_used } { ssl_c_der -m found }
    # attenuo sees every client behind this proxy as one address, so limit /token per client
    # address here: at most 300 requests a minute, then 429. An IPv6 client counts by its
    # /64, as attenuo counts IPv6 peers. Raise it for many agents behind one NAT address.
    stick-table type ipv6 size 100k expire 60s store http_req_rate(60s)
    http-request track-sc0 src,ipmask(32,64) if { path /token }
    http-request deny deny_status 429 if { path /token } { sc_http_req_rate(0) gt 300 }
    default_backend attenuo_forwarding

backend attenuo_forwarding
    mode http
    server attenuo "${ATTENUO_FORWARDING}"
```

Before you send traffic through it:

1. Run `haproxy -c -f forwarded-client-cert.cfg` with the variables set. It must say `Configuration file is valid` with no warning that `'http-request' rules [are] ignored`. That warning means HAProxy is in TCP mode and the lines that remove the client's headers are not running: every client can then claim any certificate.
2. **Required check.** From a client with no certificate, send a forged header through the proxy and expect `401` with `"code": "client_auth_missing"`, never a token:

   ```sh
   curl -s https://attenuo.example.com/token -H 'Content-Type: application/json' \
     -H "Client-Cert: :$(openssl x509 -in coder.crt -outform DER | base64 -w0):" \
     -d '{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token":"<a token>","subject_token_type":"urn:ietf:params:oauth:token-type:jwt","actor":"coder","client_id":"coder"}'
   ```

Notes:

- `verify optional` with `ca-ignore-err all crt-ignore-err all` passes on any certificate whose key the client proved, as attenuo's own listener does. attenuo then checks the pin, or the chain and name. To let only certificates from your CA through the proxy, use `verify optional ca-file <your CA>` without the two `ignore-err` options, and add `{ ssl_c_verify 0 }` to the condition; then pinned self-signed certificates do not pass. This variant was not run here.
- **TLS session resumption.** HAProxy resumes TLS sessions by default (a session cache and TLS tickets), and a resumed session keeps the first handshake's client certificate without a new proof of the key, for as long as the session or ticket lives. attenuo's own listener does not resume sessions. The recipe turns resumption off, for the same behaviour: `tune.ssl.cachesize 0` in `global` and `no-tls-tickets` on the `bind` line (checked with HAProxy 2.8.30: with both, a second connection with the first one's session is a new handshake over TLS 1.2 and 1.3; without them, it is resumed and HAProxy forwards the first certificate).
- **Per-address limit.** The recipe answers `/token` with `429` after 300 requests a minute from one client address (a stick table; an IPv6 client counts by its /64), since attenuo sees only the proxy's address. It counts every `/token` request, those of agents that authenticate too, and refused requests keep counting, so a client that keeps retrying stays refused until it slows down. Raise it for busy agents or many agents behind one address.
- HAProxy cannot send the chain as an RFC 9440 list (`ssl_c_chain_der` is one blob), so it sends no `Client-Cert-Chain`. For a certificate from an intermediate CA, put the intermediate CA's certificate in the entry's `tls_client_ca_pem_path`. With only the root there, the check fails (`chain_invalid` in the debug log).
- HAProxy's request buffer (`tune.bufsize`, 16 KiB by default) holds the whole request head, so it bounds the size of the client certificate it can forward. A certificate of a few KiB fits; raise `tune.bufsize` in `global` for larger ones.
- **What was run.** `scripts/haproxy-forwarded-smoke.sh` (not part of CI) runs the file above as it is, with HAProxy 2.8.30 (Ubuntu 24.04) and `attenuo-server`, on 127.0.0.1, over HTTP/1.1 and over HTTP/2 to HAProxy. On 2026-11-24: `haproxy -c` valid with no warning; a pinned self-signed certificate and a certificate from an intermediate CA got tokens; a stranger's certificate with coder's id got `401 client_authentication_failed`; forged `Client-Cert` and `Client-Cert-Chain` headers from a client without a certificate got `401 client_auth_missing`, and from a client with the stranger's certificate `401 client_authentication_failed`; a forged, malformed `Client-Cert-Chain` next to a good certificate was removed (`200`); a direct request from `127.0.0.2` to the forwarding listener got `403`; the header on the main listener got `400`; no TLS 1.2 or 1.3 session was resumed; the 301st `/token` request of a minute from one address got HAProxy's `429`; the log named `client_cert_source="forwarded"`.

nginx exposes the certificate as URL-encoded PEM (`$ssl_client_escaped_cert`), not as an RFC 9440 byte sequence, and cannot make one without a script module. Envoy's default header is its own `x-forwarded-client-cert`, which attenuo does not read. Neither was tested here. [ADR-0021](../decisions/0021-forwarded-client-certificates.md) has the decision.

## Load limits

attenuo is an inline, fail-closed decision point: when it is down or swamped, every agent's calls fail. Denial of service is still outside the [threat model](../spec/threat-model.md), but `[limits]` ([reference](../reference/config.md#limits)) gives one process some basic protection, all of it in-process and per server (one replica):

- **In-flight cap.** `max_in_flight` (default 1024) requests are handled at once on the main listener; the next gets `503` `overloaded` with `Retry-After: 1` at once instead of waiting in a queue. `/healthz` and `/readyz` are never refused, so a busy server is not restarted for being busy. A streamed MCP answer stops counting once its headers are sent. The admin listener (`[admin] listen`) is not counted, which keeps revocation reachable while the main listener sheds.
- **Deadlines.** Headers must arrive within `header_read_timeout_seconds` (30), which also closes idle kept-alive connections; bodies within `request_body_timeout_seconds` (30, else `408`); every answer except `/mcp/{server}` and `/admin/*` within `request_timeout_seconds` (60, else `503`). The proxy keeps its own upstream deadlines (`[proxy] upstream_connect_timeout_seconds`, `upstream_response_timeout_seconds`), and its streams stay open for as long as their leases are live.
- **Rate limits, off by default.** `mcp_requests_per_minute` per run, `authzen_search_requests_per_minute` (AuthZEN action search) per run, `token_requests_per_minute` per authenticated agent and `token_unauthenticated_requests_per_minute` per peer address. Over the limit: `429` with `Retry-After`. Start at a few times the busiest legitimate rate, watch `requests_rate_limited_total`, and keep the per-peer limit off behind a reverse proxy, where every caller shares the proxy's address (the [forwarding listener](#forwarded-client-certificates) has its own rule for this).
- **Set `authzen_search_requests_per_minute` when agents can reach `/access/v1/search/action`.** The caller of a search chooses the arguments, so without a limit a run can try argument values against your policy as fast as the server answers. Each search writes one `search` audit record, so you can see it happen, but nothing stops it ([action search](../reference/authzen.md#action-search), SR-117). The limit counts per run (also for a PEP sending an unsigned chain), after authentication; evaluations are not counted by it. Set it, as the others, at a few times the busiest legitimate run's search rate; a run that meets it shows in `requests_rate_limited_total{limit="authzen_search"}`.

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

Then run `attenuo admin operator reload` (role `admin`): the server re-reads `[[admin.operators]]` from its config file and puts them in force without a restart (a restart works too). Hand the token to alice over a secure channel; the file keeps only its SHA-256. `viewer` reads (the audit log, its export, leases, policies, approvals), `operator` also revokes leases and decides approvals, `admin` does everything (policy, operators and agents reload, budget refunds, the dev root mint). A role too low gets 403 `admin_role_insufficient`. `GET /admin/whoami` (and the console's header) says which operator a token is. In the audit log, each admin action and operator approval names `urn:attenuo:admin:<name>`.

- Every token is compared, as a SHA-256 digest, in constant time against every credential; with no credential configured `/admin` answers 403 rather than opening.
- `[admin] token` still works as before: it is the operator `admin` with role `admin`, recorded as `urn:attenuo:admin`, so its records do not say which person used it. It sits in the config file in clear text (or comes from `ATTENUO_ADMIN_TOKEN`). Treat the file as a secret either way: mode 0600, not in the image, not in the repository, not in a CI log. In Docker or Kubernetes, mount the whole file from a secret. Once everyone has an operator entry, remove `[admin] token`.
- Operators pass their token to the CLI with `ATTENUO_ADMIN_TOKEN`, `--admin-token-stdin` or `--admin-token-file`. `--admin-token` still works but prints a warning, since command-line arguments show up in process listings (`ps`, `/proc/<pid>/cmdline`) and shell history. The same goes for an agent's client secret (`ATTENUO_CLIENT_SECRET`, `--client-secret-stdin`, `--client-secret-file`).
- **A leaked operator token:** remove its entry from the config file (or set its `expires_at` to a time in the past) and run `attenuo admin operator reload`. The token's next request is refused (401); requests it already had in flight finish. The reload's answer and its `admin.operators.reload` audit record name the operator removed or changed. Then look in the audit log for what the token did (`attenuo audit tail --subject urn:attenuo:admin:<name>`). A leaked `[admin] token` is not reloaded: change it (or `ATTENUO_ADMIN_TOKEN`) and restart.
- **Expiry:** give a token a lifetime with `attenuo admin operator new --expires-in 30d` (or `--expires-at <RFC 3339>`), which writes `expires_at` into the entry. After it the token gets 401 `admin_credential_expired`; the entry stays harmless in the file, and the server warns about it at startup and on each reload until you remove it.
- **Rotation without a gap:** add a second entry for the same person (`alice-2`) with a new token, reload, switch, then remove the old entry and reload again.
- A reload that would leave no working `admin` credential (no `[admin] token` and no unexpired operator with role `admin`) is refused, and so is a file that does not parse or breaks a rule; the operators in force stay as they were. A server started without a config file (one that builds its configuration in code) has nothing to reload.
- Do not hand an admin token to agents. Even a `viewer` token reads every audit entry. Agents use delegation tokens only.
- Whoever can edit the config file, or set `ATTENUO_ADMIN_TOKEN` in the server's environment, can make themselves an admin. There is no login, no second factor and no per-operator rate limit; the [threat model](../spec/threat-model.md) (A8) lists what is and is not covered.

## Adding or rotating an agent without a restart

`[[agents]]` and `[[peps]]` can change while the server runs. Edit the config file the server was started with, then run:

```sh
attenuo admin agent reload
```

(role `admin`; `POST /admin/agents/reload`). The server re-reads both lists, checks them as it does at startup and puts them in force at once. Each request authenticates against one snapshot: the old lists or the new ones, never a mix. The answer lists the ids added, removed and changed, with a SHA-256 of each new list. The `admin.agents.reload` audit record names the operator who reloaded; of its arguments (the path, the ids, the list digests and `restart_needed`) it keeps only a digest, so keep the command's output, or the server log, if you need the ids later. A file that does not parse, or a list that breaks a startup rule, is refused with the startup message (`agents_invalid`), and nothing changes.

Two more refusals guard against reloading the wrong file. A file that leaves `[[agents]]` or `[[peps]]` empty while the server has entries is refused (`agents_reload_empties`), because an empty or cut-off file reads that way; pass `--allow-empty` when you mean it. A file whose `[issuer]` (its key files aside) or `[audit]` differs from the running config is refused (`config_file_mismatch`), because it may be another server's file; pass `--allow-mismatch` to reload its lists anyway. Warnings go to stderr and the command still exits 0, so read them.

- **Add an agent:** add its entry and reload. It can authenticate with its next request. If it also needs a `[[root_grants]]` entry or a `client_ids` key in `[[idps]]`, those take a restart: the reload does not apply other sections, and its answer names each one that differs from the running config in `restart_needed`.
- **Rotate a secret:** put the new `secret_sha256` in the entry and reload. The old secret is refused from the next request on, so update the agent first or right after. For a key (`jwks`), there is no gap: add the new key with a new `kid`, reload, move the agent to it, then remove the old key and reload again. For keys at a `jwks_url`, there is nothing to reload: publish the new key next to the old one, move the agent to it, then remove the old key. The new key works within 30 seconds at most (an unknown `kid` fetches the set again, at most once per 30 seconds, and anyone can use that allowance up with made-up `kid`s), so publish it at least 30 seconds before the agent first signs with it. The removed one stops working at the latest `jwks_ttl_seconds` (default 300) after the last fetch. Changing the URL itself takes a reload, and the keys from the old URL stop working for every request that starts after the reload answered.
- **Remove a compromised agent:** delete its entry and reload. It can no longer authenticate with its secret or key. That does not always stop new tokens: with `[token] require_actor_auth = false` an exchange can still name it as the actor without credentials, and an `[[actor_trust]]` entry that maps a workload to its id still lets it in with an actor token. Changing either takes a restart, and the reload warns about both. Tokens it already has are not revoked by the reload and keep working, and renewing, until they expire. So revoke them too: `attenuo lease revoke --user <SUB>` or `--chain-id <ID>`, or `attenuo lease revoke <LEASE>` for one chain (see [Revoking during an incident](#revoking-during-an-incident)).

## Key rotation

The server signs every token with the Ed25519 key named by `[issuer] private_key_pem_path`. Each token's JOSE header carries a `kid`: the first 16 bytes of the SHA-256 of the key's SubjectPublicKeyInfo DER, base64url-encoded (22 characters). `/.well-known/jwks.json` lists every key the server trusts, signing key first, each with its `kid`.

Rotation has an overlap period. Retired keys listed in `[issuer] previous_key_paths` stay trusted for verification and in the JWKS, but never sign. Tokens signed before the switch keep working until they expire, and can still be exchanged for children.

```toml
[issuer]
private_key_pem_path = "/etc/attenuo/issuer-2.pem"          # signs from now on
previous_key_paths   = ["/etc/attenuo/issuer-1.pem"]        # verify only
```

To rotate:

1. Generate the new key: `openssl genpkey -algorithm ed25519 -out /etc/attenuo/issuer-2.pem`, then `chmod 600` it. (At startup the server also generates a key if the path does not exist. A reload does not.)
2. Edit the config: point `private_key_pem_path` at the new file and add the old file to `previous_key_paths`. A previous key file may be the old private key or just its public key (`openssl pkey -in issuer-1.pem -pubout -out issuer-1.pub`); only the public half is used, so prefer the public file and archive the private one.
3. Run `attenuo admin key reload` (role `admin`; `POST /admin/keys/reload`), or restart the server. The reload prints the old and new `kid` and the verifying keys. Check `/.well-known/jwks.json` lists both. With several replicas, or verifiers that cache the JWKS, use the two steps below instead.
4. Wait at least the longest token lifetime (`default_ttl_seconds`, or the largest `ttl_seconds` you allow) plus `clock_skew`. By then every token signed by the old key has expired, and so has every child rooted under it.
5. Keep the old public key in `previous_key_paths`. Then destroy the old private key. Keeping the public key costs nothing, and the old audit checkpoints and anchors keep verifying.

You can remove the old key from `previous_key_paths` only when nothing you keep was signed by it: the reload refuses while the live audit log holds a checkpoint or anchor it signed (`keys_reload_drops_audit_key`). In practice that is after `attenuo audit prune` has removed every entry from its time and a newer anchor covers them. The check cannot see archives, exports or checkpoints already shipped by `[audit.sink]`. So before you remove a key, save a copy of `/.well-known/jwks.json` with each archive and export, or keep the key.

### Rotation with replicas or cached JWKS

Each replica reloads on its own, and a verifier that caches the JWKS may not see a new key at once. A token signed by the new key on one replica would then fail on another. Rotate in two reloads, neither of which needs an override:

1. Publish the new key first, and keep signing with the old one. Set `previous_key_paths` to the new public key and leave `private_key_pem_path` as it is:

   ```toml
   [issuer]
   private_key_pem_path = "/etc/attenuo/issuer-1.pem"          # still signs
   previous_key_paths   = ["/etc/attenuo/issuer-2.pub"]        # published, verify only
   ```

   Reload every replica. The JWKS now lists both keys, old first. Wait until every cache has the new key (the JWKS cache time of your verifiers).
2. Swap: point `private_key_pem_path` at the new key and set `previous_key_paths` to the old public key, as in step 2 above. Reload every replica. Tokens of either key verify everywhere.

The reload swaps the signing key and the verifying keys in one step. Each request uses one set of keys from start to end. New tokens, approval tokens, audit checkpoints and prune anchors are signed with the new key. Only the two key settings are read from the file; other sections that differ are named in the answer as needing a restart. Two things keep the key the server started with until a restart, when they are on: the DPoP nonces (`[token] dpop_nonce`) and the subject digests of `[telemetry]` and `[logging] redact_subjects`. The reload names them under `kept_until_restart`.

An environment variable wins over the file at a reload, as at startup. While `ATTENUO__ISSUER__PRIVATE_KEY_PEM_PATH` is set, editing `private_key_pem_path` in the file does nothing; the reload warns about it. Change the file the variable names, or unset it and restart.

The reload refuses, and changes nothing, when a key file cannot be read, is not an Ed25519 key of the right kind, or holds the same key as another file. It also refuses two mistakes that are easy to make:

- A new signing key without the current one in `previous_key_paths` (`keys_reload_drops_current`). That would make every live token fail at once. Pass `--allow-drop-current` only for a key compromise.
- Verifying keys that leave out a key that signed an audit checkpoint or prune anchor the log still holds (`keys_reload_drops_audit_key`). That would make `audit verify` fail. Pass `--allow-drop-audit-key` only when you accept that. The current key always signs the audit log, so dropping it always needs both flags.

Notes:

- The originating-user block of a token (`ou_sig`) is signed once, at the root, and copied to every child. A child minted after the switch is signed by the new key but still carries an old-key `ou_sig` (its `ou_kid` names the old key), so the old key must stay trusted until the whole chain has expired. That is why step 4 waits for the longest chain, not for one token. Dropping the old key ends those children too, though the new key signed them.
- A token whose `kid` is not in the trusted set is rejected with `invalid_grant`, whatever its signature. Tokens issued by a version before `kid` existed carry no `kid` and are tried against every trusted key.
- Third parties that verify attenuo tokens offline should select the key by `kid` and refresh the JWKS when they see an unknown one. `attenuo token inspect --verify` fetches the JWKS and trusts every key in it.
- In an emergency (key compromise), skip the overlap: replace the key, leave the old one out of `previous_key_paths`, and run `attenuo admin key reload --allow-drop-current --allow-drop-audit-key` (or restart). Every outstanding token stops verifying; agents re-run login and exchange. Then restart too, so the DPoP nonces and subject digests stop using the old key.

The audit log's hash chain does not depend on the issuer key, but its signed checkpoints and prune anchors do. Each one names the `kid` that signed it, and `audit verify` checks it against the JWKS. So a rotation keeps `audit verify` passing as long as every key that signed a checkpoint or anchor you keep stays in `previous_key_paths`. A reload refuses to drop such a key unless asked. Old leases stay in the database but belong to tokens that no longer verify.

The PEM is the most sensitive file attenuo owns. Whoever has it can mint any token for any user. Back it up apart from the database, with the same care as any signing key.

## SQLite file: placement and backup

`[audit] sqlite_path` holds two things in one file: the hash-chained audit log and the lease registry. The server creates the parent directory if it is missing.

Placement:

- Put it on local, durable storage that the service user owns. The server refuses to start when the file's directory is on a network filesystem; see [Not on a network filesystem](#not-on-a-network-filesystem).
- Keep it away from anything agents can reach. Whoever can write the file can rewrite the log and un-revoke leases.
- In a container, mount a volume. The image's working directory is `/var/lib/attenuo`, owned by the `attenuo` user (uid 10001).
- Watch free disk space. An audit append that fails turns the decision into a deny with reason `audit_error`, so a full disk stops all calls and token issuance. That is the fail-closed rule working as designed.
- Rows of the audit log are never deleted unless pruned (`[audit.retention]`), so by default the file grows for as long as the server takes traffic. With `[audit.retention] prune = "manual"` and `[audit.sink]` set, the admin can archive and prune the oldest entries with `attenuo audit prune`; with `prune = "auto"` the server prunes on its own what is older than `keep_seconds` (see [Bounding the audit log](#bounding-the-audit-log)). Without that, size the volume for the log you expect to keep, and never delete rows by hand: a log whose first entries are missing without a valid anchor fails `audit verify`, exactly as a truncated one does. Watch `audit_db_size_bytes` for your own growth rate; how many bytes an entry takes has not been measured.
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
        terminationGracePeriodSeconds: 35
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

## Bounding the audit log

By default no row of the audit log is ever deleted. To keep the file bounded, prune the oldest entries now and then, after archiving them ([ADR-0015](../decisions/0015-audit-retention.md), [design](../design/audit-retention.md)).

1. **Enable it.** Set `[audit.retention] prune = "manual"` ([config](../reference/config.md#auditretention)). It needs `[audit.sink]`, so the checkpoints and the prune's signed anchor are shipped off the host. `min_age_seconds` (90 days by default) is the youngest entry a prune may remove. Restart the server.
2. **Plan.** `attenuo audit prune --before 2026-08-01T00:00:00Z --dry-run` prints the boundary the server would use (the newest checkpoint older than that time that no live run points into and that the sink has delivered), how many entries it removes, and which guard limited it. It changes nothing.
3. **Prune.** `attenuo audit prune --before 2026-08-01T00:00:00Z --archive /mnt/archive/attenuo-0001.jsonl` exports the entries to the archive (mode 0600 on Unix), verifies it with the issuer's keys (pass `--jwks <file>` to use keys you hold yourself rather than the server's), and only then asks the server to prune, with the archive's SHA-256 signed into the anchor. Nothing on the server changes before that last request, so a failure or crash before it leaves the log as it was. If the request itself fails, the archive is kept, and `attenuo audit prune --archive /mnt/archive/attenuo-0001.jsonl --reuse-archive` sends it again. The rows are then deleted in the background, in batches of `batch_rows`; reads start after the boundary at once.
4. **Keep the archive off the host.** After the prune, the archive is the only copy of those entries. Copy it to storage that whoever holds this host cannot change (an Object Lock bucket, a separate machine), and keep every archive: the next prune's archive starts where this one ends. `attenuo audit verify --file attenuo-0001.jsonl --file attenuo-0002.jsonl --file retained.jsonl --checkpoints shipped.jsonl` checks them, with an export taken now, as one log, and prints `from genesis` when the first file starts at seq 1. Each pair must link by hash; the later file's header anchor, if present, must name the earlier file's end. Use the JWKS you saved yourself (`--jwks`): keys fetched from the server only show that the files are consistent with what the server publishes now.
5. **The file does not shrink by itself.** SQLite keeps the freed pages and reuses them for new entries, so after a prune the file stays the same size and stops growing until the freed space is used up. `audit_db_free_bytes` shows how much is free. The server never shrinks the file. To give the space back to the disk, compact it offline:
   1. Stop the server.
   2. Back up the file: copy `attenuo.sqlite` and its `-wal` and `-shm` files, if there are any, while nothing runs.
   3. Run `attenuo audit compact --db /var/lib/attenuo/attenuo.sqlite --dry-run`. It runs the checks and prints how much would be freed and how much free space it needs. Then run it again without `--dry-run`. Use the same attenuo version as the server.
   4. Start the server, and run `attenuo audit verify`.

   [`audit compact`](../reference/cli.md#audit-compact---db-path) runs SQLite's `VACUUM` on the file and then empties the WAL, so the file gets smaller. It refuses (exit 2) when the file is in use, when it is not in WAL mode, when `PRAGMA integrity_check` is not `ok`, when the schema version is not the one this attenuo reads, when the hash chain does not verify, or when there is not enough free space. After `VACUUM` it checks that the schema version, the entry count, the chain head, the prune marker, the newest anchor and every row of every table are what they were. If anything differs, or a step after `VACUUM` fails so the file cannot be checked, it exits 3: do not start the server on that file, restore the backup. A refusal or a dry run leaves the database and its WAL byte for byte as they were; it may create `attenuo.sqlite.lock` and write its pid there, as the server does. It writes no audit entry, since it changes no row.

   Free space: `VACUUM` writes a copy of the live data (the file less its free pages) into SQLite's temporary directory (`SQLITE_TMPDIR`, else `TMPDIR`, else `/var/tmp`, `/usr/tmp` or `/tmp`) and once more into the WAL next to the file. The command asks for that much on each filesystem, plus 2% and 16 MiB, and twice that when both are on one filesystem.

   "In use" means one of two locks. The server holds `attenuo.sqlite.lock` for as long as it runs, busy or idle. SQLite's own lock covers other programs: in WAL mode, which the server always leaves the file in, a connection that has read the file holds a shared lock until it closes, so a `sqlite3` shell or a backup tool with the file open is seen too. Not seen: a connection that was opened but has not read anything yet, and one opened with SQLite's `nolock=1` or `immutable=1`, which take no locks. The command always refuses a file on a network filesystem, where neither lock can be trusted, even when the server's config sets `allow_network_filesystem = true`. When it cannot tell the filesystem type, it goes ahead, as the server does.

Never delete rows by hand: a log whose first entries are gone without a valid anchor fails `audit verify` at its first entry, as a truncated log does.

### Pruning on a timer

To have the server prune for you, set:

```toml
[audit.retention]
prune = "auto"
keep_seconds = 7776000                       # prune what is older than 90 days
interval_seconds = 3600                      # look once an hour (the default)
archive_dir = "/var/lib/attenuo/audit-archive"  # keep a copy of what is pruned
```

`keep_seconds` must be at least `min_age_seconds` and at least a day. Every interval the server makes the same plan as step 2 with `keep_seconds` as the age, verifies the entries it would prune, and prunes them only if they verify and the sink has delivered their checkpoint and the last anchor. You can still run `attenuo audit prune` by hand; the two never both commit.

**Set `archive_dir`.** We recommend it for every server with `prune = "auto"`. Create the directory first, writable by the server's account only (the server warns if its group or everyone can write it), and give an absolute path (a relative one is taken from the server's working directory). The server refuses to start if it cannot write there. Before each prune, the server writes the entries it is about to remove into it as `audit-<from>-<through>.jsonl`, the same file `attenuo audit export` writes, and checks the file. If that fails, nothing is pruned. The anchor it ships carries the file's SHA-256.

The server does not move these files. That is your job, as in step 4:

- Copy new files from `archive_dir` off the host (to backup storage, object storage, another machine). Someone who controls the host can delete the files there. The SHA-256 in the shipped anchor is what proves that a copy you kept is the real one: check it with `sha256sum`, or with `attenuo audit verify --file <archive> ... --file <retained> --checkpoints <shipped>`, which checks the files against the shipped anchors.
- Delete old files from `archive_dir` when your own policy allows. The server never replaces a file and never deletes one it did not just write (it removes its own file only when the prune that file was for did not happen). A file with the name it wants that is not that prefix's archive stops the automatic prune (`reason="archive_exists"`) until you move it away. The shipped anchors name the real archives; a file that matches no anchor is not part of the log, and the server warns about it once.
- Plan for the space: each file holds the entries one prune removed. `max_entries_per_run` (a million by default) caps that size, and also splits the first prune of a large old log into several runs.

**Without `archive_dir` the server keeps no copy.** It warns at start. The shipped checkpoints and anchors prove how many entries were pruned and their last hash, not what they said. If you must keep the records and do not set `archive_dir`, export each new stretch yourself, from the seq after your last archive to a recent checkpoint, well before it passes `keep_seconds`, and keep those files off the host. Entries that pass `keep_seconds` before you export them are gone for good.

**The clock matters.** The cutoff of a run is `keep_seconds` before the earliest of three times: now, the newest entry that is not a prune record, and the wall time at start plus the monotonic time since. Inside one process, a clock jump cannot speed pruning up: the cutoff moves at most as fast as the monotonic clock, with or without new entries. Across a restart the server cannot tell a jumped clock from real downtime, so after a restart with a wrong clock the cutoff starts from the wrong time. Entries written while the clock was behind carry old timestamps, and once the clock is set right they can be pruned early by up to that error. On an idle server the last `keep_seconds` before the newest entry are kept. `archive_dir` is what protects the content. Keep NTP healthy, alert on `clock_jump`, and set `archive_dir`.

Watch it with these:

- `audit_auto_prune_runs_total{outcome="failed"}` should stay at 0. `reason="verify_failed"` means the entries do not verify: the server keeps them, and `attenuo audit verify` tells you where the log is broken. Treat it as an incident. `reason="archive_write_failed"` means `archive_dir` is missing, read-only or full. `reason="archive_exists"` means a file with the archive's name that is not this prefix's archive is in the way.
- `audit_auto_prune_runs_total{outcome="skipped",reason="clock_jump"}` should stay at 0. An increase means the wall clock and the monotonic clock moved apart by more than an hour between two runs. Most often the host's clock was stepped; check it. On Linux the monotonic clock does not count a suspend or a VM pause, so resuming a paused host or VM can count one too.
- `audit_auto_prune_runs_total{outcome="skipped",reason="sink_behind"}` growing means the sink is not delivering; nothing is pruned until it does.
- `audit_prune_last_timestamp_seconds` tells you when the log was last pruned, by anyone.
- `GET /admin/audit/prune/plan` shows the settings and the last run under `auto`, and so does `attenuo audit prune --dry-run --through <seq>`.

A run that fails is logged and tried again at the next interval. It never stops the server and does not change `/readyz`. At shutdown the server waits for a run in progress to finish. A run reads every entry it removes, to verify it and, with `archive_dir`, to write and check the file, so the first runs on a large log that was never pruned can take a while; `max_entries_per_run` keeps each one bounded. The deletes then take several runs of the maintenance task.

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
    stop_grace_period: 35s         # above the server's worst case at shutdown, see Signals
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

- **Signals.** The server shuts down gracefully on SIGTERM (what `docker stop` and Kubernetes send) and on SIGINT. It stops accepting connections, gives in-flight requests up to 10 seconds to finish (on the admin API, admin console and metrics listeners too), stops its timers, closes the database and releases its lock, then exits; it logs `shutdown signal received; draining`, `shutdown complete` and `single-writer fence released`. With `[audit.sink]`, `[approvals.notify]` or `[leases.notify]` set, the server then gives what they still have queued 5 more seconds, shared by all three, and a request already in flight can run to its own `timeout_seconds`. With `[telemetry]` set, spans get up to 5 seconds after that. So the worst case is 10 + 5 + the longest `timeout_seconds` + 5 + 2 seconds, which is 32 seconds with the default timeouts. Set `stop_grace_period` (or `terminationGracePeriodSeconds`) above that; the examples and the Helm chart use 35 seconds. A grace above 10 seconds but shorter than the worst case only cuts this tail: approval and revocation notices still queued stay in the outbox and are sent at the next start. No `stop_signal` override is needed. SQLite writes are transactional, so even a kill does not corrupt the log.
- **Read-only root.** The server only writes under the data directory and, when the key file is missing, to the key path. Keep the key file in the read-only mount, so a missing key is an error you see, not a new key you did not plan.
- **Upstreams** must be reachable from the container. `127.0.0.1` in `[[upstreams]]` means the container itself. The proxy gives an upstream `[proxy] upstream_connect_timeout_seconds` (default 5) to accept a connection and `upstream_response_timeout_seconds` (default 120) to send response headers, or a JSON answer it must read; past that the agent gets `502 upstream_unreachable` or `504 upstream_timeout`. Raise the second for tools that answer in JSON after a long run. Streams (SSE) are not cut by it.

## Kubernetes (Helm)

The repository has a Helm chart in `deploy/helm/attenuo`. It is not published to a chart repository: install it from a checkout of the release you run. It runs one `attenuo-server` pod from the release image, and its values are explained in the chart's `values.yaml`.

```sh
kubectl create namespace attenuo
kubectl -n attenuo create secret generic attenuo-admin \
  --from-literal=admin-token="$(openssl rand -hex 32)"

helm install attenuo deploy/helm/attenuo -n attenuo \
  --set publicUrl=https://attenuo.example.com \
  --set-file config=attenuo.toml \
  --set-file policy=policy.cedar \
  --set adminToken.existingSecret=attenuo-admin
```

What you give it:

- `publicUrl` (required): the `https://` URL agents use. The chart does not turn on attenuo's own TLS (`[server.tls]`), so terminate TLS at an ingress or gateway (`ingress.enabled`, or your own). An `http://` URL is refused unless `allowInsecureHttp=true`.
- `config` (required): your `attenuo.toml`, stored in a Secret. Leave out `[server] listen` and `public_url`, `[admin] listen`, `[policy] policies_path`, `[audit] sqlite_path` and `[issuer] private_key_pem_path`: the chart sets them through `ATTENUO__...` environment overrides, which win over the file. `existingConfigSecret` names a Secret you manage instead.
- `policy` (required): your Cedar file, stored in a ConfigMap (`existingPolicyConfigMap` for your own).
- `adminToken.existingSecret`: the Secret with the admin bearer. Do not put the token in `config`.
- `issuerKey.existingSecret` (recommended): the Ed25519 issuer key from a Secret. Without it the server creates a key on the data volume on first start, and losing the volume then changes the key that every token and audit checkpoint is verified with.

What the chart decides, and why:

- **One replica, `strategy: Recreate`, a `ReadWriteOnce` volume.** One process may open the SQLite file ([One process per file](#one-process-per-file)). There is no replica count to set, and a rollout has a short gap in service.
- **The data volume is kept.** The claim carries `helm.sh/resource-policy: keep`, so `helm uninstall` does not delete the audit log. Delete the claim yourself when you mean to.
- **The admin API listens on loopback inside the pod.** No other pod can reach it, and no Service or Ingress points at it. Reach it with `kubectl -n attenuo port-forward deploy/attenuo 9102:9102`, then `attenuo --server http://127.0.0.1:9102 ...`. `admin.service.enabled=true` makes it listen on the pod's address and adds a ClusterIP Service for clients inside the cluster. Every pod the network policy lets through can then reach it, so add a NetworkPolicy.
- **The pod is locked down.** It runs as uid 10001 with a read-only root filesystem, no capabilities, no privilege escalation, the default seccomp profile and no service account token.
- **Probes.** Liveness and startup ask `/healthz`, readiness asks `/readyz` ([Health and readiness](#health-and-readiness)).
- **A change to `config` restarts the pod.** The config is read at start, and the chart puts its checksum on the pod. With `existingConfigSecret`, and after changing the admin token's Secret, restart it yourself: `kubectl -n attenuo rollout restart deploy/attenuo`. The policy needs no restart: after changing it, wait for the ConfigMap to reach the pod (up to about a minute) and run `attenuo policy reload`.
- **Files the config names must be mounted.** The root filesystem is read-only. For `[issuer] previous_key_paths` (key rotation), `[policy] catalog_path` and `schema_path`, and the `ca_pem_path` keys, use `extraVolumes` and `extraVolumeMounts`.
- **Start and stop.** The startup probe waits up to 5 minutes (`startupProbe.failureThreshold`), because schema migrations run before the server answers; raise it for a very large audit log. The pod gets 35 seconds to shut down (`terminationGracePeriodSeconds`).

`metrics.enabled=true` opens the metrics listener on port 9100 in the pod and adds a ClusterIP Service of its own (`attenuo-metrics`) for a scraper inside the cluster. It is never added to the main Service, which may be a LoadBalancer. Metrics have no authentication, so restrict the port with a NetworkPolicy.

Tested by `scripts/helm-smoke.sh` (the CI job `helm chart`): template checks for the defaults, every optional part and every value the chart refuses, then an install into a kind cluster with the published image (the chart's `appVersion`), where a token is minted and exchanged, one call is allowed and one denied through the proxy, the pod is deleted and the new pod still verifies the old token and the audit chain, and a changed config rolls the pod. The cluster test runs the published image, not a server built from the same commit. Not tested: a cloud provider's cluster, an ingress controller, and upgrades between chart versions.

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
| `audit_db_size_bytes`, `audit_db_free_bytes`, `audit_pruned_entries_total` | The database file's size and the part of it on SQLite's free list, as a trend, and the entries prunes of the log (`[audit.retention]`) have deleted. |
| `audit_auto_prune_runs_total`, `audit_auto_prune_last_run_timestamp_seconds`, `audit_prune_last_timestamp_seconds` | With `prune = "auto"`: alert on any `outcome="failed"`, and on a last run or a last prune older than you expect (see [Pruning on a timer](#pruning-on-a-timer)). |
| `approval_notify_dropped_total`, `approval_notify_outbox_rows` | `[approvals.notify]` notices given up, and notices stored but not yet delivered. The outbox count staying up means the receiver is down; the notices survive a restart. |
| `tls_certificate_not_after_timestamp_seconds`, `tls_certificate_reloads_total{result}`, `tls_handshake_failures_total{reason}` | With `[server.tls]`: when the certificate in force expires (alert well before), reloads that were refused (`result="failed"`), and failed handshakes. A rise in `reason="peer_alert"` after a renewal means clients do not trust the new certificate. |
| `lease_notify_dropped_total`, `lease_notify_outbox_rows` | The same for `[leases.notify]` revocation notices. A dropped one costs only time: the PEP still learns of the revocation when it next asks. |

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
- `503` answers from `POST /token` with `jwks_unavailable`. That is your identity provider, the network path to it, or a certificate attenuo does not trust; the `warn` line (`IdP JWKS unavailable`, or `actor token issuer JWKS unavailable`) names the cause, the answer does not.
- `warn` lines `client JWKS unavailable`. An agent or PEP with `jwks_url` whose key set attenuo cannot fetch, or refuses (a private key in it, say). The line names the client and the cause, once per failed fetch; the requests refused while the next fetch waits (5 seconds) are logged at debug level only. The client is answered `401 client_authentication_failed`, as an unknown client is, so look at the log, not the answer.

From the audit log (`GET /admin/audit`, `attenuo audit tail`):

- The count of denies by reason. A jump in `capability_denied` or `policy_deny` for one agent often means a prompt-injected agent. A jump in `lease_expired` means agents that stopped renewing. `lease_revoked` denies after a revocation, under `initialize`, `tools/list` or a tool, mean an agent or its client is still using the revoked token.
- Any `audit_error`, `lease_error` or `policy_error`. These are internal failures and every one denied a call.
- `token.root` rows per user and agent. Root mints are the entry point of every chain.
- `audit verify` on a schedule. It exits 2 on a broken chain or an invalid checkpoint, and 1 when it could not check (server unreachable, bad admin token).
- The checkpoint `seq` should only grow. Compare each reading with the last.

If you run a second system that needs to react to revocations, such as an AuthZEN PEP, it learns of a revocation when it asks. To tell it sooner, set [`[leases.notify]`](../reference/config.md#leasesnotify): the server then `POST`s a signed `lease.revoked` notice to a webhook after each revocation. Give it its own secret in `ATTENUO_LEASE_NOTIFY_SECRET`. The notice is a hint. It can be late or lost, so the PEP should still ask, or cache an allow only briefly. See [Revocation notices](../reference/authzen.md#revocation-notices).

## Upgrades

Until 1.0, minor versions can change the config, the token format and the database layout. Read the [CHANGELOG](https://github.com/attenuo-dev/attenuo/blob/main/CHANGELOG.md) before every upgrade, and back up the database and the key first. Tokens issued by one version may not verify on the next. Plan to re-mint.

### The database schema

The SQLite file carries a schema version (SQLite's `user_version`). Each build knows the newest version it can read, and upgrades the file to it when it starts. An upgrade of the database goes like this:

1. Stop the old server, and wait until it has exited (it holds the [single-writer lock](#one-process-per-file)).
2. Back up the file with `sqlite3 attenuo.sqlite ".backup '/backups/attenuo-before-upgrade.sqlite'"`, or copy `attenuo.sqlite`, `-wal` and `-shm` together while nothing runs. This backup is the only way back.
3. Start the new binary. Before it serves anything, it brings the file to its schema version, each step in one transaction, and logs it (timestamps left out):

   ```text
   INFO attenuo_server::state: database schema migrated path="/var/lib/attenuo/attenuo.sqlite" from=0 to=5
   INFO attenuo_server::state: audit store opened (WAL) path="/var/lib/attenuo/attenuo.sqlite" durability=normal wal_checkpoint_seconds=5 schema_version=5
   ```

   `from=0` is a new file or one written before schema versions existed; a file from a build whose newest version was 1, 2, 3 or 4 shows `from=1` to `from=4`. Every start logs `schema_version` on the `audit store opened` line, so the version a server runs on is in its start-up log. A step that fails leaves the file at the version before it, and the server does not start; the error names the step.

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
- **Version 3** adds the `used_credentials` table, which records the single-use credentials the server has 