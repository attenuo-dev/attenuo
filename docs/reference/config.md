# Configuration keys

The server reads one TOML file: `onbehalf-server --config <file>` or `ONBEHALF_CONFIG=<file>`. Unknown keys are rejected at start-up. Relative paths resolve against the working directory.

The annotated source of truth is [config/example.toml](https://github.com/7Mudit/onbehalf/blob/main/config/example.toml). Never use its example admin token or agent secret for anything real. [Deploying](../guides/deploying.md) covers what to change before you expose a server.

## `[server]`

| Key | Default | Meaning |
| --- | --- | --- |
| `listen` | `127.0.0.1:8080` | Address to bind. |
| `public_url` | from the `Host` header | Externally visible base URL, used in `/.well-known/authzen-configuration`. |

## `[issuer]`

| Key | Default | Meaning |
| --- | --- | --- |
| `issuer` | `http://127.0.0.1:8080` | The `iss` of tokens. Also the `aud` an ID-JAG must carry. |
| `audience` | `onbehalf` | The `aud` of issued tokens. |
| `max_depth` | library default | Longest allowed delegation chain. The example sets 8. |
| `default_ttl_seconds` | `900` | Token lifetime when the exchange does not ask for one. |
| `lease_interval_seconds` | `300` | How long a lease lives after issuance or renewal. Must be positive. |
| `private_key_pem_path` | ephemeral key | Ed25519 PKCS#8 key. Created with mode 0600 on first start if missing. |
| `previous_key_paths` | none | Retired keys (PEM) that stay trusted for verification and in the JWKS. They never sign. |

## `[policy]`

| Key | Default | Meaning |
| --- | --- | --- |
| `policies_path` | none | Cedar policy file. `POST /admin/policies/reload` re-reads it. |
| `catalog_path` | none | JSON tool catalog. Can be combined with `[policy.catalog]`. |
| `user_attributes` | none | Extra `originating_user.attributes` for the Cedar schema, as `{ name = "type" }`. Types: `string`, `long`, `bool`, `set<string>`. |

The built-in user attributes `mfa` (bool), `roles` (set of string), `tenant` and `email` are always declared.

### `[policy.catalog.<server>.<tool>]`

| Key | Meaning |
| --- | --- |
| `readonly` | Boolean. Tests as `resource.readonly` in policies. |
| `sensitive` | Boolean. Tests as `resource.sensitive` in policies. |
| `inputs` | Table of argument name to type. Used to validate `context.input.*`. |

Every action a policy names must be in the catalog.

## `[audit]`

| Key | Default | Meaning |
| --- | --- | --- |
| `sqlite_path` | none | Audit log and lease registry. `:memory:` keeps both in memory and loses them on exit. |

## `[[upstreams]]`

One table per MCP server, using streamable HTTP.

| Key | Meaning |
| --- | --- |
| `name` | Mount name, served at `/mcp/<name>`. It is the `server` part of capabilities. |
| `url` | Upstream MCP endpoint. |

## `[admin]`

| Key | Meaning |
| --- | --- |
| `token` | Static bearer for `/admin/*`. With no token configured, admin routes answer 403 `admin_disabled`. Do not expose `/admin` publicly. |

## `[[idps]]`

Trusted identity providers for hop 0. Only these issuers are accepted at `POST /token`.

| Key | Default | Meaning |
| --- | --- | --- |
| `issuer` | | The IdP issuer URL. |
| `audience` | | The `aud` an ID token must carry, normally the client id registered at the IdP. |
| `jwks_url` | discovery | JWKS location. Otherwise `jwks_uri` from `<issuer>/.well-known/openid-configuration`. |
| `allowed_algs` | `RS256`, `ES256`, `EdDSA` | Accepted signature algorithms. HMAC is refused. |
| `attribute_claims` | `email`, `groups`, `amr` | Claims copied into `originating_user.attributes`. `mfa` is always derived from `amr`. |
| `jwks_ttl_seconds` | `300` | How long a fetched key set is used. |
| `clock_skew_seconds` | `60` | Leeway for `exp`, `iat` and `nbf`. |

## `[[agents]]`

Agents (OAuth clients) that may present user credentials at `POST /token`. With none configured, all IdP intake is rejected.

| Key | Meaning |
| --- | --- |
| `id` | Client id. Must match the `actor` if one is sent. |
| `secret_sha256` | SHA-256 of the client secret, in hex. Make it with `printf %s "$SECRET" \| sha256sum`. |

## `[[root_grants]]`

The most a root token may carry.

| Key | Meaning |
| --- | --- |
| `issuer` | Issuer of the users this applies to. |
| `agent` | The agent that holds the root token. |
| `subject` | Optional. Pins the entry to one user. A pinned entry wins over an unpinned one. |
| `capabilities` | List of `server:tool` strings. Requests are attenuated against this. |
| `attributes` | Used only by the development root mint. IdP intake takes attributes from the verified token. |

With no matching entry, no root token is issued.

## `[dev]`

| Key | Default | Meaning |
| --- | --- | --- |
| `allow_root_mint` | `false` | Mounts `POST /admin/root-token`, which mints root tokens for a user nobody verified. Development only. The server logs a warning when it is on. |

## `[metrics]`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Serve Prometheus text on a separate listener. |
| `listen` | `127.0.0.1:9100` | Address of the metrics listener. No authentication, so keep it on loopback or a private network. |
