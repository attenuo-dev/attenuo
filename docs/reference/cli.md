# CLI commands

The `attenuo` binary comes from the `attenuo-cli` crate. It talks to a running attenuo server over HTTP, except for `key gen` (`--dpop` and `--client`), `admin operator new` and `admin operator hash`, `policy lint`, `policy test` with `--via local` (the default), `token inspect` without `--verify`, `audit verify --file` with `--jwks`, and `approval verify` with a `--jwks` file, which run offline, `stdio-bridge`, which serves a local STDIO MCP server over HTTP and talks to no attenuo server, and `init`, which writes a starter configuration and talks only to the MCP server it is for. `connect` talks to the attenuo server, but over STDIO on its own side: it is started by a desktop MCP client, not typed.

```
attenuo [--server URL] [--json] <command>
```

## Global options

| Option | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--server`, `--url` | `ATTENUO_SERVER` | `http://127.0.0.1:8080` | Base URL of the attenuo server. Goes before the subcommand. Every request goes here, except requests to `/admin/*` when `--admin-server` is set. Give the final URL: the CLI follows no redirect (SR-112), and a 3xx answer is an error (exit 1) naming the URL, the status and the `Location`, for example `error: http://attenuo.internal:8080/token answered 308 Permanent Redirect (Location https://attenuo.internal/token); attenuo does not follow redirects, so --server must be the final URL, the one that answers without a redirect`. The same holds for `--admin-server` and for an `approval verify --jwks` URL. |
| `--admin-server URL` | `ATTENUO_ADMIN_SERVER` | `--server` | Base URL of the admin API, for a server with `[admin] listen` ([network exposure](../guides/deploying.md#network-exposure)): the main listener answers `/admin/*` as an unknown path. Every request to `/admin/*` goes here. Those are the requests of `token root`, `lease`, `audit` other than `audit verify --file`, `approval list`, `show`, `grant` and `decline`, `budget refund`, `policy reload`, `show`, `check` and `evaluate`, `policy test --via admin-evaluate`, `admin operator reload`, `admin agent reload` and `admin key reload`. Everything else, including `health` and the JWKS that `token inspect --verify`, `approval verify` and `audit verify --file` fetch, still goes to `--server`, so one invocation can use both. Unset or empty, `/admin/*` goes to `--server` as well, and a `404` without an error code from it (the main listener's answer to a path it does not serve) gets a second line, `hint: the server may serve its admin API on a separate listener ([admin] listen); pass --admin-server URL (or set ATTENUO_ADMIN_SERVER)`. A JSON `404` `not_found` (an unknown lease, approval or audit record) gets no hint. Goes before or after the subcommand. |
| `--admin-token-stdin` | | off | Read the admin token from the first line of standard input. The three admin token options go before or after the subcommand. |
| `--admin-token-file PATH` | | none | Read the admin token from the first line of a file. |
| `--admin-token TOKEN` | `ATTENUO_ADMIN_TOKEN` | none | Bearer for `/admin/*`. Prefer the environment variable, stdin or a file: an argument is readable by other local users (`ps`, `/proc/<pid>/cmdline`) and lands in shell history, so the CLI prints a warning to stderr when it is used. |
| `--json` | | off | Print machine-readable JSON instead of text. Works after any subcommand. |

The MCP upstream a subcommand talks to (`call`, `tools`, `authzen eval`, `policy evaluate`, `audit tail`) is its `--upstream`, for example `github`. Those subcommands still accept the old spelling `--server <name>` after the subcommand, which is deprecated: it works as before, is hidden from `--help`, and prints a one-line warning to stderr. Giving both is an error.

## Exit status

| Status | Meaning |
| --- | --- |
| 0 | Success; for a command that asks a question (`call`, `tools`, `token inspect --verify`, `policy evaluate`, `authzen eval`, `policy test`, `policy lint`, `policy check`, `audit verify`, `approval verify`), the answer was yes; for `audit prune`, the prune committed (or was already committed with that archive), or the dry run printed its plan. |
| 1 | An error: the server could not be reached or answered with an error, a file could not be read, a test file could not be run, or the command line could not be parsed (unknown flag, missing argument). The message goes to stderr as `error: ...`; for a command line, it is clap's usage message. `--help` and `--version` exit 0. `health` exits 1, not 2, when the server answers but is not healthy or ready. |
| 2 | The answer was no: a denial or `APPROVAL REQUIRED`, a JSON-RPC error from `tools`, a token that fails `--verify`, a failed test case, policy errors, a broken audit chain or invalid checkpoint, audit files that do not link, an invalid approval token; for `budget refund`, nothing to refund; for `audit prune`, a refusal, nothing to prune, an archive that does not verify or does not fit the log, or a committed prune whose anchor does not match the archive. |
| 3, 4 | `budget refund` only: already refunded, charge pruned (see [`budget refund`](#budget-refund-id---reason-text)). |

A refusal from a REST route reads `error: server answered <status>: <error> (<code>): <detail>`: the OAuth-style `error`, then the stable `code` in parentheses, then the server's `detail`, for example `error: server answered 400 Bad Request: invalid_grant (replayed): this credential was already used; present a fresh one`. Match on the code, which is never reworded ([Errors](http-api.md#errors)); the detail is for people. The ` (<code>)` is left out when the code is the `error` itself or the whole `detail` (`unauthorized: token_expired`), and so is `: <detail>` when there is none. A body that is not an error object is printed as it came. Control characters in any of these strings are printed escaped (`\u{1b}`), so an answer cannot drive the terminal (SR-118). `--json` does not change this: an error is always this text on stderr, never JSON on stdout. The one exception is `audit prune`, whose refusals are answers (exit 2) and print a JSON object on stdout with `--json` (see [`audit prune`](#audit-prune)).

## Secrets

Secrets are never taken from the argument list by default. That covers the admin token, the agent client secret and the delegation tokens (`--token`, `--subject-token`). For each, the CLI accepts, in this order of preference: the environment variable, `--…-file PATH`, stdin, and (with a one-line warning on stderr) the flag itself. Stdin is `--admin-token-stdin` / `--client-secret-stdin` for the first two, and the value `-` for the tokens (`--token -`, `--subject-token -`). A value from a file or stdin is the first line, without the line ending. At most one value can come from stdin per invocation. The flag, file and stdin forms are mutually exclusive on the command line; any of them overrides the environment variable.

| Secret | Environment | File | Stdin |
| --- | --- | --- | --- |
| Admin token | `ATTENUO_ADMIN_TOKEN` | `--admin-token-file` | `--admin-token-stdin` |
| Client secret | `ATTENUO_CLIENT_SECRET` | `--client-secret-file` | `--client-secret-stdin` |
| Delegation token (`call`, `tools`, `authzen eval`, `authzen search`) | `ATTENUO_TOKEN` | `--token-file` | `--token -` |
| Parent token, or the IdP credential at hop 0 (`token exchange`) | `ATTENUO_TOKEN` | `--subject-token-file` | `--subject-token -` |

```sh
export ATTENUO_ADMIN_TOKEN=$(cat /run/secrets/attenuo-admin)
printf '%s\n' "$CODER_SECRET" | ATTENUO_TOKEN="$ROOT" attenuo token exchange --actor coder --client-secret-stdin --cap github:read_file
attenuo --admin-token-file /run/secrets/attenuo-admin lease show "$LEASE"
printf '%s\n' "$CODER" | attenuo call --token - --upstream github --tool read_file --arg repo=acme/api
```

`token inspect -` also reads a token from stdin.

## Argument forms

- `--cap server:tool` is a capability. Globs are allowed. Repeat the flag, or comma-separate plain values. A value that starts with `{` is a full capability as JSON, which can carry constraints and run `limits` (`{"server":"banking","tool":"send_money","limits":{"calls":1,"sum":{"arg":"amount","max":100}}}`). Commands that print capabilities show limits after the constraints: `banking:send_money [calls <= 1, sum(amount) <= 100]`. `distinct` and a derived value work the same way: `--cap '{"server":"web","tool":"get_webpage","limits":{"distinct":{"arg":"url","derive":"host","max":2}}}'` prints as `web:get_webpage [distinct url#host <= 2]`. A limit kind or derivation the CLI does not know is refused before anything is sent. Constraints use the same JSON form as in a token, `{"op": ..., "value": ...}`; there is no separate flag for constraints. A `range` bounds an integer argument, both ends inclusive, either end optional: `--cap '{"server":"banking","tool":"send_money","constraints":{"amount":{"op":"range","value":{"min":0,"max":2000}}}}'` prints as `banking:send_money {0 <= amount <= 2000}` (`amount <= 2000` or `amount >= 0` with one bound). A range with no bound, `min` greater than `max`, a non-integer bound or a member other than `min` and `max` is refused before anything is sent. On exchange the child's range must sit inside the parent's, or the server answers `invalid_scope` (`exchange_widening`). A `path_prefix` holds a file path compared by `/` segment: `--cap '{"server":"fs","tool":"read_file","constraints":{"path":{"op":"path_prefix","value":"/workspace/"}}}'` prints as `fs:read_file {path is a path under "/workspace/"}`; a path with a `.` or `..` segment, `//`, a backslash, a control character or `%2e`, `%2f` or `%5c` is refused before anything is sent. `token root` and `token exchange` print `warning: ...` on stderr for a `prefix` on an argument that looks like a file path, and send the request anyway ([`prefix` or `path_prefix`](../concepts/capabilities-and-attenuation.md#prefixes-of-strings-and-of-paths)).
- `--arg key=value` sets a string argument. `--arg key:=json` sets any JSON value, such as a number or an object.
- `--attr key=value` follows the same rule for user attributes.

## Commands

### `init --upstream NAME=URL`

Write a working starter configuration for one MCP server. It is the quickest way from an installed binary to a proxied call, and it is for trying attenuo on one machine: the configuration listens on loopback and turns on the development root mint.

```text
attenuo init --upstream github=http://127.0.0.1:3001/mcp --dir ~/attenuo-try
```

It asks the MCP server for its tools (`initialize`, then every page of `tools/list`; no tool is called) and writes three files into `--dir` (default: the current directory; created when missing), plus an empty `data/` directory (mode 0700) for the issuer key and the audit log:

| File | Mode | What it holds |
| --- | --- | --- |
| `attenuo.toml` | 0600 | The server configuration: the upstream, a fresh admin token, the agent `coder` (the SHA-256 of its client secret), a root grant for the agent `planner` over `NAME:*`, and every tool in `[policy.catalog]`. |
| `policy.cedar` | 0644 | A starter policy: tools marked `readonly` in the catalog are permitted, chains deeper than 3 are forbidden, and each other tool has a commented-out permit to fill in. As written, no tool is marked `readonly`, so every call is denied until you allow it. |
| `attenuo.env` | 0600 | `ATTENUO_SERVER`, `ATTENUO_ADMIN_TOKEN` and `ATTENUO_CLIENT_SECRET` as `export` lines, to load with `. ./attenuo.env`. |

No secret is printed. The command ends with the next commands to run: start `attenuo-server`, mint a root token, exchange it for `coder`, list the tools and call one.

What it takes from the MCP server, which is the thing being guarded and so is not trusted further than this:

- A tool whose name breaks the naming rules (`[A-Za-z0-9_.-]`) cannot be called through the proxy. It is left out and named in the output.
- `annotations.readOnlyHint == true` is only reported: the output lists the tools the server says only read, and nothing is permitted because of it. It is the server's own claim, and a server that lies about it would otherwise get its tools allowed. With `--trust-readonly-hints` you accept the claim: those tools are marked `readonly` in the catalog, and the starter policy permits them. A tool that claims to be both read-only and destructive is never marked read-only.
- `annotations.destructiveHint == true` marks the tool `sensitive`.
- Arguments of type `string`, `integer` and `boolean` in the tool's `inputSchema` become catalog `inputs` (`string`, `long`, `bool`) so a policy can test them; other types and names that are not plain identifiers are left out (at most 64 per tool).
- Descriptions and every other text from the server are written nowhere.

Options:

- `--upstream NAME=URL` (required): the name the MCP server gets in attenuo and its Streamable HTTP URL (`http://` or `https://`, no user name, password or fragment).
- `--dir DIR`: where the files go.
- `--listen ADDR`: the address the attenuo server will listen on, `127.0.0.1:8080` by default. Must be loopback, because the server refuses the development root mint elsewhere, and must name a port (not 0).
- `--no-discover`: do not contact the MCP server. The catalog is left empty with an example entry in a comment, so every call is denied (`tool_not_in_catalog`) until you list the tools. Use it for a server that needs credentials (discovery sends none) or is not running.
- `--trust-readonly-hints`: see above. Cannot be combined with `--no-discover`.
- `--force`: replace the three files when they exist, with new secrets. Without it the command refuses, before it contacts the MCP server, when any of the three exists, and changes nothing.

Each file is written in full under a temporary name and then moved into place, so a failure part-way leaves no half-written file. A symbolic link at one of the three names counts as an existing file: without `--force` it is refused, and with `--force` the link itself is replaced and the file it points to is not touched. A `data/` directory that is already there is left as it is, its mode too. The upstream name `attenuo` is refused, because the server's own audit records use it.

Limits: at most 2,000 tools over at most 200 pages, each answer at most 16 MB and all of them together at most 48 MB, a 30 s timeout per request, and no redirect is followed. Exit status 1 with a message when the MCP server cannot be reached, answers with an HTTP or JSON-RPC error, or does not answer as an MCP server; nothing is written then. Tested in `crates/attenuo-cli/tests/init.rs`, where a real attenuo server loads the files as written and proxies the calls: all denied by default, and one allowed and two denied with `--trust-readonly-hints`.

### `health`

Check that the server is up: `GET /healthz`, or with `--ready`, `GET /readyz` ([health and readiness](../guides/deploying.md#health-and-readiness)). Needs no token. Prints `ok (attenuo-server <version>)` or `ready {...checks...}` and exits 0; exits 1 with `error: ...` on stderr when the server cannot be reached within the timeout, answers another status (for `/readyz`, the message names the failing check), or answers 200 with a body that is not attenuo's (another service on the port). It never exits 2, because Docker reserves that status for health checks. The release image's `HEALTHCHECK` is `attenuo --server http://127.0.0.1:8080 health`. Point it at the main listener: the admin listener (`[admin] listen`) has no `/healthz`.

| Option | Default | Meaning |
| --- | --- | --- |
| `--ready` | off | Ask `/readyz` (audit log and lease store answer, the last audit append succeeded) instead of `/healthz`. |
| `--timeout SECS` | `5` | Give up after this many seconds (1 to 300), connecting and answering together. |

```sh
attenuo --server http://127.0.0.1:8080 health            # liveness
attenuo --server http://127.0.0.1:8080 health --ready    # readiness, for a load balancer or readinessProbe
```

### `token root`

Mint a root (hop 0) token. This uses the development endpoint, so it needs the admin token and `[dev] allow_root_mint = true` on the server. Without the setting the route does not exist, and the `404` gets a line `hint: POST /admin/root-token exists only when the server's config sets [dev] allow_root_mint = true (development only); ...`. For a root token from a user's IdP credential, use `token exchange --subject-token-type id-token` instead ([Hop 0](#hop-0-from-an-id-token)).

| Option | Meaning |
| --- | --- |
| `--subject` | The user the agent acts for. Required. |
| `--issuer` | Issuer of the user's identity. Default `https://idp.example`. |
| `--agent` | The root agent. Required. |
| `--cap` | Capability to request. Omit to take the `[[root_grants]]` ceiling. With `[[root_grants]]` set, two `--cap` under one limited capability of the entry are refused (`invalid_scope` / `limit_split_at_root`): ask for one capability with a `one_of` instead. |
| `--ttl-seconds` | Requested lifetime. |
| `--attr` | User attribute. Repeatable. |
| `--may-act <AGENT>` | Only this agent may exchange the root token (RFC 8693 `may_act`). Repeatable, or comma-separated. Must be within the `[[root_grants]]` entry's `may_act` when it has one. Without it and without `--no-delegation` the grant's `may_act` applies; when the grant has none, or the server has no `[[root_grants]]`, the root token has no `may_act`, so any authenticated agent may exchange it. Values that are all empty are refused. |
| `--no-delegation` | Send `may_act: []`: no agent may exchange the root token. An empty list is within any grant's `may_act`. Cannot be combined with `--may-act`. |
| `--dpop-key PATH` | Bind the root token to this DPoP key (a private JWK from `key gen --dpop`). |
| `--print token\|lease` | Print only that value, for scripts. |

### `token exchange`

RFC 8693 exchange: delegate a subset of a token's capabilities to a sub-agent. With `--subject-token-type id-token` or `id-jag` it is hop 0 instead: an agent trades a user's credential from an `[[idps]]` issuer for a root token (see [Hop 0](#hop-0-from-an-id-token)).

| Option | Meaning |
| --- | --- |
| `--subject-token-file PATH` | Read the parent token (at hop 0, the IdP credential) from the first line of a file. |
| `--subject-token <JWT\|->` (`ATTENUO_TOKEN`) | The parent token (at hop 0, the IdP credential); `-` reads it from stdin. One of the flag, the file or `ATTENUO_TOKEN` is required. The flag with a literal token prints a warning. |
| `--subject-token-type jwt\|id-token\|id-jag` | What the subject token is, sent as `subject_token_type`. `jwt` (the default, `urn:ietf:params:oauth:token-type:jwt`): an attenuo token, exchanged from hop n to hop n+1. `id-token` (`...:id_token`, an OIDC ID token) or `id-jag` (`...:id-jag`, an ID-JAG): hop 0. |
| `--actor` | The sub-agent that will hold the new token; at hop 0, the agent presenting the credential. Required. |
| `--client-secret-stdin` | Read the agent's client secret from the first line of standard input. |
| `--client-secret-file PATH` | Read it from the first line of a file. |
| `--client-secret` (`ATTENUO_CLIENT_SECRET`) | The agent's client secret, required when the server has `require_actor_auth` (the default). Prefer the environment variable, stdin or a file; the flag prints a warning. |
| `--client-id` | Client id to authenticate with. Defaults to `--actor`. |
| `--client-key PATH` | Authenticate with `private_key_jwt` (RFC 7523) instead of a secret, for an agent whose `[[agents]]` entry has `jwks` or `jwks_url`: sign a client assertion with this private JWK (Ed25519 or P-256, as `key gen --client` writes). The assertion's `iss` and `sub` are the client id, its `kid` the file's, its `jti` fresh, and it lives one minute. Cannot be combined with the `--client-secret` forms; `ATTENUO_CLIENT_SECRET` is then ignored. |
| `--client-assertion-audience ISSUER` | The assertion's `aud`, which must be the server's `[issuer] issuer`. Defaults to the subject token's `iss`; required at hop 0, where the subject token's `iss` is the IdP's. Needs `--client-key`. |
| `--cap` | Capability to hand over. Required, repeatable. Must be covered by the parent; at hop 0, by the `[[root_grants]]` entry, and two `--cap` under one limited capability of the entry are refused (`invalid_scope` / `limit_split_at_root`): ask for one capability with a `one_of` instead. |
| `--ttl-seconds` | Requested lifetime, clamped to the parent's expiry; at hop 0, to the credential's. |
| `--actor-token <JWT\|->` | Authenticate `--actor` with an RFC 8693 actor token, such as a SPIFFE JWT-SVID from an `[[actor_trust]]` issuer, instead of a client secret. `-` reads it from stdin. Each token works for one exchange. |
| `--actor-token-file <PATH>` | Read the actor token from a file, for example the JWT-SVID a SPIFFE helper writes. Cannot be combined with `--actor-token`. |
| `--may-act <AGENT>` | Only this agent may exchange the new token (RFC 8693 `may_act`). Repeatable, or comma-separated. Without it and without `--no-delegation` the new token has no `may_act`, so any authenticated agent may exchange it; it does not inherit the parent's list. Values that are all empty are refused. |
| `--no-delegation` | Send `may_act: []`: no agent may exchange the new token. Cannot be combined with `--may-act`. |
| `--dpop-key PATH` | Bind the new token to this DPoP key. Required when the parent is bound. When the parent is bound to the same key, the proof also covers the parent. At hop 0, required for an ID-JAG with a `cnf` key, which must be this key. |
| `--subject-token-dpop-file PATH` | The parent holder's sign-off (`subject_token_dpop`), made with `token sign-off` for this exchange's `--dpop-key` and `--actor`. Required when the parent is bound to a key other than `--dpop-key`. Refused at hop 0. |
| `--subject-dpop-key PATH` | Instead of `--subject-token-dpop-file`, when this process may hold the parent's key too: the sign-off is made here. Cannot be combined with `--subject-token-dpop-file`. Refused at hop 0. |
| `--print token\|lease` | Print only that value. |

```sh
ATTENUO_TOKEN="$PARENT" attenuo token exchange --actor coder \
  --cap github:read_file --actor-token-file /run/spiffe/coder.jwt --may-act reviewer
```

#### Hop 0 from an ID token

With `--subject-token-type id-token` the subject token is a user's OIDC ID token, and the request is the hop-0 exchange of [Identity providers](../guides/identity-providers.md): `subject_token_type` `urn:ietf:params:oauth:token-type:id_token`, the capabilities as `authorization_details`, and the agent's credentials. The answer is a root token for the user and `--actor`. `--subject-token-type id-jag` sends an ID-JAG the same way (`...:id-jag`, as a token exchange; the CLI does not send the `jwt-bearer` grant). The server's rules for hop 0 apply: the agent always authenticates (client secret, `--client-key` or `--actor-token`), `--cap` must be within its `[[root_grants]]` entry (and, for an ID-JAG under `[idps.id_jag_ceiling]`, within what its claims leave of it), two `--cap` may not fall under one limited capability of the entry (`invalid_scope` / `limit_split_at_root`), a `--cap` under limited capabilities whose limits one capability cannot carry together is refused (`invalid_scope` / `limit_conflict_at_root`), the entry's `credentials` must list the credential's kind (`invalid_grant` / `credential_type_not_accepted`), `--may-act` and `--no-delegation` within the entry's `may_act`, and each credential mints one root token (a second use is `invalid_grant` / `replayed`). The sign-off flags are refused before anything is sent, since there is no parent token, and so is `--client-key` without `--client-assertion-audience`.

```sh
printf '%s\n' "$PLANNER_SECRET" | ATTENUO_TOKEN="$ID_TOKEN" attenuo token exchange \
  --subject-token-type id-token --actor planner --client-secret-stdin \
  --cap '{"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"prefix","value":"acme/"}}}'
```

A refused exchange that the server audited (its subject token verified) prints the record id under the error, as `decision <id>`, for `audit show --id`:

```text
error: server answered 400 Bad Request: invalid_request (actor_not_permitted): agent `reviewer` is not permitted to act on this token (may_act)
decision 6c65098c-383f-4119-8c0f-95ce3a384bdc
```

### `token sign-off`

Made by the holder of a bound parent token, to consent to one exchange that binds the child to another key. Prints a proof by `--dpop-key` (the parent's key) for `POST` to the server's `/token`, with `ath` of the parent token and the claims `child_jkt` and `child_actor`; with `--json`, `{"subject_token_dpop": ...}`. The server accepts it only for an exchange whose `DPoP` key and `actor` are the ones it names, within `[token] dpop_max_age_seconds`, once. A sign-off made before a server restart is refused after it (`invalid_dpop_proof`, the restart fence of [binding tokens to keys](../guides/binding-tokens-to-keys.md#limits)): make a new one. Hand it to the sub-agent, which passes it with `token exchange --subject-token-dpop-file`; the parent's key stays with the parent.

| Option | Meaning |
| --- | --- |
| `--subject-token <JWT\|->` / `--subject-token-file PATH` | The parent token. Defaults to `ATTENUO_TOKEN`. |
| `--dpop-key PATH` | The key the parent token is bound to. Required; refused if it is not that key. |
| `--child-jkt JKT` | Thumbprint of the sub-agent's key (`key gen --dpop` prints it). Required. |
| `--actor AGENT` | The sub-agent that will make the exchange. Required. |

```sh
ATTENUO_TOKEN="$ROOT" attenuo token sign-off --dpop-key assistant.jwk \
  --child-jkt "$CODER_JKT" --actor coder > sign-off.txt
```

### `key gen --dpop <PATH>`

Write a new Ed25519 DPoP key (RFC 9449) to `PATH` as a private JWK, mode 0600, and print its thumbprint (`jkt`, what a bound token's `cnf.jkt` will be). An existing file is never overwritten (exit code 1). Pass the file to the command that uses the key (`token root --dpop-key`, `token exchange --dpop-key`, `call --dpop-key`); the Python and TypeScript SDKs read the same format. See [Binding tokens to keys](../guides/binding-tokens-to-keys.md).

```console
$ attenuo key gen --dpop coder.jwk
wrote DPoP key coder.jwk (EdDSA)
jkt  4MMDxQj9pafXPrWH6dxBeoSk2DpHFpEZvXvsmr6JibU
```

### `key gen --client <PATH> [--kid KID]`

Write a new Ed25519 client key for `private_key_jwt` (RFC 7523) to `PATH` as a private JWK, mode 0600, and print the `jwks` line, with only its public half, to paste into the agent's `[[agents]]` entry (or a PEP's `[[peps]]` entry). The `kid` is `--kid`, or the key's RFC 7638 thumbprint. An existing file is never overwritten (exit code 1). Pass the file to `token exchange --client-key`; the SDKs read the same format. With `--json`: `{path, kid, alg, jwk}`. To rotate, generate a key with a new `kid`, add it to the entry's `jwks` next to the old one, run [`admin agent reload`](#admin-agent-reload) (or restart), move the agent over, then remove the old key and reload again ([config](config.md#agents)).

```console
$ attenuo key gen --client coder-client.jwk --kid coder-2026-11
wrote client key coder-client.jwk (EdDSA, kid coder-2026-11)
add to the agent's [[agents]] (or the PEP's [[peps]]) entry:
jwks = '''{"keys":[{"kty":"OKP","crv":"Ed25519","x":"…","kid":"coder-2026-11","alg":"EdDSA","use":"sig"}]}'''
```

### `admin operator new --name <NAME> --role <ROLE>` / `admin operator hash`

Make the credential of a named admin operator ([ADR-0016](../decisions/0016-admin-operators.md)). Offline: nothing is written to disk and nothing is sent to a server.

`admin operator new` generates a token from 32 random bytes (base64url, 43 characters) and prints it once on stdout, then a blank line, then the `[[admin.operators]]` entry for the server's config, which holds only the token's SHA-256. A two-line reminder goes to stderr. `--role` is `viewer`, `operator` or `admin` ([roles](config.md#admin)). `--name` is `[a-z0-9_-]{1,64}` and not `admin`; a name the server would refuse is refused here (exit code 1, nothing on stdout). `--expires-in <DURATION>` (a whole number and a unit, `s`, `m`, `h` or `d`: `90d`, `12h`; at most `3650d`) or `--expires-at <RFC3339>` (a time with an offset, in the future), not both, adds `expires_at` to the entry: from then on the server answers the token 401 `admin_credential_expired`. With `--json`, stdout is one object with `name`, `role`, `token`, `token_sha256`, `expires_at` (`null` without an expiry) and `toml` (the entry). Hand the token to the operator over a secure channel, add the entry to the config file and run [`admin operator reload`](#admin-operator-reload) (or restart the server).

```console
$ attenuo admin operator new --name alice --role operator
q3J0bXk1Wm5hZ2FvN2dLc2l0bU9lQk1HWWJ0QkxzRmc

[[admin.operators]]
name = "alice"
token_sha256 = "42a700cb2073e31b8140cd98dee7d52ab967d8331ede74514a895d9e41c5163f"
role = "operator"
The token above is shown once and is stored nowhere: give it to `alice` over a secure channel.
Add the [[admin.operators]] entry to the server's config file, then run `attenuo admin operator reload` (or restart the server).
```

```console
$ attenuo admin operator new --name contractor --role viewer --expires-in 30d
…
[[admin.operators]]
name = "contractor"
token_sha256 = "…"
role = "viewer"
expires_at = "2026-12-13T09:00:00Z"
```

`admin operator hash` reads a token from the first line of stdin and prints its `token_sha256` (`{"token_sha256": ...}` with `--json`), for a token made some other way. It cannot be combined with `--admin-token-stdin`.

```sh
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | tee alice.token | attenuo admin operator hash
```

The operator then uses the token like any admin token (`ATTENUO_ADMIN_TOKEN`, `--admin-token-file`, `--admin-token-stdin`); a command whose route the operator's role does not reach exits 1 with `admin_role_insufficient`.

### `admin operator reload`

Ask the server to re-read `[[admin.operators]]` from the config file it was started with and put them in force without a restart (`POST /admin/operators/reload`, role `admin`). Prints the operators added, removed and changed (role, token or expiry), by name; `--json` prints the server's answer. Only the operators are re-read: `[admin] token` and the rest of the file are not reloaded. Use it to add an operator, to withdraw a leaked token (remove its entry, or give it an `expires_at` in the past, then reload), or to change a role.

```console
$ attenuo admin operator reload
reloaded operators: 1 added, 1 removed, 1 changed
  added    alice
  removed  bob
  changed  carol
```

A refusal exits 1 with the server's code, and the operators in force stay as they were: `operators_invalid` (the file is not TOML, or an entry breaks a [startup rule](config.md#adminoperators)), `operators_no_admin` (the new list would leave no unexpired credential with role `admin`, and there is no `[admin] token`), `reload_unavailable` (the server was not started from a config file), `config_unreadable` (the file cannot be read), or `admin_role_insufficient` (the token's role is below `admin`).

### `admin agent reload`

Ask the server to re-read `[[agents]]` and `[[peps]]` from the config file it was started with and put them in force without a restart (`POST /admin/agents/reload`, role `admin`). Prints, for each list, how many entries are in force and the ids added, removed and changed (secret or keys), then the other sections of the file that differ from the running config and need a restart; `--json` prints the server's answer. Use it to add an agent or a PEP, to rotate a secret or a key, or to remove a credential.

| Option | Meaning |
| --- | --- |
| `--allow-empty` | Accept a file that leaves `[[agents]]` or `[[peps]]` empty while the server has entries in force. Without it the reload is refused (`agents_reload_empties`): an empty or cut-off file reads that way. |
| `--allow-mismatch` | Accept a file whose `[issuer]` (its key files aside) or `[audit]` differs from the running config. Without it the reload is refused (`config_file_mismatch`): such a file may be another server's. Only the lists are applied either way. |

```console
$ attenuo admin agent reload
agents: 3 in force, 1 added, 1 removed, 1 changed
peps: 1 in force, 0 added, 0 removed, 0 changed
  added    agent tester
  removed  agent coder
  changed  agent reviewer
```

Warnings go to stderr, one `warning:` line each, in text and `--json` mode alike, and the exit status stays 0: the startup warnings the new lists raise, a removed agent that can still get new tokens another way (see below), and the lists that the file's own settings would refuse after a restart.

Removing an agent stops it authenticating with its secret or key. It does not always stop new tokens: with `[token] require_actor_auth = false` an exchange can still name it as the actor, and an `[[actor_trust]]` entry that maps a workload to its id still lets it in with an actor token (removing that takes a restart). The reload warns about both. Tokens already issued are not revoked either: revoke them with [`lease revoke`](#lease-revoke-id---reason-text). To contain a compromised agent, remove it, reload, and revoke its leases.

A refusal exits 1 with the server's code, and the lists in force stay as they were: `agents_invalid` (the file does not parse, or a list breaks a [startup rule](config.md#agents)), `agents_reload_empties` and `config_file_mismatch` (above), `reload_unavailable` (the server was not started from a config file), `config_unreadable` (the file cannot be read), or `admin_role_insufficient` (the token's role is below `admin`).

### `admin key reload`

Ask the server to rotate its token signing key without a restart (`POST /admin/keys/reload`, role `admin`). The server re-reads its config file, takes from it only `[issuer] private_key_pem_path` and `previous_key_paths`, reads those key files, and puts the new signing key and verifying keys in force at once. Prints the signing key id before and after, the key ids added to and removed from the verifying set, the key that now signs audit checkpoints, and the sections of the file that differ from the running config and need a restart; `--json` prints the server's answer. Only key ids are printed, never a key. The steps of a rotation are in [Deploying](../guides/deploying.md#key-rotation).

| Option | Meaning |
| --- | --- |
| `--allow-drop-current` | Accept a new signing key while the current one is not in `previous_key_paths`. Every token the current key signed stops verifying at once. Without it the reload is refused (`keys_reload_drops_current`). Use it after a key compromise. It always needs `--allow-drop-audit-key` too, since the current key is the one that signs the audit log. |
| `--allow-drop-audit-key` | Accept verifying keys that leave out a key that signed audit checkpoints or anchors the log still holds, or the key that signs them now. `attenuo audit verify` then reports those as signed by an unknown key. Without it the reload is refused (`keys_reload_drops_audit_key`). |
| `--allow-mismatch` | Accept a file whose `[issuer]` (its key files aside) or `[audit]` differs from the running config. Without it the reload is refused (`config_file_mismatch`): such a file may be another server's. Only the keys are applied either way. |

```console
$ attenuo admin key reload
signing key: 9gqQK0TiSahsP4OxT1Gk2g -> mQ3lMQcsS6m-yZ-a9pD1yQ
verifying keys: 2 in force, 1 added, 0 removed
  added    mQ3lMQcsS6m-yZ-a9pD1yQ
audit checkpoints signed by: mQ3lMQcsS6m-yZ-a9pD1yQ
```

Warnings go to stderr, one `warning:` line each, with `--json` too, and the exit status stays 0. A line `warning: still keyed by the startup key (restart to re-key)` names the DPoP nonces and the subject digests, when they are on: they keep the key the server started with until a restart.

A refusal exits 1 with the server's code, and the keys in force stay as they were: `keys_config_invalid` (the file does not parse, or sets no `private_key_pem_path`), `key_file_unreadable`, `key_file_invalid` (not a regular file, over 64 KiB, or not an Ed25519 key of the kind wanted), `key_duplicate` (a key in two files), `keys_reload_drops_current`, `keys_reload_drops_audit_key` and `config_file_mismatch` (above), `reload_unavailable` (the server was not started from a config file), `config_unreadable` (the file cannot be read), or `admin_role_insufficient` (the token's role is below `admin`).

### `token inspect <JWT>`

Decode a token and show its delegation chain as a tree. Use `-` to read the token from stdin.

| Option | Meaning |
| --- | --- |
| `--verify` | Fetch the server JWKS and verify signature, issuer, audience and chain. |
| `--issuer` | With `--verify`: expected issuer. Default: the token's own. |
| `--audience` | With `--verify`: expected audience. Default: the token's own. |

The text output has a `may_act` line saying who may exchange the token next: `may_act (absent): any authenticated agent may exchange this token`, `may_act []: no agent may exchange this token`, or `may_act coder, reviewer: only these agents may exchange this token` (agent ids with control characters escaped). With `--verify` it is read from the verified claims, which the signature covers. For a bound token the text output adds `bound to DPoP key jkt <thumbprint>`. A key line follows `iss`/`aud`/`jti`: `kid <kid>` is the key that signed the token (the JWT header) and `ou_kid <kid>` the key that made the originating-user signature at the root; each is shown only when present. They differ for a token exchanged after a key rotation from a root minted before it. The `--json` output has both already, in `header.kid` and `claims.ou_kid`.

### `call`

Call a tool through the proxy (`tools/call`).

| Option | Meaning |
| --- | --- |
| `--token <JWT\|->` (`ATTENUO_TOKEN`) | Delegation token; `-` reads it from stdin. One of the flag, `--token-file` or `ATTENUO_TOKEN` is required. The flag with a literal token prints a warning. |
| `--token-file PATH` | Read the delegation token from the first line of a file. |
| `--dpop-key PATH` (`ATTENUO_DPOP_KEY`) | The DPoP key the token is bound to. Every request then carries a proof and `Authorization: DPoP`. Against a server with `[token] dpop_nonce = "required"` the CLI keeps the `DPoP-Nonce` the server sent, puts it in the proof, and sends a request once more when the server answers `use_dpop_nonce` (RFC 9449 §8); nonces are never printed or logged. Also on `tools`, `authzen eval` and `authzen search`, and on `token root` and `token exchange`. |
| `--upstream` | MCP upstream name. Required. (`--server` after `call` is a deprecated spelling.) |
| `--tool` | Tool name. Required. |
| `--arg` | Tool argument. Repeatable. |

The text output prints the tool's text content with its line breaks and tabs, and every other control character escaped (`\u{1b}`, `\r`): the result, an error message and the fields of a denial come from the server or the upstream MCP server, and must not drive the terminal (SR-118). `--json` prints the answer as JSON, whose strings escape control characters anyway.

A call that needs an approval prints `APPROVAL REQUIRED` followed by the approval id, its expiry, the call hash and the decision id, and exits 2, like a denial. Once the approval is granted, run the identical command again: it is allowed once.

### `tools`

List the tools the token may see (`tools/list`). Takes `--token` (or `--token-file`, or `ATTENUO_TOKEN`) and `--upstream` (`--server` after `tools` is a deprecated spelling), and `--dpop-key PATH` (`ATTENUO_DPOP_KEY`) for a token bound to a key, as `call` does. Tool names and descriptions are the upstream's: the text output escapes their control characters, keeping a description's line breaks and tabs (SR-118).

### `lease revoke <ID> [--reason TEXT]`

Revoke a lease and every lease delegated from it. Needs the admin token.

### `lease revoke --user SUB | --chain-id ID | --session ID [--preview] [--reason TEXT]`

Revoke every unrevoked lease of one originating user (`--user`, the `sub` of the chain's originating user), of one delegation chain (`--chain-id`, the `chain_id` of its audit records, which is its first hop's lease) or of the chain that opened one MCP session through the proxy (`--session`, the raw `Mcp-Session-Id`), each with everything delegated from it ([`POST /admin/leases/revoke`](http-api.md#revoke-by-user-or-chain)). Give exactly one of a lease id, `--user`, `--chain-id` and `--session`. `--preview` lists what would be revoked and changes nothing. Leases registered before the server recorded subjects have none, so `--user` does not find them; `--chain-id` does. Needs the admin token.

```text
$ attenuo lease revoke --user alice@example.com --reason "laptop stolen"
selector  user alice@example.com
matched   2 lease(s)
revoked 3 lease(s)
  0b7e...
  6f1c...
  a93d...
reason    laptop stolen
audit     3f2a...
```

The matches come first, then the descendants the cascade reached. With `--preview` the output starts with `preview: nothing was changed`, says `would revoke`, and has no reason or audit line. `--json` prints the server's answer.

With `--session` the server hashes the id and resolves it to the chain that opened the session ([Revoke by session](http-api.md#revoke-by-session)). The output names the session by its audit tag, never the id, and adds a `chains` line:

```text
$ attenuo lease revoke --session 3b9f0c1e-... --preview
preview: nothing was changed
selector  session 9c2e41d07a5b
chains    6f1c...
matched   2 lease(s)
would revoke 2 lease(s)
  6f1c...
  a93d...
```

A session the server has no record of prints `chains    none recorded for this session` and matches nothing. The id is a command-line argument, so it lands in shell history; it is useless without the session owner's token (SR-11), and after the revocation that token's chain is dead.

### `lease show <ID>`

Show a lease's state. Needs the admin token.

### `lease tree <ID> [--max-nodes N]`

A dry run of `lease revoke`: shows what a revocation of `ID` would reach and changes nothing (`GET /admin/leases/{id}/tree`). Prints the lease's ancestors nearest first, then the lease and everything delegated from it as an indented tree. Each lease shows the agent it was issued to, its state (`active, expires ...`, `REVOKED <time> (<reason>)` or `expired ...`) and the audit `seq` that issued it. The last line is `would revoke N lease(s)`, the count a revoke sent now would return. `--max-nodes` caps the listing (server default 1000, at most 10000); when the cap cuts it short, a `truncated:` line says so, and `would revoke` still counts the whole subtree. Needs the admin token. In the examples ids are shortened and times are cut to the second; the CLI prints them in full (`2026-10-23T22:13:22.418406557Z`).

```console
$ attenuo lease tree 4cf28235-...
root lease (no ancestors)
4cf28235-...  planner  active, expires 2026-10-23T22:13:22Z  issued #1
└─ 0ee3ac8b-...  coder  active, expires 2026-10-23T22:13:22Z  issued #3
   └─ 6dd4e10a-...  reviewer  REVOKED 2026-10-23T22:08:23Z (rotated)  issued #4
would revoke 2 lease(s) if revoked now
```

A lease whose hop has run limits ([ADR-0010](../decisions/0010-run-limits.md)), or that something was charged under, gets its budget on the lines under it, from the node's `budget` member ([Lease tree](http-api.md#lease-tree)). There is one `limit` line per limit: `<server>/<tool> <kind> [<arg>] <used>/<max> (<remaining> left)`. `used` is calls for `calls`, the sum for `sum`, the number of values seen for `distinct`, and for `calls_per` the most calls any one value has had, with the number of values seen after what is left. A host-derived argument shows as `url#host`. On a run's root lease, one `usage` line per destructive tool gives the run's calls, amount and number of destinations. A lease issued by a server that did not keep its hop's limits prints `limits not recorded` and then its counters as `cap <n> <kind> [<arg>] <used> used`. A lease with no limits and no charges adds nothing, so a tree without run limits looks as above. Every call is charged to every hop it passes through, so the smallest figure left along a branch is what its lowest lease can still spend. There is no flag to hide the budget lines: they are indented inside their lease's branch, and their number is bounded by the limits in each token. `--json` prints the server's answer unchanged.

```console
$ attenuo lease tree 7a1c90e2-...
root lease (no ancestors)
7a1c90e2-...  planner  active, expires 2026-10-24T14:20:00Z  issued #1
│    limit bank/send_money calls 1/3 (2 left)
│    limit bank/send_money sum amount 40/100 (60 left)
│    limit web/get_webpage distinct url#host 2/3 (1 left)
│    usage bank/send_money: 1 calls, amount 40, 1 destinations
└─ 5e21d4b0-...  coder  active, expires 2026-10-24T14:20:00Z  issued #2
        limit bank/send_money calls 1/2 (1 left)
        limit bank/send_money calls_per to 1/1 (0 left, 1 values)
        limit web/get_webpage distinct url#host 2/2 (0 left)
would revoke 1 lease(s) if revoked now
```

The run's root lease (the first line when `ID` is the root, otherwise the last ancestor) also gets the per-user windows of the run's originating user ([run limits phase 3](../design/run-limits-phase3.md)), from the tree's `user_windows` member, after its budget lines: one `window <kind> <start> <server>/<tool>: <calls> calls, amount <amount>` line per tool the run used and window kind a loaded policy reads, with the window's start in UTC. The figures count every run of that user, not only this one. A run issued before the server kept the user's issuer (schema version 4) prints `user windows not recorded (lease issued before schema version 4)` instead; a run with no usage, or a deployment whose policies read no window, adds nothing, and so does a server older than the member. When the server's cap cut the list, a `user windows truncated: only N listed` line follows.

```console
$ attenuo lease tree 7a1c90e2-...
root lease (no ancestors)
7a1c90e2-...  planner  active, expires 2026-10-24T14:20:00Z  issued #1
│    usage bank/send_money: 1 calls, amount 40, 1 destinations
│    window day 2026-10-24T00:00:00Z bank/send_money: 3 calls, amount 120
└─ 5e21d4b0-...  coder  active, expires 2026-10-24T14:20:00Z  issued #2
would revoke 1 lease(s) if revoked now
```

### `budget refund <ID> --reason TEXT`

Give back to every run-limit counter what one allowed decision charged, once, for a call whose effect did not happen (`POST /admin/budgets/refund`). `ID` is the decision record's id: the `id=` that `audit tail` prints for the allowed call, or the AuthZEN `context.decision_id`. `--reason` is required and must not be blank; it is recorded in the `admin.budget.refund` audit record the server appends. The run usage the decision charged is given back too, but `refunded` counts only the token-limit counters, so a call that charged usage alone answers 0. A `distinct` value counts as refunded only when no other unrefunded decision used it (SR-62): until then it stays counted, and a refund that frees nothing answers 0. `--json` prints the server's `{decision_id, refunded, reason, audit_id}`. Needs the admin token.

```console
$ attenuo budget refund 9f35c2a1-... --reason "upstream timed out"
decision  9f35c2a1-...
refunded  2 limit counter(s)
reason    upstream timed out
audit     e1b04d7c-...
```

When the server refuses, one line goes to stderr and nothing to stdout, with `--json` too:

| Server answer | Message | Exit status |
| --- | --- | --- |
| 404 `not_found` | `error: ` and the server's detail, which says which case it is: ``unknown decision `<id>`: no audit record has this id; nothing to refund``, ``decision `<id>` charged nothing: ...`` or ``decision `<id>` charged no run limit, only run usage, ...`` (see [Budget refund](http-api.md#budget-refund)); from a server without that detail, `error: no charge is recorded for decision <id> (it charged no run limit or run usage, or its charge log was pruned); nothing to refund` | 2 |
| 409 `already_refunded` | `error: the charge of decision <id> was already refunded` | 3 |
| 410 `charge_pruned` | `error: the charge of decision <id> was pruned ([leases] run_state_retention_seconds after its run ended); it can no longer be refunded` | 4 |
| anything else | `error: server answered ...` | 1 |

Exit 3 lets a script that retries a refund tell "already done" from "nothing to do", and exit 4 tells "too late: the charge log no longer has it" from both. If the refund stood but its audit record could not be written, `audit` reads `- (the refund stands, but its audit record was not written; see the server log)` and the exit status is 0.

### `audit tail`

Show the most recent audit entries, oldest of them first. Filters keep only matching entries, so `audit tail -n 5 --decision deny` is the last five denials. Needs the admin token.

| Option | Default | Meaning |
| --- | --- | --- |
| `-n`, `--lines` | 20 | How many entries. |
| `--before SEQ` | the head | Show the `-n` matching entries just below `SEQ` instead of the newest (the range `to=SEQ-1` of `GET /admin/audit`). To page back, pass the oldest `seq` shown. Not with `--follow`. |
| `-f`, `--follow` | off | Keep polling for new matching entries. |
| `--interval-ms` | 1000 | Polling interval with `--follow`. |
| `--kind` | all | Record kind: `decision`, `tool_result`, `approval_request`, `approval_grant`, `exchange`, `root_token`, `lease_renew`, `lease_revoke`, `admin` or `search`. Repeatable, or comma-separated; any of them matches. |
| `--decision` | all | `allow` or `deny`. It matches every kind whose record carries that decision: the `tool_result` record of an allowed call is `allow` too, so add `--kind decision` to get only decision records (for example to find the `id=` for `budget refund`). |
| `--reason` | all | The record's `reason` (`policy_deny`, `lease_revoked`, ...). |
| `--subject` | all | The originating user. |
| `--agent` | all | An agent anywhere in the record's chain. |
| `--lease` | all | A lease anywhere in the record's chain. |
| `--upstream` | all | The MCP upstream the call went to (the record's `server`). `--server` after `audit tail` is a deprecated spelling; the attenuo server URL is the global `--server` before the subcommand. |
| `--tool` | all | The tool. attenuo's own records use `token.root`, `token.exchange`, `lease.renew` and `admin.*`. |
| `--chain-id` | all | The delegation chain (the lease id of its first hop). |
| `--since`, `--until` | | RFC 3339 times: records with `at` in `[since, until)`. |

Refused token exchanges and refused lease renewals are kind `decision`, not `exchange` or `lease_renew`, so `--kind exchange` lists issued exchanges only. Find the refusals by tool and decision, then open one by the `decision <id>` the CLI printed under the error:

```sh
attenuo audit tail -n 50 --tool token.exchange --decision deny   # refused exchanges
attenuo audit tail -n 50 --tool lease.renew --decision deny      # refused renewals
attenuo audit tail --tool token.exchange --reason exchange_widening
attenuo audit show --id 6685bd7f-cbb3-48e5-ab05-f2b8ceae9a61
```

The filters are the query parameters of `GET /admin/audit` (see [Querying the audit log](http-api.md#querying-the-audit-log)): exact matches, combined with AND. A bad kind, decision or time is refused before any request. The CLI reads newest first (`order=desc`, with `to` for `--before`) and keeps following `next_cursor` until it has `-n` entries, because a filtered page can come back short, even empty, when the server stops scanning. `--follow` then reads forward with `from` just above the head, follows `next_cursor` while it is set, and polls again from above the last `seq` it read. With `--json` each entry is one JSON line.

Every line starts with the sequence number and the time. Decisions, token issuance, lease and admin records show `ALLOW` or `DENY`, `server/tool`, the agents and user, the `reason` and the record id. Records that are not decisions show their kind where `ALLOW`/`DENY` would be, and the details of that kind in place of the reason. Shown here with ids and times shortened:

```text
#3    2026-10-24T08:45:18Z  ALLOW github/read_file  assistant for alice  reason=policy_allow  id=9f35...
#4    2026-10-24T08:45:18Z  tool_result  github/read_file  assistant for alice  decision=9f35...  label=untrusted size=149  id=a70d...
#5    2026-10-24T08:45:18Z  DENY  github/create_issue  assistant for alice  reason=approval_required  id=b9ad...
#6    2026-10-24T08:45:18Z  approval_request  github/create_issue  assistant for alice  decision=b9ad...  approval=1388... expires=2026-10-24T08:47:18Z  id=7a41...
#7    2026-10-24T08:45:18Z  approval_grant  github/create_issue  assistant for alice  decision=b9ad...  approval=1388... outcome=grant by=operator  id=e966...
#8    2026-10-24T08:45:19Z  search  github/authzen.search  assistant for alice  evaluated=4 permitted=3  id=c2e1...
```

- `tool_result`: `decision=` is the call it answers, `label=` is `untrusted` or `trusted`, `size=` the bytes of the canonical result; ` error` follows when the upstream answered with a JSON-RPC error. The content is not stored.
- `approval_request`: `decision=` is the gated decision, `expires=` when the approval stops being usable.
- `approval_grant`: `outcome=` is `grant` or `decline`, `by=` is `user` or `operator`.
- `search`: one AuthZEN action search. `evaluated=` is how many candidate tools it evaluated, `permitted=` how many it returned. It is not a decision.
- `exchange`, `root_token`, `lease_renew`, `lease_revoke` and `admin` records already name themselves in `server/tool` (`attenuo/token.exchange`, `attenuo/admin.lease.revoke`, ...) and print as before. `audit show` prints the same first line.

### `audit show <SEQ>` / `audit show --id <UUID>`

One entry with its context, from `GET /admin/audit/entries/{seq}` or, with `--id`, `GET /admin/audit/records/{id}` (the `decision_id` that denials and AuthZEN answers return). Prints the entry line as `audit tail` does, then the record's kind, chain, policies and hashes, the state of each lease in its chain now (root first; `unknown to the lease registry` for a lease the registry does not hold), the stored checkpoint that covers the entry (or that none does yet), and whether the policy was reloaded after it. A missing entry is a 404 and a malformed id a 400 (exit 1). `--json` prints the server's `{entry, lease_states, covered_by_checkpoint, policy_reloaded_after}`. Needs the admin token.

### `audit checkpoints [--cursor CURSOR] [--limit N]`

List stored checkpoints, newest first, one line each (`seq`, time, `kid`, head hash), from `GET /admin/audit/checkpoints`. When more are older, the last line is `older: audit checkpoints --cursor <next_cursor>` (with the `--limit` you gave, if any), the command for the next page. Read-only: unlike `GET /admin/audit/checkpoint` it never signs a new checkpoint. `--limit` defaults to the server's 100, at most 1000. Needs the admin token.

### `audit verify`

Walk the whole hash chain and verify the signed checkpoints against the server's JWKS. Prints whether the chain is intact, then the checkpoint status: how many checkpoints exist, the last signed `seq`, how many entries come after it, and any invalid checkpoint with its reason. Exits 2 if the chain is broken or a checkpoint is invalid. Needs the admin token.

With `--file` it verifies an export offline instead and needs no admin token. The check is strict: it exits 2 unless every entry in the file is inside the range its header declares, the file covers that whole range, and every entry is covered by a valid checkpoint in the file.

Give `--file` more than once, oldest file first, to check the archives of earlier prunes and the retained export as one log: `attenuo audit verify --file archive-1.jsonl --file archive-2.jsonl --file retained.jsonl`. Each file is verified strictly on its own, then each pair of neighbours must link: the seqs are contiguous, the later file's first `prev_hash` is the earlier file's last entry hash, the earlier file ends at a checkpoint at its last seq that signs that hash, and an anchor in the later file's header, if present, names the earlier file's end (the hash link is what binds the files; the anchor is checked when it is there). A pair that does not link is printed as `files do NOT link: <earlier> then <later>: <reason>`, and a changed entry in any file is reported at its seq in that file's block. The command exits 0 only when every file verifies and every pair links.

The set is not required to start at genesis. When every file verifies and every pair links, the command prints where the set starts: `files link: N files hold seq F..L as one log, from genesis` (the first file starts at seq 1), `..., starting right after the prune through seq X (the archives before it are not among the files)` (the first file starts at its header's anchor), or `..., starting at seq F, not at genesis: entries before it are not covered` (a partial `audit export` with no anchor). To check the whole log, the first file must be the first archive and the line must say `from genesis`. With `--json` a single file prints its report as before; several print `{ok, from_genesis, from_anchor, first_seq, last_seq, files, links}`, where each item of `files` is that file's report with its `file` path, and `links` lists each pair that does not link (`earlier`, `later`, `reason`).

| Option | Meaning |
| --- | --- |
| `--file <PATH>` | Repeatable. An export from `audit export` or an archive from `audit prune` (JSON Lines, or the object of `audit export --format json`, format `attenuo-audit-export-v2`; older `v1` exports are refused). Re-hashes every entry, checks the links, verifies each checkpoint signature and its head hash. Fails a file that is shorter than the range in its header, one that holds entries outside it, and one with entries after its last valid checkpoint. A filtered export (`audit export --kind`, `--chain-id`, `--tool` or `--decision`) is refused with an error: its chain has gaps, so nothing shows it is complete. |
| `--jwks <PATH>` | JWKS file with the issuer keys (what `/.well-known/jwks.json` returns). Without it, the JWKS is fetched from `--server`, and the check then only shows that the files are consistent with the keys the server publishes: someone who holds the host and its key can sign a rewritten log. Pass keys you saved yourself (a copy of the JWKS taken when the server was set up) for a stronger check, and use `--checkpoints`. Without `--jwks` and with no server to reach, the command fails with an error that names the server and says to pass `--jwks`. Only with `--file`. |
| `--checkpoints <PATH>` | Checkpoints shipped off the host by `[audit.sink]`: the file sink's JSON Lines, webhook bodies one per line, or bare checkpoint lines. Each one inside the export's range must equal the export's checkpoint at that `seq` and match the entry hash there; a checkpoint signed again after it was shipped, or deleted, is a mismatch (exit 2). Two different shipped checkpoints for one `seq` and shipped copies that do not verify against the JWKS are reported too. The Python SDK (`attenuo.audit.cross_check`) and the TypeScript SDK (`crossCheck`) report the same findings, for the shipped anchors below too. Shipped checkpoints below the export's range (pruned, or in an earlier archive) are counted as `below_range` and not compared. The lines of a prune's anchor (`format` `attenuo-shipped-anchor-v1`, shipped by the same sink, `[audit.retention]`) are checked as well: each must verify against the JWKS and agree with its envelope; the anchor of the boundary right before the export's first entry must equal the anchor in the export's header (an export whose header anchor is not in the shipped file fails); and an anchor whose prune record is inside the export but whose boundary is at or past the export's start means the log was rewound to before that prune (a restored backup), reported as `REWOUND`. Anchors whose prune record lies past the export's end (an archive taken before that prune) are counted and not checked, unless their boundary lies inside the export's range: an export that holds entries a later shipped prune removed, without that prune's record, was taken before that prune or comes from a log rewound to before it, and fails with a line naming the shipped prune (check an export taken now). Shipped checkpoints above the export's end are counted and printed as `note: N shipped checkpoints are newer than this export`: for the retained export or the last file of a set, that note means the file is cut short or the log is shorter than what was shipped. An older CLI or SDK fails on a shipped file that holds an anchor line, so upgrade them before the first prune. With `--json` the report gains a `shipped` object (`in_range`, `matched`, `beyond_range`, `below_range`, `mismatches`) and a `shipped_anchors` object (`shipped`, `checked`, `matched`, `beyond_range`, `mismatches`), and the top-level `ok` covers all three checks. With several files each one is checked against the shipped file. Only with `--file`. |
| `--allow-unsigned-tail` | Accept entries after the file's last valid checkpoint, which only the hash chain covers: an export taken while the log was ahead of its newest checkpoint. They are still reported (`unsigned_tail`). Entries outside the header's range fail either way. With several files it applies to the last one only. Only with `--file`. |

To get an export that passes without the flag, sign the head first (`GET /admin/audit/checkpoint`) and export up to it, or export up to an existing checkpoint with `audit export --to`.

### `audit export`

Write entries and the checkpoints inside the range. Needs the admin token.

| Option | Default | Meaning |
| --- | --- | --- |
| `--from` | the first entry | First sequence number: 1, or after a prune (`[audit.retention]`) one above its boundary, and the export then carries the signed anchor in its header. A `--from` or `--to` at or below the boundary is refused (410 `audit_pruned`). |
| `--to` | the head | Last sequence number, inclusive. |
| `--format` | `jsonl` | `jsonl` streams one object per line (header, entries, checkpoints). `json` writes one object `{header, entries, checkpoints}`. |
| `--out` | stdout | Write to this file. A new file or an existing regular file is written to a temporary file next to it (`.<name>.partial-<pid>-<random>`), flushed to disk, and renamed to `--out` only when the server's body ended cleanly; an export the server cut short (a prune that committed while it streamed) exits 1 and leaves the old file as it was. A replaced file keeps its mode, but its owner becomes the user running the command. When `--out` is a symlink, a FIFO, a device or any other file that is not regular, or its directory is under `/dev` or `/proc` (`/dev/stdout`, `/dev/fd/N`, process substitution), the export is written to it directly, as before; a cut-short export then exits 1 with the partial text already written. |
| `--kind` | all | Keep only records of this kind: `decision`, `tool_result`, `approval_request`, `approval_grant`, `exchange`, `root_token`, `lease_renew`, `lease_revoke`, `admin` or `search`. |
| `--chain-id` | all | Keep only records of this delegation chain (the `chain_id` field: the lease id of the chain's first hop). |
| `--tool` | all | Keep only records for this tool, as on `audit tail`: an MCP tool name, or one of attenuo's own (`token.root`, `token.exchange`, `lease.renew`, `admin.*`). Exact match. |
| `--decision` | all | Keep only records with this decision: `allow` or `deny`. |

The filters combine, and apply inside `--from`/`--to`. A refused exchange or renewal is kind `decision`, not `exchange` or `lease_renew`, so `--kind` alone mixes it with every tool-call decision; `audit export --tool token.exchange --decision deny` (or `--tool lease.renew`) exports just those. A filtered export has a `filter` member in its header naming the filters it was taken with (`{"decision":"deny","tool":"token.exchange"}`) and cannot be verified with `audit verify --file` (its hash chain has gaps by construction): verify an unfiltered export, then filter. The same filters are `?kind=`, `?chain_id=`, `?tool=` and `?decision=` on `GET /admin/audit/export`; an unknown kind or decision, more than one kind, or an empty value is a 400.

### `audit prune`

Prune the start of the audit log through a checkpoint, after archiving it. The server must set `[audit.retention] prune = "manual"` (otherwise the plan is refused with `prune_disabled`). Needs the admin token.

```sh
attenuo audit prune --before 2026-08-01T00:00:00Z --archive /mnt/archive/attenuo-0001.jsonl
attenuo audit prune --through 1000000 --archive ./a.jsonl --jwks jwks.json
attenuo audit prune --before 2026-08-01T00:00:00Z --dry-run
```

The command runs these steps, and stops at the first that fails:

1. Plan: `GET /admin/audit/prune/plan?before=` (or `?through=`). The server answers the largest boundary its guards allow at or below the request. With `--dry-run` the plan is printed and the command stops. When nothing can be pruned, the plan and the guard that limited it are printed and the command exits 2.
2. Export `from..=through` to a temporary file next to `--archive` (`.<name>.partial-<pid>-<random>`), created with mode 0600 on Unix and flushed to disk. An `--archive` that exists is refused before anything is exported. The plan must name the checkpoint's hash; a plan without it is an error.
3. Verify the file strictly with the issuer keys (`--jwks`, else `/.well-known/jwks.json` from `--server`), as `audit verify --file` does, and check that it is the plan's range, that it starts where the log now starts, that its last entry is the one the plan's checkpoint signs, and, when it does not start at seq 1, that its header anchor is the server's newest anchor. A file that does not pass is removed, and the command exits 2.
4. Move the file to `--archive` (with a hard link, so a file that appeared meanwhile is never overwritten; where hard links are not supported, with `renameat2(RENAME_NOREPLACE)` on Linux, and on other systems the command stops with an error and keeps the verified temporary file), sync the directory (a directory that cannot be synced stops the command before the request), and take the SHA-256 of its bytes. The archive keeps mode 0600.
5. `POST /admin/audit/prune {"through": B, "archive_sha256": "<digest>", "from": F, "through_hash": "<hash>"}`, with the archive's first seq and its last entry hash. The server refuses (`prune_archive_mismatch`) unless `from` is the first retained seq and `through_hash` is the entry hash at `B`, so a prune can never remove entries that are not in the archive. It signs the digest into the prune anchor.
6. Check the anchor the server answers against the archive: its signature against the keys, `through_seq` and `through_hash` against the archive's last entry, `archive_sha256` against the digest, and `previous_through_seq` against the archive's header anchor (or null for an archive from seq 1). A mismatch prints `PRUNE COMMITTED, BUT THE ANCHOR DOES NOT MATCH THE ARCHIVE` with each problem and exits 2: the prune was committed, so keep the archive and the server's answer and check the log.
7. Print the prune record's seq, the anchor (boundary and hash, prune record hash, previous boundary, digest, time and key), the checkpoints before and after, whether the sink has delivered the anchor, and that the rows are being deleted in the background.

Nothing on the server changes before step 5, so a failure or a crash at any earlier step leaves the log as it was (at most a `.partial-` file is left behind, which you can delete). If step 5 fails or is refused, the archive is kept and the command says how to repeat: `attenuo audit prune --archive <PATH> --reuse-archive` verifies the file again and sends the same request (after `prune_conflict`, `prune_archive_mismatch` or `audit_pruned` it says the same request would be refused again instead). Before sending, `--reuse-archive` reads the server's newest anchor (`GET /admin/audit/anchors?limit=1`) and applies the checks of step 3 to it: the archive must start right after that anchor (or at seq 1 when there is none), and its header anchor must be that anchor. An archive the log has already been pruned past is refused with nothing sent. When the newest anchor is the archive's own prune (a repeat after a success the command did not see), its `through_hash` and `archive_sha256` must be the archive's, and the request is sent again: the server answers the same anchor with `already pruned` and writes nothing.

| Option | Meaning |
| --- | --- |
| `--before <TIME>` | Prune entries older than this RFC 3339 time, up to the newest checkpoint that is. Not with `--through`. |
| `--through <SEQ>` | Prune at most through this seq; the boundary is the newest checkpoint the guards allow at or below it. With `--reuse-archive`, it must equal the archive's last seq. |
| `--archive <PATH>` | Where to write the archive, with mode 0600 on Unix. Refused if the file exists. Required unless `--dry-run`. Keep it off the host: after the prune it is the only copy of those entries. |
| `--jwks <PATH>` | JWKS file with the issuer keys to verify the archive with. Without it, the JWKS is fetched from `--server`, which only shows that the archive is consistent with the keys the server publishes. |
| `--dry-run` | Print the plan and stop. Exports and changes nothing. |
| `--reuse-archive` | `--archive` already exists from an earlier run whose request failed: verify it again, check that it starts where the log now starts, take its digest and send the prune for its last seq. Skips the plan. Not with `--before` or `--dry-run`. |

A refusal prints `prune refused: <code>: <detail>` and exits 2. The codes are `prune_disabled`, `prune_not_at_checkpoint`, `prune_too_recent`, `prune_live_run`, `sink_behind`, `prune_in_progress`, `prune_conflict` (the same boundary was pruned with another digest), `prune_archive_mismatch` (the archive does not start at the log's first retained entry, or does not end at the entry hash at the boundary) and `audit_pruned` (the boundary is below the log's start). Any other failure exits 1, as text on stderr.

With `--json` every answer is one object on stdout with `ok`:

- success: `{ok: true, plan, archive: {path, sha256, entries, from, through}, prune}`, where `prune` is the server's answer `{prune_seq, pruned_through, anchor, checkpoint_before, checkpoint_after, deleting, shipped, already}` (`plan` is null with `--reuse-archive`);
- `--dry-run`: `{ok: true, plan}`; nothing can be pruned: `{ok: false, plan}`;
- a refusal: `{ok: false, refused: {code, detail}}`;
- an archive that does not verify or does not fit: `{ok: false, archive_problems: [...]}` (with `plan` when there was one);
- a committed prune whose anchor does not match: `{ok: false, committed: true, anchor_problems: [...], archive, prune}`.

The database file does not shrink after a prune: SQLite reuses the freed pages for new entries. See [Bounding the audit log](../guides/deploying.md#bounding-the-audit-log).

### `policy reload`

Ask the server to re-read its policy file. Needs the admin token.

### `policy show`

The policy set the server has in force (`GET /admin/policies`): the file path, the `sha256` and load time of the text it loaded, the policy ids, any validation warnings, then each policy's text. After an edit that was not reloaded, this is still the old text. Needs the admin token.

### `policy check`

Lint the policy file as it is on the server's disk now, against the running schema, without loading it (`GET /admin/policies/check`). Prints the issues as `policy lint` does (`path:line:column: severity[stage] (policy id): message`), the counts, whether the file differs from the loaded set, and whether a reload would succeed. Exit 0 when it would, 2 when the file has errors. Needs the admin token.

### `policy evaluate`

Dry run: what the loaded policies decide for one call (`POST /admin/policies/evaluate`). The capability stage and Cedar run as for a real call; the lease check does not, and nothing is audited or counted. Prints the decision and reason, the policies that decided, where the chain came from and any diagnostics. Exit 0 for allow, 2 for deny. Needs the admin token.

| Option | Meaning |
| --- | --- |
| `--token <JWT\|->` (`ATTENUO_TOKEN`) / `--token-file PATH` | The delegation token whose chain makes the call. An expired token is accepted and reported as expired. |
| `--chain-file PATH` | A delegation chain as JSON instead of a token. The server checks only its shape, so the answer says `admin supplied`. Not with `--token` or `--token-file`. |
| `--upstream` | MCP upstream name. Required. (`--server` after `policy evaluate` is a deprecated spelling.) |
| `--tool` | Tool name. Required. |
| `--arg` | Tool argument. Repeatable. |

```sh
ATTENUO_TOKEN="$CODER" attenuo policy evaluate --upstream github --tool create_issue --arg repo=acme/api
```

### `policy test <FILE>...`

Run YAML policy test files, offline by default (`--via` sends the cases to a running server instead). Exit 0 if every case passes, 2 if any fails, 1 if a file cannot be run. The format is in [Writing policies](../guides/writing-policies.md).

After the cases, the run lists the policies no case exercised: `N of M policies not exercised:` and one `file:line  id` line each, or `all M policies exercised`. A policy is exercised when it is among the policies that decided at least one evaluated case (the `policy_ids` of the result), whether that case passed or not. Test files that name the same policy file share its policies. With `--json` the output has a `coverage` object: `policies` (the total), `exercised`, and `unexercised` as `[{id, file, line}]`.

| Option | Meaning |
| --- | --- |
| `--fail-on-unexercised` | Exit 2 when some policy was not exercised, even if every case passed. Off by default. |
| `--via local\|authzen\|admin-evaluate` | Where the cases are decided. `local` (default) builds the engine from the test file and runs offline. `authzen` sends each case to `POST /access/v1/evaluation` of the server named by the global `--server`, with the token below as the bearer. `admin-evaluate` sends each case, with its own chain, to that server's admin dry run `POST /admin/policies/evaluate`, with the admin token (`ATTENUO_ADMIN_TOKEN`, `--admin-token-file`, `--admin-token-stdin` or `--admin-token`, before or after `policy test`). |
| `--token <JWT\|->` (`ATTENUO_TOKEN`) / `--token-file PATH` / `--dpop-key PATH` | With `--via authzen`: the delegation token whose chain makes every call, and its DPoP key if it is bound to one. Refused with the other arms. |
| `--schema-file PATH` | Cedar schema file replacing the built-in base schema (the entity types) for every test file, over the `[policy] schema_path` of a server config named by `catalog:`. It must still declare `User`, `Agent in [User, Agent]`, `Server` and `Tool in [Server]` with every attribute of the default, required and of the same type; otherwise the file cannot be run (exit 1) and the error says what is missing. Only with `--via local`: refused with the other arms, since the server validates with its own schema. |
| `--watch` | Run again whenever a test file, or the policy file, catalog or server config, or base schema file one of them reads, changes. The files are polled every 250 ms (no file-notification dependency); a change runs the suite once it has stayed unchanged for 200 ms. The screen is cleared before each run (not with `--json`), and a `watching N file(s)` line goes to stderr. Exit with Ctrl-C. Works with every `--via`. |

With `--via authzen` the server decides with its own policies, catalog and clock, and takes the chain from the token, so the test file's `catalog`, `unknown_tools` and `now` do not apply (a `note:` says so for `now`), and the unexercised list is computed against the test file's local `policies` file. A case that sets something the endpoint cannot carry is skipped, not failed, and the run prints why: `session`, `approval`, `budget`, `usage` or `user.authenticated_at_unix`; a `user` other than the default that differs from the token's user (subject, issuer, attributes); a `chain` whose agents differ from the token's, or whose explicit `capabilities` differ from the token hop's. The summary then reads `N passed, M failed, K skipped`, and `--json` has `skipped` per file and in total. A refused token or an unreachable server stops that file with an error (exit 1). Each evaluation is a real decision, so the server writes an audit record for every case it decides.

```sh
attenuo --server https://attenuo.internal policy test --via authzen --token-file coder.jwt policy_test.yaml
```

With `--via admin-evaluate` the server also decides with its own policies, catalog and clock, but each case's own chain is sent (`subject.properties.chain`, checked by the server for shape and against its `max_depth`, not for having been issued by it), with the case's `session`, `approval`, `usage` and `budget` as the run's state. The route checks no lease, charges nothing and writes no audit record. So every case replays as written and none is skipped. A case's `budget` goes as the dry run's `budget` block, with only the members the case sets: limits in the case's chain that match the call are checked against it by the server's own limit check (`budget_exhausted` when spent, unlike offline, where `budget` only sets `context.budget`), and with no such limit Cedar sees the figures as given, as offline. The chain is stamped at the current time, because the server validates it at its own clock; an explicit `user.authenticated_at_unix` moves with it, keeping its distance from the file's `now`, and a `note:` says that `now` is not sent. A case without `session` or `usage` is sent as an untainted run with no usage, so nothing is read from the server's store. A case the server refuses with 400 (a chain deeper than its `max_depth`, an approval `by` other than `user`, `operator` or `policy`, a negative `budget` figure) is that case's error, reported as failed; any other refusal (a wrong admin token, a server without the route) or an unreachable server stops that file (exit 1). The unexercised list is computed against the test file's local `policies` file, as with `authzen`.

```sh
# --admin-server: the admin API's address, for a server that sets [admin] listen
attenuo --admin-server http://127.0.0.1:9102 --admin-token-file /run/secrets/attenuo-admin \
  policy test --via admin-evaluate config/policies/default_test.yaml
```

### `policy lint <POLICY>`

Parse a Cedar policy file and validate it against the generated schema. Prints errors with line and column. Exit 0 if clean, 2 if there are errors.

With `--config`, it also reads the config's `[[root_grants]]` capabilities and prints `<config>: warning: [[root_grants]] ...` for each `prefix` constraint on an argument that looks like a file path, recommending `path_prefix` ([why](../concepts/capabilities-and-attenuation.md#prefixes-of-strings-and-of-paths)). These warnings do not change the exit code; `--json` lists them under `capability_warnings`. It does not run the server's start-up checks on `[[root_grants]]` (the reserved agent id, a capability that does not parse, a server or tool name that is not allowed, the size bounds, limits no token may carry): a configuration that passes `policy lint` can still refuse to start, and the server's message names the entry.

| Option | Meaning |
| --- | --- |
| `--config` | Server config whose `[policy.catalog]` declares the tools, or a JSON catalog. Without it, the tools are declared from the policy's own `<server>/<tool>` action names and a `note:` lists what could not be checked (tool attributes, input types, user attributes). |
| `--schema-file PATH` | Cedar schema file replacing the built-in base schema, over the config's `[policy] schema_path`. Checked as the server checks it at start: a file without the required entity types, attributes or hierarchy is an error (exit 1). |
| `--schema` | Also print the generated schema. |

### `approval list` / `show` / `grant` / `decline` / `verify`

Approvals of gated calls, as the operator (admin token, `ATTENUO_ADMIN_TOKEN`).

| Command | Does |
| --- | --- |
| `approval list [--chain-id ID] [--state pending\|granted\|declined\|consumed] [--limit N] [--cursor CURSOR \| --all]` | `GET /admin/approvals`: one line per approval, newest first (id, state, call, run, expiry). One page (`--limit` 1 to 500, server default 100); when more exist the last line is `more: approval list ... --cursor <next_cursor>, or --all`, the command for the next page with the filters and `--limit` you gave. `--all` follows the cursor and lists every match (`--json` then prints `{approvals, next_cursor: null}` with all of them). |
| `approval show <ID>` | `GET /admin/approvals/{id}`: the exact call with its arguments, the call hash, user, agents, run and lease, the labels the run carried with their audit seqs, the times, and who decided. |
| `approval grant <ID>` | `POST /admin/approvals/{id}` with `grant`. The agent's identical retry then runs once. Recorded as `by = "operator"`. |
| `approval decline <ID>` | The same with `decline`. |
| `approval verify <TOKEN> [--jwks URL\|PATH] [--issuer S] [--audience S] [--chain-id ID] [--lease ID] [--call-hash HEX] [--jkt JKT\|none]` | Offline: verifies a signed approval token (`typ: attenuo-approval+jwt`) against the issuer's JWKS (an `http(s)` URL, a file, or `<server>/.well-known/jwks.json` by default): signature, `typ`, `iss` and `aud` (default: the token's own), `exp`, and each binding given (`--jkt none` for a bearer hop). Prints the claims and `VALID` or `INVALID: <reason>`, exit 0 or 2; `--json` prints `{header, claims, valid, error}`. `-` reads the token from stdin. It proves the grant was made, not that it is unused. |

The grant's answer (and `approval show` while the approval is granted) carries `approval_token`, which an agent may send with its retry instead of relying on the identical-call lookup ([HTTP API](http-api.md#approval-tokens)).

A grant or decline of an approval that is no longer pending fails with `approval_not_pending`, `approval_expired` or `lease_revoked`. `--json` prints the server's answer. A user approves with their own ID token at `POST /approvals/{id}`; the CLI does not do that for them.

### `authzen eval`

Ask the decision endpoint whether the token's chain may make a call, without making it.

| Option | Default | Meaning |
| --- | --- | --- |
| `--token <JWT\|->` (`ATTENUO_TOKEN`) | | Delegation token, sent as the bearer; `-` reads it from stdin. Or `--token-file PATH`. |
| `--dpop-key PATH` (`ATTENUO_DPOP_KEY`) | | The DPoP key a bound token needs. |
| `--upstream` | `github` | MCP upstream name. (`--server` after `authzen eval` is a deprecated spelling.) |
| `--tool` | | Tool name. Required. |
| `--arg` | | Tool argument. Repeatable. |

### `authzen search`

List the tools of one MCP upstream that the token's chain may call with these arguments, without calling them: AuthZEN action search, `POST /access/v1/search/action` ([AuthZEN conformance](authzen.md#action-search)). The candidates are the tools the server's `[policy] catalog` lists for the upstream that the token's capabilities name. A search writes one `search` audit record, charges no run limit and takes no approval, so an approval-gated tool is never listed.

| Option | Default | Meaning |
| --- | --- | --- |
| `--token <JWT\|->` (`ATTENUO_TOKEN`) | | Delegation token, sent as the bearer; `-` reads it from stdin. Or `--token-file PATH`. |
| `--dpop-key PATH` (`ATTENUO_DPOP_KEY`) | | The DPoP key a bound token needs. |
| `--upstream` | `github` | MCP upstream name. |
| `--arg` | | Argument every candidate is decided with, as `context.input`. Repeatable. |
| `--limit N` | the server's `[authzen] max_batch` | How many catalogued tools one page evaluates (at least 1; a larger value is clamped by the server). A page can list fewer tools, even none, while more pages remain. |
| `--page-token TOKEN` | | Ask for the page after the one that printed this token, with the same delegation token, server and arguments (`--limit` may change); otherwise 400 `invalid_cursor`. |
| `--all` | | Follow the pages to the last one and print every result. Not with `--page-token`. |

It prints one `<upstream>/<tool>` per line, then `next page: --page-token <token>` while more pages remain; `--json` prints `{"page": {"next_token", "count"}, "results"}` in the server's shape, with every page's results under `--all`. The exit status is 0 whether or not a tool is listed; a refused request (a bad token, `--upstream` naming one tool, a token the server did not issue) is 1.

```sh
attenuo authzen search --upstream github --arg repo=alice/public-docs --all
```

### `stdio-bridge --listen ADDR -- <COMMAND>...`

Run a local STDIO MCP server as a child process and serve it as a Streamable HTTP MCP endpoint at `http://ADDR/mcp`, so that it can be an [`[[upstreams]]`](config.md#upstreams) entry of the proxy. The guide is [STDIO MCP servers](../guides/stdio-servers.md). Everything after `--` is the command and its arguments. The child inherits the bridge's environment, minus every variable whose name starts with `ATTENUO_` (the CLI's and the server's secrets, and the `ATTENUO__*` configuration overrides). Its stderr goes to the bridge's stderr. Once bound, the bridge prints `listening on http://ADDR/mcp` on stdout.

| Option | Default | Meaning |
| --- | --- | --- |
| `--listen ADDR` | | IP address and port to serve on, for example `127.0.0.1:3001`. Port 0 picks a free one. Required. |
| `--allow-non-loopback` | off | Accept a `--listen` address that is not loopback. Without it such an address is refused (exit 1). The bridge does not authenticate its callers: anyone who can reach it calls the STDIO server without attenuo. |
| `--timeout SECS` | `90` | How long a request waits for the child's answer (1 to 3600). Past it the caller gets HTTP 504 and a JSON-RPC error `-32603` with its own id. A late answer is dropped. Keep it below the proxy's `upstream_response_timeout_seconds` (120 by default), so the bridge answers before the proxy gives up. |
| `--max-request-bytes BYTES` | `4194304` (4 MiB) | Largest HTTP request body. A larger one is HTTP 413 and is not sent to the child. |
| `--max-line-bytes BYTES` | `16777216` (16 MiB) | Longest line read from the child's stdout. A longer line is dropped with one line on stderr, and the request it answered times out. |
| `--verbose` | off | One line on stderr for each message of the child the bridge drops or answers itself. |

What the bridge does with each message:

- A `POST` with a request is written to the child as one line, with its `id` replaced by a number unique to the bridge, and answered with the child's response (`200`, `application/json`) with the caller's `id` put back. Two callers that use the same id each get their own answer.
- A `POST` with a notification is written to the child and answered `202` with no body. A `POST` with a response is answered `202` and dropped, because the bridge never passes the child's own requests on.
- A batch (a JSON array) is refused with `400` and JSON-RPC `-32600`. So is a request whose `id` is not a string or a number. A body that is not JSON is `400` and `-32700`. A `Content-Type` other than `application/json` is `415`. A request with an `Origin` header is `403`: the proxy never sends one, and a browser always does.
- `GET` and `DELETE` on the endpoint are `405`. There is no server-to-client stream and no `Mcp-Session-Id`: the child is one MCP session.
- `initialize` is sent to the child once. A later `initialize` gets the child's first answer, with its own id, and is not sent on. Only the first `notifications/initialized` reaches the child.
- The child's notifications (progress, log messages) are dropped. Its requests (sampling, elicitation, roots, ping) are answered at once with JSON-RPC `-32601`. A line that is not a JSON-RPC message is dropped. On exit the bridge prints how many of each it dropped.

The child's arguments and environment are never printed; error messages name only the program. Exit status: 0 after SIGINT, SIGTERM, SIGHUP or SIGQUIT; 1 when the child cannot be started, or exits or closes its stdout (the bridge does not restart it), or `--listen` is refused or in use. On the way out the bridge closes the child's stdin, waits up to 2 seconds for it to exit, then kills it. Then the processes the child started are stopped too: the child runs in a process group of its own, and what is left of the group gets SIGTERM, up to 2 seconds, then SIGKILL (SR-135). A process that left the group is not reached. Stopping can so take up to about 4 seconds. The child is not in the terminal's foreground group, so it cannot read from the terminal. On Windows only the child is killed.

```sh
attenuo stdio-bridge --listen 127.0.0.1:3001 -- npx -y @modelcontextprotocol/server-filesystem /srv/docs
```

### `connect --upstream NAME`

A STDIO front for desktop MCP clients (Claude Desktop, Claude Code, Cursor), which start a local MCP server as a command and talk to it over STDIO. The client starts `attenuo connect` in place of the MCP server. It reads MCP messages from stdin, one JSON-RPC message per line, sends each one to the proxy at `<--server>/mcp/<NAME>` as a Streamable HTTP `POST` with a fresh delegation token as the bearer, and writes what comes back to stdout, one message per line. It decides nothing and adds no authority: it sends the token it was given, and only to `--server`. The guide, with the configuration for each client, is [Desktop clients](../guides/integrating-mcp-clients.md#desktop-clients-claude-desktop-claude-code-cursor).

```sh
attenuo --server http://127.0.0.1:8080 connect --upstream github --token-command '/usr/local/bin/get-attenuo-token alice'
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--upstream NAME` | | The upstream name, as mounted at `/mcp/NAME`. Required. |
| `--token-command CMD` | | A program and its arguments, as one string, that prints a delegation token on the first line of its stdout. See below. |
| `--token-file PATH` | | Read the token from the first line of this file, and read it again whenever a new token is needed. Something else keeps the file fresh. |
| `--token-command-timeout SECS` | `60` | How long the token command may run (1 to 600). Past it, it is killed and counts as failed. Only with `--token-command`. |
| `--timeout SECS` | `300` | How long one request may take, its answer included, also a streamed one (1 to 86400). Past it the client gets a JSON-RPC error with the request's id. |
| `--max-message-bytes BYTES` | `16777216` (16 MiB) | Largest single message: a line from stdin, a JSON answer, or one event of a streamed answer. |
| `--max-stream-bytes BYTES` | `67108864` (64 MiB) | Most bytes read from the streamed (SSE) answer to one request, all its events together. |
| `--max-in-flight N` | `64` | Most requests waiting for an answer at once (1 to 4096). A request over the limit gets a JSON-RPC error at once and is not sent. |

**The token.** It comes from exactly one place: `--token-command`, `--token-file`, or, with neither, the `ATTENUO_TOKEN` environment variable. `--token-command` and `--token-file` cannot be given together.

- `--token-command` is split into words the way a shell splits a command line: spaces separate words, `'...'` keeps its text as it is, `"..."` keeps its text except that `\"`, `\\`, `\$` and a backslash before a backtick stand for the character, and a backslash outside quotes keeps the next character. No shell runs it, so there are no variables, globs, pipes or redirections. For those, give a script, or `sh -c '...'`. A first word of the form `NAME=value` (a shell habit) is refused, since no shell would read it: use `env NAME=value CMD ...`, a wrapper script, or the client's `env` setting. On Windows, the backslash is an escape here too, so write paths with forward slashes (`C:/Tools/get-token.exe`) or put them in single quotes. The command runs at start and again whenever a new token is needed. It gets this process's environment, an empty stdin (stdin carries MCP), and its stderr goes to this process's stderr. Exit status other than 0, a timeout, or an empty first line is a failure. On Unix it runs in a process group of its own, and on a timeout the whole group is killed, so a process it started does not stay behind.
- `ATTENUO_TOKEN` is used as it is and never replaced. When it expires, the connector says so once on stderr and answers every request with a JSON-RPC error without sending it.
- A token that has already expired at start, or expires within 5 seconds, is refused (exit 1), from every source.
- A token must be visible ASCII and at most 16 KiB. A token bound to a DPoP key (`cnf.jkt`) gets a warning: the connector sends no DPoP proofs, so the proxy refuses it.

**Keeping the token fresh.** The connector reads the token's `exp` without checking the signature. It gets a new token when two thirds of the token's lifetime have passed (and never sooner than a second after the last one), and at once when the proxy answers 401. The request that got the 401 is then sent once more with the new token, and only once; a second 401 is passed to the client. A token whose `exp` cannot be read (not an attenuo token) is replaced only on a 401. Only one fetch runs at a time. A fetch fails when the command or the file fails, and also when it gives the same token again, or a token that has expired or expires within 5 seconds. After a failure the next fetch waits 1, 2, 4, ... seconds, at most 30, and the count starts again only after a fetch that works. Requests that need a new token while a fetch runs wait for it and use its token. When it failed, or the pause after the last failure has not passed, they get that failure without a new fetch, so an interactive helper is not started once per request.

**Renewing the lease.** In the background, `POST /token/renew` with the current token: once when a token is new, then at a third of the `expires_in` the answer gives, at most once a second. The server's renewal repairs the token's own lease when it has lapsed, so `lease_expired` comes only from an ancestor's lease, and `lease_unknown` from a lease the server does not know. Either one, or a 401, gets a new token (with a new lease) from `--token-command` or `--token-file`, after 1, 2, 4, ... seconds. With `ATTENUO_TOKEN`, renewal stops instead. Any other failure is tried again after 1, 2, 4, ... seconds, at most 30. A new token does not reset that pause; a renewal that works does.

**A revoked lease.** `lease_revoked` is final, wherever it is seen: the answer to a renewal, a 401 or a JSON-RPC error to a request (`error.data.reason`), or the listen stream. The connector fetches no new token from then on, not even on a 401, and sends nothing more. The request that saw it gets the proxy's answer. Every other request in flight gets a JSON-RPC error `-32603` with `error.data.reason` `lease_revoked`. stderr says so in one line, and the connector exits with status 3, so that the client shows the server as stopped instead of one that fails every call. Restart it with a new token to start again.

What happens to each line from stdin:

- A request is sent with `Accept: application/json, text/event-stream`, `Content-Type: application/json`, the bearer, and, after `initialize`, the `Mcp-Session-Id` the proxy returned and the negotiated `Mcp-Protocol-Version`. Requests may be in flight together. `initialize` and notifications are sent in the order they are read, and the next line is read when they are done.
- A JSON answer is written as one line. An SSE answer is written one message per line, in order, the upstream's notifications and requests in it too, up to the answer to the request. `202` with no body writes nothing for a notification.
- A notification or a response from the client is never answered on stdout. When the proxy refuses one (a bad token, a lost session, a `4xx` with a JSON-RPC error), stderr says so and nothing is written. Requests and notifications from the server in the same answer are still written.
- `notifications/cancelled` stops the local work for the request it names and frees its place under `--max-in-flight`. That request gets no answer. The notification is sent to the proxy too.
- A request whose id is the id of a request still in flight gets `-32600`.
- The proxy's own JSON-RPC errors (a denial, `-32003`, or `-32001` on a bad token) are passed on as they came. When one has `"id": null`, because the proxy refused the request before it read it, the request's id is put in, so that the client can match it.
- A request that cannot be answered gets a JSON-RPC error `-32603` with its id, a message that starts with `attenuo connect:`, and `error.data.reason`: `unreachable`, `timeout` or `transport` (the network), `http_status` (an HTTP error without a JSON-RPC body), `redirect`, `not_jsonrpc`, `no_answer` (`202` for a request), `too_large`, `no_token`, `too_many_in_flight`, or `session_ended`. A notification or response that cannot be delivered is only logged.
- A line that is not JSON gets `-32700` with `"id": null`. A JSON array (a batch) gets `-32600` with `"id": null`: MCP 2025-06-18 removed batching. A line over `--max-message-bytes` gets `-32600` with `"id": null`. An empty line is skipped.
- A `404` to a request that carried the session id means the proxy no longer knows the session (it ended, or the proxy restarted). A desktop client does not send `initialize` again to a process that is still running, so the connector does it: it keeps the client's `initialize` and `notifications/initialized`, sends them again once to open a new session (the answer is not written to stdout), sends the request once more, and opens the listen stream again on the new session. stderr says so in one line. When the new session cannot be opened, that request gets `-32603` with `session_ended`, and the next request tries again; there is no loop. When the request gets a `404` on the new session too, the client gets the proxy's error.
- No redirect is followed. A `3xx` answer is a JSON-RPC error, and nothing is sent to its `Location`.

**The listen stream.** After `notifications/initialized` is accepted, the connector opens `GET` on the endpoint for messages from the server. Its headers must come within 30 seconds; the stream itself may then stay quiet for as long as it likes. A `405` (the upstream has none) ends it quietly. A `404` ends it until the next request opens a new session. The requests and notifications it carries are written to stdout; responses on it (the proxy's end-of-stream error) are not, since they answer nothing the client sent. When it ends it is opened again after 1, 2, 4, ... seconds (at most 30), with `Last-Event-ID` when the stream gave event ids.

**The end.** At end of stdin, or on SIGINT, SIGTERM, SIGHUP or SIGQUIT, the connector stops reading, gives the requests in flight 5 seconds to finish, sends `DELETE` with the session id, and exits 0. A signal is seen even while a line is being handled (an `initialize` that waits, a write to stdout that waits). When the last lines cannot be written within a second, because the client does not read stdout, the connector exits without them. Exit status 3 after `lease_revoked` (see above). Exit status 1 when no token can be had at start (the token command fails, the file is missing or empty, `ATTENUO_TOKEN` is unset, the token has expired), or `--server`, `--upstream` or `--token-command` is not valid. That happens before stdin is read and nothing is written to stdout. `--server` must be an `http://` or `https://` URL without a user name, password, query or fragment. With `http://` to a host that is not loopback, stderr gets a warning at start: the token then travels in cleartext for as long as the connector runs. `--admin-token-stdin` cannot be used with `connect`, since stdin carries MCP.

**What is logged.** stdout carries MCP messages only. On stderr: where it forwards to, each new token's source and how long it lives, failures of renewals and of token fetches, requests that got no answer (by method), notifications and responses that could not be delivered, a lost session and the new one, a revoked lease, and how many requests were dropped at the end. The token, the token command's arguments and the content of messages are never logged; the token command is named by its program only. Strings from the server's error bodies are logged with control characters escaped.

Tested in `crates/attenuo-cli/tests/connect.rs`, which runs the binary in front of a real attenuo server (configured by `attenuo init`) and a fake MCP server, in front of a canned HTTP server for answers the proxy rarely gives, and in front of a fake upstream that forgets its sessions. The tests cover the handshake, allowed and denied calls, concurrent requests, JSON and SSE answers, the listen stream's first opening and a `405`, a refused token replaced from `--token-command` and from `--token-file`, a token command that fails at start, one that times out (its child is gone too) and one that starts with `NAME=value`, an expired token at start from each source, a command that keeps giving expired tokens (tried after 1, 2, 4 s, not in a loop), an unchanged token file with a `lease_unknown` renewal (no loop), five refused requests sharing one failing fetch, renewal (counted in the audit log), a revoked lease seen by the renewal, by a request and with another request in flight (exit 3, no new token), a lost session opened again (and the listen stream with it), a new session that cannot be opened, a cancelled request, notifications and responses that the proxy refuses (nothing on stdout), the `http_status`, `redirect`, `no_answer`, `too_large` and `too_many_in_flight` errors, the cleartext warning, and the end at end of stdin, on SIGTERM, and on SIGTERM while stdout is not read. Not run by the tests: SIGINT, the `unreachable`, `timeout`, `transport` and `not_jsonrpc` errors, `lease_revoked` on the listen stream, and Windows. The token schedule, the checks on a fetched token, the sorting of renewal answers and the arithmetic on an unverified `exp` are unit tests in `src/connect.rs`.
