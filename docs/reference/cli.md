# CLI commands

The `attenuo` binary comes from the `attenuo-cli` crate. It talks to a running attenuo server over HTTP, except for `policy test` and `policy lint`, which run offline.

```
attenuo [--server URL] [--json] <command>
```

## Global options

| Option | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--server`, `--url` | `ATTENUO_SERVER` | `http://127.0.0.1:8080` | Base URL of the attenuo server. Goes before the subcommand. |
| `--admin-token-stdin` | | off | Read the admin token from the first line of standard input. |
| `--admin-token-file PATH` | | none | Read the admin token from the first line of a file. |
| `--admin-token TOKEN` | `ATTENUO_ADMIN_TOKEN` | none | Bearer for `/admin/*`. Prefer the environment variable, stdin or a file: an argument is readable by other local users (`ps`, `/proc/<pid>/cmdline`) and lands in shell history, so the CLI prints a warning to stderr when it is used. |
| `--json` | | off | Print machine-readable JSON instead of text. Works after any subcommand. |

The `--server` flag of `call`, `tools` and `authzen eval` is different. It names the MCP upstream, for example `github`.

## Secrets

Secrets are never taken from the argument list by default. That covers the admin token, the agent client secret and the delegation tokens (`--token`, `--subject-token`). For each, the CLI accepts, in this order of preference: the environment variable, `--…-file PATH`, stdin, and (with a one-line warning on stderr) the flag itself. Stdin is `--admin-token-stdin` / `--client-secret-stdin` for the first two, and the value `-` for the tokens (`--token -`, `--subject-token -`). A value from a file or stdin is the first line, without the line ending. At most one value can come from stdin per invocation. The flag, file and stdin forms are mutually exclusive on the command line; any of them overrides the environment variable.

| Secret | Environment | File | Stdin |
| --- | --- | --- | --- |
| Admin token | `ATTENUO_ADMIN_TOKEN` | `--admin-token-file` | `--admin-token-stdin` |
| Client secret | `ATTENUO_CLIENT_SECRET` | `--client-secret-file` | `--client-secret-stdin` |
| Delegation token (`call`, `tools`, `authzen eval`) | `ATTENUO_TOKEN` | `--token-file` | `--token -` |
| Parent token (`token exchange`) | `ATTENUO_TOKEN` | `--subject-token-file` | `--subject-token -` |

```sh
export ATTENUO_ADMIN_TOKEN=$(cat /run/secrets/attenuo-admin)
printf '%s\n' "$CODER_SECRET" | ATTENUO_TOKEN="$ROOT" attenuo token exchange --actor coder --client-secret-stdin --cap github:read_file
attenuo --admin-token-file /run/secrets/attenuo-admin lease show "$LEASE"
printf '%s\n' "$CODER" | attenuo call --token - --server github --tool read_file --arg repo=acme/api
```

`token inspect -` also reads a token from stdin.

## Argument forms

- `--cap server:tool` is a capability. Globs are allowed. Repeat the flag, or comma-separate plain values. A value that starts with `{` is a full capability as JSON, which can carry constraints.
- `--arg key=value` sets a string argument. `--arg key:=json` sets any JSON value, such as a number or an object.
- `--attr key=value` follows the same rule for user attributes.

## Commands

### `token root`

Mint a root (hop 0) token. This uses the development endpoint, so it needs the admin token and `[dev] allow_root_mint = true` on the server.

| Option | Meaning |
| --- | --- |
| `--subject` | The user the agent acts for. Required. |
| `--issuer` | Issuer of the user's identity. Default `https://idp.example`. |
| `--agent` | The root agent. Required. |
| `--cap` | Capability to request. Omit to take the `[[root_grants]]` ceiling. |
| `--ttl-seconds` | Requested lifetime. |
| `--attr` | User attribute. Repeatable. |
| `--may-act <AGENT>` | Only this agent may exchange the root token (RFC 8693 `may_act`). Repeatable, or comma-separated. Must be within the `[[root_grants]]` entry's `may_act` when it has one; without the flag the grant's `may_act` applies. |
| `--dpop-key PATH` | Bind the root token to this DPoP key (a private JWK from `key gen --dpop`). |
| `--print token\|lease` | Print only that value, for scripts. |

### `token exchange`

RFC 8693 exchange: delegate a subset of a token's capabilities to a sub-agent.

| Option | Meaning |
| --- | --- |
| `--subject-token-file PATH` | Read the parent token from the first line of a file. |
| `--subject-token <JWT\|->` (`ATTENUO_TOKEN`) | The parent token; `-` reads it from stdin. One of the flag, the file or `ATTENUO_TOKEN` is required. The flag with a literal token prints a warning. |
| `--actor` | The sub-agent that will hold the new token. Required. |
| `--client-secret-stdin` | Read the agent's client secret from the first line of standard input. |
| `--client-secret-file PATH` | Read it from the first line of a file. |
| `--client-secret` (`ATTENUO_CLIENT_SECRET`) | The agent's client secret, required when the server has `require_actor_auth` (the default). Prefer the environment variable, stdin or a file; the flag prints a warning. |
| `--client-id` | Client id to authenticate with. Defaults to `--actor`. |
| `--cap` | Capability to hand over. Required, repeatable. Must be covered by the parent. |
| `--ttl-seconds` | Requested lifetime, clamped to the parent's expiry. |
| `--actor-token <JWT\|->` | Authenticate `--actor` with an RFC 8693 actor token, such as a SPIFFE JWT-SVID from an `[[actor_trust]]` issuer, instead of a client secret. `-` reads it from stdin. Each token works for one exchange. |
| `--actor-token-file <PATH>` | Read the actor token from a file, for example the JWT-SVID a SPIFFE helper writes. Cannot be combined with `--actor-token`. |
| `--may-act <AGENT>` | Only this agent may exchange the new token (RFC 8693 `may_act`). Repeatable, or comma-separated. |
| `--dpop-key PATH` | Bind the new token to this DPoP key. Required when the parent is bound. When the parent is bound to the same key, the proof also covers the parent. |
| `--subject-token-dpop-file PATH` | The parent holder's sign-off (`subject_token_dpop`), made with `token sign-off` for this exchange's `--dpop-key` and `--actor`. Required when the parent is bound to a key other than `--dpop-key`. |
| `--subject-dpop-key PATH` | Instead of `--subject-token-dpop-file`, when this process may hold the parent's key too: the sign-off is made here. Cannot be combined with `--subject-token-dpop-file`. |
| `--print token\|lease` | Print only that value. |

```sh
ATTENUO_TOKEN="$PARENT" attenuo token exchange --actor coder \
  --cap github:read_file --actor-token-file /run/spiffe/coder.jwt --may-act reviewer
```

### `token sign-off`

Made by the holder of a bound parent token, to consent to one exchange that binds the child to another key. Prints a proof by `--dpop-key` (the parent's key) for `POST` to the server's `/token`, with `ath` of the parent token and the claims `child_jkt` and `child_actor`; with `--json`, `{"subject_token_dpop": ...}`. The server accepts it only for an exchange whose `DPoP` key and `actor` are the ones it names, within `[token] dpop_max_age_seconds`, once. Hand it to the sub-agent, which passes it with `--subject-token-dpop-file`; the parent's key stays with the parent.

| Option | Meaning |
| --- | --- |
| `--subject-token <JWT\|->` / `--subject-token-file PATH` | The parent token. Defaults to `ATTENUO_TOKEN`. |
| `--dpop-key PATH` | The key the parent token is bound to. Required; refused if it is not that key. |
| `--child-jkt JKT` | Thumbprint of the sub-agent's key (`key gen --dpop` prints it). Required. |
| `--actor AGENT` | The sub-agent that will make the exchange. Required. |

```sh
attenuo token sign-off --subject-token "$ROOT" --dpop-key assistant.jwk \
  --child-jkt "$CODER_JKT" --actor coder > sign-off.txt
```

### `key gen --dpop <PATH>`

Write a new Ed25519 DPoP key (RFC 9449) to `PATH` as a private JWK, mode 0600, and print its thumbprint (`jkt`, what a bound token's `cnf.jkt` will be). An existing file is never overwritten (exit code 1). Pass the file to `--dpop-key`; the Python and TypeScript SDKs read the same format. See [Binding tokens to keys](../guides/binding-tokens-to-keys.md).

```console
$ attenuo key gen --dpop coder.jwk
wrote DPoP key coder.jwk (EdDSA)
jkt  4MMDxQj9pafXPrWH6dxBeoSk2DpHFpEZvXvsmr6JibU
```

### `token inspect <JWT>`

Decode a token and show its delegation chain as a tree. Use `-` to read the token from stdin.

| Option | Meaning |
| --- | --- |
| `--verify` | Fetch the server JWKS and verify signature, issuer, audience and chain. |
| `--issuer` | With `--verify`: expected issuer. Default: the token's own. |
| `--audience` | With `--verify`: expected audience. Default: the token's own. |

For a bound token the text output adds `bound to DPoP key jkt <thumbprint>`.

### `call`

Call a tool through the proxy (`tools/call`).

| Option | Meaning |
| --- | --- |
| `--token <JWT\|->` (`ATTENUO_TOKEN`) | Delegation token; `-` reads it from stdin. One of the flag, `--token-file` or `ATTENUO_TOKEN` is required. The flag with a literal token prints a warning. |
| `--token-file PATH` | Read the delegation token from the first line of a file. |
| `--dpop-key PATH` (`ATTENUO_DPOP_KEY`) | The DPoP key the token is bound to. Every request then carries a proof and `Authorization: DPoP`. Against a server with `[token] dpop_nonce = "required"` the CLI keeps the `DPoP-Nonce` the server sent, puts it in the proof, and sends a request once more when the server answers `use_dpop_nonce` (RFC 9449 §8); nonces are never printed or logged. Also on `tools` and `authzen eval`, and on `token root` and `token exchange`. |
| `--server`, `--upstream` | MCP upstream name. Required. |
| `--tool` | Tool name. Required. |
| `--arg` | Tool argument. Repeatable. |

### `tools`

List the tools the token may see (`tools/list`). Takes `--token` (or `--token-file`, or `ATTENUO_TOKEN`) and `--server`.

### `lease revoke <ID> [--reason TEXT]`

Revoke a lease and every lease delegated from it. Needs the admin token.

### `lease show <ID>`

Show a lease's state. Needs the admin token.

### `audit tail`

Show the most recent audit entries. Needs the admin token.

| Option | Default | Meaning |
| --- | --- | --- |
| `-n`, `--lines` | 20 | How many entries. |
| `-f`, `--follow` | off | Keep polling for new entries. |
| `--interval-ms` | 1000 | Polling interval with `--follow`. |

### `audit verify`

Walk the whole hash chain and verify the signed checkpoints against the server's JWKS. Prints whether the chain is intact, then the checkpoint status: how many checkpoints exist, the last signed `seq`, how many entries come after it, and any invalid checkpoint with its reason. Exits 2 if the chain is broken or a checkpoint is invalid. Needs the admin token.

With `--file` it verifies an export offline instead and needs no admin token. The check is strict: it exits 2 unless every entry in the file is inside the range its header declares, the file covers that whole range, and every entry is covered by a valid checkpoint in the file.

| Option | Meaning |
| --- | --- |
| `--file <PATH>` | An export from `audit export` (JSON Lines, or the `--format json` object, format `attenuo-audit-export-v2`; older `v1` exports are refused). Re-hashes every entry, checks the links, verifies each checkpoint signature and its head hash. Fails a file that is shorter than the range in its header, one that holds entries outside it, and one with entries after its last valid checkpoint. A filtered export (`audit export --kind` or `--chain-id`) is refused with an error: its chain has gaps, so nothing shows it is complete. |
| `--jwks <PATH>` | JWKS file with the issuer keys (what `/.well-known/jwks.json` returns). Without it, the JWKS is fetched from `--server`. Only with `--file`. |
| `--checkpoints <PATH>` | Checkpoints shipped off the host by `[audit.sink]`: the file sink's JSON Lines, webhook bodies one per line, or bare checkpoint lines. Each one inside the export's range must equal the export's checkpoint at that `seq` and match the entry hash there; a checkpoint signed again after it was shipped, or deleted, is a mismatch (exit 2). Two different shipped checkpoints for one `seq` and shipped copies that do not verify against the JWKS are reported too. The Python SDK (`attenuo.audit.cross_check`) and the TypeScript SDK (`crossCheck`) report the same findings. With `--json` the report gains a `shipped` object (`in_range`, `matched`, `beyond_range`, `mismatches`) and the top-level `ok` covers both checks. Only with `--file`. |
| `--allow-unsigned-tail` | Accept entries after the file's last valid checkpoint, which only the hash chain covers: an export taken while the log was ahead of its newest checkpoint. They are still reported (`unsigned_tail`). Entries outside the header's range fail either way. Only with `--file`. |

To get an export that passes without the flag, sign the head first (`GET /admin/audit/checkpoint`) and export up to it, or export up to an existing checkpoint with `--to`.

### `audit export`

Write entries and the checkpoints inside the range. Needs the admin token.

| Option | Default | Meaning |
| --- | --- | --- |
| `--from` | 1 | First sequence number. |
| `--to` | the head | Last sequence number, inclusive. |
| `--format` | `jsonl` | `jsonl` streams one object per line (header, entries, checkpoints). `json` writes one object `{header, entries, checkpoints}`. |
| `--out` | stdout | Write to this file. |
| `--kind` | all | Keep only records of this kind: `decision`, `exchange`, `root_token`, `lease_renew`, `lease_revoke` or `admin`. |
| `--chain-id` | all | Keep only records of this delegation chain (the `chain_id` field: the lease id of the chain's first hop). |

`--kind` and `--chain-id` combine, and apply inside `--from`/`--to`. A filtered export has a `filter` member in its header and cannot be verified with `audit verify --file` (its hash chain has gaps by construction): verify an unfiltered export, then filter. The same filters are `?kind=` and `?chain_id=` on `GET /admin/audit/export`; an unknown kind or an empty `chain_id` is a 400.

### `policy reload`

Ask the server to re-read its policy file. Needs the admin token.

### `policy test <FILE>...`

Run YAML policy test files offline. Exit 0 if every case passes, 2 if any fails, 1 if a file cannot be run. The format is in [Writing policies](../guides/writing-policies.md).

### `policy lint <POLICY>`

Parse a Cedar policy file and validate it against the generated schema. Prints errors with line and column. Exit 0 if clean, 2 if there are errors.

| Option | Meaning |
| --- | --- |
| `--config` | Server config whose `[policy.catalog]` declares the tools, or a JSON catalog. Without it, the tools are declared from the policy's own `<server>/<tool>` action names and a `note:` lists what could not be checked (tool attributes, input types, user attributes). |
| `--schema` | Also print the generated schema. |

### `authzen eval`

Ask the decision endpoint whether the token's chain may make a call, without making it.

| Option | Default | Meaning |
| --- | --- | --- |
| `--token <JWT\|->` (`ATTENUO_TOKEN`) | | Delegation token, sent as the bearer; `-` reads it from stdin. Or `--token-file PATH`. |
| `--dpop-key PATH` (`ATTENUO_DPOP_KEY`) | | The DPoP key a bound token needs. |
| `--server` | `github` | MCP server name. |
| `--tool` | | Tool name. Required. |
| `--arg` | | Tool argument. Repeatable. |
