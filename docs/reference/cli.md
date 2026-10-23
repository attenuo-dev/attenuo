# CLI commands

The `onbehalf` binary comes from the `onbehalf-cli` crate. It talks to a running onbehalf server over HTTP, except for `policy test` and `policy lint`, which run offline.

```
onbehalf [--server URL] [--admin-token TOKEN] [--json] <command>
```

## Global options

| Option | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--server`, `--url` | `ONBEHALF_SERVER` | `http://127.0.0.1:8080` | Base URL of the onbehalf server. Goes before the subcommand. |
| `--admin-token` | `ONBEHALF_ADMIN_TOKEN` | none | Bearer for `/admin/*`. |
| `--json` | | off | Print machine-readable JSON instead of text. Works after any subcommand. |

The `--server` flag of `call`, `tools` and `authzen eval` is different. It names the MCP upstream, for example `github`.

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
| `--print token\|lease` | Print only that value, for scripts. |

### `token exchange`

RFC 8693 exchange: delegate a subset of a token's capabilities to a sub-agent.

| Option | Meaning |
| --- | --- |
| `--subject-token` (`ONBEHALF_TOKEN`) | The parent token. Required. |
| `--actor` | The sub-agent that will hold the new token. Required. |
| `--cap` | Capability to hand over. Required, repeatable. Must be covered by the parent. |
| `--ttl-seconds` | Requested lifetime, clamped to the parent's expiry. |
| `--print token\|lease` | Print only that value. |

### `token inspect <JWT>`

Decode a token and show its delegation chain as a tree. Use `-` to read the token from stdin.

| Option | Meaning |
| --- | --- |
| `--verify` | Fetch the server JWKS and verify signature, issuer, audience and chain. |
| `--issuer` | With `--verify`: expected issuer. Default: the token's own. |
| `--audience` | With `--verify`: expected audience. Default: the token's own. |

### `call`

Call a tool through the proxy (`tools/call`).

| Option | Meaning |
| --- | --- |
| `--token` (`ONBEHALF_TOKEN`) | Delegation token. Required. |
| `--server`, `--upstream` | MCP upstream name. Required. |
| `--tool` | Tool name. Required. |
| `--arg` | Tool argument. Repeatable. |

### `tools`

List the tools the token may see (`tools/list`). Takes `--token` and `--server`.

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

Walk the whole hash chain. Exits 1 if it is broken. Needs the admin token.

### `policy reload`

Ask the server to re-read its policy file. Needs the admin token.

### `policy test <FILE>...`

Run YAML policy test files offline. Exit 0 if every case passes, 2 if any fails, 1 if a file cannot be run. The format is in [Writing policies](../guides/writing-policies.md).

### `policy lint <POLICY>`

Parse a Cedar policy file and validate it against the generated schema. Prints errors with line and column. Exit 0 if clean, 2 if there are errors.

| Option | Meaning |
| --- | --- |
| `--config` | Server config whose `[policy.catalog]` declares the tools, or a JSON catalog. Without it the catalog is empty and any policy naming an action fails. |
| `--schema` | Also print the generated schema. |

### `authzen eval`

Ask the decision endpoint whether the token's chain may make a call, without making it.

| Option | Default | Meaning |
| --- | --- | --- |
| `--token` (`ONBEHALF_TOKEN`) | | Delegation token, sent as the bearer. Required. |
| `--server` | `github` | MCP server name. |
| `--tool` | | Tool name. Required. |
| `--arg` | | Tool argument. Repeatable. |
