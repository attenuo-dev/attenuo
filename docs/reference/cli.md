# CLI commands

The `attenuo` binary comes from the `attenuo-cli` crate. It talks to a running attenuo server over HTTP, except for `policy test` (unless `--via authzen`) and `policy lint`, which run offline.

```
attenuo [--server URL] [--json] <command>
```

## Global options

| Option | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--server`, `--url` | `ATTENUO_SERVER` | `http://127.0.0.1:8080` | Base URL of the attenuo server. Goes before the subcommand. |
| `--admin-token-stdin` | | off | Read the admin token from the first line of standard input. The three admin token options go before or after the subcommand. |
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

- `--cap server:tool` is a capability. Globs are allowed. Repeat the flag, or comma-separate plain values. A value that starts with `{` is a full capability as JSON, which can carry constraints and run `limits` (`{"server":"banking","tool":"send_money","limits":{"calls":1,"sum":{"arg":"amount","max":100}}}`). Commands that print capabilities show limits after the constraints: `banking:send_money [calls <= 1, sum(amount) <= 100]`. `distinct` and a derived value work the same way: `--cap '{"server":"web","tool":"get_webpage","limits":{"distinct":{"arg":"url","derive":"host","max":2}}}'` prints as `web:get_webpage [distinct url#host <= 2]`. A limit kind or derivation the CLI does not know is refused before anything is sent.
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
| `--may-act <AGENT>` | Only this agent may exchange the root token (RFC 8693 `may_act`). Repeatable, or comma-separated. Must be within the `[[root_grants]]` entry's `may_act` when it has one. Without it and without `--no-delegation` the grant's `may_act` applies; when the grant has none, or the server has no `[[root_grants]]`, the root token has no `may_act`, so any authenticated agent may exchange it. Values that are all empty are refused. |
| `--no-delegation` | Send `may_act: []`: no agent may exchange the root token. An empty list is within any grant's `may_act`. Cannot be combined with `--may-act`. |
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
| `--may-act <AGENT>` | Only this agent may exchange the new token (RFC 8693 `may_act`). Repeatable, or comma-separated. Without it and without `--no-delegation` the new token has no `may_act`, so any authenticated agent may exchange it; it does not inherit the parent's list. Values that are all empty are refused. |
| `--no-delegation` | Send `may_act: []`: no agent may exchange the new token. Cannot be combined with `--may-act`. |
| `--dpop-key PATH` | Bind the new token to this DPoP key. Required when the parent is bound. When the parent is bound to the same key, the proof also covers the parent. |
| `--subject-token-dpop-file PATH` | The parent holder's sign-off (`subject_token_dpop`), made with `token sign-off` for this exchange's `--dpop-key` and `--actor`. Required when the parent is bound to a key other than `--dpop-key`. |
| `--subject-dpop-key PATH` | Instead of `--subject-token-dpop-file`, when this process may hold the parent's key too: the sign-off is made here. Cannot be combined with `--subject-token-dpop-file`. |
| `--print token\|lease` | Print only that value. |

```sh
ATTENUO_TOKEN="$PARENT" attenuo token exchange --actor coder \
  --cap github:read_file --actor-token-file /run/spiffe/coder.jwt --may-act reviewer
```

A refused exchange that the server audited (its subject token verified) prints the record id under the error, as `decision <id>`, for `audit show --id`:

```text
error: server answered 400 Bad Request: invalid_request: agent `reviewer` is not permitted to act on this token (may_act)
decision 6685bd7f-cbb3-48e5-ab05-f2b8ceae9a61
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

The text output has a `may_act` line saying who may exchange the token next: `may_act (absent): any authenticated agent may exchange this token`, `may_act []: no agent may exchange this token`, or `may_act coder, reviewer: only these agents may exchange this token` (agent ids with control characters escaped). With `--verify` it is read from the verified claims, which the signature covers. For a bound token the text output adds `bound to DPoP key jkt <thumbprint>`.

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

A call that needs an approval prints `APPROVAL REQUIRED` followed by the approval id, its expiry, the call hash and the decision id, and exits 2, like a denial. Once the approval is granted, run the identical command again: it is allowed once.

### `tools`

List the tools the token may see (`tools/list`). Takes `--token` (or `--token-file`, or `ATTENUO_TOKEN`) and `--server`.

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

A dry run of `lease revoke`: shows what a revocation of `ID` would reach and changes nothing (`GET /admin/leases/{id}/tree`). Prints the lease's ancestors nearest first, then the lease and everything delegated from it as an indented tree. Each lease shows the agent it was issued to, its state (`active, expires ...`, `REVOKED <time> (<reason>)` or `expired ...`) and the audit `seq` that issued it. The last line is `would revoke N lease(s)`, the count a revoke sent now would return. `--max-nodes` caps the listing (server default 1000, at most 10000); when the cap cuts it short, a `truncated:` line says so, and `would revoke` still counts the whole subtree. Needs the admin token.

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
| 404 `not_found` | `error: decision <id> charged no run limit or run usage; nothing to refund` | 2 |
| 409 `already_refunded` | `error: the charge of decision <id> was already refunded` | 3 |
| anything else | `error: server answered ...` | 1 |

Exit 3 lets a script that retries a refund tell "already done" from "nothing to do". If the refund stood but its audit record could not be written, `audit` reads `- (the refund stands, but its audit record was not written; see the server log)` and the exit status is 0.

### `audit tail`

Show the most recent audit entries, oldest of them first. Filters keep only matching entries, so `audit tail -n 5 --decision deny` is the last five denials. Needs the admin token.

| Option | Default | Meaning |
| --- | --- | --- |
| `-n`, `--lines` | 20 | How many entries. |
| `--before SEQ` | the head | Show the `-n` matching entries just below `SEQ` instead of the newest. To page back, pass the oldest `seq` shown. Not with `--follow`. |
| `-f`, `--follow` | off | Keep polling for new matching entries. |
| `--interval-ms` | 1000 | Polling interval with `--follow`. |
| `--kind` | all | Record kind: `decision`, `tool_result`, `approval_request`, `approval_grant`, `exchange`, `root_token`, `lease_renew`, `lease_revoke` or `admin`. Repeatable, or comma-separated; any of them matches. |
| `--decision` | all | `allow` or `deny`. |
| `--reason` | all | The record's `reason` (`policy_deny`, `lease_revoked`, ...). |
| `--subject` | all | The originating user. |
| `--agent` | all | An agent anywhere in the record's chain. |
| `--lease` | all | A lease anywhere in the record's chain. |
| `--server` | all | The MCP upstream the call went to. This `--server` comes after `audit tail`; the attenuo server URL is the global `--server` before the subcommand. |
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

The filters are the query parameters of `GET /admin/audit` (see [Querying the audit log](http-api.md#querying-the-audit-log)): exact matches, combined with AND. A bad kind, decision or time is refused before any request. The CLI reads newest first (`order=desc&before=N`) and keeps following `prev` until it has `-n` entries, because a filtered page can come back short, even empty, when the server stops scanning. `--follow` then reads forward from the head the same way, following `next`. With `--json` each entry is one JSON line.

Every line starts with the sequence number and the time. Decisions, token issuance, lease and admin records show `ALLOW` or `DENY`, `server/tool`, the agents and user, the `reason` and the record id. Records that are not decisions show their kind where `ALLOW`/`DENY` would be, and the details of that kind in place of the reason. Shown here with ids and times shortened:

```text
#3    2026-10-24T08:45:18Z  ALLOW github/read_file  assistant for alice  reason=policy_allow  id=9f35...
#4    2026-10-24T08:45:18Z  tool_result  github/read_file  assistant for alice  decision=9f35...  label=untrusted size=149  id=a70d...
#5    2026-10-24T08:45:18Z  DENY  github/create_issue  assistant for alice  reason=approval_required  id=b9ad...
#6    2026-10-24T08:45:18Z  approval_request  github/create_issue  assistant for alice  decision=b9ad...  approval=1388... expires=2026-10-24T08:47:18Z  id=7a41...
#7    2026-10-24T08:45:18Z  approval_grant  github/create_issue  assistant for alice  decision=b9ad...  approval=1388... outcome=grant by=operator  id=e966...
```

- `tool_result`: `decision=` is the call it answers, `label=` is `untrusted` or `trusted`, `size=` the bytes of the canonical result; ` error` follows when the upstream answered with a JSON-RPC error. The content is not stored.
- `approval_request`: `decision=` is the gated decision, `expires=` when the approval stops being usable.
- `approval_grant`: `outcome=` is `grant` or `decline`, `by=` is `user` or `operator`.
- `exchange`, `root_token`, `lease_renew`, `lease_revoke` and `admin` records already name themselves in `server/tool` (`attenuo/token.exchange`, `attenuo/admin.lease.revoke`, ...) and print as before. `audit show` prints the same first line.

### `audit show <SEQ>` / `audit show --id <UUID>`

One entry with its context, from `GET /admin/audit/entries/{seq}` or, with `--id`, `GET /admin/audit/records/{id}` (the `decision_id` that denials and AuthZEN answers return). Prints the entry line as `audit tail` does, then the record's kind, chain, policies and hashes, the state of each lease in its chain now (root first; `unknown to the lease registry` for a lease the registry does not hold), the stored checkpoint that covers the entry (or that none does yet), and whether the policy was reloaded after it. A missing entry is a 404 and a malformed id a 400 (exit 1). `--json` prints the server's `{entry, lease_states, covered_by_checkpoint, policy_reloaded_after}`. Needs the admin token.

### `audit checkpoints [--before SEQ] [--limit N]`

List stored checkpoints, newest first, one line each (`seq`, time, `kid`, head hash), from `GET /admin/audit/checkpoints`. When more are older, the last line gives the `--before` for the next page. Read-only: unlike `GET /admin/audit/checkpoint` it never signs a new checkpoint. `--limit` defaults to the server's 100, at most 1000. Needs the admin token.

### `audit verify`

Walk the whole hash chain and verify the signed checkpoints against the server's JWKS. Prints whether the chain is intact, then the checkpoint status: how many checkpoints exist, the last signed `seq`, how many entries come after it, and any invalid checkpoint with its reason. Exits 2 if the chain is broken or a checkpoint is invalid. Needs the admin token.

With `--file` it verifies an export offline instead and needs no admin token. The check is strict: it exits 2 unless every entry in the file is inside the range its header declares, the file covers that whole range, and every entry is covered by a valid checkpoint in the file.

| Option | Meaning |
| --- | --- |
| `--file <PATH>` | An export from `audit export` (JSON Lines, or the `--format json` object, format `attenuo-audit-export-v2`; older `v1` exports are refused). Re-hashes every entry, checks the links, verifies each checkpoint signature and its head hash. Fails a file that is shorter than the range in its header, one that holds entries outside it, and one with entries after its last valid checkpoint. A filtered export (`audit export --kind`, `--chain-id`, `--tool` or `--decision`) is refused with an error: its chain has gaps, so nothing shows it is complete. |
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
| `--kind` | all | Keep only records of this kind: `decision`, `tool_result`, `exchange`, `root_token`, `lease_renew`, `lease_revoke` or `admin`. |
| `--chain-id` | all | Keep only records of this delegation chain (the `chain_id` field: the lease id of the chain's first hop). |
| `--tool` | all | Keep only records for this tool, as on `audit tail`: an MCP tool name, or one of attenuo's own (`token.root`, `token.exchange`, `lease.renew`, `admin.*`). Exact match. |
| `--decision` | all | Keep only records with this decision: `allow` or `deny`. |

The filters combine, and apply inside `--from`/`--to`. A refused exchange or renewal is kind `decision`, not `exchange` or `lease_renew`, so `--kind` alone mixes it with every tool-call decision; `audit export --tool token.exchange --decision deny` (or `--tool lease.renew`) exports just those. A filtered export has a `filter` member in its header naming the filters it was taken with (`{"decision":"deny","tool":"token.exchange"}`) and cannot be verified with `audit verify --file` (its hash chain has gaps by construction): verify an unfiltered export, then filter. The same filters are `?kind=`, `?chain_id=`, `?tool=` and `?decision=` on `GET /admin/audit/export`; an unknown kind or decision, more than one kind, or an empty value is a 400.

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
| `--server`, `--upstream` | MCP upstream name. Required. |
| `--tool` | Tool name. Required. |
| `--arg` | Tool argument. Repeatable. |

```sh
ATTENUO_TOKEN="$CODER" attenuo policy evaluate --server github --tool create_issue --arg repo=acme/api
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

With `--via admin-evaluate` the server also decides with its own policies, catalog and clock, but each case's own chain is sent (`subject.properties.chain`, checked by the server for shape and against its `max_depth`, not for having been issued by it), with the case's `session`, `approval` and `usage` as the run's state. The route checks no lease, charges nothing and writes no audit record. So every case replays as written except one that sets `budget`, which is skipped with the reason: the dry run reads `context.budget` from the run limits in the chain's capabilities and the server's counters. The chain is stamped at the current time, because the server validates it at its own clock; an explicit `user.authenticated_at_unix` moves with it, keeping its distance from the file's `now`, and a `note:` says that `now` is not sent. A case without `session` or `usage` is sent as an untainted run with no usage, so nothing is read from the server's store. A case the server refuses with 400 (a chain deeper than its `max_depth`, an approval `by` other than `user`, `operator` or `policy`) is that case's error, reported as failed; any other refusal (a wrong admin token, a server without the route) or an unreachable server stops that file (exit 1). The unexercised list is computed against the test file's local `policies` file, as with `authzen`.

```sh
attenuo --server https://attenuo.internal --admin-token-file /run/secrets/attenuo-admin \
  policy test --via admin-evaluate config/policies/default_test.yaml
```

### `policy lint <POLICY>`

Parse a Cedar policy file and validate it against the generated schema. Prints errors with line and column. Exit 0 if clean, 2 if there are errors.

| Option | Meaning |
| --- | --- |
| `--config` | Server config whose `[policy.catalog]` declares the tools, or a JSON catalog. Without it, the tools are declared from the policy's own `<server>/<tool>` action names and a `note:` lists what could not be checked (tool attributes, input types, user attributes). |
| `--schema-file PATH` | Cedar schema file replacing the built-in base schema, over the config's `[policy] schema_path`. Checked as the server checks it at start: a file without the required entity types, attributes or hierarchy is an error (exit 1). |
| `--schema` | Also print the generated schema. |

### `approval list` / `show` / `grant` / `decline` / `verify`

Approvals of gated calls, as the operator (admin token, `ATTENUO_ADMIN_TOKEN`).

| Command | Does |
| --- | --- |
| `approval list [--chain-id ID] [--state pending\|granted\|declined\|consumed] [--limit N]` | `GET /admin/approvals`: one line per approval, newest first (id, state, call, run, expiry). `--limit` 1 to 500. |
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
| `--server` | `github` | MCP server name. |
| `--tool` | | Tool name. Required. |
| `--arg` | | Tool argument. Repeatable. |
