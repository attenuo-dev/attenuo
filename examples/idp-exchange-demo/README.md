# IdP exchange demo

> **The identity provider in this demo is a mock, for demonstration only.** It is a small local program (`crates/attenuo-server/examples/mock_idp.rs`) that signs an ID token for a fixed user, alice, for anyone who asks, with no login. Never point a real deployment at it. Everything else is the real attenuo-server with its real IdP intake.

The other examples start each chain with the dev-only root mint (`[dev] allow_root_mint = true`, `attenuo token root`). This one starts where a real deployment starts: alice signs in at an OpenID Connect identity provider, the agent platform receives her ID token, and the planner agent exchanges that ID token at attenuo's `POST /token` (RFC 8693 token exchange) for the root delegation token. The dev mint is off (`[dev] allow_root_mint = false`). Then the planner delegates a narrower token to a coder, and the coder makes one call that is allowed and one that is denied.

| Hop | Who | Holds |
| --- | --- | --- |
| user | alice | signed in at the IdP; `sub`, `email` and `amr` come from her verified ID token |
| 1 | planner | its `[[root_grants]]` ceiling for users of this IdP: `get_file_contents` and `create_issue`, both with `repo` starting with `acme/`; `may_act: [coder]` |
| 2 | coder | `get_file_contents` with `repo` starting with `acme/api` only; `may_act: []`, so nobody may exchange its token |

## Run it

```sh
examples/idp-exchange-demo/run.sh
```

It needs a Rust toolchain, `curl` and `python3`, and no network beyond loopback. It starts three local processes on free ports: the mock IdP, attenuo-server and the fake GitHub MCP server the other examples use (here with the tools `get_file_contents` and `create_issue`). Everything lives in a temp directory that an exit trap removes (`KEEP=1` keeps it for the logs); `ATTENUO_BIN_DIR=DIR` uses prebuilt binaries (`attenuo-server`, `attenuo`, `examples/fake_mcp`, `examples/mock_idp`) instead of `cargo build`. The script checks the exit status and the outcome of every step, the audit entry count (5) and the number of calls that reached the upstream (1), and exits non-zero if anything comes out differently.

## The mock IdP

`mock_idp` binds `127.0.0.1` only and makes a new P-256 key each time it starts. Its URL is the issuer.

| Route | Answer |
| --- | --- |
| `GET /.well-known/openid-configuration` | OIDC discovery: `issuer` and `jwks_uri` |
| `GET /jwks` | the public key (`kid` `demo-key-1`, ES256) |
| `GET /demo/id-token` | a fresh signed ID token for alice: `aud` `agent-platform`, `email`, `amr` `["pwd", "mfa"]`, a new `jti`, valid for 5 minutes |

`/demo/id-token` is not part of OIDC. It stands in for the browser login and the authorization-code flow a real application runs to get an ID token. The discovery document and the JWKS are what attenuo fetches from any OIDC provider, and attenuo verifies the token exactly as it would one from Keycloak, Okta or Entra ID. It is a Cargo example of `attenuo-server`, so it is never in a release build or the container image.

To use a real provider instead, change `[[idps]]` and `[[root_grants]]` in `config.toml` as the [identity providers guide](../../docs/guides/identity-providers.md) describes, and present an ID token your application received.

## What happens

| Step | Who | Request | Result | Why |
| --- | --- | --- | --- | --- |
| 1 | anyone | `attenuo token root` (the dev mint) | `404 Not Found` | `[dev] allow_root_mint = false`: `POST /admin/root-token` is not mounted. |
| 2 | alice | signs in at the IdP (`GET /demo/id-token`) | an ES256 ID token | Printed decoded: `iss` is the mock IdP, `aud` is the planner's client id at the IdP. |
| 3 | planner | `POST /token` with the ID token as `subject_token`, `subject_token_type` `urn:ietf:params:oauth:token-type:id_token`, its own client credentials (HTTP Basic) and the capabilities as `authorization_details` | root token issued, `expires_in` about 300 | attenuo fetches the IdP's discovery document and JWKS, verifies the signature, `iss`, `aud` (against `[[idps]] client_ids`), `exp` and `iat`, and attenuates the request against `[[root_grants]]`. The root token never outlives the ID token. |
| 4 | planner | the same request again | refused, `invalid_grant` / `replayed` | Each IdP credential mints one root token. |
| 5 | | `token inspect --verify` | user alice, issuer the mock IdP, `mfa=true`; planner at hop 1 | The originating user is built from the verified claims; `mfa` is derived from `amr`. |
| 6 | planner → coder | `token exchange --actor coder --no-delegation`, `get_file_contents` on `acme/api` | issued | The coder authenticates as itself (secret on stdin). The token can only narrow. |
| 7 | coder | `get_file_contents acme/api src/lib.rs` | allowed, reaches upstream | Inside the coder's token and the policy. |
| 8 | coder | `get_file_contents acme/billing README.md` | denied, `capability_denied` | The policy allows any `acme/` repository; the coder's token covers only `acme/api`. |
| 9 | operator | `audit tail`, `audit verify` | 5 entries, chain OK | The root token (`token.root`), the exchange, the read and its `tool_result`, the denial; every record says `for alice`. No admin record: no dev mint was made. |

At the end the script prints what the fake GitHub server received (one `tools/call`, the coder's read) and what the mock IdP served (one ID token, the discovery document and the JWKS, the last two fetched by attenuo).

## Transcript

Output of `examples/idp-exchange-demo/run.sh` from one real run. Ports, ids and timestamps differ on every run, and tokens are shortened for display.

```text
== Setup
# Mock OIDC IdP (demonstration only) at http://127.0.0.1:40149; attenuo at http://127.0.0.1:41747 trusts it in [[idps]].
# attenuo proxies a fake GitHub MCP server at port 36781 as 'github'. [dev] allow_root_mint = false.

== 1. The dev shortcut the other demos use is off
# POST /admin/root-token is not mounted, so the only way to a root token is POST /token.
$ attenuo token root --subject alice --agent planner
error: server answered 404 Not Found

== 2. alice signs in at the IdP; the agent platform receives her ID token
# The mock's /demo/id-token stands in for the browser login and the authorization-code flow.
$ curl -sSf "$IDP/demo/id-token"
eyJ0eXAiOiJKV1QiLCJhbGci...
$ jwt_claims "$ID_TOKEN"
header  {"typ": "JWT", "alg": "ES256", "kid": "demo-key-1"}
claims  {
  "iss": "http://127.0.0.1:40149",
  "aud": "agent-platform",
  "sub": "alice",
  "email": "alice@example.com",
  "amr": [
    "pwd",
    "mfa"
  ],
  "iat": 1794522808,
  "auth_time": 1794522808,
  "exp": 1794523108,
  "jti": "fb0779c0-a5b6-4512-b5d7-f1016e0528c3"
}

== 3. Hop 0: the planner exchanges alice's ID token for a root token at POST /token (RFC 8693)
# The planner authenticates as itself (HTTP Basic). attenuo fetches the IdP's discovery
# document and JWKS, verifies the signature, iss, aud (the planner's client id), exp and iat,
# then attenuates the request against the [[root_grants]] entry for this IdP and agent.
$ curl -sS "$ATTENUO_SERVER/token" -u planner:demo-planner-secret \
  --data-urlencode grant_type="$EXCHANGE" \
  --data-urlencode subject_token="$ID_TOKEN" \
  --data-urlencode subject_token_type="$ID_TOKEN_TYPE" \
  --data-urlencode authorization_details="$ROOT_CAPS" | pretty
{
  "access_token": "eyJ0eXAiOiJhdHRlbnVvK2p3...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 299,
  "lease": "d1c2e2cd-eac3-4b7b-8ae6-97f4853ba5ea"
}
# expires_in is about 300 s, not the 900 s default: a root token never outlives its ID token.

== 4. The same ID token a second time: refused, each IdP credential mints one root token
$ curl -sS "$ATTENUO_SERVER/token" -u planner:demo-planner-secret \
  --data-urlencode grant_type="$EXCHANGE" \
  --data-urlencode subject_token="$ID_TOKEN" \
  --data-urlencode subject_token_type="$ID_TOKEN_TYPE" \
  --data-urlencode authorization_details="$ROOT_CAPS" | pretty
{
  "error": "invalid_grant",
  "detail": "this credential was already used; present a fresh one",
  "error_description": "replayed"
}

== 5. The root token: alice from the IdP, the planner at hop 1
# The originating user is built from the verified ID token: sub, iss, and the claims in
# [[idps]] attribute_claims (email, amr), plus mfa derived from amr.
$ attenuo token inspect "$ROOT_TOKEN" --verify
user alice  (issuer http://127.0.0.1:40149)
  authenticated 2026-11-12T22:33:28Z
  attributes amr=["pwd","mfa"], email="alice@example.com", mfa=true
└─ agent planner  <- holds this token
     can   github:create_issue {repo starts with "acme/"}, github:get_file_contents {repo starts with "acme/"}
     until 2026-11-12T22:38:28Z (in 4m 58s)
     lease d1c2e2cd-eac3-4b7b-8ae6-97f4853ba5ea

iss http://127.0.0.1:41747   aud attenuo   jti da5b7277-73da-410d-b16c-efd0bad41889
kid E1aOhYsQXm9i4E5RCP48uQ   ou_kid E1aOhYsQXm9i4E5RCP48uQ
exp 2026-11-12T22:38:28Z (in 4m 58s)
may_act coder: only this agent may exchange this token
verified: signature, type, issuer, audience, expiry, chain

== 6. Exchange: planner -> coder, narrowed to reading acme/api, and nobody may exchange it further
# The coder authenticates as itself (its secret on stdin).
$ printf "%s\n" demo-coder-secret | ATTENUO_TOKEN="$ROOT_TOKEN" attenuo token exchange --actor coder --client-secret-stdin --no-delegation --cap '{"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"prefix","value":"acme/api"}}}'
lease       fd485723-b300-4772-846c-15b00e079039
expires_in  298s
token       eyJ0eXAiOiJhdHRlbnVvK2p3...

== 7. The coder reads a file in acme/api: allowed
$ ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool get_file_contents --arg repo=acme/api --arg path=src/lib.rs
ALLOWED
{"arguments":{"path":"src/lib.rs","repo":"acme/api"},"name":"get_file_contents"}

== 8. The coder reads a file in acme/billing: denied, outside what the planner delegated
# The policy would allow any acme/ repository; the coder's token covers only acme/api.
$ ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool get_file_contents --arg repo=acme/billing --arg path=README.md
DENIED  capability_denied
decision ed5aec1a-0aa4-43bc-847c-2a496bc51810

== 9. The audit log: every record goes back to alice, and the hash chain checks out
# #1 is the hop-0 exchange (token.root). There is no dev-mint (admin) record: none was made.
$ attenuo audit tail -n 20
#1    2026-11-12T22:33:29.015897704Z  ALLOW attenuo/token.root  planner for alice  reason=token_issued  id=b3a331d7-a956-485b-9096-0626e1d233fd
#2    2026-11-12T22:33:29.173395752Z  ALLOW attenuo/token.exchange  planner > coder for alice  reason=token_issued  id=d9b64f2c-4369-4657-9448-d863203e43dd
#3    2026-11-12T22:33:29.210239224Z  ALLOW github/get_file_contents  planner > coder for alice  reason=policy_allow  id=6146ca7e-93ff-4192-b9db-873b2f8d9f15
#4    2026-11-12T22:33:29.219998498Z  tool_result  github/get_file_contents  planner > coder for alice  decision=6146ca7e-93ff-4192-b9db-873b2f8d9f15  label=untrusted size=149  id=311778e4-3105-4df8-808b-233b5c9e964c
#5    2026-11-12T22:33:29.235526544Z  DENY  github/get_file_contents  planner > coder for alice  reason=capability_denied  id=ed5aec1a-0aa4-43bc-847c-2a496bc51810
$ attenuo audit verify
audit chain OK: 5 entries verified
checkpoints: none signed yet

== What reached the GitHub server
  fake-mcp: tools/call get_file_contents {"path":"src/lib.rs","repo":"acme/api"}
  -> 1 tools/call reached upstream (the coder's read of acme/api). The denied call never left attenuo.

== What the IdP served
  GET /demo/id-token (sub alice)
  GET /.well-known/openid-configuration
  GET /jwks
```

## Files

| File | What |
| --- | --- |
| `run.sh` | the scenario above |
| `config.toml` | server config: `[[idps]]` (the mock IdP, `client_ids = { planner = "agent-platform" }`, ES256), `[[root_grants]]`, the two `[[agents]]`, `[dev] allow_root_mint = false` |
| `policy.cedar` | one permit: reads and issues anywhere under `acme/` |
| [`crates/attenuo-server/examples/mock_idp.rs`](../../crates/attenuo-server/examples/mock_idp.rs) | the mock IdP |
