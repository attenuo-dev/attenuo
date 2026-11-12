# Identity providers

attenuo does not log users in. It trusts your identity provider (IdP) for that, and builds the first token of every delegation chain from a credential the IdP issued. This guide shows how to wire that up, with config for Keycloak, Auth0, Okta, Entra ID and Google.

**Read this first: what was tested.**

- The config keys, the claim mapping and the error codes below come from the code in `crates/attenuo-server/src/config.rs` and `crates/attenuo-server/src/idp/`. The server's own tests exercise them with locally signed tokens. Config shapes in this guide were parsed by the real server.
- **No provider-specific setup in this guide was run against a live provider.** Every IdP section is marked **untested**. The issuer formats, claim names and console steps come from the providers' public conventions and may be out of date or wrong for your tenant. Check each against your tenant before relying on it, using [Checking your setup](#checking-your-setup).

## How hop 0 works

1. A user logs in to some application you run, usually the agent platform, using standard OIDC. The application receives an **ID token**.
2. The agent calls `POST /token` on attenuo, authenticating as itself with a client id and secret (or with a workload-identity token, see [Hop 0 with a JWT-SVID](#hop-0-with-a-jwt-svid)), and passes the ID token as the `subject_token`.
3. attenuo finds the `[[idps]]` entry for the token's `iss`, fetches that IdP's signing keys, and verifies the token: signature, algorithm, `iss`, `aud`, `exp`, `iat`, `nbf`, `sub`.
4. It builds the **originating user** from the verified claims.
5. It looks up the `[[root_grants]]` entry for this issuer and agent, and attenuates the request against it. If the agent asked for more than the grant allows, it fails.
6. It issues a **root token** for that user and agent, with a lease, and writes an audit row.

Three config lists are involved and they do different jobs:

| List | Question it answers |
| --- | --- |
| `[[idps]]` | Whose user credentials do I believe, and how do I verify them? |
| `[[agents]]` | Which agents may present a user credential, and how do they prove who they are? |
| `[[root_grants]]` | How much may this agent get for the users of this IdP? |

All three must match for hop 0 to work. With no `[[agents]]` and no `[[actor_trust]]`, every intake request is rejected.

## `[[idps]]`

```toml
[[idps]]
issuer = "https://idp.example.com/realms/acme"   # exact `iss` of the tokens
client_ids = { planner = "agent-platform" }       # client id of each agent at the IdP
# jwks_url = "https://idp.example.com/keys"       # optional
allowed_algs = ["RS256", "ES256", "EdDSA"]        # default
attribute_claims = ["email", "groups", "amr"]     # default
jwks_ttl_seconds = 300                            # default
clock_skew_seconds = 60                           # default
```

| Key | Meaning |
| --- | --- |
| `issuer` | Required. Compared byte for byte with the token's `iss` and with the `issuer` in the discovery document. A trailing slash counts. |
| `client_ids` | Table of agent id to the client id registered for that agent at the IdP, the application that ran the login. An ID token is accepted only when its `aud` contains the presenting agent's client id, and its `azp` equals it when `aud` has several values or `azp` is present. An agent with no entry must have a client id equal to its agent id; the server logs a warning at startup for each such agent. Not used for an ID-JAG, whose `aud` must be attenuo's own `[issuer] issuer` and whose `client_id` must be the agent. |
| `audience` | Deprecated. Ignored for ID tokens since SR-37, which needed the audience to be per agent. Existing configs still load; the server logs a warning when it is set. |
| `jwks_url` | Where to fetch signing keys. When absent, attenuo reads `jwks_uri` from `<issuer>/.well-known/openid-configuration`. Every key fetch must be `https://` (plain `http://` is accepted only for a loopback host, for local testing), and redirects are not followed, so give the final URL. |
| `allowed_algs` | Accepted JWS algorithms. Asymmetric only: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `PS256` and so on. A symmetric algorithm such as `HS256` is refused when the config loads. |
| `attribute_claims` | Claims copied verbatim into `originating_user.attributes`, when present and not null. |
| `jwks_ttl_seconds` | How long fetched keys are used before refetching. A token with an unknown `kid` triggers one early refetch, at most once per 30 seconds. |
| `clock_skew_seconds` | Leeway for `exp`, `iat` and `nbf`. |

You can list several IdPs. The unverified `iss` selects the entry. An issuer that is not listed is rejected without any network call.

### Which claims become `originating_user.attributes`

The user block of the root token is built like this:

| Field | Source |
| --- | --- |
| `subject` | `sub` |
| `issuer` | `iss` |
| `authenticated_at` | `auth_time` if present, otherwise `iat` |
| `attributes` | each claim named in `attribute_claims`, copied as is, plus `mfa` |
| `attributes.mfa` | derived, `true` when `amr` contains `mfa`, `otp`, `hwk` or `swk` |

Points to know:

- `mfa` is always set, `false` when `amr` is missing. It overrides any claim called `mfa`. `pwd`, `sms` and the other `amr` values do not set it on their own. If your IdP does not send `amr`, every user looks like they did not use MFA, and policies that require `mfa` (the starter policy does, for `sensitive` tools) will deny them. Fix it at the IdP, not in attenuo.
- `attributes` set in `[[root_grants]]` are ignored for IdP intake. User attributes come only from the verified token.
- **Cedar policies should only test attributes the policy schema declares.** By default those are `mfa` (bool), `roles` (set of strings), `tenant` (string) and `email` (string). Other attributes, `groups` among them, are copied into the token and the audit trail, but a policy that tests an undeclared one is reported as "impossible" at load time. Declare them with `[policy] user_attributes = { groups = "set<string>" }`; see [Writing policies](writing-policies.md#user-attributes). A claim whose value has a different type than declared (a list where you declared `string`, which Keycloak's multivalued mappers and SCIM-sourced claims produce) is denied with `attribute_type_mismatch` and audited; attenuo does not coerce it. This covers `mfa`, `roles`, `tenant` and `email` too.
- The token also carries the whole `attributes` map, and it is readable by whoever holds the token. Do not list claims you would not want an agent to see.
- `sub` is the user's identity inside attenuo. Some providers issue a different `sub` per application (Entra does). Two applications then see the same person as two users.

## `[[agents]]`

```toml
[[agents]]
id = "planner"
secret_sha256 = "a93d472e76b73bffcef69973eb463fb679b1365377e183a459d7f33c2ee97b7a"
```

`id` is the OAuth `client_id`. It becomes the agent id on the root hop and is what shows up in the audit log. `secret_sha256` is the lowercase hex SHA-256 of the client secret. Make one:

```sh
SECRET=$(openssl rand -hex 24)
printf %s "$SECRET" | sha256sum | cut -d' ' -f1     # put this in the config
echo "$SECRET"                                      # give this to the agent, once
```

The agent sends the secret as HTTP Basic (`-u planner:$SECRET`) or as `client_id` and `client_secret` form fields, not both. A wrong secret is `401 invalid_client`, and it is checked before the ID token is looked at, so an unauthenticated caller cannot make the server fetch anything.

Notes:

- Use a separate entry and a separate secret for each agent identity. Do not share one across agents.
- The secret goes in the agent's runtime. Treat a leak as a leak of that agent's root-grant ceiling for every user whose ID token the attacker can also get.
- Secrets are static. There is no `private_key_jwt` and no mTLS in v0. Rotating one means editing the config and restarting.
- If an `actor` is sent on an intake request it must equal the authenticated agent.
- The same `[[agents]]` entries authenticate sub-agents: a token exchange must authenticate as its `actor`. Give every agent that receives delegated tokens an entry, or a workload identity under [`[[actor_trust]]`](#workload-identity-for-sub-agents).
- Each ID token or ID-JAG mints one root token. A second presentation, by any agent, is `invalid_grant` / `replayed` (keyed by `iss` and `jti`, or by the whole token when it has no `jti`). The root token expires no later than the credential, and a credential accepted only thanks to `clock_skew_seconds` is refused with `credential_expired`. The record of used credentials is in memory, so it is per server process.

## `[[root_grants]]`

```toml
[[root_grants]]
issuer = "https://idp.example.com/realms/acme"
agent = "planner"
capabilities = ["github:read_*", "github:create_issue"]

# One user gets more. A grant with a `subject` wins over one without.
[[root_grants]]
subject = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
issuer = "https://idp.example.com/realms/acme"
agent = "planner"
capabilities = ["github:*"]
```

A root grant is the ceiling on what a root token for this issuer, this agent and (optionally) this user can carry. The request is attenuated against it. The most specific match wins: an entry pinned to a `subject` first, then one without. No match means no root token (`invalid_scope`, `no_root_grant`). Asking for more than the entry allows is `invalid_scope`, `scope_exceeds_grant`.

Capabilities can be a `"server:tool"` string (globs allowed) or a table with constraints:

```toml
capabilities = [
  "github:read_*",
  { server = "github", tool = "create_issue", constraints = { repo = { op = "prefix", value = "acme/" } } },
]
```

`op` is `equals`, `one_of`, `prefix`, `path_prefix` or `range`; use `path_prefix`, not `prefix`, for a file path ([why](../concepts/capabilities-and-attenuation.md#prefixes-of-strings-and-of-paths)). Start narrow. A root token is the widest anything in the chain can be.

ID tokens are bearer credentials, bound to the agent that presents them only through `aud`/`azp` (SR-37): a token issued for agent A is refused from agent B with `credential_audience_mismatch`. `nonce` is not checked, because it binds a token to the browser session that requested it and the agent presenting the token here is not that session; the bearer risk remains until sender-constrained tokens exist.

Root tokens last `[issuer] default_ttl_seconds` (900 by default), not as long as the ID token. v0 does not cap them by the ID token's `exp`, and does not remember used ID tokens: the same ID token can be exchanged again by the same agent until it expires. Prefer short-lived ID tokens.

## Provider recipes

In every recipe, the **client id** is the id of the application the user logs in to; it goes under the agent's name in `client_ids` (these examples use an agent called `planner`). The **issuer** must match the `iss` claim exactly. Replace the placeholders.

### Keycloak (untested)

At Keycloak:

- Realm `acme`, an OIDC client (for example `agent-platform`) with the standard flow. Its client id goes in `client_ids`.
- Client scopes `openid`, `email` and `profile` give `sub`, `email` and the basics.
- For roles, add a mapper of type "User Realm Role" (or "User Client Role") to the client's dedicated scope with token claim name `roles`, multivalued, "Add to ID token" on. Without this, roles sit in a nested `realm_access.roles` claim that attenuo cannot use.
- For groups, add a "Group Membership" mapper with claim name `groups` and "Add to ID token" on.
- Keycloak does not send `amr` in ID tokens by default, to our knowledge. If that is right, `mfa` is always `false` until you add a mapper that emits it. Untested.

At attenuo:

```toml
[[idps]]
issuer = "https://keycloak.example.com/realms/acme"   # older Keycloak: .../auth/realms/acme
client_ids = { planner = "agent-platform" }
attribute_claims = ["email", "roles", "amr"]
```

Discovery is at `https://keycloak.example.com/realms/acme/.well-known/openid-configuration`.

### Auth0 (untested)

At Auth0:

- An application (Regular Web App or SPA) whose client id goes in `client_ids`.
- Under the application's advanced settings, make sure the ID token signing algorithm is **RS256**. HS256 is symmetric and attenuo refuses it.
- Custom claims in Auth0 must be namespaced URLs, set in a post-login Action, for example `https://example.com/roles`. List the full namespaced name in `attribute_claims`. Because the name is not `roles`, a Cedar policy cannot test it in v0.
- When a user completes MFA, Auth0 is expected to include `amr` with `mfa` in the ID token. This is not confirmed for any tenant.

At attenuo:

```toml
[[idps]]
issuer = "https://acme.us.auth0.com/"      # trailing slash: Auth0 puts one in `iss`
client_ids = { planner = "AUTH0_APP_CLIENT_ID" }
allowed_algs = ["RS256"]
attribute_claims = ["email", "amr"]
```

Auth0's `iss` ends with a slash and its discovery document repeats it. attenuo trims the slash only when it builds the discovery URL, so keep the slash in `issuer`. If you set it without the slash, you will get `untrusted_issuer`. Discovery is at `https://acme.us.auth0.com/.well-known/openid-configuration`.

Whether Auth0 for AI Agents issues ID-JAG assertions is unknown to us ("?").

### Okta (untested)

At Okta:

- An OIDC web app integration. Its client id goes in `client_ids`.
- Pick the authorization server. The org server issuer is `https://acme.okta.com`. A custom server's issuer is `https://acme.okta.com/oauth2/<id>`, and the built-in one is `https://acme.okta.com/oauth2/default`. Use the issuer that your app's ID tokens actually carry in `iss`.
- Add a groups claim to the ID token (a claim named `groups` with a filter), or name it `roles` if you want policy to see it.
- Okta ID tokens are expected to carry `amr`. Check which values appear for your sign-on policy: only `mfa`, `otp`, `hwk` and `swk` count.

At attenuo:

```toml
[[idps]]
issuer = "https://acme.okta.com/oauth2/default"
client_ids = { planner = "0oa1b2c3d4EXAMPLE" }
attribute_claims = ["email", "groups", "amr"]
```

Okta Cross App Access and Agent SSO issue ID-JAG assertions, per the sources in [the standards note](../research/standards.md#id-jag-identity-assertion-jwt-authorization-grant-and-cross-app-access). See [ID-JAG](#id-jag) below. The console steps to register attenuo as the target of an ID-JAG are not covered here, and they have not been tried.

### Entra ID (untested)

At Entra:

- An app registration. Its Application (client) ID goes in `client_ids`. Use the v2.0 endpoints, so that ID tokens carry the v2.0 issuer.
- Single-tenant: `https://login.microsoftonline.com/<tenant-id>/v2.0`. Use the tenant id, not `common` or `organizations`: those serve a templated issuer that would not match.
- Optional claims for the ID token: `email`. App roles arrive as a `roles` claim of strings, which matches the attribute Cedar knows about. The `groups` claim carries group object ids, and above a size limit the token carries a pointer (an "overage") instead. attenuo does not follow it.
- `sub` is unique per user per application.
- `amr` is expected in v2.0 tokens, with `pwd` and `mfa`. Not confirmed here.

At attenuo:

```toml
[[idps]]
issuer = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
client_ids = { planner = "66666666-7777-8888-9999-000000000000" }
attribute_claims = ["email", "roles", "amr"]
```

Discovery is at `.../v2.0/.well-known/openid-configuration` under the same prefix. As of the sources in [the standards note](../research/standards.md), Entra Agent ID does not ship ID-JAG, so use ID tokens.

### Google (untested)

At Google Cloud:

- An OAuth 2.0 client (Web application) in the Google Cloud console. Its client id goes in `client_ids`.
- Google ID tokens carry `sub`, `email`, `email_verified`, and `hd` for Workspace accounts. They carry no groups and no `amr`.

At attenuo:

```toml
[[idps]]
issuer = "https://accounts.google.com"
client_ids = { planner = "1234567890-abcdefg.apps.googleusercontent.com" }
attribute_claims = ["email", "hd"]
```

Because there is no `amr`, `mfa` is always `false` for Google users. Policies that require MFA will deny them. Google's documentation says the `iss` is `https://accounts.google.com` and in some cases `accounts.google.com` without the scheme. attenuo accepts only the one you configure, so tokens with the other form fail with `untrusted_issuer`. We know of no Google product that issues ID-JAG.

### Any other OIDC provider

Anything that publishes `/.well-known/openid-configuration` and signs ID tokens with RS256, ES256 or EdDSA should work, for example Dex, Authentik or Zitadel. Set `issuer` to the value in the discovery document's `issuer` field and put your client id under the agent in `client_ids`. Not tested with any of them.

## ID-JAG

An ID-JAG (Identity Assertion JWT Authorization Grant, `draft-ietf-oauth-identity-assertion-authz-grant`) is a JWT an IdP issues to say: this client may act for this user toward this resource. attenuo accepts it as an alternative to an ID token at hop 0. It follows **draft -04**. Drafts change. The claim mapping is isolated in one function (`idp::claims::map_id_jag`) so it can follow the draft.

What attenuo checks:

- Header `typ` is `oauth-id-jag+jwt`.
- `iss` is a configured `[[idps]]` issuer, and the signature verifies with that IdP's keys.
- `aud` equals attenuo's own `[issuer] issuer`. This is not `[[idps]] audience`. The IdP has to be set up to issue assertions addressed to attenuo.
- `client_id` is present and equals the authenticated agent, so `[[agents]] id` must be the client id the IdP knows the agent by.
- `exp`, `iat`, `nbf`, `sub` as for an ID token.

The draft's `resource` and `scope` claims are not used. What the root token may carry comes from `[[root_grants]]`.

Two ways to send it:

```sh
# As a token exchange
curl -s -X POST https://attenuo.example.com/token -u planner:$SECRET \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode subject_token=$ID_JAG \
  --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:id-jag \
  --data-urlencode scope='github:read_file'

# As a JWT bearer grant
curl -s -X POST https://attenuo.example.com/token -u planner:$SECRET \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  --data-urlencode assertion=$ID_JAG \
  --data-urlencode scope='github:read_file'
```

Status: **untested against any real provider.** The server's tests use assertions it signs itself. Okta and Descope are the providers named in [the standards note](../research/standards.md) as shipping ID-JAG. attenuo has not been run against either.

## Workload identity for sub-agents

Hop 0 is about the user. Every later hop is about an agent: the caller of an exchange must prove it is the `actor` it names. Besides an `[[agents]]` client secret, it can send an RFC 8693 `actor_token`: a JWT that a workload-identity system issued to that agent. attenuo verifies it against an `[[actor_trust]]` entry and maps its `sub` to an agent id, which must equal `actor`.

**Status: tested only with tokens the server's tests sign themselves.** The SPIRE settings below follow SPIRE's documentation and have not been run against a live SPIRE deployment.

### SPIRE (untested)

SPIRE issues JWT-SVIDs whose `sub` is the workload's SPIFFE ID, for example `spiffe://example.org/ns/agents/sa/coder`. Their signing keys are in the trust bundle, which the SPIRE server serves from its bundle endpoint (`federation { bundle_endpoint { ... } }` in `server.conf`). attenuo fetches that URL as a JWKS and keeps the keys with `use` = `jwt-svid`. It never discovers the URL: you give it.

```toml
[token]
actor_auth = "either"          # or "actor_token" once every agent has an identity

[[actor_trust]]
spiffe_trust_domain = "example.org"
spiffe_bundle_url = "https://spire-server.example.org:8443"
audience = "https://attenuo.example.com"
# Map SPIFFE IDs to the agent ids your policies and root grants use.
subject_to_agent = { "spiffe://example.org/ns/agents/sa/coder" = "coder", "spiffe://example.org/ns/agents/sa/reviewer" = "reviewer" }
# Or take the path as the agent id: spiffe://example.org/agents/coder -> "agents/coder".
# subject_to_agent = "spiffe_path"
allowed_algs = ["ES256", "RS256"]
```

The bundle endpoint's TLS certificate must be one attenuo trusts through the web PKI (SPIRE's `https_web` profile, or a TLS proxy in front). If you run the SPIRE OIDC Discovery Provider instead, configure `jwt_issuer` in SPIRE so JWT-SVIDs carry an `iss`, and use a generic entry: `issuer = "<jwt_issuer>"`, `jwks_url = "https://<discovery provider>/keys"`, plus the same `audience` and `subject_to_agent`.

The agent fetches a JWT-SVID with attenuo's URL as the audience and sends it on the exchange:

```sh
spire-agent api fetch jwt -audience https://attenuo.example.com \
  -socketPath /run/spire/sockets/agent.sock
ATTENUO_TOKEN="$PARENT" attenuo token exchange --actor coder \
  --cap github:read_file --actor-token -   # reads the JWT-SVID from stdin
```

What attenuo checks: the entry (by `iss` when the entry has `issuer`, by the trust domain of `sub`), `alg` in `allowed_algs`, the key by `kid`, the signature, `aud` contains `audience`, `exp` is present and not past, `nbf` and `iat` are not in the future, and `sub` is a well-formed SPIFFE ID in the trust domain. Then `subject_to_agent` must give the exchange's `actor`.

Each actor token authenticates one exchange: a second use is `invalid_grant` / `replayed`. The SPIRE agent caches JWT-SVIDs and may hand out the same one until it is half expired, so fetch a new one per exchange; asking with an extra, unique audience next to attenuo's URL gets a fresh token, and attenuo accepts an `aud` array that contains its own value. The child token never outlives the actor token, so with SPIRE's default five-minute JWT-SVIDs a child lives at most five minutes. Use leases and renewals for longer work.

### Hop 0 with a JWT-SVID

The agent that presents the user's ID token can authenticate the same way, so no agent needs an `[[agents]]` secret at all. Send the JWT-SVID as `actor_token` next to the ID token:

```sh
SVID=$(spire-agent api fetch jwt -audience https://attenuo.example.com \
  -socketPath /run/spire/sockets/agent.sock | sed -n 2p | tr -d '[:space:]')
curl -s https://attenuo.example.com/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$ID_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  -d actor=planner \
  -d scope="github:read_file github:create_issue" \
  -d actor_token="$SVID" \
  -d actor_token_type=urn:ietf:params:oauth:token-type:jwt
```

From the SDKs: `ob.exchange(id_token, "planner", ["github:*"], actor_token=svid)` (Python) or `ob.exchange(idToken, "planner", ["github:*"], { actorToken: svid })` (TypeScript).

The agent the SVID maps to (here `spiffe://example.org/ns/agents/sa/planner` to `planner`) is the root hop's agent. It must equal `actor` and `client_id` when the request sends them (`actor_mismatch`), the ID token's `aud` must be that agent's client id (`[[idps]] client_ids`), and a `[[root_grants]]` entry must exist for it. The rules are the exchange's: `[token] actor_auth` decides which methods are accepted (`"actor_token"` refuses client secrets here too; `"either"` checks both when both are sent), the SVID is used once, and the root token never outlives it. The ID token and the SVID are recorded as used together, so a request refused for one does not spend the other.

### Any other workload JWT

Anything that signs JWTs with RS256, ES256 or EdDSA and publishes a JWKS works the same way: Kubernetes projected service-account tokens, a cloud provider's workload identity tokens, your own issuer.

```toml
[[actor_trust]]
issuer = "https://kubernetes.default.svc.cluster.local"
jwks_url = "https://k8s-api.example.com/openid/v1/jwks"
audience = "https://attenuo.example.com"
subject_to_agent = { "system:serviceaccount:agents:coder" = "coder" }
```

Pick an `audience` that only attenuo accepts. A token minted for some other service must not double as an actor token.

### `may_act`: who may exchange a token next

A token can name the agents allowed to exchange it, as the RFC 8693 §4.4 `may_act` claim. Set it on the exchange that mints the token (`"may_act": ["reviewer"]`), on the intake request at hop 0, or as a ceiling in `[[root_grants]]`:

```toml
[[root_grants]]
issuer = "https://idp.example.com"
agent = "planner"
capabilities = ["github:*"]
may_act = ["coder", "reviewer"]   # only these may receive a delegation from planner's root token
```

An exchange whose `actor` is not listed fails with `invalid_request` / `actor_not_permitted`. A request may narrow a grant's list but not widen it (`may_act_exceeds_grant`). Tokens without `may_act` can be exchanged by any authenticated agent, as before.

## Checking your setup

Before you point an agent at it:

1. Fetch the discovery document and compare its `issuer` with your config, byte for byte:

   ```sh
   curl -s https://idp.example.com/realms/acme/.well-known/openid-configuration | jq '{issuer, jwks_uri, id_token_signing_alg_values_supported}'
   ```

2. Get a real ID token from a login and look at its claims:

   ```sh
   echo "$ID_TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{iss, aud, sub, exp, amr, email, roles, groups}'
   ```

   `iss` must equal `issuer`. `aud` must contain the client id you set for the agent in `client_ids` (it may be an array, in which case `azp` must equal it too). Check the header too: `cut -d. -f1` gives `alg` and `kid`. `alg` must be in `allowed_algs`.
3. Try the exchange:

   ```sh
   curl -s -X POST http://127.0.0.1:8080/token -u planner:$SECRET \
     --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
     --data-urlencode subject_token=$ID_TOKEN \
     --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:id_token \
     --data-urlencode scope='github:read_file'
   ```

4. Inspect the result. The user block should show the right subject, issuer and attributes:

   ```sh
   attenuo token inspect "$ROOT_TOKEN" --verify
   ```

### When it fails

Errors carry a stable `error_description`. The usual causes:

| Response | Cause |
| --- | --- |
| `401 invalid_client` / `client_authentication_failed` | Wrong agent id or secret, or the hash in `[[agents]]` was made from a different string. Check for a trailing newline: use `printf %s`, not `echo` |
| `401 invalid_client` / `no_agents_configured` | `[[agents]]` is empty |
| `400 invalid_grant` / `untrusted_issuer` | `iss` is not in `[[idps]]`. Look for a trailing slash, `http` against `https`, or a tenant id mismatch |
| `400 invalid_grant` / `credential_audience_mismatch` | An ID token's `aud` (or `azp`) does not name the presenting agent's client id: the token was issued to another client, or `client_ids` has no entry for this agent and the id differs from the agent id |
| `400 invalid_grant` / `audience_mismatch` | An ID-JAG's `aud` is not `[issuer] issuer` |
| `400 invalid_grant` / `unsupported_alg` | The token's `alg` is not in `allowed_algs` |
| `400 invalid_grant` / `unknown_kid` | The signing key is not in the IdP's JWKS, even after a refetch |
| `400 invalid_grant` / `bad_signature`, `expired`, `not_yet_valid` | The token is bad, stale, or your clock is off by more than `clock_skew_seconds` |
| `400 invalid_grant` / `client_id_mismatch` | ID-JAG `client_id` is not the authenticated agent |
| `400 invalid_grant` / `typ_mismatch` | Wrong credential type for the `subject_token_type` you sent |
| `400 invalid_scope` / `no_root_grant` | No `[[root_grants]]` entry for this issuer and agent |
| `400 invalid_scope` / `scope_exceeds_grant` | The request asks for more than the entry allows |
| `503 temporarily_unavailable` / `jwks_unavailable` | attenuo cannot reach the IdP, or the JWKS or discovery document is bad. Failed refreshes drop old keys: there are no stale keys |

The server log shows each rejection with the issuer and the code.

The full flow, with a sequence diagram, is in [design/server.md](../design/server.md#hop-0-intake-from-an-identity-provider).
