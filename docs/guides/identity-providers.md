# Identity providers

attenuo does not log users in. It trusts your identity provider (IdP) for that, and builds the first token of every delegation chain from a credential the IdP issued. This guide shows how to wire that up, with config for Keycloak, Auth0, Okta, Entra ID and Google.

**Read this first: what was tested.**

- The config keys, the claim mapping and the error codes below come from the code in `crates/attenuo-server/src/config.rs` and `crates/attenuo-server/src/idp/`. The server's own tests exercise them with locally signed tokens. Config shapes in this guide were parsed by the real server.
- [examples/idp-exchange-demo](https://github.com/attenuo-dev/attenuo/blob/main/examples/idp-exchange-demo/README.md) runs hop 0 end to end, with the dev mint off: OIDC discovery, the JWKS fetch, an ES256 ID token exchanged at `POST /token`, the replay refusal, then a delegation and two proxied calls. Its identity provider is a local mock, for demonstration only, not a real provider.
- **Keycloak is the one provider run for real**: Keycloak 26.8.2 in dev mode (`start-dev`: plain HTTP on 127.0.0.1 and the built-in dev database), on 2026-11-14, with [`scripts/live-keycloak-smoke.sh`](https://github.com/attenuo-dev/attenuo/blob/main/scripts/live-keycloak-smoke.sh). The [Keycloak section](#keycloak-tested-2682-dev-mode) says which of its statements that run checked. A production Keycloak (HTTPS, a real database, several nodes) and other Keycloak versions were not tried.
- **SPIRE was run too**: SPIRE 1.16.0 (server, agent and OIDC Discovery Provider from the release tarball, `join_token` node attestor, `unix` workload attestor, 127.0.0.1 only), on 2026-11-14, with [`scripts/live-spire-smoke.sh`](https://github.com/attenuo-dev/attenuo/blob/main/scripts/live-spire-smoke.sh). The [SPIRE section](#spire-tested-1160-join-token-attestor) says which of its statements that run checked. A production SPIRE (a real node attestor such as `k8s_psat` or `aws_iid`, the Kubernetes workload attestor, federation, several servers) was not tried.
- **No other provider-specific setup in this guide was run against a live provider.** The Auth0, Okta, Entra ID and Google sections and ID-JAG are marked **untested**. Their issuer formats, claim names and console steps come from the providers' public conventions and may be out of date or wrong for your tenant. Check each against your tenant before relying on it, using [Checking your setup](#checking-your-setup).

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
# ca_pem_path = "/etc/attenuo/idp-ca.pem"         # optional, a private CA for this IdP
allowed_algs = ["RS256", "ES256", "EdDSA"]        # default
attribute_claims = ["email", "groups", "amr"]     # default
jwks_ttl_seconds = 300                            # default
clock_skew_seconds = 60                           # default
# tenant = "acme"                                 # optional, ID-JAG only
# credentials = ["id_token", "id-jag"]            # default: both kinds
```

| Key | Meaning |
| --- | --- |
| `issuer` | Required. Compared byte for byte with the token's `iss` and with the `issuer` in the discovery document. A trailing slash counts. |
| `client_ids` | Table of agent id to the client id registered for that agent at the IdP, the application that ran the login. An ID token is accepted only when its `aud` contains the presenting agent's client id, and its `azp` equals it when `aud` has several values or `azp` is present. An agent with no entry must have a client id equal to its agent id; the server logs a warning at startup for each such agent. Not used for an ID-JAG, whose `aud` must be attenuo's own `[issuer] issuer` and whose `client_id` must be the agent. |
| `audience` | Deprecated. Ignored for ID tokens since SR-37, which needed the audience to be per agent. Existing configs still load; the server logs a warning when it is set. |
| `jwks_url` | Where to fetch signing keys. When absent, attenuo reads `jwks_uri` from `<issuer>/.well-known/openid-configuration`. Every key fetch must be `https://` (plain `http://` is accepted only for a loopback host, for local testing), and redirects are not followed, so give the final URL. |
| `ca_pem_path` | Optional. A PEM file of CA certificates that this entry's key fetches (discovery, JWKS, the refetch on an unknown `kid`) trust in addition to the built-in web PKI roots, for an IdP whose certificate a private CA issued. See [Private CAs for key URLs](#private-cas-for-key-urls). |
| `allowed_algs` | Accepted JWS algorithms. Asymmetric only: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `PS256` and so on. A symmetric algorithm such as `HS256` is refused when the config loads. |
| `attribute_claims` | Claims copied verbatim into `originating_user.attributes`, when present and not null. |
| `jwks_ttl_seconds` | How long fetched keys are used before refetching. A token with an unknown `kid` triggers one early refetch, at most once per 30 seconds. |
| `clock_skew_seconds` | Leeway for `exp`, `iat` and `nbf`. |
| `tenant` | Optional. For a multi-tenant issuer: the tenant whose users this entry trusts. An ID-JAG must then carry a `tenant` claim equal to it, else `missing_claim` or `tenant_mismatch` ([ID-JAG](#id-jag)). ID tokens are not affected. Unset by default: `tenant` is not checked. |
| `credentials` | Which credentials this issuer's users may be brought in with at hop 0: `"id_token"`, `"id-jag"` or both (the default). A kind not listed is refused with `credential_type_not_accepted` before it is checked or used up. Set `["id-jag"]` with [the ceiling](#id-jag) so that an ID token cannot get past it. |
| `id_jag_ceiling` | Optional table: the ID-JAG's own claims as a ceiling under the root grant ([ID-JAG](#id-jag)). |

You can list several IdPs. The unverified `iss` selects the entry. An issuer that is not listed is rejected without any network call.

### Private CAs for key URLs

attenuo checks the certificate of every key URL (an IdP's discovery document and JWKS, an `[[actor_trust]]` JWKS or SPIFFE bundle endpoint) against the Mozilla root set built into it (the `webpki-roots` crate), not against the system's trust store. An IdP or a bundle endpoint whose certificate a private CA issued is refused: the request that needed its keys fails with `503 temporarily_unavailable` / `jwks_unavailable`, and the server log names the TLS cause. To trust such a CA, put its certificate (PEM; several are fine) in a file and name it in that entry:

```toml
[[idps]]
issuer = "https://idp.corp.example/realms/acme"
ca_pem_path = "/etc/attenuo/corp-ca.pem"
```

The server refuses to start when the file is missing, unreadable or empty, or holds no usable certificate. It reads the file once, at start; no reload re-reads it, so restart after replacing it.

Why additive: the file adds roots to the built-in ones and never replaces them, so naming a private CA cannot make a public IdP stop working, and no setting can turn verification or the hostname check off; the certificate must still be valid for the URL's host, the `https://` rule stays, and redirects are still refused. Why per entry: a CA trusted for one key URL is a CA that can sign keys for that issuer, so it is trusted for the entry that names it and nothing else. Another `[[idps]]` or `[[actor_trust]]` entry, and the server's other outbound connections (the audit sink, approval notifications, trace export), keep the built-in roots alone, and a private CA for the SPIRE server does not become able to vouch for your IdP.

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
- Secrets are static. To rotate one, edit the entry and run `attenuo admin agent reload` (or restart); see [Deploying](deploying.md#adding-or-rotating-an-agent-without-a-restart). To keep no shared secret on the server at all, give the agent a key pair or a TLS client certificate instead (below).
- If an `actor` is sent on an intake request it must equal the authenticated agent.

### A key instead of a secret

An entry can hold public keys instead of, or next to, the secret hash. The agent then proves who it is with a short-lived JWT it signs (RFC 7523 client authentication, `private_key_jwt`), and the server stores nothing that would let anyone else sign one:

```sh
attenuo key gen --client planner-client.jwk --kid planner-1
# wrote client key planner-client.jwk (EdDSA, kid planner-1)
# add to the agent's [[agents]] (or the PEP's [[peps]]) entry:
# jwks = '''{"keys":[{"kty":"OKP","crv":"Ed25519","x":"…","kid":"planner-1","alg":"EdDSA","use":"sig"}]}'''
```

```toml
[[agents]]
id = "planner"
jwks = '''{"keys":[{"kty":"OKP","crv":"Ed25519","x":"…","kid":"planner-1","alg":"EdDSA","use":"sig"}]}'''
```

The private key file stays with the agent. On each request it sends `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion`, a JWT with `iss` and `sub` = `planner`, `aud` = the server's `[issuer] issuer` (not the token endpoint URL), a short `exp` and a fresh `jti`; each assertion is accepted once. The CLI does this with `--client-key`, the SDKs with `DpopKey.client_assertion` (Python) and `clientAssertion` (TypeScript). Two refusals leave the assertion unused, because the client is told to send the same request again: `use_dpop_nonce` under `[token] dpop_nonce = "required"`, and `429 rate_limited` from `[limits] token_requests_per_minute`. The CLI and both SDKs send the same assertion on the nonce retry, and the SDKs on their opt-in load retry (`max_retries`, `maxRetries`); the integration tests check each against a real server. The load retry is not made when its wait (the `Retry-After`, up to a minute) would reach the assertion's `exp`: the SDK raises the 429 instead, and the agent mints a new assertion and calls again, or mints assertions with a `lifetime` that covers the waits, at most `[token] client_assertion_max_lifetime_seconds`. Treat an assertion as spent after any other answer. The full list of checks and refusal codes is in the [HTTP API reference](../reference/http-api.md#client-authentication). To rotate, add the new key with its own `kid` next to the old one, run `attenuo admin agent reload` (or restart), switch the agent, then remove the old key and reload again ([Deploying](deploying.md#adding-or-rotating-an-agent-without-a-restart)). A spent assertion stays spent across a reload.

- The same `[[agents]]` entries authenticate sub-agents: a token exchange must authenticate as its `actor`. Give every agent that receives delegated tokens an entry, or a workload identity under [`[[actor_trust]]`](#workload-identity-for-sub-agents).
- Each ID token or ID-JAG mints one root token. A second presentation, by any agent, is `invalid_grant` / `replayed` (keyed by `iss` and `jti`, or by the whole token when it has no `jti`). The root token expires no later than the credential, and a credential accepted only thanks to `clock_skew_seconds` is refused with `credential_expired`. The record of used credentials is kept in the server's database (`[audit] sqlite_path`), so it survives a restart; it is not shared with a server on another database file.

### Keys at a URL the agent publishes

Instead of `jwks`, an entry can name a URL where the agent (or its platform) publishes its public keys, as a JWK Set. The agent then rotates its keys itself, with no change to attenuo's config and no reload:

```toml
[[agents]]
id = "planner"
jwks_url = "https://planner.example.com/.well-known/jwks.json"
# jwks_ttl_seconds = 300                     # default
# ca_pem_path = "/etc/attenuo/planner-ca.pem" # for a private CA
```

The rules are those of the `[[idps]]` key URLs: `https://` only (plain `http://` only on loopback), no redirects, at most 256 KiB, 5 seconds, and `ca_pem_path` for a private CA ([private CAs for key URLs](#private-cas-for-key-urls)). The set must pass the rules of `jwks`, but keys for other uses (`use: "enc"`, a curve or algorithm attenuo does not accept) are skipped; a set with a private key in it is refused whole. Nothing is fetched at startup. Keys are kept for `jwks_ttl_seconds`; an assertion with a `kid` that is not in the set fetches it again at once, at most once per 30 seconds, so a new key works within 30 seconds at most. To rotate: publish the new key next to the old one, wait at least 30 seconds, switch the agent to it, then remove the old key. A removed key stops working at the latest `jwks_ttl_seconds` after the last fetch, so lower it if that must be sooner. One entry has `jwks` or `jwks_url`, never both.

Whoever controls the URL controls the agent's identity at attenuo, so serve it from a place only the agent's owner can change. If attenuo cannot fetch the set, the agent is refused with the answer an unknown client gets (`client_authentication_failed`), and the server logs `client JWKS unavailable` at warn level with the cause. The full rules are in the [config reference](../reference/config.md#keys-from-a-url).

### TLS client certificates

An agent or a PEP can also prove who it is with a self-signed TLS client certificate (RFC 8705 `self_signed_tls_client_auth`). The server keeps only the certificate's SHA-256 thumbprint. The client keeps the private key.

This works when the client connects to attenuo's own TLS listener: directly, or through a TCP (layer 4) pass-through. See [TLS in attenuo itself](deploying.md#tls-in-attenuo-itself). A proxy that ends TLS in front of attenuo hides the certificate, unless it forwards it in the `Client-Cert` header to a listener set aside for that ([behind a TLS-terminating proxy](#behind-a-tls-terminating-proxy)).

**1. Make a key and a certificate.** The certificate must not be a CA certificate, and its extended key usage must allow client authentication. A plain `openssl req -x509` makes a CA certificate, which attenuo refuses, so add the two `-addext` lines:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout planner-client.key -out planner-client.crt -days 90 -subj "/CN=planner" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "extendedKeyUsage=clientAuth"
chmod 600 planner-client.key
```

Ed25519 (`-newkey ed25519`) and RSA (`-newkey rsa:2048`) work too. The name in `-subj` is for you: attenuo does not read it.

**2. Get the thumbprint.** It is the SHA-256 of the certificate in DER form, in lowercase hex:

```sh
openssl x509 -in planner-client.crt -outform DER | sha256sum | cut -d' ' -f1
```

(`openssl x509 -noout -fingerprint -sha256` prints the same value in upper case with colons. attenuo wants lower case and no colons.)

**3. Configure.** Ask for client certificates on the listener, and put the thumbprint on the entry:

```toml
[server.tls]
cert_pem_path = "/etc/attenuo/tls/server.crt"
key_pem_path = "/etc/attenuo/tls/server.key"
client_certificates = "optional"

[[agents]]
id = "planner"
tls_client_cert_sha256 = ["324c5a7527fbc287fad0d167b264a16419c02bafaca3f95978bab6ceda220291"]
```

The client sends the certificate in the handshake and `client_id` in the body, with no secret:

```sh
curl --cert planner-client.crt --key planner-client.key --cacert server-ca.pem \
  https://attenuo.example.com:8443/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$ID_TOKEN" -d subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  -d client_id=planner
```

A PEP sends `pep_id` in the evaluation body instead.

The `attenuo` CLI presents the certificate with `--tls-client-cert` and `--tls-client-key` (or `ATTENUO_TLS_CLIENT_CERT` and `ATTENUO_TLS_CLIENT_KEY`). `token exchange` then sends `client_id` and no secret. Give the server's CA with `--tls-ca-cert` too when its certificate comes from a private CA. The same hop-0 exchange as the `curl` above:

```sh
ATTENUO_TOKEN="$ID_TOKEN" attenuo --server https://attenuo.example.com:8443 \
  --tls-ca-cert server-ca.pem \
  --tls-client-cert planner-client.crt --tls-client-key planner-client.key \
  token exchange --subject-token-type id-token --actor planner --cap 'github:*'
```

The CLI sends the certificate only to the origin of `--server`, never to an `--admin-server` or a `--jwks` URL on another origin, and it reads the key file once. It needs an `https://` `--server`. One exception: through an `https://` proxy (`HTTPS_PROXY=https://...`), the proxy is offered the certificate too if it asks for one, and its own certificate must chain to `--tls-ca-cert`. It sends no `client_id` when you pass an actor token (see the notes below). The CLI has no PEP mode, so it does not send `pep_id`.

The Python and TypeScript SDKs take the same three files. The certificate goes only to the origin of the server URL, and `exchange` without a secret, a client assertion or an actor token sends `client_id` and no secret. The proxy exception is different: Python reaches an `https://` proxy with httpx's default roots and never offers it the client certificate, and the TypeScript options use no proxy at all.

```python
from attenuo import Client

with Client(
    "https://attenuo.example.com:8443",
    tls_ca_cert="server-ca.pem",
    tls_client_cert="planner-client.crt",
    tls_client_key="planner-client.key",
) as ob:
    planner = ob.exchange(id_token, "planner", ["github:*"])
```

```ts
import { AttenuoClient } from "@attenuo/sdk";

const ob = new AttenuoClient("https://attenuo.example.com:8443", {
  tlsCaCert: "server-ca.pem",
  tlsClientCert: "planner-client.crt",
  tlsClientKey: "planner-client.key",
});
const planner = await ob.exchange(idToken, "planner", ["github:*"]);
```

The SDKs work the same way with a certificate from a CA ([below](#tls-client-certificates-from-a-ca-spiffe)): put the intermediate CA certificates after the client certificate in the `tls_client_cert` (`tlsClientCert`) file, at most 4. Both SDKs' integration tests run an exchange with such a file against the server, and check that the client certificate alone, without its intermediate, gets `401`. The TypeScript options need Node.js 20.16 or later. The SDKs have no PEP mode either, and they do not read the `ATTENUO_TLS_*` variables. The details are in the [Python](https://github.com/attenuo-dev/attenuo/blob/main/sdk/python/README.md#tls-a-private-ca-and-a-client-certificate) and [TypeScript](https://github.com/attenuo-dev/attenuo/blob/main/sdk/typescript/README.md#tls-a-private-ca-and-a-client-certificate) READMEs.

**4. Rotate.** An entry takes up to 8 thumbprints. Add the new certificate's thumbprint next to the old one and run `attenuo admin agent reload`. Move the client to the new certificate. Then remove the old thumbprint and reload again. A removed thumbprint stops working on the next request, also on a connection that is already open. A token bound to the old certificate does not work with the new one: get new tokens after the switch.

Notes:

- `"optional"` means the server asks every client for a certificate but never requires one. Clients without one still connect and use a secret or a key.
- If a request carries a secret or a client assertion too, that one decides. The certificate is then ignored.
- A certificate on the connection makes `client_id` a credential, also next to an actor token. With an actor token, send no `client_id`, or present no certificate: otherwise the certificate counts too. Under `[token] actor_auth = "actor_token"` the request is then refused with `client_auth_not_accepted`, whatever the certificate. Under `"either"` it is refused with `client_authentication_failed` when the certificate is not pinned for that id.
- The certificate's dates are checked on every request. An expired certificate stops working without a reload, so renew it in time.
- There is no CRL or OCSP check. To revoke a certificate, remove its thumbprint and reload. CRL files apply to certificates from a CA only.
- Tokens issued this way are bearer tokens (or DPoP-bound, if the client sends a DPoP proof). With `[token] tls_client_certificate_bound_access_tokens = true` they are bound to the certificate instead, and every later request with them must show it ([binding tokens to a TLS client certificate](binding-tokens-to-keys.md#binding-tokens-to-a-tls-client-certificate)).
- Every refusal is the same `401 client_authentication_failed`. The reason is in the server's debug log.

The full rules are in the [config reference](../reference/config.md#tls-client-certificates).

### TLS client certificates from a CA (SPIFFE)

Instead of pinning each certificate, an entry can trust a CA and one name (RFC 8705 `tls_client_auth`). The CA issues and renews certificates, and attenuo's config does not change. This fits SPIFFE: SPIRE gives each workload an X.509-SVID whose only URI name is its SPIFFE ID.

The listener rules above still apply: `client_certificates = "optional"`, and a direct connection or a TCP pass-through.

**1. A CA and a client certificate.** With SPIRE, the workload already has its SVID, its key and the trust bundle. Without SPIRE, `openssl` can play the CA. These commands make a CA and a certificate for the agent `coder` with its SPIFFE ID:

```sh
# The CA. Keep agents-ca.key away from attenuo.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout agents-ca.key -out agents-ca.pem -days 365 -subj "/CN=agents CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# A key and a request for the agent.
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout coder.key -out coder.csr -subj "/CN=coder"
chmod 600 coder.key

# The CA signs it, with the SPIFFE ID as the only URI name.
cat > coder.ext <<'END'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = URI:spiffe://example.org/ns/agents/sa/coder
END
openssl x509 -req -in coder.csr -CA agents-ca.pem -CAkey agents-ca.key \
  -CAcreateserial -days 30 -extfile coder.ext -out coder.crt
```

For a DNS name, use `subjectAltName = DNS:coder.agents.internal` instead. If an intermediate CA signs the certificate, the client must send it too: put it after the client certificate in the file the client presents.

**2. Configure.** Put only the CA certificate on the server, never its key:

```toml
[server.tls]
cert_pem_path = "/etc/attenuo/tls/server.crt"
key_pem_path = "/etc/attenuo/tls/server.key"
client_certificates = "optional"

[[agents]]
id = "coder"
tls_client_ca_pem_path = "/etc/attenuo/agents-ca.pem"
tls_client_auth_san_uri = "spiffe://example.org/ns/agents/sa/coder"
# or: tls_client_auth_san_dns = "coder.agents.internal"
```

Each agent gets its own entry with its own name. Many entries can name the same CA file. A certificate for `reviewer` from the same CA never authenticates as `coder`.

**3. Call.** The client sends its certificate and `client_id`, with no secret. Here, an exchange:

```sh
curl --cert coder.crt --key coder.key --cacert server-ca.pem \
  https://attenuo.example.com:8443/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$PARENT_TOKEN" -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  -d actor=coder -d client_id=coder \
  --data-urlencode 'authorization_details=[{"type":"attenuo_capabilities","capabilities":[{"server":"github","tool":"read_file"}]}]'
```

The audit record says `actor_auth` = `tls_client_auth`. The same call with a certificate for `spiffe://example.org/ns/agents/sa/reviewer` gets `401 client_authentication_failed`, and the server's debug log says `reason="san_mismatch"` with the name it found.

**4. Rotate.** A new certificate from the same CA with the same name works at once, with no change. A token bound to the old certificate does not move to the new one, even with the same name: get new tokens with the new certificate. When the CA itself changes (SPIRE rotates its bundle), write the new CA certificates to the file, old and new together during the change, and run `attenuo admin agent reload`. The file may hold up to 16 CA certificates.

Notes:

- Only these names are matched: one URI (exactly, case-sensitive) or one DNS name (any case, never through a wildcard). The subject DN, its common name, IP addresses and e-mail addresses are not matched.
- For a `spiffe://` name, the certificate must carry exactly one URI name, as an X.509-SVID does.
- The dates of the certificate and its intermediates are checked on every request.
- The client may send at most 4 intermediate CA certificates. If it needs cross-certificates, it sends the one its path uses first: only the first one with a given subject is used.
- A certificate that also carries the name of another agent (or, for a PEP, another PEP) is refused. Extra names that no entry uses are fine. So adding an entry whose name is an extra SAN in another client's certificate (for example one of SPIRE's `dns_names`) makes that certificate be refused for both entries; the debug log says `certificate_names_several_clients`.
- A key-rollover link certificate (the new root signed by the old one) that the client sends is ignored, because it is self-issued: put the new root in the CA file.
- There is no OCSP check. To stop a certificate before it expires, list your CA's CRL ([below](#revoking-certificates-with-a-crl)), or remove the CA or change the name on the entry and reload. Short-lived certificates make this matter less.
- A CA you list can make a certificate for any name. List a CA only on the entries it should vouch for.

The full rules are in the [config reference](../reference/config.md#tls-client-certificates-from-a-ca).

#### Revoking certificates with a CRL

An entry can list CRL files from its CA. A certificate a CRL lists is refused on its next request, also on a connection that is already open. attenuo reads the files; it never fetches them.

**1. Make a CRL.** With the CA from step 1 above, `openssl ca` keeps a small database of revoked certificates:

```sh
# Once: the database and its config.
mkdir -p crl-db && touch crl-db/index.txt && echo 01 > crl-db/crlnumber
cat > crl.cnf <<'END'
[ca]
default_ca = agents

[agents]
database = crl-db/index.txt
crlnumber = crl-db/crlnumber
default_md = sha256
default_crl_days = 7
crl_extensions = crl_ext

[crl_ext]
authorityKeyIdentifier = keyid:always
END

# Revoke coder's certificate, then write a new CRL.
openssl ca -config crl.cnf -cert agents-ca.pem -keyfile agents-ca.key -revoke coder.crt
openssl ca -config crl.cnf -cert agents-ca.pem -keyfile agents-ca.key -gencrl -out agents-ca.crl
openssl crl -in agents-ca.crl -noout -text
```

Each `-gencrl` raises the CRL number, and the CRL is valid for `default_crl_days`. Run it again before then, also when nothing was revoked.

**2. Configure.**

```toml
[[agents]]
id = "coder"
tls_client_ca_pem_path = "/etc/attenuo/agents-ca.pem"
tls_client_auth_san_uri = "spiffe://example.org/ns/agents/sa/coder"
tls_client_crl_paths = ["/etc/attenuo/agents-ca.crl"]
```

If an intermediate CA issues the certificates, list its CRL too, and put the intermediate's certificate in `tls_client_crl_issuer_pem_path`, so attenuo knows its key. The root's CRL then covers the intermediate itself. If the intermediate is in `tls_client_ca_pem_path` as well (for clients that send no chain), the path ends there, and attenuo checks the intermediate in the root's CRL only when the root is in `tls_client_ca_pem_path` or `tls_client_crl_issuer_pem_path` too. So keep the root in the CA file next to the intermediate. Each certificate of `tls_client_crl_issuer_pem_path` must be valid now and issued by a CA allowed to sign certificates. Once the root's CRL revokes the intermediate, remove the intermediate's CRL from `tls_client_crl_paths` in the same reload: a revoked CA signs no CRL attenuo uses, and the reload is refused while it is listed.

**3. Reload after each new CRL.** Copy the new file into place in one step (write it next to the old one, then `mv`), and run `attenuo admin agent reload`. The reload reads every CRL again. It is refused, and the CRLs in force stay, when a file is broken, signed by another key, or older than the one in force (`client_crl_older`).

**What stale means.** A CRL is stale once its `nextUpdate` has passed. By default (`tls_client_crl_stale = "refuse"`) every certificate whose path needs that CRL is refused from that second on, with no reload: the server cannot tell whether it was revoked since. The answer is `401 client_certificate_revocation_unknown`. A server with a stale CRL does not start, and a reload with one is refused. So schedule the new CRL well before `nextUpdate`, and alert when the job fails. With `tls_client_crl_stale = "allow"`, a stale CRL is still used.

Notes:

- A revoked certificate gets `401 client_certificate_revoked`, logged at info level with its `x5t#S256`. Refusals are not audited.
- A CA with no CRL in the entry is not checked, unless `tls_client_crl_missing = "refuse"`. Under the default, the start and each reload log a warning naming each such CA by subject.
- A CA certificate in `tls_client_ca_pem_path` that is not self-signed, and whose issuer is in that file or in `tls_client_crl_issuer_pem_path`, is checked in its issuer's CRL like any intermediate, and a warning names it when that CRL lists it. A self-signed root, or a CA whose issuer neither file holds, cannot be revoked by a CRL: remove a compromised one from the file and reload.
- The rule that a reload never goes back to an older CRL compares with the CRLs in force only. A restart accepts any valid CRL, also an older one than before the restart. So does a reload after one that dropped that CA's CRL. Keep only the newest file in place.
- Pinned certificates (`tls_client_cert_sha256`) are not affected by CRLs.
- A token bound to a revoked certificate stops working too; see [binding tokens](binding-tokens-to-keys.md#binding-tokens-to-a-tls-client-certificate).

The full rules are in the [config reference](../reference/config.md#crl-files).

### Behind a TLS-terminating proxy

When TLS must end at a reverse proxy, the proxy can check the client's certificate and forward it to attenuo in the RFC 9440 headers `Client-Cert` and `Client-Cert-Chain`. Set `[server.forwarded_client_cert]` with a `listen` of its own and the proxy's addresses in `trusted_peers`, and point the proxy's backend there. The entries are the same: `tls_client_cert_sha256`, or `tls_client_ca_pem_path` with a name. The client does the same as above, against the proxy's URL.

What is different:

- attenuo sees no handshake. It trusts the proxy to have checked that the client holds the key. The proxy must remove any `Client-Cert` and `Client-Cert-Chain` the client sent and set them only from its own handshake.
- Anyone who can connect to the forwarding listener from a listed address can claim any certificate. Bind it where only the proxy reaches it.
- Every other listener refuses those headers with `400` while the section is set. So a client that sends them to the main listener fails at once.
- The audit records say `"source": "forwarded"` in `client_cert`; `actor_auth` and `agent_auth` are the same as on the native listener.
- With HAProxy, which sends no chain, put the intermediate CA in the entry's CA file. With CRLs, keep the root in that file too: the intermediate is then checked in the root's CRL, as when the client sends it.
- With certificate-bound tokens, the proxy must forward the certificate on every route that takes a token, not only on `/token`.

The setup, the fences, and a tested HAProxy recipe are in [forwarded client certificates](deploying.md#forwarded-client-certificates).

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

A root grant is the ceiling on what a root token for this issuer, this agent and (optionally) this user can carry. The request is attenuated against it. The most specific match wins: an entry pinned to a `subject` first, then one without. No match means no root token (`invalid_scope`, `no_root_grant`). Asking for more than the entry allows is `invalid_scope`, `scope_exceeds_grant`. A limit in the entry bounds the root token once: two requested capabilities under the same limited capability of the entry (`send_money` once per recipient under one `sum`) are refused with `invalid_scope`, `limit_split_at_root`; ask for one capability with a `one_of` constraint instead. A requested capability under one or more limited capabilities of the entry (a tighter one within a wider one) carries the limits of each (`[[root_grants]]` in the [configuration reference](../reference/config.md)).

Capabilities can be a `"server:tool"` string (globs allowed) or a table with constraints:

```toml
capabilities = [
  "github:read_*",
  { server = "github", tool = "create_issue", constraints = { repo = { op = "prefix", value = "acme/" } } },
]
```

`op` is `equals`, `one_of`, `prefix`, `path_prefix` or `range`; use `path_prefix`, not `prefix`, for a file path ([why](../concepts/capabilities-and-attenuation.md#prefixes-of-strings-and-of-paths)). Start narrow. A root token is the widest anything in the chain can be.

ID tokens are bearer credentials, bound to the agent that presents them only through `aud`/`azp` (SR-37): a token issued for agent A is refused from agent B with `credential_audience_mismatch`. `nonce` is not checked, because it binds a token to the browser session that requested it and the agent presenting the token here is not that session; the bearer risk remains until sender-constrained tokens exist.

Root tokens last `requested_ttl_seconds`, or `[issuer] default_ttl_seconds` (900 by default), capped at the ID token's remaining lifetime: a root token never outlives the credential it came from. Each credential mints one root token (`replayed` on a second presentation, see [`[[agents]]`](#agents)); the record of used credentials is in the server's database and survives a restart. Prefer short-lived ID tokens.

## Provider recipes

In every recipe, the **client id** is the id of the application the user logs in to; it goes under the agent's name in `client_ids` (these examples use an agent called `planner`). The **issuer** must match the `iss` claim exactly. Replace the placeholders.

### Keycloak (tested: 26.8.2, dev mode)

Run on 2026-11-14 against Keycloak 26.8.2 (`keycloak/keycloak:26.8.2`, `sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0`) in `start-dev` mode on 127.0.0.1, by [`scripts/live-keycloak-smoke.sh`](https://github.com/attenuo-dev/attenuo/blob/main/scripts/live-keycloak-smoke.sh). The script sets Keycloak up with `kcadm.sh` as the list below says, logs a test user in with the authorization-code flow (it posts Keycloak's login form as a browser would, so the client needs no direct access grant), and runs attenuo with the recipe below, its issuer replaced by the local `http://127.0.0.1:<port>/realms/acme` (plain `http://` is accepted only for a loopback host). Each statement below says whether that run checked it.

At Keycloak:

- Realm `acme`, an OIDC client (for example `agent-platform`) with the standard flow; the run used a confidential client. Its client id goes in `client_ids`. Keycloak puts the client id in the ID token's `aud` as a string and in `azp`, which is what attenuo checks; an ID token issued to another client of the realm is refused with `credential_audience_mismatch`. Tested.
- The login asks for the `openid` scope. The client's default scopes then give `sub` (the `basic` scope), `email` and `email_verified` (`email`), and the name claims (`profile`). There is no client scope called `openid`. Tested.
- For roles, add a mapper of type "User Realm Role" (or "User Client Role") to the client's dedicated scope with token claim name `roles`, multivalued, "Add to ID token" on. Without it the ID token has no role claim at all: Keycloak's default `roles` scope puts `realm_access.roles` in the access token only. Tested for the realm role mapper; the client role mapper was not run. The claim lists the realm's default roles (`default-roles-acme`, `offline_access`, `uma_authorization`) next to the user's own, and a policy on `roles` saw it (`context.originating_user.attributes.roles.contains(...)`). Keycloak 26.8.2 logs that the client's "Full scope allowed" switch, on by default and what lets every realm role reach the token, is deprecated; with it off, the roles must be in the client's scope. That case was not run.
- For groups, add a "Group Membership" mapper with claim name `groups` and "Add to ID token" on. Tested: created through the admin API without the "Full group path" option, it gives `["engineering"]`; with that option on, Keycloak sends the path (`/engineering`, not run). The recipe below does not copy `groups`: add it to `attribute_claims`, and declare it in `[policy] user_attributes` if a policy is to read it (not run).
- Keycloak 26.8.2 does not send `amr` in ID tokens by default. Tested: `mfa` is `false`, and a policy that requires `mfa` denies (`policy_deny`). Keycloak has a mapper of type "Authentication Method Reference (AMR)"; added to the client, it sends `amr: []` until the steps of the login flow carry a reference value. With `pwd` set as the reference of the "Username Password Form" step it sends `["pwd"]`, which does not set `mfa`. Both tested. Setting `otp` (or `mfa`) as the reference of the OTP step, for a user who logs in with a second factor, should give `mfa = true`; not tested.
- Keycloak signs ID tokens with RS256 by default, which the default `allowed_algs` accepts; the realm's JWKS also carries an `RSA-OAEP` encryption key, which does not get in the way. Tested.
- Key rotation: after a new RS256 key provider with a higher priority was added to the realm, the next ID token carried the new `kid`, attenuo fetched the JWKS again once (`unknown kid; refetching JWKS` in its log) and accepted the token. Tested, more than 30 seconds after the previous fetch, the floor between early refetches.
- ID tokens live 300 seconds by default, so a root token from one lives at most 300 seconds. Tested (`expires_in` 300).

At attenuo:

```toml
[[idps]]
issuer = "https://keycloak.example.com/realms/acme"   # older Keycloak, or --http-relative-path=/auth: .../auth/realms/acme (not tested)
client_ids = { planner = "agent-platform" }
attribute_claims = ["email", "roles", "amr"]
```

Discovery is at `https://keycloak.example.com/realms/acme/.well-known/openid-configuration`; its `issuer` is the realm URL, byte for byte. Tested over plain HTTP on loopback; Keycloak behind HTTPS was not run.

What the run did with that recipe, all passing: hop 0 with the `curl` command of [Checking your setup](#checking-your-setup) (with `authorization_details`, see there), the same ID token again (`replayed`), `attenuo token inspect --verify` of the root token (issuer, `email`, `roles`, `mfa=false`), hop 0 with the Python SDK (`Client.exchange(id_token, "planner", caps, client_id="planner", client_secret=...)`) and the TypeScript SDK (`AttenuoClient.exchange(idToken, "planner", caps, { clientId, clientSecret })`), each followed by `inspect` with verification, whose header `kid` is the one in the server's JWKS; hop 0 with the CLI (`attenuo token exchange --subject-token-type id-token`, see [Checking your setup](#checking-your-setup)), followed by `inspect --verify` (issuer, `roles`), and the same ID token again through the CLI (`invalid_grant`, already used); then a narrowed child exchange with the CLI and calls through the proxy: one allowed, one `capability_denied`, and one `policy_deny` for want of `mfa`; and `attenuo audit verify`. The CLI hop-0 step was added to the script after the first run and checked in a second run of it, against the same pinned image, on the same day.

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

An ID-JAG (Identity Assertion JWT Authorization Grant, `draft-ietf-oauth-identity-assertion-authz-grant`) is a JWT an IdP issues to say: this client may act for this user toward this resource. attenuo accepts it as an alternative to an ID token at hop 0. It was written against draft -04 and checked on 2026-11-13 against **draft -06** (31 October 2026); [the standards note](../research/standards.md#id-jag-conformance-against--06) has the conformance table. Drafts change. The claim mapping is isolated in one function (`idp::claims::map_id_jag`) so it can follow the draft.

What attenuo checks:

- Header `typ` is `oauth-id-jag+jwt`, in any case, with or without the `application/` prefix (RFC 7515 §4.1.9).
- `iss` is a configured `[[idps]]` issuer, and the signature verifies with that IdP's keys and one of its `allowed_algs`.
- `aud` equals attenuo's own `[issuer] issuer`, as a string or as an array with exactly one element (draft §4.4.1). An array that also names another authorization server is refused. This is not `[[idps]] audience`. The IdP has to be set up to issue assertions addressed to attenuo.
- `client_id` is present and equals the authenticated agent, so `[[agents]] id` must be the client id the IdP knows the agent by.
- `jti` is present (REQUIRED in the draft); each ID-JAG is accepted once.
- `exp`, `iat`, `nbf`, `sub` as for an ID token.
- With `[[idps]] tenant` set, `tenant` is present and equal to it (see below).
- With a `cnf` claim (a sender-constrained ID-JAG), the request carries a DPoP proof by the key in `cnf.jkt`, and the root token is bound to that key. Without a proof the request fails with `credential_pop_required`, with a proof by another key with `credential_pop_mismatch`. A `cnf` without `jkt` (for example an mTLS certificate binding) is refused with `credential_pop_required`, because attenuo cannot check it, and so is any `cnf` when `[token] dpop = "off"`.

The agent always authenticates (client secret, client assertion or actor token), even for a sender-constrained ID-JAG; the draft only requires one or the other.

By default the draft's `resource`, `scope` and `authorization_details` claims are not used: what the root token may carry comes from `[[root_grants]]` and the request, and an IdP that narrows an ID-JAG to one resource does not narrow the root token. `aud_tenant`, `aud_sub` and `sub_id` are never used: the user is `sub`.

**The ID-JAG's claims as a ceiling.** Add `[idps.id_jag_ceiling]` to the IdP's entry and the root token carries no more than both the root grant and the ID-JAG allow. attenuo does not guess what a resource URL or a scope means, so you write down the mapping:

```toml
[[idps]]
issuer = "https://idp.example.com"
credentials = ["id-jag"]   # ID tokens from this issuer would get past the ceiling

[idps.id_jag_ceiling]
# resource (RFC 8707) -> upstream servers; each stands for <server>:*
resources = { "https://mcp.example.com/github" = ["github"] }
# scope token -> capabilities, as in [[root_grants]] capabilities
scopes = { "repo.read" = ["github:read_file", "github:list_*"] }

[[root_grants]]
issuer = "https://idp.example.com"
agent = "planner"
capabilities = ["github:*", "slack:*"]
```

With this, an ID-JAG with `resource = "https://mcp.example.com/github"` gives at most `github:*` (slack is out), one with `scope = "repo.read"` at most the two read tools, and one with both their intersection. An `authorization_details` entry of attenuo's own type, `attenuo_capabilities`, names capabilities directly, constraints and limits included. Each claim present narrows; a claim the ID-JAG does not carry narrows nothing, so an ID-JAG with none of them gets the root grant. A claim never widens: a resource mapped to a server the grant does not give, or a scope mapped to `*:*`, adds nothing. An unmapped resource or scope token and an `authorization_details` entry of another type name nothing, so an ID-JAG whose claims name only such things is refused with `invalid_scope` / `id_jag_ceiling_empty`. A request within the grant but beyond the ID-JAG is `invalid_scope` / `scope_exceeds_id_jag`. Every later hop is bounded by the root token, so the ceiling holds for the whole chain. ID tokens are not affected, and that is a way around it: an agent that can present this issuer's ID tokens (its `client_ids` entry, or its agent id, is the ID token's `aud`) gets the root grant as it is by presenting the user's ID token instead of the ID-JAG, and in the draft's flow the agent got its ID-JAG by exchanging that ID token, so it usually has one. Hence `credentials = ["id-jag"]` above: the entry then accepts only ID-JAGs at hop 0, and an ID token from this issuer is refused with `invalid_grant` / `credential_type_not_accepted` before it is checked or used up. The default, with the key absent, still accepts both, so the ceiling alone does not close the gap; the server logs a warning at start for an entry with a ceiling that accepts ID tokens (SR-122). Approval ID tokens are not affected by `credentials`. A limit in a claim bounds the root token once: a request that splits one limited capability of the claims into several is refused with `limit_split_at_root` (SR-121), also when the limit is in a `scopes` entry and `authorization_details` names the parts separately under it (SR-127), and when the root grant itself holds several limited capabilities under one limited capability of a claim (SR-131). The keys and the exact rules are in the [configuration reference](../reference/config.md#idpsidjagceiling).

**Multi-tenant issuers.** When one IdP issuer serves several tenants and tells them apart with the `tenant` claim, the draft says the authorization server must require `tenant` and trust `iss` and `tenant` together. Set `tenant` on the `[[idps]]` entry to the one tenant whose users it trusts:

```toml
[[idps]]
issuer = "https://idp.example.com"
tenant = "acme"          # ID-JAGs without tenant = "acme" are refused
```

An ID-JAG without `tenant` is refused with `missing_claim`, one for another tenant with `tenant_mismatch`. ID tokens are not affected. One entry trusts one tenant, because `[[idps]] issuer` is unique and `[[root_grants]]` match on the issuer and `sub` alone, so two tenants' users with the same `sub` would share a grant. Without `tenant`, the claim is not checked, as before.

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

Hop 0 is about the user. Every later hop is about an agent: the caller of an exchange must prove it is the `actor` it names. Besides an `[[agents]]` client secret or client assertion, it can send an RFC 8693 `actor_token`: a JWT that a workload-identity system issued to that agent. attenuo verifies it against an `[[actor_trust]]` entry and maps its `sub` to an agent id, which must equal `actor`.

**Status: SPIRE was run once, the other workload-identity issuers were not.** The SPIRE settings below were run against SPIRE 1.16.0 (see the next section for what was and was not checked); Kubernetes service-account tokens and cloud workload tokens are tested only with tokens the server's tests sign themselves.

### SPIRE (tested: 1.16.0, join-token attestor)

Run on 2026-11-14 against SPIRE 1.16.0, by [`scripts/live-spire-smoke.sh`](https://github.com/attenuo-dev/attenuo/blob/main/scripts/live-spire-smoke.sh). The `ghcr.io/spiffe` images could not be pulled where it ran, so the script downloads the release tarballs (`spire-1.16.0-linux-amd64-musl.tar.gz`, SHA-256 `7bcf5e167151a1fc58293768462b44e155ba8784214582aefa6adf18c633d1d5`, and `spire-extras-1.16.0-linux-amd64-musl.tar.gz`, SHA-256 `b2ee7828549e46a333c5ba83541457214d1f6d886000168231aed086236137d5`, the values in the release's checksum files) and runs the server, the agent and the OIDC Discovery Provider in one `alpine:3.20` container (`sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`), on 127.0.0.1. The server has the `join_token` node attestor, an in-memory key manager, `jwt_issuer` set, and a bundle endpoint with the `https_web` profile; the agent identifies workloads by uid (`unix` workload attestor), one registration entry per agent id. The bundle endpoint's certificate came from a CA made for the run, and attenuo fetched the bundle from it directly over TLS, with `ca_pem_path` naming that CA (a second run the same day, after the setting was added; the first run reached it through a loopback relay). Each statement below says whether that run checked it. Not run: a production deployment (a real node attestor such as `k8s_psat` or `aws_iid`, the Kubernetes workload attestor, a disk or cloud key manager, several servers), SPIRE federation, the `https_spiffe` bundle endpoint profile, ACME, RSA JWT keys (`RS256`), `subject_to_agent = "spiffe_path"`, the TypeScript SDK, and other SPIRE versions.

SPIRE issues JWT-SVIDs whose `sub` is the workload's SPIFFE ID, for example `spiffe://example.org/ns/agents/sa/coder`. Their signing keys are in the trust bundle, which the SPIRE server serves from its bundle endpoint (`federation { bundle_endpoint { ... } }` inside the `server` block of `server.conf`). attenuo fetches that URL as a JWKS and keeps the keys with `use` = `jwt-svid`. It never discovers the URL: you give it. Tested: SPIRE 1.16.0's bundle holds one `x509-svid` key (with `x5c`) and one `jwt-svid` key per JWT authority, and attenuo verified JWT-SVIDs (ES256, SPIRE's default key type) against the `jwt-svid` key.

```toml
[token]
actor_auth = "either"          # or "actor_token" once every agent has an identity

[[actor_trust]]
spiffe_trust_domain = "example.org"
spiffe_bundle_url = "https://spire-server.example.org:8443"
# ca_pem_path = "/etc/attenuo/spire-bundle-ca.pem"   # when a private CA issued the endpoint's certificate
audience = "https://attenuo.example.com"
# Map SPIFFE IDs to the agent ids your policies and root grants use.
subject_to_agent = { "spiffe://example.org/ns/agents/sa/coder" = "coder", "spiffe://example.org/ns/agents/sa/reviewer" = "reviewer" }
# Or take the path as the agent id: spiffe://example.org/agents/coder -> "agents/coder".
# subject_to_agent = "spiffe_path"
allowed_algs = ["ES256", "RS256"]
```

**TLS: the web PKI, plus the entry's `ca_pem_path`.** attenuo checks the bundle endpoint's certificate against the Mozilla root set built into it (the `webpki-roots` crate), not the system's trust store, plus the CA certificates of the entry's `ca_pem_path` when it is set ([Private CAs for key URLs](#private-cas-for-key-urls)). So use SPIRE's `https_web` profile, with `acme` or with `serving_cert_file` holding a certificate a public CA issued, or with `serving_cert_file` holding one from your own CA and that CA's certificate in `ca_pem_path`; or put a TLS proxy with such a certificate in front. SPIRE's default profile, `https_spiffe`, serves the server's own X.509-SVID, which is checked against the SPIFFE bundle rather than a CA, and attenuo does not do that, so it does not work (`ca_pem_path` does not help: the certificate names a SPIFFE ID, not the host). Tested: with `https_web` and `serving_cert_file` holding a certificate (for `IP:127.0.0.1`) from a CA made for the run, and that CA in `ca_pem_path`, attenuo fetched the bundle directly over TLS, and every bundle-endpoint check in this section passed that way, the unknown-`kid` refetch of the key rotation included. Without `ca_pem_path`, and with `ca_pem_path` naming another CA, every exchange failed with `503 temporarily_unavailable` (`jwks_unavailable`), the response named no cause, and attenuo's WARN line `actor token issuer JWKS unavailable` gave it: `error sending request: client error (Connect): invalid peer certificate: UnknownIssuer`. In SPIRE 1.16.0, `serving_cert_file` without `file_sync_interval` stops the server at start with `time: invalid duration ""`; set it (the run used `"1h"`).

If you run the SPIRE OIDC Discovery Provider instead, configure `jwt_issuer` in SPIRE so JWT-SVIDs carry an `iss`, and use a generic entry: `issuer = "<jwt_issuer>"`, `jwks_url = "https://<discovery provider>/keys"`, plus the same `audience` and `subject_to_agent`. Tested, with the provider on 127.0.0.1 over plain `http://` (`insecure_addr` and `allow_insecure_scheme`): its discovery document's `issuer` is the server's `jwt_issuer`, its `/keys` serves the JWT key with `alg` and no `use`, and hop 0 and an exchange verified against it. The provider's own TLS (`acme` or `serving_cert_file`) was not run; the TLS rule above applies to it too, `ca_pem_path` included. `jwt_issuer` also puts an `iss` in the SVIDs a bundle-endpoint entry checks; that entry ignores it unless it sets `issuer`.

The agent fetches a JWT-SVID with attenuo's URL as the audience and sends it on the exchange. `spire-agent api fetch jwt` prints a header line, the token on the second line and then the bundle, so take the second line:

```sh
spire-agent api fetch jwt -audience https://attenuo.example.com \
  -socketPath /run/spire/sockets/agent.sock | sed -n 2p | tr -d '[:space:]' \
  | ATTENUO_TOKEN="$PARENT" attenuo token exchange --actor coder \
      --cap github:read_file --actor-token -   # reads the JWT-SVID from stdin
```

Tested: `sed -n 2p` gives the token; `attenuo token exchange --actor-token -` with it gives a child token. The Python SDK's `Client.exchange(parent, "reviewer", ["github:read_file"], actor_token=svid)` was run too (followed by `inspect` with verification).

What attenuo checks: the entry (by `iss` when the entry has `issuer`, by the trust domain of `sub`), `alg` in `allowed_algs`, the key by `kid`, the signature, `aud` contains `audience`, `exp` is present and not past, `nbf` and `iat` are not in the future, and `sub` is a well-formed SPIFFE ID in the trust domain. Then `subject_to_agent` must give the exchange's `actor`. Tested against real SVIDs: one fetched for another audience is `actor_token_audience_mismatch`; a SPIFFE ID mapped to another agent than `--actor` (the reviewer's SVID, or the planner's, for `--actor coder`) is `actor_mismatch`; a SPIFFE ID of the trust domain that `subject_to_agent` does not list is `actor_token_unmapped_subject`. The SVIDs SPIRE 1.16.0 issues carry `aud` (an array), `exp`, `iat`, `sub` and, with `jwt_issuer`, `iss`; no `jti` and no `nbf`.

Each actor token authenticates one exchange: a second use is `invalid_grant` / `replayed`. Tested, through both key sources, with the second use under another parent token (an exchange of one parent token to one actor is single use in its own right: a second exchange of the same parent to the same actor is `replayed` too, whatever SVID it carries). The SPIRE agent caches JWT-SVIDs and may hand out the same one until it is half expired, so fetch a new one per exchange; asking with an extra, unique audience next to attenuo's URL gets a fresh token, and attenuo accepts an `aud` array that contains its own value. Tested: the same audience twice gave the same token; an extra audience gave a new one, which attenuo accepted. The child token never outlives the actor token, so with SPIRE's default five-minute JWT-SVIDs a child lives at most five minutes. Use leases and renewals for longer work. Tested: the SVIDs lived 300 seconds, and the child's and the root token's `exp` were not later than their SVID's.

Key rotation. Tested with `spire-server localauthority jwt prepare`, `activate`, `taint` and `revoke`. A prepared key is in the bundle (and, once the provider has polled the server, at the discovery provider's `/keys`) before it signs anything; after `activate`, new SVIDs carry its `kid`. Through the bundle endpoint (default `jwks_ttl_seconds`), attenuo fetched the bundle again once on the unknown `kid` (`unknown kid; refetching JWKS`) and accepted them; through the discovery provider (on a server with `jwks_ttl_seconds = 5`) they were accepted too. Activate only after the new key has reached every key source attenuo reads: the discovery provider polls the server (every 10 seconds by default), and attenuo refetches on an unknown `kid` at most once per 30 seconds, so a key activated at once can be refused until the cache expires. After `revoke` the old key leaves the bundle, but attenuo keeps verifying with it until `jwks_ttl_seconds` (default 300) has passed since its last fetch: tested, an unspent SVID signed with the revoked key was accepted from the cache, and refused (`actor_token_unknown_kid`) on a server with `jwks_ttl_seconds = 5` once that time had passed. Lower `jwks_ttl_seconds` if a revocation must take effect sooner.

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

Tested with SPIRE 1.16.0: the `curl` command above, with a real JWT-SVID and an ID token from the mock identity provider of `examples/idp-exchange-demo` (not a real IdP), gave a root token for `planner` whose `exp` was not later than the SVID's, through the bundle endpoint (over TLS, with `ca_pem_path`, as described under [SPIRE](#spire-tested-1160-join-token-attestor)) and through the discovery provider. Hop 0 from the SDKs with an SVID was not run.

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

   A `scope` string asks for the tool with no constraints. When the `[[root_grants]]` entry has constraints (a repository prefix, say), that is more than the grant allows and is refused with `scope_exceeds_grant`; ask with `authorization_details` and the same constraints instead, as [examples/idp-exchange-demo](https://github.com/attenuo-dev/attenuo/blob/main/examples/idp-exchange-demo/run.sh) does. A request refused this way does not spend the ID token (seen with Keycloak: the same token was accepted after a `scope_exceeds_grant`).

   Or with the CLI, which sends the same exchange with the capabilities as `authorization_details` (constraints included) and reads the ID token from `ATTENUO_TOKEN`, `--subject-token-file` or `--subject-token -`, as it reads a parent token ([CLI reference](../reference/cli.md#hop-0-from-an-id-token)):

   ```sh
   printf '%s\n' "$SECRET" | ATTENUO_TOKEN="$ID_TOKEN" attenuo --server http://127.0.0.1:8080 \
     token exchange --subject-token-type id-token --actor planner --client-secret-stdin \
     --cap '{"server":"github","tool":"read_file","constraints":{"repo":{"op":"prefix","value":"acme/"}}}'
   ```

   `--subject-token-type id-jag` sends an ID-JAG the same way. Without `--subject-token-type`, `token exchange` sends its subject token as an attenuo token, and an ID token is refused (`invalid_grant`, unknown key id). A refusal prints the server's error, its stable code in parentheses and its detail: a second use of one ID token reads `invalid_grant (replayed): this credential was already used; present a fresh one`.

4. Inspect the result. The user block should show the right subject, issuer and attributes:

   ```sh
   attenuo token inspect "$ROOT_TOKEN" --verify
   ```

### When it fails

Errors carry a stable `code` (the same value as `error_description`, which older clients read). The usual causes:

| Response | Cause |
| --- | --- |
| `401 invalid_client` / `client_authentication_failed` | Wrong agent id or secret, or the hash in `[[agents]]` was made from a different string. Check for a trailing newline: use `printf %s`, not `echo` |
| `401 invalid_client` / `no_agents_configured` | `[[agents]]` is empty |
| `401 invalid_client` / `client_auth_missing`, `actor_token_required` | The request sent no credential at all; `actor_token_required` when `[token] actor_auth = "actor_token"`, where only an `actor_token` authenticates the agent |
| `400 invalid_grant` / `untrusted_issuer` | `iss` is not in `[[idps]]`. Look for a trailing slash, `http` against `https`, or a tenant id mismatch |
| `400 invalid_grant` / `credential_type_not_accepted` | The issuer's `[[idps]] credentials` does not list this kind of credential (an ID token under `["id-jag"]`, or the other way round) |
| `400 invalid_grant` / `credential_audience_mismatch` | An ID token's `aud` (or `azp`) does not name the presenting agent's client id: the token was issued to another client, or `client_ids` has no entry for this agent and the id differs from the agent id |
| `400 invalid_grant` / `audience_mismatch` | An ID-JAG's `aud` is not `[issuer] issuer`, or is an array with more than one element |
| `400 invalid_grant` / `tenant_mismatch` | An ID-JAG's `tenant` is not the `[[idps]] tenant` of its issuer |
| `400 invalid_grant` / `credential_pop_required`, `credential_pop_mismatch` | The ID-JAG has a `cnf` claim and the request has no DPoP proof, a proof by another key, or `[token] dpop = "off"` |
| `400 invalid_grant` / `unsupported_alg` | The token's `alg` is not in `allowed_algs` |
| `400 invalid_grant` / `unknown_kid` | The signing key is not in the IdP's JWKS, even after a refetch |
| `400 invalid_grant` / `bad_signature`, `expired`, `not_yet_valid` | The token is bad, stale, or your clock is off by more than `clock_skew_seconds` |
| `400 invalid_grant` / `client_id_mismatch` | ID-JAG `client_id` is not the authenticated agent |
| `400 invalid_grant` / `missing_claim` | A required claim is missing: `sub`, `exp`, `iat`; for an ID-JAG also `client_id` and `jti`, and `tenant` when `[[idps]] tenant` is set |
| `400 invalid_grant` / `typ_mismatch` | Wrong credential type for the `subject_token_type` you sent |
| `400 invalid_scope` / `no_root_grant` | No `[[root_grants]]` entry for this issuer and agent |
| `400 invalid_scope` / `scope_exceeds_grant` | The request asks for more than the entry allows |
| `400 invalid_scope` / `limit_split_at_root` | Two requested capabilities fall under the same limited capability of the entry or of the ID-JAG's claims; ask for one capability covering both (`one_of`, a wider constraint or tool pattern) |
| `400 invalid_scope` / `limit_conflict_at_root` | A requested capability is under one or more limited capabilities of the entry or of the ID-JAG's claims that set one kind of limit on different arguments, which one capability cannot carry; ask for one fewer of them cover, or change the entry |
| `400 invalid_scope` / `id_jag_ceiling_empty` | With `[idps.id_jag_ceiling]`: the ID-JAG's `resource`, `scope` or `authorization_details` name nothing the root grant gives (unmapped, of another type, or outside the grant) |
| `400 invalid_scope` / `scope_exceeds_id_jag` | With `[idps.id_jag_ceiling]`: the request is within the root grant but asks for more than the ID-JAG's claims allow |
| `400 invalid_scope` / `too_many_capabilities`, `too_many_constraints`, `too_many_one_of_values`, `one_of_too_long` | The request is over a size bound: more than 1,024 capabilities, argument constraints or `one_of` values in all, or a `one_of` of more than 1,024 values |
| `503 temporarily_unavailable` / `jwks_unavailable` | attenuo cannot reach the IdP, or the JWKS or discovery document is bad. Failed refreshes drop old keys: there are no stale keys. The server's WARN line `IdP JWKS unavailable` (`actor token issuer JWKS unavailable` for `[[actor_trust]]`) names the URL and the cause, for a TLS failure the certificate error (`invalid peer certificate: UnknownIssuer` for a CA attenuo does not trust, see [Private CAs for key URLs](#private-cas-for-key-urls); `certificate not valid for name ...` for a hostname mismatch); the response does not |

At the default log level the server logs only the `jwks_unavailable` WARN line above; the other refusals are answered with their code alone (SR-17). With `RUST_LOG=attenuo_server=debug,info` each refusal is also logged as `IdP credential refused` with its code (`reason`) and the verifier's text (`detail`, which names the issuer for `untrusted_issuer`).

The full flow, with a sequence diagram, is in [design/server.md](../design/server.md#hop-0-intake-from-an-identity-provider).
