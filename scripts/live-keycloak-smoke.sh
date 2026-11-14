#!/usr/bin/env bash
# Hop 0 from a real Keycloak login, following the Keycloak section of
# docs/guides/identity-providers.md.
#
#   scripts/live-keycloak-smoke.sh
#
# Starts Keycloak in dev mode (pinned image, host network, 127.0.0.1 only), and sets it up with
# kcadm.sh inside the container the way the guide tells a reader to: realm `acme`, a
# confidential OIDC client `agent-platform` with the standard flow, a "User Realm Role" mapper
# with claim `roles` and a "Group Membership" mapper with claim `groups` on the client's
# dedicated scope, and a test user with a realm role and a group. A second client, `other-app`,
# gives a token for the wrong audience. Logs the user in with the authorization-code flow (the
# login form is posted as a browser would), so the ID tokens are the ones a real login gets.
#
# Then runs attenuo-server with the guide's Keycloak `[[idps]]` recipe, its issuer replaced by
# the local one, and checks: discovery and the JWKS fetch, RS256, `iss`, `aud`/`azp` (a token
# for `other-app` is refused), the replay refusal, the user block (`email`, `roles`, `mfa`),
# whether `amr` is sent, the hop-0 exchange with curl (the guide's command, with
# authorization_details), the Python SDK, the TypeScript SDK and the CLI (`token exchange
# --subject-token-type id-token`, with its replay refusal), `inspect(verify=True)` and the
# `kid` of the root token against the server's JWKS, a key rotation at Keycloak, a narrowed
# child exchange with the CLI, and MCP calls through the proxy (allowed, capability_denied, and
# policy_deny for a tool whose policy needs `mfa`). Last, it adds Keycloak's AMR mapper and
# checks what `amr` it then sends.
#
# Not part of CI. Needs docker (the daemon running), curl and python3; the Python SDK step
# needs httpx, the TypeScript one node and a built sdk/typescript/dist (`npm ci && npm run
# build` there). A step whose tool is missing is reported as skipped, and the script then
# exits non-zero, so a partial run is never mistaken for a pass. Skips with exit status 0 when
# docker is not available. The admin password, client secrets, agent secrets and user password
# are random per run and stay in the temp dir (mode 0700). `kcadm.sh` inside the container and
# curl take some of them as arguments, which other local users can read in `ps` while they
# run; run it on a machine you do not share, or accept that for these throwaway, loopback-only
# credentials. Nothing leaves the machine except the image pull.
#
# Environment:
#   KEYCLOAK_IMAGE       Keycloak image (default: the pinned 26.8.2 digest below)
#   ATTENUO_BIN_DIR=DIR  prebuilt attenuo-server, attenuo, examples/fake_mcp (default: cargo build)
#   KEEP=1               keep the temp dir (logs, config)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# keycloak/keycloak:26.8.2 (Docker Hub), pulled 2026-11-14.
KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-keycloak/keycloak@sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0}"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "skip: docker is not available (no client, or the daemon is not running)"
  exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/attenuo-keycloak-smoke.XXXXXX")"
chmod 700 "$WORK"
CONTAINER="attenuo-keycloak-smoke-$$"
PIDS=()
SKIPPED=()
export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}"
export no_proxy="$NO_PROXY"

cleanup() {
  local rc=$?
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [ "$rc" -ne 0 ]; then
    echo >&2
    echo "keycloak smoke test failed (exit $rc). Last server and Keycloak log lines:" >&2
    tail -n 10 "$WORK/server.log" 2>/dev/null >&2 || true
    docker logs --tail 10 "$CONTAINER" >&2 2>/dev/null || true
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [ "${KEEP:-0}" = 1 ]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

say() { printf '\n== %s\n' "$*"; }
ok() { printf 'ok   %s\n' "$*"; }
fail() { echo "!! $*" >&2; exit 1; }
rand() { od -An -tx1 -N16 /dev/urandom | tr -d ' \n'; }
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
# The header or claims of a JWT (decoded, not verified), as JSON.
jwt_part() {
  python3 -c 'import base64,json,sys; s=sys.argv[1].split(".")[int(sys.argv[2])]; print(json.dumps(json.loads(base64.urlsafe_b64decode(s+"="*(-len(s)%4)))))' "$1" "$2"
}
jq_py() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"; }

if [ -n "${ATTENUO_BIN_DIR:-}" ]; then
  BIN="$ATTENUO_BIN_DIR"
else
  echo "building..." >&2
  cargo build -q -p attenuo-server -p attenuo-cli
  cargo build -q -p attenuo-proxy --features testing --example fake_mcp
  BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
fi
CLI="$BIN/attenuo"
FAKE_BIN="$BIN/examples/fake_mcp"; [ -x "$FAKE_BIN" ] || FAKE_BIN="$BIN/fake_mcp"

KC_PORT="$(free_port)"; OB_PORT="$(free_port)"; MCP_PORT="$(free_port)"
KC="http://127.0.0.1:$KC_PORT"
REALM="$KC/realms/acme"
REDIRECT="http://127.0.0.1:$(free_port)/callback"   # never served: the code is read off the redirect
rand > "$WORK/kc-admin.pw"; rand > "$WORK/user.pw"

# --- Keycloak --------------------------------------------------------------------------------
say "Keycloak: $KEYCLOAK_IMAGE"
# The password reaches the container through docker's environment (`-e NAME` copies it from
# ours), not its argument list, which other local users can read with `ps` (SR-120).
KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat "$WORK/kc-admin.pw")" \
docker run -d --name "$CONTAINER" --network host \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD \
  "$KEYCLOAK_IMAGE" start-dev --http-port="$KC_PORT" --http-host=127.0.0.1 >/dev/null
for _ in $(seq 1 120); do
  curl -sf "$KC/realms/master" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "$KC/realms/master" >/dev/null || fail "Keycloak did not start"
docker logs "$CONTAINER" 2>&1 | grep -oE 'Keycloak [0-9.]+ on JVM' | head -n1

kc() { docker exec "$CONTAINER" /opt/keycloak/bin/kcadm.sh "$@"; }
kc config credentials --server "$KC" --realm master --user admin \
  --password "$(cat "$WORK/kc-admin.pw")" >/dev/null 2>&1

say "realm, clients, mappers, user (kcadm.sh)"
kc create realms -s realm=acme -s enabled=true
new_client() {  # name -> prints the client's internal id
  kc create clients -r acme -s clientId="$1" -s protocol=openid-connect -s publicClient=false \
    -s standardFlowEnabled=true -s directAccessGrantsEnabled=false \
    -s "redirectUris=[\"$REDIRECT\"]" -i
}
CID="$(new_client agent-platform)"
OTHER_CID="$(new_client other-app)"
kc get "clients/$CID/client-secret" -r acme --fields value --format csv --noquotes > "$WORK/agent-platform.secret"
kc get "clients/$OTHER_CID/client-secret" -r acme --fields value --format csv --noquotes > "$WORK/other-app.secret"
# The guide: "User Realm Role" mapper, claim `roles`, multivalued, in the ID token; "Group
# Membership" mapper, claim `groups`, in the ID token. Both on the client's dedicated scope.
kc create "clients/$CID/protocol-mappers/models" -r acme -s name=roles -s protocol=openid-connect \
  -s protocolMapper=oidc-usermodel-realm-role-mapper -s 'config."claim.name"=roles' \
  -s config.multivalued=true -s 'config."id.token.claim"=true' -s 'config."access.token.claim"=true' \
  -s 'config."jsonType.label"=String'
kc create "clients/$CID/protocol-mappers/models" -r acme -s name=groups -s protocol=openid-connect \
  -s protocolMapper=oidc-group-membership-mapper -s 'config."claim.name"=groups' \
  -s 'config."id.token.claim"=true' -s 'config."access.token.claim"=true'
kc create roles -r acme -s name=github-reader
kc create groups -r acme -s name=engineering
USER_ID="$(kc create users -r acme -s username=alice -s enabled=true -s email=alice@example.com \
  -s emailVerified=true -s firstName=Alice -s lastName=Test -i)"
kc set-password -r acme --username alice --new-password "$(cat "$WORK/user.pw")"
kc add-roles -r acme --uusername alice --rolename github-reader
GID="$(kc get groups -r acme --fields id,name --format csv --noquotes | awk -F, '$2=="engineering"{print $1}')"
kc update "users/$USER_ID/groups/$GID" -r acme -s realm=acme -s userId="$USER_ID" -s groupId="$GID" -n

# The authorization-code flow, with Keycloak's login form posted as a browser posts it.
cat > "$WORK/login.py" <<'EOF'
import html, json, re, sys, urllib.error, urllib.parse, urllib.request, http.cookiejar
realm, client, secret_file, user, pw_file, redirect = sys.argv[1:]
secret = open(secret_file).read().strip()
pw = open(pw_file).read().strip()
jar = http.cookiejar.CookieJar()
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
op = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                 urllib.request.HTTPCookieProcessor(jar), NoRedirect)
q = urllib.parse.urlencode({"client_id": client, "response_type": "code", "scope": "openid",
                            "redirect_uri": redirect, "state": "s", "nonce": "n"})
page = op.open(f"{realm}/protocol/openid-connect/auth?{q}").read().decode()
m = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page)
assert m, "no login form"
# Keycloak marks its cookies Secure; a browser sends them to http://127.0.0.1 (a secure
# context), urllib does not unless told.
for c in jar:
    c.secure = False
try:
    op.open(html.unescape(m.group(1)),
            urllib.parse.urlencode({"username": user, "password": pw, "credentialId": ""}).encode())
    raise SystemExit("login did not redirect")
except urllib.error.HTTPError as e:
    if e.code not in (302, 303):
        raise
    loc = e.headers["Location"]
code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["code"][0]
body = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code,
                               "redirect_uri": redirect, "client_id": client,
                               "client_secret": secret}).encode()
print(json.load(op.open(f"{realm}/protocol/openid-connect/token", body))["id_token"])
EOF
login() {  # [client] -> an ID token for alice
  local client="${1:-agent-platform}"
  python3 -I "$WORK/login.py" "$REALM" "$client" "$WORK/$client.secret" alice "$WORK/user.pw" "$REDIRECT"
}

say "1. discovery and a real ID token"
DISCOVERY="$(curl -sf "$REALM/.well-known/openid-configuration")"
[ "$(printf %s "$DISCOVERY" | jq_py 'd["issuer"]')" = "$REALM" ] || fail "discovery issuer differs"
ok "discovery issuer = $REALM"
ID_TOKEN="$(login)"
HEADER="$(jwt_part "$ID_TOKEN" 0)"; CLAIMS="$(jwt_part "$ID_TOKEN" 1)"
echo "header $HEADER"
printf %s "$CLAIMS" | jq_py '{k: d.get(k) for k in ("iss","aud","azp","typ","amr","acr","email","roles","groups")}'
printf %s "$CLAIMS" | jq_py 'int(d["exp"]) - int(d["iat"])' | sed 's/^/ID token lifetime (s): /'
[ "$(printf %s "$HEADER" | jq_py 'd["alg"]')" = RS256 ] || fail "expected RS256"
[ "$(printf %s "$CLAIMS" | jq_py 'd["aud"]')" = agent-platform ] || fail "aud is not agent-platform"
[ "$(printf %s "$CLAIMS" | jq_py 'd["azp"]')" = agent-platform ] || fail "azp is not agent-platform"
[ "$(printf %s "$CLAIMS" | jq_py '"amr" in d')" = False ] || fail "Keycloak sent amr by default"
ok "RS256, aud and azp = agent-platform, no amr claim by default"
[ "$(printf %s "$CLAIMS" | jq_py '"github-reader" in d["roles"]')" = True ] || fail "roles mapper"
[ "$(printf %s "$CLAIMS" | jq_py 'd["groups"]')" = "['engineering']" ] || fail "groups mapper"
ok "roles and groups claims from the guide's mappers"

# --- attenuo-server with the guide's recipe ----------------------------------------------------
PLANNER_SECRET="$(rand)"; CODER_SECRET="$(rand)"; ADMIN_TOKEN="$(rand)"
sha() { printf %s "$1" | sha256sum | cut -d' ' -f1; }
python3 - "$ROOT/docs/guides/identity-providers.md" "$REALM" > "$WORK/config.toml" <<'EOF'
import re, sys
guide, realm = sys.argv[1:]
section = open(guide).read().split("### Keycloak")[1].split("\n### ")[0]
recipe = re.search(r"```toml\n(.*?)```", section, re.S).group(1)
assert "https://keycloak.example.com/realms/acme" in recipe
print(recipe.replace("https://keycloak.example.com/realms/acme", realm))
EOF
echo "the guide's recipe, issuer replaced:"; sed 's/^/  /' "$WORK/config.toml"
cat > "$WORK/policy.cedar" <<'EOF'
@id("readers_read_acme")
permit(principal, action == Action::"github/get_file_contents", resource)
when {
  context.input has repo && context.input.repo like "acme/*" &&
  context.originating_user.attributes has roles &&
  context.originating_user.attributes.roles.contains("github-reader")
};

@id("issues_need_mfa")
permit(principal, action == Action::"github/create_issue", resource)
when {
  context.input has repo && context.input.repo like "acme/*" &&
  context.originating_user.attributes has mfa && context.originating_user.attributes.mfa
};
EOF
cat >> "$WORK/config.toml" <<EOF

[server]
listen = "127.0.0.1:$OB_PORT"

[issuer]
issuer = "http://127.0.0.1:$OB_PORT"
audience = "attenuo"

[policy]
policies_path = "$WORK/policy.cedar"

[policy.catalog.github.get_file_contents]
readonly = true
inputs = { repo = "string", path = "string" }

[policy.catalog.github.create_issue]
inputs = { repo = "string", title = "string" }

[audit]
sqlite_path = ":memory:"

[[upstreams]]
name = "github"
url = "http://127.0.0.1:$MCP_PORT/mcp"

[admin]
token = "$ADMIN_TOKEN"

[[root_grants]]
issuer = "$REALM"
agent = "planner"
may_act = ["coder"]
capabilities = [
  { server = "github", tool = "get_file_contents", constraints = { repo = { op = "prefix", value = "acme/" } } },
  { server = "github", tool = "create_issue", constraints = { repo = { op = "prefix", value = "acme/" } } },
]

[[agents]]
id = "planner"
secret_sha256 = "$(sha "$PLANNER_SECRET")"

[[agents]]
id = "coder"
secret_sha256 = "$(sha "$CODER_SECRET")"

[dev]
allow_root_mint = false
EOF
"$FAKE_BIN" --port "$MCP_PORT" --tools get_file_contents,create_issue \
  > "$WORK/fake-mcp.out" 2> "$WORK/fake-mcp.log" &
PIDS+=($!)
RUST_LOG=info "$BIN/attenuo-server" --config "$WORK/config.toml" > "$WORK/server.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 100); do
  curl -sf "http://127.0.0.1:$OB_PORT/healthz" >/dev/null 2>&1 \
    && grep -q listening "$WORK/fake-mcp.out" 2>/dev/null && break
  sleep 0.1
done
curl -sf "http://127.0.0.1:$OB_PORT/healthz" >/dev/null || fail "server did not start"
export ATTENUO_SERVER="http://127.0.0.1:$OB_PORT"
unset ATTENUO_TOKEN ATTENUO_CLIENT_SECRET ATTENUO_ADMIN_TOKEN

CAPS='[{"type":"attenuo_capabilities","capabilities":[
  {"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"prefix","value":"acme/"}}},
  {"server":"github","tool":"create_issue","constraints":{"repo":{"op":"prefix","value":"acme/"}}}]}]'
hop0() {  # id-token -> the /token answer (the guide's command, authorization_details for scope)
  curl -s -X POST "$ATTENUO_SERVER/token" -u "planner:$PLANNER_SECRET" \
    --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    --data-urlencode subject_token="$1" \
    --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:id_token \
    --data-urlencode authorization_details="$CAPS"
}

say "2. hop 0 with curl"
# The guide's command as written, with a scope string: more than the constrained grant allows.
CODE="$(curl -s -X POST "$ATTENUO_SERVER/token" -u "planner:$PLANNER_SECRET" \
  --data-urlencode grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  --data-urlencode subject_token="$ID_TOKEN" \
  --data-urlencode subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  --data-urlencode scope='github:get_file_contents' | jq_py 'd.get("code")')"
[ "$CODE" = scope_exceeds_grant ] || fail "expected scope_exceeds_grant, got $CODE"
ok "scope=github:get_file_contents against a constrained grant: scope_exceeds_grant"
ANSWER="$(hop0 "$ID_TOKEN")"
ROOT_TOKEN="$(printf %s "$ANSWER" | jq_py 'd.get("access_token", "")')"
[ -n "$ROOT_TOKEN" ] || fail "hop 0 refused: $ANSWER"
ok "the same ID token, with authorization_details: root token issued (the refusal did not spend it), expires_in $(printf %s "$ANSWER" | jq_py 'd["expires_in"]') s"
grep -q 'trusted IdP' "$WORK/server.log" && ok "server log: $(grep -o 'trusted IdP.*' "$WORK/server.log" | head -n1)"
[ "$(hop0 "$ID_TOKEN" | jq_py 'd.get("code")')" = replayed ] || fail "replay was not refused"
ok "the same ID token again: replayed"
OTHER="$(login other-app)"
# other-app has no mappers of its own: what Keycloak puts in an ID token by default.
[ "$(jwt_part "$OTHER" 1 | jq_py '[k for k in ("roles", "realm_access", "groups", "amr") if k in d]')" = "[]" ] \
  || fail "a client without the guide's mappers got role, group or amr claims"
ok "without the mappers, the ID token has no roles, realm_access, groups or amr claim"
[ "$(hop0 "$OTHER" | jq_py 'd.get("code")')" = credential_audience_mismatch ] \
  || fail "a token for other-app was not refused"
ok "an ID token for other-app: credential_audience_mismatch"
"$CLI" token inspect "$ROOT_TOKEN" --verify | tee "$WORK/inspect.txt"
grep -q "issuer $REALM" "$WORK/inspect.txt" || fail "issuer not in the user block"
grep -q 'email="alice@example.com"' "$WORK/inspect.txt" || fail "email attribute"
grep -q 'mfa=false' "$WORK/inspect.txt" || fail "mfa should be false without amr"
grep -q '"github-reader"' "$WORK/inspect.txt" || fail "roles attribute"
ok "user block: issuer, email, roles, mfa=false"

say "3. hop 0 with the Python SDK, and inspect(verify=True)"
if python3 -c 'import httpx' 2>/dev/null; then
  ATTENUO_SDK_SRC="$ROOT/sdk/python/src" ID_TOKEN="$(login)" PLANNER_SECRET="$PLANNER_SECRET" \
  python3 - <<'EOF'
import base64, json, os, sys
sys.path.insert(0, os.environ["ATTENUO_SDK_SRC"])
import attenuo
cap = {"server": "github", "tool": "get_file_contents",
       "constraints": {"repo": {"op": "prefix", "value": "acme/"}}}
with attenuo.Client(os.environ["ATTENUO_SERVER"]) as ob:
    root = ob.exchange(os.environ["ID_TOKEN"], "planner", [cap], client_id="planner",
                       client_secret=os.environ["PLANNER_SECRET"])
    v = ob.inspect(root, verify=True)
    kids = [k.get("kid") for k in ob.jwks()["keys"]]
user = v.chain.user
assert v.verified and v.agent == "planner", v
assert user.attributes["mfa"] is False and "github-reader" in user.attributes["roles"], user
assert v.header["kid"] in kids, (v.header, kids)
print(f"ok   Python SDK: root token for {v.agent}, verified; header kid {v.header['kid']} is in the server JWKS {kids}")
EOF
else
  echo "skip: no httpx for the Python SDK"; SKIPPED+=(python-sdk)
fi

say "4. hop 0 with the TypeScript SDK, and inspect({ verify: true })"
if command -v node >/dev/null 2>&1 && [ -f "$ROOT/sdk/typescript/dist/index.js" ]; then
  ID_TOKEN="$(login)" PLANNER_SECRET="$PLANNER_SECRET" \
  node --input-type=module -e '
const { AttenuoClient } = await import(process.argv[1]);
const ob = new AttenuoClient(process.env.ATTENUO_SERVER);
const cap = { server: "github", tool: "get_file_contents",
              constraints: { repo: { op: "prefix", value: "acme/" } } };
const root = await ob.exchange(process.env.ID_TOKEN, "planner", [cap],
  { clientId: "planner", clientSecret: process.env.PLANNER_SECRET });
const v = await ob.inspect(root, { verify: true });
const kids = (await ob.jwks()).keys.map((k) => k.kid);
const user = v.chain.user;
if (!v.verified || v.agent !== "planner" || user.attributes.mfa !== false ||
    !user.attributes.roles.includes("github-reader") || !kids.includes(v.header.kid)) {
  console.error(JSON.stringify({ verified: v.verified, header: v.header, kids, user })); process.exit(1);
}
console.log(`ok   TypeScript SDK: root token for ${v.agent}, verified; header kid ${v.header.kid} is in the server JWKS`);
' "$ROOT/sdk/typescript/dist/index.js"
else
  echo "skip: no node or no sdk/typescript/dist"; SKIPPED+=(typescript-sdk)
fi

say "5. hop 0 with the CLI (token exchange --subject-token-type id-token)"
CLI_ID_TOKEN="$(login)"
cli_hop0() {  # the CLI's hop 0 of $CLI_ID_TOKEN, the secret on stdin
  printf '%s\n' "$PLANNER_SECRET" | ATTENUO_TOKEN="$CLI_ID_TOKEN" "$CLI" --json token exchange \
    --subject-token-type id-token --actor planner --client-secret-stdin \
    --cap '{"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"prefix","value":"acme/"}}}'
}
CLI_ROOT="$(cli_hop0 | jq_py 'd.get("access_token", "")')"
[ -n "$CLI_ROOT" ] || fail "hop 0 with the CLI refused"
"$CLI" token inspect "$CLI_ROOT" --verify > "$WORK/inspect-cli.txt"
grep -q "issuer $REALM" "$WORK/inspect-cli.txt" || fail "CLI root token: issuer not in the user block"
grep -q '"github-reader"' "$WORK/inspect-cli.txt" || fail "CLI root token: roles attribute"
ok "CLI: root token for planner, verified, issuer $REALM, roles github-reader"
if OUT="$(cli_hop0 2>&1)"; then fail "the CLI's second use of one ID token was not refused"; fi
printf %s "$OUT" | grep -q 'invalid_grant (replayed): this credential was already used' \
  || fail "expected the replay refusal: $OUT"
ok "CLI: the same ID token again: invalid_grant (replayed), already used"

say "6. key rotation at Keycloak"
REALM_ID="$(kc get realms/acme --fields id --format csv --noquotes)"
OLD_KID="$(printf %s "$HEADER" | jq_py 'd["kid"]')"
sleep 31   # past the server's 30 s floor between early JWKS refetches
kc create components -r acme -s name=rsa-rotated -s providerId=rsa-generated \
  -s providerType=org.keycloak.keys.KeyProvider -s parentId="$REALM_ID" \
  -s 'config.priority=["500"]' -s 'config.algorithm=["RS256"]'
ROTATED="$(login)"
NEW_KID="$(jwt_part "$ROTATED" 0 | jq_py 'd["kid"]')"
[ "$NEW_KID" != "$OLD_KID" ] || fail "Keycloak still signs with the old key"
[ -n "$(hop0 "$ROTATED" | jq_py 'd.get("access_token", "")')" ] || fail "token from the new key refused"
grep -q 'unknown kid; refetching JWKS' "$WORK/server.log" || fail "no refetch logged"
ok "new kid $NEW_KID: one early JWKS refetch, then accepted"

say "7. a narrowed child exchange and MCP calls through the proxy"
CODER="$(printf '%s\n' "$CODER_SECRET" | ATTENUO_TOKEN="$ROOT_TOKEN" "$CLI" token exchange \
  --actor coder --client-secret-stdin --no-delegation \
  --cap '{"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"prefix","value":"acme/api"}}}' \
  | sed -n -E 's/^token +([^ ]+).*/\1/p' | head -n1)"
[ -n "$CODER" ] || fail "child exchange refused"
ok "planner -> coder, get_file_contents on acme/api only"
OUT="$(ATTENUO_TOKEN="$CODER" "$CLI" call --upstream github --tool get_file_contents \
  --arg repo=acme/api --arg path=src/lib.rs)"
printf %s "$OUT" | grep -q ALLOWED || fail "allowed call: $OUT"
ok "coder reads acme/api: ALLOWED (policy readers_read_acme matched the Keycloak role)"
OUT="$(ATTENUO_TOKEN="$CODER" "$CLI" call --upstream github --tool get_file_contents \
  --arg repo=acme/billing --arg path=README.md || true)"
printf %s "$OUT" | grep -q capability_denied || fail "expected capability_denied: $OUT"
ok "coder reads acme/billing: capability_denied"
OUT="$(ATTENUO_TOKEN="$ROOT_TOKEN" "$CLI" call --upstream github --tool create_issue \
  --arg repo=acme/api --arg title=t || true)"
printf %s "$OUT" | grep -q policy_deny || fail "expected policy_deny: $OUT"
ok "planner opens an issue: policy_deny, the policy needs mfa and Keycloak sent no amr"
[ "$(grep -c 'tools/call' "$WORK/fake-mcp.log")" = 1 ] || fail "expected exactly one upstream call"
ok "one tools/call reached the upstream"

say "8. Keycloak's AMR mapper"
kc get serverinfo | jq_py '[p["name"] for p in d["protocolMapperTypes"]["openid-connect"] if p["id"] == "oidc-amr-mapper"]' \
  | sed 's/^/mapper type oidc-amr-mapper: /'
kc create "clients/$CID/protocol-mappers/models" -r acme -s name=amr -s protocol=openid-connect \
  -s protocolMapper=oidc-amr-mapper -s 'config."id.token.claim"=true' -s 'config."access.token.claim"=true'
AMR="$(jwt_part "$(login)" 1 | jq_py 'd.get("amr")')"
[ "$AMR" = "[]" ] || fail "expected an empty amr from the mapper alone, got $AMR"
ok "mapper alone: amr = [] (no authenticator has a reference value)"
EXEC="$(kc get authentication/flows/browser/executions -r acme | \
  jq_py '[e["id"] for e in d if e.get("providerId") == "auth-username-password-form"][0]')"
kc create "authentication/executions/$EXEC/config" -r acme -s alias=amr-pwd \
  -s 'config."default.reference.value"=pwd' -s 'config."default.reference.maxAge"=36000'
AMR="$(jwt_part "$(login)" 1 | jq_py 'd.get("amr")')"
[ "$AMR" = "['pwd']" ] || fail "expected amr ['pwd'], got $AMR"
ok "with a reference value on the password step: amr = ['pwd'] (mfa stays false)"

say "9. the audit chain"
ATTENUO_ADMIN_TOKEN="$ADMIN_TOKEN" "$CLI" audit verify
if [ "${#SKIPPED[@]}" -gt 0 ]; then
  fail "skipped: ${SKIPPED[*]}; this run is incomplete"
fi
echo "keycloak smoke test passed"
