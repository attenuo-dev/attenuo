#!/usr/bin/env bash
# The first hop from a real login: an OIDC ID token, exchanged at POST /token (RFC 8693).
#
#   examples/idp-exchange-demo/run.sh
#
# Starts a mock OIDC identity provider, attenuo-server (with the dev root mint off) and a fake
# GitHub MCP server on free local ports, then plays the scenario with curl and the `attenuo`
# CLI. The IdP is a mock for demonstration: it signs an ID token for a fixed user, alice, for
# anyone who asks. No model, no real IdP, no real GitHub and no network beyond loopback.
# Exits non-zero if any step does not come out as expected. Re-runnable: nothing is written
# outside a temp dir, which the exit trap removes.
#
# Environment:
#   KEEP=1                keep the temp dir (logs, rendered config) after the run
#   ATTENUO_BIN_DIR=DIR   use prebuilt attenuo-server / attenuo / examples/fake_mcp /
#                         examples/mock_idp from DIR instead of building (default: cargo build
#                         into the target dir)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/attenuo-idp-exchange.XXXXXX")"
PIDS=()

cleanup() {
  local rc=$?
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [ "$rc" -ne 0 ]; then
    echo >&2
    echo "demo failed (exit $rc). Last server log lines:" >&2
    tail -n 15 "$WORK/server.log" 2>/dev/null >&2 || true
  fi
  if [ "${KEEP:-0}" = 1 ]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

# --- output helpers ------------------------------------------------------------------------
if [ -t 1 ]; then B=$'\033[1m'; D=$'\033[2m'; R=$'\033[0m'; else B=""; D=""; R=""; fi
say()  { printf '\n%s== %s%s\n' "$B" "$*" "$R"; }
note() { printf '%s# %s%s\n' "$D" "$*" "$R"; }

# Show a command, run it, show its output, and check its exit status (default 0).
# Usage: step EXPECTED_STATUS 'command string'      -> output also left in $OUT
step() {
  local want="$1" cmd="$2" rc=0
  printf '$ %s\n' "$cmd"
  OUT="$(eval "$cmd" 2>&1)" || rc=$?
  # Long tokens make a transcript unreadable; shorten them for display only.
  printf '%s\n' "$OUT" | sed -E -e 's/(token +[A-Za-z0-9_-]{24})[A-Za-z0-9_.-]+/\1.../' \
    -e 's/^(eyJ[A-Za-z0-9_-]{21})[A-Za-z0-9_.-]+$/\1.../'
  if [ "$rc" -ne "$want" ]; then
    echo "!! expected exit status $want, got $rc" >&2
    exit 1
  fi
}

# Check that the last step's output contains a string.
expect() {
  printf '%s\n' "$OUT" | grep -qF -- "$1" || { echo "!! expected output to contain: $1" >&2; exit 1; }
}

# Pull `key  value` out of the CLI's text output.
field() { printf '%s\n' "$OUT" | sed -n -E "s/^$1 +([^ ]+).*/\1/p" | head -n1; }

# Pretty-print a JSON body from stdin, with long strings (tokens) shortened for display; the
# body itself is kept in $WORK/last.json.
pretty() {
  tee "$WORK/last.json" | python3 -c '
import json, sys
def short(v):
    if isinstance(v, str) and len(v) > 48 and " " not in v: return v[:24] + "..."
    if isinstance(v, dict): return {k: short(x) for k, x in v.items()}
    if isinstance(v, list): return [short(x) for x in v]
    return v
print(json.dumps(short(json.load(sys.stdin)), indent=2))'
}

# One member of the last JSON body.
json_get() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$WORK/last.json" "$1"; }

# The header and claims of a JWT, decoded without verifying it (display only).
jwt_claims() {
  python3 -c '
import base64, json, sys
def part(s): return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
h, p, _ = sys.argv[1].split(".")
print("header ", json.dumps(part(h)))
print("claims ", json.dumps(part(p), indent=2))' "$1"
}

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])' \
    2>/dev/null || echo $((20000 + RANDOM % 30000))
}

# --- build ----------------------------------------------------------------------------------
if [ -n "${ATTENUO_BIN_DIR:-}" ]; then
  BIN="$ATTENUO_BIN_DIR"
else
  echo "building (first run takes a while)..." >&2
  cargo build -q -p attenuo-server -p attenuo-cli
  cargo build -q -p attenuo-server --example mock_idp
  cargo build -q -p attenuo-proxy --features testing --example fake_mcp
  BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
fi
SERVER_BIN="$BIN/attenuo-server"; CLI="$BIN/attenuo"
FAKE_BIN="$BIN/examples/fake_mcp"; [ -x "$FAKE_BIN" ] || FAKE_BIN="$BIN/fake_mcp"
IDP_BIN="$BIN/examples/mock_idp"; [ -x "$IDP_BIN" ] || IDP_BIN="$BIN/mock_idp"
attenuo() { "$CLI" "$@"; }

# --- start the mock IdP first: its URL is the issuer the server config names ----------------
"$IDP_BIN" --port 0 --client-id agent-platform --subject alice \
  > "$WORK/idp.out" 2> "$WORK/idp.log" &
PIDS+=($!)
for _ in $(seq 1 100); do
  grep -q '^listening on ' "$WORK/idp.out" 2>/dev/null && break
  sleep 0.1
done
IDP="$(sed -n 's/^listening on //p' "$WORK/idp.out")"
[ -n "$IDP" ] || { echo "mock IdP did not start" >&2; exit 1; }

# --- then attenuo-server and the fake GitHub MCP server on free ports ----------------------
OB_PORT="$(free_port)"; MCP_PORT="$(free_port)"
while [ "$MCP_PORT" = "$OB_PORT" ]; do MCP_PORT="$(free_port)"; done

sed -e "s#http://127.0.0.1:19001#$IDP#g" -e "s/18091/$OB_PORT/g" -e "s/13003/$MCP_PORT/g" \
    -e "s#examples/idp-exchange-demo/policy.cedar#$HERE/policy.cedar#" \
    "$HERE/config.toml" > "$WORK/config.toml"

"$FAKE_BIN" --port "$MCP_PORT" --tools get_file_contents,create_issue \
  > "$WORK/fake-mcp.out" 2> "$WORK/fake-mcp.log" &
PIDS+=($!)
RUST_LOG=warn "$SERVER_BIN" --config "$WORK/config.toml" > "$WORK/server.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 100); do
  curl -sf "http://127.0.0.1:$OB_PORT/healthz" >/dev/null 2>&1 \
    && grep -q listening "$WORK/fake-mcp.out" 2>/dev/null && break
  sleep 0.1
done
curl -sf "http://127.0.0.1:$OB_PORT/healthz" >/dev/null || { echo "server did not start" >&2; exit 1; }

export ATTENUO_SERVER="http://127.0.0.1:$OB_PORT"
export ATTENUO_ADMIN_TOKEN="demo-admin-token"
unset ATTENUO_TOKEN ATTENUO_CLIENT_SECRET

EXCHANGE="urn:ietf:params:oauth:grant-type:token-exchange"
ID_TOKEN_TYPE="urn:ietf:params:oauth:token-type:id_token"
# What the planner asks for at hop 0: exactly its [[root_grants]] ceiling.
ROOT_CAPS='[{"type":"attenuo_capabilities","capabilities":[
  {"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"prefix","value":"acme/"}}},
  {"server":"github","tool":"create_issue","constraints":{"repo":{"op":"prefix","value":"acme/"}}}]}]'

# --- the scenario --------------------------------------------------------------------------
say "Setup"
note "Mock OIDC IdP (demonstration only) at $IDP; attenuo at $ATTENUO_SERVER trusts it in [[idps]]."
note "attenuo proxies a fake GitHub MCP server at port $MCP_PORT as 'github'. [dev] allow_root_mint = false."

say "1. The dev shortcut the other demos use is off"
note "POST /admin/root-token is not mounted, so the only way to a root token is POST /token."
step 1 'attenuo token root --subject alice --agent planner'
expect "404"

say "2. alice signs in at the IdP; the agent platform receives her ID token"
note "The mock's /demo/id-token stands in for the browser login and the authorization-code flow."
step 0 'curl -sSf "$IDP/demo/id-token"'
ID_TOKEN="$OUT"
step 0 'jwt_claims "$ID_TOKEN"'
expect '"sub": "alice"'
expect '"aud": "agent-platform"'

say "3. Hop 0: the planner exchanges alice's ID token for a root token at POST /token (RFC 8693)"
note "The planner authenticates as itself (HTTP Basic). attenuo fetches the IdP's discovery"
note "document and JWKS, verifies the signature, iss, aud (the planner's client id), exp and iat,"
note "then attenuates the request against the [[root_grants]] entry for this IdP and agent."
step 0 'curl -sS "$ATTENUO_SERVER/token" -u planner:demo-planner-secret \
  --data-urlencode grant_type="$EXCHANGE" \
  --data-urlencode subject_token="$ID_TOKEN" \
  --data-urlencode subject_token_type="$ID_TOKEN_TYPE" \
  --data-urlencode authorization_details="$ROOT_CAPS" | pretty'
expect '"access_token"'
ROOT_TOKEN="$(json_get access_token)"
note "expires_in is about 300 s, not the 900 s default: a root token never outlives its ID token."

say "4. The same ID token a second time: refused, each IdP credential mints one root token"
step 0 'curl -sS "$ATTENUO_SERVER/token" -u planner:demo-planner-secret \
  --data-urlencode grant_type="$EXCHANGE" \
  --data-urlencode subject_token="$ID_TOKEN" \
  --data-urlencode subject_token_type="$ID_TOKEN_TYPE" \
  --data-urlencode authorization_details="$ROOT_CAPS" | pretty'
expect '"replayed"'

say "5. The root token: alice from the IdP, the planner at hop 1"
note "The originating user is built from the verified ID token: sub, iss, and the claims in"
note "[[idps]] attribute_claims (email, amr), plus mfa derived from amr."
step 0 'attenuo token inspect "$ROOT_TOKEN" --verify'
expect "$IDP"
expect "planner"

say "6. Exchange: planner -> coder, narrowed to reading acme/api, and nobody may exchange it further"
note "The coder authenticates as itself (its secret on stdin)."
step 0 'printf "%s\n" demo-coder-secret | ATTENUO_TOKEN="$ROOT_TOKEN" attenuo token exchange --actor coder --client-secret-stdin --no-delegation --cap '"'"'{"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"prefix","value":"acme/api"}}}'"'"''
CODER="$(field token)"
[ -n "$CODER" ] || { echo "!! expected the exchange to print a token" >&2; exit 1; }

say "7. The coder reads a file in acme/api: allowed"
step 0 'ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool get_file_contents --arg repo=acme/api --arg path=src/lib.rs'
expect ALLOWED

say "8. The coder reads a file in acme/billing: denied, outside what the planner delegated"
note "The policy would allow any acme/ repository; the coder's token covers only acme/api."
step 2 'ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool get_file_contents --arg repo=acme/billing --arg path=README.md'
expect capability_denied

say "9. The audit log: every record goes back to alice, and the hash chain checks out"
note "#1 is the hop-0 exchange (token.root). There is no dev-mint (admin) record: none was made."
step 0 'attenuo audit tail -n 20'
step 0 'attenuo audit verify'
expect "audit chain OK: 5 entries verified"

say "What reached the GitHub server"
UPSTREAM_CALLS="$(grep -c 'tools/call' "$WORK/fake-mcp.log" || true)"
grep 'tools/call' "$WORK/fake-mcp.log" | sed 's/^/  /'
echo "  -> $UPSTREAM_CALLS tools/call reached upstream (the coder's read of acme/api). The denied call never left attenuo."
[ "$UPSTREAM_CALLS" = 1 ] || { echo "!! expected exactly 1 upstream call" >&2; exit 1; }

say "What the IdP served"
sed 's/^/  /' "$WORK/idp.log"
