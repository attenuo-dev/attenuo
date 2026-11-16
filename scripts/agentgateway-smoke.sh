#!/usr/bin/env bash
# One allowed and one denied MCP tool call through a real agentgateway that asks attenuo
# (`/ext-authz/v1/mcp/{server}`), set up as docs/guides/agentgateway.md says.
#
#   AGENTGATEWAY_BIN=/path/to/agentgateway scripts/agentgateway-smoke.sh
#
# Starts fake_mcp (the upstream), attenuo-server with an `[[ext_authz]]` entry, and agentgateway
# with the guide's YAML, all on 127.0.0.1 with free ports. Mints a token for `coder` that may
# call `github:read_file` only, then through the gateway: initialize, tools/call `read_file`
# (expects 200, the call reaches fake_mcp once, attenuo records an allow) and tools/call
# `create_issue` (expects 403 with JSON-RPC -32003 `capability_denied` and an
# `x-attenuo-decision-id` header, the call does not reach fake_mcp). Exits non-zero on any
# mismatch.
#
# Not part of CI. Run with agentgateway v1.7.0 (commit 26f5aebe) on 2026-11-16; other versions
# may differ. Needs curl and python3. Skips with exit status 0 when AGENTGATEWAY_BIN is unset.
#
# Environment:
#   AGENTGATEWAY_BIN     the agentgateway binary (required, else the script skips)
#   ATTENUO_BIN_DIR=DIR  prebuilt attenuo-server, attenuo, examples/fake_mcp (default: cargo build)
#   KEEP=1               keep the temp dir (logs, configs)

set -euo pipefail

if [ -z "${AGENTGATEWAY_BIN:-}" ]; then
  echo "skip: AGENTGATEWAY_BIN is not set"
  exit 0
fi
if [ ! -x "$AGENTGATEWAY_BIN" ]; then
  echo "AGENTGATEWAY_BIN=$AGENTGATEWAY_BIN is not an executable file" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/attenuo-agentgateway-smoke.XXXXXX")"
chmod 700 "$WORK"
PIDS=()
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
    echo "agentgateway smoke test failed (exit $rc). Last log lines:" >&2
    for f in server.log agentgateway.log fake_mcp.log; do
      echo "--- $f" >&2
      tail -n 10 "$WORK/$f" >&2 2>/dev/null || true
    done
  fi
  if [ "${KEEP:-0}" = 1 ]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_http() {
  for _ in $(seq 100); do
    curl -s -o /dev/null "$1" && return 0
    sleep 0.2
  done
  fail "nothing answers at $1"
}

if [ -n "${ATTENUO_BIN_DIR:-}" ]; then
  BIN="$ATTENUO_BIN_DIR"
else
  cargo build -q -p attenuo-server -p attenuo-cli
  cargo build -q -p attenuo-proxy --features testing --example fake_mcp
  BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
fi

MCP_PORT="$(free_port)"; AT_PORT="$(free_port)"; GW_PORT="$(free_port)"
ADMIN_PORT="$(free_port)"; STATS_PORT="$(free_port)"; READY_PORT="$(free_port)"

echo "agentgateway: $("$AGENTGATEWAY_BIN" -V 2>/dev/null || echo unknown)"

cd "$WORK"
mkdir data
cp "$ROOT/config/policies/default.cedar" policy.cedar
ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
CODER_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
GW_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
sha256() { printf %s "$1" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'; }

cat > attenuo.toml <<EOF
[server]
listen = "127.0.0.1:$AT_PORT"

[issuer]
private_key_pem_path = "data/issuer.pem"

[policy]
policies_path = "policy.cedar"

[policy.catalog.github.read_file]
readonly = true
inputs = { repo = "string", path = "string" }

[policy.catalog.github.create_issue]
inputs = { repo = "string", title = "string" }

[policy.catalog.github.delete_repo]
sensitive = true
inputs = { repo = "string" }

[audit]
sqlite_path = "data/attenuo.sqlite"

[[ext_authz]]
server = "github"
secret_sha256 = "$(sha256 "$GW_SECRET")"

[admin]
token = "$ADMIN_TOKEN"

[[agents]]
id = "coder"
secret_sha256 = "$(sha256 "$CODER_SECRET")"

[[root_grants]]
issuer = "https://idp.example"
agent = "planner"
capabilities = ["github:*"]

[dev]
allow_root_mint = true
EOF
chmod 600 attenuo.toml

# The guide's YAML, with this run's ports and secret. The config: block only moves the admin,
# stats and readiness listeners off their default ports.
cat > agentgateway.yaml <<EOF
config:
  adminAddr: 127.0.0.1:$ADMIN_PORT
  statsAddr: 127.0.0.1:$STATS_PORT
  readinessAddr: 127.0.0.1:$READY_PORT
gateways:
  default:
    port: $GW_PORT
    bindAddress: 127.0.0.1
mcp:
  targets:
  - name: github
    mcp:
      host: http://127.0.0.1:$MCP_PORT/mcp
  policies:
    extAuthz:
      host: 127.0.0.1:$AT_PORT
      protocol:
        http:
          path: '"/ext-authz/v1/mcp/github"'
          addRequestHeaders:
            x-attenuo-gateway-secret: '"$GW_SECRET"'
      includeRequestHeaders: [authorization, dpop]
      includeRequestBody:
        maxRequestBytes: 1048576
      failureMode: deny
    requestHeaderModifier:
      remove: [authorization, dpop]
EOF
chmod 600 agentgateway.yaml

"$BIN/examples/fake_mcp" --port "$MCP_PORT" > fake_mcp.log 2>&1 &
PIDS+=($!)
"$BIN/attenuo-server" --config attenuo.toml > server.log 2>&1 &
PIDS+=($!)
"$AGENTGATEWAY_BIN" -f agentgateway.yaml > agentgateway.log 2>&1 &
PIDS+=($!)
wait_http "http://127.0.0.1:$AT_PORT/healthz"
wait_http "http://127.0.0.1:$READY_PORT/healthz/ready"
wait_http "http://127.0.0.1:$GW_PORT/"

export ATTENUO_SERVER="http://127.0.0.1:$AT_PORT" ATTENUO_ADMIN_TOKEN="$ADMIN_TOKEN"
ROOT_TOKEN="$("$BIN/attenuo" token root --subject alice --agent planner --cap 'github:*' --print token)"
CODER="$(ATTENUO_TOKEN="$ROOT_TOKEN" ATTENUO_CLIENT_SECRET="$CODER_SECRET" \
  "$BIN/attenuo" token exchange --actor coder --cap github:read_file --print token)"

URL="http://127.0.0.1:$GW_PORT/mcp"
# post NAME BODY [SESSION]: writes NAME.headers and NAME.body, prints the status.
post() {
  local extra=()
  [ -n "${3:-}" ] && extra=(-H "mcp-session-id: $3")
  curl -s -o "$1.body" -D "$1.headers" -w '%{http_code}' -X POST "$URL" \
    -H "authorization: Bearer $CODER" -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' -H 'mcp-protocol-version: 2025-06-18' \
    "${extra[@]}" -d "$2"
}
header() { awk -v h="$2" 'BEGIN{IGNORECASE=1} tolower($0) ~ "^"h":" {sub(/^[^:]*: */,""); sub(/\r$/,""); print}' "$1.headers"; }
upstream_calls() { grep -c "tools/call $1" fake_mcp.log || true; }

s="$(post init '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}')"
[ "$s" = 200 ] || fail "initialize: HTTP $s: $(cat init.body)"
SESSION="$(header init mcp-session-id)"
[ -n "$SESSION" ] || fail "initialize: no mcp-session-id"
s="$(post initialized '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$SESSION")"
[ "$s" = 202 ] || fail "notifications/initialized: HTTP $s"
echo "ok   initialize through the gateway"

s="$(post allowed '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"acme/api","path":"README.md"}}}' "$SESSION")"
[ "$s" = 200 ] || fail "allowed call: HTTP $s: $(cat allowed.body)"
grep -q '"isError":false' allowed.body || fail "allowed call: unexpected body: $(cat allowed.body)"
[ "$(upstream_calls read_file)" = 1 ] || fail "allowed call: fake_mcp saw $(upstream_calls read_file) read_file calls, expected 1"
"$BIN/attenuo" --json audit tail > audit.json
python3 - audit.json <<'PY' || fail "allowed call: no allow record for github/read_file in the audit log"
import json, sys
text = open(sys.argv[1]).read()
ok = any(r.get("tool") == "read_file" and r.get("server") == "github" and r.get("decision") == "allow"
         and r.get("id")
         for r in (json.loads(l)["record"] for l in text.splitlines() if l.strip()))
sys.exit(0 if ok else 1)
PY
echo "ok   allowed call: 200, reached fake_mcp once, allow recorded"

s="$(post denied '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"create_issue","arguments":{"repo":"acme/api","title":"x"}}}' "$SESSION")"
[ "$s" = 403 ] || fail "denied call: HTTP $s, expected 403: $(cat denied.body)"
python3 - denied.body "$(header denied x-attenuo-decision-id)" <<'PY' || fail "denied call: unexpected body or header: $(cat denied.body)"
import json, sys
b = json.load(open(sys.argv[1]))
e = b["error"]
assert b["id"] == 3, b
assert e["code"] == -32003, e
assert e["data"]["code"] == "capability_denied", e
assert e["data"]["decision_id"] == sys.argv[2] != "", (e, sys.argv[2])
PY
[ "$(upstream_calls create_issue)" = 0 ] || fail "denied call reached fake_mcp"
echo "ok   denied call: 403, JSON-RPC -32003 capability_denied, x-attenuo-decision-id, not forwarded"

echo "agentgateway smoke test passed"
