#!/usr/bin/env bash
# Smoke test of the admin console listener against the real attenuo-server binary.
#
#   scripts/admin-ui-smoke.sh
#
# Starts the server with `[admin_ui] enabled = true` on free local ports and checks with curl:
# the page answers 200 with the console's CSP, `/admin/audit` is 401 without the admin token
# and 200 with it, and `/admin/root-token` is 404 on the console port even with the dev mint on.
# Exits non-zero on the first check that fails. Linux and macOS; needs curl and python3.
#
# Environment:
#   ATTENUO_BIN_DIR=DIR  use a prebuilt attenuo-server from DIR instead of `cargo build`

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/attenuo-ui-smoke.XXXXXX")"
PID=""
cleanup() {
  local rc=$?
  [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
  wait 2>/dev/null || true
  if [ "$rc" -ne 0 ]; then
    echo "admin console smoke test failed (exit $rc). Server log:" >&2
    tail -n 20 "$WORK/server.log" >&2 2>/dev/null || true
  fi
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT INT TERM

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}

if [ -n "${ATTENUO_BIN_DIR:-}" ]; then
  SERVER="$ATTENUO_BIN_DIR/attenuo-server"
else
  cargo build --locked -q -p attenuo-server
  TARGET="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
  SERVER="$TARGET/debug/attenuo-server"
fi

MAIN_PORT="$(free_port)"
UI_PORT="$(free_port)"
while [ "$UI_PORT" = "$MAIN_PORT" ]; do UI_PORT="$(free_port)"; done
ADMIN_TOKEN="smoke-admin-token"

cat > "$WORK/config.toml" <<EOF
[server]
listen = "127.0.0.1:$MAIN_PORT"

[audit]
sqlite_path = ":memory:"

[admin]
token = "$ADMIN_TOKEN"

[admin_ui]
enabled = true
listen = "127.0.0.1:$UI_PORT"

# On, to show the console listener never mounts the dev mint.
[dev]
allow_root_mint = true
EOF

RUST_LOG=warn "$SERVER" --config "$WORK/config.toml" > "$WORK/server.log" 2>&1 &
PID=$!

UI="http://127.0.0.1:$UI_PORT"
for _ in $(seq 1 100); do
  curl -sf -o /dev/null "$UI/admin/ui/" && break
  sleep 0.1
done

fail() { echo "FAIL: $*" >&2; exit 1; }
# status METHOD URL [curl args...]: print the HTTP status code.
status() {
  local method="$1" url="$2"
  shift 2
  curl -s -o /dev/null -w '%{http_code}' -X "$method" "$@" "$url"
}

# 1. The page, with the console's CSP.
code="$(curl -s -o "$WORK/index.html" -D "$WORK/headers" -w '%{http_code}' "$UI/admin/ui/")"
[ "$code" = 200 ] || fail "GET /admin/ui/ answered $code, want 200"
csp="$(tr -d '\r' < "$WORK/headers" | sed -n 's/^[Cc]ontent-[Ss]ecurity-[Pp]olicy: //p')"
want="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'"
[ "$csp" = "$want" ] || fail "CSP is '$csp'"
grep -q '<!doctype html>' "$WORK/index.html" || fail "the page is not the console HTML"
echo "ok  GET /admin/ui/ 200 with the console CSP"

# 2. The admin API needs the admin token.
code="$(status GET "$UI/admin/audit")"
[ "$code" = 401 ] || fail "GET /admin/audit without a token answered $code, want 401"
echo "ok  GET /admin/audit without a token: 401"
code="$(status GET "$UI/admin/audit?limit=1" -H "Authorization: Bearer $ADMIN_TOKEN")"
[ "$code" = 200 ] || fail "GET /admin/audit with the token answered $code, want 200"
echo "ok  GET /admin/audit with the token: 200"
# The console's login check: the token's operator and role (ADR-0016).
who="$(curl -s "$UI/admin/whoami" -H "Authorization: Bearer $ADMIN_TOKEN")"
[ "$who" = '{"name":"admin","role":"admin"}' ] || fail "GET /admin/whoami answered '$who'"
echo "ok  GET /admin/whoami with the token: admin, role admin"

# 3. The dev mint is on the main listener only.
body='{"subject":"alice","issuer":"https://idp.example","agent":"planner","capabilities":["github:*"]}'
code="$(status POST "$UI/admin/root-token" -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' -d "$body")"
[ "$code" = 404 ] || fail "POST /admin/root-token on the console answered $code, want 404"
echo "ok  POST /admin/root-token on the console port: 404"

echo "admin console smoke test passed"
