#!/usr/bin/env bash
# The HAProxy recipe of docs/guides/deploying.md ("Forwarded client certificates") against a
# real attenuo-server: deploy/haproxy/forwarded-client-cert.cfg as it is, with only its
# environment variables set.
#
#   HAPROXY_BIN=/usr/sbin/haproxy scripts/haproxy-forwarded-smoke.sh
#
# Makes the certificates with openssl, starts attenuo-server with [server.forwarded_client_cert]
# and HAProxy in front of it, all on 127.0.0.1 with free ports. Then, over HTTP/1.1 and over
# HTTP/2 to HAProxy: a pinned self-signed certificate (200), a CA-issued one (200), a stranger's
# certificate with coder's id (401 client_authentication_failed), forged Client-Cert and
# Client-Cert-Chain headers from a client with no certificate (401 client_auth_missing) and
# from one with the stranger's certificate (401 client_authentication_failed), and a CA-issued
# certificate with a forged chain (200: the forged chain is dropped). Also: `haproxy -c` gives
# no "rules ignored" warning, a direct request from 127.0.0.2 is 403, the header sent to the
# main listener is 400, HAProxy resumes no TLS session (TLS 1.2 and 1.3), and its per-address
# limit answers /token requests over 300 a minute with 429. Exits non-zero on any mismatch.
#
# Not part of CI. Run with HAProxy 2.8.30 on 2026-11-24. Needs curl (with HTTP/2), openssl and
# python3. Skips with exit status 0 when HAPROXY_BIN is unset.
#
# Environment:
#   HAPROXY_BIN          the haproxy binary (required, else the script skips)
#   ATTENUO_BIN_DIR=DIR  a prebuilt attenuo-server (default: cargo build)
#   KEEP=1               keep the temp dir (logs, configs, certificates)

set -euo pipefail

if [ -z "${HAPROXY_BIN:-}" ]; then
  echo "skip: HAPROXY_BIN is not set"
  exit 0
fi
if [ ! -x "$HAPROXY_BIN" ]; then
  echo "HAPROXY_BIN=$HAPROXY_BIN is not an executable file" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RECIPE="$ROOT/deploy/haproxy/forwarded-client-cert.cfg"
cd "$ROOT"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/attenuo-haproxy-smoke.XXXXXX")"
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
    echo "haproxy smoke test failed (exit $rc). Last log lines:" >&2
    for f in server.log haproxy.log; do
      echo "--- $f" >&2
      tail -n 15 "$WORK/$f" >&2 2>/dev/null || true
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
    curl -s -o /dev/null "$@" && return 0
    sleep 0.2
  done
  fail "nothing answers at $*"
}

if [ -n "${ATTENUO_BIN_DIR:-}" ]; then
  BIN="$ATTENUO_BIN_DIR"
else
  cargo build -q -p attenuo-server
  BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
fi

MAIN_PORT="$(free_port)"; FWD_PORT="$(free_port)"; PROXY_PORT="$(free_port)"
echo "haproxy: $("$HAPROXY_BIN" -v | head -n 1)"

cd "$WORK"
mkdir data

# --- certificates -------------------------------------------------------------------------
ossl() { openssl "$@" 2>/dev/null; }
ext() { printf '%s\n' "$@" > "$WORK/ext.cnf"; echo "$WORK/ext.cnf"; }
key() { ossl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }
# A CA: root, then an intermediate under it, then the proxy's CA for its server certificate.
key root.key
ossl req -x509 -new -key root.key -subj "/CN=smoke agents root CA" -days 2 -out root.crt \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
key mid.key
ossl req -new -key mid.key -subj "/CN=smoke agents intermediate CA" -out mid.csr
ossl x509 -req -in mid.csr -CA root.crt -CAkey root.key -CAcreateserial -days 2 -out mid.crt \
  -extfile "$(ext "basicConstraints=critical,CA:TRUE" "keyUsage=critical,keyCertSign,cRLSign")"
# planner: issued by the intermediate, SAN DNS.
key planner.key
ossl req -new -key planner.key -subj "/CN=planner" -out planner.csr
ossl x509 -req -in planner.csr -CA mid.crt -CAkey mid.key -CAcreateserial -days 2 -out planner.crt \
  -extfile "$(ext "basicConstraints=CA:FALSE" "extendedKeyUsage=clientAuth" "subjectAltName=DNS:planner.agents.internal")"
cat planner.crt mid.crt > planner-chain.crt
# coder and stranger: self-signed.
for who in coder stranger; do
  key "$who.key"
  ossl req -x509 -new -key "$who.key" -subj "/CN=$who" -days 2 -out "$who.crt" \
    -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=clientAuth"
done
# The agents' CA file holds the intermediate (HAProxy does not forward the chain) and the root.
cat mid.crt root.crt > agents-ca.pem
# The proxy's server certificate.
key proxy-ca.key
ossl req -x509 -new -key proxy-ca.key -subj "/CN=smoke proxy CA" -days 2 -out proxy-ca.crt \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
key proxy.key
ossl req -new -key proxy.key -subj "/CN=localhost" -out proxy.csr
ossl x509 -req -in proxy.csr -CA proxy-ca.crt -CAkey proxy-ca.key -CAcreateserial -days 2 -out proxy.crt \
  -extfile "$(ext "basicConstraints=CA:FALSE" "subjectAltName=DNS:localhost")"
cat proxy.crt proxy.key > proxy.pem
CODER_SHA="$(openssl x509 -in coder.crt -outform DER | sha256sum | cut -d' ' -f1)"
CODER_DER="$(openssl x509 -in coder.crt -outform DER | base64 -w0)"
MID_DER="$(openssl x509 -in mid.crt -outform DER | base64 -w0)"

# --- attenuo ------------------------------------------------------------------------------
ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
cat > attenuo.toml <<EOF
[server]
listen = "127.0.0.1:$MAIN_PORT"
public_url = "https://localhost:$PROXY_PORT"

[server.forwarded_client_cert]
listen = "127.0.0.1:$FWD_PORT"
trusted_peers = ["127.0.0.1/32"]

[issuer]
issuer = "https://attenuo.test"
private_key_pem_path = "data/issuer.pem"

[audit]
sqlite_path = "data/attenuo.sqlite"

[admin]
token = "$ADMIN_TOKEN"

[dev]
allow_root_mint = true

[[agents]]
id = "coder"
tls_client_cert_sha256 = ["$CODER_SHA"]

[[agents]]
id = "planner"
tls_client_ca_pem_path = "$WORK/agents-ca.pem"
tls_client_auth_san_dns = "planner.agents.internal"
EOF
chmod 600 attenuo.toml
"$BIN/attenuo-server" --config attenuo.toml > server.log 2>&1 &
PIDS+=($!)
wait_http "http://127.0.0.1:$MAIN_PORT/healthz"

# --- HAProxy, with the recipe as it is ------------------------------------------------------
export ATTENUO_PROXY_BIND="127.0.0.1:$PROXY_PORT"
export ATTENUO_PROXY_PEM="$WORK/proxy.pem"
export ATTENUO_CLIENT_CA="$WORK/agents-ca.pem"
export ATTENUO_FORWARDING="127.0.0.1:$FWD_PORT"
"$HAPROXY_BIN" -c -f "$RECIPE" > haproxy-check.log 2>&1 || { cat haproxy-check.log >&2; fail "haproxy -c"; }
if grep -qi "ignored" haproxy-check.log; then cat haproxy-check.log >&2; fail "haproxy -c warns that rules are ignored"; fi
echo "ok   haproxy -c: valid, no rules ignored"
"$HAPROXY_BIN" -db -f "$RECIPE" > haproxy.log 2>&1 &
PIDS+=($!)
wait_http --cacert proxy-ca.crt "https://localhost:$PROXY_PORT/healthz"

# --- the cases ------------------------------------------------------------------------------
root() {
  curl -s -X POST "http://127.0.0.1:$MAIN_PORT/admin/root-token" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"subject":"alice","issuer":"https://idp.test","agent":"frontdesk","capabilities":["github:*"]}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}
# exchange NAME PROTO ACTOR WANT_STATUS WANT_CODE [curl options]
TOKEN_REQUESTS=0
exchange() {
  TOKEN_REQUESTS=$((TOKEN_REQUESTS + 1))
  local name=$1 proto=$2 actor=$3 want=$4 want_code=$5; shift 5
  local parent out status code
  parent="$(root)"
  out="$(curl -s -w '\n%{http_code} %{http_version}' --cacert proxy-ca.crt "--$proto" "$@" \
    -X POST "https://localhost:$PROXY_PORT/token" -H 'Content-Type: application/json' \
    -d "{\"grant_type\":\"urn:ietf:params:oauth:grant-type:token-exchange\",\"subject_token\":\"$parent\",\"subject_token_type\":\"urn:ietf:params:oauth:token-type:jwt\",\"actor\":\"$actor\",\"client_id\":\"$actor\",\"authorization_details\":[{\"type\":\"attenuo_capabilities\",\"capabilities\":[{\"server\":\"github\",\"tool\":\"read_file\"}]}]}")"
  status="$(tail -n 1 <<<"$out")"
  code="$(head -n -1 <<<"$out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("code",""))' 2>/dev/null || true)"
  case "$proto:${status#* }" in http1.1:1.1|http2:2) ;; *) fail "$name over $proto: spoke HTTP ${status#* }";; esac
  [ "${status%% *}" = "$want" ] || fail "$name over $proto: status ${status%% *}, want $want"
  [ "$code" = "$want_code" ] || fail "$name over $proto: code '$code', want '$want_code'"
  echo "ok   $name over $proto: ${status%% *}${code:+ $code}"
}
for proto in http1.1 http2; do
  exchange "coder, pinned self-signed certificate" "$proto" coder 200 "" --cert coder.crt --key coder.key
  exchange "planner, CA-issued certificate" "$proto" planner 200 "" --cert planner-chain.crt --key planner.key
  exchange "the stranger's certificate with coder's id" "$proto" coder 401 client_authentication_failed \
    --cert stranger.crt --key stranger.key
  exchange "no certificate, forged Client-Cert" "$proto" coder 401 client_auth_missing \
    -H "Client-Cert: :$CODER_DER:"
  exchange "no certificate, forged Client-Cert and Client-Cert-Chain" "$proto" coder 401 client_auth_missing \
    -H "Client-Cert: :$CODER_DER:" -H "Client-Cert-Chain: :$MID_DER:"
  exchange "no certificate, forged Client-Cert-Chain alone" "$proto" coder 401 client_auth_missing \
    -H "Client-Cert-Chain: :$MID_DER:"
  exchange "the stranger's certificate, forged headers claiming coder's" "$proto" coder 401 client_authentication_failed \
    --cert stranger.crt --key stranger.key -H "Client-Cert: :$CODER_DER:" -H "Client-Cert-Chain: :$CODER_DER:"
  exchange "planner's certificate, a forged chain that is not well formed" "$proto" planner 200 "" \
    --cert planner-chain.crt --key planner.key -H "Client-Cert-Chain: :AAAA:, junk"
done

status="$(curl -s -o /dev/null -w '%{http_code}' --interface 127.0.0.2 "http://127.0.0.1:$FWD_PORT/healthz" \
  -H "Client-Cert: :$CODER_DER:" -H 'X-Forwarded-For: 127.0.0.1')"
[ "$status" = 403 ] || fail "a direct request from 127.0.0.2: $status, want 403"
echo "ok   a direct request from 127.0.0.2 to the forwarding listener: 403"
status="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$MAIN_PORT/healthz" -H "Client-Cert: :$CODER_DER:")"
[ "$status" = 400 ] || fail "Client-Cert on the main listener: $status, want 400"
echo "ok   Client-Cert sent to the main listener: 400"
for v in tls1_2 tls1_3; do
  rm -f sess.pem
  (sleep 1) | openssl s_client "-$v" -connect "127.0.0.1:$PROXY_PORT" -servername localhost -CAfile proxy-ca.crt \
    -cert coder.crt -key coder.key -sess_out sess.pem > first.out 2>&1 || true
  if [ -s sess.pem ]; then
    (sleep 1) | openssl s_client "-$v" -connect "127.0.0.1:$PROXY_PORT" -servername localhost -CAfile proxy-ca.crt \
      -sess_in sess.pem > second.out 2>&1 || true
    grep -q '^Reused,' second.out && fail "HAProxy resumed a $v session"
    grep -q '^New,' second.out || fail "the second $v connection did not complete"
  fi
  grep -q '^New,' first.out || fail "the first $v connection did not complete"
  echo "ok   no $v session resumption"
done
grep -q 'client_cert_source="forwarded"' server.log || grep -q 'client_cert_source=forwarded' server.log \
  || fail "no log line names client_cert_source forwarded"
echo "ok   the log names client_cert_source forwarded"
# Last, since it uses up this address's minute: HAProxy's own limit on /token.
args=()
for _ in $(seq 302); do args+=(-o /dev/null "https://localhost:$PROXY_PORT/token"); done
codes="$(curl -s --cacert proxy-ca.crt -w '%{http_code}\n' "${args[@]}")"
# The cases above sent $TOKEN_REQUESTS of this minute's requests already.
left=$((300 - TOKEN_REQUESTS))
[ "$(head -n "$left" <<<"$codes" | grep -c '^429$')" = 0 ] || fail "a /token request within the limit was refused"
[ "$(tail -n +"$((left + 1))" <<<"$codes" | grep -vc '^429$')" = 0 ] || fail "a /token request over the limit was not refused"
echo "ok   HAProxy answers /token requests over 300 a minute from one address with 429"
echo "all cases passed"
