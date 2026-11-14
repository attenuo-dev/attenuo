#!/usr/bin/env bash
# The S3 checkpoint sink over HTTPS and with temporary (STS) credentials, against a real MinIO.
#
#   scripts/live-minio-tls-sts-smoke.sh
#   STS_EXPIRY=1 scripts/live-minio-tls-sts-smoke.sh   # also step 9 (waits about 16 minutes)
#
# The sibling of scripts/live-minio-smoke.sh, which runs the sink over plain HTTP with static
# keys. This one makes a private CA (openssl) and starts MinIO (pinned image, host network,
# 127.0.0.1 only) serving TLS with a certificate from it, sets it up with the image's own `mc`
# (a bucket with Object Lock and a default COMPLIANCE retention, a user whose only permission
# is `s3:PutObject` on it), and runs attenuo-server with the S3 sink pointed at it. Checks:
#
#   1. MinIO serves TLS with the run's CA (curl with the CA accepts, curl without it refuses);
#   2. without `ca_pem_path` every PUT is refused, the server logs the TLS cause (`invalid peer
#      certificate: UnknownIssuer`), decisions are still made, `/readyz` is 200 and degraded;
#   3. with `ca_pem_path` naming another CA: refused the same way;
#   4. a `ca_pem_path` that holds no certificate: the server refuses to start, naming it;
#   5. with the run's CA: one object per checkpoint, each the canonical shipped envelope of
#      the checkpoint the server signed; `audit verify --checkpoints` accepts the export
#      against them and exits 2 once one is altered;
#   6. endpoint spellings over TLS: `https://LOCALHOST:<port>/` (a non-default port), and
#      `https://127.0.0.1:443` and `https://127.0.0.1` (a second TLS MinIO on port 443, root
#      in its container; the step fails as skipped if the port is taken);
#   7. `http://` next to `https://`: a plain-HTTP MinIO gets objects from an `http://`
#      endpoint (with `ca_pem_path` set, which the server warns is not used); `http://` to
#      the TLS port and `https://` to the plain port are refused, and the log says why;
#   8. STS: `AssumeRole` for the PutObject-only user (a SigV4-signed POST by curl) gives a
#      temporary key, secret and session token; the sink with all three delivers; MinIO's
#      own trace shows `X-Amz-Security-Token` sent and listed in `SignedHeaders`; the same
#      key and secret without the token, and with a changed token, are refused (403, the log
#      names S3's error code), decisions are still made, the failure counter rises and
#      `/readyz` is degraded;
#   9. (STS_EXPIRY=1 only) temporary credentials that expire while the server runs: PUTs
#      start failing (the log names the code), nothing refreshes them, and a restart with new
#      ones delivers again. MinIO's shortest AssumeRole is 900 seconds, hence the opt-in.
#
# Not part of CI. Needs docker (the daemon running), curl (7.75 or later, for --aws-sigv4),
# openssl and python3. Skips with exit status 0 when docker is not available. Every secret
# (the MinIO root password, the sink user's secret, the temporary credentials, the admin
# token, the CA keys) is random per run and stays in the temp dir (mode 0700, files 0600).
# curl reads the sink user's secret from a config file, not its argument list; `mc` inside
# the container takes the root password and the sink secret as arguments, which other local
# users can read in `ps` while it runs (as in live-minio-smoke.sh). Nothing leaves the
# machine except the image pull.
#
# Environment:
#   MINIO_IMAGE          MinIO image with `minio` and `mc` (default: the pinned digest below)
#   ATTENUO_BIN_DIR=DIR  prebuilt attenuo-server, attenuo, examples/fake_mcp (default: cargo build)
#   STS_EXPIRY=1         run step 9
#   KEEP=1               keep the temp dir (logs, config, objects)

set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# The image live-minio-smoke.sh pins: bitnamilegacy/minio:2025.7.23 (Docker Hub), MinIO
# server RELEASE.2025-07-23 and mc RELEASE.2025-07-21.
MINIO_IMAGE="${MINIO_IMAGE:-bitnamilegacy/minio@sha256:8935e75fa5d11295c17171e4aa49efe390a1193cd7f12e4d21b92af9ffef09d7}"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "skip: docker is not available (no client, or the daemon is not running)"
  exit 0
fi
command -v openssl >/dev/null 2>&1 || { echo "!! openssl is needed for the run's CA" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/attenuo-minio-tls.XXXXXX")"
chmod 700 "$WORK"
C_TLS="attenuo-minio-tls-$$"
C_443="attenuo-minio-tls-443-$$"
C_HTTP="attenuo-minio-http-$$"
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
    echo "minio tls/sts smoke test failed (exit $rc). Last server and MinIO log lines:" >&2
    tail -n 10 "$WORK"/server*.log 2>/dev/null >&2 || true
    docker logs --tail 10 "$C_TLS" >&2 2>/dev/null || true
  fi
  docker rm -f "$C_TLS" "$C_443" "$C_HTTP" >/dev/null 2>&1 || true
  if [ "${KEEP:-0}" = 1 ]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

say() { printf '\n== %s\n' "$*"; }
ok() { printf 'ok   %s\n' "$*"; }
fail() { echo "!! $*" >&2; exit 1; }
rand() { od -An -tx1 -N16 /dev/urandom | tr -d ' \n'; }
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
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

TLS_PORT="$(free_port)"; HTTP_PORT="$(free_port)"; MCP_PORT="$(free_port)"
TLS="https://127.0.0.1:$TLS_PORT"
PLAIN="http://127.0.0.1:$HTTP_PORT"
BUCKET=attenuo-checkpoints
rand > "$WORK/root.pw"; rand > "$WORK/sink.secret"; rand > "$WORK/admin.token"
SINK_USER=attenuo-sink

# --- the run's CA and MinIO's certificate ---------------------------------------------------
say "a private CA for this run (openssl)"
mkdir "$WORK/pki"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -keyout "$WORK/pki/ca.key" -out "$WORK/ca.pem" -subj "/CN=attenuo minio smoke CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$WORK/pki/private.key" -out "$WORK/pki/leaf.csr" -subj "/CN=127.0.0.1" 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' > "$WORK/pki/leaf.ext"
openssl x509 -req -in "$WORK/pki/leaf.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/pki/ca.key" \
  -CAcreateserial -days 1 -extfile "$WORK/pki/leaf.ext" -out "$WORK/pki/public.crt" 2>/dev/null
# Another CA, which did not issue MinIO's certificate (step 3), and a file with no certificate
# (step 4).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -keyout "$WORK/pki/other.key" -out "$WORK/other-ca.pem" -subj "/CN=attenuo minio smoke other CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
cp "$WORK/pki/other.key" "$WORK/not-a-cert.pem"
# What goes into each MinIO container (docker cp, not a bind mount, so the files stay 0600 in
# the 0700 temp dir): MinIO's certificate and key, and the CA for the container's own `mc`.
mkdir -p "$WORK/ctr/certs/CAs" "$WORK/ctr/mc/certs/CAs"
cp "$WORK/pki/public.crt" "$WORK/pki/private.key" "$WORK/ctr/certs/"
cp "$WORK/ca.pem" "$WORK/ctr/certs/CAs/ca.pem"
cp "$WORK/ca.pem" "$WORK/ctr/mc/certs/CAs/ca.pem"
ok "CA, MinIO certificate for IP:127.0.0.1 and DNS:localhost, another CA"

# --- MinIO -----------------------------------------------------------------------------------
start_minio() {  # name address [tls] -> a running MinIO; root in the container (port 443)
  local name="$1" addr="$2" tls="${3:-}"
  local args=(server /tmp/data --address "$addr" --console-address "127.0.0.1:$(free_port)")
  [ -n "$tls" ] && args+=(--certs-dir /attenuo/certs)
  MINIO_ROOT_PASSWORD="$(cat "$WORK/root.pw")" \
  docker create --name "$name" --network host --user 0 --entrypoint minio \
    -e MINIO_ROOT_USER=minio-root -e MINIO_ROOT_PASSWORD "$MINIO_IMAGE" "${args[@]}" >/dev/null
  docker cp "$WORK/ctr" "$name:/attenuo" >/dev/null
  docker start "$name" >/dev/null
}
wait_live() {  # url-base -> MinIO answers its liveness probe (over TLS: with the run's CA)
  for _ in $(seq 1 60); do
    curl -sf --cacert "$WORK/ca.pem" "$1/minio/health/live" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}
say "MinIO over TLS: $MINIO_IMAGE"
start_minio "$C_TLS" "127.0.0.1:$TLS_PORT" tls
wait_live "$TLS" || fail "MinIO over TLS did not start"
docker exec "$C_TLS" minio --version | head -n1
mcx() { local c="$1"; shift; docker exec "$c" mc --config-dir /attenuo/mc "$@" </dev/null; }
mc() { mcx "$C_TLS" "$@"; }

say "1. MinIO serves TLS with a certificate from the run's CA"
curl -sf --cacert "$WORK/ca.pem" "$TLS/minio/health/live" >/dev/null || fail "curl with the CA"
if curl -sf "$TLS/minio/health/live" >/dev/null 2>&1; then
  fail "curl without the run's CA accepted MinIO's certificate"
fi
openssl s_client -connect "127.0.0.1:$TLS_PORT" -CAfile "$WORK/ca.pem" </dev/null 2>/dev/null \
  | grep -m1 -E 'Verify return code' | sed 's/^ */    /'
ok "curl --cacert <run CA> accepts $TLS; curl with the system roots refuses it"

mc alias set root "$TLS" minio-root "$(cat "$WORK/root.pw")" >/dev/null
mc mb --with-lock "root/$BUCKET" >/dev/null
mc retention set --default COMPLIANCE 1d "root/$BUCKET" >/dev/null
mc admin user add root "$SINK_USER" "$(cat "$WORK/sink.secret")" >/dev/null
cat > "$WORK/put-only.json" <<EOF
{"Version": "2012-10-17",
 "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject"],
                "Resource": ["arn:aws:s3:::$BUCKET/*"]}]}
EOF
docker cp "$WORK/put-only.json" "$C_TLS:/attenuo/put-only.json" >/dev/null
mc admin policy create root attenuo-put-only /attenuo/put-only.json >/dev/null
mc admin policy attach root attenuo-put-only --user "$SINK_USER" >/dev/null
ok "bucket $BUCKET: Object Lock, COMPLIANCE 1 day; user $SINK_USER: s3:PutObject only (mc over TLS)"

# --- attenuo-server --------------------------------------------------------------------------
# write_config port sqlite prefix max_lag -> config on stdout. ENDPOINT, CA (a path or empty),
# KEY_ID, SECRET_FILE and TOKEN_FILE (a path or empty) choose the sink's endpoint and keys.
write_config() {
  cat <<EOF
[server]
listen = "127.0.0.1:$1"
public_url = "http://127.0.0.1:$1"

[issuer]
issuer = "http://127.0.0.1:$1"
audience = "attenuo"
# One key for every server of the run, so a restart on the same log keeps its checkpoints'
# signatures valid (step 10).
private_key_pem_path = "$WORK/issuer.pem"

[policy]
policies_path = "$ROOT/examples/github-leak-demo/policy.cedar"

[policy.catalog.github.read_file]
readonly = true
inputs = { repo = "string", path = "string" }

[policy.catalog.github.create_issue]
inputs = { repo = "string", title = "string" }

[approvals]
client_id = "minio-tls-smoke"

[audit]
sqlite_path = "$WORK/$2"
checkpoint_every = 2

[audit.sink]
kind = "s3"
endpoint = "${ENDPOINT:-$TLS}"
bucket = "$BUCKET"
prefix = "$3"
access_key_id = "${KEY_ID:-$SINK_USER}"
secret_access_key = "$(cat "${SECRET_FILE:-$WORK/sink.secret}")"
initial_backoff_ms = 200
max_backoff_seconds = 1
max_lag_seconds = $4
EOF
  if [ -n "${TOKEN_FILE:-}" ]; then echo "session_token = \"$(cat "$TOKEN_FILE")\""; fi
  if [ -n "${CA:-}" ]; then echo "ca_pem_path = \"$CA\""; fi
  cat <<EOF

[[upstreams]]
name = "github"
url = "http://127.0.0.1:$MCP_PORT/mcp"

[admin]
token = "$(cat "$WORK/admin.token")"

[metrics]
enabled = true
listen = "127.0.0.1:$5"

[dev]
allow_root_mint = true
EOF
}
SERVER_PID=
start_server() {  # name prefix max_lag -> server on $PORT, log $WORK/server-<name>.log
  PORT="$(free_port)"; MPORT="$(free_port)"
  write_config "$PORT" "${SQLITE:-audit-$1.sqlite}" "$2" "$3" "$MPORT" > "$WORK/config-$1.toml"
  RUST_LOG=info "$BIN/attenuo-server" --config "$WORK/config-$1.toml" > "$WORK/server-$1.log" 2>&1 &
  SERVER_PID=$!
  PIDS+=("$SERVER_PID")
  for _ in $(seq 1 100); do
    curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
    sleep 0.1
  done
  curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null || fail "server $1 did not start"
  export ATTENUO_SERVER="http://127.0.0.1:$PORT"
}
stop_server() { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
token_of() { sed -n -E 's/^token +([^ ]+).*/\1/p' | head -n1; }
decisions() {  # audit records: a root token and two calls (one allowed, one denied)
  local root out
  root="$("$CLI" token root --subject alice --agent assistant --cap 'github:*' | token_of)"
  [ -n "$root" ] || fail "no root token"
  out="$(ATTENUO_TOKEN="$root" "$CLI" call --upstream github --tool read_file \
    --arg repo=alice/public-docs --arg path=README.md)"
  printf %s "$out" | grep -q ALLOWED || fail "allowed call: $out"
  out="$(ATTENUO_TOKEN="$root" "$CLI" call --upstream github --tool read_file \
    --arg repo=alice/private --arg path=README.md || true)"
  printf %s "$out" | grep -q policy_deny || fail "expected policy_deny: $out"
}
count_objects() {  # container alias/path -> number of object versions
  mcx "$1" ls --recursive --versions --json "$2" 2>/dev/null | grep -c '"type":"file"' || true
}
wait_objects() {  # container alias/path n -> succeeds once n objects are there
  for _ in $(seq 1 75); do
    [ "$(count_objects "$1" "$2")" -ge "$3" ] && return 0
    sleep 0.2
  done
  return 1
}
wait_log() {  # file pattern -> succeeds once the log holds it
  for _ in $(seq 1 75); do
    grep -q -- "$2" "$1" && return 0
    sleep 0.2
  done
  return 1
}
show() { grep -m1 -- "$2" "$1" | sed -E 's/^.*(WARN|ERROR|INFO) /    \1 /'; }
metric() { curl -sf "http://127.0.0.1:$MPORT/metrics" | sed -n "s/^$1 //p"; }
degraded_readyz() {  # name -> /readyz is 200 and reports the sink degraded
  local code
  code="$(curl -s -o "$WORK/readyz-$1.json" -w '%{http_code}' "$ATTENUO_SERVER/readyz")"
  [ "$code" = 200 ] || fail "$1: readyz $code (fail_readiness is off)"
  [ "$(jq_py 'd["checks"]["checkpoint_sink"]' < "$WORK/readyz-$1.json")" = degraded ] \
    || fail "$1: readyz not degraded: $(cat "$WORK/readyz-$1.json")"
}
export ATTENUO_ADMIN_TOKEN
ATTENUO_ADMIN_TOKEN="$(cat "$WORK/admin.token")"
unset ATTENUO_TOKEN ATTENUO_CLIENT_SECRET

"$FAKE_BIN" --port "$MCP_PORT" --tools read_file,create_issue \
  > "$WORK/fake-mcp.out" 2> "$WORK/fake-mcp.log" &
PIDS+=($!)

say "2. no ca_pem_path: the built-in roots do not hold the run's CA"
CA= start_server noca noca/ 2
decisions
wait_log "$WORK/server-noca.log" 'delivery failed' || fail "no delivery failure logged"
show "$WORK/server-noca.log" 'delivery failed'
grep -q 'invalid peer certificate: UnknownIssuer' "$WORK/server-noca.log" \
  || fail "the log does not name the TLS cause"
ok "every PUT refused; the log names the cause: invalid peer certificate: UnknownIssuer"
ok "decisions are made while the sink fails (allowed and policy_deny as usual)"
sleep 3
degraded_readyz noca
ok "/readyz: 200, checks.checkpoint_sink = degraded"
[ "$(count_objects "$C_TLS" "root/$BUCKET/noca/")" = 0 ] || fail "an object arrived under noca/"
stop_server

say "3. ca_pem_path naming another CA"
CA="$WORK/other-ca.pem" start_server otherca otherca/ 300
decisions
wait_log "$WORK/server-otherca.log" 'UnknownIssuer' || fail "no UnknownIssuer with another CA"
show "$WORK/server-otherca.log" 'delivery failed'
[ "$(count_objects "$C_TLS" "root/$BUCKET/otherca/")" = 0 ] || fail "an object arrived under otherca/"
ok "refused: invalid peer certificate: UnknownIssuer, nothing stored"
stop_server

say "4. a ca_pem_path that holds no certificate refuses to start"
P="$(free_port)"
CA="$WORK/not-a-cert.pem" write_config "$P" audit-bad.sqlite bad/ 300 "$(free_port)" > "$WORK/config-bad.toml"
set +e
timeout 20 "$BIN/attenuo-server" --config "$WORK/config-bad.toml" > "$WORK/server-bad.log" 2>&1
RC=$?
set -e
[ "$RC" != 0 ] && [ "$RC" != 124 ] || fail "the server started (exit $RC) with a CA file holding no certificate"
grep -q '\[audit.sink\] ca_pem_path' "$WORK/server-bad.log" || fail "the error does not name ca_pem_path: $(tail -n3 "$WORK/server-bad.log")"
grep -m1 'ca_pem_path' "$WORK/server-bad.log" | sed 's/^/    /'
ok "exit $RC, naming [audit.sink] ca_pem_path and the file"

say "5. ca_pem_path = the run's CA: checkpoints reach the bucket over TLS"
PREFIX=attenuo/checkpoints/
CA="$WORK/ca.pem" SQLITE=audit-tls.sqlite start_server tls "$PREFIX" 300
TLS_SERVER="$ATTENUO_SERVER"
for _ in 1 2 3; do decisions; done
"$CLI" audit export --out "$WORK/export.jsonl" >/dev/null
WANT="$(grep -c '"type":"checkpoint"' "$WORK/export.jsonl" || true)"
[ "$WANT" -ge 3 ] || fail "expected at least 3 checkpoints in the export, got $WANT"
wait_objects "$C_TLS" "root/$BUCKET/$PREFIX" "$WANT" || fail "expected $WANT objects"
[ "$(count_objects "$C_TLS" "root/$BUCKET/$PREFIX")" = "$WANT" ] || fail "more objects than checkpoints"
ok "$WANT checkpoints signed, $WANT objects at $TLS/$BUCKET/$PREFIX..."
mkdir "$WORK/objects"
mc ls --recursive --json "root/$BUCKET/$PREFIX" \
  | python3 -c 'import json,sys; [print(json.loads(l)["key"]) for l in sys.stdin if l.strip()]' \
  | while read -r key; do mc cat "root/$BUCKET/$PREFIX$key" > "$WORK/objects/$key"; done
python3 - "$WORK/export.jsonl" "$WORK/objects" "$TLS_SERVER" <<'EOF'
import hashlib, json, os, sys
export, objdir, public_url = sys.argv[1:]
canon = lambda v: json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
signed = {}
for line in open(export):
    d = json.loads(line)
    if d.get("type") == "checkpoint":
        signed[d["seq"]] = {k: d[k] for k in ("seq", "head_hash", "at", "kid", "signature")}
for name in sorted(os.listdir(objdir)):
    raw = open(os.path.join(objdir, name), "rb").read()
    obj = json.loads(raw)
    assert raw == canon(obj), f"{name}: not canonical JSON"
    cp = obj["checkpoint"]
    assert cp == signed.pop(cp["seq"]), f"{name}: differs from the server's checkpoint"
    sha = hashlib.sha256(canon(cp)).hexdigest()
    assert obj["checkpoint_sha256"] == sha and name == f"{cp['seq']:020d}-{sha[:16]}.json", name
    assert obj["format"] == "attenuo-shipped-checkpoint-v1" and obj["public_url"] == public_url
assert not signed, f"signed but not shipped: {sorted(signed)}"
print(f"    {len(os.listdir(objdir))} objects: canonical, match the export, sha256 and keys ok")
EOF
ok "object bytes = canonical shipped envelope of each signed checkpoint"
curl -sf "$TLS_SERVER/.well-known/jwks.json" > "$WORK/jwks.json"
for f in "$WORK"/objects/*; do cat "$f"; echo; done > "$WORK/shipped.jsonl"
"$CLI" audit verify --file "$WORK/export.jsonl" --jwks "$WORK/jwks.json" \
  --checkpoints "$WORK/shipped.jsonl" --allow-unsigned-tail | sed 's/^/    /'
ok "verify --checkpoints accepts the export against the objects fetched over TLS"
python3 - "$WORK/shipped.jsonl" "$WORK/tampered.jsonl" <<'EOF'
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
lines[0]["checkpoint"]["head_hash"] = "0" * 64
open(sys.argv[2], "w").write("".join(json.dumps(l) + "\n" for l in lines))
EOF
set +e
"$CLI" audit verify --file "$WORK/export.jsonl" --jwks "$WORK/jwks.json" \
  --checkpoints "$WORK/tampered.jsonl" --allow-unsigned-tail > "$WORK/verify-tampered.out" 2>&1
RC=$?
set -e
[ "$RC" = 2 ] || { cat "$WORK/verify-tampered.out"; fail "a changed object: expected exit 2, got $RC"; }
ok "one object's head_hash changed: verify exits 2"
[ "$(metric attenuo_audit_sink_delivered_total)" -ge "$WANT" ] || fail "delivered_total below $WANT"
ok "attenuo_audit_sink_delivered_total = $(metric attenuo_audit_sink_delivered_total), failures_total = $(metric attenuo_audit_sink_failures_total)"
stop_server

say "6. endpoint spellings over TLS: the signed host is the host sent"
ENDPOINT="https://LOCALHOST:$TLS_PORT/" CA="$WORK/ca.pem" start_server upper spelling-upper/ 300
decisions
wait_objects "$C_TLS" "root/$BUCKET/spelling-upper/" 1 \
  || { show "$WORK/server-upper.log" 'delivery failed' >&2; fail "https://LOCALHOST:<port>/: nothing arrived"; }
ok "endpoint https://LOCALHOST:$TLS_PORT/ (non-default port, upper case, trailing /): objects arrive"
stop_server
if python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",443))' 2>/dev/null; then
  start_minio "$C_443" 127.0.0.1:443 tls
  wait_live https://127.0.0.1 || true
fi
if curl -sf --cacert "$WORK/ca.pem" https://127.0.0.1/minio/health/live >/dev/null 2>&1 \
   && docker ps -q --filter "name=$C_443" | grep -q .; then
  mcx "$C_443" alias set root https://127.0.0.1 minio-root "$(cat "$WORK/root.pw")" >/dev/null
  mcx "$C_443" mb "root/$BUCKET" >/dev/null
  for ep in https://127.0.0.1:443 https://127.0.0.1; do
    n="p443-$( [ "$ep" = https://127.0.0.1 ] && echo implicit || echo explicit )"
    ENDPOINT="$ep" KEY_ID=minio-root SECRET_FILE="$WORK/root.pw" CA="$WORK/ca.pem" \
      start_server "$n" "$n/" 300
    decisions
    wait_objects "$C_443" "root/$BUCKET/$n/" 1 \
      || { show "$WORK/server-$n.log" 'delivery failed' >&2; fail "endpoint $ep: nothing arrived"; }
    ok "endpoint $ep: objects arrive (signed host 127.0.0.1, no :443)"
    stop_server
  done
else
  echo "skip: port 443 is taken; the explicit-:443 check did not run"
  SKIPPED+=("endpoint with :443")
fi

say "7. http:// next to https://"
start_minio "$C_HTTP" "127.0.0.1:$HTTP_PORT"
wait_live "$PLAIN" || fail "plain-HTTP MinIO did not start"
mcx "$C_HTTP" alias set root "$PLAIN" minio-root "$(cat "$WORK/root.pw")" >/dev/null
mcx "$C_HTTP" mb "root/$BUCKET" >/dev/null
ENDPOINT="$PLAIN" KEY_ID=minio-root SECRET_FILE="$WORK/root.pw" CA="$WORK/ca.pem" \
  start_server plain plain/ 300
decisions
wait_objects "$C_HTTP" "root/$BUCKET/plain/" 1 || fail "http:// endpoint: nothing arrived"
ok "endpoint $PLAIN (plain HTTP MinIO, while the TLS one runs): objects arrive"
grep -q 'ca_pem_path is set but the sink.s URL is http://' "$WORK/server-plain.log" \
  || fail "no warning that ca_pem_path is unused with http://"
show "$WORK/server-plain.log" 'ca_pem_path is set'
ok "the server warns that ca_pem_path is not used with an http:// endpoint"
stop_server
ENDPOINT="http://127.0.0.1:$TLS_PORT" start_server http2tls http2tls/ 300
decisions
wait_log "$WORK/server-http2tls.log" 'delivery failed' || fail "http:// to the TLS port: no failure logged"
show "$WORK/server-http2tls.log" 'delivery failed'
grep -q 'S3 answered 400 Bad Request' "$WORK/server-http2tls.log" || fail "http:// to TLS: expected 400"
ok "http:// to the TLS port: refused, S3 answered 400 Bad Request (MinIO: HTTP request to an HTTPS server)"
stop_server
ENDPOINT="https://127.0.0.1:$HTTP_PORT" CA="$WORK/ca.pem" KEY_ID=minio-root SECRET_FILE="$WORK/root.pw" \
  start_server tls2http tls2http/ 300
decisions
wait_log "$WORK/server-tls2http.log" 'delivery failed' || fail "https:// to the plain port: no failure logged"
show "$WORK/server-tls2http.log" 'delivery failed'
grep -q -i 'InvalidContentType\|corrupt message\|tls' "$WORK/server-tls2http.log" \
  || fail "https:// to the plain port: no TLS cause in the log"
[ "$(count_objects "$C_HTTP" "root/$BUCKET/tls2http/")" = 0 ] || fail "an object arrived under tls2http/"
ok "https:// to the plain port: refused, the log names the TLS cause"
stop_server

say "8. STS: temporary credentials from AssumeRole"
assume_role() {  # seconds -> $WORK/sts.{key,secret,token,expiration}
  # The sink user's secret goes to curl in a config file (0600), not on its command line.
  printf 'user = "%s:%s"\n' "$SINK_USER" "$(cat "$WORK/sink.secret")" > "$WORK/sts.curlrc"
  curl -sS -K "$WORK/sts.curlrc" --cacert "$WORK/ca.pem" --aws-sigv4 "aws:amz:us-east-1:sts" \
    -X POST --data "Action=AssumeRole&Version=2011-06-15&DurationSeconds=$1" "$TLS/" > "$WORK/sts.xml"
  python3 - "$WORK/sts.xml" "$WORK/sts" <<'EOF'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
ns = {"s": "https://sts.amazonaws.com/doc/2011-06-15/"}
c = root.find(".//s:Credentials", ns)
assert c is not None, open(sys.argv[1]).read()
for tag, ext in (("AccessKeyId", "key"), ("SecretAccessKey", "secret"),
                 ("SessionToken", "token"), ("Expiration", "expiration")):
    open(f"{sys.argv[2]}.{ext}", "w").write(c.find(f"s:{tag}", ns).text)
EOF
}
assume_role 900
ok "AssumeRole (SigV4-signed POST to MinIO's STS over TLS) for $SINK_USER: key $(cut -c1-4 "$WORK/sts.key")..., session token $(wc -c < "$WORK/sts.token") bytes, expires $(cat "$WORK/sts.expiration")"
# MinIO's own view of the requests: `mc admin trace --verbose` prints each S3 call's headers.
docker exec "$C_TLS" sh -c 'exec timeout 30 mc --config-dir /attenuo/mc admin trace --verbose --call s3 root' \
  > "$WORK/trace.out" 2>&1 &
TRACE_PID=$!
PIDS+=("$TRACE_PID")
sleep 2
KEY_ID="$(cat "$WORK/sts.key")" SECRET_FILE="$WORK/sts.secret" TOKEN_FILE="$WORK/sts.token" \
  CA="$WORK/ca.pem" start_server sts sts/ 300
decisions
wait_objects "$C_TLS" "root/$BUCKET/sts/" 1 \
  || { show "$WORK/server-sts.log" 'delivery failed' >&2; fail "STS credentials: nothing arrived"; }
ok "the sink with access_key_id, secret_access_key and session_token: objects arrive"
for _ in $(seq 1 50); do grep -q 'X-Amz-Security-Token' "$WORK/trace.out" && break; sleep 0.2; done
python3 - "$WORK/trace.out" "$WORK/sts.token" <<'EOF'
import re, sys
trace = open(sys.argv[1], encoding="utf-8", errors="replace").read()
token = open(sys.argv[2]).read().strip()
puts = [b for b in trace.split("[REQUEST s3.PutObject]")[1:] if "/sts/" in b.split("\n", 2)[1]]
assert puts, "no PutObject under sts/ in MinIO's trace"
for b in puts:
    sent = re.search(r"X-Amz-Security-Token: (\S+)", b)
    assert sent and sent.group(1) == token, "the session token was not sent as issued"
    signed = re.search(r"SignedHeaders=([^,\s]+)", b).group(1).split(";")
    assert "x-amz-security-token" in signed, f"not signed: {signed}"
    assert re.search(r"\n[^\n]* 200 OK", b), "not answered 200"
print(f"    {len(puts)} PutObject: X-Amz-Security-Token = the issued token; SignedHeaders = {';'.join(signed)}")
EOF
ok "MinIO's trace: x-amz-security-token sent and in SignedHeaders, answered 200"
stop_server
KEY_ID="$(cat "$WORK/sts.key")" SECRET_FILE="$WORK/sts.secret" TOKEN_FILE= \
  CA="$WORK/ca.pem" start_server notoken notoken/ 300
decisions
wait_log "$WORK/server-notoken.log" 'S3 answered 403' || fail "no session token: no 403 logged"
show "$WORK/server-notoken.log" 'S3 answered 403'
[ "$(count_objects "$C_TLS" "root/$BUCKET/notoken/")" = 0 ] || fail "an object arrived without the token"
ok "the temporary key and secret without session_token: refused (403), nothing stored"
stop_server
python3 -c 'import sys; t=open(sys.argv[1]).read().strip(); i=len(t)//2; print(t[:i] + ("A" if t[i] != "A" else "B") + t[i+1:], end="")' \
  "$WORK/sts.token" > "$WORK/sts-wrong.token"
KEY_ID="$(cat "$WORK/sts.key")" SECRET_FILE="$WORK/sts.secret" TOKEN_FILE="$WORK/sts-wrong.token" \
  CA="$WORK/ca.pem" start_server wrongtoken wrongtoken/ 2
decisions
ok "decisions are made while every PUT is refused"
wait_log "$WORK/server-wrongtoken.log" 'S3 answered 403 Forbidden (' || fail "a changed token: no 403 with a code"
show "$WORK/server-wrongtoken.log" 'S3 answered 403'
CODE="$(sed -n 's/.*S3 answered 403 Forbidden (\([A-Za-z0-9]*\)).*/\1/p' "$WORK/server-wrongtoken.log" | head -n1)"
ok "a changed session token: refused, the log names S3's code: $CODE"
sleep 3
degraded_readyz wrongtoken
[ "$(metric attenuo_audit_sink_failures_total)" -ge 1 ] || fail "failures_total did not rise"
[ "$(metric attenuo_audit_sink_delivered_total)" = 0 ] || fail "delivered_total is not 0"
ok "/readyz 200 and degraded; attenuo_audit_sink_failures_total = $(metric attenuo_audit_sink_failures_total), delivered_total = 0"
[ "$(count_objects "$C_TLS" "root/$BUCKET/wrongtoken/")" = 0 ] || fail "an object arrived with a changed token"
stop_server

if [ "${STS_EXPIRY:-0}" = 1 ]; then
  say "9. temporary credentials that expire while the server runs"
  assume_role 900
  EXP="$(cat "$WORK/sts.expiration")"
  KEY_ID="$(cat "$WORK/sts.key")" SECRET_FILE="$WORK/sts.secret" TOKEN_FILE="$WORK/sts.token" \
    CA="$WORK/ca.pem" SQLITE=audit-expiry.sqlite start_server expiry expiry/ 60
  decisions
  wait_objects "$C_TLS" "root/$BUCKET/expiry/" 1 || fail "expiry: nothing arrived before the expiry"
  BEFORE="$(count_objects "$C_TLS" "root/$BUCKET/expiry/")"
  ok "$BEFORE objects delivered with credentials that expire at $EXP"
  WAIT="$(python3 -c 'import datetime,sys; e=datetime.datetime.fromisoformat(sys.argv[1].replace("Z","+00:00")); print(max(0, int((e-datetime.datetime.now(datetime.timezone.utc)).total_seconds()) + 15))' "$EXP")"
  echo "    waiting ${WAIT}s for the credentials to expire..."
  sleep "$WAIT"
  decisions
  wait_log "$WORK/server-expiry.log" 'S3 answered 4' || fail "expiry: no refusal logged after the expiry"
  show "$WORK/server-expiry.log" 'S3 answered 4'
  sleep 3
  [ "$(count_objects "$C_TLS" "root/$BUCKET/expiry/")" = "$BEFORE" ] || fail "an object arrived after the expiry"
  ok "after the expiry: every PUT refused, nothing refreshes the credentials; decisions still made"
  sleep 60
  degraded_readyz expiry
  ok "/readyz 200 and degraded once max_lag_seconds (60) passed"
  stop_server
  assume_role 900
  KEY_ID="$(cat "$WORK/sts.key")" SECRET_FILE="$WORK/sts.secret" TOKEN_FILE="$WORK/sts.token" \
    CA="$WORK/ca.pem" SQLITE=audit-expiry.sqlite start_server expiry2 expiry/ 60
  decisions
  wait_objects "$C_TLS" "root/$BUCKET/expiry/" $((BEFORE + 1)) || fail "after a restart with new credentials: nothing arrived"
  "$CLI" audit export --out "$WORK/export-expiry.jsonl" >/dev/null
  SIGNED="$(grep -c '"type":"checkpoint"' "$WORK/export-expiry.jsonl")"
  NOW="$(count_objects "$C_TLS" "root/$BUCKET/expiry/")"
  "$CLI" audit verify | sed 's/^/    /'
  ok "restarted with new credentials: delivering again ($NOW objects for $SIGNED checkpoints; the ones queued while expired were in memory and are not re-sent, a later checkpoint covers their entries)"
  stop_server
else
  echo
  echo "(step 9, expiry while running, not run: set STS_EXPIRY=1; it waits about 16 minutes)"
fi

say "10. the TLS server's audit chain"
CA="$WORK/ca.pem" SQLITE=audit-tls.sqlite start_server tls-again "$PREFIX" 300
"$CLI" audit verify | sed 's/^/    /'
stop_server
if [ "${#SKIPPED[@]}" -gt 0 ]; then
  fail "skipped: ${SKIPPED[*]}; this run is incomplete"
fi
echo "minio tls/sts smoke test passed"
