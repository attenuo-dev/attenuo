#!/usr/bin/env bash
# The S3 checkpoint sink (`[audit.sink] kind = "s3"`), run against a real MinIO.
#
#   scripts/live-minio-smoke.sh
#
# Starts MinIO (pinned image, host network, 127.0.0.1 only) and sets it up with the image's
# own `mc` the way docs/concepts/audit-log.md tells an operator to: a bucket created with
# Object Lock (so versioning is on) and a default COMPLIANCE retention, and a user whose only
# permission is `s3:PutObject` on it. Then runs attenuo-server with the S3 sink pointed at that
# bucket with that user's keys, makes audit records (root tokens and MCP calls through the
# proxy to a fake upstream) so checkpoints are signed, and checks:
#
#   1. one object per checkpoint arrives, path-style, at the documented key
#      (`<prefix><seq, 20 digits>-<16 hex of checkpoint_sha256>.json`);
#   2. each object's bytes are the canonical `attenuo-shipped-checkpoint-v1` envelope of the
#      checkpoint the server signed (compared field for field with the server's export, and
#      `checkpoint_sha256` recomputed);
#   2b. each upload carried `x-amz-checksum-sha256` (with `x-amz-sdk-checksum-algorithm`):
#      MinIO stored the SHA-256 of the object's bytes, and refuses a PUT (sent by curl, not
#      by attenuo) whose checksum is wrong;
#   3. `attenuo audit verify --file --jwks --checkpoints` accepts the export against the
#      objects, and exits 2 once one object is altered;
#   4. what PutObject-only keys can and cannot do: they cannot read, list or delete; an
#      overwrite of an object adds a version and keeps the original, which retention keeps
#      from being deleted; a verify against every version reports the forged one;
#   5. a wrong secret: every PUT is refused with 403, the server logs `S3 answered 403
#      Forbidden` and keeps retrying, decisions are still made, and `/readyz` stays 200 with
#      `"degraded": true` once `max_lag_seconds` passes;
#   6. endpoint spellings: `http://LOCALHOST:<port>/` and `http://127.0.0.1:80` (a second MinIO
#      on port 80, root in its container; the step fails as skipped if the port is taken).
#
# Not part of CI. Needs docker (the daemon running), curl (7.75 or later, for --aws-sigv4)
# and python3. Skips with exit status 0 when docker is not available. The MinIO root
# password, the sink user's secret and the admin token are random per run and stay in the
# temp dir. Nothing leaves the machine except the image pull.
#
# Environment:
#   MINIO_IMAGE          MinIO image with `minio` and `mc` (default: the pinned digest below)
#   ATTENUO_BIN_DIR=DIR  prebuilt attenuo-server, attenuo, examples/fake_mcp (default: cargo build)
#   KEEP=1               keep the temp dir (logs, config, objects)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# bitnamilegacy/minio:2025.7.23 (Docker Hub), pulled 2026-11-14: MinIO server
# RELEASE.2025-07-23 (commit 7ced9663) and mc RELEASE.2025-07-21, built by Bitnami. The
# minio/minio repository is no longer on Docker Hub.
MINIO_IMAGE="${MINIO_IMAGE:-bitnamilegacy/minio@sha256:8935e75fa5d11295c17171e4aa49efe390a1193cd7f12e4d21b92af9ffef09d7}"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "skip: docker is not available (no client, or the daemon is not running)"
  exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/attenuo-minio-smoke.XXXXXX")"
chmod 700 "$WORK"
CONTAINER="attenuo-minio-smoke-$$"
CONTAINER80="attenuo-minio-smoke-80-$$"
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
    echo "minio smoke test failed (exit $rc). Last server and MinIO log lines:" >&2
    tail -n 10 "$WORK"/server*.log 2>/dev/null >&2 || true
    docker logs --tail 10 "$CONTAINER" >&2 2>/dev/null || true
  fi
  docker rm -f "$CONTAINER" "$CONTAINER80" >/dev/null 2>&1 || true
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

S3_PORT="$(free_port)"; CONSOLE_PORT="$(free_port)"; MCP_PORT="$(free_port)"
OB_PORT="$(free_port)"; OB2_PORT="$(free_port)"; METRICS_PORT="$(free_port)"
OB3_PORT="$(free_port)"; OB4_PORT="$(free_port)"
S3="http://127.0.0.1:$S3_PORT"
BUCKET=attenuo-checkpoints
PREFIX="attenuo/checkpoints/"
rand > "$WORK/root.pw"; rand > "$WORK/sink.secret"; rand > "$WORK/admin.token"
SINK_USER=attenuo-sink

# --- MinIO -----------------------------------------------------------------------------------
say "MinIO: $MINIO_IMAGE"
docker run -d --name "$CONTAINER" --network host --entrypoint minio \
  -e MINIO_ROOT_USER=minio-root -e MINIO_ROOT_PASSWORD="$(cat "$WORK/root.pw")" \
  "$MINIO_IMAGE" server /tmp/data --address "127.0.0.1:$S3_PORT" \
  --console-address "127.0.0.1:$CONSOLE_PORT" >/dev/null
for _ in $(seq 1 60); do
  curl -sf "$S3/minio/health/live" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf "$S3/minio/health/live" >/dev/null || fail "MinIO did not start"
docker exec "$CONTAINER" minio --version | head -n1
docker exec "$CONTAINER" mc --version | head -n1

# `mc` in the MinIO container. Only mc_in passes stdin: a `docker exec -i` inside a
# `while read` loop would eat the loop's input.
mc() { docker exec "$CONTAINER" mc "$@" </dev/null; }
mc_in() { docker exec -i "$CONTAINER" mc "$@"; }
mc alias set root "$S3" minio-root "$(cat "$WORK/root.pw")" >/dev/null

say "bucket with Object Lock, a PutObject-only user (mc)"
mc mb --with-lock "root/$BUCKET" >/dev/null
mc retention set --default COMPLIANCE 1d "root/$BUCKET" >/dev/null
mc version info "root/$BUCKET"
mc admin user add root "$SINK_USER" "$(cat "$WORK/sink.secret")" >/dev/null
cat > "$WORK/put-only.json" <<EOF
{"Version": "2012-10-17",
 "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject"],
                "Resource": ["arn:aws:s3:::$BUCKET/*"]}]}
EOF
mc_in admin policy create root attenuo-put-only /dev/stdin < "$WORK/put-only.json" >/dev/null
mc admin policy attach root attenuo-put-only --user "$SINK_USER" >/dev/null
mc alias set sink "$S3" "$SINK_USER" "$(cat "$WORK/sink.secret")" >/dev/null
ok "bucket $BUCKET: Object Lock, COMPLIANCE 1 day; user $SINK_USER: s3:PutObject only"

# --- attenuo-server --------------------------------------------------------------------------
write_config() {  # port sqlite secret-file prefix max_lag -> config on stdout
  cat <<EOF
[server]
listen = "127.0.0.1:$1"
public_url = "http://127.0.0.1:$1"

[issuer]
issuer = "http://127.0.0.1:$1"
audience = "attenuo"

[policy]
policies_path = "$ROOT/examples/github-leak-demo/policy.cedar"

[policy.catalog.github.read_file]
readonly = true
inputs = { repo = "string", path = "string" }

[policy.catalog.github.create_issue]
inputs = { repo = "string", title = "string" }

[policy.catalog.github.delete_repo]
sensitive = true
inputs = { repo = "string" }

[approvals]
client_id = "minio-smoke"

[audit]
sqlite_path = "$WORK/$2"
checkpoint_every = 2

[audit.sink]
kind = "s3"
endpoint = "${ENDPOINT:-$S3}"
bucket = "$BUCKET"
prefix = "$4"
access_key_id = "${KEY_ID:-$SINK_USER}"
secret_access_key = "$(cat "$3")"
initial_backoff_ms = 200
max_backoff_seconds = 1
max_lag_seconds = $5

[[upstreams]]
name = "github"
url = "http://127.0.0.1:$MCP_PORT/mcp"

[admin]
token = "$(cat "$WORK/admin.token")"

[dev]
allow_root_mint = true
EOF
}
start_server() {  # config log port
  RUST_LOG=info "$BIN/attenuo-server" --config "$1" > "$2" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 100); do
    curl -sf "http://127.0.0.1:$3/healthz" >/dev/null 2>&1 && break
    sleep 0.1
  done
  curl -sf "http://127.0.0.1:$3/healthz" >/dev/null || fail "server on $3 did not start"
}
token_of() { sed -n -E 's/^token +([^ ]+).*/\1/p' | head -n1; }
decisions() {  # make audit records: a root token and two calls (one allowed, one denied)
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

"$FAKE_BIN" --port "$MCP_PORT" --tools read_file,create_issue \
  > "$WORK/fake-mcp.out" 2> "$WORK/fake-mcp.log" &
PIDS+=($!)
cp "$WORK/sink.secret" "$WORK/sink-a.secret"
write_config "$OB_PORT" audit-a.sqlite "$WORK/sink-a.secret" "$PREFIX" 300 > "$WORK/config-a.toml"
printf '\n[metrics]\nenabled = true\nlisten = "127.0.0.1:%s"\n' "$METRICS_PORT" >> "$WORK/config-a.toml"
start_server "$WORK/config-a.toml" "$WORK/server-a.log" "$OB_PORT"
export ATTENUO_SERVER="http://127.0.0.1:$OB_PORT" ATTENUO_ADMIN_TOKEN
ATTENUO_ADMIN_TOKEN="$(cat "$WORK/admin.token")"
unset ATTENUO_TOKEN ATTENUO_CLIENT_SECRET

say "1. audit records and checkpoints reach the bucket"
for _ in 1 2 3; do decisions; done
# The export holds the checkpoints the server signed; each must become one object.
"$CLI" audit export --out "$WORK/export.jsonl" >/dev/null
WANT="$(grep -c '"type":"checkpoint"' "$WORK/export.jsonl" || true)"
[ "$WANT" -ge 3 ] || fail "expected at least 3 checkpoints in the export, got $WANT"
list_objects() {  # alias path -> one JSON line per object version
  mc ls --recursive --versions --json "$1"
}
for _ in $(seq 1 50); do
  HAVE="$(list_objects "root/$BUCKET/$PREFIX" | grep -c '"type":"file"' || true)"
  [ "$HAVE" -ge "$WANT" ] && break
  sleep 0.2
done
[ "$HAVE" = "$WANT" ] || fail "expected $WANT objects, found $HAVE"
list_objects "root/$BUCKET/$PREFIX" > "$WORK/objects.jsonl"
python3 - "$WORK/objects.jsonl" <<'EOF'
import json, re, sys
keys = [json.loads(l)["key"] for l in open(sys.argv[1]) if l.strip()]
bad = [k for k in keys if not re.fullmatch(r"[0-9]{20}-[0-9a-f]{16}\.json", k)]
assert not bad, f"keys not in the documented form: {bad}"
print("keys:", ", ".join(sorted(keys)))
EOF
ok "$WANT checkpoints signed, $WANT objects at <prefix><seq, 20 digits>-<16 hex>.json (path-style $S3/$BUCKET/...)"

say "2. each object is the shipped envelope of a checkpoint the server signed"
mkdir "$WORK/objects"
python3 -c 'import json,sys; [print(json.loads(l)["key"]) for l in open(sys.argv[1]) if l.strip()]' \
  "$WORK/objects.jsonl" | while read -r key; do
  mc cat "root/$BUCKET/$PREFIX$key" > "$WORK/objects/$key"
done
python3 - "$WORK/export.jsonl" "$WORK/objects" "http://127.0.0.1:$OB_PORT" <<'EOF'
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
    assert cp == signed[cp["seq"]], f"{name}: differs from the server's checkpoint at {cp['seq']}"
    sha = hashlib.sha256(canon(cp)).hexdigest()
    assert obj["checkpoint_sha256"] == sha, f"{name}: checkpoint_sha256"
    assert name == f"{cp['seq']:020d}-{sha[:16]}.json", f"{name}: key"
    assert obj["format"] == "attenuo-shipped-checkpoint-v1"
    assert obj["kid"] == cp["kid"] and obj["signature"] == cp["signature"]
    assert obj["public_url"] == public_url
    print(f"seq {cp['seq']}: {len(raw)} bytes, canonical, matches the export, sha256 ok")
    signed.pop(cp["seq"])
assert not signed, f"signed but not shipped: {sorted(signed)}"
EOF
ok "object bytes = canonical shipped envelope of the signed checkpoint"

say "2b. each upload carried a SHA-256 checksum, and MinIO checks it"
# The sink sends x-amz-sdk-checksum-algorithm: SHA256 with x-amz-checksum-sha256 (what AWS
# documents as required for an upload into an Object Lock bucket with a retention period).
# MinIO stores the checksum it verified; a HEAD with x-amz-checksum-mode: ENABLED returns it.
s3curl() {  # user secret-file curl-args... (SigV4 by curl itself, not by attenuo)
  local user="$1" secret="$2"; shift 2
  curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$user:$(cat "$secret")" "$@"
}
for f in "$WORK"/objects/*; do
  key="$(basename "$f")"
  want="$(python3 -c 'import base64,hashlib,sys; print(base64.b64encode(hashlib.sha256(open(sys.argv[1],"rb").read()).digest()).decode())' "$f")"
  got="$(s3curl minio-root "$WORK/root.pw" -I -H 'x-amz-checksum-mode: ENABLED' \
    "$S3/$BUCKET/$PREFIX$key" | tr -d '\r' | sed -n 's/^[Xx]-[Aa]mz-[Cc]hecksum-[Ss]ha256: //p')"
  [ "$got" = "$want" ] || fail "$key: stored x-amz-checksum-sha256 '$got', want '$want'"
done
ok "every object has the x-amz-checksum-sha256 of its bytes stored (HEAD, checksum mode)"
# A wrong checksum is refused. Sent by curl with the sink user's keys, not by attenuo: the
# server has no switch to send a wrong one, and gets none.
echo '{"probe":true}' > "$WORK/probe.json"
BAD="$(python3 -c 'import base64,hashlib; print(base64.b64encode(hashlib.sha256(b"something else").digest()).decode())')"
code="$(s3curl "$SINK_USER" "$WORK/sink.secret" -o "$WORK/probe.out" -w '%{http_code}' -X PUT \
  -H "x-amz-sdk-checksum-algorithm: SHA256" -H "x-amz-checksum-sha256: $BAD" \
  --data-binary @"$WORK/probe.json" "$S3/$BUCKET/probe/wrong-checksum.json")"
[ "$code" = 400 ] || fail "a wrong x-amz-checksum-sha256 was answered $code: $(cat "$WORK/probe.out")"
grep -q -i 'checksum\|digest' "$WORK/probe.out" || fail "400 for another reason: $(cat "$WORK/probe.out")"
reason="$(sed -n 's:.*<Code>\(.*\)</Code>.*:\1:p' "$WORK/probe.out")"
mc stat "root/$BUCKET/probe/wrong-checksum.json" >/dev/null 2>&1 && fail "the refused object exists"
ok "a PUT with a wrong x-amz-checksum-sha256 is refused: 400 $reason, nothing stored"

say "3. audit verify against the objects"
curl -sf "$ATTENUO_SERVER/.well-known/jwks.json" > "$WORK/jwks.json"
for f in "$WORK"/objects/*; do cat "$f"; echo; done > "$WORK/shipped.jsonl"
"$CLI" audit verify --file "$WORK/export.jsonl" --jwks "$WORK/jwks.json" \
  --checkpoints "$WORK/shipped.jsonl" --allow-unsigned-tail
ok "verify --checkpoints accepts the export against the bucket's objects"
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

say "4. what PutObject-only keys can do"
FIRST="$(ls "$WORK/objects" | head -n1)"
mc cat "sink/$BUCKET/$PREFIX$FIRST" >/dev/null 2>&1 && fail "the sink user could read an object"
ok "sink keys cannot read (GetObject denied)"
mc ls "sink/$BUCKET/" >/dev/null 2>&1 && fail "the sink user could list the bucket"
ok "sink keys cannot list"
mc rm "sink/$BUCKET/$PREFIX$FIRST" >/dev/null 2>&1 && fail "the sink user could delete an object"
ok "sink keys cannot delete"
# An attacker on the host holds these keys: overwrite the first object with a re-signed copy.
python3 - "$WORK/objects/$FIRST" "$WORK/forged.json" <<'EOF'
import hashlib, json, sys
canon = lambda v: json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
d = json.load(open(sys.argv[1]))
d["checkpoint"]["head_hash"] = "f" * 64
d["checkpoint_sha256"] = hashlib.sha256(canon(d["checkpoint"])).hexdigest()
open(sys.argv[2], "w").write(json.dumps(d, sort_keys=True, separators=(",", ":")))
EOF
mc_in pipe "sink/$BUCKET/$PREFIX$FIRST" < "$WORK/forged.json" >/dev/null
VERSIONS="$(mc ls --versions --json "root/$BUCKET/$PREFIX$FIRST" | grep -c '"type":"file"' || true)"
[ "$VERSIONS" = 2 ] || fail "expected 2 versions after the overwrite, got $VERSIONS"
ok "an overwrite with the sink keys adds a version; the original is still there"
mc cat "root/$BUCKET/$PREFIX$FIRST" | cmp -s - "$WORK/forged.json" \
  || fail "expected the latest version to be the overwrite"
ok "a plain GET now returns the overwrite: collect every version, not the latest"
mc rm --versions --force "root/$BUCKET/$PREFIX$FIRST" >/dev/null 2>&1 \
  && fail "retention did not keep the versions from being deleted"
[ "$(mc ls --versions --json "root/$BUCKET/$PREFIX$FIRST" | grep -c '"type":"file"')" = 2 ] \
  || fail "a version was deleted under COMPLIANCE retention"
ok "even the root user cannot delete either version (COMPLIANCE retention)"
# Collect every version of every object, as an operator should, and cross-check.
mc ls --recursive --versions --json "root/$BUCKET/$PREFIX" | python3 -c '
import json, sys
for l in sys.stdin:
    if l.strip():
        d = json.loads(l); print(d["key"], d["versionId"])' | while read -r key vid; do
  mc cat --version-id "$vid" "root/$BUCKET/$PREFIX$key"; echo
done > "$WORK/all-versions.jsonl"
set +e
"$CLI" audit verify --file "$WORK/export.jsonl" --jwks "$WORK/jwks.json" \
  --checkpoints "$WORK/all-versions.jsonl" --allow-unsigned-tail > "$WORK/verify-versions.out" 2>&1
RC=$?
set -e
[ "$RC" = 2 ] || { cat "$WORK/verify-versions.out"; fail "every version: expected exit 2, got $RC"; }
ok "verify against every version: exit 2, the overwrite is reported"
sed 's/^/    /' "$WORK/verify-versions.out" | grep -i -m3 'seq\|mismatch\|signature' || true

say "5. a wrong secret"
rand > "$WORK/wrong.secret"
write_config "$OB2_PORT" audit-b.sqlite "$WORK/wrong.secret" "wrong-secret/" 2 > "$WORK/config-b.toml"
start_server "$WORK/config-b.toml" "$WORK/server-b.log" "$OB2_PORT"
ATTENUO_SERVER="http://127.0.0.1:$OB2_PORT" decisions
ok "decisions are made while every PUT fails (allowed and policy_deny as usual)"
for _ in $(seq 1 50); do
  grep -q 'S3 answered 403 Forbidden' "$WORK/server-b.log" && break
  sleep 0.2
done
grep -m1 'S3 answered 403 Forbidden' "$WORK/server-b.log" | sed 's/^/    /' \
  || fail "no 'S3 answered 403 Forbidden' in the server log"
ok "the server logs: [audit.sink] delivery failed; retrying ... S3 answered 403 Forbidden"
sleep 3
READY_CODE="$(curl -s -o "$WORK/readyz-b.json" -w '%{http_code}' "http://127.0.0.1:$OB2_PORT/readyz")"
[ "$READY_CODE" = 200 ] || fail "readyz: expected 200 (fail_readiness off), got $READY_CODE"
[ "$(jq_py 'd.get("degraded")' < "$WORK/readyz-b.json")" = True ] || fail "readyz not degraded: $(cat "$WORK/readyz-b.json")"
[ "$(jq_py 'd["checks"]["checkpoint_sink"]' < "$WORK/readyz-b.json")" = degraded ] \
  || fail "checks.checkpoint_sink not degraded"
ok "/readyz: 200, degraded: true, checks.checkpoint_sink = degraded (max_lag_seconds = 2)"
[ "$(mc ls --recursive "root/$BUCKET/wrong-secret/" 2>/dev/null | wc -l)" = 0 ] \
  || fail "an object arrived with a wrong secret"
ok "no object under wrong-secret/"
curl -sf "http://127.0.0.1:$METRICS_PORT/metrics" | grep -E '^attenuo_audit_sink_(delivered|failures)_total' \
  | sed 's/^/    server 1: /'
curl -sf "http://127.0.0.1:$METRICS_PORT/metrics" | grep -qE '^attenuo_audit_sink_delivered_total [1-9]' \
  || fail "server 1: attenuo_audit_sink_delivered_total is 0"

say "6. endpoint spellings: the signed host is the host sent"
# `Host` is what the URL parser makes of the endpoint: lowercased, without a default port.
wait_objects() {  # alias/path -> succeeds once one object is there
  for _ in $(seq 1 50); do
    [ "$(mc ls --recursive "$1" 2>/dev/null | wc -l)" -ge 1 ] && return 0
    sleep 0.2
  done
  return 1
}
ENDPOINT="http://LOCALHOST:$S3_PORT/" write_config "$OB3_PORT" audit-c.sqlite "$WORK/sink.secret" \
  "spelling/" 300 > "$WORK/config-c.toml"
start_server "$WORK/config-c.toml" "$WORK/server-c.log" "$OB3_PORT"
ATTENUO_SERVER="http://127.0.0.1:$OB3_PORT" decisions
wait_objects "root/$BUCKET/spelling/" || fail "endpoint http://LOCALHOST:<port>/: nothing arrived"
ok "endpoint http://LOCALHOST:$S3_PORT/ (upper case, trailing /): objects arrive"
# A second MinIO on port 80 (root in the container), for an endpoint with an explicit default
# port. Before the fix the signed host kept `:80` and MinIO answered 403.
if python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",80))' 2>/dev/null \
   || [ "$(id -u)" != 0 ]; then
  docker run -d --name "$CONTAINER80" --network host --user 0 --entrypoint minio \
    -e MINIO_ROOT_USER=minio-root -e MINIO_ROOT_PASSWORD="$(cat "$WORK/root.pw")" \
    "$MINIO_IMAGE" server /tmp/data --address 127.0.0.1:80 \
    --console-address "127.0.0.1:$(free_port)" >/dev/null || true
  for _ in $(seq 1 60); do
    curl -sf "http://127.0.0.1:80/minio/health/live" >/dev/null 2>&1 && break
    sleep 0.5
  done
fi
if curl -sf "http://127.0.0.1:80/minio/health/live" >/dev/null 2>&1 \
   && docker ps -q --filter "name=$CONTAINER80" | grep -q .; then
  docker exec "$CONTAINER80" mc alias set root http://127.0.0.1:80 minio-root "$(cat "$WORK/root.pw")" >/dev/null
  docker exec "$CONTAINER80" mc mb "root/$BUCKET" >/dev/null
  ENDPOINT="http://127.0.0.1:80" KEY_ID=minio-root write_config "$OB4_PORT" audit-d.sqlite \
    "$WORK/root.pw" "port80/" 300 > "$WORK/config-d.toml"
  start_server "$WORK/config-d.toml" "$WORK/server-d.log" "$OB4_PORT"
  ATTENUO_SERVER="http://127.0.0.1:$OB4_PORT" decisions
  ok=0
  for _ in $(seq 1 50); do
    [ "$(docker exec "$CONTAINER80" mc ls --recursive "root/$BUCKET/port80/" | wc -l)" -ge 1 ] && { ok=1; break; }
    sleep 0.2
  done
  [ "$ok" = 1 ] || { grep -m1 'S3 answered' "$WORK/server-d.log" >&2 || true; fail "endpoint http://127.0.0.1:80: nothing arrived"; }
  ok "endpoint http://127.0.0.1:80 (explicit default port): objects arrive"
else
  echo "skip: port 80 is taken; the explicit-default-port check did not run"
  SKIPPED+=("endpoint with :80")
fi

say "7. the first server's audit chain"
ATTENUO_SERVER="http://127.0.0.1:$OB_PORT" "$CLI" audit verify
if [ "${#SKIPPED[@]}" -gt 0 ]; then
  fail "skipped: ${SKIPPED[*]}; this run is incomplete"
fi
echo "minio smoke test passed"
