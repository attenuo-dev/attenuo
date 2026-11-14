#!/usr/bin/env bash
# `[[actor_trust]]` against a live SPIRE, following the SPIRE part of
# docs/guides/identity-providers.md ("Workload identity for sub-agents").
#
#   scripts/live-spire-smoke.sh
#
# Runs a SPIRE server, a SPIRE agent and the SPIRE OIDC Discovery Provider from the release
# tarball (pinned by SHA-256) in one container (pinned base image, host network, 127.0.0.1
# only). The server has the `join_token` node attestor, an in-memory key manager, `jwt_issuer`
# set, and a bundle endpoint with the `https_web` profile serving a certificate from a CA made
# for this run. The agent attests with a join token and identifies workloads with the `unix`
# attestor: each agent id below is a uid in the container, registered with
# `spire-server entry create`.
#
# Then runs attenuo-server with the guide's SPIFFE `[[actor_trust]]` entry and checks: a real
# JWT-SVID fetched with the guide's command and audience; hop 0 with the guide's curl command
# (an ID token from the mock IdP of examples/idp-exchange-demo plus the SVID as actor_token);
# a delegation with `attenuo token exchange --actor-token -`; the Python SDK; the child's
# expiry capped at the SVID's; single use; SPIRE's JWT-SVID cache and the extra-audience
# workaround; a wrong audience; a SPIFFE ID mapped to another agent; an unmapped SPIFFE ID; the
# same through the OIDC Discovery Provider (`issuer` plus `jwks_url`); and a JWT key rotation
# forced with `spire-server localauthority jwt prepare / activate / taint / revoke`.
#
# The bundle endpoint is HTTPS with a certificate from this run's CA, which is not a web PKI
# root. attenuo reaches it directly, over TLS, with the entry's `ca_pem_path` naming that CA;
# step 4 shows that without the setting, or with another CA, the fetch is refused and the log
# names the TLS cause. The discovery provider is served on 127.0.0.1 over plain http
# (`insecure_addr`).
#
# Not part of CI. Needs docker (the daemon running), curl, openssl and python3; the Python
# SDK step needs httpx. A step whose tool is missing is reported as skipped, and the script
# then exits non-zero. Skips with exit status 0 when docker is not available. The admin token,
# the join token and the CA key are random per run and stay in the temp dir (mode 0700). Network use: the
# image pull and the SPIRE release download (skipped with SPIRE_BIN_DIR).
#
# Environment:
#   BASE_IMAGE           image the SPIRE binaries run in (default: the pinned digest below)
#   SPIRE_BIN_DIR=DIR    spire-server, spire-agent, oidc-discovery-provider (default: download
#                        SPIRE 1.16.0 and check the pinned SHA-256)
#   ATTENUO_BIN_DIR=DIR  prebuilt attenuo-server, attenuo, examples/mock_idp (default: cargo build)
#   KEEP=1               keep the temp dir (logs, config)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# alpine:3.20 (Docker Hub), pulled 2026-11-14. The SPIRE binaries are static (musl).
BASE_IMAGE="${BASE_IMAGE:-alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc}"
# SPIRE 1.16.0 release tarballs (GitHub releases), downloaded 2026-11-14; the SHA-256s are the
# ones in the release's *_sha256sum.txt files. ghcr.io/spiffe images were not reachable.
SPIRE_VERSION=1.16.0
SPIRE_URL="https://github.com/spiffe/spire/releases/download/v$SPIRE_VERSION"
SPIRE_TGZ="spire-$SPIRE_VERSION-linux-amd64-musl.tar.gz"
SPIRE_SHA256=7bcf5e167151a1fc58293768462b44e155ba8784214582aefa6adf18c633d1d5
EXTRAS_TGZ="spire-extras-$SPIRE_VERSION-linux-amd64-musl.tar.gz"
EXTRAS_SHA256=b2ee7828549e46a333c5ba83541457214d1f6d886000168231aed086236137d5

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "skip: docker is not available (no client, or the daemon is not running)"
  exit 0
fi

# mktemp's 0700: the admin token, the attenuo configs and the CA keys at the top are this
# user's alone. Only conf/ and bin/ are mounted into the container, and they are 0755 for a
# container user that is not this one (user namespace remapping); the mounts do not need the
# top directory to be readable, so other local users cannot reach them either (SR-120).
WORK="$(mktemp -d "${TMPDIR:-/tmp}/attenuo-spire-smoke.XXXXXX")"
CONTAINER="attenuo-spire-smoke-$$"
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
    echo "spire smoke test failed (exit $rc). Last server and SPIRE log lines:" >&2
    tail -n 10 "$WORK"/server-*.log 2>/dev/null >&2 || true
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
jwt_part() {
  python3 -c 'import base64,json,sys; s=sys.argv[1].split(".")[int(sys.argv[2])]; print(json.dumps(json.loads(base64.urlsafe_b64decode(s+"="*(-len(s)%4)))))' "$1" "$2"
}
jq_py() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"; }
command -v openssl >/dev/null 2>&1 || fail "openssl is needed for the bundle endpoint's certificate"

if [ -n "${ATTENUO_BIN_DIR:-}" ]; then
  BIN="$ATTENUO_BIN_DIR"
else
  echo "building..." >&2
  cargo build -q -p attenuo-server -p attenuo-cli
  cargo build -q -p attenuo-server --example mock_idp
  BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
fi
CLI="$BIN/attenuo"
IDP_BIN="$BIN/examples/mock_idp"; [ -x "$IDP_BIN" ] || IDP_BIN="$BIN/mock_idp"

# --- SPIRE binaries --------------------------------------------------------------------------
mkdir -m 755 "$WORK/bin"
if [ -n "${SPIRE_BIN_DIR:-}" ]; then
  cp "$SPIRE_BIN_DIR"/spire-server "$SPIRE_BIN_DIR"/spire-agent \
     "$SPIRE_BIN_DIR"/oidc-discovery-provider "$WORK/bin/"
else
  mkdir "$WORK/dl"
  for f in "$SPIRE_TGZ" "$EXTRAS_TGZ"; do
    curl -sSfL -o "$WORK/dl/$f" "$SPIRE_URL/$f"
  done
  printf '%s  %s\n%s  %s\n' "$SPIRE_SHA256" "$WORK/dl/$SPIRE_TGZ" "$EXTRAS_SHA256" "$WORK/dl/$EXTRAS_TGZ" \
    | sha256sum -c --quiet - || fail "SPIRE release tarball checksum mismatch"
  tar -xzf "$WORK/dl/$SPIRE_TGZ" -C "$WORK/dl"
  tar -xzf "$WORK/dl/$EXTRAS_TGZ" -C "$WORK/dl"
  cp "$WORK/dl/spire-$SPIRE_VERSION/bin/spire-server" "$WORK/dl/spire-$SPIRE_VERSION/bin/spire-agent" \
     "$WORK/dl/spire-extras-$SPIRE_VERSION/bin/oidc-discovery-provider" "$WORK/bin/"
  rm -rf "$WORK/dl"
fi

SPIRE_PORT="$(free_port)"; BE_PORT="$(free_port)"; ODP_PORT="$(free_port)"; OB_OTHER_PORT="$(free_port)"
OB_PORT="$(free_port)"; OB_ODP_PORT="$(free_port)"; OB_TLS_PORT="$(free_port)"
TD=example.org
ODP="http://127.0.0.1:$ODP_PORT"
AUD="http://127.0.0.1:$OB_PORT"   # the guide: attenuo's own URL as the audience
rand > "$WORK/admin.token"

# The bundle endpoint's certificate (https_web profile, serving_cert_file), from a CA made here.
mkdir -m 755 "$WORK/conf"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -keyout "$WORK/ca.key" -out "$WORK/ca.pem" -subj "/CN=attenuo spire smoke CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$WORK/conf/be.key" -out "$WORK/be.csr" -subj "/CN=127.0.0.1" 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' > "$WORK/be.ext"
openssl x509 -req -in "$WORK/be.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
  -days 1 -extfile "$WORK/be.ext" -out "$WORK/be.pem" 2>/dev/null
cat "$WORK/be.pem" "$WORK/ca.pem" > "$WORK/conf/be-chain.pem"
# Another CA, which did not issue the endpoint's certificate (step 4).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -keyout "$WORK/other-ca.key" -out "$WORK/other-ca.pem" -subj "/CN=attenuo spire smoke other CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
chmod 644 "$WORK/conf/be.key"   # for the container's user; $WORK (0700) keeps others out

cat > "$WORK/conf/server.conf" <<EOF
server {
  bind_address = "127.0.0.1"
  bind_port = "$SPIRE_PORT"
  socket_path = "/tmp/spire-server/api.sock"
  trust_domain = "$TD"
  data_dir = "/tmp/spire-server/data"
  log_level = "INFO"
  jwt_issuer = "$ODP"
  federation {
    bundle_endpoint {
      address = "127.0.0.1"
      port = $BE_PORT
      profile "https_web" {
        serving_cert_file {
          cert_file_path = "/conf/be-chain.pem"
          key_file_path = "/conf/be.key"
          file_sync_interval = "1h"
        }
      }
    }
  }
}
plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
      connection_string = "/tmp/spire-server/data/datastore.sqlite3"
    }
  }
  NodeAttestor "join_token" { plugin_data {} }
  KeyManager "memory" { plugin_data {} }
}
EOF
cat > "$WORK/conf/odp.conf" <<EOF
log_level = "INFO"
domains = ["127.0.0.1"]
allow_insecure_scheme = true
insecure_addr = "127.0.0.1:$ODP_PORT"
server_api {
  address = "unix:///tmp/spire-server/api.sock"
}
EOF

# --- SPIRE server, agent, discovery provider -------------------------------------------------
say "SPIRE $SPIRE_VERSION in $BASE_IMAGE"
docker run -d --name "$CONTAINER" --network host -v "$WORK/bin:/spire:ro" -v "$WORK/conf:/conf:ro" \
  "$BASE_IMAGE" /spire/spire-server run -config /conf/server.conf >/dev/null
SOCK=/tmp/spire-server/api.sock
srv() { docker exec "$CONTAINER" /spire/spire-server "$@" -socketPath "$SOCK"; }
for _ in $(seq 1 60); do
  srv healthcheck >/dev/null 2>&1 && break
  sleep 0.5
done
srv healthcheck >/dev/null || fail "SPIRE server did not start"
docker exec "$CONTAINER" /spire/spire-server --version 2>&1 | sed 's/^/spire-server /'

srv bundle show > "$WORK/conf/bootstrap.crt"
JOIN="$(srv token generate -spiffeID "spiffe://$TD/smoke-node" | awk '{print $2}')"
[ -n "$JOIN" ] || fail "no join token"
# The agent's config holds the join token; it stays in the run's temp dir.
cat > "$WORK/conf/agent.conf" <<EOF
agent {
  data_dir = "/tmp/spire-agent/data"
  log_level = "INFO"
  server_address = "127.0.0.1"
  server_port = "$SPIRE_PORT"
  socket_path = "/tmp/spire-agent/api.sock"
  trust_domain = "$TD"
  trust_bundle_path = "/conf/bootstrap.crt"
  join_token = "$JOIN"
}
plugins {
  NodeAttestor "join_token" { plugin_data {} }
  KeyManager "memory" { plugin_data {} }
  WorkloadAttestor "unix" { plugin_data {} }
}
EOF
docker exec -d "$CONTAINER" sh -c '/spire/spire-agent run -config /conf/agent.conf > /tmp/agent.log 2>&1'
docker exec -d "$CONTAINER" sh -c '/spire/oidc-discovery-provider -config /conf/odp.conf > /tmp/odp.log 2>&1'

# One workload per uid: planner 1004 (hop 0), coder 1001, reviewer 1002, intruder 1003 (has a
# SPIFFE ID in the trust domain but no agent mapping).
PARENT="spiffe://$TD/spire/agent/join_token/$JOIN"
for w in 1001:coder 1002:reviewer 1003:intruder 1004:planner; do
  srv entry create -parentID "$PARENT" -spiffeID "spiffe://$TD/ns/agents/sa/${w#*:}" \
    -selector "unix:uid:${w%%:*}" >/dev/null
done
uid_of() { case "$1" in coder) echo 1001;; reviewer) echo 1002;; intruder) echo 1003;; planner) echo 1004;; esac; }
# The guide's command: `spire-agent api fetch jwt -audience ... -socketPath ...`, second line.
svid() {  # workload audience[,audience] -> a JWT-SVID
  docker exec -u "$(uid_of "$1")" "$CONTAINER" /spire/spire-agent api fetch jwt \
    -audience "$2" -socketPath /tmp/spire-agent/api.sock | sed -n 2p | tr -d '[:space:]'
}
for _ in $(seq 1 60); do
  [ -n "$(svid coder "$AUD" 2>/dev/null)" ] && break
  sleep 0.5
done
[ -n "$(svid coder "$AUD")" ] || fail "the agent hands out no JWT-SVID"
for _ in $(seq 1 40); do
  curl -sf "$ODP/keys" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -sf "$ODP/keys" >/dev/null || fail "the OIDC discovery provider did not start"

say "1. the bundle endpoint and a real JWT-SVID"
curl -sf --cacert "$WORK/ca.pem" "https://127.0.0.1:$BE_PORT" > "$WORK/bundle.json"
python3 - "$WORK/bundle.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
uses = sorted(k.get("use") for k in d["keys"])
assert "jwt-svid" in uses and "x509-svid" in uses, uses
print("bundle keys by use:", uses, "| spiffe_sequence", d.get("spiffe_sequence"),
      "| spiffe_refresh_hint", d.get("spiffe_refresh_hint"))
EOF
SVID="$(svid coder "$AUD")"
HEADER="$(jwt_part "$SVID" 0)"; CLAIMS="$(jwt_part "$SVID" 1)"
echo "header $HEADER"
echo "claims $(printf %s "$CLAIMS" | jq_py '{k: d.get(k) for k in ("iss","sub","aud","jti")}')"
printf %s "$CLAIMS" | jq_py 'int(d["exp"]) - int(d["iat"])' | sed 's/^/JWT-SVID lifetime (s): /'
[ "$(printf %s "$CLAIMS" | jq_py 'd["sub"]')" = "spiffe://$TD/ns/agents/sa/coder" ] || fail "sub"
[ "$(printf %s "$HEADER" | jq_py 'd["alg"]')" = ES256 ] || fail "expected ES256"
KID1="$(printf %s "$HEADER" | jq_py 'd["kid"]')"
python3 -c 'import json,sys; assert sys.argv[2] in [k.get("kid") for k in json.load(open(sys.argv[1]))["keys"] if k.get("use")=="jwt-svid"]' \
  "$WORK/bundle.json" "$KID1" || fail "the SVID's kid is not a jwt-svid key of the bundle"
ok "ES256 JWT-SVID, kid $KID1 is the bundle's jwt-svid key; no jti; iss = jwt_issuer"
[ "$(svid coder "$AUD")" = "$SVID" ] || fail "expected the agent to hand out its cached SVID again"
ok "the agent hands out the same JWT-SVID for the same audience (its cache)"
OTHER="$(svid coder "$AUD,smoke-$(rand)")"
[ "$OTHER" != "$SVID" ] || fail "an extra audience did not give a fresh SVID"
ok "an extra, unique audience gives a fresh one (aud = $(jwt_part "$OTHER" 1 | jq_py 'd["aud"]'))"

# --- the mock IdP (hop 0) and attenuo-server ------------------------------------------------
"$IDP_BIN" --port 0 --client-id agent-platform --subject alice > "$WORK/idp.out" 2> "$WORK/idp.log" &
PIDS+=($!)
for _ in $(seq 1 100); do
  grep -q '^listening on ' "$WORK/idp.out" 2>/dev/null && break
  sleep 0.1
done
IDP="$(sed -n 's/^listening on //p' "$WORK/idp.out")"
[ -n "$IDP" ] || fail "mock IdP did not start"

write_config() {  # port, then the [[actor_trust]] key-source lines on stdin -> config on stdout
  local trust; trust="$(cat)"
  cat <<EOF
[server]
listen = "127.0.0.1:$1"

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
client_id = "spire-smoke"

[audit]
sqlite_path = ":memory:"

[admin]
token = "$(cat "$WORK/admin.token")"

[token]
actor_auth = "either"

[[idps]]
issuer = "$IDP"
client_ids = { planner = "agent-platform" }
allowed_algs = ["ES256"]

[[root_grants]]
issuer = "$IDP"
agent = "planner"
capabilities = ["github:*"]

# The guide's SPIRE entry, with this run's URLs.
[[actor_trust]]
$trust
audience = "$AUD"
subject_to_agent = { "spiffe://$TD/ns/agents/sa/planner" = "planner", "spiffe://$TD/ns/agents/sa/coder" = "coder", "spiffe://$TD/ns/agents/sa/reviewer" = "reviewer" }
allowed_algs = ["ES256", "RS256"]
jwks_ttl_seconds = ${JWKS_TTL:-300}
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
# The guide's hop-0 curl command, with this run's URLs: ID token plus JWT-SVID.
hop0() {  # server svid -> response body
  curl -sS "$1/token" \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d subject_token="$(curl -sSf "$IDP/demo/id-token")" \
    -d subject_token_type=urn:ietf:params:oauth:token-type:id_token \
    -d actor=planner \
    -d scope="github:read_file github:create_issue" \
    -d actor_token="$2" \
    -d actor_token_type=urn:ietf:params:oauth:token-type:jwt
}
# The guide's exchange: `attenuo token exchange --actor ... --actor-token -`, SVID on stdin.
exchange() {  # server parent actor svid -> CLI output (exit status kept)
  printf '%s\n' "$4" | ATTENUO_SERVER="$1" ATTENUO_TOKEN="$2" "$CLI" token exchange \
    --actor "$3" --cap github:read_file --actor-token - 2>&1
}
fresh() { svid "$1" "$AUD,smoke-$(rand)"; }   # a fresh SVID for workload $1
# A new root token. Each (parent, actor) pair is exchanged once, so every check below that
# expects an exchange to pass, or that tests the SVID's own single use, takes a new parent.
new_root() {  # server -> a root token for planner
  local r; r="$(hop0 "$1" "$(fresh planner)" | jq_py 'd.get("access_token") or ""')"
  [ -n "$r" ] || fail "hop 0 on $1 refused"
  printf %s "$r"
}
expect_refusal() {  # label code output
  printf %s "$3" | grep -q "$2" || fail "$1: expected $2, got: $3"
  ok "$1: refused, $2"
}

# The bundle endpoint directly, over TLS, trusting this run's CA for this entry only.
printf 'spiffe_trust_domain = "%s"\nspiffe_bundle_url = "https://127.0.0.1:%s"\nca_pem_path = "%s"\n' \
  "$TD" "$BE_PORT" "$WORK/ca.pem" | write_config "$OB_PORT" > "$WORK/config-bundle.toml"
start_server "$WORK/config-bundle.toml" "$WORK/server-bundle.log" "$OB_PORT"
OB="http://127.0.0.1:$OB_PORT"
unset ATTENUO_TOKEN ATTENUO_CLIENT_SECRET ATTENUO_ADMIN_TOKEN

say "2. trust through the bundle endpoint: hop 0 and an exchange"
PLANNER_SVID="$(fresh planner)"
RESP="$(hop0 "$OB" "$PLANNER_SVID")"
ROOT_TOKEN="$(printf %s "$RESP" | jq_py 'd.get("access_token") or ""')"
[ -n "$ROOT_TOKEN" ] || fail "hop 0 with a JWT-SVID refused: $RESP"
[ "$(jwt_part "$ROOT_TOKEN" 1 | jq_py 'int(d["exp"]) <= '"$(jwt_part "$PLANNER_SVID" 1 | jq_py 'd["exp"]')")" = True ] \
  || fail "the root token outlives the planner's SVID"
ok "hop 0 (guide's curl): root token for planner, exp <= the SVID's exp"
CODER_SVID="$(fresh coder)"
OUT="$(exchange "$OB" "$ROOT_TOKEN" coder "$CODER_SVID")" || fail "exchange refused: $OUT"
CHILD="$(printf %s "$OUT" | token_of)"
[ -n "$CHILD" ] || fail "no child token: $OUT"
[ "$(jwt_part "$CHILD" 1 | jq_py 'int(d["exp"]) <= '"$(jwt_part "$CODER_SVID" 1 | jq_py 'd["exp"]')")" = True ] \
  || fail "the child token outlives the SVID"
ok "attenuo token exchange --actor coder --actor-token -: child token, exp <= the SVID's exp"
grep -q 'JWKS unavailable' "$WORK/server-bundle.log" && fail "a bundle fetch failed: $(grep 'JWKS unavailable' "$WORK/server-bundle.log")"
ok "the bundle came straight from https://127.0.0.1:$BE_PORT (ca_pem_path = this run's CA)"

say "3. refusals"
P="$(new_root "$OB")"
OUT="$(exchange "$OB" "$P" coder "$CODER_SVID" || true)"
expect_refusal "the same SVID again (a new parent)" replayed "$OUT"
P="$(new_root "$OB")"
OUT="$(exchange "$OB" "$P" coder "$(svid coder "https://other.example,smoke-$(rand)")" || true)"
expect_refusal "an SVID for another audience" actor_token_audience_mismatch "$OUT"
P="$(new_root "$OB")"
OUT="$(exchange "$OB" "$P" coder "$(fresh reviewer)" || true)"
expect_refusal "the reviewer's SVID for --actor coder" actor_mismatch "$OUT"
P="$(new_root "$OB")"
OUT="$(exchange "$OB" "$P" intruder "$(fresh intruder)" || true)"
expect_refusal "an unmapped SPIFFE ID" actor_token_unmapped_subject "$OUT"
P="$(new_root "$OB")"
OUT="$(printf '%s\n' "$(fresh planner)" | ATTENUO_SERVER="$OB" ATTENUO_TOKEN="$P" "$CLI" token exchange \
  --actor coder --cap github:read_file --actor-token - 2>&1 || true)"
expect_refusal "the planner's SVID for --actor coder" actor_mismatch "$OUT"

say "4. the same endpoint without ca_pem_path, and with another CA: refused"
refused_tls() {  # label port config-lines
  printf '%s' "$3" | write_config "$2" > "$WORK/config-$2.toml"
  start_server "$WORK/config-$2.toml" "$WORK/server-$2.log" "$2"
  OUT="$(hop0 "http://127.0.0.1:$2" "$(fresh planner)")"
  printf %s "$OUT" | grep -q 'temporarily_unavailable' && printf %s "$OUT" | grep -q 'jwks_unavailable' \
    || fail "$1: expected 503 jwks_unavailable: $OUT"
  printf %s "$OUT" | grep -q -i 'certificate\|UnknownIssuer\|error sending' \
    && fail "$1: the response names the TLS cause: $OUT"
  LINE="$(grep -m1 'actor token issuer JWKS unavailable' "$WORK/server-$2.log" || true)"
  printf %s "$LINE" | grep -o 'detail=.*' | cut -c1-220 | sed 's/^/    /'
  printf %s "$LINE" | grep -q 'invalid peer certificate: UnknownIssuer' \
    || fail "$1: the log line does not name the TLS cause: $LINE"
  ok "$1: 503 jwks_unavailable; the log names the cause (UnknownIssuer), the response does not"
}
refused_tls "no ca_pem_path" "$OB_TLS_PORT" \
  "$(printf 'spiffe_trust_domain = "%s"\nspiffe_bundle_url = "https://127.0.0.1:%s"\n' "$TD" "$BE_PORT")"
refused_tls "ca_pem_path = another CA" "$OB_OTHER_PORT" \
  "$(printf 'spiffe_trust_domain = "%s"\nspiffe_bundle_url = "https://127.0.0.1:%s"\nca_pem_path = "%s"\n' \
    "$TD" "$BE_PORT" "$WORK/other-ca.pem")"

say "5. trust through the OIDC Discovery Provider"
DISC="$(curl -sf "$ODP/.well-known/openid-configuration")"
[ "$(printf %s "$DISC" | jq_py 'd["issuer"]')" = "$ODP" ] || fail "discovery issuer: $DISC"
ok "discovery issuer = jwt_issuer = $ODP; jwks_uri = $(printf %s "$DISC" | jq_py 'd["jwks_uri"]')"
# jwks_ttl_seconds = 5 here, to see a revoked key leave attenuo's cache in step 7.
printf 'issuer = "%s"\njwks_url = "%s/keys"\n' "$ODP" "$ODP" | JWKS_TTL=5 write_config "$OB_ODP_PORT" \
  > "$WORK/config-odp.toml"
start_server "$WORK/config-odp.toml" "$WORK/server-odp.log" "$OB_ODP_PORT"
OB2="http://127.0.0.1:$OB_ODP_PORT"
RESP="$(hop0 "$OB2" "$(fresh planner)")"
ROOT2="$(printf %s "$RESP" | jq_py 'd.get("access_token") or ""')"
[ -n "$ROOT2" ] || fail "hop 0 via the discovery provider refused: $RESP"
ok "hop 0 with a JWT-SVID verified against $ODP/keys"
CODER_SVID2="$(fresh coder)"
OUT="$(exchange "$OB2" "$ROOT2" coder "$CODER_SVID2")" || fail "exchange refused: $OUT"
[ -n "$(printf %s "$OUT" | token_of)" ] || fail "no child token: $OUT"
ok "exchange --actor coder with a JWT-SVID verified against the discovery provider's keys"
P="$(new_root "$OB2")"
OUT="$(exchange "$OB2" "$P" coder "$CODER_SVID2" || true)"
expect_refusal "the same SVID again, a new parent (discovery provider)" replayed "$OUT"

say "6. the Python SDK"
if python3 -c 'import httpx' 2>/dev/null; then
  P="$(new_root "$OB")"
  ATTENUO_SDK_SRC="$ROOT/sdk/python/src" OB="$OB" PARENT_TOKEN="$P" SVID="$(fresh reviewer)" \
  python3 - <<'EOF'
import os, sys
sys.path.insert(0, os.environ["ATTENUO_SDK_SRC"])
import attenuo
with attenuo.Client(os.environ["OB"]) as ob:
    child = ob.exchange(os.environ["PARENT_TOKEN"], "reviewer", ["github:read_file"],
                        actor_token=os.environ["SVID"])
    v = ob.inspect(child, verify=True)
assert v.verified and v.agent == "reviewer", v
print(f"ok   Python SDK: exchange(..., actor_token=svid) -> a verified token for {v.agent}")
EOF
else
  echo "skip: no httpx for the Python SDK"; SKIPPED+=(python-sdk)
fi

say "7. a JWT key rotation at SPIRE"
OLD_SVID="$(fresh coder)"    # signed with the current key, kept unspent for the end
OLD_SVID2="$(fresh coder)"
srv localauthority jwt prepare >/dev/null
for _ in $(seq 1 40); do
  NEXT="$(srv localauthority jwt show | awk '/Prepared JWT authority/{p=1} p && /Authority ID/{print $3; exit}')"
  [ -n "$NEXT" ] && break
  sleep 0.25
done
[ -n "${NEXT:-}" ] || fail "no prepared JWT authority"
# A prepared key is published before it signs anything. Activate only once both key sources
# list it: attenuo refetches once on an unknown kid, and the discovery provider polls the
# server (every 10 s by default), so a key activated at once can reach attenuo before it
# reaches the provider's /keys.
for _ in $(seq 1 120); do
  curl -sf --cacert "$WORK/ca.pem" "https://127.0.0.1:$BE_PORT" | grep -q "$NEXT" \
    && curl -sf "$ODP/keys" | grep -q "$NEXT" && break
  sleep 0.25
done
curl -sf "$ODP/keys" | grep -q "$NEXT" || fail "the prepared key did not reach the discovery provider"
ok "prepared JWT authority $NEXT is in the bundle and at the discovery provider's /keys"
srv localauthority jwt activate -authorityID "$NEXT" >/dev/null
for _ in $(seq 1 60); do
  NEW_SVID="$(fresh coder)"
  [ "$(jwt_part "$NEW_SVID" 0 | jq_py 'd["kid"]')" = "$NEXT" ] && break
  sleep 0.5
done
[ "$(jwt_part "$NEW_SVID" 0 | jq_py 'd["kid"]')" = "$NEXT" ] || fail "the agent still signs with the old key"
ok "prepared and activated a new JWT authority: SVIDs now carry kid $NEXT"
P="$(new_root "$OB")"
OUT="$(exchange "$OB" "$P" coder "$NEW_SVID")" || fail "new-key SVID refused (bundle): $OUT"
grep -q "unknown kid; refetching JWKS.*$NEXT" "$WORK/server-bundle.log" \
  || fail "expected an unknown-kid refetch for $NEXT"
ok "bundle path (jwks_ttl_seconds = 300): the new kid is unknown, one refetch, accepted"
P="$(new_root "$OB2")"
OUT="$(exchange "$OB2" "$P" coder "$(fresh coder)")" || fail "new-key SVID refused (discovery provider): $OUT"
ok "discovery provider path: accepted too"
srv localauthority jwt taint -authorityID "$KID1" >/dev/null
srv localauthority jwt revoke -authorityID "$KID1" >/dev/null
for _ in $(seq 1 40); do
  curl -sf --cacert "$WORK/ca.pem" "https://127.0.0.1:$BE_PORT" | grep -q "$KID1" || break
  sleep 0.25
done
curl -sf --cacert "$WORK/ca.pem" "https://127.0.0.1:$BE_PORT" | grep -q "$KID1" \
  && fail "the revoked key is still in the bundle"
ok "tainted and revoked the old authority: kid $KID1 left the bundle"
P="$(new_root "$OB")"
OUT="$(exchange "$OB" "$P" coder "$OLD_SVID")" \
  || fail "expected the cached old key to verify until jwks_ttl_seconds: $OUT"
ok "bundle path: an SVID signed with the revoked key is still accepted from the cache (jwks_ttl_seconds = 300)"
for _ in $(seq 1 120); do
  curl -sf "$ODP/keys" | grep -q "$KID1" || break
  sleep 0.25
done
curl -sf "$ODP/keys" | grep -q "$KID1" && fail "the revoked key is still at the discovery provider"
sleep 6   # jwks_ttl_seconds = 5 on this server
P="$(new_root "$OB2")"
OUT="$(exchange "$OB2" "$P" coder "$OLD_SVID2" || true)"
expect_refusal "discovery provider path, once the key left /keys and jwks_ttl_seconds = 5 passed: an SVID signed with the revoked key" actor_token_unknown_kid "$OUT"

if [ "${#SKIPPED[@]}" -gt 0 ]; then
  fail "skipped: ${SKIPPED[*]}; this run is incomplete"
fi
echo "spire smoke test passed"
