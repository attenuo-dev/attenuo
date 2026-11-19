#!/usr/bin/env bash
# attenuo's trace export through a real OpenTelemetry Collector into a real tracing backend.
#
#   scripts/live-otel-backend-smoke.sh
#
# The pipeline is the observability guide's: attenuo-server -> OpenTelemetry Collector (the
# guide's YAML, its `otlp` exporter pointed at the backend) -> Jaeger (all in one, in memory).
# Everything is read back from Jaeger's query API (`/api/v3/traces`, what the Jaeger UI reads),
# so the checks are on what a user of the backend sees. Builds on live-collector-smoke.sh, which
# reads the collector's `debug` output and checks the metrics scrape; this script does not
# repeat the scrape (Jaeger takes no metrics, and the collector's drop of them is printed).
#
# What it runs, each phase a fresh attenuo-server with its own `service.name` (through
# `OTEL_SERVICE_NAME`, except the first, which keeps the guide's):
#
#   main      The guide's `[telemetry]` block with every trace sampled. A root token from an
#             OIDC ID token (a mock IdP) at POST /token, an exchange with a run limit, a
#             renewal, an MCP session, two allowed calls that charge the limit, a third that
#             meets it, a policy deny, a call carrying a caller's `traceparent`, a streamed
#             call cut by a lease revocation, AuthZEN evaluations (bearer, a `[[peps]]` entry
#             with HTTP Basic, a batch) and an action search. Checks: one trace per proxied
#             call with the guide's span names and parent/child shape; the resource; integer
#             and boolean attributes typed as such in the backend; the caller's context as a
#             link; the upstream's `traceparent` naming the `attenuo.upstream` span;
#             `attenuo.session_tag` without the raw session id; `attenuo.charge`,
#             `attenuo.limit.kind`, `attenuo.stream_end` linked to the request; the token and
#             AuthZEN spans; no span for admin routes or the action search; no secret in any
#             span. Then the guide's "From a span to the signed record": the record of a span's
#             `attenuo.decision_id` fetched as the guide shows, `attenuo audit verify`, and the
#             search of the backend by `attenuo.decision_id`.
#   parent    `inbound_mcp = "parent"` at ratio 0: a caller's sampled context is adopted (same
#             trace id in the backend, the caller's span as parent), an unsampled one is not
#             exported.
#   sampler   The guide's `sample_ratio = 0.1` over 400 calls (the count of traces in the
#             backend must lie in an exact binomial interval, two-sided 1e-4), ratio 1 (every
#             call), ratio 0 (none, even with a caller's sampled `traceparent` in link mode),
#             and `OTEL_SDK_DISABLED=true` (none, and no `traceparent` upstream). Every
#             exported trace matches an upstream `traceparent` with flags 01, every other call's
#             has flags 00.
#   failure   The collector stopped before the server starts and again mid-run: every call is
#             answered, the failure is logged once per outage and counted, the outage's spans
#             are dropped (never in the backend), the spans after recovery arrive.
#   slow      `docker pause` on the collector: p50/p95 of 200 `tools/call` with the collector
#             up and paused (printed; the check is loose, see SLOW_FACTOR), the spans dropped
#             counter rising once the queue (`max_queue_spans`) is full, and the server's
#             resident memory before and after.
#
# Not part of CI. Needs docker (the daemon running), curl and python3, and free ports 4318
# and 9100 (the guide's) and 14317, 16685, 16686, 13134 (Jaeger) on 127.0.0.1. Skips with exit status
# 0 when docker is not available. Nothing leaves the machine except the image pulls.
#
# Secrets: every agent, PEP and admin secret is random per run, written under the work dir
# (mktemp's 0700, files 0600), and reaches attenuo-server, the CLI and the driver through files
# and the environment, never a command line. The containers get config paths only, mounted
# from a 0755 subdirectory that holds no secret. The guide's `curl -H "Authorization: Bearer
# ..."` step is run with the header read from a file (`curl -H @file`), the one change to the
# guide's commands. The mock IdP signs an ID token for anyone who asks: it is a test fixture.
#
# Environment:
#   COLLECTOR_IMAGE      collector image (default: the pinned contrib 0.165.0 digest below)
#   JAEGER_IMAGE         Jaeger v2 image (default: the pinned 2.23.0 digest below)
#   ATTENUO_BIN_DIR=DIR  prebuilt attenuo-server, attenuo and examples/mock_idp (default:
#                        cargo build)
#   SLOW_FACTOR=N        paused p50 and p95 may be at most N times the running ones plus 25 ms
#                        (default 3)
#   KEEP=1               keep the temp dir (logs, configs, what Jaeger returned)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# otel/opentelemetry-collector-contrib:0.165.0, pulled 2026-11-14 (as live-collector-smoke.sh).
COLLECTOR_IMAGE="${COLLECTOR_IMAGE:-otel/opentelemetry-collector-contrib@sha256:e40d61f10c9a617cca1ffd1be4d7e2b3a4b0f0001798ff07e58cabe82e618cea}"
# jaegertracing/jaeger:2.23.0, pulled 2026-11-14.
JAEGER_IMAGE="${JAEGER_IMAGE:-jaegertracing/jaeger@sha256:3823829974ccfc2485d2e48b165579091f32295022ae80ca49704e2f4834116e}"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "skip: docker is not available (no client, or the daemon is not running)"
  exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/attenuo-otel-backend.XXXXXX")"
COLLECTOR="attenuo-otel-collector-$$"
JAEGER="attenuo-otel-jaeger-$$"
PIDS=()
SERVER_PID=""
export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}"
export no_proxy="$NO_PROXY"

cleanup() {
  local rc=$?
  docker unpause "$COLLECTOR" >/dev/null 2>&1 || true
  for pid in "${PIDS[@]:-}" "$SERVER_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  docker logs "$COLLECTOR" > "$WORK/collector.log" 2>&1 || true
  docker logs "$JAEGER" > "$WORK/jaeger.log" 2>&1 || true
  docker rm -f "$COLLECTOR" "$JAEGER" >/dev/null 2>&1 || true
  if [ "$rc" -ne 0 ]; then
    echo >&2
    echo "otel backend smoke test failed (exit $rc). Last server and collector log lines:" >&2
    tail -n 10 "$WORK"/server-*.log 2>/dev/null >&2 || true
    grep -iE 'error|warn' "$WORK/collector.log" 2>/dev/null | tail -n 5 | cut -c1-300 >&2 || true
  fi
  if [ "${KEEP:-0}" = 1 ]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

say() { printf '\n== %s\n' "$*"; }
fail() { echo "!! $*" >&2; exit 1; }

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for p in 4318 9100 14317 16685 16686 13134; do
  port_busy "$p" && fail "127.0.0.1:$p is in use"
done

if [ -n "${ATTENUO_BIN_DIR:-}" ]; then
  BIN="$ATTENUO_BIN_DIR"
else
  echo "building..." >&2
  cargo build -q -p attenuo-server -p attenuo-cli
  cargo build -q -p attenuo-server --example mock_idp
  BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
fi
IDP_BIN="$BIN/examples/mock_idp"; [ -x "$IDP_BIN" ] || IDP_BIN="$BIN/mock_idp"
[ -x "$BIN/attenuo-server" ] && [ -x "$BIN/attenuo" ] && [ -x "$IDP_BIN" ] \
  || fail "attenuo-server, attenuo or mock_idp missing in $BIN"
export ATTENUO_CLI="$BIN/attenuo"

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

# --- per-run secrets, in files under the 0700 work dir -----------------------------------------
umask 077
rand() { python3 -c 'import secrets; print(secrets.token_hex(16))'; }
sha() { printf %s "$1" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'; }
mkdir -p "$WORK/secrets"
for name in admin planner coder pep; do rand > "$WORK/secrets/$name"; done
export SECRETS_DIR="$WORK/secrets"
printf 'Authorization: Bearer %s\n' "$(cat "$WORK/secrets/admin")" > "$WORK/secrets/admin.header"

# --- the guide's snippets, as they stand -----------------------------------------------------
GUIDE=docs/guides/observability.md
mkdir -m 755 "$WORK/mount"
python3 - "$GUIDE" "$WORK" <<'EOF'
import re, sys
text = open(sys.argv[1]).read()
work = sys.argv[2]
blocks = re.findall(r"```(yaml|toml)\n(.*?)```", text, re.S)
yaml = [b for t, b in blocks if t == "yaml"]
toml = [b for t, b in blocks if t == "toml" and "[telemetry]" in b]
assert yaml and toml, "guide has no collector YAML or [telemetry] TOML block"
open(work + "/telemetry.toml", "w").write(toml[0])
# The guide says to replace `your-backend:4317` with the backend's OTLP/gRPC address. Jaeger
# here listens without TLS on loopback, so the exporter also gets `tls: insecure: true`, as the
# guide says for a backend without TLS. Nothing else changes.
y = yaml[0]
assert "    endpoint: your-backend:4317\n" in y, "the guide's exporter endpoint has moved"
y = y.replace("    endpoint: your-backend:4317\n",
              "    endpoint: 127.0.0.1:14317\n    tls:\n      insecure: true\n")
open(work + "/mount/collector.yaml", "w").write(y)
EOF
cat > "$WORK/mount/jaeger.yaml" <<'EOF'
# Jaeger v2 all in one, in memory, on ports that leave the guide's 4318 to the collector.
service:
  extensions: [jaeger_storage, jaeger_query, healthcheckv2]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [jaeger_storage_exporter]
  telemetry:
    metrics:
      level: none
extensions:
  healthcheckv2:
    use_v2: true
    http:
      endpoint: 127.0.0.1:13134
  jaeger_query:
    storage:
      traces: mem
    http:
      endpoint: 127.0.0.1:16686
    grpc:
      endpoint: 127.0.0.1:16685
  jaeger_storage:
    backends:
      mem:
        memory:
          max_traces: 100000
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:14317
processors:
  batch:
    timeout: 200ms
exporters:
  jaeger_storage_exporter:
    trace_storage: mem
EOF
chmod 644 "$WORK/mount/collector.yaml" "$WORK/mount/jaeger.yaml"

say "backend: $JAEGER_IMAGE"
docker run --rm "$JAEGER_IMAGE" --version 2>/dev/null | tail -n 1
docker run -d --name "$JAEGER" --network host -v "$WORK/mount/jaeger.yaml:/jaeger.yaml:ro" \
  "$JAEGER_IMAGE" --config /jaeger.yaml >/dev/null
say "collector: $COLLECTOR_IMAGE"
docker run --rm "$COLLECTOR_IMAGE" --version
docker run -d --name "$COLLECTOR" --network host -v "$WORK/mount/collector.yaml:/c.yaml:ro" \
  "$COLLECTOR_IMAGE" --config /c.yaml >/dev/null

ready() { # container: wait for "Everything is ready" in its log since it was last started
  local since="$2"
  for _ in $(seq 1 150); do
    docker logs --since "$since" "$1" 2>&1 | grep -q 'Everything is ready' && return 0
    sleep 0.2
  done
  return 1
}
ready "$JAEGER" 0 || fail "Jaeger did not start"
ready "$COLLECTOR" 0 || fail "the collector did not start"
export JAEGER_QUERY="http://127.0.0.1:16686"

# --- a mock IdP, and an upstream that records what it gets and can stream --------------------
"$IDP_BIN" --port 0 > "$WORK/idp.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 100); do grep -q 'listening on' "$WORK/idp.log" && break; sleep 0.1; done
IDP_URL="$(sed -n -E 's/.*listening on (http[^ ]+).*/\1/p' "$WORK/idp.log" | head -n1)"
[ -n "$IDP_URL" ] || fail "the mock IdP did not start"
export IDP_URL

UP_PORT="$(free_port)"
export UPSTREAM_LOG="$WORK/upstream.jsonl" UPSTREAM_URL="http://127.0.0.1:$UP_PORT/mcp"
cat > "$WORK/upstream.py" <<'EOF'
import json, secrets, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
log = open(sys.argv[2], "a")
SESSION = "sess-" + secrets.token_hex(12)   # raw Mcp-Session-Id: must never be exported
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = body.get("method")
        tool = (body.get("params") or {}).get("name")
        log.write(json.dumps({"method": method, "tool": tool,
                              "traceparent": self.headers.get_all("traceparent") or [],
                              "session": self.headers.get("Mcp-Session-Id")}) + "\n")
        log.flush()
        if "id" not in body:
            self.send_response(202); self.send_header("Content-Length", "0"); self.end_headers()
            return
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "recorder", "version": "1"}}
        else:
            result = {"content": [{"type": "text", "text": "ok"}], "isError": False}
        if tool == "stream_file":
            # A long tools/call: one notification, then nothing until the proxy cuts it.
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            note = {"jsonrpc": "2.0", "method": "notifications/message",
                    "params": {"level": "info", "data": "working"}}
            try:
                self.wfile.write(f"data: {json.dumps(note)}\n\n".encode()); self.wfile.flush()
                for _ in range(300):
                    time.sleep(0.1)
                    self.wfile.write(b": keep-alive\n\n"); self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        out = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        if method == "initialize":
            self.send_header("Mcp-Session-Id", SESSION)
        self.end_headers()
        self.wfile.write(out)
    def do_DELETE(self):
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
open(sys.argv[3], "w").write(SESSION)
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
EOF
python3 "$WORK/upstream.py" "$UP_PORT" "$UPSTREAM_LOG" "$WORK/secrets/session" &
PIDS+=($!)

# --- attenuo-server configuration --------------------------------------------------------------
cat > "$WORK/policy.cedar" <<'EOF'
@id("reads")
permit(principal, action == Action::"github/read_file", resource);
@id("streams")
permit(principal, action == Action::"github/stream_file", resource);
EOF

# config PORT [extra lines for [telemetry.traces]]
config() {
  local port="$1" extra="${2:-}"
  cat <<EOF
[server]
listen = "127.0.0.1:$port"

[issuer]
issuer = "http://127.0.0.1:$port"
audience = "attenuo"
default_ttl_seconds = 900

[policy]
policies_path = "$WORK/policy.cedar"

[policy.catalog.github.read_file]
readonly = true
inputs = { repo = "string", path = "string" }

[policy.catalog.github.stream_file]
readonly = true
inputs = { repo = "string" }

[policy.catalog.github.create_issue]
inputs = { repo = "string", title = "string" }

[audit]
sqlite_path = "$WORK/audit-$port.db"

[authzen]
allow_unsigned_chain = true

[proxy]
stream_recheck_seconds = 1

[[upstreams]]
name = "github"
url = "$UPSTREAM_URL"

[[idps]]
issuer = "$IDP_URL"
client_ids = { planner = "agent-platform" }
allowed_algs = ["ES256"]

[[root_grants]]
issuer = "$IDP_URL"
agent = "planner"
may_act = ["coder"]
capabilities = ["github:*"]

[[root_grants]]
subject = "alice"
issuer = "https://idp.example"
agent = "planner"
may_act = ["coder"]
capabilities = ["github:*"]

[[agents]]
id = "planner"
secret_sha256 = "$(sha "$(cat "$WORK/secrets/planner")")"

[[agents]]
id = "coder"
secret_sha256 = "$(sha "$(cat "$WORK/secrets/coder")")"

[[peps]]
id = "gateway"
secret_sha256 = "$(sha "$(cat "$WORK/secrets/pep")")"

[dev]
allow_root_mint = true

[metrics]
enabled = true
listen = "127.0.0.1:9100"

EOF
  # The guide's [telemetry] block, with phase-specific [telemetry.traces] keys after its header.
  python3 - "$WORK/telemetry.toml" "$extra" <<'PY'
import sys
toml, extra = open(sys.argv[1]).read(), sys.argv[2]
assert "[telemetry.traces]\n" in toml
print(toml.replace("[telemetry.traces]\n", "[telemetry.traces]\n" + (extra + "\n" if extra else "")))
PY
}

# start_server NAME [extra traces keys]   (environment for the server: SERVER_ENV="K=V ...")
start_server() {
  local name="$1" extra="${2:-}" port
  port="$(free_port)"
  config "$port" "$extra" > "$WORK/config-$name.toml"
  # shellcheck disable=SC2086
  env ATTENUO_ADMIN_TOKEN="$(cat "$WORK/secrets/admin")" RUST_LOG=warn ${SERVER_ENV:-} \
    "$BIN/attenuo-server" --config "$WORK/config-$name.toml" > "$WORK/server-$name.log" 2>&1 &
  SERVER_PID=$!
  export ATTENUO_SERVER="http://127.0.0.1:$port" SERVER_LOG="$WORK/server-$name.log"
  for _ in $(seq 1 150); do
    curl -sf "$ATTENUO_SERVER/healthz" >/dev/null 2>&1 && return 0
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 0.1
  done
  cat "$WORK/server-$name.log" >&2
  fail "server $name did not start"
}
# Stop the server with SIGTERM: it drains and flushes its span queue (5 s at most).
stop_server() {
  kill -TERM "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
}

# --- the driver: every HTTP call and every check ---------------------------------------------
cat > "$WORK/drive.py" <<'EOF'
import base64, http.client, json, math, os, re, secrets, subprocess, sys, time, urllib.parse
from urllib.request import Request, urlopen

SECRETS = os.environ["SECRETS_DIR"]
def secret(name): return open(f"{SECRETS}/{name}").read().strip()
ADMIN = secret("admin")
SERVER = os.environ.get("ATTENUO_SERVER", "")
JAEGER = os.environ["JAEGER_QUERY"]
UPLOG = os.environ["UPSTREAM_LOG"]
STATE = os.environ["WORK"] + "/state.json"
failed = []

def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failed.append(what)

def done():
    if failed:
        print(f"{len(failed)} check(s) failed", file=sys.stderr)
        sys.exit(1)

def load():
    try: return json.load(open(STATE))
    except FileNotFoundError: return {}

def save(**kv):
    s = load(); s.update(kv); json.dump(s, open(STATE, "w"))

def req(method, path, body=None, headers=None, form=False, base=None):
    url = (base or SERVER) + path
    h = dict(headers or {})
    data = None
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            data = json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
    r = Request(url, data=data, method=method, headers=h)
    try:
        with urlopen(r, timeout=30) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except Exception as e:
        if hasattr(e, "code"):
            return e.code, dict(e.headers), e.read()
        raise

def basic(user, pw):
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

def jwt_claims(tok):
    p = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))

def tp(trace=None, span=None, flags="01"):
    trace = trace or secrets.token_hex(16); span = span or secrets.token_hex(8)
    return trace, span, f"00-{trace}-{span}-{flags}"

class Mcp:
    """One keep-alive connection to /mcp/github."""
    def __init__(self, token, session=None):
        u = urllib.parse.urlparse(SERVER)
        self.conn = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
        self.token, self.session, self.n = token, session, 0
    def post(self, msg, traceparent=None):
        h = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
             "Accept": "application/json, text/event-stream"}
        if self.session: h["Mcp-Session-Id"] = self.session
        if traceparent: h["traceparent"] = traceparent
        self.conn.request("POST", "/mcp/github", json.dumps(msg), h)
        r = self.conn.getresponse()
        return r.status, dict(r.getheaders()), r.read()
    def call(self, tool, args, traceparent=None):
        self.n += 1
        return self.post({"jsonrpc": "2.0", "id": self.n, "method": "tools/call",
                          "params": {"name": tool, "arguments": args}}, traceparent)

def answer(body):
    try: return json.loads(body)
    except ValueError:
        for line in body.decode().splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:])
    return {}

def upstream_log():
    return [json.loads(l) for l in open(UPLOG)]

def mint(subject="alice", caps=("github:*",)):
    s, _, b = req("POST", "/admin/root-token",
                  {"subject": subject, "issuer": "https://idp.example", "agent": "planner",
                   "capabilities": list(caps)}, {"Authorization": f"Bearer {ADMIN}"})
    assert s == 200, (s, b)
    return json.loads(b)

def metric(name):
    with urlopen("http://127.0.0.1:9100/metrics", timeout=10) as r:
        text = r.read().decode()
    m = re.search(rf"^{name}(?:{{[^}}]*}})? (\S+)$", text, re.M)
    return float(m.group(1)) if m else None

# --- Jaeger ----------------------------------------------------------------------------------
def val(v):
    if "intValue" in v: return ("int", int(v["intValue"]))
    if "boolValue" in v: return ("bool", v["boolValue"])
    if "doubleValue" in v: return ("double", v["doubleValue"])
    if "stringValue" in v: return ("str", v["stringValue"])
    return ("other", v)

def jaeger(service, attributes=None):
    q = {"query.service_name": service,
         "query.start_time_min": "2000-01-01T00:00:00Z",
         "query.start_time_max": "2100-01-01T00:00:00Z",
         "query.search_depth": "5000"}
    if attributes: q["query.attributes"] = json.dumps(attributes)
    try:
        with urlopen(f"{JAEGER}/api/v3/traces?" + urllib.parse.urlencode(q), timeout=30) as r:
            doc = json.load(r)
    except Exception as e:
        if getattr(e, "code", None) == 404: return []
        raise
    spans = []
    for rs in doc.get("result", {}).get("resourceSpans", []):
        res = {a["key"]: val(a["value"]) for a in rs.get("resource", {}).get("attributes", [])}
        for ss in rs.get("scopeSpans", []):
            for s in ss.get("spans", []):
                # Jaeger adds `@jaeger@warnings` of its own (a parent span that is not in the
                # trace, as for a caller's span in parent mode); kept apart from attenuo's.
                attrs = s.get("attributes", [])
                s["attrs"] = {a["key"]: val(a["value"]) for a in attrs
                              if not a["key"].startswith("@jaeger@")}
                s["jaeger"] = [a for a in attrs if a["key"].startswith("@jaeger@")]
                s["resource"] = res
                spans.append(s)
    return spans

def settled(service, want=None, quiet=6.0, limit=90.0):
    """Spans of `service` once their count has not changed for `quiet` seconds."""
    start, last, since = time.time(), -1, time.time()
    while time.time() - start < limit:
        spans = jaeger(service)
        if len(spans) != last:
            last, since = len(spans), time.time()
        elif time.time() - since >= quiet and (want is None or want(spans)):
            return spans
        time.sleep(0.5)
    return jaeger(service)

def traces(spans):
    out = {}
    for s in spans: out.setdefault(s["traceId"], []).append(s)
    return out

def named(spans, name): return [s for s in spans if s["name"] == name]
def a(span, key): return span["attrs"].get(key, (None, None))[1]
def children(spans, parent): return [s for s in spans if s.get("parentSpanId") == parent["spanId"]]

# --- phases ----------------------------------------------------------------------------------
def main_drive():
    planner, coder, pep = secret("planner"), secret("coder"), secret("pep")
    idp = os.environ["IDP_URL"]
    with urlopen(f"{idp}/demo/id-token", timeout=10) as r:
        id_token = r.read().decode().strip()
    ex = "urn:ietf:params:oauth:grant-type:token-exchange"
    caps = json.dumps([{"type": "attenuo_capabilities",
                        "capabilities": [{"server": "github", "tool": "*"}]}])
    s, _, b = req("POST", "/token", {"grant_type": ex, "subject_token": id_token,
                  "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                  "authorization_details": caps}, {"Authorization": basic("planner", planner)},
                  form=True)
    check(s == 200, f"root token from the IdP's ID token at POST /token ({s})")
    root = json.loads(b)["access_token"]

    def exchange(capabilities):
        s, _, b = req("POST", "/token", {
            "grant_type": ex, "subject_token": root,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "actor": "coder",
            "client_id": "coder", "client_secret": coder,
            "authorization_details": [{"type": "attenuo_capabilities",
                                       "capabilities": capabilities}]})
        assert s == 200, (s, b)
        return json.loads(b)
    # One exchange: a delegation token is exchanged once (a second is `replayed`).
    streamer = exchange([{"server": "github", "tool": "read_file", "limits": {"calls": 2}},
                         {"server": "github", "tool": "create_issue"},
                         {"server": "github", "tool": "stream_file"}])
    limited = streamer["access_token"]
    s, _, _ = req("POST", "/token/renew", None, {"Authorization": f"Bearer {limited}"})
    check(s == 200, f"POST /token/renew ({s})")

    m = Mcp(limited)
    s, h, b = m.post({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                      "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "smoke", "version": "1"}}})
    sid = {k.lower(): v for k, v in h.items()}.get("mcp-session-id")
    check(s == 200 and sid == secret("session"), "initialize binds the upstream's session")
    m.session = sid
    m.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
    marker = "ARG-" + secrets.token_hex(6)
    caller_trace, caller_span, caller_tp = tp()
    calls = []
    for tool, args, t in [("read_file", {"repo": "acme/api", "path": marker}, caller_tp),
                          ("read_file", {"repo": "acme/api", "path": "b"}, None),
                          ("read_file", {"repo": "acme/api", "path": "c"}, None),
                          ("create_issue", {"repo": "acme/api", "title": marker}, None)]:
        s, h, b = m.call(tool, args, t)
        msg = answer(b)
        did = {k.lower(): v for k, v in h.items()}.get("x-attenuo-decision-id") \
            or ((msg.get("error") or {}).get("data") or {}).get("decision_id")
        reason = ((msg.get("error") or {}).get("data") or {}).get("reason")
        calls.append({"tool": tool, "status": s, "decision_id": did, "reason": reason,
                      "error": "error" in msg})
    check([c["error"] for c in calls] == [False, False, True, True],
          f"allow, allow, deny (run limit), deny (policy): {[c['reason'] for c in calls]}")
    check(calls[2]["reason"] == "budget_exhausted", "the third read_file meets the run limit")

    # A streamed call, cut when its lease is revoked (last: the token is dead after it).
    u = urllib.parse.urlparse(SERVER)
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
    c.request("POST", "/mcp/github", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "stream_file", "arguments": {"repo": "acme/api"}}}),
              {"Authorization": f"Bearer {streamer['access_token']}",
               "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"})
    r = c.getresponse()
    first = r.readline()
    s, _, b = req("POST", f"/admin/leases/{streamer['lease']}/revoke", {"reason": "smoke"},
                  {"Authorization": f"Bearer {ADMIN}"})
    check(s == 200, f"lease of the streamed call revoked ({s})")
    rest = r.read().decode()
    ends = [json.loads(l[5:]) for l in rest.splitlines() if l.startswith("data:")]
    end = ends[-1] if ends else {}
    check(first.startswith(b"data:") or first.startswith(b"id:") or first.startswith(b"event:"),
          "the streamed call got its first event")
    end_data = (end.get("error") or {}).get("data") or {}
    check(end_data.get("reason") == "lease_revoked",
          f"the stream ended with lease_revoked ({end_data.get('reason')})")

    # AuthZEN: a bearer caller (linked), a PEP with HTTP Basic (parent), a batch, a search.
    ev = {"subject": {"type": "agent", "id": ""}, "action": {"name": "read_file"},
          "resource": {"type": "tool", "id": "github/read_file", "properties": {"server": "github"}},
          "context": {"input": {"repo": "acme/api", "path": marker}}}
    bearer_trace, bearer_span, bearer_tp = tp()
    s, _, b = req("POST", "/access/v1/evaluation", ev,
                  {"Authorization": f"Bearer {root}", "traceparent": bearer_tp})
    check(s == 200 and json.loads(b).get("decision") is True, f"AuthZEN evaluation, bearer ({s})")
    chain = jwt_claims(root)["chain"]
    pev = dict(ev, subject={"type": "agent", "id": "planner",
                            "properties": {"chain": chain,
                                           "originating_user": chain["originating_user"]}})
    pep_trace, pep_span, pep_tp = tp()
    s, _, b = req("POST", "/access/v1/evaluation", pev,
                  {"Authorization": basic("gateway", pep), "traceparent": pep_tp})
    check(s == 200 and json.loads(b).get("decision") is True,
          f"AuthZEN evaluation, [[peps]] entry with HTTP Basic and an unsigned chain ({s} {b[:200]!r})")
    s, _, b = req("POST", "/access/v1/evaluations",
                  {"subject": ev["subject"], "resource": ev["resource"],
                   "context": ev["context"],
                   "evaluations": [{"action": {"name": "read_file"}},
                                   {"action": {"name": "create_issue"}}]},
                  {"Authorization": f"Bearer {root}"})
    check(s == 200 and len(json.loads(b).get("evaluations", [])) == 2,
          f"AuthZEN batch of two evaluations ({s})")
    s, _, b = req("POST", "/access/v1/search/action",
                  {"subject": ev["subject"], "resource": {"type": "mcp_server", "id": "github"},
                   "context": ev["context"]},
                  {"Authorization": f"Bearer {root}"})
    check(s == 200, f"AuthZEN action search ({s}: {b[:120]!r})")

    save(main={"calls": calls, "caller": [caller_trace, caller_span],
               "bearer": [bearer_trace, bearer_span], "pep": [pep_trace, pep_span],
               "marker": marker, "session": sid,
               "secrets": [root, limited, id_token, planner, coder,
                           pep, ADMIN, sid, marker, os.environ["UPSTREAM_URL"],
                           "alice@example.com"],
               "stream_end": end_data})
    done()

def shape(spans, root):
    """The names under `root`, as a sorted list of (name, sorted child names)."""
    out = []
    def walk(s):
        kids = children(spans, s)
        out.append((s["name"], sorted(k["name"] for k in kids)))
        for k in kids: walk(k)
    walk(root)
    return sorted(out)

def main_check():
    st = load()["main"]
    spans = settled("attenuo-server")
    json.dump(spans, open(os.environ["WORK"] + "/jaeger-main.json", "w"))
    by = traces(spans)
    print(f"{len(spans)} spans in {len(by)} traces: {sorted({s['name'] for s in spans})}")
    res = spans[0]["resource"] if spans else {}
    check(res.get("service.name") == ("str", "attenuo-server"), "resource service.name")
    check(res.get("deployment.environment") == ("str", "staging"),
          "resource attribute from resource_attributes")

    reqs = named(spans, "mcp.request")
    calls = [r for r in reqs if any(d["name"] == "attenuo.decide" for d in children(spans, r))]
    # One trace per proxied request: initialize, notifications/initialized, four calls, stream.
    check(len(reqs) == 7 and len({r["traceId"] for r in reqs}) == 7,
          f"one trace per proxied request (7 mcp.request in {len({r['traceId'] for r in reqs})} traces)")
    check(all(not r.get("parentSpanId") for r in reqs), "mcp.request is a root span (link mode)")
    check(all(r["kind"] == 2 for r in reqs), "mcp.request is a server span")
    up = named(spans, "attenuo.upstream")
    check(all(u["kind"] == 3 for u in up) and up, "attenuo.upstream is a client span")

    allowed = [r for r in calls if any(a(d, "attenuo.decision") == "allow"
                                       for d in children(spans, r) if d["name"] == "attenuo.decide")
               and a(r, "http.response.status_code") == 200
               and any(c["name"] == "attenuo.upstream" for c in children(spans, r))]
    want_top = ["attenuo.authenticate", "attenuo.decide", "attenuo.response",
                "attenuo.session_gate", "attenuo.upstream"]
    want_decide = ["attenuo.audit_append", "attenuo.charge", "attenuo.lease_check",
                   "attenuo.policy", "attenuo.run_state"]
    buffered = [r for r in allowed if a(r, "attenuo.session_tag")]
    check(len(buffered) == 2, f"two allowed, buffered calls in the session ({len(buffered)})")
    for r in buffered:
        sh = dict(shape(spans, r))
        check(sh["mcp.request"] == want_top, f"mcp.request children {sh['mcp.request']}")
        check(sh["attenuo.decide"] == want_decide, f"attenuo.decide children {sh['attenuo.decide']}")
        check(sh["attenuo.response"] == ["attenuo.record_result"],
              "attenuo.record_result is a child of attenuo.response")
    tags = {a(r, "attenuo.session_tag") for r in reqs if a(r, "attenuo.session_tag")}
    check(len(tags) == 1 and st["session"] not in tags,
          f"attenuo.session_tag is one value, not the raw Mcp-Session-Id ({tags})")

    decides = named(spans, "attenuo.decide")
    by_id = {a(d, "attenuo.decision_id"): d for d in decides}
    c = st["calls"]
    for call in c:
        check(call["decision_id"] in by_id, f"decision {call['tool']} {call['reason']} has its span")
    ex = by_id.get(c[2]["decision_id"])
    if ex:
        check(a(ex, "attenuo.decision") == "deny" and a(ex, "attenuo.reason") == "budget_exhausted"
              and a(ex, "attenuo.limit.kind") == "calls"
              and a(ex, "attenuo.budget.exhausted_at") == "check",
              f"run limit met: decide has limit.kind calls, exhausted_at check "
              f"({a(ex, 'attenuo.limit.kind')}, {a(ex, 'attenuo.budget.exhausted_at')})")
        check(not [k for k in children(spans, ex) if k["name"] == "attenuo.charge"],
              "a call that meets the limit has no attenuo.charge")
    for call in c[:2]:
        d = by_id.get(call["decision_id"])
        check(d is not None and [k["name"] for k in children(spans, d)].count("attenuo.charge") == 1,
              "an allowed limited call has one attenuo.charge")

    ints = {"http.response.status_code", "attenuo.chain_depth", "attenuo.audit.seq"}
    bools = {"attenuo.dpop_bound", "attenuo.tainted"}
    bad = sorted({(s["name"], k, t) for s in spans for k, (t, _) in s["attrs"].items()
                  if (k in ints and t != "int") or (k in bools and t != "bool")
                  or (k not in ints | bools and t != "str")})
    check(not bad, f"integers are ints, booleans bools, the rest strings in Jaeger ({bad})")
    allowed_keys = {"http.request.method", "http.route", "http.response.status_code",
                    "attenuo.server", "attenuo.session_tag", "attenuo.chain_id",
                    "attenuo.chain_depth", "attenuo.dpop_bound", "attenuo.token.cache",
                    "attenuo.reason", "attenuo.tool", "attenuo.decision", "attenuo.decision_id",
                    "attenuo.audit.seq", "attenuo.policy_ids", "attenuo.tainted",
                    "attenuo.subject_digest", "attenuo.limit.kind",
                    "attenuo.budget.exhausted_at", "attenuo.result.label"}
    extra = sorted({k for s in spans for k in s["attrs"]} - allowed_keys)
    check(not extra, f"every attribute is on the guide's list ({extra})")

    # The caller's traceparent: a link on mcp.request, not the trace.
    ct, cs = st["caller"]
    linked = [r for r in reqs if any(l["traceId"] == ct and l["spanId"] == cs
                                     for l in r.get("links", []))]
    check(len(linked) == 1 and linked[0]["traceId"] != ct,
          "the caller's traceparent is a link on mcp.request, its trace id not adopted")
    check(not any(s["traceId"] == ct for s in spans), "no span in the caller's trace")

    # The upstream's traceparent names the attenuo.upstream span.
    want = {f"00-{u['traceId']}-{u['spanId']}-01" for u in up}
    got = [r["traceparent"] for r in upstream_log()]
    check(all(len(t) == 1 for t in got), "each upstream request carried one traceparent")
    check({t[0] for t in got} == want,
          f"the upstream's traceparent is the attenuo.upstream span ({len(want)} spans)")
    check(not any(ct in t[0] for t in got), "the caller's traceparent is not forwarded")

    # The stream end: a root span linked to the request's attenuo.response.
    se = named(spans, "attenuo.stream_end")
    check(len(se) == 1, f"one attenuo.stream_end ({len(se)})")
    if se:
        e = se[0]
        resp = [s for s in spans if s["name"] == "attenuo.response"
                and any(l["spanId"] == s["spanId"] for l in e.get("links", []))]
        check(not e.get("parentSpanId") and len(e.get("links", [])) == 1 and len(resp) == 1,
              "attenuo.stream_end is a root span linked to the stream's attenuo.response")
        check(a(e, "attenuo.reason") == "lease_revoked"
              and a(e, "attenuo.decision_id") == st["stream_end"].get("decision_id")
              and isinstance(a(e, "attenuo.audit.seq"), int),
              "attenuo.stream_end has the reason, decision id and seq of the stream.end record")

    # Token routes.
    for name, route, n in [("attenuo.token.root", "/token", 1), ("attenuo.token.exchange", "/token", 1),
                           ("attenuo.token.renew", "/token/renew", 1)]:
        t = named(spans, name)
        check(len(t) == n and all(a(x, "http.route") == route and a(x, "http.request.method") == "POST"
                                  and a(x, "http.response.status_code") == 200 and x["kind"] == 2
                                  for x in t),
              f"{n} {name} span(s), server kind, route {route}, status 200")

    # AuthZEN.
    ev = named(spans, "attenuo.authzen.evaluate")
    check(len(ev) == 3, f"three attenuo.authzen.evaluate spans ({len(ev)})")
    bt, bs = st["bearer"]; pt, ps = st["pep"]
    pep = [e for e in ev if e["traceId"] == pt]
    check(len(pep) == 1 and pep[0].get("parentSpanId") == ps,
          "a [[peps]] caller with HTTP Basic is the parent: its trace id, its span as parent")
    br = [e for e in ev if any(l["traceId"] == bt for l in e.get("links", []))]
    check(len(br) == 1 and br[0]["traceId"] != bt and not br[0].get("parentSpanId"),
          "a bearer AuthZEN caller is linked, not adopted")
    nd = sorted(len([k for k in children(spans, e) if k["name"] == "attenuo.decide"]) for e in ev)
    check(nd == [1, 1, 2], f"an attenuo.decide child per evaluation ({nd})")
    routes = {a(s, "http.route") for s in spans if a(s, "http.route")}
    check(routes <= {"/mcp/{server}", "/token", "/token/renew", "/access/v1/evaluation",
                     "/access/v1/evaluations"},
          f"no span for admin routes or the action search ({sorted(routes)})")
    roots = {s["name"] for s in spans if not s.get("parentSpanId")}
    check(roots <= {"mcp.request", "attenuo.token.root", "attenuo.token.exchange",
                    "attenuo.token.renew", "attenuo.authzen.evaluate", "attenuo.stream_end"},
          f"root spans ({sorted(roots)}), none for the action search")

    blob = json.dumps(spans)
    for i, sec in enumerate(st["secrets"]):
        check(sec[:24] not in blob, f"secret #{i} is in no exported span")
    check("alice" not in blob, "the subject is in no exported span")

    # From a span to the signed record, as the guide says.
    d = by_id.get(c[0]["decision_id"])
    did, seq = a(d, "attenuo.decision_id"), a(d, "attenuo.audit.seq")
    save(join={"decision_id": did, "seq": seq})
    found = jaeger("attenuo-server", {"attenuo.decision_id": did})
    check(any(s["spanId"] == d["spanId"] for s in found) and
          {s["traceId"] for s in found} == {d["traceId"]},
          "searching Jaeger for attenuo.decision_id finds the call's trace")
    done()

def sampler(service, n, expect, traceparent_flags=None):
    """`n` calls on one token; `expect` is "ratio:<p>", "all", "none" or "off"."""
    before = len(upstream_log())
    m = Mcp(mint()["access_token"])
    for i in range(n):
        t = tp(flags=traceparent_flags)[2] if traceparent_flags else None
        s, _, b = m.call("read_file", {"repo": "acme/api", "path": str(i)}, t)
        assert s == 200 and "error" not in answer(b), (s, b)
    save(**{f"sampler_{service}": {"from": before, "n": n, "expect": expect}})

def binom_interval(n, p, alpha=1e-4):
    pmf = [math.comb(n, k) * p**k * (1 - p)**(n - k) for k in range(n + 1)]
    lo, acc = 0, 0.0
    while acc + pmf[lo] <= alpha / 2: acc += pmf[lo]; lo += 1
    hi, acc = n, 0.0
    while acc + pmf[hi] <= alpha / 2: acc += pmf[hi]; hi -= 1
    return lo, hi

def sampler_check(service):
    st = load()[f"sampler_{service}"]
    n, expect = st["n"], st["expect"]
    ups = upstream_log()[st["from"]:]
    check(len(ups) == n, f"{service}: {n} calls reached the upstream ({len(ups)})")
    spans = settled(service, quiet=6.0)
    reqs = named(spans, "mcp.request")
    exported = {r["traceId"] for r in reqs}
    tps = [u["traceparent"] for u in ups]
    if expect == "off":
        check(not spans, f"{service}: nothing in Jaeger with telemetry off ({len(spans)} spans)")
        check(all(t == [] for t in tps), f"{service}: no traceparent upstream with telemetry off")
        return
    check(all(len(t) == 1 for t in tps), f"{service}: one traceparent on every upstream request")
    flags = [t[0].split("-")[3] for t in tps if t]
    sampled = {t[0].split("-")[1] for t in tps if t and t[0].endswith("-01")}
    check(set(flags) <= {"00", "01"}, f"{service}: upstream flags are 00 or 01")
    check(exported == sampled,
          f"{service}: the exported traces are exactly the upstream traceparents with flags 01")
    check(len(spans) == len({s['spanId'] for s in spans}) and
          all(len([s for s in spans if s["traceId"] == t]) >= 9 for t in exported),
          f"{service}: every exported trace is whole")
    k = len(exported)
    if expect == "all":
        check(k == n, f"{service}: ratio 1 exports every call ({k}/{n})")
    elif expect == "none":
        check(k == 0 and flags.count("00") == n, f"{service}: ratio 0 exports nothing ({k}/{n}), "
              f"every upstream traceparent has flags 00")
    else:
        p = float(expect.split(":")[1])
        lo, hi = binom_interval(n, p)
        check(lo <= k <= hi, f"{service}: {k} of {n} traces exported at ratio {p}: inside the "
              f"exact binomial interval [{lo}, {hi}] (two-sided 1e-4)")
        print(f"     observed share {k / n:.3f}")
    done()

def parent_phase():
    m = Mcp(mint()["access_token"])
    st = {}
    for label, flags in [("sampled", "01"), ("unsampled", "00")]:
        tr, sp, t = tp(flags=flags)
        s, _, b = m.call("read_file", {"repo": "acme/api", "path": label}, t)
        assert s == 200, (s, b)
        st[label] = [tr, sp]
    s, _, b = m.call("read_file", {"repo": "acme/api", "path": "none"})
    save(parent=st)

def parent_check():
    st = load()["parent"]
    spans = settled("attenuo-parent", quiet=6.0)
    reqs = named(spans, "mcp.request")
    tr, sp = st["sampled"]
    check(len(reqs) == 1 and reqs[0]["traceId"] == tr and reqs[0].get("parentSpanId") == sp,
          "parent mode: a caller's sampled context is adopted (its trace id, its span as parent)")
    check({s["traceId"] for s in spans} == {tr}, "parent mode, ratio 0: only that trace is exported")
    ups = [u for u in upstream_log() if u["method"] == "tools/call"][-3:]
    check(ups[0]["traceparent"][0].startswith(f"00-{tr}-") and ups[0]["traceparent"][0].endswith("-01"),
          "parent mode: the upstream gets a traceparent in the caller's trace, sampled")
    ut, _ = st["unsampled"]
    check(ups[1]["traceparent"][0].startswith(f"00-{ut}-") and ups[1]["traceparent"][0].endswith("-00"),
          "parent mode: an unsampled caller stays unsampled (flags 00 upstream, nothing exported)")
    check(ups[2]["traceparent"][0].endswith("-00"), "parent mode, ratio 0: a call with no traceparent is not sampled")
    done()

def calls(n, label):
    """`n` calls; record which trace each went out with (from the upstream's traceparent)."""
    before = len(upstream_log())
    m = Mcp(load().get("fail_token") or mint()["access_token"])
    save(fail_token=m.token)
    ok = 0
    for i in range(n):
        s, _, b = m.call("read_file", {"repo": "acme/api", "path": f"{label}-{i}"})
        ok += s == 200 and "error" not in answer(b)
    check(ok == n, f"{label}: {ok}/{n} calls answered and allowed")
    ids = [u["traceparent"][0].split("-")[1] for u in upstream_log()[before:]]
    save(**{f"batch_{label}": ids})
    done()

def log_lines(pattern):
    return len(re.findall(pattern, open(os.environ["SERVER_LOG"]).read()))

def failure_check(step):
    if step == "down":
        check(log_lines(r"telemetry export failed") == 1, "outage 1: the failure is logged once")
        f = metric("attenuo_telemetry_export_failures_total")
        check(f is not None and f >= 1, f"outage 1: export failures counted ({f})")
    elif step == "recovered":
        check(log_lines(r"telemetry export recovered") >= 1, "recovery is logged")
    elif step == "down2":
        check(log_lines(r"telemetry export failed") == 2, "outage 2: logged once more (once per outage)")
        f = metric("attenuo_telemetry_export_failures_total")
        check(f is not None and f >= 2, f"outage 2: export failures counted ({f})")
        print(f"     spans dropped (queue full): "
              f"{metric('attenuo_telemetry_spans_dropped_total')}")
    elif step == "final":
        st = load()
        spans = settled("attenuo-failure", quiet=6.0)
        got = {s["traceId"] for s in named(spans, "mcp.request")}
        for label, want in [("A", False), ("B", True), ("C", False), ("D", True)]:
            ids = set(st[f"batch_{label}"])
            n = len(ids & got)
            check(n == (len(ids) if want else 0),
                  f"batch {label} ({'collector up' if want else 'collector down'}): "
                  f"{n}/{len(ids)} traces in Jaeger")
    done()

def rss(pid):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith("VmRSS:"): return int(line.split()[1])

def latency(label, n=200):
    m = Mcp(load().get("slow_token") or mint()["access_token"])
    save(slow_token=m.token)
    m.call("read_file", {"repo": "acme/api", "path": "warm"})
    t = []
    for i in range(n):
        t0 = time.perf_counter()
        s, _, b = m.call("read_file", {"repo": "acme/api", "path": f"{label}-{i}"})
        t.append(time.perf_counter() - t0)
        assert s == 200 and "error" not in answer(b), (s, b)
    t.sort()
    p50, p95, mx = t[n // 2] * 1e3, t[int(n * 0.95)] * 1e3, t[-1] * 1e3
    print(f"     {label}: p50 {p50:.2f} ms, p95 {p95:.2f} ms, max {mx:.2f} ms "
          f"(RSS {rss(int(os.environ['SERVER_PID'])) // 1024} MiB)")
    save(**{f"lat_{label}": [p50, p95, mx]})

def slow_check():
    st = load()
    k = float(os.environ.get("SLOW_FACTOR", "3"))
    up = [min(st["lat_up1"][i], st["lat_up2"][i]) for i in range(2)]
    noise = [abs(st["lat_up1"][i] - st["lat_up2"][i]) for i in range(2)]
    pa = st["lat_paused"]
    print(f"     up (best of two runs): p50 {up[0]:.2f} ms, p95 {up[1]:.2f} ms; run-to-run "
          f"difference p50 {noise[0]:.2f} ms, p95 {noise[1]:.2f} ms")
    for i, q in enumerate(["p50", "p95"]):
        check(pa[i] <= k * up[i] + 25.0,
              f"paused collector: {q} {pa[i]:.2f} ms <= {k:g} x {up[i]:.2f} + 25 ms")
    check(pa[2] < 1000.0, f"paused collector: no call near the 10 s export timeout (max {pa[2]:.1f} ms)")
    done()

def until_dropped(limit=3000):
    m = Mcp(load()["slow_token"])
    n = 0
    while (metric("attenuo_telemetry_spans_dropped_total") or 0) == 0 and n < limit:
        for _ in range(50):
            m.call("read_file", {"repo": "acme/api", "path": "fill"})
        n += 50
    d = metric("attenuo_telemetry_spans_dropped_total") or 0
    check(d > 0, f"with the collector paused the queue fills and drops are counted "
                 f"({d:.0f} dropped after {n} more calls)")
    print(f"     RSS now {rss(int(os.environ['SERVER_PID'])) // 1024} MiB")
    done()

if __name__ == "__main__":
    cmd, *args = sys.argv[1:]
    {"main-drive": main_drive, "main-check": main_check, "sampler": lambda: sampler(
        args[0], int(args[1]), args[2], args[3] if len(args) > 3 else None),
     "sampler-check": lambda: sampler_check(args[0]), "parent": parent_phase,
     "parent-check": parent_check, "calls": lambda: calls(int(args[0]), args[1]),
     "failure-check": lambda: failure_check(args[0]), "latency": lambda: latency(args[0]),
     "slow-check": slow_check, "until-dropped": until_dropped}[cmd]()
EOF
export WORK
drive() { python3 -I "$WORK/drive.py" "$@"; }

# --- main --------------------------------------------------------------------------------------
say "main: the guide's [telemetry], every trace sampled (OTEL_TRACES_SAMPLER_ARG=1)"
SERVER_ENV="OTEL_TRACES_SAMPLER_ARG=1" start_server main
drive main-drive
say "main: what Jaeger shows"
drive main-check

say "main: from a span to the signed record, as the guide says"
# The guide's two commands, with the decision id and seq read from Jaeger. The guide's curl
# sends the admin token in a header; here the header comes from a file so it is not in `ps`.
DID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["join"]["decision_id"])' "$WORK/state.json")"
SEQ="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["join"]["seq"])' "$WORK/state.json")"
echo "span: attenuo.decision_id=$DID attenuo.audit.seq=$SEQ"
curl -s -H @"$WORK/secrets/admin.header" \
  "$ATTENUO_SERVER/admin/audit/records/$DID" > "$WORK/record.json"
python3 - "$WORK/record.json" "$DID" "$SEQ" <<'EOF2' || fail "the record is not the span's"
import json, sys
r = json.load(open(sys.argv[1]))
e = r["entry"]
ok = e["record"]["id"] == sys.argv[2] and e["seq"] == int(sys.argv[3])
print(("ok   " if ok else "FAIL ") + f"GET /admin/audit/records/<id>: record {e['record']['id']} "
      f"at seq {e['seq']}, {e['record']['kind']} {e['record']['decision']} {e['record']['tool']}")
sys.exit(0 if ok else 1)
EOF2
VERIFY="$(ATTENUO_ADMIN_TOKEN="$(cat "$WORK/secrets/admin")" "$ATTENUO_CLI" audit verify)" \
  || fail "attenuo audit verify failed"
echo "$VERIFY"
N="$(printf '%s\n' "$VERIFY" | sed -n -E 's/^audit chain OK: ([0-9]+) entries verified.*/\1/p')"
[ -n "$N" ] && [ "$N" -ge "$SEQ" ] || fail "the verified chain does not reach seq $SEQ"
echo "ok   attenuo audit verify: the chain holds seq $SEQ ($N entries)"
stop_server

# --- parent mode -------------------------------------------------------------------------------
say "parent: inbound_mcp = \"parent\", ratio 0"
SERVER_ENV="OTEL_TRACES_SAMPLER_ARG=0 OTEL_SERVICE_NAME=attenuo-parent" \
  start_server parent 'inbound_mcp = "parent"'
drive parent
stop_server
drive parent-check

# --- the sampler -------------------------------------------------------------------------------
say "sampler: the guide's sample_ratio = 0.1 over 400 calls"
SERVER_ENV="OTEL_SERVICE_NAME=attenuo-ratio-0.1" start_server r01
drive sampler attenuo-ratio-0.1 400 ratio:0.1
stop_server
drive sampler-check attenuo-ratio-0.1

say "sampler: ratio 1 over 50 calls"
SERVER_ENV="OTEL_TRACES_SAMPLER_ARG=1 OTEL_SERVICE_NAME=attenuo-ratio-1" start_server r1
drive sampler attenuo-ratio-1 50 all
stop_server
drive sampler-check attenuo-ratio-1

say "sampler: ratio 0 over 50 calls, each with a caller's sampled traceparent (link mode)"
SERVER_ENV="OTEL_TRACES_SAMPLER_ARG=0 OTEL_SERVICE_NAME=attenuo-ratio-0" start_server r0
drive sampler attenuo-ratio-0 50 none 01
stop_server
drive sampler-check attenuo-ratio-0

say "sampler: telemetry off (OTEL_SDK_DISABLED=true), 50 calls"
SERVER_ENV="OTEL_SDK_DISABLED=true OTEL_SERVICE_NAME=attenuo-off" start_server off
drive sampler attenuo-off 50 off
stop_server
drive sampler-check attenuo-off

# --- failure: the collector down at start, and again mid-run ---------------------------------
say "failure: the collector stopped before the server starts"
docker stop "$COLLECTOR" >/dev/null
# RUST_LOG=info: the recovery line is at info, the failure at warn.
SERVER_ENV="RUST_LOG=info OTEL_TRACES_SAMPLER_ARG=1 OTEL_SERVICE_NAME=attenuo-failure" start_server failure
echo "ok   the server starts with the collector unreachable"
drive calls 20 A
sleep 7   # one export interval (5 s) and the failed export
drive failure-check down
T0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker start "$COLLECTOR" >/dev/null
ready "$COLLECTOR" "$T0" || fail "the collector did not restart"
drive calls 20 B
sleep 7
drive failure-check recovered
say "failure: the collector stopped mid-run"
docker stop "$COLLECTOR" >/dev/null
drive calls 20 C
sleep 7
drive failure-check down2
T0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker start "$COLLECTOR" >/dev/null
ready "$COLLECTOR" "$T0" || fail "the collector did not restart"
drive calls 20 D
stop_server
drive failure-check final

# --- slow: the collector paused ------------------------------------------------------------------
say "slow: 200 tools/call with the collector up, twice, then paused (docker pause)"
SERVER_ENV="OTEL_TRACES_SAMPLER_ARG=1 OTEL_SERVICE_NAME=attenuo-slow" start_server slow
export SERVER_PID
drive latency up1
drive latency up2
docker pause "$COLLECTOR" >/dev/null
drive latency paused
drive slow-check
drive until-dropped
# Shutdown with the collector still paused: the queue gets 5 s (TELEMETRY_SHUTDOWN_GRACE),
# and an export request blocked on the paused collector must not hold the exit past it.
T0="$(date +%s.%N)"
stop_server
STOP_S="$(python3 -c "import sys,time; print(f'{time.time() - float(sys.argv[1]):.1f}')" "$T0")"
python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) < 12 else 1)" "$STOP_S" \
  || fail "shutdown with the collector paused took ${STOP_S} s"
echo "ok   shutdown with the collector paused took ${STOP_S} s (grace 5 s; bound checked: 12 s)"
docker unpause "$COLLECTOR" >/dev/null

say "collector notes"
docker logs "$COLLECTOR" 2>&1 | grep -oE '"otlp" alias is deprecated[^{]*' | sort -u || true
# The guide's metrics pipeline goes to the same exporter; Jaeger takes traces only.
docker logs "$COLLECTOR" 2>&1 | grep -oE 'unknown service opentelemetry\.proto\.collector\.metrics\.v1\.MetricsService' \
  | sort -u | sed 's/^/metrics pipeline to Jaeger: /' || true
echo "otel backend smoke test passed"
