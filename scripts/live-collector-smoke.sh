#!/usr/bin/env bash
# The observability guide's collector configuration, run against a real OpenTelemetry Collector.
#
#   scripts/live-collector-smoke.sh
#
# Takes the collector YAML and the `[telemetry]` TOML out of docs/guides/observability.md as
# they stand, so the guide is what is tested. Checks the YAML with the collector's own
# `validate`, then runs the collector (pinned image, host network) with that YAML plus one
# `debug` exporter added to both pipelines, so the spans and the scraped metrics show in the
# collector's log. Starts attenuo-server with the guide's `[telemetry]` block and `[metrics]`
# on the guide's ports (OTLP/HTTP 127.0.0.1:4318, metrics 127.0.0.1:9100), a small upstream
# that records the headers it gets, and drives a root token, an exchange, an allowed call, a
# denied call and a call carrying a W3C `traceparent`. Then reads the collector's output and
# checks: the span names and attributes the guide lists, integer types for the numeric ones,
# the caller's trace linked and not adopted, attenuo's own `traceparent` on the upstream
# request naming the `attenuo.upstream` span, no token, subject, argument, secret or upstream
# URL in any exported span, and the scraped `/metrics` series.
#
# Not part of CI. Needs docker (the daemon running), curl and python3, and free ports 4318 and
# 9100 on 127.0.0.1. Skips with exit status 0 when docker is not available. Nothing leaves the
# machine except the image pull: the guide's `otlp` exporter points at `your-backend:4317`,
# which does not resolve, and the collector logs that it cannot export there.
#
# Environment:
#   COLLECTOR_IMAGE      collector image (default: the pinned contrib 0.165.0 digest below)
#   ATTENUO_BIN_DIR=DIR  prebuilt attenuo-server, attenuo (default: cargo build)
#   KEEP=1               keep the temp dir (collector log, server log, config)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# otel/opentelemetry-collector-contrib:0.165.0, pulled 2026-11-14.
COLLECTOR_IMAGE="${COLLECTOR_IMAGE:-otel/opentelemetry-collector-contrib@sha256:e40d61f10c9a617cca1ffd1be4d7e2b3a4b0f0001798ff07e58cabe82e618cea}"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "skip: docker is not available (no client, or the daemon is not running)"
  exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/attenuo-collector-smoke.XXXXXX")"
CONTAINER="attenuo-collector-smoke-$$"
PIDS=()
export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}"
export no_proxy="$NO_PROXY"

cleanup() {
  local rc=$?
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  docker logs "$CONTAINER" > "$WORK/collector.log" 2>&1 || true
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [ "$rc" -ne 0 ]; then
    echo >&2
    echo "collector smoke test failed (exit $rc). Last server and collector log lines:" >&2
    tail -n 10 "$WORK/server.log" 2>/dev/null >&2 || true
    grep -iE 'error|warn' "$WORK/collector.log" 2>/dev/null | tail -n 10 >&2 || true
  fi
  if [ "${KEEP:-0}" = 1 ]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

say() { printf '\n== %s\n' "$*"; }
fail() { echo "!! $*" >&2; exit 1; }

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for p in 4318 9100; do
  port_busy "$p" && fail "127.0.0.1:$p is in use; the guide's configuration needs it"
done

if [ -n "${ATTENUO_BIN_DIR:-}" ]; then
  BIN="$ATTENUO_BIN_DIR"
else
  echo "building..." >&2
  cargo build -q -p attenuo-server -p attenuo-cli
  BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
fi
CLI="$BIN/attenuo"

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

# --- the guide's two snippets, as they stand -------------------------------------------------
GUIDE=docs/guides/observability.md
python3 - "$GUIDE" "$WORK" <<'EOF'
import re, sys
text = open(sys.argv[1]).read()
blocks = re.findall(r"```(yaml|toml)\n(.*?)```", text, re.S)
yaml = [b for t, b in blocks if t == "yaml"]
toml = [b for t, b in blocks if t == "toml" and "[telemetry]" in b]
assert yaml and toml, "guide has no collector YAML or [telemetry] TOML block"
open(sys.argv[2] + "/guide.yaml", "w").write(yaml[0])
open(sys.argv[2] + "/telemetry.toml", "w").write(toml[0])
# The same YAML with a debug exporter in both pipelines: the only change.
out, added = [], False
for line in yaml[0].splitlines():
    m = re.match(r"(\s*exporters: \[)(.*)\]\s*$", line)
    if m:
        line = f"{m.group(1)}{m.group(2)}, debug]"
    out.append(line)
    if line == "exporters:" and not added:
        out += ["  debug:", "    verbosity: detailed"]
        added = True
assert added, "no top-level exporters: in the guide's YAML"
open(sys.argv[2] + "/collector.yaml", "w").write("\n".join(out) + "\n")
EOF

say "collector: $COLLECTOR_IMAGE"
docker run --rm "$COLLECTOR_IMAGE" --version
say "the guide's YAML, unchanged, through the collector's validate"
docker run --rm --network host -v "$WORK/guide.yaml:/guide.yaml:ro" "$COLLECTOR_IMAGE" \
  validate --config /guide.yaml || fail "the collector rejects the guide's configuration"

docker run -d --name "$CONTAINER" --network host -v "$WORK/collector.yaml:/c.yaml:ro" \
  "$COLLECTOR_IMAGE" --config /c.yaml >/dev/null
for _ in $(seq 1 100); do
  docker logs "$CONTAINER" 2>&1 | grep -q 'Everything is ready' && break
  sleep 0.2
done
docker logs "$CONTAINER" 2>&1 | grep -q 'Everything is ready' || fail "the collector did not start"

# --- an upstream that records each request's headers -----------------------------------------
UP_PORT="$(free_port)"; OB_PORT="$(free_port)"
cat > "$WORK/upstream.py" <<'EOF'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
log = open(sys.argv[2], "a")
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        log.write(json.dumps({"method": body.get("method"),
                              "traceparent": self.headers.get_all("traceparent") or []}) + "\n")
        log.flush()
        out = json.dumps({"jsonrpc": "2.0", "id": body.get("id"),
                          "result": {"content": [{"type": "text", "text": "ok"}],
                                     "isError": False}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
EOF
python3 "$WORK/upstream.py" "$UP_PORT" "$WORK/upstream.jsonl" &
PIDS+=($!)

# --- attenuo-server: the leak demo's config, the guide's [telemetry], and [metrics] ----------
sed -e "s#examples/github-leak-demo/policy.cedar#$ROOT/examples/github-leak-demo/policy.cedar#" \
    -e "s/18080/$OB_PORT/g" -e "s#http://127.0.0.1:13001/mcp#http://127.0.0.1:$UP_PORT/mcp#" \
    examples/github-leak-demo/config.toml > "$WORK/config.toml"
{ echo; cat "$WORK/telemetry.toml"; printf '\n[metrics]\nenabled = true\nlisten = "127.0.0.1:9100"\n'; } \
  >> "$WORK/config.toml"
# The guide samples 10 % of traces; every trace here, through the documented override.
OTEL_TRACES_SAMPLER_ARG=1 RUST_LOG=warn "$BIN/attenuo-server" --config "$WORK/config.toml" \
  > "$WORK/server.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 100); do
  curl -sf "http://127.0.0.1:$OB_PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -sf "http://127.0.0.1:$OB_PORT/healthz" >/dev/null || fail "server did not start"

export ATTENUO_SERVER="http://127.0.0.1:$OB_PORT" ATTENUO_ADMIN_TOKEN="demo-admin-token"
unset ATTENUO_TOKEN ATTENUO_CLIENT_SECRET
token_of() { sed -n -E 's/^token +([^ ]+).*/\1/p' | head -n1; }

say "decisions"
ROOT_TOKEN="$("$CLI" token root --subject alice --agent assistant --cap 'github:*' | token_of)"
[ -n "$ROOT_TOKEN" ] || fail "no root token"
CODER="$(printf 'demo-coder-secret\n' | ATTENUO_TOKEN="$ROOT_TOKEN" \
  "$CLI" token exchange --actor coder --client-secret-stdin --cap github:read_file | token_of)"
[ -n "$CODER" ] || fail "no exchanged token"
ATTENUO_TOKEN="$CODER" "$CLI" call --upstream github --tool read_file \
  --arg repo=alice/public-docs --arg path=README.md | head -n1
ATTENUO_TOKEN="$CODER" "$CLI" call --upstream github --tool create_issue \
  --arg repo=alice/public-docs --arg title=leak | head -n1 || true
CALLER_TRACE=4bf92f3577b34da6a3ce929d0e0e4736 CALLER_SPAN=00f067aa0ba902b7
ARG_MARKER="ARGVALUE-must-not-be-exported"
curl -sS -o /dev/null -w 'traceparent call: HTTP %{http_code}\n' "$ATTENUO_SERVER/mcp/github" \
  -H "Authorization: Bearer $CODER" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H "traceparent: 00-$CALLER_TRACE-$CALLER_SPAN-01" \
  -d '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"alice/public-docs","path":"'"$ARG_MARKER"'"}}}'

say "waiting for the spans and a scrape (scrape_interval 15s)"
for _ in $(seq 1 60); do
  docker logs "$CONTAINER" > "$WORK/collector.log" 2>&1
  grep -q 'Name *: attenuo.record_result' "$WORK/collector.log" \
    && grep -q 'attenuo_decisions_total' "$WORK/collector.log" && break
  sleep 1
done

say "checks"
python3 - "$WORK/collector.log" "$WORK/upstream.jsonl" "$CALLER_TRACE" "$CALLER_SPAN" \
  "$ROOT_TOKEN" "$CODER" "$ARG_MARKER" "127.0.0.1:$UP_PORT" <<'EOF'
import json, re, sys
log, upstream, caller_trace, caller_span, root, coder, marker, up_url = sys.argv[1:]
text = open(log).read()
failed = []
def check(ok, what):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok: failed.append(what)

# Parse the debug exporter's span blocks.
spans = []
for block in re.split(r"\nSpan #\d+\n", text)[1:]:
    block = block.split("\nScopeSpans #")[0].split("\nResourceSpans #")[0]
    s = {"attrs": {}, "links": []}
    for k in ("Trace ID", "Parent ID", "ID", "Name", "Kind"):
        m = re.search(rf"^\s+{k}\s+: ?(.*)$", block, re.M)
        s[k] = m.group(1).strip() if m else ""
    attrs = block.split("Attributes:")[1].split("Links:")[0] if "Attributes:" in block else ""
    for m in re.finditer(r"-> ([\w.]+): (\w+)\((.*)\)", attrs):
        s["attrs"][m.group(1)] = (m.group(2), m.group(3))
    if "Links:" in block:
        for m in re.finditer(r"-> Trace ID: (\w+)\n\s+-> ID: (\w+)", block.split("Links:")[1]):
            s["links"].append((m.group(1), m.group(2)))
    spans.append(s)
names = {s["Name"] for s in spans}
print(f"{len(spans)} spans: {', '.join(sorted(names))}")

check("service.name: Str(attenuo-server)" in text, "resource service.name = attenuo-server")
check("deployment.environment: Str(staging)" in text, "resource attribute from resource_attributes")
for n in ["mcp.request", "attenuo.authenticate", "attenuo.session_gate", "attenuo.decide",
          "attenuo.lease_check", "attenuo.run_state", "attenuo.policy", "attenuo.audit_append",
          "attenuo.upstream", "attenuo.response", "attenuo.record_result", "attenuo.token.exchange"]:
    check(n in names, f"span {n} exported")
allowed = {"http.request.method", "http.route", "http.response.status_code", "attenuo.server",
           "attenuo.session_tag", "attenuo.chain_id", "attenuo.chain_depth", "attenuo.dpop_bound",
           "attenuo.token.cache", "attenuo.reason", "attenuo.tool", "attenuo.decision",
           "attenuo.decision_id", "attenuo.audit.seq", "attenuo.policy_ids", "attenuo.tainted",
           "attenuo.subject_digest", "attenuo.limit.kind", "attenuo.budget.exhausted_at",
           "attenuo.result.label"}
extra = {k for s in spans for k in s["attrs"]} - allowed
check(not extra, f"every attribute is on the guide's list (extra: {sorted(extra)})")
ints = {"http.response.status_code", "attenuo.chain_depth", "attenuo.audit.seq"}
bad = {(s["Name"], k, t) for s in spans for k, (t, _) in s["attrs"].items() if k in ints and t != "Int"}
check(not bad, f"numeric attributes are Int ({sorted(bad)})")
decides = [s for s in spans if s["Name"] == "attenuo.decide"]
check({s["attrs"].get("attenuo.decision", ("", ""))[1] for s in decides} >= {"allow", "deny"},
      "attenuo.decide for an allow and a deny")
check(all(set(s["attrs"]) >= {"attenuo.tool", "attenuo.decision_id", "attenuo.audit.seq",
                              "attenuo.subject_digest"} for s in decides),
      "attenuo.decide carries tool, decision_id, audit.seq, subject_digest")
check(all(re.fullmatch(r"[0-9a-f]{16}", s["attrs"]["attenuo.subject_digest"][1]) for s in decides),
      "subject exported only as a 16-hex digest")

linked = [s for s in spans if s["Name"] == "mcp.request" and (caller_trace, caller_span) in s["links"]]
check(len(linked) == 1, "the caller's traceparent is a span link on mcp.request")
check(bool(linked) and linked[0]["Trace ID"] != caller_trace and linked[0]["Parent ID"] == "",
      "the caller's trace id is not adopted (inbound_mcp = link)")
check(caller_trace not in {s["Trace ID"] for s in spans}, "no exported span is in the caller's trace")

ups = [s for s in spans if s["Name"] == "attenuo.upstream"]
sent = [json.loads(l) for l in open(upstream)]
calls = [r for r in sent if r["method"] == "tools/call"]
want = {f"00-{s['Trace ID']}-{s['ID']}-01" for s in ups}
got = [tp for r in calls for tp in r["traceparent"]]
check(len(calls) == 2 and all(len(r["traceparent"]) == 1 for r in calls),
      "each upstream tools/call carried exactly one traceparent")
check(set(got) == want, "the upstream traceparent names the attenuo.upstream span")
check(not any(caller_trace in tp for tp in got), "the caller's traceparent is not forwarded")

span_text = "".join(re.findall(r"Span #\d+\n.*?(?=\nSpan #|\nResourceSpans|\nResourceMetrics|\Z)", text, re.S))
check("attenuo.subject_digest" in span_text, "the span text searched below holds the spans")
for label, secret in [("root token", root[:40]), ("exchanged token", coder[:40]), ("a JWT", "eyJ"),
                      ("subject", "alice"), ("argument value", marker), ("argument", "public-docs"),
                      ("agent secret", "demo-coder-secret"), ("admin token", "demo-admin-token"),
                      ("upstream URL", up_url), ("Bearer", "Bearer")]:
    check(secret not in span_text, f"no {label} in any exported span")

for series in ["attenuo_decisions_total", "attenuo_telemetry_spans_dropped_total",
               "attenuo_telemetry_export_failures_total"]:
    check(f"-> Name: {series}" in text, f"metric {series} scraped from [metrics] listen")
sys.exit(1 if failed else 0)
EOF

say "collector notes"
grep -oE '"otlp" alias is deprecated[^{]*' "$WORK/collector.log" | sort -u || true
echo "collector smoke test passed"
