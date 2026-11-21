#!/usr/bin/env bash
# Test the Helm chart (deploy/helm/attenuo).
#
#   scripts/helm-smoke.sh --template     chart checks that need no cluster
#   scripts/helm-smoke.sh                the same, then install into the cluster of the
#                                        current kubectl context and play a scenario
#
# Template checks (need `helm`): `helm lint`, a render with the test values, a render with
# every optional part on, and each value the chart must refuse (no publicUrl, an http://
# publicUrl without allowInsecureHttp, no config, no policy, config together with
# existingConfigSecret, an access mode that is not ReadWriteOnce). They also check what the
# rendered Deployment must always say: one replica, strategy Recreate, a non-root user, a
# read-only root filesystem, no service account token, and no admin port on the Service or
# the Ingress.
#
# Cluster test (needs `helm`, `kubectl` and a cluster; CI uses kind): a fake GitHub MCP server
# (examples/github-leak-demo/fake_github_mcp.py, in the stock Python image) and the chart
# with the demo config in a namespace of its own. Then, with the `attenuo` CLI inside the
# pod: mint a root token, exchange it, one allowed call and one denied call through the
# proxy, and `audit verify`. Then the pod is deleted, and the test checks that the new pod
# still verifies the token minted before (the signing key is on the data volume), still
# allows the call, and has the earlier audit entries in a chain that verifies. Last, a
# changed config rolls the pod.
#
# Environment: ATTENUO_IMAGE_REPOSITORY and ATTENUO_IMAGE_TAG choose the image (default: the
# chart's, ghcr.io/attenuo-dev/attenuo at the chart's appVersion); NAMESPACE (default
# attenuo-smoke); KEEP=1 leaves the namespace in place afterwards.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
chart="$root/deploy/helm/attenuo"
ns="${NAMESPACE:-attenuo-smoke}"
release=smoke
deploy="deploy/$release-attenuo"

say() { printf '\n== %s\n' "$*"; }
fail() {
    echo "FAIL: $*" >&2
    exit 1
}

base_values=(
    --set publicUrl=http://attenuo.test
    --set allowInsecureHttp=true
    --set-file "config=$chart/ci/kind-config.toml"
    --set-file "policy=$root/examples/github-leak-demo/policy.cedar"
    --set adminToken.existingSecret=attenuo-admin
)

# ---------------------------------------------------------------- template checks

say "helm lint"
helm lint "$chart" "${base_values[@]}" >/dev/null || fail "helm lint"

say "render with the test values"
out=$(helm template "$release" "$chart" --kube-version 1.30.0 "${base_values[@]}")
has() { grep -qF -- "$1" <<<"$out" || fail "the render lacks: $1"; }
lacks() { if grep -qF -- "$1" <<<"$out"; then fail "the render has: $1"; fi; }
has "replicas: 1"
has "type: Recreate"
has "runAsNonRoot: true"
has "readOnlyRootFilesystem: true"
has "automountServiceAccountToken: false"
has "terminationGracePeriodSeconds: 35"
has "failureThreshold: 150"
# The admin API is on loopback in the pod unless its Service is on.
has 'value: "127.0.0.1:9102"'
lacks "0.0.0.0:9102"
has "helm.sh/resource-policy: keep"
has "path: /readyz"
has "name: ATTENUO_ADMIN_TOKEN"
has "value: /var/lib/attenuo/data/issuer.pem"
lacks "kind: Ingress"
lacks "$release-attenuo-admin"
lacks "name: metrics"
# The Service carries the main port only.
svc=$(awk '/^kind: Service$/,/^---$/' <<<"$out")
[ -n "$svc" ] || fail "no Service in the render"
if grep -q "9102\|targetPort: admin" <<<"$svc"; then fail "the Service exposes the admin port"; fi

say "render with every optional part on"
out=$(helm template "$release" "$chart" --kube-version 1.30.0 "${base_values[@]}" \
    --set publicUrl=https://attenuo.example.com --set allowInsecureHttp=false \
    --set issuerKey.existingSecret=attenuo-issuer \
    --set admin.service.enabled=true --set metrics.enabled=true \
    --set persistence.existingClaim=my-claim --set service.type=LoadBalancer \
    --set 'extraVolumes[0].name=ca' --set 'extraVolumes[0].secret.secretName=my-ca' \
    --set 'extraVolumeMounts[0].name=ca' --set 'extraVolumeMounts[0].mountPath=/etc/attenuo/ca' \
    --set ingress.enabled=true --set ingress.className=nginx \
    --set 'ingress.hosts[0].host=attenuo.example.com' \
    --set 'extraEnv[0].name=ATTENUO__LIMITS__MAX_IN_FLIGHT' --set-string 'extraEnv[0].value=64')
has "kind: Ingress"
has "$release-attenuo-admin"
has "$release-attenuo-metrics"
has 'value: "0.0.0.0:9102"'
has "secretName: my-ca"
has "mountPath: /etc/attenuo/ca"
has "value: /etc/attenuo/issuer/issuer.pem"
has "claimName: my-claim"
has "ATTENUO__METRICS__ENABLED"
has "ATTENUO__LIMITS__MAX_IN_FLIGHT"
lacks "kind: PersistentVolumeClaim"
lacks "ALLOW_INSECURE_HTTP"
ing=$(awk '/^kind: Ingress$/,/^---$/' <<<"$out")
[ -n "$ing" ] || fail "no Ingress in the render"
# A host given without paths gets "/".
grep -qF 'path: "/"' <<<"$ing" || fail "the Ingress host has no path"
# The main Service is a LoadBalancer here. The metrics and admin ports have no
# authentication of that kind to rely on, so neither may be on it.
lb=$(awk -v RS='---\n' '/type: LoadBalancer/' <<<"$out")
[ -n "$lb" ] || fail "no LoadBalancer Service in the render"
if grep -q "metrics\|9100\|9102" <<<"$lb"; then fail "the LoadBalancer Service carries the metrics or admin port"; fi
if grep -q "name: admin\|9102\|attenuo-admin" <<<"$ing"; then fail "the Ingress routes to the admin port"; fi

say "values the chart refuses"
refuses() { # <what the message must contain> <helm arguments...>
    local want=$1 err
    shift
    if err=$(helm template "$release" "$chart" --kube-version 1.30.0 "$@" 2>&1); then
        fail "rendered, but must be refused: $*"
    fi
    grep -qF -- "$want" <<<"$err" || fail "expected \"$want\" for: $*; got: $err"
}
refuses "publicUrl is required" --set-file "config=$chart/ci/kind-config.toml" --set policy=x
refuses "cleartext" --set publicUrl=http://attenuo.example.com --set config=x --set policy=x
refuses "must start with https://" --set publicUrl=attenuo.example.com --set config=x --set policy=x
refuses "config is required" --set publicUrl=https://a.example --set policy=x
refuses "policy is required" --set publicUrl=https://a.example --set config=x
refuses "not both" --set publicUrl=https://a.example --set config=x --set existingConfigSecret=s --set policy=x
refuses "not both" --set publicUrl=https://a.example --set config=x --set policy=x --set existingPolicyConfigMap=c
refuses "ReadWriteOnce" --set publicUrl=https://a.example --set config=x --set policy=x \
    --set 'persistence.accessModes[0]=ReadWriteMany'
echo "template checks passed"

if [ "${1:-}" = "--template" ]; then
    exit 0
fi

# ---------------------------------------------------------------- cluster test

image_args=()
[ -n "${ATTENUO_IMAGE_REPOSITORY:-}" ] && image_args+=(--set "image.repository=$ATTENUO_IMAGE_REPOSITORY")
[ -n "${ATTENUO_IMAGE_TAG:-}" ] && image_args+=(--set "image.tag=$ATTENUO_IMAGE_TAG")

created=0
changed_config=$(mktemp)
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        echo "---- pods" >&2
        kubectl -n "$ns" get pods -o wide >&2 || true
        echo "---- describe" >&2
        kubectl -n "$ns" describe "$deploy" >&2 || true
        kubectl -n "$ns" describe pods -l app.kubernetes.io/name=attenuo >&2 || true
        echo "---- logs" >&2
        kubectl -n "$ns" logs "$deploy" --tail=80 >&2 || true
    fi
    rm -f "$changed_config"
    # Only a namespace this run created is deleted.
    if [ "$created" = "1" ] && [ "${KEEP:-}" != "1" ]; then
        kubectl delete namespace "$ns" --wait=false >/dev/null 2>&1 || true
    fi
    exit "$status"
}
trap cleanup EXIT

say "namespace, admin token, fake MCP server"
kubectl create namespace "$ns" || fail "could not create the namespace $ns (if it exists, it is not this test's: choose another with NAMESPACE)"
created=1
admin_token=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
kubectl -n "$ns" create secret generic attenuo-admin --from-literal=admin-token="$admin_token"
kubectl -n "$ns" create configmap fake-mcp --from-file="$root/examples/github-leak-demo/fake_github_mcp.py"
kubectl -n "$ns" apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fake-mcp
spec:
  replicas: 1
  selector:
    matchLabels: {app: fake-mcp}
  template:
    metadata:
      labels: {app: fake-mcp}
    spec:
      containers:
        - name: fake-mcp
          image: python:3.12-slim
          command: ["python3", "-u", "/srv/fake_github_mcp.py", "--host", "0.0.0.0", "--port", "3001"]
          ports: [{containerPort: 3001}]
          volumeMounts: [{name: script, mountPath: /srv, readOnly: true}]
      volumes:
        - name: script
          configMap: {name: fake-mcp}
---
apiVersion: v1
kind: Service
metadata:
  name: fake-mcp
spec:
  selector: {app: fake-mcp}
  ports: [{port: 3001, targetPort: 3001}]
YAML
kubectl -n "$ns" rollout status deploy/fake-mcp --timeout=180s

say "helm install"
helm install "$release" "$chart" -n "$ns" "${base_values[@]}" "${image_args[@]}" --wait --timeout 240s
kubectl -n "$ns" rollout status "$deploy" --timeout=120s

MAIN=http://127.0.0.1:8080
ADMIN=http://127.0.0.1:9102
# Run the CLI inside the pod. Secrets go in on stdin, never on a command line.
cli() { kubectl -n "$ns" exec -i "$deploy" -- attenuo "$@"; }
admin_cli() {
    printf '%s\n' "$admin_token" | kubectl -n "$ns" exec -i "$deploy" -- attenuo --server "$ADMIN" --admin-token-stdin "$@"
}
call_with() { # <token> <arguments of `attenuo call`...>
    local t=$1
    shift
    printf '%s\n' "$t" | kubectl -n "$ns" exec -i "$deploy" -- attenuo --server "$MAIN" call --token - "$@"
}
verify_token() { # <token>: signature, issuer, audience and chain against the pod's JWKS
    printf '%s\n' "$1" | kubectl -n "$ns" exec -i "$deploy" -- attenuo --server "$MAIN" token inspect - --verify
}

say "the pod runs as the chart says"
uid=$(kubectl -n "$ns" exec "$deploy" -- id -u)
[ "$uid" = "10001" ] || fail "the container runs as uid $uid"
ro=$(kubectl -n "$ns" exec "$deploy" -- sh -c 'if touch /tmp/x 2>/dev/null; then echo writable; else echo read-only; fi')
[ "$ro" = "read-only" ] || fail "the root filesystem is: $ro"
# The admin API answers on loopback in the pod and not on the pod's address.
pod_ip=$(kubectl -n "$ns" get pods -l app.kubernetes.io/name=attenuo -o jsonpath='{.items[0].status.podIP}')
[ -n "$pod_ip" ] || fail "no pod address"
if printf '%s\n' "$admin_token" | kubectl -n "$ns" exec -i "$deploy" -- attenuo --server "http://$pod_ip:9102" --admin-token-stdin audit verify >/dev/null 2>&1; then
    fail "the admin API answers on the pod's address"
fi
if kubectl -n "$ns" exec "$deploy" -- test -e /var/run/secrets/kubernetes.io/serviceaccount/token; then
    fail "a service account token is mounted"
fi
cli --server "$MAIN" health --ready

say "mint, exchange, one allowed and one denied call"
root_token=$(admin_cli token root --subject alice --agent assistant --cap 'github:*' --print token)
[ -n "$root_token" ] || fail "no root token"
coder=$(printf '%s\n%s\n' "$root_token" demo-coder-secret | kubectl -n "$ns" exec -i "$deploy" -- sh -c \
    'read -r t; ATTENUO_TOKEN="$t" exec attenuo --server '"$MAIN"' token exchange --actor coder --client-secret-stdin --cap github:read_file --print token')
[ -n "$coder" ] || fail "no token for coder"
allowed=$(call_with "$coder" --upstream github --tool read_file --arg repo=alice/public-docs --arg path=README.md)
grep -q "^ALLOWED" <<<"$allowed" || fail "the public read was not allowed: $allowed"
set +e
denied=$(call_with "$coder" --upstream github --tool read_file --arg repo=alice/private-salaries --arg path=x 2>&1)
status=$?
set -e
[ "$status" -ne 0 ] || fail "the private read was allowed"
grep -q "policy_deny" <<<"$denied" || fail "the private read was not denied by policy: $denied"
reached=$(kubectl -n "$ns" logs deploy/fake-mcp | grep -c "tools/call read_file" || true)
[ "$reached" = "1" ] || fail "the fake MCP server saw $reached read_file calls, expected 1"
admin_cli audit verify
entries_before=$(admin_cli --json audit verify | sed -n 's/.*"entries": *\([0-9]*\).*/\1/p' | head -1)
[ -n "$entries_before" ] || fail "could not read the audit count"
verify_token "$coder" >/dev/null || fail "the new token does not verify"
echo "audit entries: $entries_before"

say "delete the pod: the data volume keeps the key and the log"
# The one pod that is not $1, once it is Ready.
ready_pod_other_than() {
    local old=$1 name i
    for i in $(seq 1 60); do
        name=$(kubectl -n "$ns" get pods -l app.kubernetes.io/name=attenuo \
            -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep -vx "$old" | head -1 || true)
        if [ -n "$name" ] && kubectl -n "$ns" wait --for=condition=Ready "pod/$name" --timeout=5s >/dev/null 2>&1; then
            echo "$name"
            return 0
        fi
        sleep 2
    done
    return 1
}
old_pod=$(kubectl -n "$ns" get pods -l app.kubernetes.io/name=attenuo -o jsonpath='{.items[0].metadata.name}')
kubectl -n "$ns" delete pod "$old_pod" --wait=true
new_pod=$(ready_pod_other_than "$old_pod") || fail "no new pod became ready after the old one was deleted"
# Signed with the same key, so the old token still verifies and is still accepted.
verify_token "$coder" >/dev/null || fail "the token minted before the restart no longer verifies"
allowed=$(call_with "$coder" --upstream github --tool read_file --arg repo=alice/public-docs --arg path=README.md)
grep -q "^ALLOWED" <<<"$allowed" || fail "the call after the restart was not allowed: $allowed"
admin_cli audit verify
entries_after=$(admin_cli --json audit verify | sed -n 's/.*"entries": *\([0-9]*\).*/\1/p' | head -1)
[ "$entries_after" -gt "$entries_before" ] || fail "the audit log did not survive the restart ($entries_before before, $entries_after after)"
echo "audit entries after the restart: $entries_after"

say "a changed config rolls the pod"
sed 's/audience = "attenuo"/audience = "attenuo-2"/' "$chart/ci/kind-config.toml" >"$changed_config"
helm upgrade "$release" "$chart" -n "$ns" "${base_values[@]}" "${image_args[@]}" \
    --set-file "config=$changed_config" --wait --timeout 240s
ready_pod_other_than "$new_pod" >/dev/null || fail "the pod was not rolled after the config changed"
cli --server "$MAIN" health --ready
admin_cli audit verify

echo
echo "helm-smoke: all checks passed"
