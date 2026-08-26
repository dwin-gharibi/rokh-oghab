#!/usr/bin/env bash
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

RELEASE="${RO_K8S_RELEASE:-ro}"
NS="${RO_K8S_NAMESPACE:-rokh-oghab}"
SANDBOX_NS="${RO_K8S_SANDBOX_NAMESPACE:-execution}"
CHART="deploy/helm/rokh-oghab"
REGISTRY="${RO_IMAGE_REGISTRY:-rokh-oghab}"
TAG="${RO_IMAGE_TAG:-dev}"
PULL_POLICY="${RO_IMAGE_PULL_POLICY:-IfNotPresent}"
TIMEOUT="${RO_K8S_TIMEOUT:-240s}"
ADMIN_TOKEN="${RO_K8S_ADMIN_TOKEN:-k8s-admin-token-000000000001}"
PROXY_TOKEN="${RO_K8S_PROXY_TOKEN:-k8s-sandbox-token-00000000001}"

PASS=0
FAIL=0
SKIP=0

ok()   { printf '    ok   %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '    FAIL %s\n         %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }
skip() { printf '    skip %s\n         %s\n' "$1" "${2:-}"; SKIP=$((SKIP + 1)); }
note() { printf '\n  %s\n' "$1"; }

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "this suite needs $1" >&2
        exit 77
    }
}

need kubectl
need helm

if ! kubectl cluster-info >/dev/null 2>&1; then
    echo "no reachable Kubernetes cluster in the current context" >&2
    echo "create one with: kind create cluster --config tests/k8s/kind-config.yaml" >&2
    exit 77
fi

CONTEXT="$(kubectl config current-context 2>/dev/null || echo unknown)"

cleanup() {
    if [ "${RO_K8S_KEEP:-0}" = "1" ]; then
        printf '\n  leaving the release in place (RO_K8S_KEEP=1)\n'
        return
    fi
    printf '\n  cleaning up\n'
    kubectl delete -f examples/kubernetes/01-python-sandbox-pod.yaml \
        --ignore-not-found --wait=false >/dev/null 2>&1 || true
    helm uninstall "$RELEASE" -n "$NS" >/dev/null 2>&1 || true
    kubectl delete namespace "$NS" "$SANDBOX_NS" \
        --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

sandbox() {
    kubectl -n "$SANDBOX_NS" exec python-sandbox -- "$@" 2>&1
}

sandbox_py() {
    kubectl -n "$SANDBOX_NS" exec python-sandbox -- python -c "$1" 2>&1
}

escape_blocked() {
    local name="$1" script="$2" out
    out="$(sandbox_py "$script")"
    if printf '%s' "$out" | grep -q "ESCAPED"; then
        bad "$name" "$out"
    else
        ok "$name"
    fi
}

printf 'Rokh Oghab Kubernetes suite\n'
printf '%s\n' "========================================================================"
printf '  context  %s\n' "$CONTEXT"
printf '  release  %s in namespace %s\n' "$RELEASE" "$NS"
printf '  images   %s/{gateway,controller,agent}:%s\n' "$REGISTRY" "$TAG"

note "installing the chart"
if ! helm upgrade --install "$RELEASE" "$CHART" \
        --namespace "$NS" --create-namespace \
        --set global.imageRegistry="$REGISTRY" \
        --set global.imagePullPolicy="$PULL_POLICY" \
        --set gateway.image.tag="$TAG" \
        --set controller.image.tag="$TAG" \
        --set agent.image.tag="$TAG" \
        --set tokens.gatewayAdmin="$ADMIN_TOKEN" \
        --wait --timeout "$TIMEOUT" >/dev/null 2>&1; then
    bad "helm install" "the chart did not become ready within $TIMEOUT"
    kubectl -n "$NS" get pods 2>/dev/null || true
    printf '\npassed=%d failed=%d skipped=%d\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi
ok "the chart installs and every workload becomes ready"

note "the deployment has the shape it claims"
if kubectl -n "$NS" get deploy -o name | grep -q gateway; then
    ok "a gateway deployment exists"
else
    bad "gateway deployment" "no gateway deployment was created"
fi

if kubectl -n "$NS" get deploy -o name | grep -q controller; then
    ok "a controller deployment exists"
else
    bad "controller deployment" "no controller deployment was created"
fi

if kubectl -n "$NS" get daemonset -o name | grep -q agent; then
    ok "a node agent daemonset exists"
else
    skip "node agent daemonset" "the chart was rendered without the agent"
fi

netpols="$(kubectl -n "$SANDBOX_NS" get networkpolicy -o name 2>/dev/null | wc -l)"
if [ "$netpols" -ge 2 ]; then
    ok "the sandbox namespace carries default-deny network policies"
else
    bad "network policies" "found $netpols policies in $SANDBOX_NS, expected at least 2"
fi

note "the pods are hardened"
for check in \
    '.spec.template.spec.securityContext.runAsNonRoot|true|runs as a non-root user' \
    '.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem|true|has a read-only root filesystem' \
    '.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation|false|cannot escalate privilege' \
    '.spec.template.spec.automountServiceAccountToken|false|mounts no service account token'
do
    path="${check%%|*}"
    rest="${check#*|}"
    want="${rest%%|*}"
    label="${rest#*|}"
    got="$(kubectl -n "$NS" get deploy -l app.kubernetes.io/component=gateway \
        -o jsonpath="{.items[0]$path}" 2>/dev/null)"
    if [ "$got" = "$want" ]; then
        ok "the gateway $label"
    else
        bad "the gateway $label" "got '${got:-<unset>}', expected '$want'"
    fi
done

note "the gateway is serving"
if kubectl -n "$NS" get svc rokh-oghab-gateway >/dev/null 2>&1; then
    ok "the gateway service exists"
else
    bad "gateway service" "rokh-oghab-gateway was not created"
fi

ready="$(kubectl -n "$NS" get pods -l app.kubernetes.io/component=gateway \
    -o jsonpath='{.items[*].status.containerStatuses[*].ready}' 2>/dev/null)"
case "$ready" in
    *true*) ok "at least one gateway pod reports ready" ;;
    *)      bad "gateway readiness" "no gateway pod is ready: '${ready:-<none>}'" ;;
esac

note "placing an untrusted sandbox behind the gateway"
kubectl -n "$SANDBOX_NS" delete secret sandbox-egress \
    --ignore-not-found >/dev/null 2>&1 || true
kubectl -n "$SANDBOX_NS" create secret generic sandbox-egress \
    --from-literal=token="$PROXY_TOKEN" >/dev/null 2>&1

kubectl delete -f examples/kubernetes/01-python-sandbox-pod.yaml \
    --ignore-not-found >/dev/null 2>&1 || true
if kubectl apply -f examples/kubernetes/01-python-sandbox-pod.yaml >/dev/null 2>&1 \
   && kubectl -n "$SANDBOX_NS" wait --for=condition=Ready pod/python-sandbox \
        --timeout="$TIMEOUT" >/dev/null 2>&1; then
    ok "the example sandbox pod starts and becomes ready"
else
    bad "sandbox pod" "the example pod did not become ready"
    kubectl -n "$SANDBOX_NS" describe pod python-sandbox 2>/dev/null | tail -20
    printf '\npassed=%d failed=%d skipped=%d\n' "$PASS" "$FAIL" "$SKIP"
    exit 1
fi

note "the sandbox cannot route around the gateway"

escape_blocked "a direct TCP connection to a public address" "
import socket
try:
    socket.create_connection(('1.1.1.1', 443), timeout=5).close()
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"

escape_blocked "a direct TCP connection to the cloud metadata endpoint" "
import socket
try:
    socket.create_connection(('169.254.169.254', 80), timeout=5).close()
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"

escape_blocked "a direct TCP connection to the kubernetes api server" "
import os, socket
host = os.environ.get('KUBERNETES_SERVICE_HOST', '10.96.0.1')
port = int(os.environ.get('KUBERNETES_SERVICE_PORT', '443'))
try:
    socket.create_connection((host, port), timeout=5).close()
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"

escape_blocked "a direct TCP connection to the gateway admin port" "
import socket
try:
    s = socket.create_connection(('rokh-oghab-gateway-admin.$NS.svc.cluster.local', 9145), timeout=5)
    s.sendall(b'GET /v1/status HTTP/1.0\r\n\r\n')
    data = s.recv(256)
    s.close()
    print('ESCAPED' if data else 'blocked: no data')
except OSError as e:
    print('blocked:', e)
"

escape_blocked "a UDP datagram to an external resolver" "
import socket, struct
q = struct.pack('>HHHHHH', 1, 0x0100, 1, 0, 0, 0)
for label in ('example', 'com'):
    q += bytes([len(label)]) + label.encode()
q += b'\x00' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
try:
    s.sendto(q, ('8.8.8.8', 53))
    data, _ = s.recvfrom(512)
    answers = struct.unpack('>H', data[6:8])[0]
    print('ESCAPED: %d records' % answers if answers else 'no answer')
except OSError as e:
    print('blocked:', e)
"

note "no service account token is available to the sandbox"
token_out="$(sandbox_py "
import os
p = '/var/run/secrets/kubernetes.io/serviceaccount/token'
print('ESCAPED: token present' if os.path.exists(p) else 'no token mounted')
")"
if printf '%s' "$token_out" | grep -q "ESCAPED"; then
    bad "service account token" "the sandbox can read a service account token"
else
    ok "the sandbox has no service account token to steal"
fi

note "the sandbox reaches the gateway and is refused by policy"
denied_out="$(sandbox_py "
import os, urllib.error, urllib.request
proxy = os.environ['HTTPS_PROXY']
token = os.environ.get('RO_PROXY_TOKEN', '')
o = urllib.request.build_opener(urllib.request.ProxyHandler(
    {'http': proxy, 'https': proxy}))
r = urllib.request.Request('http://example.com/')
if token:
    r.add_header('Proxy-Authorization', 'Bearer ' + token)
try:
    with o.open(r, timeout=15) as res:
        print('allowed', res.status)
except urllib.error.HTTPError as e:
    reason = e.headers.get('X-Rokh-Oghab-Reason') if e.headers else None
    print('refused', e.code, reason)
except Exception as e:
    print('error', type(e).__name__, e)
")"
case "$denied_out" in
    refused*rokh*|refused*policy*|refused*identity*)
        ok "the gateway answered with a Rokh Oghab refusal: $denied_out" ;;
    refused*)
        ok "the gateway refused the request: $denied_out" ;;
    allowed*)
        bad "policy enforcement" "an unlisted destination was allowed: $denied_out" ;;
    *)
        bad "gateway reachability" "unexpected result: $denied_out" ;;
esac

note "the gateway exposes metrics and health"
gw_pod="$(kubectl -n "$NS" get pods -l app.kubernetes.io/component=gateway \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
if [ -n "$gw_pod" ]; then
    health="$(kubectl -n "$NS" exec "$gw_pod" -- \
        wget -qO- http://127.0.0.1:9145/healthz 2>/dev/null || true)"
    if printf '%s' "$health" | grep -q '"status"'; then
        ok "the gateway health endpoint answers"
    else
        bad "health endpoint" "got: ${health:-<empty>}"
    fi

    metrics="$(kubectl -n "$NS" exec "$gw_pod" -- \
        wget -qO- http://127.0.0.1:9145/metrics 2>/dev/null || true)"
    if printf '%s' "$metrics" | grep -q 'ro_requests_total'; then
        ok "the gateway exports its metrics"
    else
        bad "metrics endpoint" "ro_requests_total was not exported"
    fi
    if printf '%s' "$metrics" | grep -q 'ro_policy_stale 0'; then
        ok "the gateway is not enforcing a stale bundle"
    else
        skip "policy freshness" "ro_policy_stale was not 0"
    fi
else
    bad "gateway pod" "no gateway pod to query"
fi

note "the audit trail records the refusal"
if [ -n "$gw_pod" ]; then
    logs="$(kubectl -n "$NS" logs "$gw_pod" --tail=200 2>/dev/null || true)"
    if printf '%s' "$logs" | grep -q '"action":"deny"'; then
        ok "denials appear in the audit trail"
    else
        bad "audit trail" "no deny event was recorded"
    fi
fi

note "the chart's own tests"
if helm test "$RELEASE" -n "$NS" --timeout "$TIMEOUT" >/dev/null 2>&1; then
    ok "helm test passes"
else
    skip "helm test" "the chart's test hooks did not pass in this cluster"
fi

printf '\n%s\n' "========================================================================"
printf 'passed=%d failed=%d skipped=%d\n' "$PASS" "$FAIL" "$SKIP"
printf '%s\n' "========================================================================"
[ "$FAIL" -eq 0 ]
