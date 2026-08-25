#!/usr/bin/env bash

set -uo pipefail

RELEASE="ro"
NAMESPACE="rokh-oghab"
WORKLOAD_NS="execution"
WORKLOAD="sandbox"
PROFILE="untrusted-python"
APPLY="false"

while [ $# -gt 0 ]; do
    case "$1" in
        --release) RELEASE="$2"; shift 2 ;;
        --namespace) NAMESPACE="$2"; shift 2 ;;
        --workload-namespace) WORKLOAD_NS="$2"; shift 2 ;;
        --workload) WORKLOAD="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --apply) APPLY="true"; shift ;;
        -h|--help)
            sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

die() { printf '\033[31mro-onboard: %s\033[0m\n' "$1" >&2; exit 1; }
say() { printf '  %s\n' "$1"; }
ok()  { printf '  \033[32mok\033[0m    %s\n' "$1"; }

command -v kubectl >/dev/null 2>&1 || die "kubectl is not on PATH"
kubectl version -o json >/dev/null 2>&1 || die "kubectl cannot reach a cluster"

printf '\nOnboarding %s/%s onto Rokh Oghab\n' "$WORKLOAD_NS" "$WORKLOAD"
printf '%s\n\n' "======================================================================"

SECRET="$RELEASE-rokh-oghab-tokens"
kubectl -n "$NAMESPACE" get secret "$SECRET" >/dev/null 2>&1 \
    || SECRET="rokh-oghab-tokens"
kubectl -n "$NAMESPACE" get secret "$SECRET" >/dev/null 2>&1 \
    || die "cannot find the token secret in namespace $NAMESPACE"

OPERATOR="$(kubectl -n "$NAMESPACE" get secret "$SECRET" \
    -o jsonpath='{.data.operator}' 2>/dev/null | base64 -d 2>/dev/null || true)"
[ -n "$OPERATOR" ] || OPERATOR="$(kubectl -n "$NAMESPACE" get secret "$SECRET" \
    -o jsonpath='{.data.admin}' | base64 -d)"
[ -n "$OPERATOR" ] || die "the token secret holds no operator or admin token"
ok "read a control-plane token from $NAMESPACE/$SECRET"

CONTROLLER="$(kubectl -n "$NAMESPACE" get svc -l app.kubernetes.io/component=controller \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
[ -n "$CONTROLLER" ] || CONTROLLER="$RELEASE-rokh-oghab-controller"
PORT="$(kubectl -n "$NAMESPACE" get svc "$CONTROLLER" \
    -o jsonpath='{.spec.ports[0].port}' 2>/dev/null || echo 8081)"
ok "controller service: $CONTROLLER:$PORT"

GATEWAY="$(kubectl -n "$NAMESPACE" get svc -l app.kubernetes.io/component=gateway \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
[ -n "$GATEWAY" ] || GATEWAY="$RELEASE-rokh-oghab-gateway"
GATEWAY_IP="$(kubectl -n "$NAMESPACE" get svc "$GATEWAY" \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
PROXY_PORT="$(kubectl -n "$NAMESPACE" get svc "$GATEWAY" \
    -o jsonpath='{.spec.ports[?(@.name=="proxy")].port}' 2>/dev/null || echo 3128)"
[ -n "$GATEWAY_IP" ] || die "cannot read the gateway service address"
ok "gateway service: $GATEWAY_IP:$PROXY_PORT"

printf '\n  minting an identity for %s/%s (profile %s)\n' \
    "$WORKLOAD_NS" "$WORKLOAD" "$PROFILE"

PF_LOG="$(mktemp)"
kubectl -n "$NAMESPACE" port-forward "svc/$CONTROLLER" "$PORT:$PORT" \
    >"$PF_LOG" 2>&1 &
PF_PID=$!
trap 'kill "$PF_PID" 2>/dev/null; rm -f "$PF_LOG"' EXIT
for _ in $(seq 1 30); do
    curl -sf -o /dev/null "http://127.0.0.1:$PORT/healthz" 2>/dev/null && break
    sleep 0.5
done
curl -sf -o /dev/null "http://127.0.0.1:$PORT/healthz" 2>/dev/null \
    || die "the controller did not answer through the port-forward: $(cat "$PF_LOG")"

RESPONSE="$(curl -sS -X POST "http://127.0.0.1:$PORT/v1/identities/tokens" \
    -H "Authorization: Bearer $OPERATOR" \
    -H "Content-Type: application/json" \
    -d "{\"namespace\":\"$WORKLOAD_NS\",\"profile\":\"$PROFILE\",\"id\":\"$WORKLOAD\"}")"
TOKEN="$(printf '%s' "$RESPONSE" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
[ -n "$TOKEN" ] || die "could not mint a token: $RESPONSE"
ok "minted an identity for $WORKLOAD"

PUB="$(curl -sS -X POST "http://127.0.0.1:$PORT/v1/publish" \
    -H "Authorization: Bearer $OPERATOR" \
    -H "Content-Type: application/json" -d '{"note":"onboard"}')"
VERSION="$(printf '%s' "$PUB" | sed -n 's/.*"version":\([0-9]*\).*/\1/p')"
[ -n "$VERSION" ] || die "could not publish: $PUB"
ok "published version $VERSION"

kubectl get namespace "$WORKLOAD_NS" >/dev/null 2>&1 \
    || kubectl create namespace "$WORKLOAD_NS" >/dev/null
kubectl -n "$WORKLOAD_NS" create secret generic "$WORKLOAD-egress" \
    --from-literal=token="$TOKEN" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
ok "stored the token as secret $WORKLOAD_NS/$WORKLOAD-egress"

PROXY="http://$GATEWAY_IP:$PROXY_PORT"
DNS_IP="$GATEWAY_IP"

printf '\n%s\n' "======================================================================"
printf 'Add this to the pod spec of %s/%s:\n\n' "$WORKLOAD_NS" "$WORKLOAD"
cat <<SPEC
  dnsPolicy: None
  dnsConfig:
    nameservers: ["$DNS_IP"]
  containers:
    - name: <your container>
      env:
        - name: HTTP_PROXY
          value: $PROXY
        - name: HTTPS_PROXY
          value: $PROXY
        - name: NO_PROXY
          value: localhost,127.0.0.1
        - name: RO_TOKEN
          valueFrom:
            secretKeyRef:
              name: $WORKLOAD-egress
              key: token
SPEC
printf '\nThe token authenticates the workload to the gateway. A client sends it as\n'
printf 'Proxy-Authorization: Bearer \$RO_TOKEN.\n\n'

if [ "$APPLY" = "true" ]; then
    printf 'Applying a demonstration pod that proves it works:\n\n'
    kubectl -n "$WORKLOAD_NS" delete pod "$WORKLOAD-check" --ignore-not-found \
        >/dev/null 2>&1
    cat <<POD | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: $WORKLOAD-check
  namespace: $WORKLOAD_NS
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  dnsPolicy: None
  dnsConfig:
    nameservers: ["$DNS_IP"]
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: check
      image: curlimages/curl:8.10.1
      command: ["sh", "-c"]
      args:
        - |
          echo "through the gateway, a permitted destination:"
          curl -sS -o /dev/null -w "  %{http_code}\\n" --max-time 10 \\
            -x "\$HTTP_PROXY" -H "Proxy-Authorization: Bearer \$RO_TOKEN" \\
            https://pypi.org/simple/ || echo "  refused"
          echo "straight at the network, no gateway:"
          curl -sS -o /dev/null -w "  %{http_code}\\n" --max-time 6 \\
            --noproxy '*' https://example.com/ || echo "  no route, which is correct"
      env:
        - name: HTTP_PROXY
          value: $PROXY
        - name: HTTPS_PROXY
          value: $PROXY
        - name: RO_TOKEN
          valueFrom:
            secretKeyRef:
              name: $WORKLOAD-egress
              key: token
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
POD
    kubectl -n "$WORKLOAD_NS" wait --for=condition=Ready \
        "pod/$WORKLOAD-check" --timeout=90s >/dev/null 2>&1 || true
    sleep 12
    kubectl -n "$WORKLOAD_NS" logs "$WORKLOAD-check" 2>/dev/null \
        | sed 's/^/  /' || say "the pod produced no logs yet"
    printf '\n  kubectl -n %s delete pod %s-check   # when you are done\n\n' \
        "$WORKLOAD_NS" "$WORKLOAD"
fi
