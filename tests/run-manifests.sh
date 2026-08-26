#!/usr/bin/env bash
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

K8S_VERSION="${RO_K8S_VERSION:-1.31.0}"
CHART="deploy/helm/rokh-oghab"
BASE="deploy/kubernetes/base"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()  { printf '    ok   %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '    FAIL %s\n         %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }

have() { command -v "$1" >/dev/null 2>&1; }

printf 'Rokh Oghab manifest suite\n'
printf '%s\n' "======================================================================"

if ! have kubeconform; then
    echo "kubeconform is not installed; skipping schema validation" >&2
    exit 77
fi

printf '\n  kustomize base\n'
if have kubectl; then
    if kubectl kustomize "$BASE" > "$WORK/base.yaml" 2>"$WORK/err"; then
        ok "the base renders"
        if kubeconform -strict -summary -kubernetes-version "$K8S_VERSION" \
            -ignore-missing-schemas "$WORK/base.yaml" >/dev/null 2>&1; then
            ok "the base validates against Kubernetes $K8S_VERSION"
        else
            bad "base schema validation" "$(kubeconform -strict -kubernetes-version "$K8S_VERSION" "$WORK/base.yaml" 2>&1 | head -3)"
        fi
        for ns in rokh-oghab execution; do
            if grep -q "name: $ns" "$WORK/base.yaml"; then
                ok "the $ns namespace survives the transformers"
            else
                bad "$ns namespace" "it was not rendered"
            fi
        done
        if grep -q "policyTypes" "$WORK/base.yaml"; then
            ok "network policies are part of the base"
        else
            bad "network policies" "none were rendered"
        fi
    else
        bad "kustomize build" "$(head -2 "$WORK/err")"
    fi
else
    echo "    skip kubectl is not installed"
fi

printf '\n  helm chart\n'
if have helm; then
    if helm lint "$CHART" >/dev/null 2>&1; then
        ok "the chart lints"
    else
        bad "helm lint" "$(helm lint "$CHART" 2>&1 | tail -3)"
    fi

    render() {
        local name="$1"; shift
        if helm template ro "$CHART" "$@" > "$WORK/$name.yaml" 2>"$WORK/err"; then
            if kubeconform -strict -summary -kubernetes-version "$K8S_VERSION" \
                -ignore-missing-schemas "$WORK/$name.yaml" >/dev/null 2>&1; then
                ok "renders and validates: $name"
            else
                bad "schema: $name" "$(kubeconform -strict -kubernetes-version "$K8S_VERSION" -ignore-missing-schemas "$WORK/$name.yaml" 2>&1 | head -2)"
            fi
        else
            bad "render: $name" "$(tail -1 "$WORK/err")"
        fi
    }

    render default
    render no-agent --set agent.enabled=false
    render no-controller --set controller.enabled=false
    render no-networkpolicy --set networkPolicy.enabled=false
    render transparent --set agent.transparent=true --set gateway.mode=transparent_tls
    render no-autoscaling --set gateway.autoscaling.enabled=false --set gateway.replicaCount=5
    render monitoring --set monitoring.serviceMonitor.enabled=true --set monitoring.prometheusRule.enabled=true
    render existing-secret --set tokens.existingSecret=my-secret --set tokens.create=false
    render multi-sandbox --set 'sandbox.namespaces={execution,training,ci}'
    render custom-registry --set global.imageRegistry=registry.example.com/security --set gateway.image.tag=v2
    render digest-pinned --set gateway.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000
    render no-persistence --set controller.persistence.enabled=false
    render agent-both-hooks --set agent.hook=both --set agent.blockIPv6=false
    render custom-tls-ports --set 'gateway.config.strict.tlsPorts={443,8443,9443,10443}'

    reject() {
        local name="$1"; shift
        if helm template ro "$CHART" "$@" >/dev/null 2>&1; then
            bad "reject: $name" "the invalid value was accepted"
        else
            ok "the schema rejects: $name"
        fi
    }
    reject "an unknown agent hook" --set agent.hook=bogus
    reject "an unsupported TLS version" --set gateway.config.strict.minTlsVersion=2.0
    reject "an unknown gateway mode" --set gateway.mode=wide-open
    reject "an empty sandbox namespace list" --set 'sandbox.namespaces={}'
    reject "a malformed pod CIDR" --set 'sandbox.podCidrs={not-a-cidr}'
    reject "no gateway address while the agent is enabled" \
        --set gateway.service.clusterIP=""
    render agent-off-needs-no-gateway-address \
        --set gateway.service.clusterIP="" --set agent.enabled=false
    render quickstart-values -f "$ROOT/deploy/helm/values-quickstart.yaml"
    render quickstart-overridden -f "$ROOT/deploy/helm/values-quickstart.yaml" \
        --set gateway.service.clusterIP=172.20.0.53 \
        --set 'sandbox.podCidrs={192.168.0.0/16}'

    printf '\n  fail-closed defaults\n'
    helm template ro "$CHART" > "$WORK/defaults.yaml" 2>/dev/null
    if grep -q '"allowAnonymous": false' "$WORK/defaults.yaml"; then
        ok "anonymous identities are disabled by default"
    else
        bad "allowAnonymous" "the default should be false"
    fi
    if grep -q '"blockObfuscated": true' "$WORK/defaults.yaml"; then
        ok "obfuscated address literals are blocked by default"
    else
        bad "blockObfuscated" "the default should be true"
    fi
    if grep -q '"version": 0' "$WORK/defaults.yaml"; then
        ok "the bootstrap bundle ships as version 0"
    else
        bad "bootstrap version" "expected version 0"
    fi
    if grep -q 'readOnlyRootFilesystem: true' "$WORK/defaults.yaml"; then
        ok "containers run with a read-only root filesystem"
    else
        bad "readOnlyRootFilesystem" "it is not set"
    fi
    if grep -q 'runAsNonRoot: true' "$WORK/defaults.yaml"; then
        ok "workloads run as a non-root user"
    else
        bad "runAsNonRoot" "it is not set"
    fi
    if ! grep -q 'privileged: true' "$WORK/defaults.yaml"; then
        ok "no container asks for full privilege"
    else
        bad "privileged" "a privileged container was rendered"
    fi
    if grep -q 'automountServiceAccountToken: false' "$WORK/defaults.yaml"; then
        ok "service account tokens are not mounted"
    else
        bad "automountServiceAccountToken" "it is not disabled"
    fi
else
    echo "    skip helm is not installed"
fi

printf '\n%s\n' "======================================================================"
printf 'passed=%d failed=%d\n' "$PASS" "$FAIL"
printf '%s\n' "======================================================================"
[ "$FAIL" -eq 0 ]
