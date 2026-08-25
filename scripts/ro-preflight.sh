#!/usr/bin/env bash
set -uo pipefail

RELEASE="ro"
NAMESPACE="rokh-oghab"
CHART="deploy/helm/rokh-oghab"

while [ $# -gt 0 ]; do
    case "$1" in
        --release) RELEASE="$2"; shift 2 ;;
        --namespace) NAMESPACE="$2"; shift 2 ;;
        --chart) CHART="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

fail=0
say()  { printf '  %s\n' "$1"; }
ok()   { printf '  \033[32mok\033[0m    %s\n' "$1"; }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$1"; }
bad()  { printf '  \033[31mno\033[0m    %s\n' "$1"; fail=$((fail + 1)); }

printf '\nRokh Oghab preflight\n'
printf '%s\n\n' "======================================================================"

command -v kubectl >/dev/null 2>&1 || { bad "kubectl is not on PATH"; exit 1; }
command -v helm >/dev/null 2>&1 || { bad "helm is not on PATH"; exit 1; }

if ! kubectl version -o json >/dev/null 2>&1; then
    bad "kubectl cannot reach a cluster"
    exit 1
fi
ok "kubectl reaches a cluster: $(kubectl config current-context 2>/dev/null)"

service_cidr=""
probe="$(kubectl create service clusterip ro-preflight-probe \
    --clusterip=1.1.1.1 --tcp=1:1 --dry-run=server 2>&1 || true)"
service_cidr="$(printf '%s' "$probe" \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -1)"

if [ -z "$service_cidr" ]; then
    kube_dns="$(kubectl -n kube-system get svc kube-dns \
        -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
    if [ -n "$kube_dns" ]; then
        warn "could not read the service CIDR; deriving from kube-dns at $kube_dns"
        service_cidr="$(printf '%s' "$kube_dns" | sed 's/\.[0-9]*$/.0\/16/')"
    fi
fi

gateway_ip=""
if [ -n "$service_cidr" ]; then
    ok "service CIDR: $service_cidr"
    base="$(printf '%s' "$service_cidr" | cut -d/ -f1)"
    prefix="$(printf '%s' "$base" | cut -d. -f1-3)"
    for last in 53 54 55 56 57; do
        candidate="$prefix.$last"
        if ! kubectl get svc -A -o jsonpath='{range .items[*]}{.spec.clusterIP}{"\n"}{end}' \
             2>/dev/null | grep -qx "$candidate"; then
            gateway_ip="$candidate"
            break
        fi
    done
    if [ -n "$gateway_ip" ]; then
        ok "a free address for the gateway service: $gateway_ip"
    else
        warn "every candidate address is taken; pick a free one in $service_cidr"
    fi
else
    bad "could not determine the service CIDR; set gateway.service.clusterIP by hand"
fi

pod_cidr="$(kubectl cluster-info dump 2>/dev/null \
    | grep -m1 -oE 'cluster-cidr=[0-9./]+' | cut -d= -f2 || true)"
if [ -z "$pod_cidr" ]; then
    pod_cidr="$(kubectl get nodes -o jsonpath='{range .items[*]}{.spec.podCIDR}{"\n"}{end}' \
        2>/dev/null | grep -v '^$' | sort -u | paste -sd, - || true)"
    node_count="$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
        2>/dev/null | grep -cv '^$' || echo 0)"
    cidr_count="$(printf '%s' "$pod_cidr" | tr ',' '\n' | grep -cv '^$' || echo 0)"
    if [ -n "$pod_cidr" ] && [ "$cidr_count" -gt 1 ]; then
        warn "no cluster-wide pod CIDR was published; using the union of $cidr_count per-node ranges across $node_count nodes"
        warn "a node added later will not be covered -- prefer the cluster pod CIDR if your platform exposes one"
    fi
fi
if [ -n "$pod_cidr" ]; then
    ok "pod CIDR: $pod_cidr"
else
    warn "could not read the pod CIDR; the node agent needs it to know what to confine"
    warn "on a cluster where pods hold VPC addresses, set sandbox.podCidrs to that range"
fi

if kubectl get crd networkpolicies.crd.projectcalico.org >/dev/null 2>&1 \
   || kubectl -n kube-system get ds -o name 2>/dev/null \
      | grep -qiE 'calico|cilium|weave|antrea|kube-router'; then
    ok "the CNI looks like one that enforces NetworkPolicy"
else
    warn "could not confirm the CNI enforces NetworkPolicy"
    warn "if it does not, keep agent.enabled=true so nftables is the boundary"
fi

if kubectl auth can-i create daemonsets -n "$NAMESPACE" >/dev/null 2>&1; then
    ok "you can create the DaemonSet the node agent needs"
else
    warn "you may not be able to create a DaemonSet in $NAMESPACE"
fi

printf '\n%s\n' "======================================================================"
if [ "$fail" -gt 0 ]; then
    printf 'preflight found %d thing(s) to fix first\n\n' "$fail"
    exit 1
fi

printf 'Install with:\n\n'
printf '  helm upgrade --install %s %s \\\n' "$RELEASE" "$CHART"
printf '    --namespace %s --create-namespace \\\n' "$NAMESPACE"
[ -n "$gateway_ip" ] && printf '    --set gateway.service.clusterIP=%s \\\n' "$gateway_ip"
[ -n "$pod_cidr" ] && printf '    --set sandbox.podCidrs[0]=%s \\\n' "$pod_cidr"
printf '    --wait\n\n'
printf 'Then:\n\n'
printf '  bash scripts/ro-onboard.sh --release %s --namespace %s\n\n' \
    "$RELEASE" "$NAMESPACE"
