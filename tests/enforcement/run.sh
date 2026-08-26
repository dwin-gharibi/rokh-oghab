#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AGENT="$ROOT/bin/ro-agent"
NET="ro_enforce"
SUBNET="10.97.0.0/24"
GATEWAY_IP="10.97.0.5"
ORIGIN_IP="10.97.0.10"
SANDBOX_IP="10.97.0.20"
IMAGE="${RO_GATEWAY_IMAGE:-rokh-oghab/gateway:dev}"
BASE_IMAGE="${RO_TEST_IMAGE:-openresty/openresty:1.27.1.2-0-alpine-fat}"
WORK="$(mktemp -d)"

PASS=0
FAIL=0

ok()   { printf '    ok   %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '    FAIL %s\n         %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }
note() { printf '\n  %s\n' "$1"; }

host_veth_for() {
    local container="$1" iflink iface name
    iflink="$(docker exec "$container" cat /sys/class/net/eth0/iflink 2>/dev/null)" \
        || return 1
    case "$iflink" in
        ''|*[!0-9]*) return 1 ;;
    esac
    for iface in /sys/class/net/*; do
        name="$(basename "$iface")"
        case "$name" in
            veth*|cali*|lxc*|eni*) ;;
            *) continue ;;
        esac
        if [ "$(cat "$iface/ifindex" 2>/dev/null)" = "$iflink" ]; then
            printf '%s' "$name"
            return 0
        fi
    done
    return 1
}

scope_sandbox_ipv6() {
    local veth
    veth="$(host_veth_for "$1" || true)"
    if [ -n "$veth" ]; then
        export RO_SANDBOX_IFACES="$veth"
        note "sandbox interface on the host is $veth"
    else
        export RO_IPV6_UNSCOPED=allow
        note "the sandbox interface could not be determined; this IPv4-only \
network accepts unfiltered ipv6 deliberately"
    fi
}

cleanup() {
    printf '\n  cleaning up\n'
    RO_TABLE=ro_enforce_test "$AGENT" flush >/dev/null 2>&1 || true
    docker rm -f ro-enf-gateway ro-enf-origin ro-enf-sandbox >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

require_root() {
    if [ "$(id -u)" != "0" ]; then
        echo "this suite needs root to program nftables" >&2
        exit 77
    fi
    if ! command -v nft >/dev/null 2>&1; then
        echo "nft is not installed; skipping enforcement suite" >&2
        exit 77
    fi
}

sandbox_can_reach_directly() {
    docker exec ro-enf-sandbox curl -sS --max-time 4 --noproxy '*' \
        "http://$ORIGIN_IP/" >/dev/null 2>&1
}

sandbox_can_reach_via_proxy() {
    docker exec ro-enf-sandbox curl -sS --max-time 6 \
        -x "http://$GATEWAY_IP:3128" "http://$ORIGIN_IP/" 2>/dev/null
}

sandbox_can_open_raw_port() {
    docker exec ro-enf-sandbox timeout 4 nc -z -w 3 "$ORIGIN_IP" 80 >/dev/null 2>&1
}

sandbox_can_reach_gateway_proxy_port() {
    docker exec ro-enf-sandbox timeout 4 nc -z -w 3 "$GATEWAY_IP" 3128 >/dev/null 2>&1
}

sandbox_can_reach_gateway_admin_port() {
    docker exec ro-enf-sandbox timeout 4 nc -z -w 3 "$GATEWAY_IP" 9145 >/dev/null 2>&1
}

main() {
    require_root

    printf 'Rokh Oghab node enforcement suite\n'
    printf '%s\n' "========================================================================"

    cat > "$WORK/gateway.json" <<JSON
{
  "node": "ro-enforce",
  "mode": "explicit",
  "bundleFile": "/etc/rokh-oghab/bundle.json",
  "resolver": { "servers": ["$ORIGIN_IP:53"], "timeoutMs": 1000, "retries": 1 },
  "guard": { "includeDefaults": true, "allowExceptions": ["$SUBNET"] },
  "strict": { "path": true, "sniMatch": true, "hostMatch": true,
              "minTlsVersion": "1.2", "redirectGuard": true },
  "audit": { "path": "/dev/stdout", "level": "info", "bufferMax": 1 },
  "admin": { "token": "enforce-admin-token-0000000001", "allowFrom": [] },
  "identities": { "allowAnonymous": false }
}
JSON

    cat > "$WORK/bundle.json" <<JSON
{
  "version": 1,
  "ttlSeconds": 300,
  "defaults": { "maxStalenessSeconds": 900 },
  "identities": {
    "allowAnonymous": false,
    "tokens": {},
    "sources": [
      { "cidr": "$SANDBOX_IP/32", "id": "enforce-sandbox",
        "namespace": "execution", "profile": "enforced",
        "serviceAccount": "sandbox-runner" }
    ]
  },
  "policies": [
    {
      "name": "enforced-profile",
      "tier": "profile",
      "selector": { "profiles": ["enforced"] },
      "rules": [
        { "name": "origin", "action": "allow",
          "destinations": { "cidrs": ["$ORIGIN_IP/32"] },
          "ports": [80], "protocols": ["http"] }
      ]
    }
  ]
}
JSON

    cat > "$WORK/origin.conf" <<'CONF'
worker_processes 1;
error_log /dev/stderr notice;
pid /tmp/origin.pid;
daemon off;
events { worker_connections 256; }
http {
    access_log off;
    server {
        listen 80;
        location / {
            default_type application/json;
            return 200 '{"origin":"enforce-origin"}';
        }
    }
}
CONF

    note "bringing up an isolated sandbox network"
    docker network rm "$NET" >/dev/null 2>&1 || true
    docker network create --subnet "$SUBNET" "$NET" >/dev/null \
        || { bad "create network" "docker network create failed"; return 1; }

    docker run -d --name ro-enf-origin --network "$NET" --ip "$ORIGIN_IP" \
        -v "$WORK/origin.conf:/etc/origin.conf:ro" "$BASE_IMAGE" \
        /usr/local/openresty/nginx/sbin/nginx -c /etc/origin.conf \
        -p /usr/local/openresty/nginx >/dev/null

    docker run -d --name ro-enf-gateway --network "$NET" --ip "$GATEWAY_IP" \
        -v "$WORK/gateway.json:/etc/rokh-oghab/gateway.json:ro" \
        -v "$WORK/bundle.json:/etc/rokh-oghab/bundle.json:ro" \
        "$IMAGE" >/dev/null

    docker run -d --name ro-enf-sandbox --network "$NET" --ip "$SANDBOX_IP" \
        "$BASE_IMAGE" sleep infinity >/dev/null

    sleep 5

    scope_sandbox_ipv6 ro-enf-sandbox

    note "baseline: without enforcement the sandbox has unrestricted egress"
    if sandbox_can_reach_directly; then
        ok "sandbox reaches the origin directly (the test is meaningful)"
    else
        bad "baseline direct access" "the sandbox could not reach the origin at all"
        return 1
    fi

    note "applying node enforcement"
    RO_TABLE=ro_enforce_test \
    RO_GATEWAY_ADDR="$GATEWAY_IP" \
    RO_SANDBOX_CIDRS="$SANDBOX_IP/32" \
    RO_HOOK=forward \
    "$AGENT" apply 2>/dev/null \
        || { bad "apply ruleset" "ro-agent apply failed"; return 1; }
    ok "nftables ruleset applied"

    note "with enforcement the only path out is the gateway"
    if sandbox_can_reach_directly; then
        bad "direct HTTP is blocked" "the sandbox still reached the origin directly"
    else
        ok "direct HTTP to the origin is dropped"
    fi

    if sandbox_can_open_raw_port; then
        bad "raw TCP is blocked" "the sandbox opened a raw TCP connection"
    else
        ok "raw TCP to the origin is dropped"
    fi

    if sandbox_can_reach_gateway_admin_port; then
        bad "admin port is blocked" "the sandbox reached the gateway admin port"
    else
        ok "the gateway admin port is unreachable from the sandbox"
    fi

    if sandbox_can_reach_gateway_proxy_port; then
        ok "the gateway proxy port stays reachable"
    else
        bad "proxy port reachable" "the sandbox cannot reach the proxy"
    fi

    body="$(sandbox_can_reach_via_proxy)"
    if printf '%s' "$body" | grep -q "enforce-origin"; then
        ok "traffic through the gateway is permitted by policy"
    else
        bad "proxied request" "expected the origin payload, got: ${body:-<empty>}"
    fi

    denied="$(docker exec ro-enf-sandbox curl -sS --max-time 6 \
        -x "http://$GATEWAY_IP:3128" "http://169.254.169.254/" 2>/dev/null)"
    if printf '%s' "$denied" | grep -q "forbidden_by_rokh_oghab"; then
        ok "the gateway still denies metadata access on the only allowed path"
    else
        bad "metadata denied" "unexpected response: ${denied:-<empty>}"
    fi

    note "the ruleset repairs itself if it is removed"
    nft delete table inet ro_enforce_test >/dev/null 2>&1 || true
    if sandbox_can_reach_directly; then
        ok "removing the ruleset restores direct access (proves it was enforcing)"
    else
        bad "flush restores access" "still blocked after removing the ruleset"
    fi

    RO_TABLE=ro_enforce_test \
    RO_GATEWAY_ADDR="$GATEWAY_IP" \
    RO_SANDBOX_CIDRS="$SANDBOX_IP/32" \
    RO_HOOK=forward \
    "$AGENT" apply 2>/dev/null
    if sandbox_can_reach_directly; then
        bad "re-apply" "the sandbox is not blocked after reapplying"
    else
        ok "reapplying the ruleset restores enforcement"
    fi

    note "a gateway reached through a load balancer is still reachable"
    CLUSTER_IP="10.96.0.253"
    nft delete table inet ro_enforce_dnat >/dev/null 2>&1 || true
    if nft -f - <<NFT 2>/dev/null
table inet ro_enforce_dnat {
    chain pre {
        type nat hook prerouting priority dstnat; policy accept;
        ip saddr ${SANDBOX_IP} ip daddr ${CLUSTER_IP} tcp dport 3128 \
            counter dnat ip to ${GATEWAY_IP}:3128
    }
}
NFT
    then
        RO_TABLE=ro_enforce_test \
        RO_GATEWAY_ADDR="$CLUSTER_IP" \
        RO_SANDBOX_CIDRS="$SANDBOX_IP/32" \
        RO_HOOK=forward \
        "$AGENT" apply 2>/dev/null \
            || bad "clusterip apply" "ro-agent apply failed"

        if docker exec ro-enf-sandbox curl -sS --max-time 6 \
            -x "http://$CLUSTER_IP:3128" "http://$ORIGIN_IP/" >/dev/null 2>&1
        then
            ok "a gateway behind a dnat is reachable through its service address"
        else
            bad "clusterip reachability" \
                "the sandbox could not reach the gateway through a dnat'd \
service address; a rule written against the pre-nat destination alone never \
matches in a filter hook, and every sandbox loses egress"
        fi

        if docker exec ro-enf-sandbox curl -sS --max-time 4 --noproxy '*' \
            "http://$ORIGIN_IP/" >/dev/null 2>&1
        then
            bad "clusterip containment" \
                "matching the pre-nat destination must not open direct egress"
        else
            ok "matching a pre-nat destination does not widen anything else"
        fi

        nft delete table inet ro_enforce_dnat >/dev/null 2>&1 || true
        RO_TABLE=ro_enforce_test \
        RO_GATEWAY_ADDR="$GATEWAY_IP" \
        RO_SANDBOX_CIDRS="$SANDBOX_IP/32" \
        RO_HOOK=forward \
        "$AGENT" apply 2>/dev/null || true
    else
        printf '    skip cannot install a dnat rule on this host\n'
    fi

    note "when the gateway is stopped the sandbox has no network at all"
    docker stop ro-enf-gateway >/dev/null 2>&1
    sleep 2
    if sandbox_can_reach_directly; then
        bad "fail closed" "the sandbox regained direct egress once the gateway died"
    else
        ok "killing the gateway leaves the sandbox with zero egress, not open egress"
    fi
    docker start ro-enf-gateway >/dev/null 2>&1
    sleep 3

    printf '\n%s\n' "========================================================================"
    printf 'passed=%d failed=%d\n' "$PASS" "$FAIL"
    printf '%s\n' "========================================================================"
    [ "$FAIL" -eq 0 ]
}

main "$@"
