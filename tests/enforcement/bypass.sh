#!/usr/bin/env bash

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AGENT="$ROOT/bin/ro-agent"
NET="ro_bypass"
SUBNET="10.95.0.0/24"
GATEWAY_IP="10.95.0.5"
ORIGIN_IP="10.95.0.10"
SANDBOX_IP="10.95.0.20"
NEIGHBOUR_IP="10.95.0.21"
TABLE="ro_bypass_test"
IMAGE="${RO_GATEWAY_IMAGE:-rokh-oghab/gateway:dev}"
BASE_IMAGE="${RO_TEST_IMAGE:-openresty/openresty:1.27.1.2-0-alpine-fat}"
PYTHON_IMAGE="${RO_PYTHON_IMAGE:-python:3.12-alpine}"
WORK="$(mktemp -d)"

PASS=0
FAIL=0
SKIP=0

ok()   { printf '    ok   %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '    FAIL %s\n         %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }
skip() { printf '    skip %s\n         %s\n' "$1" "${2:-}"; SKIP=$((SKIP + 1)); }
note() { printf '\n  %s\n' "$1"; }

cleanup() {
    printf '\n  cleaning up\n'
    RO_TABLE="$TABLE" "$AGENT" flush >/dev/null 2>&1 || true
    docker rm -f ro-bypass-gateway ro-bypass-origin ro-bypass-sandbox \
        ro-bypass-neighbour >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

if [ "$(id -u)" != "0" ] || ! command -v nft >/dev/null 2>&1; then
    echo "this suite needs root and nft" >&2
    exit 77
fi

sandbox() { docker exec ro-bypass-sandbox "$@"; }

sandbox_py() {
    docker exec ro-bypass-sandbox python -c "$1" 2>&1
}

escape_blocked() {
    local name="$1" script="$2"
    local out
    out="$(sandbox_py "$script")"
    if printf '%s' "$out" | grep -q "ESCAPED"; then
        bad "$name" "$out"
    elif printf '%s' "$out" | grep -qE "blocked:|captured by the gateway|raw socket unavailable"; then
        ok "$name"
    else
        bad "$name" "the probe produced no verdict, so it never ran: ${out:-<no output>}"
    fi
}

host_veth_for() {
    local container="$1"
    local iflink
    iflink="$(docker exec "$container" cat /sys/class/net/eth0/iflink 2>/dev/null)" \
        || return 1
    case "$iflink" in
        ''|*[!0-9]*) return 1 ;;
    esac
    local iface name
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

printf 'Rokh Oghab sandbox bypass suite\n'
printf '%s\n' "========================================================================"

cat > "$WORK/gateway.json" <<JSON
{
  "node": "ro-bypass",
  "mode": "explicit",
  "bundleFile": "/etc/rokh-oghab/bundle.json",
  "resolver": { "servers": ["$ORIGIN_IP:53"], "timeoutMs": 1000, "retries": 1 },
  "guard": { "includeDefaults": true, "allowExceptions": ["$SUBNET"] },
  "strict": { "path": true, "sniMatch": true, "hostMatch": true,
              "minTlsVersion": "1.2", "redirectGuard": true },
  "audit": { "path": "/dev/stdout", "level": "info", "bufferMax": 1 },
  "admin": { "token": "bypass-admin-token-0000000001", "allowFrom": [] },
  "identities": { "allowAnonymous": false }
}
JSON

cat > "$WORK/bundle.json" <<JSON
{
  "version": 1,
  "ttlSeconds": 300,
  "defaults": { "maxStalenessSeconds": 900 },
  "identities": {
    "allowAnonymous": false, "tokens": {},
    "sources": [
      { "cidr": "$SANDBOX_IP/32", "id": "bypass-sandbox",
        "namespace": "execution", "profile": "enforced",
        "serviceAccount": "sandbox-runner" }
    ]
  },
  "policies": [
    { "name": "enforced-profile", "tier": "profile",
      "selector": { "profiles": ["enforced"] },
      "rules": [
        { "name": "origin", "action": "allow",
          "destinations": { "cidrs": ["$ORIGIN_IP/32"] },
          "ports": [80], "protocols": ["http"] }
      ] }
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
        location / { default_type application/json; return 200 '{"origin":"bypass-origin"}'; }
    }
}
CONF

note "building an isolated sandbox network"
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --subnet "$SUBNET" "$NET" >/dev/null

docker run -d --name ro-bypass-origin --network "$NET" --ip "$ORIGIN_IP" \
    -v "$WORK/origin.conf:/etc/origin.conf:ro" "$BASE_IMAGE" \
    /usr/local/openresty/nginx/sbin/nginx -c /etc/origin.conf \
    -p /usr/local/openresty/nginx >/dev/null

docker run -d --name ro-bypass-gateway --network "$NET" --ip "$GATEWAY_IP" \
    -v "$WORK/gateway.json:/etc/rokh-oghab/gateway.json:ro" \
    -v "$WORK/bundle.json:/etc/rokh-oghab/bundle.json:ro" \
    "$IMAGE" >/dev/null

docker run -d --name ro-bypass-neighbour --network "$NET" --ip "$NEIGHBOUR_IP" \
    -v "$WORK/origin.conf:/etc/origin.conf:ro" "$BASE_IMAGE" \
    /usr/local/openresty/nginx/sbin/nginx -c /etc/origin.conf \
    -p /usr/local/openresty/nginx >/dev/null

docker run -d --name ro-bypass-sandbox --network "$NET" --ip "$SANDBOX_IP" \
    --cap-add NET_RAW \
    -e HTTP_PROXY="http://$GATEWAY_IP:3128" \
    -e HTTPS_PROXY="http://$GATEWAY_IP:3128" \
    "$PYTHON_IMAGE" sleep infinity >/dev/null

sleep 5

VETH="$(host_veth_for ro-bypass-sandbox || true)"
if [ -n "$VETH" ]; then
    note "sandbox interface on the host is $VETH"
else
    note "could not determine the sandbox interface"
fi

note "applying node enforcement"
RO_TABLE="$TABLE" \
RO_GATEWAY_ADDR="$GATEWAY_IP" \
RO_SANDBOX_CIDRS="$SANDBOX_IP/32" \
RO_SANDBOX_IFACES="${VETH:-}" \
RO_DNS_PORT=5353 \
RO_DNS_REDIRECT=true \
RO_HOOK=forward \
"$AGENT" apply 2>/dev/null || { bad "apply" "ro-agent apply failed"; exit 1; }
ok "the enforcement ruleset is active"

note "the permitted path still works"
body="$(sandbox_py "
import urllib.request
o = urllib.request.build_opener(urllib.request.ProxyHandler(
    {'http': 'http://$GATEWAY_IP:3128'}))
print(o.open('http://$ORIGIN_IP/', timeout=8).read().decode())
")"
if printf '%s' "$body" | grep -q "bypass-origin"; then
    ok "traffic through the gateway is permitted by policy"
else
    bad "permitted path" "expected the origin payload, got: ${body:-<empty>}"
fi

note "escape attempts at the transport layer"

escape_blocked "a direct TCP connection to the origin" "
import socket
try:
    socket.create_connection(('$ORIGIN_IP', 80), timeout=3).close()
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"

escape_blocked "a direct TCP connection to a public address" "
import socket
try:
    socket.create_connection(('1.1.1.1', 443), timeout=3).close()
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"

escape_blocked "a direct TCP connection to a neighbouring sandbox" "
import socket
try:
    socket.create_connection(('$NEIGHBOUR_IP', 80), timeout=3).close()
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"

escape_blocked "a direct TCP connection to the gateway admin port" "
import socket
try:
    s = socket.create_connection(('$GATEWAY_IP', 9145), timeout=3)
    s.sendall(b'GET /v1/status HTTP/1.0\r\n\r\n')
    data = s.recv(256)
    s.close()
    print('ESCAPED' if data else 'blocked: no data')
except OSError as e:
    print('blocked:', e)
"

escape_blocked "a UDP datagram to a public address" "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(b'x' * 8, ('1.1.1.1', 4444))
    s.recvfrom(64)
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"

escape_blocked "an ICMP echo to a public address" "
import socket, struct
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(3)
    pkt = struct.pack('>BBHHH', 8, 0, 0, 1, 1)
    s.sendto(pkt, ('1.1.1.1', 0))
    s.recvfrom(128)
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"

escape_blocked "an IPv6 connection to a public address" "
import socket
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(('2606:4700:4700::1111', 443))
    s.close()
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"

escape_blocked "ignoring the proxy environment entirely" "
import os, socket
for key in list(os.environ):
    if 'PROXY' in key.upper():
        del os.environ[key]
try:
    socket.create_connection(('$ORIGIN_IP', 80), timeout=3).close()
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"

escape_blocked "a DNS query to an external resolver" "
import socket, struct
q = struct.pack('>HHHHHH', 1, 0x0100, 1, 0, 0, 0)
for label in ('example', 'com'):
    q += bytes([len(label)]) + label.encode()
q += b'\x00' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(q, ('8.8.8.8', 53))
    data, addr = s.recvfrom(512)
    answers = struct.unpack('>H', data[6:8])[0]
    rcode = struct.unpack('>H', data[2:4])[0] & 15
    if answers > 0:
        print('ESCAPED: a real resolver answered with', answers, 'records')
    else:
        print('captured by the gateway, rcode', rcode)
except OSError as e:
    print('blocked:', e)
"

note "a sandbox cannot borrow another sandbox's identity"

forged_out="$(sandbox_py "
import socket, struct
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    payload = b'rokh-oghab-spoof-probe'
    udp = struct.pack('>HHHH', 40000, 5353, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64,
                     socket.IPPROTO_UDP, 0,
                     socket.inet_aton('$NEIGHBOUR_IP'),
                     socket.inet_aton('$GATEWAY_IP'))
    for _ in range(5):
        s.sendto(ip + udp, ('$GATEWAY_IP', 0))
    print('sent')
except OSError as e:
    print('raw socket unavailable:', e)
")"
if printf '%s' "$forged_out" | grep -q "raw socket unavailable"; then
    ok "the sandbox cannot craft raw packets at all"
elif ! printf '%s' "$forged_out" | grep -q "sent"; then
    bad "identity forging" "the probe produced no verdict: ${forged_out:-<none>}"
else
    sleep 1
    attributed="$(docker logs ro-bypass-gateway 2>&1 \
        | grep -c "bypass-neighbour" || true)"
    if [ "${attributed:-0}" -gt 0 ]; then
        bad "identity forging" "the gateway attributed traffic to a neighbour \
identity after a forged-source packet"
    else
        ok "a forged source address is never attributed to another identity"
    fi
fi

unmapped="$(sandbox_py "
import socket
try:
    s = socket.create_connection(('$GATEWAY_IP', 3128), timeout=5)
    s.sendall(b'GET http://denied.test/ HTTP/1.1\r\nHost: denied.test\r\n'
              b'Connection: close\r\n\r\n')
    print('blocked:', s.recv(120).split(b'\r\n')[0].decode())
    s.close()
except OSError as e:
    print('blocked:', e)
")"
case "$unmapped" in
    *200*) bad "unmapped identity" "an unlisted destination was served: $unmapped" ;;
    *blocked:*) ok "the gateway refuses what the sandbox's identity does not permit" ;;
    *) bad "unmapped identity" "no verdict: ${unmapped:-<none>}" ;;
esac

if [ -n "${VETH:-}" ]; then
    ok "the sandbox interface is known, so the anti-spoof rule is installed"
else
    skip "anti-spoof rule" "the sandbox interface could not be determined, so \
the agent installed no interface-scoped rule"
fi

rp_all="$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo unreadable)"
rp_iface="unreadable"
if [ -n "${VETH:-}" ]; then
    rp_iface="$(cat "/proc/sys/net/ipv4/conf/$VETH/rp_filter" 2>/dev/null \
        || echo unreadable)"
fi
if [ "$rp_all" = "unreadable" ]; then
    bad "reverse path filtering" "could not read conf/all/rp_filter, so this \
check observed nothing"
elif [ "$rp_all" = "0" ] && [ "$rp_iface" != "1" ] && [ "$rp_iface" != "2" ]; then
    bad "reverse path filtering" "rp_filter is 0 on conf/all and $rp_iface on \
the sandbox interface, so forged sources are not rejected"
else
    ok "reverse path filtering is active (all=$rp_all iface=$rp_iface)"
fi

note "the enforcement layer defends itself"
nft delete table inet "$TABLE" >/dev/null 2>&1 || true
flush_out="$(sandbox_py "
import socket
try:
    socket.create_connection(('$ORIGIN_IP', 80), timeout=3).close()
    print('reachable')
except OSError as e:
    print('blocked:', e)
")"
if printf '%s' "$flush_out" | grep -q "reachable"; then
    ok "removing the ruleset restores egress, so it really was enforcing"
else
    bad "flush check" "still blocked after removing the ruleset: $flush_out"
fi
RO_TABLE="$TABLE" RO_GATEWAY_ADDR="$GATEWAY_IP" \
RO_SANDBOX_CIDRS="$SANDBOX_IP/32" RO_SANDBOX_IFACES="${VETH:-}" \
RO_DNS_PORT=5353 RO_DNS_REDIRECT=true RO_HOOK=forward \
"$AGENT" apply >/dev/null 2>&1
escape_blocked "reapplying the ruleset restores enforcement" "
import socket
try:
    socket.create_connection(('$ORIGIN_IP', 80), timeout=3).close()
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"

note "stopping the gateway must remove network access, not grant it"
docker stop ro-bypass-gateway >/dev/null 2>&1
sleep 2
escape_blocked "a direct connection once the gateway is stopped" "
import socket
try:
    socket.create_connection(('$ORIGIN_IP', 80), timeout=3).close()
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"
escape_blocked "a public connection once the gateway is stopped" "
import socket
try:
    socket.create_connection(('1.1.1.1', 443), timeout=3).close()
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"
docker start ro-bypass-gateway >/dev/null 2>&1
sleep 3

printf '\n%s\n' "========================================================================"
printf 'passed=%d failed=%d skipped=%d\n' "$PASS" "$FAIL" "$SKIP"
printf '%s\n' "========================================================================"
[ "$FAIL" -eq 0 ]
