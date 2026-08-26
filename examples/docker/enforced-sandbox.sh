#!/usr/bin/env bash

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AGENT="$ROOT/bin/ro-agent"

NET="${RO_DEMO_NET:-ro_demo}"
SUBNET="${RO_DEMO_SUBNET:-10.90.0.0/24}"
GATEWAY_IP="${RO_DEMO_GATEWAY_IP:-10.90.0.5}"
ORIGIN_IP="${RO_DEMO_ORIGIN_IP:-10.90.0.10}"
DNS_IP="${RO_DEMO_DNS_IP:-10.90.0.53}"
SANDBOX_IP="${RO_DEMO_SANDBOX_IP:-10.90.0.20}"
TABLE="${RO_DEMO_TABLE:-ro_demo}"

GATEWAY_IMAGE="${RO_GATEWAY_IMAGE:-rokh-oghab/gateway:dev}"
BASE_IMAGE="${RO_TEST_IMAGE:-openresty/openresty:1.27.1.2-0-alpine-fat}"
PYTHON_IMAGE="${RO_PYTHON_IMAGE:-python:3.12-alpine}"

SANDBOX_TOKEN="ro-demo-sandbox-token-00000001"
WORK="$(mktemp -d)"

log() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

cleanup() {
    log "cleaning up"
    RO_TABLE="$TABLE" "$AGENT" flush >/dev/null 2>&1 || true
    docker rm -f ro-demo-gateway ro-demo-origin ro-demo-dns ro-demo-sandbox \
        >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

if [ "$(id -u)" != "0" ]; then
    echo "this example programs nftables and must run as root" >&2
    exit 1
fi
if ! command -v nft >/dev/null 2>&1; then
    echo "nft is required (install the nftables package)" >&2
    exit 1
fi

log "writing the gateway configuration and policy"

cat > "$WORK/gateway.json" <<JSON
{
  "node": "ro-demo",
  "mode": "explicit",
  "bundleFile": "/etc/rokh-oghab/bundle.json",
  "resolver": { "servers": ["$DNS_IP:53"], "timeoutMs": 2000, "retries": 2,
                "minTtl": 1, "maxTtl": 30 },
  "guard": { "includeDefaults": true, "allowExceptions": ["$SUBNET"],
             "blockObfuscated": true, "allowIPv6": true },
  "strict": { "path": true, "sniMatch": true, "hostMatch": true,
              "minTlsVersion": "1.2", "redirectGuard": true,
              "blockPlaintextOnTlsPorts": true, "tlsPorts": [443, 8443, 9443] },
  "limits": { "globalMaxConnections": 2000, "clientTimeoutMs": 30000 },
  "audit": { "path": "/dev/stdout", "level": "info", "logPaths": true,
             "bufferMax": 1 },
  "dns": { "enabled": true, "allowedTypes": ["A", "AAAA"],
           "denyResponse": "nxdomain" },
  "admin": { "token": "ro-demo-admin-token-000000001",
             "allowFrom": ["127.0.0.1/32"] },
  "identities": { "allowAnonymous": false }
}
JSON

TOKEN_SHA="$(printf '%s' "$SANDBOX_TOKEN" | sha256sum | cut -d' ' -f1)"

cat > "$WORK/bundle.json" <<JSON
{
  "version": 1,
  "ttlSeconds": 300,
  "defaults": { "maxStalenessSeconds": 900 },
  "identities": {
    "allowAnonymous": false,
    "tokens": {
      "$TOKEN_SHA": {
        "id": "demo-sandbox-1",
        "namespace": "execution",
        "profile": "untrusted-python",
        "serviceAccount": "sandbox-runner"
      }
    },
    "sources": [
      { "cidr": "$SANDBOX_IP/32", "id": "demo-sandbox-by-source",
        "namespace": "execution", "profile": "untrusted-python",
        "serviceAccount": "sandbox-runner" }
    ]
  },
  "policies": [
    {
      "name": "global-baseline",
      "tier": "global",
      "rules": [
        { "name": "deny-cloud-metadata", "action": "deny",
          "destinations": { "cidrs": ["169.254.0.0/16", "100.100.100.200/32",
                                      "192.0.0.192/32"] } }
      ]
    },
    {
      "name": "untrusted-python",
      "tier": "profile",
      "priority": 10,
      "selector": { "profiles": ["untrusted-python"] },
      "rules": [
        { "name": "allowed-origin", "action": "allow",
          "destinations": { "hostnames": ["allowed.test"] },
          "ports": [80, 443], "protocols": ["http", "https"] }
      ]
    }
  ]
}
JSON

cat > "$WORK/zone.json" <<JSON
{
  "allowed.test": { "a": ["$ORIGIN_IP"], "ttl": 5 },
  "denied.test":  { "a": ["$ORIGIN_IP"], "ttl": 5 }
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
        listen 443 ssl;
        ssl_certificate /etc/origin/certs/origin.crt;
        ssl_certificate_key /etc/origin/certs/origin.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        location / {
            default_type application/json;
            return 200 '{"origin":"demo-origin"}';
        }
    }
}
CONF

mkdir -p "$WORK/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$WORK/certs/origin.key" -out "$WORK/certs/origin.crt" \
    -subj "/CN=allowed.test" \
    -addext "subjectAltName=DNS:allowed.test,DNS:denied.test,IP:$ORIGIN_IP" \
    2>/dev/null
chmod 644 "$WORK/certs/origin.key"

log "creating an isolated sandbox network"
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --subnet "$SUBNET" "$NET" >/dev/null

docker run -d --name ro-demo-dns --network "$NET" --ip "$DNS_IP" \
    -v "$ROOT/lua:/usr/local/rokh-oghab/lua:ro" \
    -v "$ROOT/tests/e2e/testdns/server.lua:/etc/testdns/server.lua:ro" \
    -v "$ROOT/tests/e2e/testdns/nginx.conf:/etc/testdns/nginx.conf:ro" \
    -v "$WORK/zone.json:/etc/testdns/zone.json:ro" \
    "$BASE_IMAGE" \
    /usr/local/openresty/nginx/sbin/nginx -c /etc/testdns/nginx.conf \
    -p /usr/local/openresty/nginx >/dev/null

docker run -d --name ro-demo-origin --network "$NET" --ip "$ORIGIN_IP" \
    -v "$WORK/origin.conf:/etc/origin.conf:ro" \
    -v "$WORK/certs:/etc/origin/certs:ro" \
    "$BASE_IMAGE" \
    /usr/local/openresty/nginx/sbin/nginx -c /etc/origin.conf \
    -p /usr/local/openresty/nginx >/dev/null

docker run -d --name ro-demo-gateway --network "$NET" --ip "$GATEWAY_IP" \
    -v "$WORK/gateway.json:/etc/rokh-oghab/gateway.json:ro" \
    -v "$WORK/bundle.json:/etc/rokh-oghab/bundle.json:ro" \
    "$GATEWAY_IMAGE" >/dev/null

sleep 5

log "programming node enforcement so the sandbox has one way out"
RO_TABLE="$TABLE" \
RO_GATEWAY_ADDR="$GATEWAY_IP" \
RO_SANDBOX_CIDRS="$SANDBOX_IP/32" \
RO_DNS_PORT=5353 \
RO_DNS_REDIRECT=true \
RO_HOOK=forward \
RO_IPV6_UNSCOPED="${RO_DEMO_IPV6_UNSCOPED:-allow}" \
"$AGENT" apply || { echo "failed to apply enforcement" >&2; exit 1; }

nft list table inet "$TABLE" | sed 's/^/    /'

printf 'nameserver %s\noptions ndots:0\n' "$GATEWAY_IP" > "$WORK/resolv.conf"

log "starting the sandbox with only proxy environment variables"
docker run -d --name ro-demo-sandbox --network "$NET" --ip "$SANDBOX_IP" \
    -v "$WORK/resolv.conf:/etc/resolv.conf:ro" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    -e HTTP_PROXY="http://$GATEWAY_IP:3128" \
    -e HTTPS_PROXY="http://$GATEWAY_IP:3128" \
    -e RO_PROXY_TOKEN="$SANDBOX_TOKEN" \
    -e RO_DEMO_INSECURE_TLS=1 \
    -e RO_DEMO_DIRECT_HOST="$ORIGIN_IP" \
    -e RO_DEMO_DNS_REDIRECTED=connected \
    -v "$ROOT/examples/python-sandbox/sandbox_demo.py:/demo.py:ro" \
    "$PYTHON_IMAGE" sleep infinity >/dev/null

sleep 2

if [ "${RO_DEMO_KEEP:-}" = "1" ]; then
    log "RO_DEMO_KEEP=1 so the environment stays up; press Ctrl-C to tear it down"
    trap - EXIT
    echo "  sandbox: docker exec -it ro-demo-sandbox sh"
    echo "  teardown: RO_TABLE=$TABLE $AGENT flush; docker rm -f ro-demo-gateway ro-demo-origin ro-demo-dns ro-demo-sandbox; docker network rm $NET"
    exit 0
fi

log "running untrusted Python inside the sandbox"
docker exec ro-demo-sandbox python /demo.py
status=$?

log "stopping the gateway to show the sandbox fails closed"
docker stop ro-demo-gateway >/dev/null 2>&1
sleep 2
if docker exec ro-demo-sandbox python -c "
import socket, sys
try:
    socket.create_connection(('$ORIGIN_IP', 80), timeout=3).close()
    print('    the sandbox still reached the origin: THIS WOULD BE A BYPASS')
    sys.exit(1)
except OSError as exc:
    print('    the sandbox has no network at all: %s' % exc)
"; then
    echo "    fail-closed behaviour confirmed"
else
    echo "    FAILED: the sandbox regained egress when the gateway stopped"
    status=1
fi

exit $status
