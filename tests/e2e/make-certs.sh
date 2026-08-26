#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS="$HERE/certs"
mkdir -p "$CERTS"

if [ -f "$CERTS/origin.crt" ] && [ -f "$CERTS/origin.key" ]; then
  echo "test certificates already present"
  exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$CERTS/origin.key" -out "$CERTS/origin.crt" \
  -subj "/CN=allowed.test/O=Rokh Oghab Test" \
  -addext "subjectAltName=DNS:allowed.test,DNS:api.allowed.test,DNS:files.allowed.test,DNS:deep.files.allowed.test,DNS:denied.test,DNS:other.test,DNS:tlsonly.test,DNS:pathrule.test,DNS:ratelimited.test,DNS:bandwidth.test,DNS:mixed.test,DNS:evilallowed.test,DNS:raw.test,IP:10.99.0.10,IP:10.99.0.11" \
  2>/dev/null
chmod 600 "$CERTS/origin.key"
echo "generated self-signed test certificates in $CERTS"
