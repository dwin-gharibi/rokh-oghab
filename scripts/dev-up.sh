#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> building images"
docker build --quiet --target gateway -t rokh-oghab/gateway:dev . >/dev/null
docker build --quiet --target controller -t rokh-oghab/controller:dev . >/dev/null

echo "==> generating test certificates"
bash tests/e2e/make-certs.sh >/dev/null

echo "==> generating the test policy bundle"
python3 tests/e2e/make-bundle.py >/dev/null

echo "==> starting the stack"
cd tests/e2e
docker compose up -d
sleep 5
docker compose ps --format '{{.Name}}\t{{.Status}}'

cat <<'EOF'

The development stack is up.

  proxy            http://127.0.0.1:13128
  gateway admin    http://127.0.0.1:19145   token ro-e2e-admin-token-000000000001
  controller       http://127.0.0.1:18081   token ctl-admin-token-0000000000001
  gateway DNS      127.0.0.1:15353/udp

Try it:

  curl -x http://127.0.0.1:13128 \
       -H 'Proxy-Authorization: Bearer ro-e2e-python-token-0000000001' \
       http://allowed.test/

  ROCTL_ENDPOINT=http://127.0.0.1:18081 \
  ROCTL_TOKEN=ctl-admin-token-0000000000001 ./bin/roctl status
EOF
