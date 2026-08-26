#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${RO_TEST_IMAGE:-openresty/openresty:1.27.1.2-0-alpine-fat}"

echo "==> Lua syntax check"
docker run --rm -v "$ROOT":/src:ro -w /src "$IMAGE" sh -c '
set -e
fail=0
for f in $(find /src/lua /src/tests -name "*.lua" | sort); do
  if ! out=$(/usr/local/openresty/luajit/bin/luajit -bl "$f" /dev/null 2>&1); then
    echo "SYNTAX ERROR: $f"
    echo "$out"
    fail=1
  fi
done
exit $fail
'
echo "==> Lua syntax check passed"

echo "==> gateway configuration check"
docker run --rm "${RO_GATEWAY_IMAGE:-rokh-oghab/gateway:dev}" check
echo "==> gateway configuration check passed"

echo "==> controller configuration check"
docker run --rm "${RO_CONTROLLER_IMAGE:-rokh-oghab/controller:dev}" check
echo "==> controller configuration check passed"
