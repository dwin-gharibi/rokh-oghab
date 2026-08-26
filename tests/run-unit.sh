#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${RO_TEST_IMAGE:-openresty/openresty:1.27.1.2-0-alpine-fat}"
exec docker run --rm \
  -v "$ROOT":/src:ro \
  -w /src \
  -e RO_TEST_FILTER="${RO_TEST_FILTER:-}" \
  "$IMAGE" \
  /usr/local/openresty/bin/resty \
    --http-include /src/tests/lib/resty-http.conf \
    -I /src/lua \
    -I /src/tests/lib \
    -I /src/tests/unit \
    /src/tests/unit/run_all.lua
