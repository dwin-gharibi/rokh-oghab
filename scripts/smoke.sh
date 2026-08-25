#!/usr/bin/env bash
set -uo pipefail

PROXY="${RO_PROXY:-http://127.0.0.1:13128}"
ADMIN="${RO_ADMIN:-http://127.0.0.1:19145}"
TOKEN="${RO_TOKEN:-ro-e2e-python-token-0000000001}"
ADMIN_TOKEN="${RO_ADMIN_TOKEN:-ro-e2e-admin-token-000000000001}"
ALLOWED="${RO_ALLOWED_URL:-http://allowed.test/}"
DENIED="${RO_DENIED_URL:-http://denied.test/}"

PASS=0
FAIL=0
ok()  { printf '  ok   %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL %s\n       %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }

curl_proxy() {
    curl -sS --max-time 10 --noproxy '' -x "$PROXY" \
        -H "Proxy-Authorization: Bearer $TOKEN" -o /dev/null -w '%{http_code}' "$1"
}

echo "Rokh Oghab smoke check"
echo "  proxy $PROXY"
echo

code="$(curl -sS --max-time 5 --noproxy '*' -o /dev/null -w '%{http_code}' "$ADMIN/healthz")"
[ "$code" = "200" ] && ok "the gateway reports healthy" \
    || bad "gateway health" "got HTTP $code"

code="$(curl -sS --max-time 5 --noproxy '*' -o /dev/null -w '%{http_code}' "$ADMIN/readyz")"
[ "$code" = "200" ] && ok "the gateway reports ready" \
    || bad "gateway readiness" "got HTTP $code"

code="$(curl_proxy "$ALLOWED")"
[ "$code" = "200" ] && ok "a permitted destination is reachable" \
    || bad "permitted destination" "got HTTP $code"

code="$(curl_proxy "$DENIED")"
[ "$code" = "403" ] && ok "a denied destination is refused" \
    || bad "denied destination" "expected 403, got HTTP $code"

code="$(curl_proxy "http://169.254.169.254/")"
[ "$code" = "403" ] && ok "cloud metadata is refused" \
    || bad "metadata" "expected 403, got HTTP $code"

code="$(curl -sS --max-time 10 --noproxy '' -x "$PROXY" -o /dev/null \
    -w '%{http_code}' "$ALLOWED")"
[ "$code" = "407" ] && ok "an unauthenticated request is refused" \
    || bad "unauthenticated request" "expected 407, got HTTP $code"

if curl -sS --max-time 5 --noproxy '*' "$ADMIN/metrics" | grep -q ro_requests_total; then
    ok "metrics are exposed"
else
    bad "metrics" "ro_requests_total was not found"
fi

echo
printf 'passed=%d failed=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
