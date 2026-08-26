#!/usr/bin/env bash

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

PASS=0
FAIL=0
ok()  { printf '    ok   %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '    FAIL %s\n         %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }

json_is() {
    local file="$1" path="$2" want="$3" label="$4"
    local got
    got="$(python3 -c "
import json, sys
doc = json.load(open('$file'))
cur = doc
for part in '$path'.split('.'):
    if part:
        cur = cur.get(part) if isinstance(cur, dict) else None
        if cur is None:
            break
print(json.dumps(cur))
" 2>/dev/null)"
    if [ "$got" = "$want" ]; then
        ok "$label"
    else
        bad "$label" "$file $path is $got, expected $want"
    fi
}

grep_absent() {
    local pattern="$1" label="$2"
    shift 2
    local hit
    hit="$(grep -RIl --exclude-dir=.git -- "$pattern" "$@" 2>/dev/null | head -3)"
    if [ -z "$hit" ]; then
        ok "$label"
    else
        bad "$label" "found in: $(printf '%s ' $hit)"
    fi
}

grep_present() {
    local pattern="$1" file="$2" label="$3"
    if grep -qE -- "$pattern" "$file" 2>/dev/null; then
        ok "$label"
    else
        bad "$label" "$file no longer contains /$pattern/"
    fi
}

printf 'Rokh Oghab shipped defaults audit\n'
printf '%s\n' "======================================================================"

printf '\n  the gateway configuration that ships in the image\n'
json_is config/gateway.json identities.allowAnonymous false \
    "anonymous identities are refused"
json_is config/gateway.json guard.includeDefaults true \
    "the address guard keeps its built-in ranges"
json_is config/gateway.json guard.blockObfuscated true \
    "obfuscated address literals are refused"
json_is config/gateway.json strict.path true \
    "request paths must arrive normalised"
json_is config/gateway.json strict.sniMatch true \
    "the SNI must match the tunnel authority"
json_is config/gateway.json strict.hostMatch true \
    "the Host header must match the request target"
json_is config/gateway.json strict.redirectGuard true \
    "redirects are evaluated against policy"
json_is config/gateway.json strict.blockPlaintextOnTlsPorts true \
    "plaintext is refused on TLS ports"
json_is config/gateway.json strict.minTlsVersion '"1.2"' \
    "TLS 1.2 is the floor"
json_is config/gateway.json audit.logPaths false \
    "request paths from untrusted workloads are not written to the audit log"
json_is config/gateway.json audit.logQuery false \
    "query strings from untrusted workloads are not written to the audit log"
json_is deploy/docker/gateway.json audit.logPaths false \
    "the compose deployment does not log request paths either"
json_is deploy/docker/gateway.json audit.logQuery false \
    "the compose deployment does not log query strings either"
json_is config/gateway.json controller.failClosed true \
    "a gateway that loses its controller fails closed"
json_is config/gateway.json admin.token '""' \
    "no admin token is baked into the image"
json_is config/gateway.json admin.readerToken '""' \
    "no reader token is baked into the image either"
json_is config/gateway.json admin.operatorToken '""' \
    "no operator token is baked into the image either"
json_is config/gateway.json admin.public '["healthz", "readyz", "metrics"]' \
    "only liveness, readiness and metrics answer without a role"
json_is config/gateway.json telemetry.enabled false \
    "tracing is off until an operator turns it on"
json_is config/gateway.json telemetry.endpoint '""' \
    "no collector address is baked into the image"
json_is config/gateway.json telemetry.trustIncomingTrace false \
    "a workload does not get to choose the trace it is recorded under"
json_is config/gateway.json telemetry.recordDestination false \
    "destinations are not written into spans by default"
json_is config/gateway.json admin.allowFrom '["127.0.0.1/32", "::1/128"]' \
    "the admin listener answers only the loopback address"
json_is config/gateway.json dns.allowedTypes '["A", "AAAA"]' \
    "only address records are served, so DNS cannot carry a tunnel"
json_is config/gateway.json dns.denyResponse '"nxdomain"' \
    "a denied name simply does not resolve"

trusted="$(python3 -c "
import json
doc = json.load(open('config/gateway.json'))
print(len((doc.get('identities') or {}).get('trustedHeaderSources') or []))
")"
if [ "$trusted" = "0" ]; then
    ok "no source may assert its own identity through a header"
else
    bad "trusted header sources" "$trusted sources may assert their own identity"
fi

printf '\n  a control that cannot be enforced refuses rather than passes\n'
if grep -q 'limit.unavailable' lua/ro/limits.lua; then
    ok "a configured limit denies when its store is unreachable"
else
    bad "limit fail-closed" "limits.lua has no unavailable path"
fi
if grep -q 'the store lock is unavailable' lua/roc/store.lua; then
    ok "the control plane refuses to write without its lock"
else
    bad "store lock fail-closed" "store.lua still writes without a lock"
fi
if grep -q 'safe_data_dir' lua/roc/store.lua; then
    ok "the control-plane data directory is validated before any shell use"
else
    bad "data directory validation" "store.lua interpolates dataDir unchecked"
fi

printf '\n  the gateway does not trust what a workload says about itself\n'
if grep -q 'ASSERTED_PREFIX' lua/ro/http.lua; then
    ok "identity headers from a workload are stripped before forwarding"
else
    bad "identity header stripping" "x-ro-* headers are forwarded to destinations"
fi
if grep -q 'reasons.label' lua/ro/proxy.lua; then
    ok "metric labels are drawn from a closed catalogue"
else
    bad "metric label bounding" "proxy.lua labels metrics with raw reasons"
fi

empty_allow="$(grep -RIl '"allowFrom": \[\]' config/gateway.json deploy 2>/dev/null | head -3)"
if [ -z "$empty_allow" ]; then
    ok "no shipped gateway leaves its admin source list empty"
else
    bad "admin source list" "empty allowFrom in: $(printf '%s ' $empty_allow)"
fi
if grep -q 'unrestricted_sources' lua/roc/api.lua; then
    ok "an unrestricted control-plane source list is a deliberate, logged choice"
else
    bad "control-plane source list" "an empty allowFrom passes silently"
fi
if grep -q 'allow_set:size() == 0' lua/ro/adminapi.lua; then
    ok "an empty gateway admin source list refuses rather than admits"
else
    bad "gateway admin source list" "an empty allowFrom admits every source"
fi

printf '\n  one workload cannot take the gateway down for the others\n'
if grep -q 'maxConnectionsPerSource' lua/ro/config.lua; then
    ok "connections are capped per source before anything is parsed"
else
    bad "per-source cap" "one source may consume every global connection slot"
fi
if grep -q 'headTimeoutMs' lua/ro/config.lua; then
    ok "an unfinished request head is dropped on its own short budget"
else
    bad "head timeout" "a partial request head is held for the full client timeout"
fi
json_is config/gateway.json limits.maxConnectionsPerSource 256 \
    "the shipped per-source cap is set"

printf '\n  a setting that reads as strict cannot behave as permissive\n'
if grep -q 'maxStalenessSeconds must be greater' lua/ro/policy.lua; then
    ok "a zero staleness budget is refused instead of disabling the check"
else
    bad "staleness budget" "maxStalenessSeconds of 0 silently disables staleness"
fi
if grep -q 'reject_empty_list' lua/ro/policy.lua; then
    ok "an empty constraint list is refused instead of meaning 'any'"
else
    bad "empty constraint lists" "protocols: [] silently means every protocol"
fi

printf '\n  the policy bundle that ships in the image\n'
json_is config/bootstrap-bundle.json version 0 \
    "the bundle announces that nothing has been published yet"
json_is config/bootstrap-bundle.json emergencyDeny false \
    "the emergency switch starts lifted"
json_is config/bootstrap-bundle.json identities.allowAnonymous false \
    "the bundle grants no anonymous identity"

allow_rules="$(python3 -c "
import json
doc = json.load(open('config/bootstrap-bundle.json'))
count = 0
for policy in doc.get('policies', []):
    for rule in policy.get('rules', []):
        if rule.get('action') == 'allow':
            count += 1
print(count)
")"
if [ "$allow_rules" = "0" ]; then
    ok "the shipped bundle contains no allow rule at all"
else
    bad "shipped allow rules" "$allow_rules allow rules ship by default"
fi

tokens="$(python3 -c "
import json
doc = json.load(open('config/bootstrap-bundle.json'))
print(len(doc.get('identities', {}).get('tokens', {})))
")"
if [ "$tokens" = "0" ]; then
    ok "no identity ships with the image"
else
    bad "shipped identities" "$tokens tokens ship by default"
fi

printf '\n  the controller configuration that ships in the image\n'
principals="$(python3 -c "
import json
print(len(json.load(open('config/controller.json')).get('principals', [])))
")"
if [ "$principals" = "0" ]; then
    ok "no control-plane principal ships with the image"
else
    bad "shipped principals" "$principals principals ship by default"
fi

printf '\n  no credential is committed anywhere\n'
PEM_BEGIN="-----BEGIN"
KEY_SUFFIX="PRIVATE KEY-----"

grep_absent "${PEM_BEGIN} RSA ${KEY_SUFFIX}" "no PKCS#1 private key is committed" \
    config deploy lua bin openresty nginx.conf 2>/dev/null
grep_absent "${PEM_BEGIN} ${KEY_SUFFIX}" "no PKCS#8 private key is committed" \
    config deploy lua bin openresty nginx.conf 2>/dev/null
grep_absent "${PEM_BEGIN} OPENSSH ${KEY_SUFFIX}" "no SSH private key is committed" \
    config deploy lua bin openresty nginx.conf scripts tests .github 2>/dev/null
grep_absent "${PEM_BEGIN} EC ${KEY_SUFFIX}" "no elliptic curve private key is committed" \
    config deploy lua bin openresty nginx.conf 2>/dev/null

printf '\n  the Helm chart defaults\n'
if command -v helm >/dev/null 2>&1; then
    rendered="$(helm template ro deploy/helm/rokh-oghab 2>/dev/null)"
    check_rendered() {
        local pattern="$1" label="$2"
        if grep -q -- "$pattern" <<<"$rendered"; then
            ok "$label"
        else
            bad "$label" "expected to find: $pattern"
        fi
    }
    check_absent_rendered() {
        local pattern="$1" label="$2"
        if grep -q -- "$pattern" <<<"$rendered"; then
            bad "$label" "unexpectedly found: $pattern"
        else
            ok "$label"
        fi
    }
    check_rendered '"allowAnonymous": false' "anonymous identities are refused"
    check_rendered '"blockObfuscated": true' "obfuscated literals are refused"
    check_rendered '"failClosed": true' "the gateway fails closed without a controller"
    check_rendered 'policyTypes' "network policies are installed"
    check_rendered 'runAsNonRoot: true' "workloads run as a non-root user"
    check_rendered 'readOnlyRootFilesystem: true' "root filesystems are read-only"
    check_rendered 'automountServiceAccountToken: false' \
        "service account tokens are not mounted"
    check_absent_rendered 'privileged: true' "no container asks for full privilege"
    check_absent_rendered 'hostPID: true' "no container shares the host process namespace"
    check_absent_rendered '"defaultAction": "allow"' "no policy defaults to allow"
else
    printf '    skip helm is not installed\n'
fi

printf '\n  the policy engine refuses to compile an unsafe policy\n'
if command -v docker >/dev/null 2>&1; then
    unit_output="$(env -u RO_TEST_FILTER bash tests/run-unit.sh 2>/dev/null)"
    unit_status=$?
    if [ "$unit_status" -eq 0 ]; then
        ok "the whole unit suite passes"
    else
        bad "unit suite" "run-unit.sh exited $unit_status"
    fi
    if printf '%s' "$unit_output" | grep -qE '^ *ok +refuses defaultAction allow'; then
        ok "a policy that defaults to allow is rejected by the compiler"
    else
        bad "compiler default-allow check" \
            "the unit suite did not report that test passing"
    fi
    executed="$(printf '%s' "$unit_output" \
        | sed -n 's/^passed=\([0-9][0-9]*\).*/\1/p' | tail -1)"
    if [ -n "$executed" ] && [ "$executed" -ge 300 ]; then
        ok "the unit suite actually ran ($executed tests)"
    else
        bad "unit suite size" \
            "only ${executed:-0} tests ran, so a clean result proves little"
    fi
else
    printf '    skip docker is not installed\n'
fi

printf '\n  the gateway can reach and trust its control plane\n'

grep_present 'bridge-nf-call-iptables' bin/ro-agent \
    "the agent notices when bridged sandbox traffic would bypass the ruleset"
grep_present 'RO_ENFORCE_BRIDGE_NF:-true' bin/ro-agent \
    "bridge netfilter is enforced unless an operator turns it off"

grep_present '^\s*resolver local=on' nginx.conf \
    "the stream block resolves names, so a controller url may be a hostname"
grep_present '^\s*lua_ssl_trusted_certificate' nginx.conf \
    "a trust store is configured, so an https control plane can be verified"
grep_present 'env RO_CONTROLLER_SIGNING_KEY' nginx.conf \
    "the bundle signing key reaches the gateway configuration"
grep_present 'env RO_CONTROLLER_REQUIRE_SIGNATURE' nginx.conf \
    "the signature requirement reaches the gateway configuration"
grep_present 'RO_CONTROLLER_BUNDLE_SIGNING_KEY' openresty/controller.conf \
    "the bundle signing key reaches the controller configuration"

json_is config/gateway.json controller.tlsVerify true \
    "the gateway verifies an https control-plane certificate by default"
json_is config/gateway.json controller.signingKey '""' \
    "no bundle signing key is baked into the shipped configuration"
json_is config/controller.json bundleSigningKey '""' \
    "no bundle signing key is baked into the shipped controller configuration"

printf '\n%s\n' "======================================================================"
printf 'passed=%d failed=%d\n' "$PASS" "$FAIL"
printf '%s\n' "======================================================================"
[ "$FAIL" -eq 0 ]
