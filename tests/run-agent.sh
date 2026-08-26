#!/usr/bin/env bash
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT="$ROOT/bin/ro-agent"
PASS=0
FAIL=0

ok()  { printf '    ok   %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '    FAIL %s\n         %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }

expect_valid() {
    local name="$1"; shift
    if out=$(env "$@" "$AGENT" check 2>&1); then
        ok "$name"
    else
        bad "$name" "$out"
    fi
}

expect_rejected() {
    local name="$1"; shift
    if out=$(env "$@" "$AGENT" check 2>&1); then
        bad "$name" "accepted but should have been rejected"
    else
        ok "$name"
    fi
}

ruleset_of() {
    env "$@" "$AGENT" print 2>/dev/null
}

expect_contains() {
    local name="$1" needle="$2"; shift 2
    local out
    out="$(ruleset_of "$@")"
    if [ -z "$out" ]; then
        bad "$name" "the agent produced no ruleset at all"
    elif printf '%s' "$out" | grep -F -- "$needle" >/dev/null; then
        ok "$name"
    else
        bad "$name" "expected the ruleset to contain: $needle"
    fi
}

expect_absent() {
    local name="$1" needle="$2"; shift 2
    local out
    out="$(ruleset_of "$@")"
    if [ -z "$out" ]; then
        bad "$name" "the agent produced no ruleset at all"
    elif printf '%s' "$out" | grep -F -- "$needle" >/dev/null; then
        bad "$name" "the ruleset must not contain: $needle"
    else
        ok "$name"
    fi
}

printf 'Rokh Oghab node agent suite\n'
printf '%s\n' "======================================================================"

printf '\n  syntax\n'
if sh -n "$AGENT"; then ok "the agent is valid POSIX shell"; else bad "posix syntax"; fi

printf '\n  ruleset generation\n'
BASE=(RO_GATEWAY_ADDR=10.99.0.5 RO_SANDBOX_CIDRS=10.244.0.0/16)
if ! command -v nft >/dev/null 2>&1; then
    printf '    skip nft validation (nft is not installed)\n'
else
    expect_valid "a minimal ruleset is valid" "${BASE[@]}"
    expect_valid "multiple sandbox ranges are valid" \
        RO_GATEWAY_ADDR=10.99.0.5 "RO_SANDBOX_CIDRS=10.244.0.0/16, 10.245.0.0/16"
    expect_valid "an allow list is valid" "${BASE[@]}" RO_ALLOW_CIDRS=10.96.0.10/32
    expect_valid "transparent mode is valid" "${BASE[@]}" RO_TRANSPARENT=true
    expect_valid "the output hook is valid" "${BASE[@]}" RO_HOOK=output
    expect_valid "both hooks are valid" "${BASE[@]}" RO_HOOK=both
    expect_valid "drop logging is valid" "${BASE[@]}" RO_LOG_DROPS=true
    expect_valid "custom ports are valid" "${BASE[@]}" RO_PROXY_PORT=8888 RO_DNS_PORT=15353
    expect_valid "ipv6 passthrough is valid" "${BASE[@]}" RO_BLOCK_IPV6=false
    expect_valid "every option together is valid" \
        RO_GATEWAY_ADDR=10.99.0.5 "RO_SANDBOX_CIDRS=10.244.0.0/16,10.245.0.0/16" \
        RO_ALLOW_CIDRS=10.96.0.10/32 RO_TRANSPARENT=true RO_HOOK=both \
        RO_LOG_DROPS=true RO_BLOCK_IPV6=true RO_TABLE=custom_table
fi

printf '\n  fail-closed content\n'
expect_contains "the sandbox chain ends in a drop" "counter drop" "${BASE[@]}"
expect_contains "the proxy port is reachable" "tcp dport 3128 counter accept" "${BASE[@]}"
expect_contains "DNS over UDP is reachable" "udp dport 5353 counter accept" "${BASE[@]}"
expect_contains "IPv6 egress is dropped by default" "meta nfproto ipv6" "${BASE[@]}"
expect_absent "the admin port is never opened" "dport 9145" "${BASE[@]}"
expect_absent "no blanket accept is emitted" "policy accept; counter accept" "${BASE[@]}"
expect_contains "transparent mode redirects 443" "tcp dport 443 counter dnat" \
    "${BASE[@]}" RO_TRANSPARENT=true
expect_absent "transparent redirects are absent by default" "dnat to" "${BASE[@]}"
expect_contains "drop logging is applied when requested" "rokh-oghab-drop" \
    "${BASE[@]}" RO_LOG_DROPS=true

printf '\n  input validation\n'
expect_rejected "a missing gateway address is rejected" RO_SANDBOX_CIDRS=10.0.0.0/8
expect_rejected "missing sandbox ranges are rejected" RO_GATEWAY_ADDR=10.0.0.1
expect_rejected "a non-numeric gateway address is rejected" \
    RO_GATEWAY_ADDR=evil.example.com RO_SANDBOX_CIDRS=10.0.0.0/8
expect_rejected "a shell metacharacter in the ranges is rejected" \
    RO_GATEWAY_ADDR=10.0.0.1 'RO_SANDBOX_CIDRS=10.0.0.0/8; rm -rf /'
expect_rejected "a command substitution in the ranges is rejected" \
    RO_GATEWAY_ADDR=10.0.0.1 'RO_SANDBOX_CIDRS=$(id)'
expect_rejected "a bare word in the ranges is rejected" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=everything
expect_rejected "an out-of-range port is rejected" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 RO_PROXY_PORT=99999
expect_rejected "a zero port is rejected" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 RO_PROXY_PORT=0
expect_rejected "a non-numeric port is rejected" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 RO_DNS_PORT=abc
expect_rejected "an unknown hook is rejected" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 RO_HOOK=evil
expect_rejected "a table name with punctuation is rejected" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 'RO_TABLE=a;b'
expect_rejected "an invalid allow-list entry is rejected" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 'RO_ALLOW_CIDRS=drop table'

printf '\n  ipv6 is either scoped or refused, never silently unfiltered\n'
expect_rejected "an ipv6-enabled host with no ipv6 scope is refused" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 RO_IPV6_PRESENT=yes
expect_contains "an ipv6 sandbox range populates the ipv6 set" "fd00:10:244::/48" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 RO_IPV6_PRESENT=yes \
    RO_SANDBOX_CIDRS6=fd00:10:244::/48
expect_contains "ipv6 sandbox traffic reaches the egress chain" \
    "ip6 saddr @ro_sandbox6 jump sandbox_egress" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 RO_IPV6_PRESENT=yes \
    RO_SANDBOX_CIDRS6=fd00:10:244::/48
expect_contains "ipv6 sandbox traffic is dropped once it gets there" \
    "meta nfproto ipv6" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 RO_IPV6_PRESENT=yes \
    RO_SANDBOX_CIDRS6=fd00:10:244::/48
expect_contains "sandbox interfaces are an acceptable ipv6 scope" "iifname" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 RO_IPV6_PRESENT=yes \
    RO_SANDBOX_IFACES=veth0
expect_contains "a host without ipv6 needs no ipv6 scope" "ro_sandbox6" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 RO_IPV6_PRESENT=no
expect_contains "unfiltered ipv6 can be accepted deliberately" "ro_sandbox" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 RO_IPV6_PRESENT=yes \
    RO_IPV6_UNSCOPED=allow
expect_rejected "a malformed ipv6 sandbox range is rejected" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8 \
    'RO_SANDBOX_CIDRS6=; rm -rf /'

printf '\n  a malformed gateway address is caught before it reaches nftables\n'
expect_rejected "a five-octet gateway address is rejected" \
    RO_GATEWAY_ADDR=1.2.3.4.5 RO_SANDBOX_CIDRS=10.0.0.0/8
expect_rejected "a three-octet gateway address is rejected" \
    RO_GATEWAY_ADDR=1.2.3 RO_SANDBOX_CIDRS=10.0.0.0/8
expect_rejected "an out-of-range octet is rejected" \
    RO_GATEWAY_ADDR=999.1.1.1 RO_SANDBOX_CIDRS=10.0.0.0/8
expect_rejected "an octal-looking octet is rejected" \
    RO_GATEWAY_ADDR=010.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8
expect_rejected "an empty octet is rejected" \
    RO_GATEWAY_ADDR=1..2.3 RO_SANDBOX_CIDRS=10.0.0.0/8
expect_rejected "a bare dot is rejected" \
    RO_GATEWAY_ADDR=.... RO_SANDBOX_CIDRS=10.0.0.0/8
expect_contains "a well formed gateway address is accepted" "10.0.0.1" \
    RO_GATEWAY_ADDR=10.0.0.1 RO_SANDBOX_CIDRS=10.0.0.0/8
expect_contains "the broadcast-looking but valid address is accepted" "255.255.255.255" \
    RO_GATEWAY_ADDR=255.255.255.255 RO_SANDBOX_CIDRS=10.0.0.0/8

printf '\n%s\n' "======================================================================"
printf 'passed=%d failed=%d\n' "$PASS" "$FAIL"
printf '%s\n' "======================================================================"
[ "$FAIL" -eq 0 ]
