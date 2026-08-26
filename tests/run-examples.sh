#!/usr/bin/env bash

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="${RO_TEST_IMAGE:-openresty/openresty:1.27.1.2-0-alpine-fat}"

PASS=0
FAIL=0
SKIP=0

ok()   { printf '    ok   %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '    FAIL %s\n         %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }
skip() { printf '    skip %s\n         %s\n' "$1" "${2:-}"; SKIP=$((SKIP + 1)); }
note() { printf '\n  %s\n' "$1"; }

printf 'Rokh Oghab examples suite\n'
printf '%s\n' "======================================================================"

note "every example policy compiles through the real policy engine"
if command -v docker >/dev/null 2>&1; then
    policies=(examples/policies/*.yaml)
    output="$(docker run --rm -v "$ROOT:/src" -w /src "$IMAGE" \
        /usr/local/openresty/bin/resty -I lua \
        tests/examples/validate-policies.lua "${policies[@]}" 2>&1)"
    rc=$?
    printf '%s\n' "$output" | grep -E '^    (ok|FAIL)' || true
    compiled="$(printf '%s' "$output" | grep -c '^    ok' || true)"
    if [ "$rc" -eq 0 ]; then
        PASS=$((PASS + compiled))
    else
        printf '%s\n' "$output" | grep -A1 '^    FAIL' || true
        FAIL=$((FAIL + 1))
    fi
else
    skip "policy compilation" "docker is not installed"
fi

note "no example policy defaults to allow"
if grep -RIl 'defaultAction:[[:space:]]*allow' examples/ >/dev/null 2>&1; then
    bad "default action" "an example policy defaults to allow"
else
    ok "every example policy defaults to deny"
fi

note "no example ships a real credential"
placeholder='replace-me'
leaked=0
while IFS= read -r line; do
    case "$line" in
        *"$placeholder"*) ;;
        *) leaked=$((leaked + 1)); printf '         %s\n' "$line" ;;
    esac
done < <(grep -RIn 'token:' examples/ 2>/dev/null \
         | grep -v 'valueFrom' \
         | grep -v 'secretKeyRef' \
         | grep -v 'RO_PROXY_TOKEN' \
         | grep -v 'tokenSecret' || true)
if [ "$leaked" -eq 0 ]; then
    ok "every token in an example is a placeholder"
else
    bad "example credentials" "$leaked literal token values found"
fi

note "every example manifest parses"
manifests=0
invalid=0
for f in examples/kubernetes/*.yaml; do
    [ -e "$f" ] || continue
    manifests=$((manifests + 1))
    if ! python3 scripts/lint-yaml.py "$f" >/dev/null 2>&1; then
        invalid=$((invalid + 1))
        printf '         %s\n' "$f"
    fi
done
if [ "$manifests" -eq 0 ]; then
    skip "example manifests" "none found"
elif [ "$invalid" -eq 0 ]; then
    ok "$manifests example manifests parse"
else
    bad "example manifests" "$invalid of $manifests do not parse"
fi

note "every example pod is hardened"
for check in \
    'privileged:[[:space:]]*true|no example asks for full privilege' \
    'hostNetwork:[[:space:]]*true|no example shares the host network' \
    'hostPID:[[:space:]]*true|no example shares the host process namespace' \
    'hostIPC:[[:space:]]*true|no example shares the host IPC namespace' \
    'automountServiceAccountToken:[[:space:]]*true|no example mounts a service account token'
do
    pattern="${check%%|*}"
    label="${check#*|}"
    if grep -RIlE "$pattern" examples/kubernetes/ >/dev/null 2>&1; then
        bad "$label" "found: $(grep -RIlE "$pattern" examples/kubernetes/ | tr '\n' ' ')"
    else
        ok "$label"
    fi
done

for required in \
    'runAsNonRoot:[[:space:]]*true|every example runs as a non-root user' \
    'readOnlyRootFilesystem:[[:space:]]*true|every example has a read-only root filesystem' \
    'allowPrivilegeEscalation:[[:space:]]*false|no example allows privilege escalation'
do
    pattern="${required%%|*}"
    label="${required#*|}"
    pods="$(grep -RIlE '^kind: (Pod|Deployment|Job)' examples/kubernetes/ 2>/dev/null | wc -l)"
    have="$(grep -RIlE "$pattern" examples/kubernetes/ 2>/dev/null | wc -l)"
    if [ "$pods" -gt 0 ] && [ "$have" -ge "$pods" ]; then
        ok "$label"
    else
        bad "$label" "$have of $pods workload manifests set it"
    fi
done

note "every example capability set drops ALL"
workloads="$(grep -RIlE '^kind: (Pod|Deployment|Job)' examples/kubernetes/ 2>/dev/null | wc -l)"
drops="$(grep -RIl 'drop: \["ALL"\]' examples/kubernetes/ 2>/dev/null | wc -l)"
if [ "$workloads" -gt 0 ] && [ "$drops" -ge "$workloads" ]; then
    ok "every workload drops all capabilities"
else
    bad "capabilities" "$drops of $workloads workload manifests drop ALL"
fi

note "every runnable example is syntactically valid"
while IFS= read -r f; do
    [ -n "$f" ] || continue
    if bash -n "$f" 2>/dev/null; then
        ok "$f parses"
    else
        bad "$f" "shell syntax error"
    fi
done < <(find examples -name '*.sh' -type f | sort)

while IFS= read -r f; do
    [ -n "$f" ] || continue
    if python3 -m py_compile "$f" 2>/dev/null; then
        ok "$f compiles"
    else
        bad "$f" "python syntax error"
    fi
done < <(find examples -name '*.py' -type f | sort)

note "the sandbox demonstration expects denials, not successes"
demo=examples/python-sandbox/sandbox_demo.py
if [ -f "$demo" ]; then
    denied="$(grep -c '"denied"' "$demo" || true)"
    blocked="$(grep -c '"blocked"' "$demo" || true)"
    if [ "$denied" -ge 3 ] && [ "$blocked" -ge 2 ]; then
        ok "the demonstration asserts refusals as expected outcomes"
    else
        bad "sandbox demonstration" \
            "expected several denied and blocked expectations, found $denied and $blocked"
    fi
fi

note "every reason the gateway can emit is documented"
undocumented=0
while IFS= read -r reason; do
    [ -n "$reason" ] || continue
    case "$reason" in
        policy.allow|client.write_failed|other) continue ;;
    esac
    if ! grep -q -- "$reason" docs/troubleshooting.md 2>/dev/null; then
        undocumented=$((undocumented + 1))
        printf '         %s\n' "$reason"
    fi
done < <(grep -oE '"[a-z_]+\.[a-z_.:-]+"' lua/ro/reasons.lua | tr -d '"' | sort -u)
if [ "$undocumented" -eq 0 ]; then
    ok "every deny reason appears in the troubleshooting guide"
else
    bad "undocumented reasons" \
        "$undocumented reason codes have no entry in docs/troubleshooting.md"
fi

note "the documentation references only examples that exist"
missing=0
while IFS= read -r ref; do
    [ -e "$ref" ] || { missing=$((missing + 1)); printf '         %s\n' "$ref"; }
done < <(grep -RhoE 'examples/[A-Za-z0-9._/-]+\.(yaml|py|sh)' docs/ README.md 2>/dev/null | sort -u)
if [ "$missing" -eq 0 ]; then
    ok "every example referenced by the documentation exists"
else
    bad "documentation references" "$missing referenced examples do not exist"
fi

printf '\n%s\n' "======================================================================"
printf 'passed=%d failed=%d skipped=%d\n' "$PASS" "$FAIL" "$SKIP"
printf '%s\n' "======================================================================"
[ "$FAIL" -eq 0 ]
