#!/usr/bin/env bash

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

BASELINE="tests/coverage-baseline.txt"

PASS=0
FAIL=0
ok()  { printf '    ok   %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '    FAIL %s\n         %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }

count_unit() {
    local total=0 name
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        [ -f "tests/unit/$name.lua" ] || continue
        total=$((total + $(grep -c 'h\.it(' "tests/unit/$name.lua" 2>/dev/null)))
    done < <(sed -n 's/^ *"\(test_[a-z_]*\)",.*/\1/p' tests/unit/run_all.lua)
    printf '%s' "$total"
}

count_unit_files() {
    sed -n 's/^ *"\(test_[a-z_]*\)",.*/\1/p' tests/unit/run_all.lua | wc -l | tr -d ' '
}
count_e2e() {
    grep -c '^@test(' tests/e2e/driver.py 2>/dev/null | tr -d ' '
}
count_security() {
    grep -c '^@test(' tests/e2e/security_driver.py 2>/dev/null | tr -d ' '
}
count_control() {
    grep -c '^@test(' tests/e2e/controller_driver.py 2>/dev/null | tr -d ' '
}
count_cli() {
    grep -c '^@test(' tests/e2e/cli_driver.py 2>/dev/null | tr -d ' '
}
count_agent() {
    grep -hoE '^expect_[a-z_]+' tests/run-agent.sh 2>/dev/null | wc -l | tr -d ' '
}
count_enforcement() {
    grep -hoE '^ *ok "' tests/enforcement/run.sh 2>/dev/null | wc -l | tr -d ' '
}
count_bypass() {
    grep -hoE '^escape_blocked' tests/enforcement/bypass.sh 2>/dev/null \
        | wc -l | tr -d ' '
}
count_defaults() {
    grep -hoE '^(json_is|grep_absent|    ok "|    check_rendered|    check_absent_rendered)' \
        tests/run-defaults-audit.sh 2>/dev/null | wc -l | tr -d ' '
}
count_examples() {
    ls examples/policies/*.yaml 2>/dev/null | wc -l | tr -d ' '
}

SUITES="unit unit_files e2e security control cli agent enforcement bypass defaults examples"

measure() {
    for suite in $SUITES; do
        printf '%s=%s\n' "$suite" "$(count_"$suite")"
    done
}

if [ "${1:-}" = "--update" ]; then
    {
        printf '# Test counts that must never decrease.\n'
        printf '# Regenerate with: bash tests/run-ratchet.sh --update\n'
        measure
    } > "$BASELINE"
    printf 'wrote %s\n' "$BASELINE"
    cat "$BASELINE"
    exit 0
fi

printf 'Rokh Oghab coverage ratchet\n'
printf '%s\n' "======================================================================"

if [ ! -f "$BASELINE" ]; then
    printf '\n  no baseline found; create one with:\n'
    printf '    bash tests/run-ratchet.sh --update\n'
    exit 1
fi

printf '\n  %-12s %8s %8s\n' "suite" "baseline" "now"

grew=0
while IFS='=' read -r suite want; do
    case "$suite" in ''|\#*) continue ;; esac
    got="$(count_"$suite" 2>/dev/null)"
    if [ -z "$got" ]; then
        bad "$suite" "could not count this suite"
        continue
    fi
    printf '  %-12s %8s %8s' "$suite" "$want" "$got"
    if [ "$got" -lt "$want" ]; then
        printf '  <- SHRANK\n'
        bad "$suite" "the count fell from $want to $got"
    elif [ "$got" -gt "$want" ]; then
        printf '  <- grew\n'
        grew=$((grew + 1))
        PASS=$((PASS + 1))
    else
        printf '\n'
        PASS=$((PASS + 1))
    fi
done < "$BASELINE"

if [ "$grew" -gt 0 ]; then
    printf '\n  %d suite(s) grew. Record that in the same commit as the new tests:\n' "$grew"
    printf '    bash tests/run-ratchet.sh --update\n'
fi

printf '\n%s\n' "======================================================================"
printf 'passed=%d failed=%d\n' "$PASS" "$FAIL"
printf '%s\n' "======================================================================"
[ "$FAIL" -eq 0 ]
