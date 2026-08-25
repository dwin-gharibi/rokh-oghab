#!/usr/bin/env bash
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAIL=0

run_tool() {
    tool="$1"
    dir="$2"
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "  skip  $tool is not installed"
        return 0
    fi
    echo "==> $tool fmt/validate in $dir"
    ( cd "$dir" && "$tool" fmt -check -recursive ) || FAIL=1
    ( cd "$dir" && "$tool" init -backend=false -input=false >/dev/null 2>&1 \
        && "$tool" validate ) || FAIL=1
}

run_tool terraform "$ROOT/deploy/terraform/modules/rokh-oghab-k8s"
run_tool tofu "$ROOT/deploy/opentofu"
exit $FAIL
