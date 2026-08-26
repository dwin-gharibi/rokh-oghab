#!/usr/bin/env bash
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$(id -u)" != "0" ] || ! command -v nft >/dev/null 2>&1; then
    echo "the sandbox demo suite needs root and nft; skipping" >&2
    exit 77
fi

exec bash "$ROOT/examples/docker/enforced-sandbox.sh"
