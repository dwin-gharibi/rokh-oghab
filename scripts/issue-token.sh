#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ENDPOINT="${ROCTL_ENDPOINT:-http://127.0.0.1:18081}"
TOKEN="${ROCTL_TOKEN:-}"
NAMESPACE="${RO_NAMESPACE:-execution}"
PROFILE="${RO_PROFILE:-untrusted-python}"
SERVICE_ACCOUNT="${RO_SERVICE_ACCOUNT:-sandbox-runner}"
IDENTITY="${RO_IDENTITY:-}"

if [ -z "$TOKEN" ]; then
    echo "set ROCTL_TOKEN to a controller operator or admin token" >&2
    exit 1
fi

args=(identity issue --namespace "$NAMESPACE" --profile "$PROFILE"
      --service-account "$SERVICE_ACCOUNT")
[ -n "$IDENTITY" ] && args+=(--id "$IDENTITY")

ROCTL_ENDPOINT="$ENDPOINT" ROCTL_TOKEN="$TOKEN" "$ROOT/bin/roctl" "${args[@]}"

echo
echo "Publish the change so gateways pick it up:"
echo "  ROCTL_ENDPOINT=$ENDPOINT ROCTL_TOKEN=... $ROOT/bin/roctl publish"
