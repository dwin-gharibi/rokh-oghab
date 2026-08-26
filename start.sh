#!/bin/sh
set -eu

ROLE="${RO_ROLE:-gateway}"
NGINX_CONF="${RO_NGINX_CONF:-/usr/local/rokh-oghab/nginx.conf}"
NGINX_PREFIX="${RO_NGINX_PREFIX:-/usr/local/openresty/nginx}"
NGINX_BIN="${RO_NGINX_BIN:-/usr/local/openresty/nginx/sbin/nginx}"
RESTY_BIN="${RO_RESTY_BIN:-/usr/local/openresty/bin/resty}"

log() {
    printf '{"component":"ro-start","level":"%s","role":"%s","msg":"%s"}\n' \
        "$1" "$ROLE" "$2" >&2
}

die() {
    log error "$1"
    exit 1
}

validate_json() {
    path="$1"
    label="$2"
    [ -f "$path" ] || die "$label is missing at $path"
    "$RESTY_BIN" -e '
        local cjson = require("cjson.safe")
        local path = os.getenv("RO_VALIDATE_PATH")
        local fh = io.open(path, "r")
        if not fh then os.exit(3) end
        local body = fh:read("*a")
        fh:close()
        local parsed, err = cjson.decode(body)
        if not parsed then
            io.stderr:write(tostring(err), "\n")
            os.exit(4)
        end
    ' >/dev/null 2>&1 || die "$label at $path is not valid JSON"
}

preflight() {
    [ -x "$NGINX_BIN" ] || die "openresty is not present at $NGINX_BIN"
    [ -f "$NGINX_CONF" ] || die "nginx configuration is missing at $NGINX_CONF"

    case "$ROLE" in
        gateway)
            RO_VALIDATE_PATH="${RO_CONFIG:-/etc/rokh-oghab/gateway.json}" \
                validate_json "${RO_CONFIG:-/etc/rokh-oghab/gateway.json}" \
                "the gateway configuration"
            bundle="${RO_BUNDLE_FILE:-/etc/rokh-oghab/bundle.json}"
            if [ -f "$bundle" ]; then
                RO_VALIDATE_PATH="$bundle" validate_json "$bundle" "the policy bundle"
            else
                log warn "no local policy bundle; starting fail-closed"
            fi
            if [ -z "${RO_ADMIN_TOKEN:-}" ]; then
                log warn "RO_ADMIN_TOKEN is unset; privileged admin endpoints will refuse every request"
            fi
            ;;
        controller)
            conf="${RO_CONTROLLER_CONFIG:-/etc/rokh-oghab/controller.json}"
            RO_VALIDATE_PATH="$conf" validate_json "$conf" "the controller configuration"
            if [ -z "${RO_CONTROLLER_ADMIN_TOKEN:-}" ] \
                && [ -z "${RO_CONTROLLER_OPERATOR_TOKEN:-}" ]; then
                log warn "no bootstrap tokens set; every authenticated endpoint will refuse access"
            fi
            ;;
        *)
            die "RO_ROLE must be gateway or controller, got '$ROLE'"
            ;;
    esac

    "$NGINX_BIN" -t -c "$NGINX_CONF" -p "$NGINX_PREFIX" >/dev/null 2>&1 \
        || die "the nginx configuration failed validation"
}

healthcheck() {
    RO_HEALTH_PORT="${1:-9145}"
    export RO_HEALTH_PORT
    "$RESTY_BIN" -e '
        local sock = ngx.socket.tcp()
        sock:settimeout(2000)
        local port = tonumber(os.getenv("RO_HEALTH_PORT")) or 9145
        local ok = sock:connect("127.0.0.1", port)
        if not ok then os.exit(1) end
        sock:send("GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        local line = sock:receive("*l")
        sock:close()
        if not line or not line:find("200", 1, true) then os.exit(1) end
    ' >/dev/null 2>&1
}

case "${1:-serve}" in
    serve)
        preflight
        log info "configuration validated, starting"
        exec "$NGINX_BIN" -c "$NGINX_CONF" -p "$NGINX_PREFIX"
        ;;
    check)
        preflight
        log info "configuration is valid"
        ;;
    healthcheck)
        RO_HEALTH_PORT="${2:-9145}"
        export RO_HEALTH_PORT
        healthcheck "$RO_HEALTH_PORT"
        ;;
    shell)
        exec /bin/sh
        ;;
    *)
        exec "$@"
        ;;
esac
