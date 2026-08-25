local http = require("ro.http")
local reader_mod = require("ro.reader")
local target_mod = require("ro.target")
local tls = require("ro.tls")
local limits = require("ro.limits")
local metrics = require("ro.metrics")
local log = require("ro.log")
local util = require("ro.util")
local state = require("ro.state")
local identity_mod = require("ro.identity")
local ipaddr_mod = require("ro.ipaddr")
local reasons = require("ro.reasons")
local otel = require("ro.otel")

local _M = { _VERSION = "1.0.0" }

local format = string.format
local concat = table.concat
local sub = string.sub
local find = string.find
local lower = string.lower
local min = math.min

local BUF = 65536
local PEEK_TIMEOUT_MS = 700
local MAX_PEEK = 16384
local MAX_TRAILERS = 32
local MAX_TRAILER_LINE = 4096
local MAX_TRAILER_BYTES = 8192
local MAX_INTERIM_RESPONSES = 8

local DENY_STATUS = {
    ["identity.unknown"] = 407,
    ["identity.invalid_token"] = 407,
    ["identity.malformed_credentials"] = 407,
    ["limit.rate"] = 429,
    ["limit.connections"] = 429,
    ["limit.global_connections"] = 503,
    ["limit.source_connections"] = 429,
    ["policy.resolved_cidr"] = 403,
    ["dns.all_answers_blocked"] = 403,
    ["dns.no_permitted_address"] = 403,
    ["dns.invalid_name"] = 400,
    ["dns.qtype_not_allowed"] = 403,
    ["dns.nxdomain"] = 502,
    ["dns.server_failure"] = 502,
    ["dns.refused"] = 502,
    ["dns.not_implemented"] = 502,
    ["dns.malformed_query"] = 502,
    ["dns.malformed_answer"] = 502,
    ["dns.answer_mismatch"] = 502,
    ["dns.unreachable"] = 502,
    ["dns.timeout"] = 504,
    ["dns.no_entropy"] = 503,
    ["dns.failed"] = 502,
    ["dns.no_address"] = 502,
    ["dns.ipv6_disabled"] = 403,
    ["limit.unavailable"] = 503,
    ["policy.stale"] = 503,
    ["policy.not_loaded"] = 503,
    ["emergency.deny"] = 403,
}

local function status_for(reason)
    return DENY_STATUS[reason] or 403
end

local function is_tls_port(conf, port)
    local list = conf.strict and conf.strict.tlsPorts
    if type(list) ~= "table" or #list == 0 then
        return port == 443
    end
    for i = 1, #list do
        if tonumber(list[i]) == port then
            return true
        end
    end
    return false
end

local function new_ctx(conf, mode)
    return {
        id = util.gen_id(),
        conf = conf,
        mode = mode,
        started = util.monotonic(),
        remote_addr = ngx.var.remote_addr,
        remote_port = tonumber(ngx.var.remote_port) or 0,
        bytes_sent = 0,
        bytes_received = 0,
        requests = 0,
    }
end

local function finish_span(ctx, fields)
    local span = ctx.span
    if not span then
        return
    end
    ctx.span = nil
    local denied = fields.action == "deny"
    otel.attr(span, "ro.node", ctx.conf.node)
    otel.attr(span, "ro.mode", ctx.mode)
    otel.attr(span, "ro.protocol", ctx.protocol)
    otel.attr(span, "ro.decision", fields.action or "allow")
    otel.attr(span, "ro.policy_version", ctx.policy_version)
    otel.attr(span, "ro.identity", ctx.identity and ctx.identity.id or nil)
    otel.attr(span, "ro.namespace",
        ctx.identity and ctx.identity.namespace or nil)
    otel.attr(span, "ro.profile", ctx.identity and ctx.identity.profile or nil)
    otel.attr(span, "ro.bytes_sent", ctx.bytes_sent)
    otel.attr(span, "ro.bytes_received", ctx.bytes_received)
    if denied then
        otel.attr(span, "ro.reason", reasons.label(fields.reason))
    end
    if otel.config().recordDestination then
        otel.attr(span, "ro.destination", fields.destination)
        otel.attr(span, "ro.port", fields.port)
    end
    otel.finish(span, denied and otel.STATUS_ERROR or otel.STATUS_OK,
        denied and reasons.label(fields.reason) or nil)
end

local function audit(ctx, fields)
    finish_span(ctx, fields)
    local ev = {
        event = fields.event or "request",
        request_id = ctx.id,
        node = ctx.conf.node,
        mode = ctx.mode,
        client = ctx.remote_addr,
        client_port = ctx.remote_port,
        identity = ctx.identity and ctx.identity.id or nil,
        namespace = ctx.identity and ctx.identity.namespace or nil,
        profile = ctx.identity and ctx.identity.profile or nil,
        service_account = ctx.identity and ctx.identity.serviceAccount or nil,
        policy_version = ctx.policy_version,
    }
    for k, v in pairs(fields) do
        ev[k] = v
    end
    log.audit(ev)
end

local function label_set(ctx, extra)
    local l = {
        profile = ctx.identity and ctx.identity.profile or "-",
        namespace = ctx.identity and ctx.identity.namespace or "-",
    }
    if extra then
        for k, v in pairs(extra) do l[k] = v end
    end
    return l
end

local function send_all(sock, data)
    local sent, err = sock:send(data)
    if not sent then
        return nil, err
    end
    return sent
end

local function deny_response(status, reason, detail)
    local public = reasons.public(reason)
    local body = format(
        '{"error":"forbidden_by_rokh_oghab","reason":%q,"detail":%q}',
        public, util.safe_str(detail or "", 200))
    local phrase = "Forbidden"
    if status == 407 then phrase = "Proxy Authentication Required"
    elseif status == 429 then phrase = "Too Many Requests"
    elseif status == 502 then phrase = "Bad Gateway"
    elseif status == 503 then phrase = "Service Unavailable"
    elseif status == 400 then phrase = "Bad Request"
    elseif status == 504 then phrase = "Gateway Timeout"
    end
    local head = {
        format("HTTP/1.1 %d %s", status, phrase),
        "Content-Type: application/json",
        "Content-Length: " .. #body,
        "Proxy-Agent: rokh-oghab",
        "X-Rokh-Oghab-Reason: " .. public,
        "Connection: close",
    }
    if status == 407 then
        head[#head + 1] = 'Proxy-Authenticate: Bearer realm="rokh-oghab"'
    end
    return concat(head, "\r\n") .. "\r\n\r\n" .. body
end

_M.deny_response = deny_response

local function reject(ctx, client, status, reason, detail, fields)
    local label = reasons.label(reason)
    if label == "other" then
        metrics.inc("ro_uncatalogued_reasons_total", nil)
        log.warn("a denial used a reason with no catalogue entry", {
            reason = util.safe_str(reason, 120),
        })
    end
    metrics.inc("ro_requests_total", label_set(ctx, { protocol = ctx.protocol or "-" }))
    metrics.inc("ro_denied_total", label_set(ctx, { reason = label }))
    metrics.inc("ro_policy_denials_total", label_set(ctx, { reason = label }))
    local f = fields or {}
    f.event = f.event or "request"
    f.action = "deny"
    f.reason = reason
    f.detail = detail
    f.severity = "high"
    audit(ctx, f)
    local speaks_http = ctx.mode == "explicit" or ctx.mode == "transparent_http"
    if client and speaks_http and not ctx.tunnel_established then
        pcall(send_all, client, deny_response(status, reason, detail))
    end
    return nil, reason
end

local function resolve_identity(ctx, headers)
    local st = state.get()
    if not st then
        return nil, "policy.not_loaded"
    end
    local proxy_auth
    if headers then
        proxy_auth = headers:get("proxy-authorization")
    end
    local hdrmap
    if headers then
        hdrmap = {
            ["x-ro-identity"] = headers:get("x-ro-identity"),
            ["x-ro-namespace"] = headers:get("x-ro-namespace"),
            ["x-ro-profile"] = headers:get("x-ro-profile"),
            ["x-ro-service-account"] = headers:get("x-ro-service-account"),
            ["x-ro-pod"] = headers:get("x-ro-pod"),
        }
    end
    local ident, err = st.identities:resolve({
        proxy_authorization = proxy_auth,
        remote_addr = ctx.remote_addr,
        headers = hdrmap,
    })
    if not ident then
        return nil, err or "identity.unknown"
    end
    return ident
end

local function evaluate(ctx, desc)
    local st = state.get()
    local usable, reason = state.is_usable()
    if not usable then
        return nil, reason
    end
    ctx.policy_version = st.version

    local t0 = util.monotonic()
    local decision = st.bundle:evaluate(ctx.identity, desc)
    metrics.observe("ro_policy_eval_seconds", nil, util.monotonic() - t0)

    if decision.action ~= "allow" then
        return nil, decision.reason, decision
    end
    return decision
end

local function guard_literal(ctx, info)
    local st = state.get()
    if not st then
        return false, "policy.not_loaded"
    end
    if info.kind == "hostname" then
        return true
    end
    local ok, why = st.guard:check(info)
    if not ok then
        return false, "guard.blocked:" .. tostring(why)
    end
    return true
end

local function resolve_destination(ctx, info, decision)
    local st = state.get()
    if info.kind ~= "hostname" then
        return { {
            kind = info.kind,
            v4 = info.v4,
            v6 = info.v6,
            address = info.canonical,
        } }
    end
    local dns_span = otel.child(ctx.span, "dns.resolve")
    otel.attr(dns_span, "ro.name_kind", info.kind)
    local addrs, err = st.resolver:resolve_any(info.canonical)
    if not addrs then
        otel.finish(dns_span, otel.STATUS_ERROR, reasons.label(err))
        return nil, err or "dns.no_address"
    end
    otel.attr(dns_span, "ro.answers", #addrs)
    otel.finish(dns_span, otel.STATUS_OK)
    if decision and decision.resolved_cidrs then
        local filtered, n = {}, 0
        for _, a in ipairs(addrs) do
            local ok = st.bundle:check_resolved(decision, a.kind,
                a.kind == "ipv4" and a.v4 or a.v6)
            if ok then
                n = n + 1
                filtered[n] = a
            end
        end
        if n == 0 then
            return nil, "policy.resolved_cidr"
        end
        return filtered
    end
    return addrs
end

local function enforce_limits(ctx, decision, key_suffix)
    local conf = ctx.conf
    local rps = decision.rate_limit and decision.rate_limit.rps
        or (conf.limits.defaultRequestsPerSecond > 0
            and conf.limits.defaultRequestsPerSecond or nil)
    if rps then
        local ok, _, _, lerr = limits.check_rate(ctx.identity.key, rps,
            decision.rate_limit and decision.rate_limit.burst or rps)
        if not ok then
            metrics.inc("ro_ratelimit_rejected_total",
                label_set(ctx, { kind = "rate" }))
            return nil, lerr == "limit.unavailable" and lerr or "limit.rate"
        end
    end
    local maxc = decision.max_connections
        or (conf.limits.defaultMaxConnections > 0
            and conf.limits.defaultMaxConnections or nil)
    if maxc then
        local ok, _, cerr = limits.acquire_conn(ctx.identity.key, maxc)
        if not ok then
            metrics.inc("ro_ratelimit_rejected_total",
                label_set(ctx, { kind = "connections" }))
            return nil, cerr == "limit.unavailable" and cerr or "limit.connections"
        end
        ctx.holds_conn = true
    end
    return true
end

local function release_limits(ctx)
    if ctx.holds_conn then
        limits.release_conn(ctx.identity.key)
        ctx.holds_conn = false
    end
end

local function source_key(ctx)
    return "src:" .. tostring(ctx.remote_addr or "-")
end

local function admit(ctx, client)
    local conf = ctx.conf
    local gok = limits.acquire_conn("__global", conf.limits.globalMaxConnections)
    if not gok then
        if client then
            pcall(send_all, client, deny_response(503, "limit.global_connections",
                "gateway connection capacity reached"))
        end
        audit(ctx, { action = "deny", reason = "limit.global_connections" })
        metrics.inc("ro_denied_total",
            label_set(ctx, { reason = "limit.global_connections" }))
        return false
    end
    ctx.holds_global = true

    local per_source = conf.limits.maxConnectionsPerSource
    if per_source and per_source > 0 then
        local sok = limits.acquire_conn(source_key(ctx), per_source)
        if not sok then
            if client then
                pcall(send_all, client, deny_response(429, "limit.source_connections",
                    "too many concurrent connections from this source"))
            end
            audit(ctx, { action = "deny", reason = "limit.source_connections" })
            metrics.inc("ro_denied_total",
                label_set(ctx, { reason = "limit.source_connections" }))
            metrics.inc("ro_ratelimit_rejected_total",
                label_set(ctx, { kind = "source_connections" }))
            limits.release_conn("__global")
            ctx.holds_global = false
            return false
        end
        ctx.holds_source = true
    end
    return true
end

local function depart(ctx)
    if ctx.holds_source then
        limits.release_conn(source_key(ctx))
        ctx.holds_source = false
    end
    if ctx.holds_global then
        limits.release_conn("__global")
        ctx.holds_global = false
    end
end

local function upstream_pool(ctx, host, port)
    local key = ctx.identity and ctx.identity.key or "-"
    return concat({ "ro", key, host, tostring(port) }, "|")
end

local function connect_upstream(ctx, addresses, port)
    local conf = ctx.conf
    local span = otel.child(ctx.span, "upstream.connect")
    otel.attr(span, "ro.candidates", #addresses)
    otel.attr(span, "ro.port", port)
    local last_err
    for _, a in ipairs(addresses) do
        local sock, serr = ngx.socket.tcp()
        if not sock then
            return nil, serr or "socket-error"
        end
        sock:settimeout(conf.limits.connectTimeoutMs)
        local host = a.address
        if a.kind == "ipv6" then
            host = "[" .. host .. "]"
        end
        local ok, cerr = sock:connect(host, port, {
            pool = upstream_pool(ctx, host, port),
            pool_size = conf.limits.upstreamPoolSize or 32,
        })
        if ok then
            sock:settimeout(conf.limits.upstreamTimeoutMs)
            ctx.upstream_address = a.address
            ctx.upstream_family = a.kind
            otel.attr(span, "ro.family", a.kind)
            otel.finish(span, otel.STATUS_OK)
            return sock, nil, a
        end
        last_err = cerr
        pcall(function() sock:close() end)
    end
    metrics.inc("ro_connection_failures_total", label_set(ctx))
    otel.finish(span, otel.STATUS_ERROR, "upstream.connect_failed")
    return nil, "upstream.connect_failed:" .. tostring(last_err)
end

local function relay_length(src, dst, total, cap, ctx, direction)
    local remaining = total
    if cap and total > cap then
        return nil, "limit.body_size"
    end
    while remaining > 0 do
        local want = min(remaining, BUF)
        local chunk, err = src:read_some(want)
        if not chunk then
            return nil, "peer-closed:" .. tostring(err)
        end
        local ok, serr = dst:send(chunk)
        if not ok then
            return nil, "send-failed:" .. tostring(serr)
        end
        remaining = remaining - #chunk
        if direction == "up" then
            ctx.bytes_sent = ctx.bytes_sent + #chunk
        else
            ctx.bytes_received = ctx.bytes_received + #chunk
        end
    end
    return true
end

local function relay_chunked(src, dst, cap, ctx, direction)
    local transferred = 0
    while true do
        local line, err = src:read_until("\r\n", 4096)
        if not line then
            return nil, "chunk-header:" .. tostring(err)
        end
        local size, serr = http.parse_chunk_size(sub(line, 1, #line - 2))
        if not size then
            metrics.inc("ro_protocol_violations_total",
                label_set(ctx, { kind = "chunk" }))
            return nil, "protocol.chunk:" .. tostring(serr)
        end
        local ok, sderr = dst:send(format("%x\r\n", size))
        if not ok then
            return nil, "send-failed:" .. tostring(sderr)
        end
        if size == 0 then
            local trailers, trailer_bytes = 0, 0
            while true do
                local trailer, terr = src:read_until("\r\n", MAX_TRAILER_LINE)
                if not trailer then
                    return nil, "protocol.chunk_trailers:" .. tostring(terr)
                end
                if trailer == "\r\n" then
                    break
                end
                trailers = trailers + 1
                trailer_bytes = trailer_bytes + #trailer
                if trailers > MAX_TRAILERS or trailer_bytes > MAX_TRAILER_BYTES then
                    metrics.inc("ro_protocol_violations_total",
                        label_set(ctx, { kind = "trailers" }))
                    return nil, "protocol.chunk_trailers"
                end
            end
            local done, derr = dst:send("\r\n")
            if not done then
                return nil, "send-failed:" .. tostring(derr)
            end
            return true
        end
        transferred = transferred + size
        if cap and transferred > cap then
            return nil, "limit.body_size"
        end
        local remaining = size
        while remaining > 0 do
            local chunk, cerr = src:read_some(min(remaining, BUF))
            if not chunk then
                return nil, "chunk-body:" .. tostring(cerr)
            end
            local sent, serr2 = dst:send(chunk)
            if not sent then
                return nil, "send-failed:" .. tostring(serr2)
            end
            remaining = remaining - #chunk
            if direction == "up" then
                ctx.bytes_sent = ctx.bytes_sent + #chunk
            else
                ctx.bytes_received = ctx.bytes_received + #chunk
            end
        end
        local crlf, cerr2 = src:read_exact(2)
        if not crlf or crlf ~= "\r\n" then
            return nil, "protocol.chunk_terminator:" .. tostring(cerr2)
        end
        local ok2, serr3 = dst:send("\r\n")
        if not ok2 then
            return nil, "send-failed:" .. tostring(serr3)
        end
    end
end

local function relay_until_close(src, dst, cap, ctx, direction)
    local transferred = 0
    while true do
        local chunk, err = src:read_some(BUF)
        if not chunk then
            if err == "closed" then
                return true
            end
            return true
        end
        transferred = transferred + #chunk
        if cap and transferred > cap then
            return nil, "limit.body_size"
        end
        local ok, serr = dst:send(chunk)
        if not ok then
            return nil, "send-failed:" .. tostring(serr)
        end
        if direction == "up" then
            ctx.bytes_sent = ctx.bytes_sent + #chunk
        else
            ctx.bytes_received = ctx.bytes_received + #chunk
        end
    end
end

local function relay_body(framing, src, dst, cap, ctx, direction)
    if framing.mode == "none" then
        return true
    end
    if framing.mode == "length" then
        return relay_length(src, dst, framing.length, cap, ctx, direction)
    end
    if framing.mode == "chunked" then
        return relay_chunked(src, dst, cap, ctx, direction)
    end
    if framing.mode == "until_close" then
        return relay_until_close(src, dst, cap, ctx, direction)
    end
    return nil, "unknown-framing"
end

local function redirect_authority(loc, current_scheme)
    local b1, b2 = sub(loc, 1, 1), sub(loc, 2, 2)
    if (b1 == "/" or b1 == "\\") and (b2 == "/" or b2 == "\\") then
        return current_scheme, sub(loc, 3), true
    end
    if b1 == "/" or b1 == "\\" then
        return nil, nil, false
    end
    local scheme_end = find(loc, "://", 1, true)
    if not scheme_end then
        local colon = find(loc, ":", 1, true)
        local slash = find(loc, "/", 1, true)
        if colon and (not slash or colon < slash) then
            return "", nil, true
        end
        return nil, nil, false
    end
    return lower(sub(loc, 1, scheme_end - 1)), sub(loc, scheme_end + 3), true
end

_M.redirect_authority = redirect_authority

local function location_count(headers)
    local n = 0
    for _, entry in ipairs(headers.list or {}) do
        if entry.lname == "location" then
            n = n + 1
        end
    end
    return n
end

local function check_redirect(ctx, res)
    if not ctx.conf.strict.redirectGuard then
        return true
    end
    if res.status < 300 or res.status > 399 then
        return true
    end
    local loc = res.headers:get("location")
    if not loc or loc == "" then
        return true
    end
    local scheme, rest, off_origin = redirect_authority(loc,
        ctx.protocol == "https" and "https" or "http")
    if not off_origin then
        return true
    end
    if scheme ~= "http" and scheme ~= "https" then
        return nil, "redirect.bad_scheme"
    end
    local cut = rest:find("[/?#\\]")
    local authority = cut and rest:sub(1, cut - 1) or rest
    local info, port = target_mod.parse_authority(authority,
        scheme == "https" and 443 or 80)
    if not info then
        return nil, "redirect.malformed"
    end
    local ok, why = guard_literal(ctx, info)
    if not ok then
        why = tostring(why)
        if sub(why, 1, 14) == "guard.blocked:" then
            return nil, "redirect.blocked:" .. sub(why, 15)
        end
        return nil, "redirect.not_loaded"
    end
    local decision = evaluate(ctx, {
        host_info = info,
        port = port,
        protocol = scheme == "https" and "https" or "http",
        method = "GET",
        path = "/",
    })
    if not decision then
        return nil, "redirect.policy_denied"
    end
    return true
end

local function handle_http_request(ctx, req, client_reader, client)
    local conf = ctx.conf
    local pt = req.parsed_target
    ctx.protocol = "http"
    ctx.span = otel.start_span("rokh-oghab proxy request",
        req.headers:get("traceparent"))

    if pt.form ~= "absolute" then
        return reject(ctx, client, 400, "protocol.not_a_proxy_request",
            "absolute-form request target required")
    end

    local info, port, aerr = target_mod.parse_authority(pt.authority, 80)
    if not info then
        return reject(ctx, client, 400, "protocol.bad_authority", aerr)
    end

    if conf.strict.blockPlaintextOnTlsPorts and is_tls_port(conf, port) then
        return reject(ctx, client, 403, "tls.expected_on_tls_port",
            "cleartext request to a port configured as TLS", {
                destination = info.canonical, port = port, protocol = "http",
            })
    end
    if conf.strict.requireTls then
        return reject(ctx, client, 403, "tls.required",
            "cleartext is refused while strict.requireTls is set", {
                destination = info.canonical, port = port, protocol = "http",
            })
    end

    local host_hdr = req.headers:get("host")
    if conf.strict.hostMatch and host_hdr then
        local hinfo, hport = target_mod.parse_authority(host_hdr, port)
        if not hinfo or hinfo.canonical ~= info.canonical or hport ~= port then
            return reject(ctx, client, 400, "protocol.host_mismatch",
                "Host header does not match the request target")
        end
    end

    local norm, nerr = http.normalize_path(pt.path)
    if not norm then
        return reject(ctx, client, 400, "protocol.bad_path", nerr)
    end
    if conf.strict.path and norm ~= pt.path then
        return reject(ctx, client, 400, "protocol.path_not_normalized",
            "request path must be sent in normalized form")
    end

    local framing, ferr = http.request_framing(req)
    if not framing then
        metrics.inc("ro_protocol_violations_total", label_set(ctx, { kind = "framing" }))
        return reject(ctx, client, 400, "protocol.framing", ferr)
    end

    local ident, ierr = resolve_identity(ctx, req.headers)
    if not ident then
        return reject(ctx, client, status_for(ierr), ierr)
    end
    ctx.identity = ident

    local ok, gerr = guard_literal(ctx, info)
    if not ok then
        return reject(ctx, client, 403, gerr, info.canonical,
            { destination = info.canonical, port = port })
    end

    local desc = {
        host_info = info,
        port = port,
        protocol = "http",
        method = req.method,
        path = norm,
    }
    local decision, derr = evaluate(ctx, desc)
    if not decision then
        return reject(ctx, client, status_for(derr), derr, nil, {
            destination = info.canonical, port = port,
            protocol = "http", method = req.method, path = norm,
        })
    end

    local lok, lerr = enforce_limits(ctx, decision)
    if not lok then
        return reject(ctx, client, status_for(lerr), lerr, nil, {
            destination = info.canonical, port = port,
        })
    end

    local addresses, rerr = resolve_destination(ctx, info, decision)
    if not addresses then
        release_limits(ctx)
        return reject(ctx, client, status_for(rerr), rerr, nil, {
            destination = info.canonical, port = port,
        })
    end

    local upstream, uerr = connect_upstream(ctx, addresses, port)
    if not upstream then
        release_limits(ctx)
        return reject(ctx, client, 502, uerr, nil, {
            destination = info.canonical, port = port,
        })
    end

    local request_line = format("%s %s HTTP/1.1", req.method,
        pt.query and (norm .. "?" .. pt.query) or norm)
    local host_value = info.canonical
    if info.kind == "ipv6" then
        host_value = "[" .. host_value .. "]"
    end
    if port ~= 80 then
        host_value = host_value .. ":" .. port
    end
    local extra = { "Host: " .. host_value, "Connection: keep-alive" }
    if framing.mode == "chunked" then
        extra[#extra + 1] = "Transfer-Encoding: chunked"
    end
    local head = http.serialize_head(request_line, req.headers, { host = true }, extra)

    local sent, serr = upstream:send(head)
    if not sent then
        release_limits(ctx)
        pcall(function() upstream:close() end)
        return reject(ctx, client, 502, "upstream.write_failed", serr)
    end
    ctx.bytes_sent = ctx.bytes_sent + #head

    local bok, berr = relay_body(framing, client_reader, upstream,
        decision.max_request_size, ctx, "up")
    if not bok then
        release_limits(ctx)
        pcall(function() upstream:close() end)
        return reject(ctx, client, 400, "protocol.request_body", berr)
    end

    local up_reader = reader_mod.wrap(upstream)
    local expect = req.headers:get("expect")
    local wants_continue = expect ~= nil
        and lower(util.trim(expect)) == "100-continue"
    local res
    local interim = 0
    while true do
        local raw_res, rherr = up_reader:read_until("\r\n\r\n",
            conf.limits.maxHeadBytes)
        if not raw_res then
            release_limits(ctx)
            pcall(function() upstream:close() end)
            local why = "upstream.no_response"
            if rherr == "head-too-large" then
                why = "upstream.head_too_large"
                metrics.inc("ro_protocol_violations_total",
                    label_set(ctx, { kind = "response_head" }))
            end
            return reject(ctx, client, 502, why, rherr)
        end
        local parsed, perr = http.parse_response_head(raw_res)
        if not parsed then
            release_limits(ctx)
            pcall(function() upstream:close() end)
            metrics.inc("ro_protocol_violations_total",
                label_set(ctx, { kind = "response" }))
            return reject(ctx, client, 502, "upstream.bad_response", perr)
        end
        if parsed.status >= 200 then
            res = parsed
            break
        end
        if parsed.headers:get("content-length")
            or parsed.headers:get("transfer-encoding") then
            release_limits(ctx)
            pcall(function() upstream:close() end)
            metrics.inc("ro_protocol_violations_total",
                label_set(ctx, { kind = "response_interim_framing" }))
            return reject(ctx, client, 502, "upstream.interim_framing",
                "an interim response ends at its header section and cannot "
                .. "declare a body; what follows would be read as the final "
                .. "response")
        end
        if parsed.status == 101 then
            release_limits(ctx)
            pcall(function() upstream:close() end)
            metrics.inc("ro_protocol_violations_total",
                label_set(ctx, { kind = "response_upgrade" }))
            return reject(ctx, client, 502, "upstream.protocol_upgrade",
                "an upstream may not switch protocols on a proxied request")
        end
        interim = interim + 1
        if interim > MAX_INTERIM_RESPONSES then
            release_limits(ctx)
            pcall(function() upstream:close() end)
            metrics.inc("ro_protocol_violations_total",
                label_set(ctx, { kind = "response_interim" }))
            return reject(ctx, client, 502, "upstream.interim_flood",
                "the upstream sent too many interim responses")
        end
        if wants_continue and parsed.status == 100 then
            wants_continue = false
            local iok = client:send("HTTP/1.1 100 Continue\r\n\r\n")
            if not iok then
                release_limits(ctx)
                pcall(function() upstream:close() end)
                return reject(ctx, client, 502, "client.write_failed",
                    "the client went away during an interim response")
            end
        end
    end

    if res.status >= 300 and res.status < 400 and location_count(res.headers) > 1 then
        release_limits(ctx)
        pcall(function() upstream:close() end)
        metrics.inc("ro_protocol_violations_total",
            label_set(ctx, { kind = "response_framing" }))
        return reject(ctx, client, 502, "redirect.malformed",
            "more than one Location header")
    end
    local rok, rerr2 = check_redirect(ctx, res)
    if not rok then
        release_limits(ctx)
        pcall(function() upstream:close() end)
        return reject(ctx, client, 403, rerr2, nil, {
            destination = info.canonical, port = port,
        })
    end

    local res_framing, rferr = http.response_framing(res, req.method)
    if not res_framing then
        release_limits(ctx)
        pcall(function() upstream:close() end)
        metrics.inc("ro_protocol_violations_total",
            label_set(ctx, { kind = "response_framing" }))
        return reject(ctx, client, 502, "upstream.response_framing", rferr)
    end

    local close_after = res_framing.mode == "until_close"
        or http.wants_close(res.headers, res.version)
        or http.wants_close(req.headers, req.version)

    local res_extra = { close_after and "Connection: close" or "Connection: keep-alive" }
    if res_framing.mode == "chunked" then
        res_extra[#res_extra + 1] = "Transfer-Encoding: chunked"
    end
    local res_drop = nil
    if res_framing.mode == "none" and req.method ~= "HEAD" then
        res_drop = { ["content-length"] = true, ["transfer-encoding"] = true }
    end
    local res_head = http.serialize_head(
        format("HTTP/1.1 %d %s", res.status, res.reason or ""),
        res.headers, res_drop, res_extra)

    local csent, cserr = client:send(res_head)
    if not csent then
        release_limits(ctx)
        pcall(function() upstream:close() end)
        return nil, "client.write_failed:" .. tostring(cserr)
    end

    local dok, derr2 = relay_body(res_framing, up_reader, client,
        decision.max_response_size, ctx, "down")

    release_limits(ctx)
    local drained = up_reader:pending() == 0
    if close_after or not dok or not drained then
        if not drained then
            metrics.inc("ro_protocol_violations_total",
                label_set(ctx, { kind = "upstream_overread" }))
            log.warn("upstream sent more than it declared; not pooling", {
                destination = info.canonical, port = port,
                pending = up_reader:pending(),
            })
        end
        pcall(function() upstream:close() end)
    else
        local kok = pcall(function()
            return upstream:setkeepalive(conf.limits.idleTimeoutMs,
                conf.limits.upstreamPoolSize or 32)
        end)
        if not kok then
            pcall(function() upstream:close() end)
        end
    end

    metrics.inc("ro_requests_total", label_set(ctx, { protocol = "http" }))
    metrics.inc("ro_allowed_total", label_set(ctx, { protocol = "http" }))
    metrics.inc("ro_bytes_sent_total", label_set(ctx), ctx.bytes_sent)
    metrics.inc("ro_bytes_received_total", label_set(ctx), ctx.bytes_received)
    metrics.observe("ro_request_duration_seconds", label_set(ctx),
        util.monotonic() - ctx.started)

    audit(ctx, {
        action = "allow",
        reason = decision.reason,
        rule = decision.rule,
        policy = decision.policy,
        destination = info.canonical,
        resolved = ctx.upstream_address,
        port = port,
        protocol = "http",
        method = req.method,
        path = norm,
        status = res.status,
        bytes_sent = ctx.bytes_sent,
        bytes_received = ctx.bytes_received,
        duration = util.monotonic() - ctx.started,
    })

    if not dok then
        return nil, derr2
    end
    return not close_after
end

local function pump(src_reader, dst, ctx, direction, bps)
    local throttle = bps and limits.throttle(bps) or nil
    while true do
        local chunk, err = src_reader:read_some(BUF)
        if not chunk then
            return true
        end
        local ok, serr = dst:send(chunk)
        if not ok then
            return nil, serr
        end
        if direction == "up" then
            ctx.bytes_sent = ctx.bytes_sent + #chunk
        else
            ctx.bytes_received = ctx.bytes_received + #chunk
        end
        if throttle then
            local delay = throttle:consume(#chunk)
            if delay > 0 then
                ngx.sleep(delay)
            end
        end
    end
end

local function splice(ctx, client_reader, client, upstream, bps)
    local up_reader = reader_mod.wrap(upstream)
    local t_up = ngx.thread.spawn(pump, client_reader, upstream, ctx, "up", bps)
    local t_down = ngx.thread.spawn(pump, up_reader, client, ctx, "down", bps)
    ngx.thread.wait(t_up, t_down)
    pcall(ngx.thread.wait, t_down)
    pcall(ngx.thread.wait, t_up)
    pcall(ngx.thread.kill, t_up)
    pcall(ngx.thread.kill, t_down)
    pcall(function() upstream:close() end)
    return true
end

local INCOMPLETE_HELLO = {
    ["need more data"] = true,
    ["truncated handshake"] = true,
    ["truncated ClientHello"] = true,
    ["truncated session id"] = true,
    ["truncated cipher suites"] = true,
    ["truncated compression methods"] = true,
}

local function is_incomplete(err)
    return err ~= nil and INCOMPLETE_HELLO[err] == true
end

local function peek_client_hello(ctx, client_reader)
    local conf = ctx.conf
    local sock = client_reader.sock
    pcall(function() sock:settimeout(PEEK_TIMEOUT_MS) end)
    local collected = 0
    local parsed, perr
    local looked_like_tls = false
    while collected < MAX_PEEK do
        local ok = client_reader:fill()
        if not ok then
            break
        end
        collected = client_reader:pending()
        local buffered = client_reader:leftover()
        local is_hello, undecided = tls.looks_like_client_hello(buffered)
        if not is_hello and not undecided then
            parsed = nil
            perr = "not-tls"
            looked_like_tls = false
            break
        end
        looked_like_tls = true
        if is_hello then
            parsed, perr = tls.parse_client_hello(buffered)
            if parsed and not parsed.truncated then
                break
            end
            if perr and not is_incomplete(perr) then
                parsed = nil
                break
            end
            parsed = nil
        end
    end
    pcall(function() sock:settimeout(conf.limits.clientTimeoutMs) end)
    if parsed then
        metrics.inc("ro_tls_handshakes_total", label_set(ctx))
    end
    return parsed, perr, client_reader:pending(), (not parsed) and looked_like_tls
end

local function handle_connect(ctx, req, client_reader, client)
    local conf = ctx.conf
    ctx.protocol = ctx.protocol or "connect"
    ctx.span = otel.start_span("rokh-oghab proxy connect",
        req.headers:get("traceparent"))
    local info, port, aerr = target_mod.parse_authority(req.parsed_target.authority, nil)
    if not info then
        return reject(ctx, client, 400, "protocol.bad_authority", aerr)
    end

    local ident, ierr = resolve_identity(ctx, req.headers)
    if not ident then
        return reject(ctx, client, status_for(ierr), ierr)
    end
    ctx.identity = ident

    local ok, gerr = guard_literal(ctx, info)
    if not ok then
        return reject(ctx, client, 403, gerr, info.canonical,
            { destination = info.canonical, port = port, protocol = "tunnel" })
    end

    local desc = {
        host_info = info,
        port = port,
        protocol = "tunnel",
    }
    local decision, derr = evaluate(ctx, desc)
    if not decision then
        return reject(ctx, client, status_for(derr), derr, nil, {
            destination = info.canonical, port = port, protocol = "tunnel",
        })
    end

    local lok, lerr = enforce_limits(ctx, decision)
    if not lok then
        return reject(ctx, client, status_for(lerr), lerr, nil, {
            destination = info.canonical, port = port,
        })
    end

    local addresses, rerr = resolve_destination(ctx, info, decision)
    if not addresses then
        release_limits(ctx)
        return reject(ctx, client, status_for(rerr), rerr, nil, {
            destination = info.canonical, port = port,
        })
    end

    local sent, serr = client:send("HTTP/1.1 200 Connection Established\r\n"
        .. "Proxy-Agent: rokh-oghab\r\n\r\n")
    if not sent then
        release_limits(ctx)
        return nil, "client.write_failed:" .. tostring(serr)
    end
    ctx.tunnel_established = true

    local hello, herr, _, undecided = peek_client_hello(ctx, client_reader)
    local protocol = hello and "https" or "tcp"
    ctx.protocol = protocol

    if not hello then
        if undecided then
            release_limits(ctx)
            return reject(ctx, client, 403, "tls.handshake_incomplete",
                tostring(herr), {
                    destination = info.canonical, port = port, protocol = protocol,
                })
        end
        if conf.strict.blockPlaintextOnTlsPorts and is_tls_port(conf, port) then
            release_limits(ctx)
            return reject(ctx, client, 403, "tls.expected_on_tls_port",
                tostring(herr), {
                    destination = info.canonical, port = port, protocol = protocol,
                })
        end
        if conf.strict.requireTls then
            release_limits(ctx)
            return reject(ctx, client, 403, "tls.required", tostring(herr), {
                destination = info.canonical, port = port, protocol = protocol,
            })
        end
    else
        local min_version = (decision.tls and decision.tls.min_version)
            or conf.strict.minTlsVersion
        local judged = hello.min_version_name or hello.version_name
        if min_version and not tls.version_at_least(judged, min_version) then
            release_limits(ctx)
            return reject(ctx, client, 403, "tls.version_too_low", judged, {
                destination = info.canonical, port = port,
                tls_version = judged,
            })
        end

        local require_sni = conf.strict.sniMatch
        if decision.tls and decision.tls.require_sni ~= nil then
            require_sni = decision.tls.require_sni
        end
        if info.kind == "hostname" then
            if hello.sni then
                local sni_info = target_mod.classify_host(hello.sni)
                if not sni_info or sni_info.canonical ~= info.canonical then
                    release_limits(ctx)
                    return reject(ctx, client, 403, "tls.sni_mismatch",
                        util.safe_str(hello.sni, 64), {
                            destination = info.canonical, port = port,
                            sni = util.safe_str(hello.sni, 64),
                        })
                end
            elseif require_sni then
                release_limits(ctx)
                return reject(ctx, client, 403, "tls.sni_missing", nil, {
                    destination = info.canonical, port = port,
                })
            end
        elseif hello.sni and require_sni then
            local sni_info = target_mod.classify_host(hello.sni)
            if not sni_info then
                release_limits(ctx)
                return reject(ctx, client, 403, "tls.sni_invalid", nil, {
                    destination = info.canonical, port = port,
                })
            end
            local sni_desc = {
                host_info = sni_info,
                port = port,
                protocol = "https",
            }
            local sni_decision = evaluate(ctx, sni_desc)
            if not sni_decision then
                release_limits(ctx)
                return reject(ctx, client, 403, "tls.sni_not_allowed",
                    util.safe_str(hello.sni, 64), {
                        destination = info.canonical, port = port,
                        sni = util.safe_str(hello.sni, 64),
                    })
            end
        end
        ctx.sni = hello.sni
        ctx.tls_version = hello.version_name
    end

    local final_desc = {
        host_info = info,
        port = port,
        protocol = protocol,
    }
    local final_decision, ferr = evaluate(ctx, final_desc)
    if not final_decision then
        release_limits(ctx)
        return reject(ctx, client, 403, ferr, "protocol " .. protocol
            .. " is not permitted for this destination", {
                destination = info.canonical, port = port, protocol = protocol,
            })
    end

    local st = state.get()
    if st and final_decision ~= decision and info.kind == "hostname" then
        local kept, n = {}, 0
        for _, a in ipairs(addresses) do
            if st.bundle:check_resolved(final_decision, a.kind,
                a.kind == "ipv4" and a.v4 or a.v6) then
                n = n + 1
                kept[n] = a
            end
        end
        if n == 0 then
            release_limits(ctx)
            return reject(ctx, client, 403, "policy.resolved_cidr", nil, {
                destination = info.canonical, port = port, protocol = protocol,
            })
        end
        addresses = kept
    end

    local upstream, uerr = connect_upstream(ctx, addresses, port)
    if not upstream then
        release_limits(ctx)
        return reject(ctx, client, 502, uerr, nil, {
            destination = info.canonical, port = port, protocol = protocol,
        })
    end

    local buffered = client_reader:leftover()
    if #buffered > 0 then
        client_reader:discard_buffer()
        local bsent, bserr = upstream:send(buffered)
        if not bsent then
            release_limits(ctx)
            pcall(function() upstream:close() end)
            return nil, "upstream.write_failed:" .. tostring(bserr)
        end
        ctx.bytes_sent = ctx.bytes_sent + #buffered
    end

    metrics.inc("ro_requests_total", label_set(ctx, { protocol = protocol }))
    metrics.inc("ro_allowed_total", label_set(ctx, { protocol = protocol }))

    audit(ctx, {
        event = "tunnel_open",
        action = "allow",
        reason = final_decision.reason,
        rule = final_decision.rule,
        policy = final_decision.policy,
        destination = info.canonical,
        resolved = ctx.upstream_address,
        port = port,
        protocol = protocol,
        sni = ctx.sni,
        tls_version = ctx.tls_version,
    })

    pcall(function() client_reader.sock:settimeout(conf.limits.idleTimeoutMs) end)
    pcall(function() upstream:settimeout(conf.limits.idleTimeoutMs) end)

    splice(ctx, client_reader, client, upstream, final_decision.bandwidth)
    release_limits(ctx)

    metrics.inc("ro_bytes_sent_total", label_set(ctx), ctx.bytes_sent)
    metrics.inc("ro_bytes_received_total", label_set(ctx), ctx.bytes_received)
    metrics.observe("ro_upstream_duration_seconds", label_set(ctx),
        util.monotonic() - ctx.started)

    audit(ctx, {
        event = "tunnel_close",
        action = "allow",
        destination = info.canonical,
        port = port,
        protocol = protocol,
        bytes_sent = ctx.bytes_sent,
        bytes_received = ctx.bytes_received,
        duration = util.monotonic() - ctx.started,
    })
    return false
end

local function serve_explicit(ctx, conf, client)
    state.sync()
    local client_reader = reader_mod.wrap(client)
    local keep_going = true
    local served = 0

    local head_timeout = conf.limits.headTimeoutMs or 10000
    while keep_going and served < conf.limits.maxRequestsPerConnection do
        pcall(function() client:settimeout(head_timeout) end)
        local raw, rerr = client_reader:read_until("\r\n\r\n", conf.limits.maxHeadBytes)
        pcall(function() client:settimeout(conf.limits.clientTimeoutMs) end)
        if not raw then
            break
        end
        served = served + 1
        ctx.requests = served
        ctx.id = util.gen_id()
        ctx.started = util.monotonic()
        ctx.bytes_sent = 0
        ctx.bytes_received = 0

        local req, perr = http.parse_request_head(raw)
        if not req then
            metrics.inc("ro_protocol_violations_total", { kind = "request" })
            reject(ctx, client, 400, "protocol.malformed_request", perr)
            break
        end

        if req.method == "CONNECT" then
            handle_connect(ctx, req, client_reader, client)
            keep_going = false
        else
            local cont = handle_http_request(ctx, req, client_reader, client)
            keep_going = cont == true
        end
    end

end

function _M.run_explicit(conf)
    local client, err = ngx.req.socket(true)
    if not client then
        log.error("cannot obtain downstream socket", { error = tostring(err) })
        return
    end
    client:settimeout(conf.limits.clientTimeoutMs)

    local ctx = new_ctx(conf, "explicit")
    metrics.inc("ro_connections_total", { mode = "explicit" })

    if not admit(ctx, client) then
        return
    end

    local ok, serr = pcall(serve_explicit, ctx, conf, client)
    release_limits(ctx)
    depart(ctx)
    if not ok then
        log.error("explicit proxy handler failed", { error = tostring(serr) })
    end
end

local function original_destination(ctx)
    local addr = ngx.var.server_addr
    local port = tonumber(ngx.var.server_port)
    if not addr or not port then
        return nil, nil
    end
    local info = target_mod.classify_host(addr)
    if not info then
        return nil, nil
    end
    return info, port
end

local function verify_name_binding(ctx, info, addresses, orig_info)
    if not orig_info or not ctx.conf.strict.verifyOriginalDestination then
        return true
    end
    if orig_info.kind == "ipv4" and orig_info.v4 == 0 then
        return true
    end
    for _, a in ipairs(addresses) do
        if a.kind == orig_info.kind then
            if a.kind == "ipv4" and a.v4 == orig_info.v4 then
                return true
            end
            if a.kind == "ipv6"
                and ipaddr_mod.ipv6_key(a.v6) == ipaddr_mod.ipv6_key(orig_info.v6) then
                return true
            end
        end
    end
    return nil, "transparent.name_address_mismatch"
end

local function transparent_finish(ctx, client_reader, client, info, port,
                                  decision, protocol)
    local conf = ctx.conf
    local addresses, rerr = resolve_destination(ctx, info, decision)
    if not addresses then
        return reject(ctx, client, status_for(rerr), rerr, nil, {
            destination = info.canonical, port = port, protocol = protocol,
        })
    end

    local orig_info, orig_port = original_destination(ctx)
    local bound, berr = verify_name_binding(ctx, info, addresses, orig_info)
    if not bound then
        return reject(ctx, client, 403, tostring(berr), nil, {
            destination = info.canonical, port = port, protocol = protocol,
        })
    end

    local lok, lerr = enforce_limits(ctx, decision)
    if not lok then
        return reject(ctx, client, status_for(lerr), lerr, nil, {
            destination = info.canonical, port = port,
        })
    end

    local upstream, uerr = connect_upstream(ctx, addresses, port)
    if not upstream then
        release_limits(ctx)
        return reject(ctx, client, 502, uerr, nil, {
            destination = info.canonical, port = port, protocol = protocol,
        })
    end

    local buffered = client_reader:leftover()
    if #buffered > 0 then
        client_reader:discard_buffer()
        local bsent, bserr = upstream:send(buffered)
        if not bsent then
            release_limits(ctx)
            pcall(function() upstream:close() end)
            return nil, "upstream.write_failed:" .. tostring(bserr)
        end
        ctx.bytes_sent = ctx.bytes_sent + #buffered
    end

    metrics.inc("ro_requests_total", label_set(ctx, { protocol = protocol }))
    metrics.inc("ro_allowed_total", label_set(ctx, { protocol = protocol }))
    audit(ctx, {
        event = "tunnel_open", action = "allow", reason = decision.reason,
        rule = decision.rule, policy = decision.policy,
        destination = info.canonical, resolved = ctx.upstream_address,
        port = port, protocol = protocol, sni = ctx.sni,
        tls_version = ctx.tls_version,
    })

    pcall(function() client_reader.sock:settimeout(conf.limits.idleTimeoutMs) end)
    pcall(function() upstream:settimeout(conf.limits.idleTimeoutMs) end)

    splice(ctx, client_reader, client, upstream, decision.bandwidth)
    release_limits(ctx)

    metrics.inc("ro_bytes_sent_total", label_set(ctx), ctx.bytes_sent)
    metrics.inc("ro_bytes_received_total", label_set(ctx), ctx.bytes_received)
    metrics.observe("ro_upstream_duration_seconds", label_set(ctx),
        util.monotonic() - ctx.started)
    audit(ctx, {
        event = "tunnel_close", action = "allow",
        destination = info.canonical, port = port, protocol = protocol,
        bytes_sent = ctx.bytes_sent, bytes_received = ctx.bytes_received,
        duration = util.monotonic() - ctx.started,
    })
    return true
end

local function serve_transparent_tls(ctx, conf, client, listen_port)
    state.sync()
    local port = listen_port or 443

    local ident, ierr = resolve_identity(ctx, nil)
    if not ident then
        reject(ctx, client, 403, ierr)
        return
    end
    ctx.identity = ident

    local client_reader = reader_mod.wrap(client)
    local hello, herr = peek_client_hello(ctx, client_reader)
    if not hello then
        reject(ctx, client, 403, "tls.expected_client_hello", tostring(herr),
            { port = port })
        return
    end
    if not hello.sni then
        reject(ctx, client, 403, "tls.sni_missing", nil, { port = port })
        return
    end

    local info = target_mod.classify_host(hello.sni)
    if not info or info.kind ~= "hostname" then
        reject(ctx, client, 403, "tls.sni_invalid",
            util.safe_str(hello.sni, 64), { port = port })
        return
    end
    ctx.sni = hello.sni
    ctx.tls_version = hello.version_name

    local ok, gerr = guard_literal(ctx, info)
    if not ok then
        reject(ctx, client, 403, gerr, nil, { destination = info.canonical })
        return
    end

    local decision, derr = evaluate(ctx, {
        host_info = info, port = port, protocol = "https",
    })
    if not decision then
        reject(ctx, client, 403, derr, nil, {
            destination = info.canonical, port = port, sni = hello.sni,
        })
        return
    end

    local min_version = (decision.tls and decision.tls.min_version)
        or conf.strict.minTlsVersion
    if min_version and not tls.version_at_least(hello.version_name, min_version) then
        reject(ctx, client, 403, "tls.version_too_low", hello.version_name, {
            destination = info.canonical, port = port,
        })
        return
    end

    transparent_finish(ctx, client_reader, client, info, port, decision, "https")
end

function _M.run_transparent_tls(conf, listen_port)
    local client, err = ngx.req.socket(true)
    if not client then
        log.error("cannot obtain downstream socket", { error = tostring(err) })
        return
    end
    client:settimeout(conf.limits.clientTimeoutMs)

    local ctx = new_ctx(conf, "transparent_tls")
    ctx.tunnel_established = true
    metrics.inc("ro_connections_total", { mode = "transparent_tls" })

    if not admit(ctx, nil) then
        return
    end

    local ok, serr = pcall(serve_transparent_tls, ctx, conf, client, listen_port)
    release_limits(ctx)
    depart(ctx)
    if not ok then
        log.error("transparent tls handler failed", { error = tostring(serr) })
    end
end

local function serve_transparent_http(ctx, conf, client, listen_port)
    state.sync()
    local port = listen_port or 80
    local client_reader = reader_mod.wrap(client)
    local served = 0

    while served < conf.limits.maxRequestsPerConnection do
        local raw = client_reader:read_until("\r\n\r\n", conf.limits.maxHeadBytes)
        if not raw then
            return
        end
        served = served + 1
        ctx.id = util.gen_id()
        ctx.started = util.monotonic()
        ctx.bytes_sent = 0
        ctx.bytes_received = 0

        local req, perr = http.parse_request_head(raw)
        if not req then
            metrics.inc("ro_protocol_violations_total", { kind = "request" })
            reject(ctx, client, 400, "protocol.malformed_request", perr)
            return
        end
        if req.parsed_target.form ~= "origin" then
            reject(ctx, client, 400, "protocol.origin_form_required")
            return
        end
        local host_hdr = req.headers:get("host")
        if not host_hdr then
            reject(ctx, client, 400, "protocol.missing_host")
            return
        end
        local hinfo, hport = target_mod.parse_authority(host_hdr, port)
        if not hinfo then
            reject(ctx, client, 400, "protocol.bad_host_header")
            return
        end

        local head_end = raw:find("\r\n", 1, true)
        local rebuilt = format("%s http://%s%s %s", req.method, host_hdr,
            req.target, req.version) .. sub(raw, head_end)
        local proxy_req, pperr = http.parse_request_head(rebuilt)
        if not proxy_req then
            reject(ctx, client, 400, "protocol.malformed_request", pperr)
            return
        end

        local cont = handle_http_request(ctx, proxy_req, client_reader, client)
        if cont ~= true then
            return
        end
    end
end

function _M.run_transparent_http(conf, listen_port)
    local client, err = ngx.req.socket(true)
    if not client then
        log.error("cannot obtain downstream socket", { error = tostring(err) })
        return
    end
    client:settimeout(conf.limits.clientTimeoutMs)

    local ctx = new_ctx(conf, "transparent_http")
    metrics.inc("ro_connections_total", { mode = "transparent_http" })

    if not admit(ctx, client) then
        return
    end

    local ok, serr = pcall(serve_transparent_http, ctx, conf, client, listen_port)
    release_limits(ctx)
    depart(ctx)
    if not ok then
        log.error("transparent http handler failed", { error = tostring(serr) })
    end
end

function _M.run(conf, mode, listen_port)
    conf = conf or state.config()
    if not conf then
        return
    end
    mode = mode or conf.mode
    local ok, err
    if mode == "transparent_tls" then
        ok, err = pcall(_M.run_transparent_tls, conf, listen_port)
    elseif mode == "transparent_http" then
        ok, err = pcall(_M.run_transparent_http, conf, listen_port)
    else
        ok, err = pcall(_M.run_explicit, conf)
    end
    if not ok then
        log.error("connection handler crashed", { error = tostring(err) })
    end
end

_M.evaluate = evaluate
_M.guard_literal = guard_literal
_M.resolve_destination = resolve_destination
_M.check_redirect = check_redirect

return _M
