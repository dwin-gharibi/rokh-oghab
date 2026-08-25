local httpd = require("ro.httpd")
local metrics = require("ro.metrics")
local state = require("ro.state")
local log = require("ro.log")
local util = require("ro.util")
local cidr = require("ro.cidr")
local ipaddr = require("ro.ipaddr")
local cjson = require("cjson.safe")

local _M = { _VERSION = "1.0.0" }

local format = string.format

local allow_set
local conf

local function build_allow_set(c)
    local set = cidr.new()
    local list = (c.admin and c.admin.allowFrom) or {}
    for _, entry in ipairs(list) do
        set:add(entry)
    end
    return set
end

local function source_allowed(remote_addr)
    if not allow_set or allow_set:size() == 0 then
        return false
    end
    if type(remote_addr) ~= "string" then
        return false
    end
    local v4 = ipaddr.parse_ipv4(remote_addr)
    if v4 then
        return allow_set:match_v4(v4) ~= nil
    end
    local g = ipaddr.parse_ipv6(remote_addr)
    if g then
        if allow_set:match_v6(g) then
            return true
        end
        local mapped = ipaddr.ipv4_mapped(g)
        if mapped then
            return allow_set:match_v4(mapped) ~= nil
        end
    end
    return false
end

local ROLE_RANK = { reader = 1, operator = 2, admin = 3 }

local function presented_role(ctx)
    local admin = conf.admin or {}
    local header = ctx.headers:get("authorization")
    if not header then
        return nil, "a valid bearer token is required"
    end
    local scheme, value = header:match("^(%a+)%s+(.+)$")
    if not scheme or scheme:lower() ~= "bearer" then
        return nil, "a valid bearer token is required"
    end
    value = util.trim(value)
    if value == "" then
        return nil, "a valid bearer token is required"
    end
    local matched
    for _, pair in ipairs({
        { "admin", admin.token },
        { "operator", admin.operatorToken },
        { "reader", admin.readerToken },
    }) do
        local candidate = pair[2] or ""
        if candidate ~= "" and util.const_eq(value, candidate) then
            if not matched or ROLE_RANK[pair[1]] > ROLE_RANK[matched] then
                matched = pair[1]
            end
        end
    end
    if not matched then
        return nil, "a valid bearer token is required"
    end
    return matched
end

local function authorized(ctx, need)
    local admin = conf.admin or {}
    if (admin.token or "") == "" and (admin.operatorToken or "") == ""
        and (admin.readerToken or "") == "" then
        return false, "no admin token is configured on this gateway"
    end
    local role, why = presented_role(ctx)
    if not role then
        return false, why
    end
    if ROLE_RANK[role] < ROLE_RANK[need or "admin"] then
        return false, format("this endpoint requires the %s role", need)
    end
    return true, nil, role
end

local routes = {}

routes["GET /healthz"] = function()
    return httpd.json(200, { status = "ok", component = "ro-gateway" })
end

routes["GET /readyz"] = function()
    local usable, reason = state.is_usable()
    if usable then
        return httpd.json(200, { status = "ready", version = state.get().version })
    end
    return httpd.json(503, { status = "not_ready", reason = reason })
end

routes["GET /metrics"] = function()
    return httpd.response(200, metrics.render(), nil, "text/plain; version=0.0.4")
end

routes["GET /v1/status"] = function()
    local st = state.get()
    return httpd.json(200, {
        component = "ro-gateway",
        node = conf.node,
        mode = conf.mode,
        policy = state.summary(),
        emergencyDeny = state.emergency(),
        worker = ngx.worker.id(),
        pid = ngx.worker.pid(),
        uptimeSeconds = util.now() - (st and st.loaded_at or util.now()),
    })
end

routes["GET /v1/policy"] = function()
    return httpd.json(200, state.summary())
end

routes["GET /v1/audit"] = function(ctx)
    local limit = tonumber(ctx.query.limit) or 100
    local filter = nil
    if ctx.query.action or ctx.query.identity then
        filter = {}
        if ctx.query.action then filter.action = ctx.query.action end
        if ctx.query.identity then filter.identity = ctx.query.identity end
    end
    return httpd.json(200, { events = log.recent(limit, filter) })
end

routes["POST /v1/bundle"] = function(ctx)
    local raw, derr = cjson.decode(ctx.body)
    if not raw then
        return httpd.error(400, "invalid_json", tostring(derr))
    end
    local built, aerr = state.apply(raw)
    if not built then
        return httpd.error(422, "invalid_bundle", tostring(aerr))
    end
    log.audit({
        event = "admin", action = "apply_bundle", client = ctx.remote_addr,
        version = built.version, digest = built.digest, severity = "high",
    })
    return httpd.json(200, { applied = true, version = built.version,
        digest = built.digest })
end

routes["POST /v1/validate"] = function(ctx)
    local raw, derr = cjson.decode(ctx.body)
    if not raw then
        return httpd.error(400, "invalid_json", tostring(derr))
    end
    local built, aerr = state.build(raw)
    if not built then
        return httpd.json(200, { valid = false, error = tostring(aerr) })
    end
    return httpd.json(200, { valid = true, version = built.version,
        summary = built.bundle:summary() })
end

routes["POST /v1/emergency-deny"] = function(ctx)
    local body = cjson.decode(ctx.body) or {}
    local enabled = body.enabled ~= false
    local ok, err = state.set_emergency(enabled)
    if not ok then
        return httpd.error(503, "unavailable", tostring(err))
    end
    log.audit({
        event = "admin", action = "emergency_deny", enabled = enabled,
        client = ctx.remote_addr, severity = "high",
    })
    return httpd.json(200, {
        emergencyDeny = state.emergency(),
        localOverride = enabled,
    })
end

routes["POST /v1/dns/flush"] = function(ctx)
    local st = state.get()
    if not st then
        return httpd.error(503, "not_ready", "no policy loaded")
    end
    local body = cjson.decode(ctx.body) or {}
    st.resolver:flush(body.name)
    return httpd.json(200, { flushed = body.name or "all" })
end

routes["GET /v1/config"] = function()
    local safe = util.deep_copy(conf)
    if safe.admin then
        for _, field in ipairs({ "token", "readerToken", "operatorToken" }) do
            if safe.admin[field] ~= nil then
                safe.admin[field] = safe.admin[field] ~= "" and "***" or ""
            end
        end
    end
    if safe.controller then
        safe.controller.token = safe.controller.token ~= "" and "***" or ""
    end
    if safe.telemetry and type(safe.telemetry.headers) == "table" then
        for name, value in pairs(safe.telemetry.headers) do
            safe.telemetry.headers[name] = value ~= "" and "***" or ""
        end
    end
    return httpd.json(200, safe)
end

local PUBLISHABLE = {
    ["GET /healthz"] = "healthz",
    ["GET /readyz"] = "readyz",
    ["GET /metrics"] = "metrics",
}

local REQUIRED_ROLE = {
    ["GET /healthz"] = "reader",
    ["GET /readyz"] = "reader",
    ["GET /metrics"] = "reader",
    ["GET /v1/status"] = "reader",
    ["GET /v1/policy"] = "reader",
    ["GET /v1/audit"] = "operator",
    ["POST /v1/dns/flush"] = "operator",
    ["POST /v1/emergency-deny"] = "operator",
    ["POST /v1/validate"] = "operator",
    ["GET /v1/config"] = "admin",
    ["POST /v1/bundle"] = "admin",
}

local function is_public(key)
    local name = PUBLISHABLE[key]
    if not name then
        return false
    end
    local list = conf.admin and conf.admin.public
    if type(list) ~= "table" then
        return false
    end
    for i = 1, #list do
        if list[i] == name then
            return true
        end
    end
    return false
end

function _M.router(ctx)
    state.sync()
    local key = ctx.method .. " " .. ctx.path
    if not source_allowed(ctx.remote_addr) then
        log.warn("admin request from disallowed source",
            { client = ctx.remote_addr, path = ctx.path })
        return httpd.error(403, "forbidden", "source address not permitted")
    end
    local handler = routes[key]
    if not handler then
        return httpd.error(404, "not_found", "no such endpoint")
    end
    if not is_public(key) then
        local need = REQUIRED_ROLE[key] or "admin"
        local ok, why, role = authorized(ctx, need)
        if not ok then
            metrics.inc("ro_admin_denied_total", { role = need })
            log.warn("admin request refused", {
                client = ctx.remote_addr, path = ctx.path,
                method = ctx.method, need = need,
            })
            return httpd.error(401, "unauthorized",
                why or "a valid bearer token is required")
        end
        ctx.role = role
    end
    return handler(ctx)
end

function _M.run(c)
    conf = c or state.config()
    if not conf then
        return
    end
    if allow_set == nil then
        allow_set = build_allow_set(conf)
        if allow_set:size() == 0 then
            log.warn("admin: allowFrom is empty, so the admin listener will "
                .. "refuse every request including metrics and health probes")
        end
    end
    httpd.serve(_M.router, { max_body = 8388608 })
end

return _M
