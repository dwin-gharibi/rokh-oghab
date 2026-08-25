local cjson = require("cjson.safe")
local policy = require("ro.policy")
local guard_mod = require("ro.guard")
local identity_mod = require("ro.identity")
local resolver_mod = require("ro.resolver")
local config_mod = require("ro.config")
local metrics = require("ro.metrics")
local util = require("ro.util")
local log = require("ro.log")

local _M = { _VERSION = "1.0.0" }

local current = nil
local conf = nil
local state_dict

local MAX_STALENESS = 86400
local DEFAULT_STALENESS = 900

local function staleness_budget(defaults, raw)
    local explicit = tonumber(defaults.maxStalenessSeconds)
    if explicit and explicit > 0 then
        return explicit
    end
    local ttl = tonumber(raw.ttlSeconds)
    if ttl and ttl > 0 then
        local derived = ttl * 3
        if derived ~= derived or derived > MAX_STALENESS then
            return MAX_STALENESS
        end
        return derived
    end
    return DEFAULT_STALENESS
end

function _M.configure(c)
    conf = c
    state_dict = ngx.shared.ro_state
    return true
end

function _M.config()
    return conf
end

function _M.build(raw)
    if type(raw) ~= "table" then
        return nil, "bundle must be an object"
    end

    local bundle, err = policy.compile(raw)
    if not bundle then
        return nil, err
    end

    local gconf = util.deep_copy(conf.guard or {})
    local bguard = raw.guard or {}
    local blocked = {}
    for _, c in ipairs(gconf.blocked or {}) do blocked[#blocked + 1] = c end
    for _, c in ipairs(bguard.blocked or {}) do blocked[#blocked + 1] = c end
    local exceptions = {}
    for _, c in ipairs(gconf.allowExceptions or {}) do exceptions[#exceptions + 1] = c end
    for _, c in ipairs(bguard.allowExceptions or {}) do exceptions[#exceptions + 1] = c end

    local guard, gerr = guard_mod.new({
        include_defaults = gconf.includeDefaults ~= false,
        blocked = blocked,
        allow_exceptions = exceptions,
        block_obfuscated = gconf.blockObfuscated ~= false,
        allow_ipv6 = gconf.allowIPv6 ~= false,
    })
    if not guard then
        return nil, gerr
    end

    local identities, ierr = identity_mod.new(raw.identities or {}, {
        allow_anonymous = (conf.identities or {}).allowAnonymous == true,
    })
    if not identities then
        return nil, ierr
    end

    local resolver, rerr = resolver_mod.new({
        servers = config_mod.parse_servers(conf.resolver.servers),
        timeout = conf.resolver.timeoutMs,
        retries = conf.resolver.retries,
        cache_dict = "ro_dnscache",
        guard = guard,
        min_ttl = conf.resolver.minTtl,
        max_ttl = conf.resolver.maxTtl,
        allow_ipv6 = conf.resolver.allowIPv6 ~= false,
        prefer_ipv6 = conf.resolver.preferIPv6 == true,
        max_addresses = conf.resolver.maxAddresses,
    })
    if not resolver then
        return nil, rerr
    end

    local defaults = raw.defaults or {}

    return {
        bundle = bundle,
        guard = guard,
        identities = identities,
        resolver = resolver,
        version = bundle.version,
        loaded_at = util.now(),
        issued_at = bundle.issued_at,
        max_staleness = staleness_budget(defaults, raw),
        emergency_deny = bundle.emergency_deny,
        digest = util.content_digest(raw),
        raw_defaults = defaults,
    }
end

function _M.activate(raw)
    local built, err = _M.build(raw)
    if not built then
        metrics.inc("ro_policy_reload_failures_total", { reason = "invalid" })
        return nil, err
    end
    current = built
    _M.mark_fresh()
    metrics.inc("ro_policy_reload_total", { result = "ok" })
    metrics.set("ro_policy_version", nil, built.version)
    metrics.set("ro_emergency_deny", nil, _M.emergency() and 1 or 0)
    metrics.set("ro_policy_stale", nil, 0)
    if state_dict then
        state_dict:set("policy_version", built.version)
        state_dict:set("policy_digest", built.digest)
        state_dict:set("policy_loaded_at", built.loaded_at)
    end
    log.info("policy bundle activated", {
        version = built.version,
        digest = built.digest,
        policies = #built.bundle.policies,
        rules = built.bundle.rule_count,
    })
    return built
end

function _M.load_file(path)
    local fh, ferr = io.open(path, "r")
    if not fh then
        return nil, "cannot open bundle: " .. tostring(ferr)
    end
    local body = fh:read("*a")
    fh:close()
    local raw, derr = cjson.decode(body)
    if not raw then
        return nil, "cannot parse bundle: " .. tostring(derr)
    end
    return _M.activate(raw)
end

function _M.publish(raw_json, digest)
    local dict = ngx.shared.ro_policy
    if not dict then
        return nil, "ro_policy shared dict is not configured"
    end
    local ok, err = dict:set("bundle", raw_json)
    if not ok then
        return nil, "cannot publish bundle: " .. tostring(err)
    end
    dict:set("digest", digest)
    dict:incr("generation", 1, 0)
    return true
end

function _M.published_digest()
    local dict = ngx.shared.ro_policy
    if not dict then
        return nil
    end
    return dict:get("digest")
end

function _M.sync()
    local dict = ngx.shared.ro_policy
    if not dict then
        return false
    end
    local digest = dict:get("digest")
    if not digest then
        return false
    end
    if current and current.digest == digest then
        return false
    end
    log.info("worker is adopting a newer policy bundle", {
        from = current and current.digest or "none", to = digest,
    })
    local raw_json = dict:get("bundle")
    if not raw_json then
        return false
    end
    local raw, derr = cjson.decode(raw_json)
    if not raw then
        log.error("cannot decode published bundle", { error = tostring(derr) })
        metrics.inc("ro_policy_reload_failures_total", { reason = "decode" })
        return false
    end
    local built, aerr = _M.activate(raw)
    if not built then
        log.error("cannot activate published bundle", { error = tostring(aerr) })
        return false
    end
    return true
end

function _M.apply(raw)
    local built, err = _M.build(raw)
    if not built then
        return nil, err
    end
    local raw_json = cjson.encode(raw)
    if not raw_json then
        return nil, "cannot encode bundle"
    end
    local ok, perr = _M.publish(raw_json, built.digest)
    if not ok then
        return nil, perr
    end
    current = built
    _M.mark_fresh()
    metrics.inc("ro_policy_reload_total", { result = "ok" })
    metrics.set("ro_policy_version", nil, built.version)
    metrics.set("ro_policy_stale", nil, 0)
    log.info("policy bundle applied", {
        version = built.version, digest = built.digest,
    })
    return built
end

function _M.get()
    return current
end

function _M.mark_fresh()
    if state_dict then
        state_dict:set("last_fresh", util.now())
    end
end

function _M.last_fresh()
    if state_dict then
        local v = state_dict:get("last_fresh")
        if v then
            return v
        end
    end
    return current and current.loaded_at or nil
end

function _M.staleness()
    local anchor = _M.last_fresh()
    if not anchor then
        return math.huge
    end
    return util.now() - anchor
end

function _M.set_emergency(enabled)
    if not state_dict then
        return nil, "the shared state dictionary is unavailable, so the "
            .. "emergency switch cannot be set for every worker and will not "
            .. "be set for any"
    end
    state_dict:set("emergency_deny", enabled and 1 or 0)
    metrics.set("ro_emergency_deny", nil, _M.emergency() and 1 or 0)
    log.warn("emergency deny switch changed",
        { enabled = enabled and true or false })
    return true
end

function _M.emergency()
    if state_dict and state_dict:get("emergency_deny") == 1 then
        return true
    end
    return current ~= nil and current.bundle.emergency_deny == true
end

function _M.is_usable()
    if not current then
        return false, "policy.not_loaded"
    end
    local controller = conf and conf.controller or nil
    if controller and controller.url and controller.url ~= ""
        and controller.failClosed ~= false
        and current.max_staleness and current.max_staleness > 0 then
        local age = _M.staleness()
        if age > current.max_staleness then
            metrics.set("ro_policy_stale", nil, 1)
            return false, "policy.stale"
        end
    end
    if _M.emergency() then
        return false, "emergency.deny"
    end
    return true
end

function _M.summary()
    if not current then
        return { loaded = false }
    end
    local s = current.bundle:summary()
    s.loaded = true
    s.loadedAt = current.loaded_at
    s.digest = current.digest
    s.stalenessSeconds = _M.staleness()
    s.maxStalenessSeconds = current.max_staleness
    s.guard = current.guard:stats()
    s.identities = current.identities:stats()
    return s
end

return _M
