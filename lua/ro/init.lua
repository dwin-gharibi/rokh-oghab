local config = require("ro.config")
local metrics = require("ro.metrics")
local otel = require("ro.otel")
local log = require("ro.log")
local state = require("ro.state")
local limits = require("ro.limits")
local httpc = require("ro.httpc")
local util = require("ro.util")
local cjson = require("cjson.safe")

local _M = { _VERSION = "1.0.0" }

local conf
local last_file_check = 0
local last_file_digest = nil

function _M.config()
    return conf
end

function _M.init()
    local path = os.getenv("RO_CONFIG") or "/etc/rokh-oghab/gateway.json"
    local loaded, lerr = config.load(path)
    if not loaded then
        ngx.log(ngx.ERR, "rokh-oghab: ", tostring(lerr))
        return
    end
    local valid, verr = config.validate(loaded)
    if not valid then
        ngx.log(ngx.ERR, "rokh-oghab: invalid configuration: ", tostring(verr))
        return
    end
    conf = valid

    metrics.init("ro_metrics", { max_series = 20000 })
    metrics.bootstrap()
    metrics.set("ro_build_info", { version = _M._VERSION, node = conf.node }, 1)

    log.init({
        path = conf.audit.path,
        level = conf.audit.level,
        log_paths = conf.audit.logPaths == true,
        log_query = conf.audit.logQuery == true,
        capacity = conf.audit.capacity,
        buffer_max = conf.audit.bufferMax,
        flush_interval = conf.audit.flushInterval,
        dict = "ro_audit",
        component = "ro-gateway",
    })

    otel.configure({
        enabled = conf.telemetry.enabled == true,
        endpoint = conf.telemetry.endpoint,
        tracesPath = conf.telemetry.tracesPath,
        serviceName = conf.telemetry.serviceName,
        serviceNamespace = conf.telemetry.serviceNamespace,
        node = conf.node,
        headers = conf.telemetry.headers,
        sampleRatio = conf.telemetry.sampleRatio,
        maxQueue = conf.telemetry.maxQueue,
        maxBatch = conf.telemetry.maxBatch,
        timeoutMs = conf.telemetry.timeoutMs,
        exportIntervalSeconds = conf.telemetry.exportIntervalSeconds,
        trustIncomingTrace = conf.telemetry.trustIncomingTrace == true,
        recordDestination = conf.telemetry.recordDestination == true,
    })

    state.configure(conf)

    if not conf.admin or conf.admin.token == nil or conf.admin.token == "" then
        ngx.log(ngx.WARN, "rokh-oghab: no admin.token configured; the gateway "
            .. "admin API will refuse every privileged request "
            .. "(health, readiness and metrics remain available)")
    end

    local fh = io.open(conf.bundleFile, "r")
    if not fh then
        ngx.log(ngx.WARN, "rokh-oghab: no local policy bundle at ", conf.bundleFile,
            "; gateway starts fail-closed until the controller supplies one")
        metrics.set("ro_policy_stale", nil, 1)
        return
    end
    local body = fh:read("*a")
    fh:close()
    local raw, derr = cjson.decode(body)
    if not raw then
        ngx.log(ngx.ERR, "rokh-oghab: cannot parse ", conf.bundleFile, ": ",
            tostring(derr), "; gateway starts fail-closed")
        metrics.set("ro_policy_stale", nil, 1)
        return
    end
    local built, aerr = state.apply(raw)
    if not built then
        ngx.log(ngx.ERR, "rokh-oghab: policy bundle rejected: ", tostring(aerr),
            "; gateway starts fail-closed")
        metrics.set("ro_policy_stale", nil, 1)
    end
end

local function read_file(path)
    local fh = io.open(path, "r")
    if not fh then
        return nil
    end
    local body = fh:read("*a")
    fh:close()
    return body
end

local function hmac_matches(key, body, presented)
    if type(key) ~= "string" or key == "" then
        return false
    end
    local expected = util.hmac_sha256_hex(key, body)
    if not expected then
        return false
    end
    return util.const_eq(presented, expected)
end

local function bundle_signature_ok(ctl, res)
    local key = ctl.signingKey
    local accept = ctl.acceptSigningKeys
    local extras = type(accept) == "table" and #accept or 0
    if (not key or key == "") and extras == 0 then
        return ctl.requireSignature ~= true
    end
    local header = res.headers and res.headers:get("x-ro-bundle-signature")
    if not header then
        return false
    end
    local presented = header:gsub("^sha256=", "")
    local body = res.body or ""
    if hmac_matches(key, body, presented) then
        return true
    end
    for i = 1, extras do
        if hmac_matches(accept[i], body, presented) then
            return true
        end
    end
    return false
end

local function poll_controller(premature)
    if premature then
        return
    end
    local interval = conf.controller.pollSeconds or 10
    local url = conf.controller.url
    if url and url ~= "" then
        local ctl = conf.controller
        local res, err = httpc.request(url .. "/v1/bundle", {
            token = ctl.token,
            timeout = ctl.timeoutMs,
            tls_verify = ctl.tlsVerify ~= false,
            tls_server_name = ctl.tlsServerName,
        })
        if not res then
            log.warn("controller poll failed", { error = tostring(err) })
            metrics.inc("ro_policy_reload_failures_total", { reason = "fetch" })
            metrics.set("ro_policy_stale", nil, 1)
        elseif res.status ~= 200 then
            log.warn("controller returned an error", { status = res.status })
            metrics.inc("ro_policy_reload_failures_total", { reason = "status" })
        elseif not res.json then
            log.warn("controller returned invalid json")
            metrics.inc("ro_policy_reload_failures_total", { reason = "json" })
        elseif not bundle_signature_ok(ctl, res) then
            log.error("controller bundle signature did not verify; refusing to "
                .. "adopt it")
            metrics.inc("ro_policy_reload_failures_total", { reason = "signature" })
            metrics.set("ro_policy_stale", nil, 1)
        else
            state.mark_fresh()
            local digest = util.content_digest(res.json)
            if digest ~= state.published_digest() then
                local built, aerr = state.build(res.json)
                if not built then
                    log.error("controller bundle rejected", { error = tostring(aerr) })
                    metrics.inc("ro_policy_reload_failures_total",
                        { reason = "invalid" })
                else
                    state.publish(cjson.encode(res.json), built.digest)
                    log.info("controller bundle published", {
                        version = built.version, digest = built.digest,
                    })
                end
            end
        end
    end

    local now = util.now()
    if (not url or url == "") and now - last_file_check > 5 then
        last_file_check = now
        local body = read_file(conf.bundleFile)
        if body then
            local digest = util.sha256_hex(body)
            if digest ~= last_file_digest then
                last_file_digest = digest
                local raw = cjson.decode(body)
                if raw then
                    local built, berr = state.build(raw)
                    if built then
                        if built.digest ~= state.published_digest() then
                            state.publish(cjson.encode(raw), built.digest)
                            log.info("local bundle file published", {
                                version = built.version,
                            })
                        end
                    else
                        log.error("local bundle file rejected",
                            { error = tostring(berr) })
                        metrics.inc("ro_policy_reload_failures_total",
                            { reason = "file" })
                    end
                end
            end
        end
    end

    ngx.timer.at(interval, poll_controller)
end

local function sync_worker(premature)
    if premature then
        return
    end
    local ok, err = pcall(state.sync)
    if not ok then
        log.error("policy sync failed", { error = tostring(err) })
    end
    local usable = state.is_usable()
    metrics.set("ro_policy_stale", nil, usable and 0 or 1)
    ngx.timer.at(1, sync_worker)
end

function _M.init_worker()
    if not conf then
        return
    end
    local lok, lerr = limits.init("ro_limits")
    if not lok then
        log.error("limits: shared dictionary unavailable, every configured "
            .. "rate and connection limit will refuse rather than pass",
            { error = tostring(lerr) })
        metrics.set("ro_limits_unavailable", nil, 1)
    else
        metrics.set("ro_limits_unavailable", nil, 0)
    end
    log.start()
    otel.start()
    ngx.timer.at(0, sync_worker)
    if ngx.worker.id() == 0 then
        ngx.timer.at(0, poll_controller)
    end
end

return _M
