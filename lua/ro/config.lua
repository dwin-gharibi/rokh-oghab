local cjson = require("cjson.safe")
local util = require("ro.util")

local _M = { _VERSION = "1.0.0" }

local DEFAULTS = {
    node = "ro-gateway",
    mode = "explicit",
    bundleFile = "/etc/rokh-oghab/bundle.json",
    controller = {
        url = "",
        token = "",
        pollSeconds = 10,
        timeoutMs = 3000,
        failClosed = true,
    },
    resolver = {
        servers = { "1.1.1.1:53", "8.8.8.8:53" },
        timeoutMs = 2000,
        retries = 2,
        minTtl = 5,
        maxTtl = 300,
        allowIPv6 = true,
        preferIPv6 = false,
        maxAddresses = 8,
    },
    guard = {
        includeDefaults = true,
        blocked = {},
        allowExceptions = {},
        blockObfuscated = true,
        allowIPv6 = true,
    },
    strict = {
        path = true,
        sniMatch = true,
        hostMatch = true,
        requireTls = false,
        minTlsVersion = "1.2",
        redirectGuard = true,
        blockPlaintextOnTlsPorts = true,
        tlsPorts = { 443, 8443, 9443 },
        verifyOriginalDestination = false,
    },
    limits = {
        maxHeadBytes = 65536,
        maxRequestsPerConnection = 256,
        clientTimeoutMs = 60000,
        upstreamTimeoutMs = 30000,
        connectTimeoutMs = 5000,
        idleTimeoutMs = 120000,
        globalMaxConnections = 20000,
        maxConnectionsPerSource = 256,
        headTimeoutMs = 10000,
        upstreamPoolSize = 32,
        defaultRequestsPerSecond = 0,
        defaultMaxConnections = 0,
    },
    audit = {
        path = "/dev/stdout",
        level = "info",
        logPaths = false,
        logQuery = false,
        capacity = 4096,
        bufferMax = 64,
        flushInterval = 0.2,
    },
    dns = {
        enabled = true,
        upstreamTimeoutMs = 2000,
        allowedTypes = { "A", "AAAA" },
        maxAnswers = 8,
        denyResponse = "nxdomain",
    },
    admin = {
        token = "",
        readerToken = "",
        operatorToken = "",
        allowFrom = { "127.0.0.1/32", "::1/128" },
        public = { "healthz", "readyz", "metrics" },
    },
    identities = {
        allowAnonymous = false,
    },
    telemetry = {
        enabled = false,
        endpoint = "",
        tracesPath = "/v1/traces",
        serviceName = "rokh-oghab-gateway",
        serviceNamespace = "rokh-oghab",
        headers = {},
        sampleRatio = 1.0,
        maxQueue = 512,
        maxBatch = 128,
        timeoutMs = 2000,
        exportIntervalSeconds = 5,
        trustIncomingTrace = false,
        recordDestination = false,
    },
}

local function deep_merge(base, override)
    if type(override) ~= "table" then
        return base
    end
    for k, v in pairs(override) do
        if type(v) == "table" and type(base[k]) == "table"
            and not util.is_array(v) then
            deep_merge(base[k], v)
        else
            base[k] = v
        end
    end
    return base
end

_M.deep_merge = deep_merge

function _M.defaults()
    return util.deep_copy(DEFAULTS)
end

function _M.parse_servers(list)
    local out = {}
    if type(list) ~= "table" then
        return out
    end
    for _, entry in ipairs(list) do
        if type(entry) == "string" then
            local host, port = entry:match("^%[(.+)%]:(%d+)$")
            if not host then
                host, port = entry:match("^([^:]+):(%d+)$")
            end
            if not host then
                host = entry
                port = 53
            end
            out[#out + 1] = { host = host, port = tonumber(port) or 53 }
        elseif type(entry) == "table" and entry.host then
            out[#out + 1] = { host = entry.host, port = tonumber(entry.port) or 53 }
        end
    end
    return out
end

function _M.load(path)
    local conf = _M.defaults()
    if path and path ~= "" then
        local fh = io.open(path, "r")
        if fh then
            local body = fh:read("*a")
            fh:close()
            local parsed, err = cjson.decode(body)
            if not parsed then
                return nil, "cannot parse " .. path .. ": " .. tostring(err)
            end
            deep_merge(conf, parsed)
        end
    end

    local env = os.getenv
    local function envset(value, target, key, kind)
        if value == nil or value == "" then
            return
        end
        if kind == "number" then
            local n = tonumber(value)
            if n then target[key] = n end
        elseif kind == "boolean" then
            target[key] = (value == "1" or value == "true" or value == "yes")
        else
            target[key] = value
        end
    end

    envset(env("RO_NODE"), conf, "node")
    envset(env("RO_MODE"), conf, "mode")
    envset(env("RO_BUNDLE_FILE"), conf, "bundleFile")
    envset(env("RO_CONTROLLER_URL"), conf.controller, "url")
    envset(env("RO_CONTROLLER_TOKEN"), conf.controller, "token")
    envset(env("RO_CONTROLLER_POLL_SECONDS"), conf.controller, "pollSeconds", "number")
    envset(env("RO_CONTROLLER_FAIL_CLOSED"), conf.controller, "failClosed", "boolean")
    envset(env("RO_OTEL_ENABLED"), conf.telemetry, "enabled", "boolean")
    envset(env("RO_OTEL_ENDPOINT"), conf.telemetry, "endpoint")
    envset(env("RO_OTEL_SERVICE_NAME"), conf.telemetry, "serviceName")
    envset(env("RO_OTEL_SAMPLE_RATIO"), conf.telemetry, "sampleRatio", "number")
    envset(env("RO_OTEL_TRUST_INCOMING_TRACE"), conf.telemetry,
        "trustIncomingTrace", "boolean")
    envset(env("RO_OTEL_RECORD_DESTINATION"), conf.telemetry,
        "recordDestination", "boolean")
    envset(env("RO_ADMIN_TOKEN"), conf.admin, "token")
    envset(env("RO_ADMIN_READER_TOKEN"), conf.admin, "readerToken")
    envset(env("RO_ADMIN_OPERATOR_TOKEN"), conf.admin, "operatorToken")
    envset(env("RO_AUDIT_PATH"), conf.audit, "path")
    envset(env("RO_AUDIT_LEVEL"), conf.audit, "level")
    envset(env("RO_AUDIT_LOG_PATHS"), conf.audit, "logPaths", "boolean")
    envset(env("RO_ALLOW_ANONYMOUS"), conf.identities, "allowAnonymous", "boolean")
    envset(env("RO_STRICT_PATH"), conf.strict, "path", "boolean")
    envset(env("RO_STRICT_SNI"), conf.strict, "sniMatch", "boolean")
    envset(env("RO_MIN_TLS_VERSION"), conf.strict, "minTlsVersion")

    local public = env("RO_ADMIN_PUBLIC")
    if public ~= nil then
        local list = {}
        if public ~= "" and public ~= "none" then
            for _, entry in ipairs(util.split(public, ",")) do
                local name = util.trim(entry)
                if name ~= "" then
                    list[#list + 1] = name
                end
            end
        end
        conf.admin.public = list
    end

    local servers = env("RO_RESOLVER_SERVERS")
    if servers and servers ~= "" then
        conf.resolver.servers = util.split(servers, ",")
        for i, s in ipairs(conf.resolver.servers) do
            conf.resolver.servers[i] = util.trim(s)
        end
    end

    return conf
end

function _M.validate(conf)
    if type(conf) ~= "table" then
        return nil, "config must be an object"
    end
    if conf.mode ~= "explicit" and conf.mode ~= "transparent_http"
        and conf.mode ~= "transparent_tls" then
        return nil, "mode must be explicit, transparent_http or transparent_tls"
    end
    local servers = _M.parse_servers(conf.resolver.servers)
    if #servers == 0 then
        return nil, "at least one resolver server is required"
    end
    local tel = conf.telemetry
    if type(tel) ~= "table" then
        return nil, "telemetry must be an object"
    end
    if tel.enabled == true then
        if type(tel.endpoint) ~= "string" or tel.endpoint == "" then
            return nil, "telemetry.enabled requires telemetry.endpoint"
        end
        local scheme = tel.endpoint:match("^(%a[%w+.-]*)://")
        if scheme ~= "http" and scheme ~= "https" then
            return nil, "telemetry.endpoint must be an http or https url"
        end
    end
    local ratio = tonumber(tel.sampleRatio)
    if ratio == nil or ratio < 0 or ratio > 1 then
        return nil, "telemetry.sampleRatio must be between 0 and 1"
    end
    for _, field in ipairs({ "maxQueue", "maxBatch", "timeoutMs",
        "exportIntervalSeconds" }) do
        local n = tonumber(tel[field])
        if n == nil or n <= 0 then
            return nil, "telemetry." .. field .. " must be a positive number"
        end
    end
    if type(tel.headers) ~= "table" then
        return nil, "telemetry.headers must be an object"
    end
    if conf.strict.tlsPorts ~= nil then
        if type(conf.strict.tlsPorts) ~= "table"
            or not util.is_array(conf.strict.tlsPorts) then
            return nil, "strict.tlsPorts must be an array of port numbers"
        end
        for _, port in ipairs(conf.strict.tlsPorts) do
            local n = tonumber(port)
            if not n or n < 1 or n > 65535 or n ~= math.floor(n) then
                return nil, "strict.tlsPorts contains an invalid port: "
                    .. tostring(port)
            end
        end
    end
    if conf.strict.minTlsVersion then
        local v = tostring(conf.strict.minTlsVersion)
        if v ~= "1.0" and v ~= "1.1" and v ~= "1.2" and v ~= "1.3" then
            return nil, "strict.minTlsVersion must be 1.0, 1.1, 1.2 or 1.3"
        end
    end
    return conf
end

return _M
