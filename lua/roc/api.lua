local cjson = require("cjson.safe")
local store = require("roc.store")
local yaml = require("roc.yaml")
local policy = require("ro.policy")
local util = require("ro.util")
local log = require("ro.log")
local metrics = require("ro.metrics")
local cidr = require("ro.cidr")
local ipaddr = require("ro.ipaddr")

local _M = { _VERSION = "1.0.0" }

local find = string.find
local sub = string.sub
local lower = string.lower
local format = string.format

local conf
local principals = {}
local allow_set
local unrestricted_sources = false
local bundle_signing_key

local ROLE_RANK = { gateway = 1, reader = 2, operator = 3, admin = 4 }
local TOKEN_DIGEST_LEN = 64
local TOKEN_DIGEST_MIN = 16

local function say(status, body)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["X-Content-Type-Options"] = "nosniff"
    ngx.print(cjson.encode(body))
    return ngx.exit(status)
end

local function fail(status, code, message)
    metrics.inc("roc_api_errors_total", { code = code })
    return say(status, { error = code, message = message })
end

function _M.configure(c)
    conf = c
    principals = {}
    for _, entry in ipairs(c.principals or {}) do
        local digest = entry.tokenSha256
        if digest == "" then digest = nil end
        if not digest and entry.token and entry.token ~= "" then
            digest = util.sha256_hex(entry.token)
        end
        if digest then
            principals[lower(digest)] = {
                name = entry.name or "unnamed",
                role = entry.role or "reader",
            }
        end
    end
    bundle_signing_key = nil
    if type(c.bundleSigningKey) == "string" and c.bundleSigningKey ~= "" then
        if #c.bundleSigningKey < 16 then
            ngx.log(ngx.ERR, "ro-controller: bundleSigningKey is shorter than "
                .. "16 characters and is refused; bundles will be served "
                .. "unsigned until a strong key is set")
        else
            bundle_signing_key = c.bundleSigningKey
        end
    end
    allow_set = nil
    unrestricted_sources = not c.allowFrom or #c.allowFrom == 0
    if unrestricted_sources then
        ngx.log(ngx.WARN, "ro-controller: allowFrom is empty, so any source "
            .. "that can reach this listener may present a token; every "
            .. "endpoint except healthz, readyz and metrics still requires one")
    end
    if c.allowFrom and #c.allowFrom > 0 then
        allow_set = cidr.new()
        allow_set:add_all(c.allowFrom)
    end
    return true
end

local function source_allowed()
    if not allow_set then
        return unrestricted_sources
    end
    local addr = ngx.var.remote_addr
    local v4 = ipaddr.parse_ipv4(addr)
    if v4 then
        return allow_set:match_v4(v4) ~= nil
    end
    local g = ipaddr.parse_ipv6(addr)
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

local function principal()
    local header = ngx.var.http_authorization
    if not header then
        return nil
    end
    local scheme, value = header:match("^(%a+)%s+(.+)$")
    if not scheme or lower(scheme) ~= "bearer" then
        return nil
    end
    local digest = util.sha256_hex(util.trim(value))
    if not digest then
        return nil
    end
    return principals[digest]
end

local function require_role(minimum)
    if not source_allowed() then
        log.warn("controller request from a disallowed source",
            { client = ngx.var.remote_addr, uri = ngx.var.uri })
        return nil, fail(403, "forbidden", "source address not permitted")
    end
    local who = principal()
    if not who then
        return nil, fail(401, "unauthorized", "a valid bearer token is required")
    end
    if (ROLE_RANK[who.role] or 0) < (ROLE_RANK[minimum] or 99) then
        log.warn("controller authorisation denied", {
            principal = who.name, role = who.role, required = minimum,
            uri = ngx.var.uri,
        })
        return nil, fail(403, "forbidden",
            "role " .. who.role .. " cannot perform this operation")
    end
    return who
end

local function body_document()
    ngx.req.read_body()
    local raw = ngx.req.get_body_data()
    if not raw or raw == "" then
        local path = ngx.req.get_body_file()
        if path then
            local fh = io.open(path, "r")
            if fh then
                raw = fh:read("*a")
                fh:close()
            end
        end
    end
    if not raw or raw == "" then
        return nil, "request body is empty"
    end
    if #raw > 4194304 then
        return nil, "request body is too large"
    end
    local ctype = lower(ngx.var.http_content_type or "")
    if find(ctype, "yaml", 1, true) or
        (not find(ctype, "json", 1, true) and yaml.looks_like_yaml(raw)) then
        local parsed, err = yaml.parse(raw)
        if not parsed then
            return nil, "invalid yaml: " .. tostring(err)
        end
        return parsed
    end
    local parsed, err = cjson.decode(raw)
    if not parsed then
        return nil, "invalid json: " .. tostring(err)
    end
    return parsed
end

local function audit(who, action, fields)
    local ev = fields or {}
    ev.event = "control"
    ev.action = action
    ev.actor = who and who.name or "anonymous"
    ev.role = who and who.role or "-"
    ev.client = ngx.var.remote_addr
    ev.severity = "high"
    log.audit(ev)
end

local routes = {}

local function route(method, pattern, min_role, handler)
    routes[#routes + 1] = {
        method = method, pattern = pattern, role = min_role, handler = handler,
    }
end

route("GET", "^/healthz$", nil, function()
    return say(200, { status = "ok", component = "ro-controller" })
end)

route("GET", "^/readyz$", nil, function()
    local version = store.current_version()
    if version == 0 then
        return say(503, { status = "not_ready",
            reason = "no bundle has been published yet" })
    end
    return say(200, { status = "ready", version = version })
end)

route("GET", "^/metrics$", nil, function()
    ngx.header["Content-Type"] = "text/plain; version=0.0.4"
    ngx.print(metrics.render())
    return ngx.exit(200)
end)

route("GET", "^/v1/bundle$", "gateway", function()
    local bundle, err = store.active_bundle()
    if not bundle then
        return fail(503, "no_bundle", tostring(err))
    end
    metrics.inc("roc_bundle_served_total", { version = tostring(bundle.version) })
    local body = cjson.encode(bundle)
    ngx.status = 200
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["X-Content-Type-Options"] = "nosniff"
    if bundle_signing_key then
        local sig = util.hmac_sha256_hex(bundle_signing_key, body)
        if sig then
            ngx.header["X-RO-Bundle-Signature"] = "sha256=" .. sig
        end
    end
    ngx.print(body)
    return ngx.exit(200)
end)

route("GET", "^/v1/status$", "reader", function()
    local data, err = store.load()
    if not data then
        return fail(500, "store_error", tostring(err))
    end
    return say(200, {
        component = "ro-controller",
        activeVersion = store.current_version(),
        revision = data.meta and data.meta.revision or 0,
        policyCount = util.count(data.policies),
        profileCount = util.count(data.profiles),
        tokenCount = util.count(data.identities.tokens or {}),
        sourceCount = #(data.identities.sources or {}),
        emergencyDeny = data.settings.emergencyDeny == true,
        updatedAt = data.meta and data.meta.updatedAt or 0,
    })
end)

route("GET", "^/v1/policies$", "reader", function()
    local data = store.load()
    local out = {}
    for _, name in ipairs(util.sorted_keys(data.policies)) do
        local doc = data.policies[name]
        local normalized = store.normalize_policy(doc, name)
        out[#out + 1] = {
            name = name,
            tier = normalized and normalized.tier or "?",
            priority = normalized and normalized.priority or 0,
            rules = normalized and #(normalized.rules or {}) or 0,
        }
    end
    return say(200, { policies = out })
end)

route("GET", "^/v1/policies/([^/]+)$", "reader", function(_, name)
    local data = store.load()
    local doc = data.policies[name]
    if not doc then
        return fail(404, "not_found", "no such policy")
    end
    return say(200, doc)
end)

route("PUT", "^/v1/policies/([^/]+)$", "operator", function(who, name)
    if not store.valid_name(name) then
        return fail(400, "invalid_name", "policy names must be lowercase and short")
    end
    local doc, err = body_document()
    if not doc then
        return fail(400, "invalid_body", err)
    end
    local normalized, nerr = store.normalize_policy(doc, name)
    if not normalized then
        return fail(422, "invalid_policy", nerr)
    end
    local probe = { version = 1, policies = { normalized } }
    local compiled, cerr = policy.compile(probe)
    if not compiled then
        return fail(422, "invalid_policy", cerr)
    end
    local revision, merr = store.mutate(function(data)
        data.policies[name] = doc
        return true
    end)
    if not revision then
        return fail(500, "store_error", merr)
    end
    audit(who, "put_policy", { policy = name, revision = revision })
    return say(200, { name = name, revision = revision, staged = true })
end)

route("DELETE", "^/v1/policies/([^/]+)$", "operator", function(who, name)
    local found = false
    local revision, err = store.mutate(function(data)
        if not data.policies[name] then
            return nil, "absent"
        end
        found = true
        data.policies[name] = nil
        return true
    end)
    if not found then
        return fail(404, "not_found", "no such policy")
    end
    if not revision then
        return fail(500, "store_error", err)
    end
    audit(who, "delete_policy", { policy = name, revision = revision })
    return say(200, { name = name, revision = revision, deleted = true })
end)

route("GET", "^/v1/profiles$", "reader", function()
    local data = store.load()
    local out = {}
    for _, name in ipairs(util.sorted_keys(data.profiles)) do
        out[#out + 1] = { name = name }
    end
    return say(200, { profiles = out })
end)

route("GET", "^/v1/profiles/([^/]+)$", "reader", function(_, name)
    local data = store.load()
    local doc = data.profiles[name]
    if not doc then
        return fail(404, "not_found", "no such profile")
    end
    return say(200, doc)
end)

route("PUT", "^/v1/profiles/([^/]+)$", "operator", function(who, name)
    if not store.valid_name(name) then
        return fail(400, "invalid_name", "profile names must be lowercase and short")
    end
    local doc, err = body_document()
    if not doc then
        return fail(400, "invalid_body", err)
    end
    local normalized, nerr = store.normalize_profile(doc, name)
    if not normalized then
        return fail(422, "invalid_profile", nerr)
    end
    local compiled, cerr = policy.compile({ version = 1, policies = { normalized } })
    if not compiled then
        return fail(422, "invalid_profile", cerr)
    end
    local revision, merr = store.mutate(function(data)
        data.profiles[name] = doc
        return true
    end)
    if not revision then
        return fail(500, "store_error", merr)
    end
    audit(who, "put_profile", { profile = name, revision = revision })
    return say(200, { name = name, revision = revision, staged = true })
end)

route("DELETE", "^/v1/profiles/([^/]+)$", "operator", function(who, name)
    local found = false
    local revision, err = store.mutate(function(data)
        if not data.profiles[name] then
            return nil, "absent"
        end
        found = true
        data.profiles[name] = nil
        return true
    end)
    if not found then
        return fail(404, "not_found", "no such profile")
    end
    if not revision then
        return fail(500, "store_error", err)
    end
    audit(who, "delete_profile", { profile = name, revision = revision })
    return say(200, { name = name, revision = revision, deleted = true })
end)

route("GET", "^/v1/identities$", "reader", function()
    local data = store.load()
    local tokens = {}
    for digest, spec in pairs(data.identities.tokens or {}) do
        tokens[#tokens + 1] = {
            digest = sub(digest, 1, 16),
            fullDigest = digest,
            id = spec.id,
            namespace = spec.namespace,
            profile = spec.profile,
            serviceAccount = spec.serviceAccount,
        }
    end
    table.sort(tokens, function(a, b) return tostring(a.id) < tostring(b.id) end)
    return say(200, {
        tokens = tokens,
        sources = data.identities.sources or {},
        trustedHeaderSources = data.identities.trustedHeaderSources or {},
        allowAnonymous = data.identities.allowAnonymous == true,
    })
end)

local function random_token()
    local raw, err = util.random_bytes(32)
    if not raw then
        return nil, err
    end
    return "ro_" .. util.to_hex(raw)
end

route("POST", "^/v1/identities/tokens$", "operator", function(who)
    local doc, err = body_document()
    if not doc then
        return fail(400, "invalid_body", err)
    end
    if type(doc.profile) ~= "string" or type(doc.namespace) ~= "string" then
        return fail(422, "invalid_identity",
            "namespace and profile are required")
    end
    local token, terr = random_token()
    if not token then
        return fail(500, "no_entropy", "refusing to mint a token without a "
            .. "strong random source: " .. tostring(terr))
    end
    local digest = util.sha256_hex(token)
    local spec = {
        id = doc.id or ("sandbox-" .. sub(digest, 1, 8)),
        namespace = doc.namespace,
        profile = doc.profile,
        serviceAccount = doc.serviceAccount or "-",
        pod = doc.pod,
        labels = doc.labels,
    }
    local revision, merr = store.mutate(function(data)
        data.identities.tokens = data.identities.tokens or {}
        data.identities.tokens[digest] = spec
        return true
    end)
    if not revision then
        return fail(500, "store_error", merr)
    end
    audit(who, "issue_token", { identity = spec.id, profile = spec.profile,
        digest = sub(digest, 1, 16) })
    return say(201, {
        token = token,
        digest = digest,
        identity = spec,
        revision = revision,
        warning = "this token is shown once and cannot be recovered",
    })
end)

route("DELETE", "^/v1/identities/tokens/([%x]+)$", "operator", function(who, digest)
    digest = lower(digest)
    if #digest < TOKEN_DIGEST_MIN then
        return fail(422, "invalid_digest", format("a token digest prefix must "
            .. "be at least %d hex characters; %d given", TOKEN_DIGEST_MIN,
            #digest))
    end
    if #digest > TOKEN_DIGEST_LEN then
        return fail(422, "invalid_digest", format("a token digest is at most "
            .. "%d hex characters; %d given", TOKEN_DIGEST_LEN, #digest))
    end
    local target, ambiguous
    local revision, err = store.mutate(function(data)
        local tokens = data.identities.tokens or {}
        target, ambiguous = nil, nil
        for full in pairs(tokens) do
            if full == digest then
                target, ambiguous = full, nil
                break
            end
            if sub(full, 1, #digest) == digest then
                if target then
                    ambiguous = true
                else
                    target = full
                end
            end
        end
        if ambiguous then
            return nil, "ambiguous"
        end
        if not target then
            return nil, "absent"
        end
        tokens[target] = nil
        return true
    end)
    if ambiguous then
        return fail(409, "ambiguous_digest", format("the prefix %q matches more "
            .. "than one token; supply the full %d-character digest",
            digest, TOKEN_DIGEST_LEN))
    end
    if not target then
        return fail(404, "not_found", "no such token")
    end
    if not revision then
        return fail(500, "store_error", err)
    end
    audit(who, "revoke_token", { digest = target, revision = revision })
    return say(200, { revoked = target, revision = revision })
end)

route("PUT", "^/v1/identities/sources$", "operator", function(who)
    local doc, err = body_document()
    if not doc then
        return fail(400, "invalid_body", err)
    end
    local list = doc.sources or doc
    if type(list) ~= "table" or not util.is_array(list) then
        return fail(422, "invalid_sources", "expected an array of source entries")
    end
    for i, entry in ipairs(list) do
        if type(entry) ~= "table" or type(entry.cidr) ~= "string" then
            return fail(422, "invalid_sources",
                "entry " .. i .. " requires a cidr")
        end
        local kind = ipaddr.parse_cidr(entry.cidr)
        if not kind then
            return fail(422, "invalid_sources",
                "entry " .. i .. " has an invalid cidr")
        end
    end
    local revision, merr = store.mutate(function(data)
        data.identities.sources = list
        return true
    end)
    if not revision then
        return fail(500, "store_error", merr)
    end
    audit(who, "put_sources", { count = #list, revision = revision })
    return say(200, { sources = #list, revision = revision })
end)

route("GET", "^/v1/settings$", "reader", function()
    local data = store.load()
    return say(200, data.settings)
end)

route("PUT", "^/v1/settings$", "admin", function(who)
    local doc, err = body_document()
    if not doc then
        return fail(400, "invalid_body", err)
    end
    local revision, merr = store.mutate(function(data)
        for k, v in pairs(doc) do
            data.settings[k] = v
        end
        return true
    end)
    if not revision then
        return fail(500, "store_error", merr)
    end
    audit(who, "put_settings", { revision = revision })
    return say(200, { revision = revision })
end)

route("POST", "^/v1/publish$", "operator", function(who)
    local doc = body_document() or {}
    local result, err = store.publish(who.name, doc.note)
    if not result then
        metrics.inc("roc_publish_total", { result = "rejected" })
        return fail(422, "publish_failed", tostring(err))
    end
    metrics.inc("roc_publish_total", { result = "ok" })
    metrics.set("roc_active_version", nil, result.version)
    audit(who, "publish", { version = result.version, note = doc.note })
    return say(200, result)
end)

route("GET", "^/v1/versions$", "reader", function()
    return say(200, {
        active = store.current_version(),
        versions = store.list_versions(),
    })
end)

route("GET", "^/v1/versions/(%d+)$", "reader", function(_, n)
    local bundle = store.get_version(tonumber(n))
    if not bundle then
        return fail(404, "not_found", "no such version")
    end
    return say(200, bundle)
end)

route("POST", "^/v1/rollback$", "operator", function(who)
    local doc, err = body_document()
    if not doc then
        return fail(400, "invalid_body", err)
    end
    local version = tonumber(doc.version)
    if not version then
        return fail(422, "invalid_version", "version must be a number")
    end
    local result, rerr = store.rollback(version, who.name)
    if not result then
        return fail(422, "rollback_failed", tostring(rerr))
    end
    metrics.set("roc_active_version", nil, result.version)
    audit(who, "rollback", { version = version })
    return say(200, result)
end)

route("POST", "^/v1/emergency%-deny$", "operator", function(who)
    local doc = body_document() or {}
    local enabled = doc.enabled ~= false
    local revision, err = store.mutate(function(data)
        data.settings.emergencyDeny = enabled
        return true
    end)
    if not revision then
        return fail(500, "store_error", err)
    end
    local result, perr = store.publish(who.name,
        enabled and "emergency deny engaged" or "emergency deny lifted")
    if not result then
        return fail(500, "publish_failed", tostring(perr))
    end
    audit(who, "emergency_deny", { enabled = enabled, version = result.version })
    return say(200, { emergencyDeny = enabled, version = result.version })
end)

route("POST", "^/v1/validate$", "reader", function()
    local doc, err = body_document()
    if not doc then
        return fail(400, "invalid_body", err)
    end
    local candidate = doc
    if doc.kind == "EgressPolicy" or (doc.spec and doc.spec.rules) then
        local normalized, nerr = store.normalize_policy(doc, doc.name or "candidate")
        if not normalized then
            return say(200, { valid = false, error = nerr })
        end
        candidate = { version = 1, policies = { normalized } }
    elseif doc.kind == "SandboxProfile" then
        local normalized, nerr = store.normalize_profile(doc, doc.name or "candidate")
        if not normalized then
            return say(200, { valid = false, error = nerr })
        end
        candidate = { version = 1, policies = { normalized } }
    elseif not doc.version then
        candidate = { version = 1, policies = doc.policies or {} }
    end
    local compiled, cerr = policy.compile(candidate)
    if not compiled then
        return say(200, { valid = false, error = cerr })
    end
    return say(200, { valid = true, summary = compiled:summary() })
end)

route("POST", "^/v1/preview$", "reader", function()
    local data, err = store.load()
    if not data then
        return fail(500, "store_error", tostring(err))
    end
    local bundle, berr = store.compile_bundle(data, store.current_version() + 1)
    if not bundle then
        return say(200, { valid = false, error = berr })
    end
    local compiled, cerr = policy.compile(bundle)
    if not compiled then
        return say(200, { valid = false, error = cerr })
    end
    return say(200, { valid = true, summary = compiled:summary(), bundle = bundle })
end)

route("POST", "^/v1/simulate$", "reader", function()
    local doc, err = body_document()
    if not doc then
        return fail(400, "invalid_body", err)
    end
    local bundle, berr = store.active_bundle()
    if not bundle then
        return fail(503, "no_bundle", tostring(berr))
    end
    local compiled, cerr = policy.compile(bundle)
    if not compiled then
        return fail(500, "invalid_bundle", cerr)
    end
    local target = require("ro.target")
    local info, ierr = target.classify_host(doc.host or "")
    if not info then
        return fail(422, "invalid_host", tostring(ierr))
    end
    local identity = {
        id = doc.identity or "simulated",
        namespace = doc.namespace or "-",
        profile = doc.profile or "-",
        serviceAccount = doc.serviceAccount or "-",
        labels = doc.labels,
    }
    identity.key = table.concat({ identity.namespace, identity.profile,
        identity.serviceAccount, identity.id }, "/")
    local decision = compiled:evaluate(identity, {
        host_info = info,
        port = tonumber(doc.port) or 443,
        protocol = doc.protocol or "https",
        method = doc.method,
        path = doc.path,
    })
    return say(200, {
        decision = decision.action,
        reason = decision.reason,
        rule = decision.rule,
        policy = decision.policy,
        matched = decision.matched,
        limits = {
            requestsPerSecond = decision.rate_limit and decision.rate_limit.rps,
            maxConnections = decision.max_connections,
            bandwidthBytesPerSecond = decision.bandwidth,
        },
        identity = identity,
        destination = { host = info.canonical, kind = info.kind,
            port = tonumber(doc.port) or 443 },
        bundleVersion = bundle.version,
    })
end)

local KNOWN_METHODS = {
    GET = true, HEAD = true, POST = true, PUT = true, DELETE = true,
    PATCH = true, OPTIONS = true,
}

function _M.handle()
    local method = ngx.req.get_method()
    local uri = ngx.var.uri
    metrics.inc("roc_requests_total", {
        method = KNOWN_METHODS[method] and method or "other",
    })

    for _, r in ipairs(routes) do
        if r.method == method then
            local captures = { uri:match(r.pattern) }
            if captures[1] ~= nil or uri:match(r.pattern) then
                local who
                if r.role then
                    local ok = require_role(r.role)
                    if not ok then
                        return
                    end
                    who = ok
                end
                return r.handler(who, unpack and unpack(captures)
                    or table.unpack(captures))
            end
        end
    end

    for _, r in ipairs(routes) do
        if uri:match(r.pattern) then
            return fail(405, "method_not_allowed",
                "this endpoint does not support " .. method)
        end
    end
    return fail(404, "not_found", "no such endpoint")
end

return _M
