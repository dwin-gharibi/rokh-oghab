local cidr = require("ro.cidr")
local ipaddr = require("ro.ipaddr")
local util = require("ro.util")

local _M = { _VERSION = "1.0.0" }
local mt = { __index = _M }

local sub = string.sub
local find = string.find
local lower = string.lower

local ANON = {
    id = "anonymous",
    namespace = "-",
    profile = "-",
    serviceAccount = "-",
    source = "anonymous",
    anonymous = true,
}

_M.ANONYMOUS = ANON

local function sanitize_field(v, max)
    if type(v) ~= "string" then
        return nil
    end
    if #v == 0 or #v > (max or 253) then
        return nil
    end
    if find(v, "[^%w%.%-_:@/]") then
        return nil
    end
    return v
end

local function build_identity(spec, source)
    local id = {
        id = sanitize_field(spec.id) or sanitize_field(spec.name) or "unnamed",
        namespace = sanitize_field(spec.namespace) or "-",
        profile = sanitize_field(spec.profile) or "-",
        serviceAccount = sanitize_field(spec.serviceAccount) or "-",
        pod = sanitize_field(spec.pod),
        source = source,
        labels = type(spec.labels) == "table" and spec.labels or nil,
    }
    id.key = table.concat({ id.namespace, id.profile, id.serviceAccount, id.id }, "/")
    return id
end

_M.build = build_identity

function _M.new(config, opts)
    config = config or {}
    opts = opts or {}
    local self = setmetatable({
        tokens = {},
        token_count = 0,
        sources = {},
        source_set = cidr.new(),
        trusted_headers = cidr.new(),
        has_trusted_headers = false,
        allow_anonymous = opts.allow_anonymous == true,
        require_identity = opts.require_identity ~= false,
    }, mt)

    if config.tokens then
        if type(config.tokens) ~= "table" then
            return nil, "identities.tokens must be an object"
        end
        for digest, spec in pairs(config.tokens) do
            if type(digest) ~= "string" or not find(digest, "^%x+$")
                or (#digest ~= 64 and #digest ~= 32) then
                return nil, "identities.tokens keys must be hex digests"
            end
            if type(spec) ~= "table" then
                return nil, "identities.tokens values must be objects"
            end
            self.tokens[lower(digest)] = build_identity(spec, "token")
            self.token_count = self.token_count + 1
        end
    end

    if config.sources then
        if type(config.sources) ~= "table" or not util.is_array(config.sources) then
            return nil, "identities.sources must be an array"
        end
        for i, entry in ipairs(config.sources) do
            if type(entry) ~= "table" or type(entry.cidr) ~= "string" then
                return nil, "identities.sources[" .. i .. "] requires a cidr"
            end
            local ident = build_identity(entry, "source")
            self.sources[i] = ident
            local ok, err = self.source_set:add(entry.cidr, i)
            if not ok then
                return nil, "identities.sources[" .. i .. "]: " .. tostring(err)
            end
        end
    end

    if config.trustedHeaderSources then
        if type(config.trustedHeaderSources) ~= "table"
            or not util.is_array(config.trustedHeaderSources) then
            return nil, "identities.trustedHeaderSources must be an array"
        end
        local ok, err = self.trusted_headers:add_all(config.trustedHeaderSources)
        if not ok then
            return nil, tostring(err)
        end
        self.has_trusted_headers = self.trusted_headers:size() > 0
    end

    if config.allowAnonymous ~= nil then
        self.allow_anonymous = config.allowAnonymous == true
    end

    return self
end

function _M:from_token(token)
    if type(token) ~= "string" or #token < 16 or #token > 512 then
        return nil
    end
    local digest = util.sha256_hex(token)
    if not digest then
        return nil
    end
    return self.tokens[digest]
end

function _M.parse_proxy_authorization(value)
    if type(value) ~= "string" or #value > 8192 then
        return nil
    end
    local scheme, rest = value:match("^(%a+)%s+(.+)$")
    if not scheme then
        return nil
    end
    scheme = lower(scheme)
    if scheme == "bearer" then
        return util.trim(rest)
    end
    if scheme == "basic" then
        local decoded = util.b64_decode(util.trim(rest))
        if not decoded then
            return nil
        end
        local colon = find(decoded, ":", 1, true)
        if not colon then
            return nil
        end
        return sub(decoded, colon + 1)
    end
    return nil
end

function _M:from_source(addr)
    if type(addr) ~= "string" then
        return nil
    end
    local idx
    local v4 = ipaddr.parse_ipv4(addr)
    if v4 then
        idx = self.source_set:match_v4(v4)
    else
        local g = ipaddr.parse_ipv6(addr)
        if g then
            idx = self.source_set:match_v6(g)
            if not idx then
                local mapped = ipaddr.ipv4_mapped(g)
                if mapped then
                    idx = self.source_set:match_v4(mapped)
                end
            end
        end
    end
    if not idx then
        return nil
    end
    return self.sources[idx]
end

function _M:source_is_trusted(addr)
    if not self.has_trusted_headers or type(addr) ~= "string" then
        return false
    end
    local v4 = ipaddr.parse_ipv4(addr)
    if v4 then
        return self.trusted_headers:match_v4(v4) ~= nil
    end
    local g = ipaddr.parse_ipv6(addr)
    if g then
        if self.trusted_headers:match_v6(g) then
            return true
        end
        local mapped = ipaddr.ipv4_mapped(g)
        if mapped then
            return self.trusted_headers:match_v4(mapped) ~= nil
        end
    end
    return false
end

function _M:resolve(ctx)
    ctx = ctx or {}

    if ctx.proxy_authorization then
        local token = _M.parse_proxy_authorization(ctx.proxy_authorization)
        if token then
            local ident = self:from_token(token)
            if ident then
                return ident
            end
            return nil, "identity.invalid_token"
        end
        return nil, "identity.malformed_credentials"
    end

    if ctx.client_cert_cn then
        local cn = sanitize_field(ctx.client_cert_cn)
        if cn then
            local ident = self.tokens["cn:" .. cn]
            if ident then
                return ident
            end
        end
    end

    if ctx.remote_addr then
        local ident = self:from_source(ctx.remote_addr)
        if ident then
            if ctx.headers and self:source_is_trusted(ctx.remote_addr) then
                local override = {
                    id = ctx.headers["x-ro-identity"] or ident.id,
                    namespace = ctx.headers["x-ro-namespace"] or ident.namespace,
                    profile = ctx.headers["x-ro-profile"] or ident.profile,
                    serviceAccount = ctx.headers["x-ro-service-account"]
                        or ident.serviceAccount,
                    pod = ctx.headers["x-ro-pod"] or ident.pod,
                }
                return build_identity(override, "trusted-header")
            end
            return ident
        end
    end

    if self.allow_anonymous then
        local anon = util.shallow_copy(ANON)
        anon.key = "anonymous/" .. tostring(ctx.remote_addr or "-")
        return anon
    end

    return nil, "identity.unknown"
end

function _M:stats()
    return {
        tokens = self.token_count,
        sources = #self.sources,
        trustedHeaderSources = self.trusted_headers:size(),
        allowAnonymous = self.allow_anonymous,
    }
end

return _M
