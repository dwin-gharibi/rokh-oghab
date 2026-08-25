local ipaddr = require("ro.ipaddr")
local cidr = require("ro.cidr")

local _M = { _VERSION = "1.0.0" }
local mt = { __index = _M }

_M.DEFAULT_BLOCKED_V4 = {
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.31.196.0/24",
    "192.52.193.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "233.252.0.0/24",
    "240.0.0.0/4",
    "255.255.255.255/32",
}

_M.DEFAULT_BLOCKED_V6 = {
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "::ffff:0:0:0/96",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/32",
    "2001:20::/28",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
    "5f00::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
}

_M.KNOWN_METADATA_ENDPOINTS = {
    "169.254.169.254/32",
    "169.254.169.253/32",
    "169.254.169.123/32",
    "169.254.170.2/32",
    "169.254.170.23/32",
    "100.100.100.200/32",
    "192.0.0.192/32",
    "fd00:ec2::254/128",
}

function _M.new(opts)
    opts = opts or {}
    local self = setmetatable({
        blocked = cidr.new(),
        exceptions = cidr.new(),
        block_obfuscated = opts.block_obfuscated ~= false,
        allow_ipv6 = opts.allow_ipv6 ~= false,
    }, mt)

    if opts.include_defaults ~= false then
        local ok, err = self.blocked:add_all(_M.DEFAULT_BLOCKED_V4, "default-private-v4")
        if not ok then return nil, err end
        ok, err = self.blocked:add_all(_M.DEFAULT_BLOCKED_V6, "default-private-v6")
        if not ok then return nil, err end
        ok, err = self.blocked:add_all(_M.KNOWN_METADATA_ENDPOINTS, "cloud-metadata")
        if not ok then return nil, err end
    end

    if opts.blocked then
        local ok, err = self.blocked:add_all(opts.blocked, "configured-block")
        if not ok then return nil, err end
    end
    if opts.allow_exceptions then
        local ok, err = self.exceptions:add_all(opts.allow_exceptions, "configured-exception")
        if not ok then return nil, err end
    end
    return self
end

function _M:check_v4(addr)
    if self.exceptions:match_v4(addr) then
        return true, nil
    end
    local hit = self.blocked:match_v4(addr)
    if hit then
        return false, hit
    end
    return true, nil
end

function _M:check_v6(groups)
    if not self.allow_ipv6 then
        return false, "ipv6-disabled"
    end
    if self.exceptions:match_v6(groups) then
        return true, nil
    end
    local hit = self.blocked:match_v6(groups)
    if hit then
        return false, hit
    end
    local embedded, n = ipaddr.embedded_ipv4(groups)
    for i = 1, n do
        local ok, reason = self:check_v4(embedded[i])
        if not ok then
            return false, "embedded-v4:" .. reason
        end
    end
    return true, nil
end

function _M:check(info)
    if type(info) ~= "table" then
        return false, "invalid-target"
    end
    if info.obfuscated and self.block_obfuscated then
        return false, "obfuscated-address-literal"
    end
    if info.kind == "ipv4" then
        return self:check_v4(info.v4)
    end
    if info.kind == "ipv6" then
        return self:check_v6(info.v6)
    end
    return false, "not-an-address"
end

function _M:check_resolved(kind, value)
    if kind == "ipv4" then
        return self:check_v4(value)
    end
    if kind == "ipv6" then
        return self:check_v6(value)
    end
    return false, "unknown-address-family"
end

function _M:stats()
    return {
        blocked = self.blocked:size(),
        exceptions = self.exceptions:size(),
        block_obfuscated = self.block_obfuscated,
        allow_ipv6 = self.allow_ipv6,
    }
end

return _M
