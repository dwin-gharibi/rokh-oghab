local ipaddr = require("ro.ipaddr")

local _M = { _VERSION = "1.0.0" }
local mt = { __index = _M }

local sort = table.sort

function _M.new()
    return setmetatable({
        v4 = {}, v4_lens = {}, v4_count = 0,
        v6 = {}, v6_lens = {}, v6_count = 0,
        labels = {},
    }, mt)
end

function _M:add(spec, label)
    local kind, net, prefix = ipaddr.parse_cidr(spec)
    if not kind then
        return nil, "invalid cidr: " .. tostring(spec)
    end
    if kind == "ipv4" then
        local bucket = self.v4[prefix]
        if not bucket then
            bucket = {}
            self.v4[prefix] = bucket
            self.v4_lens[#self.v4_lens + 1] = prefix
            sort(self.v4_lens, function(a, b) return a > b end)
        end
        if bucket[net] == nil then
            self.v4_count = self.v4_count + 1
        end
        bucket[net] = label or spec
    else
        local key = ipaddr.ipv6_key(net)
        local bucket = self.v6[prefix]
        if not bucket then
            bucket = {}
            self.v6[prefix] = bucket
            self.v6_lens[#self.v6_lens + 1] = prefix
            sort(self.v6_lens, function(a, b) return a > b end)
        end
        if bucket[key] == nil then
            self.v6_count = self.v6_count + 1
        end
        bucket[key] = label or spec
    end
    return true
end

function _M:add_all(list, label)
    if type(list) ~= "table" then
        return nil, "cidr list must be a table"
    end
    for i = 1, #list do
        local ok, err = self:add(list[i], label)
        if not ok then
            return nil, err
        end
    end
    return true
end

function _M:match_v4(addr)
    local lens = self.v4_lens
    for i = 1, #lens do
        local prefix = lens[i]
        local bucket = self.v4[prefix]
        local hit = bucket[ipaddr.mask_ipv4(addr, prefix)]
        if hit ~= nil then
            return hit
        end
    end
    return nil
end

function _M:match_v6(groups)
    local lens = self.v6_lens
    for i = 1, #lens do
        local prefix = lens[i]
        local bucket = self.v6[prefix]
        local hit = bucket[ipaddr.ipv6_key(ipaddr.mask_ipv6(groups, prefix))]
        if hit ~= nil then
            return hit
        end
    end
    return nil
end

function _M:is_empty()
    return self.v4_count == 0 and self.v6_count == 0
end

function _M:size()
    return self.v4_count + self.v6_count
end

return _M
