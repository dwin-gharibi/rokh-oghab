local ipaddr = require("ro.ipaddr")

local _M = { _VERSION = "1.0.0" }

local find = string.find
local sub = string.sub
local byte = string.byte
local lower = string.lower
local tonumber = tonumber

local MAX_HOST_LEN = 253
local MAX_LABEL_LEN = 63

local function is_ldh_label(label)
    local n = #label
    if n == 0 or n > MAX_LABEL_LEN then
        return false
    end
    if byte(label, 1) == 45 or byte(label, n) == 45 then
        return false
    end
    if find(label, "^[a-z0-9_-]+$") == nil then
        return false
    end
    return true
end

function _M.normalize_hostname(host)
    if type(host) ~= "string" then
        return nil, "hostname not a string"
    end
    local n = #host
    if n == 0 or n > MAX_HOST_LEN + 1 then
        return nil, "hostname length out of range"
    end
    if find(host, "[^%w%._-]") then
        return nil, "hostname contains illegal characters"
    end
    local h = lower(host)
    if byte(h, #h) == 46 then
        h = sub(h, 1, #h - 1)
    end
    if #h == 0 or #h > MAX_HOST_LEN then
        return nil, "hostname length out of range"
    end
    if find(h, "%.%.") then
        return nil, "hostname has empty label"
    end
    local start = 1
    local last_label
    while true do
        local i = find(h, ".", start, true)
        local label
        if i then label = sub(h, start, i - 1) else label = sub(h, start) end
        if not is_ldh_label(label) then
            return nil, "invalid hostname label"
        end
        last_label = label
        if not i then break end
        start = i + 1
    end
    if find(last_label, "^%d+$") then
        return nil, "hostname top label must not be all-numeric"
    end
    return h
end

function _M.classify_host(host)
    if type(host) ~= "string" or host == "" then
        return nil, "empty host"
    end
    if #host > MAX_HOST_LEN + 2 then
        return nil, "host too long"
    end
    if find(host, "[%z\1-\32\127]") then
        return nil, "host contains control characters"
    end

    if byte(host, 1) == 91 then
        local inner = host:match("^%[(.+)%]$")
        if not inner then
            return nil, "malformed bracketed host"
        end
        local g = ipaddr.parse_ipv6(inner)
        if not g then
            return nil, "malformed ipv6 literal"
        end
        return {
            kind = "ipv6",
            canonical = ipaddr.ipv6_to_string(g),
            v6 = g,
            literal = true,
            obfuscated = false,
        }
    end

    local v4 = ipaddr.parse_ipv4(host)
    if v4 then
        return {
            kind = "ipv4",
            canonical = ipaddr.ipv4_to_string(v4),
            v4 = v4,
            literal = true,
            obfuscated = false,
        }
    end

    if find(host, ":", 1, true) then
        local g = ipaddr.parse_ipv6(host)
        if g then
            return {
                kind = "ipv6",
                canonical = ipaddr.ipv6_to_string(g),
                v6 = g,
                literal = true,
                obfuscated = true,
            }
        end
        return nil, "host contains colon"
    end

    local loose = ipaddr.parse_ipv4_any(host)
    if loose then
        return {
            kind = "ipv4",
            canonical = ipaddr.ipv4_to_string(loose),
            v4 = loose,
            literal = true,
            obfuscated = true,
        }
    end

    local h, err = _M.normalize_hostname(host)
    if not h then
        return nil, err
    end
    return {
        kind = "hostname",
        canonical = h,
        literal = false,
        obfuscated = false,
    }
end

function _M.parse_port(s)
    if type(s) ~= "string" or s == "" or #s > 5 then
        return nil, "invalid port"
    end
    if find(s, "^%d+$") == nil then
        return nil, "invalid port"
    end
    if #s > 1 and byte(s, 1) == 48 then
        return nil, "invalid port"
    end
    local p = tonumber(s, 10)
    if not p or p < 1 or p > 65535 then
        return nil, "invalid port"
    end
    return p
end

function _M.parse_authority(authority, default_port)
    if type(authority) ~= "string" or authority == "" then
        return nil, nil, "empty authority"
    end
    if #authority > 300 then
        return nil, nil, "authority too long"
    end
    if find(authority, "[%z\1-\32\127]") then
        return nil, nil, "authority contains control characters"
    end
    if find(authority, "@", 1, true) then
        return nil, nil, "authority contains userinfo"
    end
    if find(authority, "[/\\?#]") then
        return nil, nil, "authority contains path characters"
    end

    local host_part, port_part
    if byte(authority, 1) == 91 then
        local close = find(authority, "]", 1, true)
        if not close then
            return nil, nil, "unterminated ipv6 literal"
        end
        host_part = sub(authority, 1, close)
        local rest = sub(authority, close + 1)
        if rest ~= "" then
            if byte(rest, 1) ~= 58 then
                return nil, nil, "malformed authority"
            end
            port_part = sub(rest, 2)
        end
    else
        local colon = find(authority, ":", 1, true)
        if colon then
            if find(authority, ":", colon + 1, true) then
                return nil, nil, "malformed authority"
            end
            host_part = sub(authority, 1, colon - 1)
            port_part = sub(authority, colon + 1)
        else
            host_part = authority
        end
    end

    local port
    if port_part ~= nil then
        local p, perr = _M.parse_port(port_part)
        if not p then
            return nil, nil, perr
        end
        port = p
    else
        port = default_port
    end
    if not port then
        return nil, nil, "missing port"
    end

    local info, herr = _M.classify_host(host_part)
    if not info then
        return nil, nil, herr
    end
    return info, port
end

return _M
