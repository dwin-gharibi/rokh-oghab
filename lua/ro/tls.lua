local _M = { _VERSION = "1.0.0" }

local byte = string.byte
local sub = string.sub
local lower = string.lower

local HANDSHAKE = 0x16
local CLIENT_HELLO = 0x01
local EXT_SNI = 0x0000
local EXT_ALPN = 0x0010
local EXT_SUPPORTED_VERSIONS = 0x002b

local VERSION_NAMES = {
    [0x0300] = "ssl3.0",
    [0x0301] = "1.0",
    [0x0302] = "1.1",
    [0x0303] = "1.2",
    [0x0304] = "1.3",
}

_M.VERSION_NAMES = VERSION_NAMES

local VERSION_RANK = {
    ["ssl3.0"] = 0,
    ["1.0"] = 1,
    ["1.1"] = 2,
    ["1.2"] = 3,
    ["1.3"] = 4,
}

_M.VERSION_RANK = VERSION_RANK

local function u8(s, i)
    if i > #s then return nil end
    return byte(s, i)
end

local function u16(s, i)
    if i + 1 > #s then return nil end
    return byte(s, i) * 256 + byte(s, i + 1)
end

local function u24(s, i)
    if i + 2 > #s then return nil end
    return byte(s, i) * 65536 + byte(s, i + 1) * 256 + byte(s, i + 2)
end

function _M.record_header(data)
    if type(data) ~= "string" or #data < 5 then
        return nil, "need more data"
    end
    local ctype = byte(data, 1)
    local version = u16(data, 2)
    local length = u16(data, 4)
    return { content_type = ctype, version = version, length = length }
end

function _M.looks_like_client_hello(data)
    if type(data) ~= "string" or #data < 1 then
        return false, true
    end
    if byte(data, 1) ~= HANDSHAKE then
        return false, false
    end
    if #data < 4 then
        return false, true
    end
    local ver = u16(data, 2)
    if ver < 0x0300 or ver > 0x0304 then
        return false, false
    end
    if #data < 6 then
        return false, true
    end
    if byte(data, 6) ~= CLIENT_HELLO then
        return false, false
    end
    return true, false
end

local function parse_extensions(body, pos, out)
    local total = u16(body, pos)
    if not total then
        return out
    end
    pos = pos + 2
    local stop = pos + total - 1
    if stop > #body then
        stop = #body
    end
    local seen = {}
    while pos + 3 <= stop do
        local etype = u16(body, pos)
        local elen = u16(body, pos + 2)
        if not etype or not elen then break end
        local edata = sub(body, pos + 4, pos + 3 + elen)
        if #edata < elen then break end

        if seen[etype] then
            out.duplicate_extension = true
            return out
        end
        seen[etype] = true

        if etype == EXT_SNI then
            local list_len = u16(edata, 1)
            if list_len then
                local p = 3
                local sni_stop = 2 + list_len
                if sni_stop > #edata then
                    sni_stop = #edata
                end
                while p + 2 <= sni_stop do
                    local ntype = u8(edata, p)
                    local nlen = u16(edata, p + 1)
                    if not nlen then break end
                    local name = sub(edata, p + 3, p + 2 + nlen)
                    if p + 2 + nlen > sni_stop then break end
                    if ntype == 0 and #name == nlen and nlen > 0 then
                        out.sni = lower(name)
                        break
                    end
                    p = p + 3 + nlen
                end
            end
        elseif etype == EXT_ALPN then
            local list_len = u16(edata, 1)
            if list_len then
                local p = 3
                out.alpn = {}
                while p <= #edata do
                    local plen = u8(edata, p)
                    if not plen or plen == 0 then break end
                    local proto = sub(edata, p + 1, p + plen)
                    if #proto == plen then
                        out.alpn[#out.alpn + 1] = proto
                    end
                    p = p + 1 + plen
                end
            end
        elseif etype == EXT_SUPPORTED_VERSIONS then
            local list_len = u8(edata, 1)
            if list_len then
                local p = 2
                out.supported_versions = {}
                while p + 1 <= 1 + list_len and p + 1 <= #edata do
                    local v = u16(edata, p)
                    if v then
                        out.supported_versions[#out.supported_versions + 1] = v
                    end
                    p = p + 2
                end
            end
        end

        pos = pos + 4 + elen
    end
    return out
end

function _M.parse_client_hello(data)
    if type(data) ~= "string" then
        return nil, "no data"
    end
    if #data < 9 then
        return nil, "need more data"
    end
    if byte(data, 1) ~= HANDSHAKE then
        return nil, "not a TLS handshake record"
    end

    local body = {}
    local pos = 1
    local total = 0
    while pos + 4 <= #data do
        local ctype = byte(data, pos)
        if ctype ~= HANDSHAKE then
            break
        end
        local rlen = u16(data, pos + 3)
        if not rlen then break end
        local payload = sub(data, pos + 5, pos + 4 + rlen)
        body[#body + 1] = payload
        total = total + #payload
        if #payload < rlen then
            break
        end
        pos = pos + 5 + rlen
    end

    local hs = table.concat(body)
    if #hs < 4 then
        return nil, "need more data"
    end
    if byte(hs, 1) ~= CLIENT_HELLO then
        return nil, "not a ClientHello"
    end
    local hlen = u24(hs, 2)
    if not hlen then
        return nil, "truncated handshake"
    end

    local p = 5
    local legacy_version = u16(hs, p)
    if not legacy_version then
        return nil, "truncated ClientHello"
    end
    p = p + 2 + 32

    local sid_len = u8(hs, p)
    if not sid_len then
        return nil, "truncated session id"
    end
    p = p + 1 + sid_len

    local cs_len = u16(hs, p)
    if not cs_len then
        return nil, "truncated cipher suites"
    end
    p = p + 2 + cs_len

    local comp_len = u8(hs, p)
    if not comp_len then
        return nil, "truncated compression methods"
    end
    p = p + 1 + comp_len

    local out = { legacy_version = legacy_version }
    if p <= #hs then
        parse_extensions(hs, p, out)
    end

    if out.duplicate_extension then
        return nil, "duplicate ClientHello extension"
    end

    local best, lowest = legacy_version, legacy_version
    if out.supported_versions then
        local sv_low, sv_seen = nil, false
        for _, v in ipairs(out.supported_versions) do
            if VERSION_NAMES[v] then
                sv_seen = true
                if v > best then best = v end
                if not sv_low or v < sv_low then sv_low = v end
            end
        end
        if sv_seen then
            if legacy_version == 0x0303 then
                lowest = sv_low
            elseif sv_low < lowest then
                lowest = sv_low
            end
        end
    end
    out.version = best
    out.version_name = VERSION_NAMES[best] or "unknown"
    out.min_version = lowest
    out.min_version_name = VERSION_NAMES[lowest] or "unknown"
    out.truncated = (#hs < hlen + 4)
    return out
end

function _M.version_at_least(name, minimum)
    local a = VERSION_RANK[name]
    local b = VERSION_RANK[minimum]
    if not a or not b then
        return false
    end
    return a >= b
end

return _M
