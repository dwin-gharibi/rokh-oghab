local _M = { _VERSION = "1.0.0" }

local sub = string.sub
local find = string.find
local byte = string.byte
local format = string.format
local floor = math.floor
local tonumber = tonumber
local type = type

local MAX_U32 = 4294967295

local function part_value(p)
    if p == "" or #p > 12 then
        return nil
    end
    if find(p, "^0[xX]%x+$") then
        if #p > 10 then return nil end
        return tonumber(sub(p, 3), 16)
    end
    if find(p, "^0%d+$") then
        if #p > 12 or find(p, "[89]") then return nil end
        return tonumber(sub(p, 2), 8)
    end
    if find(p, "^%d+$") then
        if #p > 10 then return nil end
        return tonumber(p, 10)
    end
    return nil
end

local function split_dots(s, limit)
    local parts, n = {}, 0
    local start = 1
    while true do
        local i = find(s, ".", start, true)
        if not i then
            n = n + 1
            if n > limit then return nil, 0 end
            parts[n] = sub(s, start)
            break
        end
        n = n + 1
        if n > limit then return nil, 0 end
        parts[n] = sub(s, start, i - 1)
        start = i + 1
    end
    return parts, n
end

function _M.parse_ipv4(s)
    if type(s) ~= "string" or #s < 7 or #s > 15 then
        return nil
    end
    local o1, o2, o3, o4 = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not o1 then
        return nil
    end
    local octets = { o1, o2, o3, o4 }
    local addr = 0
    for i = 1, 4 do
        local p = octets[i]
        if #p > 3 then return nil end
        if #p > 1 and byte(p, 1) == 48 then return nil end
        local v = tonumber(p, 10)
        if v > 255 then return nil end
        addr = addr * 256 + v
    end
    return addr
end

function _M.parse_ipv4_any(s)
    if type(s) ~= "string" or s == "" or #s > 45 then
        return nil
    end
    if find(s, "[^0-9A-Fa-fxX%.]") then
        return nil
    end
    local parts, n = split_dots(s, 4)
    if not parts or n < 1 then
        return nil
    end
    local vals = {}
    for i = 1, n do
        local v = part_value(parts[i])
        if v == nil then return nil end
        vals[i] = v
    end
    for i = 1, n - 1 do
        if vals[i] > 255 then return nil end
    end
    if vals[n] > 256 ^ (5 - n) - 1 then
        return nil
    end
    local addr = vals[n]
    for i = 1, n - 1 do
        addr = addr + vals[i] * 256 ^ (4 - i)
    end
    if addr < 0 or addr > MAX_U32 or addr ~= floor(addr) then
        return nil
    end
    return addr
end

local function split_colons(str, out)
    local cnt = 0
    if str == nil or str == "" then
        return out, 0
    end
    local start = 1
    while true do
        local i = find(str, ":", start, true)
        local piece
        if i then piece = sub(str, start, i - 1) else piece = sub(str, start) end
        if piece == "" then return nil, 0 end
        cnt = cnt + 1
        if cnt > 8 then return nil, 0 end
        out[cnt] = piece
        if not i then break end
        start = i + 1
    end
    return out, cnt
end

local function pieces_to_groups(pieces, cnt, allow_v4, g, gc)
    for i = 1, cnt do
        local p = pieces[i]
        if find(p, ".", 1, true) then
            if not allow_v4 or i ~= cnt then return nil, 0 end
            local v4 = _M.parse_ipv4(p)
            if not v4 then return nil, 0 end
            gc = gc + 1
            if gc > 8 then return nil, 0 end
            g[gc] = floor(v4 / 65536)
            gc = gc + 1
            if gc > 8 then return nil, 0 end
            g[gc] = v4 % 65536
        else
            if #p > 4 then return nil, 0 end
            local v = tonumber(p, 16)
            if v == nil or v < 0 or v > 65535 then return nil, 0 end
            gc = gc + 1
            if gc > 8 then return nil, 0 end
            g[gc] = v
        end
    end
    return g, gc
end

function _M.parse_ipv6(s)
    if type(s) ~= "string" then
        return nil
    end
    local n = #s
    if n < 2 or n > 45 then
        return nil
    end
    if find(s, "[^0-9A-Fa-f:%.]") then
        return nil
    end
    if not find(s, ":", 1, true) then
        return nil
    end
    local dbl_start, dbl_end = find(s, "::", 1, true)
    if dbl_start and find(s, "::", dbl_end + 1, true) then
        return nil
    end
    if not dbl_start and (byte(s, 1) == 58 or byte(s, n) == 58) then
        return nil
    end

    local head, tail
    if dbl_start then
        head = sub(s, 1, dbl_start - 1)
        tail = sub(s, dbl_end + 1)
    else
        head = s
        tail = nil
    end

    local hp, hc = split_colons(head, {})
    if not hp then return nil end
    local tp, tc = split_colons(tail, {})
    if not tp then return nil end

    local hg, hgc = pieces_to_groups(hp, hc, not dbl_start, {}, 0)
    if not hg then return nil end
    local tg, tgc = pieces_to_groups(tp, tc, dbl_start ~= nil, {}, 0)
    if not tg then return nil end

    if dbl_start then
        local fill = 8 - hgc - tgc
        if fill < 1 then return nil end
        local g = {}
        for i = 1, hgc do g[i] = hg[i] end
        for i = 1, fill do g[hgc + i] = 0 end
        for i = 1, tgc do g[hgc + fill + i] = tg[i] end
        return g
    end

    if hgc ~= 8 then return nil end
    return hg
end

function _M.ipv4_to_string(addr)
    return format("%d.%d.%d.%d",
        floor(addr / 16777216) % 256,
        floor(addr / 65536) % 256,
        floor(addr / 256) % 256,
        addr % 256)
end

function _M.ipv6_to_string(g)
    local best_start, best_len = 0, 0
    local cur_start, cur_len = 0, 0
    for i = 1, 8 do
        if g[i] == 0 then
            if cur_len == 0 then cur_start = i end
            cur_len = cur_len + 1
            if cur_len > best_len then
                best_len = cur_len
                best_start = cur_start
            end
        else
            cur_len = 0
        end
    end
    if best_len < 2 then
        return format("%x:%x:%x:%x:%x:%x:%x:%x",
            g[1], g[2], g[3], g[4], g[5], g[6], g[7], g[8])
    end
    local out = {}
    local i = 1
    while i <= 8 do
        if i == best_start then
            out[#out + 1] = ""
            if i == 1 then out[#out + 1] = "" end
            i = i + best_len
            if i > 8 then out[#out + 1] = "" end
        else
            out[#out + 1] = format("%x", g[i])
            i = i + 1
        end
    end
    return table.concat(out, ":")
end

function _M.embedded_ipv4(g)
    local out, n = {}, 0
    local low = g[7] * 65536 + g[8]

    local function push(v)
        if v and v >= 0 and v <= MAX_U32 then
            n = n + 1
            out[n] = v
        end
    end

    if g[1] == 0 and g[2] == 0 and g[3] == 0 and g[4] == 0 then
        if (g[5] == 0 and (g[6] == 65535 or g[6] == 0))
            or (g[5] == 65535 and g[6] == 0) then
            push(low)
        end
    end

    if g[1] == 100 and g[2] == 65435 then
        push(low)
        push(g[5] * 65536 + g[6])
    end

    if g[1] == 8194 then
        push(g[2] * 65536 + g[3])
    end

    if g[1] == 8193 and g[2] == 0 then
        push(g[3] * 65536 + g[4])
        push(MAX_U32 - low)
    end

    if g[5] == 0 and g[6] == 24318 then
        push(low)
    end
    if g[5] == 512 and g[6] == 24318 then
        push(low)
    end

    return out, n
end

function _M.ipv4_mapped(g)
    if g[1] == 0 and g[2] == 0 and g[3] == 0 and g[4] == 0
        and g[5] == 0 and g[6] == 65535 then
        return g[7] * 65536 + g[8]
    end
    return nil
end

function _M.mask_ipv4(addr, prefix)
    if prefix <= 0 then return 0 end
    if prefix >= 32 then return addr end
    local block = 2 ^ (32 - prefix)
    return addr - (addr % block)
end

function _M.mask_ipv6(g, prefix)
    local out = {}
    for i = 1, 8 do
        local bits = prefix - (i - 1) * 16
        if bits >= 16 then
            out[i] = g[i]
        elseif bits <= 0 then
            out[i] = 0
        else
            local block = 2 ^ (16 - bits)
            out[i] = g[i] - (g[i] % block)
        end
    end
    return out
end

function _M.ipv6_key(g)
    return format("%04x%04x%04x%04x%04x%04x%04x%04x",
        g[1], g[2], g[3], g[4], g[5], g[6], g[7], g[8])
end

function _M.parse_cidr(s)
    if type(s) ~= "string" or s == "" or #s > 60 then
        return nil, nil, nil
    end
    local addr_part, len_part = s:match("^([^/]+)/(%d+)$")
    if not addr_part then
        addr_part = s
        len_part = nil
    end
    if find(addr_part, "^%[") then
        addr_part = addr_part:match("^%[(.*)%]$")
        if not addr_part then return nil, nil, nil end
    end
    local v4 = _M.parse_ipv4(addr_part)
    if v4 then
        local prefix = 32
        if len_part then
            prefix = tonumber(len_part, 10)
            if not prefix or prefix < 0 or prefix > 32 or #len_part > 2 then
                return nil, nil, nil
            end
        end
        return "ipv4", _M.mask_ipv4(v4, prefix), prefix
    end
    local v6 = _M.parse_ipv6(addr_part)
    if v6 then
        local prefix = 128
        if len_part then
            prefix = tonumber(len_part, 10)
            if not prefix or prefix < 0 or prefix > 128 or #len_part > 3 then
                return nil, nil, nil
            end
        end
        return "ipv6", _M.mask_ipv6(v6, prefix), prefix
    end
    return nil, nil, nil
end

return _M
