local _M = { _VERSION = "1.0.0" }

local byte = string.byte
local char = string.char
local sub = string.sub
local find = string.find
local format = string.format
local floor = math.floor
local concat = table.concat
local gsub = string.gsub

local ok_sha, resty_sha256 = pcall(require, "resty.sha256")
local ok_str, resty_string = pcall(require, "resty.string")

local counter = 0

function _M.now()
    if ngx and ngx.now then
        local ok, v = pcall(ngx.now)
        if ok and v then
            return v
        end
    end
    return os.time()
end

function _M.now_ms()
    return floor(_M.now() * 1000)
end

function _M.now_ns()
    local seconds = _M.now()
    local whole = floor(seconds)
    local frac = floor((seconds - whole) * 1000000 + 0.5)
    if frac >= 1000000 then
        whole = whole + 1
        frac = 0
    end
    return whole * 1000000000 + frac * 1000
end

function _M.monotonic()
    if ngx and ngx.now then
        local ok, v = pcall(function()
            ngx.update_time()
            return ngx.now()
        end)
        if ok and v then
            return v
        end
    end
    return os.clock()
end

function _M.gen_id()
    counter = counter + 1
    if counter > 0xFFFFFF then
        counter = 1
    end
    local pid = 0
    if ngx and ngx.worker and ngx.worker.pid then
        pid = ngx.worker.pid() % 65536
    end
    return format("%08x%04x%06x", floor(_M.now()) % 0xFFFFFFFF, pid, counter)
end

function _M.sha256_hex(s)
    if type(s) ~= "string" then
        return nil
    end
    if ok_sha and ok_str then
        local d = resty_sha256:new()
        d:update(s)
        return resty_string.to_hex(d:final())
    end
    if ngx and ngx.md5 then
        return ngx.md5(s)
    end
    return nil
end

function _M.const_eq(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then
        return false
    end
    local ha = _M.sha256_hex(a)
    local hb = _M.sha256_hex(b)
    if not ha or not hb or #ha ~= #hb then
        return false
    end
    local diff = 0
    for i = 1, #ha do
        diff = diff + (byte(ha, i) == byte(hb, i) and 0 or 1)
    end
    return diff == 0
end

local function byte_xor(a, b)
    local r, p = 0, 1
    for _ = 1, 8 do
        local x, y = a % 2, b % 2
        if x ~= y then r = r + p end
        a = floor((a - x) / 2)
        b = floor((b - y) / 2)
        p = p * 2
    end
    return r
end

local function sha256_raw(s)
    local d = resty_sha256:new()
    d:update(s)
    return d:final()
end

function _M.hmac_sha256(key, message)
    if not (ok_sha and ok_str) then
        return nil
    end
    if type(key) ~= "string" or type(message) ~= "string" then
        return nil
    end
    if #key > 64 then
        key = sha256_raw(key)
    end
    local ipad, opad = {}, {}
    for i = 1, 64 do
        local kb = (i <= #key) and byte(key, i) or 0
        ipad[i] = char(byte_xor(kb, 0x36))
        opad[i] = char(byte_xor(kb, 0x5c))
    end
    local inner = sha256_raw(concat(ipad) .. message)
    return sha256_raw(concat(opad) .. inner)
end

function _M.hmac_sha256_hex(key, message)
    local raw = _M.hmac_sha256(key, message)
    if not raw then
        return nil
    end
    return resty_string.to_hex(raw)
end

function _M.clamp(v, lo, hi)
    if type(v) ~= "number" then
        return lo
    end
    if v < lo then return lo end
    if v > hi then return hi end
    return v
end

function _M.split(s, sep, max)
    local out, n = {}, 0
    if type(s) ~= "string" or s == "" then
        return out, 0
    end
    local start = 1
    while true do
        if max and n >= max - 1 then
            n = n + 1
            out[n] = sub(s, start)
            break
        end
        local i = find(s, sep, start, true)
        if not i then
            n = n + 1
            out[n] = sub(s, start)
            break
        end
        n = n + 1
        out[n] = sub(s, start, i - 1)
        start = i + #sep
    end
    return out, n
end

function _M.trim(s)
    if type(s) ~= "string" then return nil end
    return (s:gsub("^[ \t]+", ""):gsub("[ \t]+$", ""))
end

function _M.starts_with(s, prefix)
    return type(s) == "string" and type(prefix) == "string"
        and sub(s, 1, #prefix) == prefix
end

function _M.ends_with(s, suffix)
    return type(s) == "string" and type(suffix) == "string"
        and (#suffix == 0 or sub(s, -#suffix) == suffix)
end

function _M.is_array(t)
    if type(t) ~= "table" then return false end
    local n = 0
    for k in pairs(t) do
        if type(k) ~= "number" then return false end
        n = n + 1
    end
    for i = 1, n do
        if t[i] == nil then return false end
    end
    return true
end

function _M.shallow_copy(t)
    if type(t) ~= "table" then return t end
    local out = {}
    for k, v in pairs(t) do out[k] = v end
    return out
end

function _M.deep_copy(t, depth)
    depth = depth or 0
    if type(t) ~= "table" or depth > 32 then return t end
    local out = {}
    for k, v in pairs(t) do
        out[k] = _M.deep_copy(v, depth + 1)
    end
    return out
end

function _M.count(t)
    local n = 0
    if type(t) ~= "table" then return 0 end
    for _ in pairs(t) do n = n + 1 end
    return n
end

function _M.sorted_keys(t)
    local keys, n = {}, 0
    for k in pairs(t) do
        n = n + 1
        keys[n] = k
    end
    table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
    return keys, n
end

local JSON_ESCAPE = {
    ['"'] = '\\"', ["\\"] = "\\\\", ["\b"] = "\\b", ["\f"] = "\\f",
    ["\n"] = "\\n", ["\r"] = "\\r", ["\t"] = "\\t",
}

local function json_string(s)
    local out = gsub(s, '[%c"\\]', function(c)
        return JSON_ESCAPE[c] or format("\\u%04x", byte(c))
    end)
    return '"' .. out .. '"'
end

local function json_number(n)
    if n ~= n or n == 1 / 0 or n == -1 / 0 then
        return "null"
    end
    if n == floor(n) and n < 1e15 and n > -1e15 then
        return format("%d", n)
    end
    return format("%.17g", n)
end

local function canonical(v, depth, parts)
    depth = depth or 0
    if depth > 64 then
        parts[#parts + 1] = "null"
        return
    end
    local t = type(v)
    if v == nil then
        parts[#parts + 1] = "null"
    elseif t == "boolean" then
        parts[#parts + 1] = v and "true" or "false"
    elseif t == "number" then
        parts[#parts + 1] = json_number(v)
    elseif t == "string" then
        parts[#parts + 1] = json_string(v)
    elseif t ~= "table" then
        parts[#parts + 1] = "null"
    elseif _M.is_array(v) then
        parts[#parts + 1] = "["
        for i = 1, #v do
            if i > 1 then parts[#parts + 1] = "," end
            canonical(v[i], depth + 1, parts)
        end
        parts[#parts + 1] = "]"
    else
        local keys = _M.sorted_keys(v)
        parts[#parts + 1] = "{"
        for i = 1, #keys do
            if i > 1 then parts[#parts + 1] = "," end
            parts[#parts + 1] = json_string(tostring(keys[i]))
            parts[#parts + 1] = ":"
            canonical(v[keys[i]], depth + 1, parts)
        end
        parts[#parts + 1] = "}"
    end
end

function _M.canonical_json(v)
    local parts = {}
    canonical(v, 0, parts)
    return concat(parts)
end

function _M.content_digest(v)
    if type(v) == "string" then
        return _M.sha256_hex(v)
    end
    return _M.sha256_hex(_M.canonical_json(v))
end

local ok_rand, resty_random = pcall(require, "resty.random")

function _M.random_bytes(n)
    if not ok_rand or not resty_random or not resty_random.bytes then
        return nil, "no strong random source is available"
    end
    local raw = resty_random.bytes(n, true)
    if type(raw) ~= "string" or #raw ~= n then
        return nil, "the strong random source returned nothing usable"
    end
    return raw
end

function _M.random_int(lo, hi)
    local span = hi - lo + 1
    if span <= 0 then
        return nil, "an empty range has no members"
    end
    local raw, err = _M.random_bytes(4)
    if not raw then
        return nil, err
    end
    local n = 0
    for i = 1, 4 do
        n = n * 256 + byte(raw, i)
    end
    return lo + (n % span)
end

function _M.to_hex(s)
    if ok_str then
        return resty_string.to_hex(s)
    end
    local out = {}
    for i = 1, #s do
        out[i] = format("%02x", byte(s, i))
    end
    return concat(out)
end

function _M.from_hex(s)
    if type(s) ~= "string" or #s % 2 ~= 0 or find(s, "[^0-9a-fA-F]") then
        return nil
    end
    local out = {}
    for i = 1, #s, 2 do
        out[#out + 1] = char(tonumber(sub(s, i, i + 1), 16))
    end
    return concat(out)
end

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

function _M.b64_decode(data)
    if type(data) ~= "string" then return nil end
    data = data:gsub("%s", "")
    if find(data, "[^A-Za-z0-9+/=]") then return nil end
    if #data % 4 ~= 0 then return nil end
    if ngx and ngx.decode_base64 then
        return ngx.decode_base64(data)
    end
    data = data:gsub("=", "")
    local out = {}
    local bits, nbits = 0, 0
    for i = 1, #data do
        local c = sub(data, i, i)
        local v = find(B64, c, 1, true)
        if not v then return nil end
        bits = bits * 64 + (v - 1)
        nbits = nbits + 6
        if nbits >= 8 then
            nbits = nbits - 8
            local b = floor(bits / (2 ^ nbits))
            bits = bits % (2 ^ nbits)
            out[#out + 1] = char(b)
        end
    end
    return concat(out)
end

function _M.parse_size(v, default)
    if type(v) == "number" then return v end
    if type(v) ~= "string" then return default end
    local num, unit = v:match("^(%d+%.?%d*)%s*([KkMmGg]?)[IiBb]*$")
    if not num then return default end
    local n = tonumber(num)
    if not n then return default end
    unit = unit:lower()
    if unit == "k" then return floor(n * 1024) end
    if unit == "m" then return floor(n * 1024 * 1024) end
    if unit == "g" then return floor(n * 1024 * 1024 * 1024) end
    return floor(n)
end

function _M.safe_str(v, max)
    max = max or 256
    if v == nil then return "" end
    local s = tostring(v)
    s = s:gsub("[%z\1-\31\127]", "?")
    if #s > max then
        s = sub(s, 1, max) .. "..."
    end
    return s
end

return _M
