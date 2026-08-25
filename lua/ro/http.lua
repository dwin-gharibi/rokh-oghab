local util = require("ro.util")

local _M = { _VERSION = "1.0.0" }

local byte = string.byte
local sub = string.sub
local find = string.find
local lower = string.lower
local upper = string.upper
local concat = table.concat
local tonumber = tonumber

_M.MAX_HEAD = 65536
_M.MAX_HEADERS = 100
_M.MAX_HEADER_LINE = 8192
_M.MAX_URI = 8192
_M.MAX_METHOD = 16
_M.MAX_CHUNK_SIZE = 268435456

local TCHAR = {}
do
    local extra = "!#$%&'*+-.^_`|~"
    for i = 48, 57 do TCHAR[i] = true end
    for i = 65, 90 do TCHAR[i] = true end
    for i = 97, 122 do TCHAR[i] = true end
    for i = 1, #extra do TCHAR[byte(extra, i)] = true end
end

local SAFE_METHODS = {
    GET = true, HEAD = true, POST = true, PUT = true, DELETE = true,
    PATCH = true, OPTIONS = true, CONNECT = true, TRACE = true,
}

local ASSERTED_PREFIX = "x-ro-"

local HOP_BY_HOP = {
    ["connection"] = true,
    ["keep-alive"] = true,
    ["proxy-authenticate"] = true,
    ["proxy-authorization"] = true,
    ["proxy-connection"] = true,
    ["te"] = true,
    ["trailer"] = true,
    ["transfer-encoding"] = true,
    ["upgrade"] = true,
}

local NEVER_CONNECTION_SCOPED = {
    ["host"] = true,
    ["content-length"] = true,
    ["transfer-encoding"] = true,
    ["expect"] = true,
    ["close"] = true,
    ["keep-alive"] = true,
    ["upgrade"] = true,
}

_M.HOP_BY_HOP = HOP_BY_HOP
_M.ASSERTED_PREFIX = ASSERTED_PREFIX
_M.SAFE_METHODS = SAFE_METHODS

local function is_token(s, maxlen)
    local n = #s
    if n == 0 or (maxlen and n > maxlen) then
        return false
    end
    for i = 1, n do
        if not TCHAR[byte(s, i)] then
            return false
        end
    end
    return true
end

_M.is_token = is_token

local function valid_header_value(s, allow_obs)
    for i = 1, #s do
        local b = byte(s, i)
        if b == 9 then
        elseif b < 32 or b == 127 then
            return false
        elseif b > 127 and not allow_obs then
            return false
        end
    end
    return true
end

function _M.normalize_path(path)
    if type(path) ~= "string" or path == "" then
        return nil, "empty path"
    end
    if #path > _M.MAX_URI then
        return nil, "path too long"
    end
    if byte(path, 1) ~= 47 then
        return nil, "path must start with /"
    end
    if find(path, "[%z\1-\31\127]") then
        return nil, "control characters in path"
    end
    if find(path, "\\", 1, true) then
        return nil, "backslash in path"
    end

    local i = 1
    while true do
        local j = find(path, "%", i, true)
        if not j then break end
        local hex = sub(path, j + 1, j + 2)
        if #hex < 2 or find(hex, "[^0-9A-Fa-f]") then
            return nil, "malformed percent-encoding"
        end
        local v = tonumber(hex, 16)
        if v == 0 or v == 47 or v == 92 or v == 46 or v < 32 or v == 127 then
            return nil, "encoded separator or control character in path"
        end
        i = j + 3
    end

    local len = #path
    local trailing = len > 1 and byte(path, len) == 47
    local segs, n = {}, 0
    local pos = 2
    while pos <= len + 1 do
        local slash = find(path, "/", pos, true) or (len + 1)
        local seg = sub(path, pos, slash - 1)
        if seg == "" then
        elseif seg == "." then
        elseif seg == ".." then
            if n == 0 then
                return nil, "path escapes root"
            end
            segs[n] = nil
            n = n - 1
        else
            n = n + 1
            segs[n] = seg
        end
        pos = slash + 1
    end

    local out = "/" .. concat(segs, "/", 1, n)
    if trailing and n > 0 then
        out = out .. "/"
    end
    return out
end

function _M.parse_request_target(target, method)
    if type(target) ~= "string" or target == "" then
        return nil, "empty request target"
    end
    if #target > _M.MAX_URI then
        return nil, "request target too long"
    end
    if find(target, "[%z\1-\32\127]") then
        return nil, "control characters in request target"
    end

    if method == "CONNECT" then
        return { form = "authority", authority = target }
    end

    if target == "*" then
        if method ~= "OPTIONS" then
            return nil, "asterisk form only valid for OPTIONS"
        end
        return { form = "asterisk" }
    end

    if byte(target, 1) == 47 then
        local q = find(target, "?", 1, true)
        local path, query
        if q then
            path = sub(target, 1, q - 1)
            query = sub(target, q + 1)
            if find(query, "?", 1, true) then
                query = query
            end
        else
            path = target
        end
        return { form = "origin", path = path, query = query }
    end

    local scheme_end = find(target, "://", 1, true)
    if not scheme_end then
        return nil, "unsupported request target form"
    end
    local scheme = lower(sub(target, 1, scheme_end - 1))
    if scheme ~= "http" then
        return nil, "unsupported scheme in request target: " .. util.safe_str(scheme, 16)
    end
    local rest = sub(target, scheme_end + 3)
    if rest == "" then
        return nil, "missing authority in request target"
    end
    local cut = find(rest, "[/?#]")
    local authority, remainder
    if cut then
        authority = sub(rest, 1, cut - 1)
        remainder = sub(rest, cut)
    else
        authority = rest
        remainder = "/"
    end
    if authority == "" then
        return nil, "empty authority in request target"
    end
    if byte(remainder, 1) == 35 then
        return nil, "fragment in request target"
    end
    local path, query
    if byte(remainder, 1) == 63 then
        path = "/"
        query = sub(remainder, 2)
    else
        local q = find(remainder, "?", 1, true)
        if q then
            path = sub(remainder, 1, q - 1)
            query = sub(remainder, q + 1)
        else
            path = remainder
        end
    end
    if find(path, "#", 1, true) or (query and find(query, "#", 1, true)) then
        return nil, "fragment in request target"
    end
    return {
        form = "absolute",
        scheme = scheme,
        authority = authority,
        path = path,
        query = query,
    }
end

local headers_mt = {}
headers_mt.__index = headers_mt

function headers_mt:get(name)
    local v = self.map[lower(name)]
    if not v then return nil end
    return v[1]
end

function headers_mt:all(name)
    return self.map[lower(name)]
end

function headers_mt:count(name)
    local v = self.map[lower(name)]
    return v and #v or 0
end

function headers_mt:has(name)
    return self.map[lower(name)] ~= nil
end

local function parse_head_lines(raw, opts)
    opts = opts or {}
    local n = #raw
    if n < 4 then
        return nil, "head too short"
    end
    if sub(raw, n - 3) ~= "\r\n\r\n" then
        return nil, "head not CRLF terminated"
    end
    local body = sub(raw, 1, n - 2)
    if find(body, "\n\r\n", 1, true) then
        return nil, "empty line inside head"
    end

    local lines, ln = {}, 0
    local pos = 1
    local blen = #body
    while pos <= blen do
        local crlf = find(body, "\r\n", pos, true)
        if not crlf then
            return nil, "malformed head framing"
        end
        local line = sub(body, pos, crlf - 1)
        if find(line, "[\r\n]") then
            return nil, "bare CR or LF in head"
        end
        if #line > _M.MAX_HEADER_LINE then
            return nil, "header line too long"
        end
        ln = ln + 1
        if ln > _M.MAX_HEADERS + 1 then
            return nil, "too many header lines"
        end
        lines[ln] = line
        pos = crlf + 2
    end
    if ln == 0 then
        return nil, "missing start line"
    end

    local headers = setmetatable({ list = {}, map = {} }, headers_mt)
    for i = 2, ln do
        local line = lines[i]
        local b1 = byte(line, 1)
        if b1 == 32 or b1 == 9 then
            return nil, "obsolete line folding is not allowed"
        end
        local colon = find(line, ":", 1, true)
        if not colon then
            return nil, "header line without colon"
        end
        local name = sub(line, 1, colon - 1)
        if not is_token(name, 128) then
            return nil, "invalid header name"
        end
        local value = sub(line, colon + 1)
        value = value:gsub("^[ \t]+", ""):gsub("[ \t]+$", "")
        if not valid_header_value(value, opts.allow_obs_text) then
            return nil, "invalid header value"
        end
        local lname = lower(name)
        local entry = { name = name, lname = lname, value = value }
        headers.list[#headers.list + 1] = entry
        local bucket = headers.map[lname]
        if bucket then
            bucket[#bucket + 1] = value
        else
            headers.map[lname] = { value }
        end
    end

    return lines[1], headers
end

_M.parse_head_lines = parse_head_lines

function _M.parse_request_head(raw, opts)
    opts = opts or {}
    local start_line, headers = parse_head_lines(raw, opts)
    if not start_line then
        return nil, headers
    end

    if byte(start_line, 1) == 32 or byte(start_line, 1) == 9 then
        return nil, "leading whitespace in request line"
    end

    local sp1 = find(start_line, " ", 1, true)
    if not sp1 then
        return nil, "malformed request line"
    end
    local sp2 = find(start_line, " ", sp1 + 1, true)
    if not sp2 then
        return nil, "malformed request line"
    end
    if find(start_line, " ", sp2 + 1, true) then
        return nil, "malformed request line"
    end

    local method = sub(start_line, 1, sp1 - 1)
    local target = sub(start_line, sp1 + 1, sp2 - 1)
    local version = sub(start_line, sp2 + 1)

    if not is_token(method, _M.MAX_METHOD) then
        return nil, "invalid method token"
    end
    if method ~= upper(method) or not SAFE_METHODS[method] then
        return nil, "unsupported method"
    end
    if version ~= "HTTP/1.1" and version ~= "HTTP/1.0" then
        return nil, "unsupported HTTP version"
    end
    if target == "" then
        return nil, "empty request target"
    end

    local parsed, terr = _M.parse_request_target(target, method)
    if not parsed then
        return nil, terr
    end

    if version == "HTTP/1.1" and headers:count("host") ~= 1 then
        return nil, "HTTP/1.1 requires exactly one Host header"
    end
    if headers:count("host") > 1 then
        return nil, "multiple Host headers"
    end

    return {
        method = method,
        target = target,
        version = version,
        parsed_target = parsed,
        headers = headers,
        raw_size = #raw,
    }
end

function _M.parse_response_head(raw, opts)
    opts = opts or {}
    opts.allow_obs_text = true
    local start_line, headers = parse_head_lines(raw, opts)
    if not start_line then
        return nil, headers
    end
    local version, code, reason = start_line:match("^(HTTP/1%.[01]) (%d%d%d) ?(.*)$")
    if not version then
        return nil, "malformed status line"
    end
    local status = tonumber(code, 10)
    if not status or status < 100 or status > 599 then
        return nil, "invalid status code"
    end
    return {
        version = version,
        status = status,
        reason = reason,
        headers = headers,
        raw_size = #raw,
    }
end

local function parse_content_length(values)
    local first
    for _, v in ipairs(values) do
        local parts = util.split(v, ",")
        if #parts == 0 then
            return nil, "malformed content-length"
        end
        for _, piece in ipairs(parts) do
            piece = util.trim(piece)
            if piece == "" or find(piece, "^%d+$") == nil then
                return nil, "malformed content-length"
            end
            if #piece > 15 then
                return nil, "content-length too large"
            end
            if #piece > 1 and byte(piece, 1) == 48 then
                return nil, "content-length has leading zeros"
            end
            local n = tonumber(piece, 10)
            if first == nil then
                first = n
            elseif first ~= n then
                return nil, "conflicting content-length values"
            end
        end
    end
    if first == nil then
        return nil, "empty content-length"
    end
    return first
end

_M.parse_content_length = parse_content_length

local function framing_from_headers(headers)
    local te = headers:all("transfer-encoding")
    local cl = headers:all("content-length")

    if te and cl then
        return nil, "both transfer-encoding and content-length present"
    end
    if te then
        if #te > 1 then
            return nil, "multiple transfer-encoding headers"
        end
        local v = lower(util.trim(te[1]))
        if v ~= "chunked" then
            return nil, "unsupported transfer-encoding: " .. util.safe_str(v, 32)
        end
        return { mode = "chunked" }
    end
    if cl then
        local n, err = parse_content_length(cl)
        if not n then
            return nil, err
        end
        return { mode = "length", length = n }
    end
    return nil
end

function _M.request_framing(req)
    local f, err = framing_from_headers(req.headers)
    if err then
        return nil, err
    end
    if f then
        return f
    end
    return { mode = "none" }
end

function _M.response_framing(res, method)
    if method == "HEAD" or res.status == 204 or res.status == 304
        or (res.status >= 100 and res.status < 200) then
        return { mode = "none" }
    end
    local f, err = framing_from_headers(res.headers)
    if err then
        return nil, err
    end
    if f then
        return f
    end
    return { mode = "until_close" }
end

function _M.connection_tokens(headers)
    local out = {}
    local values = headers:all("connection")
    if values then
        for _, v in ipairs(values) do
            for _, tokv in ipairs(util.split(v, ",")) do
                local t = lower(util.trim(tokv))
                if t ~= "" then
                    out[t] = true
                end
            end
        end
    end
    local legacy = headers:all("proxy-connection")
    if legacy then
        for _, v in ipairs(legacy) do
            for _, tokv in ipairs(util.split(v, ",")) do
                local t = lower(util.trim(tokv))
                if t ~= "" then
                    out[t] = true
                end
            end
        end
    end
    return out
end

function _M.wants_close(headers, version)
    local tokens = _M.connection_tokens(headers)
    if tokens["close"] then
        return true
    end
    if version == "HTTP/1.0" and not tokens["keep-alive"] then
        return true
    end
    return false
end

function _M.serialize_head(start_line, headers, drop, add)
    local out = { start_line }
    local dropped = {}
    if drop then
        for k in pairs(drop) do
            dropped[lower(k)] = true
        end
    end
    for name in pairs(_M.connection_tokens(headers)) do
        if not NEVER_CONNECTION_SCOPED[name] then
            dropped[name] = true
        end
    end
    for _, entry in ipairs(headers.list) do
        if not HOP_BY_HOP[entry.lname] and not dropped[entry.lname]
            and sub(entry.lname, 1, #ASSERTED_PREFIX) ~= ASSERTED_PREFIX then
            out[#out + 1] = entry.name .. ": " .. entry.value
        end
    end
    if add then
        for i = 1, #add do
            out[#out + 1] = add[i]
        end
    end
    out[#out + 1] = ""
    out[#out + 1] = ""
    return concat(out, "\r\n")
end

function _M.parse_chunk_size(line)
    if type(line) ~= "string" then
        return nil, "invalid chunk header"
    end
    if #line == 0 or #line > 256 then
        return nil, "invalid chunk header"
    end
    local size_part = line
    local semi = find(line, ";", 1, true)
    if semi then
        size_part = sub(line, 1, semi - 1)
        local ext = sub(line, semi + 1)
        if find(ext, "[%z\1-\31\127]") then
            return nil, "invalid chunk extension"
        end
    end
    size_part = util.trim(size_part)
    if size_part == "" or #size_part > 8 or find(size_part, "[^0-9A-Fa-f]") then
        return nil, "invalid chunk size"
    end
    local n = tonumber(size_part, 16)
    if not n or n < 0 or n > _M.MAX_CHUNK_SIZE then
        return nil, "chunk size out of range"
    end
    return n
end

return _M
