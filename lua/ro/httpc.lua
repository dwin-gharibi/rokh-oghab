local http = require("ro.http")
local reader_mod = require("ro.reader")
local cjson = require("cjson.safe")

local _M = { _VERSION = "1.0.0" }

local format = string.format
local concat = table.concat
local find = string.find
local sub = string.sub

local function parse_url(url)
    if type(url) ~= "string" then
        return nil, "url must be a string"
    end
    local scheme_end = find(url, "://", 1, true)
    if not scheme_end then
        return nil, "url missing scheme"
    end
    local scheme = sub(url, 1, scheme_end - 1):lower()
    if scheme ~= "http" then
        return nil, "only http:// control-plane urls are supported"
    end
    local rest = sub(url, scheme_end + 3)
    local cut = find(rest, "/", 1, true)
    local authority = cut and sub(rest, 1, cut - 1) or rest
    local path = cut and sub(rest, cut) or "/"
    local host, port
    if sub(authority, 1, 1) == "[" then
        local close = find(authority, "]", 1, true)
        host = sub(authority, 2, close - 1)
        port = tonumber(sub(authority, close + 2)) or 80
    else
        local colon = find(authority, ":", 1, true)
        if colon then
            host = sub(authority, 1, colon - 1)
            port = tonumber(sub(authority, colon + 1)) or 80
        else
            host = authority
            port = 80
        end
    end
    if not host or host == "" then
        return nil, "url missing host"
    end
    return { host = host, port = port, path = path, authority = authority }
end

_M.parse_url = parse_url

local MAX_BODY = 8388608
local MAX_CHUNK_LINE = 4096
local READ_CHUNK = 65536

_M.MAX_BODY = MAX_BODY

function _M.read_body(rd, framing, max_body)
    max_body = max_body or MAX_BODY
    local out = {}
    local total = 0

    if framing.mode == "none" then
        return ""
    end

    if framing.mode == "length" then
        local remaining = framing.length
        if remaining > max_body then
            return nil, "response too large"
        end
        while remaining > 0 do
            local chunk, cerr = rd:read_some(remaining > READ_CHUNK
                and READ_CHUNK or remaining)
            if not chunk then
                return nil, "read-body: " .. tostring(cerr)
            end
            out[#out + 1] = chunk
            remaining = remaining - #chunk
        end
        return concat(out)
    end

    if framing.mode == "chunked" then
        while true do
            local line = rd:read_until("\r\n", MAX_CHUNK_LINE)
            if not line then break end
            local size = http.parse_chunk_size(sub(line, 1, #line - 2))
            if not size then
                return nil, "bad chunk"
            end
            if size == 0 then
                break
            end
            total = total + size
            if total > max_body then
                return nil, "response too large"
            end
            local remaining = size
            while remaining > 0 do
                local chunk = rd:read_some(remaining > READ_CHUNK
                    and READ_CHUNK or remaining)
                if not chunk then
                    return nil, "read-chunk"
                end
                out[#out + 1] = chunk
                remaining = remaining - #chunk
            end
            rd:read_exact(2)
        end
        return concat(out)
    end

    if framing.mode == "until_close" then
        while true do
            local chunk = rd:read_some(READ_CHUNK)
            if not chunk then break end
            total = total + #chunk
            if total > max_body then
                return nil, "response too large"
            end
            out[#out + 1] = chunk
        end
        return concat(out)
    end

    return nil, "unknown framing"
end

function _M.request(url, opts)
    opts = opts or {}
    local parts, perr = parse_url(url)
    if not parts then
        return nil, perr
    end

    local sock = ngx.socket.tcp()
    sock:settimeout(opts.timeout or 3000)
    local ok, cerr = sock:connect(parts.host, parts.port)
    if not ok then
        return nil, "connect: " .. tostring(cerr)
    end

    local method = opts.method or "GET"
    local body = opts.body
    if opts.json ~= nil then
        body = cjson.encode(opts.json)
    end

    local head = {
        format("%s %s HTTP/1.1", method, parts.path),
        "Host: " .. parts.authority,
        "User-Agent: rokh-oghab/1.0",
        "Accept: application/json",
        "Connection: close",
    }
    if opts.token and opts.token ~= "" then
        head[#head + 1] = "Authorization: Bearer " .. opts.token
    end
    if opts.headers then
        for k, v in pairs(opts.headers) do
            head[#head + 1] = k .. ": " .. v
        end
    end
    if body then
        head[#head + 1] = "Content-Type: application/json"
        head[#head + 1] = "Content-Length: " .. #body
    end
    local payload = concat(head, "\r\n") .. "\r\n\r\n" .. (body or "")

    local sent, serr = sock:send(payload)
    if not sent then
        sock:close()
        return nil, "send: " .. tostring(serr)
    end

    local rd = reader_mod.wrap(sock)
    local res
    local interim = 0
    while true do
        local raw, rerr = rd:read_until("\r\n\r\n", 65536)
        if not raw then
            sock:close()
            return nil, "read-head: " .. tostring(rerr)
        end
        local parsed, herr = http.parse_response_head(raw)
        if not parsed then
            sock:close()
            return nil, "parse-head: " .. tostring(herr)
        end
        if parsed.status >= 200 then
            res = parsed
            break
        end
        if parsed.headers:get("content-length")
            or parsed.headers:get("transfer-encoding") then
            sock:close()
            return nil, "an interim response cannot declare a body"
        end
        interim = interim + 1
        if interim > 8 then
            sock:close()
            return nil, "too many interim responses"
        end
    end

    local framing, ferr = http.response_framing(res, method)
    if not framing then
        sock:close()
        return nil, "framing: " .. tostring(ferr)
    end

    local body, berr = _M.read_body(rd, framing, opts.max_body)
    sock:close()
    if not body then
        return nil, berr
    end
    local text = body
    return {
        status = res.status,
        headers = res.headers,
        body = text,
        json = cjson.decode(text),
    }
end

return _M
