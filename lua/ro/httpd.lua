local http = require("ro.http")
local reader_mod = require("ro.reader")
local cjson = require("cjson.safe")
local util = require("ro.util")

local _M = { _VERSION = "1.0.0" }

local format = string.format
local concat = table.concat
local find = string.find
local sub = string.sub

local PHRASES = {
    [200] = "OK", [201] = "Created", [204] = "No Content",
    [400] = "Bad Request", [401] = "Unauthorized", [403] = "Forbidden",
    [404] = "Not Found", [405] = "Method Not Allowed",
    [409] = "Conflict", [413] = "Payload Too Large",
    [415] = "Unsupported Media Type", [422] = "Unprocessable Entity",
    [429] = "Too Many Requests", [500] = "Internal Server Error",
    [503] = "Service Unavailable",
}

function _M.response(status, body, headers, content_type)
    return {
        status = status,
        body = body,
        headers = headers,
        content_type = content_type,
    }
end

function _M.json(status, tbl)
    return {
        status = status,
        body = cjson.encode(tbl) or "{}",
        content_type = "application/json",
    }
end

function _M.text(status, body)
    return {
        status = status,
        body = body,
        content_type = "text/plain; charset=utf-8",
    }
end

function _M.error(status, code, message)
    return _M.json(status, { error = code, message = message })
end

local function serialize(res, keepalive)
    local body = res.body or ""
    local head = {
        format("HTTP/1.1 %d %s", res.status, PHRASES[res.status] or "Unknown"),
        "Content-Type: " .. (res.content_type or "application/json"),
        "Content-Length: " .. #body,
        "Server: rokh-oghab",
        "Cache-Control: no-store",
        "X-Content-Type-Options: nosniff",
        keepalive and "Connection: keep-alive" or "Connection: close",
    }
    if res.headers then
        for k, v in pairs(res.headers) do
            head[#head + 1] = k .. ": " .. v
        end
    end
    return concat(head, "\r\n") .. "\r\n\r\n" .. body
end

function _M.parse_query(query)
    local out = {}
    if type(query) ~= "string" or query == "" then
        return out
    end
    for _, pair in ipairs(util.split(query, "&")) do
        local eq = find(pair, "=", 1, true)
        local k, v
        if eq then
            k = sub(pair, 1, eq - 1)
            v = sub(pair, eq + 1)
        else
            k = pair
            v = ""
        end
        k = k:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
        v = v:gsub("+", " "):gsub("%%(%x%x)",
            function(h) return string.char(tonumber(h, 16)) end)
        if #k > 0 and #k < 128 and #v < 4096 then
            out[k] = v
        end
    end
    return out
end

function _M.serve(router, opts)
    opts = opts or {}
    local sock, serr = ngx.req.socket(true)
    if not sock then
        return
    end
    sock:settimeout(opts.timeout or 15000)

    local rd = reader_mod.wrap(sock)
    local served = 0
    local max_requests = opts.max_requests or 64
    local max_body = opts.max_body or 4194304

    while served < max_requests do
        local raw, rerr = rd:read_until("\r\n\r\n", opts.max_head or 32768)
        if not raw then
            return
        end
        served = served + 1

        local req, perr = http.parse_request_head(raw)
        if not req then
            sock:send(serialize(_M.error(400, "bad_request", tostring(perr)), false))
            return
        end

        local pt = req.parsed_target
        if pt.form ~= "origin" then
            sock:send(serialize(_M.error(400, "bad_request",
                "origin-form request target required"), false))
            return
        end

        local framing, ferr = http.request_framing(req)
        if not framing then
            sock:send(serialize(_M.error(400, "bad_request", tostring(ferr)), false))
            return
        end

        local body = ""
        if framing.mode == "length" then
            if framing.length > max_body then
                sock:send(serialize(_M.error(413, "payload_too_large",
                    "request body exceeds limit"), false))
                return
            end
            local remaining = framing.length
            local parts = {}
            while remaining > 0 do
                local chunk = rd:read_some(remaining > 65536 and 65536 or remaining)
                if not chunk then
                    return
                end
                parts[#parts + 1] = chunk
                remaining = remaining - #chunk
            end
            body = concat(parts)
        elseif framing.mode == "chunked" then
            sock:send(serialize(_M.error(400, "bad_request",
                "chunked request bodies are not accepted by the admin API"), false))
            return
        end

        local path, nerr = http.normalize_path(pt.path)
        if not path then
            sock:send(serialize(_M.error(400, "bad_request", tostring(nerr)), false))
            return
        end

        local ctx = {
            method = req.method,
            path = path,
            raw_path = pt.path,
            query = _M.parse_query(pt.query),
            headers = req.headers,
            body = body,
            remote_addr = ngx.var.remote_addr,
        }

        local ok, res = pcall(router, ctx)
        if not ok then
            ngx.log(ngx.ERR, "rokh-oghab admin handler error: ", tostring(res))
            res = _M.error(500, "internal_error", "request handling failed")
        end
        if type(res) ~= "table" or not res.status then
            res = _M.error(500, "internal_error", "handler returned no response")
        end

        local keepalive = not http.wants_close(req.headers, req.version)
            and served < max_requests
        local sent = sock:send(serialize(res, keepalive))
        if not sent or not keepalive then
            return
        end
    end
end

return _M
