local _M = {}

local RESPONSES = {
    ["/ok"] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    ["/split"] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
        .. "X-Evil: a\r\nX-Injected: yes\r\n\r\nok",
    ["/dual"] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
        .. "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    ["/dupclen"] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
        .. "Content-Length: 6\r\n\r\nhello",
    ["/badstatus"] = "HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n",
    ["/nothttp"] = "ICY 200 OK\r\nContent-Length: 0\r\n\r\n",
    ["/barelf"] = "HTTP/1.1 200 OK\nContent-Length: 2\n\nok",
    ["/obsfold"] = "HTTP/1.1 200 OK\r\nX-Fold: a\r\n b\r\nContent-Length: 2\r\n\r\nok",
    ["/spacecolon"] = "HTTP/1.1 200 OK\r\nX-Bad : 1\r\nContent-Length: 2\r\n\r\nok",
    ["/badchunk"] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        .. "zz\r\nhello\r\n0\r\n\r\n",
    ["/negchunk"] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        .. "-5\r\nhello\r\n0\r\n\r\n",
    ["/teidentity"] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n\r\nhello",
    ["/redirect-internal"] = "HTTP/1.1 302 Found\r\n"
        .. "Location: http://169.254.169.254/latest/meta-data/\r\n"
        .. "Content-Length: 0\r\n\r\n",
    ["/redirect-denied"] = "HTTP/1.1 302 Found\r\n"
        .. "Location: http://denied.test/\r\nContent-Length: 0\r\n\r\n",
    ["/redirect-decimal"] = "HTTP/1.1 302 Found\r\n"
        .. "Location: http://2852039166/latest\r\nContent-Length: 0\r\n\r\n",
    ["/redirect-relative"] = "HTTP/1.1 302 Found\r\n"
        .. "Location: /elsewhere\r\nContent-Length: 0\r\n\r\n",
    ["/redirect-allowed"] = "HTTP/1.1 302 Found\r\n"
        .. "Location: http://api.allowed.test/\r\nContent-Length: 0\r\n\r\n",
    ["/nullheader"] = "HTTP/1.1 200 OK\r\nX-Null: a\0b\r\nContent-Length: 2\r\n\r\nok",
    ["/redirect-scheme-relative"] = "HTTP/1.1 302 Found\r\n"
        .. "Location: //denied.test/steal\r\nContent-Length: 0\r\n\r\n",
    ["/redirect-scheme-relative-metadata"] = "HTTP/1.1 302 Found\r\n"
        .. "Location: //169.254.169.254/latest/meta-data/\r\n"
        .. "Content-Length: 0\r\n\r\n",
    ["/redirect-backslash"] = "HTTP/1.1 302 Found\r\n"
        .. "Location: /\\denied.test/steal\r\nContent-Length: 0\r\n\r\n",
    ["/redirect-double-backslash"] = "HTTP/1.1 302 Found\r\n"
        .. "Location: \\\\denied.test/steal\r\nContent-Length: 0\r\n\r\n",
    ["/redirect-javascript"] = "HTTP/1.1 302 Found\r\n"
        .. "Location: javascript:fetch('//denied.test')\r\n"
        .. "Content-Length: 0\r\n\r\n",
    ["/trailerflood"] = (function()
        local parts = { "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            "2\r\nok\r\n", "0\r\n" }
        for i = 1, 4000 do
            parts[#parts + 1] = "X-Trailer-" .. i .. ": padding\r\n"
        end
        parts[#parts + 1] = "\r\n"
        return table.concat(parts)
    end)(),
    ["/trailerok"] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        .. "2\r\nok\r\n0\r\nX-Checksum: abc\r\n\r\n",
    ["/interim-smuggle"] = "HTTP/1.1 100 Continue\r\n\r\n"
        .. "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n"
        .. "X-Smuggled: yes\r\n\r\nSMUGGLED!",
    ["/interim-redirect"] = "HTTP/1.1 100 Continue\r\n\r\n"
        .. "HTTP/1.1 302 Found\r\n"
        .. "Location: http://169.254.169.254/latest/meta-data/\r\n"
        .. "Content-Length: 0\r\n\r\n",
    ["/interim-then-ok"] = "HTTP/1.1 100 Continue\r\n\r\n"
        .. "HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\n"
        .. "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    ["/interim-flood"] = (function()
        local parts = {}
        for _ = 1, 64 do
            parts[#parts + 1] = "HTTP/1.1 100 Continue\r\n\r\n"
        end
        parts[#parts + 1] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        return table.concat(parts)
    end)(),
    ["/switching"] = "HTTP/1.1 101 Switching Protocols\r\n"
        .. "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        .. "RAWTUNNELBYTES",
}

function _M.run()
    local sock = ngx.req.socket(true)
    if not sock then return end
    sock:settimeout(5000)

    local buf = ""
    while not buf:find("\r\n\r\n", 1, true) do
        local data, err = sock:receiveany(4096)
        if not data then return end
        buf = buf .. data
        if #buf > 65536 then break end
    end

    local path = buf:match("^%u+%s+([^%s]+)%s") or "/ok"
    local q = path:find("?", 1, true)
    if q then path = path:sub(1, q - 1) end

    if path == "/hugeheader" then
        sock:send("HTTP/1.1 200 OK\r\nX-Big: " .. string.rep("a", 100000)
            .. "\r\nContent-Length: 2\r\n\r\nok")
        return
    end
    if path == "/nohead" then
        sock:send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n")
        ngx.sleep(3)
        return
    end
    if path == "/shortbody" then
        sock:send("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
        return
    end
    if path == "/overbody-delayed" then
        sock:send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        ngx.sleep(0.4)
        sock:send("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n"
            .. "X-Smuggled: yes\r\n\r\nSMUGGLED!")
        ngx.sleep(3)
        return
    end
    if path == "/overbody" then
        sock:send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
            .. "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n"
            .. "X-Smuggled: yes\r\n\r\nSMUGGLED!")
        ngx.sleep(2)
        return
    end
    if path == "/interim-keepalive" then
        local n = 0
        while n < 8 do
            n = n + 1
            sock:send("HTTP/1.1 100 Continue\r\n\r\n"
                .. "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n"
                .. "X-Smuggled: yes\r\nConnection: keep-alive\r\n\r\n"
                .. "SMUGGLED!")
            local buf2 = ""
            while not buf2:find("\r\n\r\n", 1, true) do
                local data = sock:receiveany(4096)
                if not data then return end
                buf2 = buf2 .. data
                if #buf2 > 65536 then return end
            end
        end
        return
    end
    if path:sub(1, 7) == "/replay" then
        local hex = buf:match("[Xx]%-[Rr]eplay:%s*([0-9a-fA-F]*)")
        if not hex or #hex == 0 or #hex % 2 == 1 then
            sock:send("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        end
        local out = {}
        for i = 1, #hex, 2 do
            out[#out + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
        end
        sock:send(table.concat(out))
        ngx.sleep(1)
        return
    end
    if path == "/interim-slow" then
        for _ = 1, 20 do
            local ok = sock:send("HTTP/1.1 100 Continue\r\n\r\n")
            if not ok then return end
            ngx.sleep(0.4)
        end
        sock:send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        return
    end
    if path == "/interim-with-body" then
        sock:send("HTTP/1.1 100 Continue\r\nContent-Length: 44\r\n\r\n"
            .. "HTTP/1.1 200 OK\r\nX-Smuggled: yes\r\n\r\nEVIL")
        ngx.sleep(2)
        return
    end
    if path == "/interim-chunked" then
        sock:send("HTTP/1.1 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\n"
            .. "4\r\nEVIL\r\n0\r\n\r\n"
            .. "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        ngx.sleep(2)
        return
    end
    if path == "/interim-huge-head" then
        sock:send("HTTP/1.1 100 Continue\r\nX-Pad: " .. string.rep("a", 200000)
            .. "\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        return
    end
    if path == "/endlesstrailers" then
        sock:send("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            .. "2\r\nok\r\n0\r\n")
        local i = 0
        local deadline = ngx.now() + 30
        while ngx.now() < deadline do
            i = i + 1
            local ok = sock:send("X-Endless-" .. i .. ": padding\r\n")
            if not ok then
                return
            end
        end
        return
    end

    local response = RESPONSES[path]
    if not response then
        response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    end
    sock:send(response)
end

return _M
