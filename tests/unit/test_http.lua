local h = require("harness")
local http = require("ro.http")

local function head(...)
    return table.concat({ ... }, "\r\n") .. "\r\n\r\n"
end

h.describe("http.normalize_path", function()
    h.it("passes through already canonical paths", function()
        h.assert_eq(http.normalize_path("/"), "/")
        h.assert_eq(http.normalize_path("/a/b"), "/a/b")
        h.assert_eq(http.normalize_path("/a/b/"), "/a/b/")
        h.assert_eq(http.normalize_path("/simple/index.html"), "/simple/index.html")
    end)

    h.it("resolves dot segments", function()
        h.assert_eq(http.normalize_path("/a/./b"), "/a/b")
        h.assert_eq(http.normalize_path("/a/../b"), "/b")
        h.assert_eq(http.normalize_path("/a/b/.."), "/a")
        h.assert_eq(http.normalize_path("/repos/../users"), "/users")
        h.assert_eq(http.normalize_path("/a/b/../../c"), "/c")
    end)

    h.it("collapses duplicate slashes", function()
        h.assert_eq(http.normalize_path("/a//b"), "/a/b")
        h.assert_eq(http.normalize_path("//a"), "/a")
    end)

    h.it("rejects traversal above the root", function()
        h.assert_nil(http.normalize_path("/.."))
        h.assert_nil(http.normalize_path("/a/../.."))
        h.assert_nil(http.normalize_path("/../etc/passwd"))
    end)

    h.it("rejects encoded separators and traversal", function()
        h.assert_nil(http.normalize_path("/a/%2e%2e/b"))
        h.assert_nil(http.normalize_path("/a/%2E%2E/b"))
        h.assert_nil(http.normalize_path("/a%2fb"))
        h.assert_nil(http.normalize_path("/a%2Fb"))
        h.assert_nil(http.normalize_path("/a%5cb"))
        h.assert_nil(http.normalize_path("/a%00b"))
    end)

    h.it("rejects malformed percent encoding", function()
        h.assert_nil(http.normalize_path("/a%zz"))
        h.assert_nil(http.normalize_path("/a%"))
        h.assert_nil(http.normalize_path("/a%2"))
    end)

    h.it("rejects control characters, backslashes and non-absolute paths", function()
        h.assert_nil(http.normalize_path("/a\rb"))
        h.assert_nil(http.normalize_path("/a\nb"))
        h.assert_nil(http.normalize_path("/a\0b"))
        h.assert_nil(http.normalize_path("/a\\b"))
        h.assert_nil(http.normalize_path("a/b"))
        h.assert_nil(http.normalize_path(""))
        h.assert_nil(http.normalize_path(string.rep("/a", 6000)))
    end)
end)

h.describe("http.parse_request_target", function()
    h.it("parses origin form", function()
        local t = http.parse_request_target("/a/b?x=1", "GET")
        h.assert_eq(t.form, "origin")
        h.assert_eq(t.path, "/a/b")
        h.assert_eq(t.query, "x=1")
    end)

    h.it("parses absolute form used by forward proxies", function()
        local t = http.parse_request_target("http://example.com/a?b=1", "GET")
        h.assert_eq(t.form, "absolute")
        h.assert_eq(t.scheme, "http")
        h.assert_eq(t.authority, "example.com")
        h.assert_eq(t.path, "/a")
        h.assert_eq(t.query, "b=1")

        t = http.parse_request_target("http://example.com", "GET")
        h.assert_eq(t.path, "/")

        t = http.parse_request_target("HTTP://Example.com/x", "GET")
        h.assert_eq(t.scheme, "http")
    end)

    h.it("parses authority form only for CONNECT", function()
        local t = http.parse_request_target("example.com:443", "CONNECT")
        h.assert_eq(t.form, "authority")
        h.assert_eq(t.authority, "example.com:443")

        h.assert_nil(http.parse_request_target("example.com:443", "GET"))
    end)

    h.it("parses asterisk form only for OPTIONS", function()
        h.assert_eq(http.parse_request_target("*", "OPTIONS").form, "asterisk")
        h.assert_nil(http.parse_request_target("*", "GET"))
    end)

    h.it("rejects non-http schemes and malformed targets", function()
        h.assert_nil(http.parse_request_target("https://example.com/", "GET"))
        h.assert_nil(http.parse_request_target("file:///etc/passwd", "GET"))
        h.assert_nil(http.parse_request_target("gopher://example.com/", "GET"))
        h.assert_nil(http.parse_request_target("http:///path", "GET"))
        h.assert_nil(http.parse_request_target("http://example.com/a#frag", "GET"))
        h.assert_nil(http.parse_request_target("http://example.com/a\r\nX: 1", "GET"))
        h.assert_nil(http.parse_request_target("", "GET"))
    end)
end)

h.describe("http.parse_request_head basics", function()
    h.it("parses a well formed proxy request", function()
        local req = http.parse_request_head(head(
            "GET http://example.com/a HTTP/1.1",
            "Host: example.com",
            "User-Agent: curl/8.0"))
        h.assert_true(req)
        h.assert_eq(req.method, "GET")
        h.assert_eq(req.version, "HTTP/1.1")
        h.assert_eq(req.parsed_target.authority, "example.com")
        h.assert_eq(req.headers:get("host"), "example.com")
        h.assert_eq(req.headers:get("HOST"), "example.com")
        h.assert_eq(req.headers:count("user-agent"), 1)
    end)

    h.it("parses CONNECT requests", function()
        local req = http.parse_request_head(head(
            "CONNECT example.com:443 HTTP/1.1",
            "Host: example.com:443"))
        h.assert_eq(req.method, "CONNECT")
        h.assert_eq(req.parsed_target.form, "authority")
    end)

    h.it("allows HTTP/1.0 without Host", function()
        local req = http.parse_request_head(head("GET http://example.com/ HTTP/1.0"))
        h.assert_eq(req.version, "HTTP/1.0")
    end)
end)

h.describe("http request smuggling defences", function()
    local function must_reject(raw, why)
        local req, err = http.parse_request_head(raw)
        h.assert_nil(req, (why or "input") .. " must be rejected")
        h.assert_true(err, "an error reason must be given")
    end

    h.it("rejects bare LF line endings", function()
        must_reject("GET http://example.com/ HTTP/1.1\nHost: example.com\r\n\r\n",
            "bare LF in request line")
        must_reject("GET http://example.com/ HTTP/1.1\r\nHost: example.com\n\r\n\r\n",
            "bare LF in header")
    end)

    h.it("rejects obsolete line folding", function()
        must_reject("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
            .. " continued\r\n\r\n", "obs-fold")
        must_reject("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
            .. "\tcontinued\r\n\r\n", "tab fold")
    end)

    h.it("rejects both Content-Length and Transfer-Encoding", function()
        local req = http.parse_request_head(head(
            "POST http://example.com/ HTTP/1.1",
            "Host: example.com",
            "Content-Length: 5",
            "Transfer-Encoding: chunked"))
        h.assert_true(req)
        local f, err = http.request_framing(req)
        h.assert_nil(f)
        h.assert_match(err, "both")
    end)

    h.it("rejects conflicting duplicate Content-Length", function()
        local req = http.parse_request_head(head(
            "POST http://example.com/ HTTP/1.1",
            "Host: example.com",
            "Content-Length: 5",
            "Content-Length: 6"))
        local f, err = http.request_framing(req)
        h.assert_nil(f)
        h.assert_match(err, "conflicting")

        req = http.parse_request_head(head(
            "POST http://example.com/ HTTP/1.1",
            "Host: example.com",
            "Content-Length: 5, 6"))
        f, err = http.request_framing(req)
        h.assert_nil(f)
        h.assert_match(err, "conflicting")
    end)

    h.it("accepts identical duplicate Content-Length", function()
        local req = http.parse_request_head(head(
            "POST http://example.com/ HTTP/1.1",
            "Host: example.com",
            "Content-Length: 5, 5"))
        local f = http.request_framing(req)
        h.assert_eq(f.mode, "length")
        h.assert_eq(f.length, 5)
    end)

    h.it("rejects malformed Content-Length values", function()
        for _, v in ipairs({ "+5", "0x5", "5.0", "-5", "", "five", "05",
                             "99999999999999999999" }) do
            local req = http.parse_request_head(head(
                "POST http://example.com/ HTTP/1.1",
                "Host: example.com",
                "Content-Length: " .. v))
            local f = req and http.request_framing(req)
            h.assert_nil(f, "Content-Length: " .. v .. " must be rejected")
        end
    end)

    h.it("rejects non-chunked and multiple Transfer-Encoding", function()
        for _, v in ipairs({ "identity", "chunked, identity", "gzip",
                             "chunked ,", "xchunked" }) do
            local req = http.parse_request_head(head(
                "POST http://example.com/ HTTP/1.1",
                "Host: example.com",
                "Transfer-Encoding: " .. v))
            local f = req and http.request_framing(req)
            h.assert_nil(f, "Transfer-Encoding: " .. v .. " must be rejected")
        end

        local req = http.parse_request_head(head(
            "POST http://example.com/ HTTP/1.1",
            "Host: example.com",
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: chunked"))
        local f, err = http.request_framing(req)
        h.assert_nil(f)
        h.assert_match(err, "multiple")
    end)

    h.it("rejects whitespace tricks around header names", function()
        must_reject(head("GET http://example.com/ HTTP/1.1",
            "Host: example.com", "Content-Length : 5"), "space before colon")
        must_reject(head("GET http://example.com/ HTTP/1.1",
            "Host: example.com", "Content\tLength: 5"), "tab in name")
        must_reject(head("GET http://example.com/ HTTP/1.1",
            "Host: example.com", ": novalue"), "empty name")
        must_reject(head("GET http://example.com/ HTTP/1.1",
            "Host: example.com", "X-Bad\x00: 1"), "null in name")
    end)

    h.it("rejects malformed request lines", function()
        must_reject(head("GET  http://example.com/ HTTP/1.1", "Host: example.com"),
            "double space")
        must_reject(head(" GET http://example.com/ HTTP/1.1", "Host: example.com"),
            "leading space")
        must_reject(head("GET http://example.com/ HTTP/1.1 extra", "Host: example.com"),
            "trailing token")
        must_reject(head("GET http://example.com/", "Host: example.com"),
            "missing version")
        must_reject(head("get http://example.com/ HTTP/1.1", "Host: example.com"),
            "lowercase method")
        must_reject(head("TRACK http://example.com/ HTTP/1.1", "Host: example.com"),
            "unknown method")
        must_reject(head("GET http://example.com/ HTTP/0.9", "Host: example.com"),
            "old version")
        must_reject(head("GET http://example.com/ HTTP/2.0", "Host: example.com"),
            "http2 version")
        must_reject(head("GET http://example.com/ http/1.1", "Host: example.com"),
            "lowercase version")
    end)

    h.it("rejects duplicate or missing Host on HTTP/1.1", function()
        must_reject(head("GET http://example.com/ HTTP/1.1",
            "Host: example.com", "Host: evil.com"), "duplicate host")
        must_reject(head("GET http://example.com/ HTTP/1.1"), "missing host")
    end)

    h.it("rejects oversized heads", function()
        local many = { "GET http://example.com/ HTTP/1.1", "Host: example.com" }
        for i = 1, 200 do
            many[#many + 1] = "X-Pad-" .. i .. ": v"
        end
        must_reject(head(table.unpack and table.unpack(many) or unpack(many)),
            "too many headers")

        must_reject(head("GET http://example.com/ HTTP/1.1", "Host: example.com",
            "X-Big: " .. string.rep("a", 9000)), "oversized header line")
    end)

    h.it("rejects heads that are not CRLF terminated", function()
        h.assert_nil(http.parse_request_head("GET http://example.com/ HTTP/1.1\r\n"))
        h.assert_nil(http.parse_request_head(""))
    end)
end)

h.describe("http.response_framing", function()
    local function res(...)
        return http.parse_response_head(table.concat({ ... }, "\r\n") .. "\r\n\r\n")
    end

    h.it("parses status lines", function()
        local r = res("HTTP/1.1 200 OK", "Content-Length: 3")
        h.assert_eq(r.status, 200)
        h.assert_eq(r.reason, "OK")
        h.assert_eq(http.response_framing(r, "GET").mode, "length")
        h.assert_eq(http.response_framing(r, "GET").length, 3)
    end)

    h.it("treats bodyless responses correctly", function()
        h.assert_eq(http.response_framing(res("HTTP/1.1 204 No Content"), "GET").mode,
            "none")
        h.assert_eq(http.response_framing(res("HTTP/1.1 304 Not Modified"), "GET").mode,
            "none")
        h.assert_eq(http.response_framing(res("HTTP/1.1 100 Continue"), "GET").mode,
            "none")
        h.assert_eq(http.response_framing(res("HTTP/1.1 200 OK",
            "Content-Length: 42"), "HEAD").mode, "none")
    end)

    h.it("detects chunked and close-delimited bodies", function()
        h.assert_eq(http.response_framing(res("HTTP/1.1 200 OK",
            "Transfer-Encoding: chunked"), "GET").mode, "chunked")
        h.assert_eq(http.response_framing(res("HTTP/1.1 200 OK"), "GET").mode,
            "until_close")
    end)

    h.it("rejects malformed status lines", function()
        h.assert_nil(res("HTTP/1.1 20 OK"))
        h.assert_nil(res("HTTP/1.1 999999 OK"))
        h.assert_nil(res("HTTP/1.1 OK"))
        h.assert_nil(res("ICY 200 OK"))
        h.assert_nil(res("HTTP/1.1 099 X"))
    end)

    h.it("refuses smuggling in responses too", function()
        local r = res("HTTP/1.1 200 OK", "Content-Length: 5", "Transfer-Encoding: chunked")
        local f, err = http.response_framing(r, "GET")
        h.assert_nil(f)
        h.assert_match(err, "both")
    end)
end)

h.describe("http connection handling", function()
    local function req(...)
        return http.parse_request_head(table.concat({ ... }, "\r\n") .. "\r\n\r\n")
    end

    h.it("detects close tokens", function()
        local r = req("GET http://e.com/ HTTP/1.1", "Host: e.com", "Connection: close")
        h.assert_true(http.wants_close(r.headers, r.version))

        r = req("GET http://e.com/ HTTP/1.1", "Host: e.com", "Connection: Keep-Alive")
        h.assert_false(http.wants_close(r.headers, r.version))

        r = req("GET http://e.com/ HTTP/1.0", "Host: e.com")
        h.assert_true(http.wants_close(r.headers, r.version))

        r = req("GET http://e.com/ HTTP/1.0", "Host: e.com", "Connection: keep-alive")
        h.assert_false(http.wants_close(r.headers, r.version))
    end)

    h.it("honours the legacy Proxy-Connection header", function()
        local r = req("GET http://e.com/ HTTP/1.1", "Host: e.com",
            "Proxy-Connection: close")
        h.assert_true(http.wants_close(r.headers, r.version))
    end)
end)

h.describe("http.serialize_head", function()
    h.it("drops hop-by-hop headers and credentials", function()
        local r = http.parse_request_head(head(
            "GET http://example.com/a HTTP/1.1",
            "Host: example.com",
            "Proxy-Authorization: Bearer secret-token-value",
            "Connection: keep-alive",
            "Proxy-Connection: keep-alive",
            "Transfer-Encoding: chunked",
            "Upgrade: websocket",
            "X-Keep: yes"))
        local out = http.serialize_head("GET /a HTTP/1.1", r.headers, nil,
            { "Connection: keep-alive" })
        h.assert_match(out, "^GET /a HTTP/1%.1\r\n")
        h.assert_match(out, "X%-Keep: yes")
        h.assert_match(out, "Host: example%.com")
        h.assert_false(string.find(out, "secret%-token%-value"))
        h.assert_false(string.find(out, "Upgrade"))
        h.assert_false(string.find(out, "Transfer%-Encoding"))
        h.assert_false(string.find(out, "Proxy%-Connection"))
        h.assert_match(out, "\r\n\r\n$")
    end)

    h.it("honours the explicit drop set", function()
        local r = http.parse_request_head(head(
            "GET http://example.com/a HTTP/1.1",
            "Host: example.com",
            "Cookie: a=b"))
        local out = http.serialize_head("GET /a HTTP/1.1", r.headers,
            { Cookie = true }, nil)
        h.assert_false(string.find(out, "Cookie"))
    end)

    h.it("never forwards an identity header the workload supplied", function()
        local r = http.parse_request_head(head(
            "GET http://example.com/a HTTP/1.1",
            "Host: example.com",
            "X-Ro-Identity: forged-identity",
            "X-Ro-Namespace: kube-system",
            "X-Ro-Profile: unrestricted",
            "X-Ro-Service-Account: cluster-admin",
            "X-Ro-Pod: someone-elses-pod",
            "x-ro-anything-else: smuggled",
            "X-Rocket: this one is not ours"))
        local out = http.serialize_head("GET /a HTTP/1.1", r.headers, nil, nil)
        h.assert_false(string.find(out, "forged%-identity"),
            "a forged identity must not reach the destination")
        h.assert_false(string.find(out, "kube%-system"))
        h.assert_false(string.find(out, "unrestricted"))
        h.assert_false(string.find(out, "cluster%-admin"))
        h.assert_false(string.find(out, "someone%-elses%-pod"))
        h.assert_false(string.find(out, "smuggled"))
        h.assert_match(out, "X%-Rocket: this one is not ours")
    end)

    h.it("still emits the identity the gateway itself asserts", function()
        local r = http.parse_request_head(head(
            "GET http://example.com/a HTTP/1.1",
            "Host: example.com",
            "X-Ro-Profile: forged"))
        local out = http.serialize_head("GET /a HTTP/1.1", r.headers, nil,
            { "X-Ro-Profile: untrusted-python" })
        h.assert_false(string.find(out, "forged"))
        h.assert_match(out, "X%-Ro%-Profile: untrusted%-python")
    end)
end)

h.describe("http.parse_chunk_size", function()
    h.it("parses valid chunk headers", function()
        h.assert_eq(http.parse_chunk_size("5"), 5)
        h.assert_eq(http.parse_chunk_size("a"), 10)
        h.assert_eq(http.parse_chunk_size("A"), 10)
        h.assert_eq(http.parse_chunk_size("0"), 0)
        h.assert_eq(http.parse_chunk_size("5;name=value"), 5)
    end)

    h.it("rejects malformed or oversized chunk headers", function()
        h.assert_nil(http.parse_chunk_size(""))
        h.assert_nil(http.parse_chunk_size("-1"))
        h.assert_nil(http.parse_chunk_size("0x5"))
        h.assert_nil(http.parse_chunk_size("zz"))
        h.assert_nil(http.parse_chunk_size("ffffffff"))
        h.assert_nil(http.parse_chunk_size("123456789"))
        h.assert_nil(http.parse_chunk_size("5\0"))
        h.assert_nil(http.parse_chunk_size(string.rep("a", 300)))
    end)
end)

h.describe("an empty Content-Length header is ambiguous framing", function()
    h.it("refuses an empty header standing alone", function()
        local n, err = http.parse_content_length({ "" })
        h.assert_nil(n)
        h.assert_true(err ~= nil)
    end)

    h.it("refuses an empty header beside a valued one", function()
        local n, err = http.parse_content_length({ "", "44" })
        h.assert_nil(n)
        h.assert_eq(err, "malformed content-length")
    end)

    h.it("refuses them in the other order too", function()
        local n, err = http.parse_content_length({ "44", "" })
        h.assert_nil(n)
        h.assert_eq(err, "malformed content-length")
    end)

    h.it("still accepts an ordinary length", function()
        h.assert_eq(http.parse_content_length({ "44" }), 44)
    end)

    h.it("still refuses conflicting values", function()
        local n = http.parse_content_length({ "5", "6" })
        h.assert_nil(n)
    end)
end)
