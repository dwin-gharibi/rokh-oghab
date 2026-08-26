local h = require("harness")
local httpc = require("ro.httpc")
local reader = require("ro.reader")

local function body_of(text, framing, max_body)
    return httpc.read_body(reader.from_string(text, 4096), framing, max_body)
end

h.describe("the control-plane client bounds every response it will read",
function()
    h.it("reads a declared body", function()
        local out = body_of("hello", { mode = "length", length = 5 })
        h.assert_eq(out, "hello")
    end)

    h.it("refuses a declared body larger than the ceiling", function()
        local out, err = body_of("x", { mode = "length", length = 99999999 }, 1024)
        h.assert_nil(out)
        h.assert_match(err, "too large")
    end)

    h.it("reads a chunked body", function()
        local out = body_of("5\r\nhello\r\n0\r\n\r\n", { mode = "chunked" })
        h.assert_eq(out, "hello")
    end)

    h.it("refuses a chunked body that exceeds the ceiling", function()
        local parts = {}
        for _ = 1, 40 do
            parts[#parts + 1] = "64\r\n" .. string.rep("a", 100) .. "\r\n"
        end
        parts[#parts + 1] = "0\r\n\r\n"
        local out, err = body_of(table.concat(parts), { mode = "chunked" }, 1024)
        h.assert_nil(out, "a chunked flood must be refused, not accumulated")
        h.assert_match(err, "too large")
    end)

    h.it("refuses a chunk header that does not parse", function()
        local out, err = body_of("zz\r\nhello\r\n0\r\n\r\n", { mode = "chunked" })
        h.assert_nil(out)
        h.assert_match(err, "chunk")
    end)

    h.it("reads a body that ends when the connection closes", function()
        local out = body_of("streamed", { mode = "until_close" })
        h.assert_eq(out, "streamed")
    end)

    h.it("refuses an unbounded stream that exceeds the ceiling", function()
        local out, err = body_of(string.rep("a", 40000),
            { mode = "until_close" }, 1024)
        h.assert_nil(out,
            "a controller streaming without a length must not be able to fill "
            .. "the gateway's memory")
        h.assert_match(err, "too large")
    end)

    h.it("applies the same ceiling to every framing", function()
        for _, framing in ipairs({
            { mode = "length", length = 40000 },
            { mode = "until_close" },
        }) do
            local out = body_of(string.rep("a", 40000), framing, 1024)
            h.assert_nil(out, framing.mode .. " must respect the ceiling")
        end
    end)

    h.it("returns nothing for a response that carries no body", function()
        h.assert_eq(body_of("", { mode = "none" }), "")
    end)

    h.it("refuses a framing it does not recognise", function()
        local out, err = body_of("x", { mode = "invented" })
        h.assert_nil(out)
        h.assert_match(err, "framing")
    end)
end)

h.describe("the control-plane client only speaks to a control plane", function()
    h.it("parses an ordinary controller url", function()
        local parts = httpc.parse_url("http://ro-controller:8081/v1/bundle")
        h.assert_eq(parts.host, "ro-controller")
        h.assert_eq(parts.port, 8081)
        h.assert_eq(parts.path, "/v1/bundle")
    end)

    h.it("defaults the port and the path", function()
        local parts = httpc.parse_url("http://ro-controller")
        h.assert_eq(parts.port, 80)
        h.assert_eq(parts.path, "/")
    end)

    h.it("parses a bracketed IPv6 authority", function()
        local parts = httpc.parse_url("http://[fd00::1]:8081/v1/bundle")
        h.assert_eq(parts.host, "fd00::1")
        h.assert_eq(parts.port, 8081)
    end)

    h.it("refuses anything that is not http", function()
        for _, url in ipairs({ "https://x/", "file:///etc/passwd",
                               "gopher://x/", "//x/", "x", "" }) do
            h.assert_nil(httpc.parse_url(url), url .. " must be refused")
        end
    end)

    h.it("refuses a url with no host", function()
        h.assert_nil(httpc.parse_url("http:///v1/bundle"))
    end)
end)
