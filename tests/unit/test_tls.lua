local h = require("harness")
local tls = require("ro.tls")

local function u16(n)
    return string.char(math.floor(n / 256) % 256, n % 256)
end

local function build_client_hello(opts)
    opts = opts or {}
    local exts = {}

    if opts.sni then
        local name = opts.sni
        local entry = string.char(0) .. u16(#name) .. name
        local list = u16(#entry) .. entry
        exts[#exts + 1] = u16(0x0000) .. u16(#list) .. list
    end
    if opts.alpn then
        local protos = {}
        for _, p in ipairs(opts.alpn) do
            protos[#protos + 1] = string.char(#p) .. p
        end
        local body = table.concat(protos)
        local list = u16(#body) .. body
        exts[#exts + 1] = u16(0x0010) .. u16(#list) .. list
    end
    if opts.supported_versions then
        local vs = {}
        for _, v in ipairs(opts.supported_versions) do
            vs[#vs + 1] = u16(v)
        end
        local body = table.concat(vs)
        local list = string.char(#body) .. body
        exts[#exts + 1] = u16(0x002b) .. u16(#list) .. list
    end

    local ext_body = table.concat(exts)
    local ext_block = u16(#ext_body) .. ext_body

    local body = u16(opts.legacy_version or 0x0303)
        .. string.rep("\0", 32)
        .. string.char(0)
        .. u16(2) .. u16(0x1301)
        .. string.char(1) .. string.char(0)
        .. ext_block

    local handshake = string.char(0x01)
        .. string.char(math.floor(#body / 65536) % 256,
                       math.floor(#body / 256) % 256, #body % 256)
        .. body

    return string.char(0x16) .. u16(0x0301) .. u16(#handshake) .. handshake
end

h.describe("tls.looks_like_client_hello", function()
    h.it("recognises a handshake record", function()
        h.assert_true(tls.looks_like_client_hello(build_client_hello()))
    end)

    h.it("rejects plaintext and other payloads", function()
        h.assert_false(tls.looks_like_client_hello("GET / HTTP/1.1\r\n\r\n"))
        h.assert_false(tls.looks_like_client_hello("SSH-2.0-OpenSSH_9.0\r\n"))
        h.assert_false(tls.looks_like_client_hello(""))
        h.assert_false(tls.looks_like_client_hello("\22\3\1"))
        h.assert_false(tls.looks_like_client_hello("\23\3\3\0\16abcdef"))
    end)
end)

h.describe("tls.parse_client_hello", function()
    h.it("extracts the SNI", function()
        local hello = tls.parse_client_hello(
            build_client_hello({ sni = "pypi.org" }))
        h.assert_eq(hello.sni, "pypi.org")
    end)

    h.it("lowercases the SNI", function()
        local hello = tls.parse_client_hello(
            build_client_hello({ sni = "PyPI.ORG" }))
        h.assert_eq(hello.sni, "pypi.org")
    end)

    h.it("extracts ALPN protocols", function()
        local hello = tls.parse_client_hello(build_client_hello({
            sni = "a.example.com", alpn = { "h2", "http/1.1" },
        }))
        h.assert_deep_eq(hello.alpn, { "h2", "http/1.1" })
    end)

    h.it("prefers supported_versions over the legacy version", function()
        local hello = tls.parse_client_hello(build_client_hello({
            sni = "a.example.com",
            legacy_version = 0x0303,
            supported_versions = { 0x0304, 0x0303 },
        }))
        h.assert_eq(hello.version_name, "1.3")

        hello = tls.parse_client_hello(build_client_hello({
            legacy_version = 0x0301,
        }))
        h.assert_eq(hello.version_name, "1.0")

        hello = tls.parse_client_hello(build_client_hello({
            legacy_version = 0x0303,
        }))
        h.assert_eq(hello.version_name, "1.2")
    end)

    h.it("handles a hello with no extensions", function()
        local hello = tls.parse_client_hello(build_client_hello({}))
        h.assert_true(hello)
        h.assert_nil(hello.sni)
    end)

    h.it("refuses non-handshake and truncated data", function()
        h.assert_nil(tls.parse_client_hello("GET / HTTP/1.1\r\n\r\n"))
        h.assert_nil(tls.parse_client_hello(""))
        h.assert_nil(tls.parse_client_hello("\22\3\1\0\5\2\0\0\1\0"))
    end)

    h.it("never raises on truncated input", function()
        local hello = build_client_hello({ sni = "a.example.com" })
        for cut = 1, #hello - 1 do
            local ok = pcall(tls.parse_client_hello, hello:sub(1, cut))
            h.assert_true(ok, "truncation at " .. cut .. " must not raise")
        end
    end)

    h.it("never raises on random byte corruption", function()
        local base = build_client_hello({
            sni = "a.example.com", supported_versions = { 0x0304 },
            alpn = { "h2" },
        })
        math.randomseed(20260824)
        for _ = 1, 400 do
            local pos = math.random(1, #base)
            local corrupted = base:sub(1, pos - 1)
                .. string.char(math.random(0, 255)) .. base:sub(pos + 1)
            local ok = pcall(tls.parse_client_hello, corrupted)
            h.assert_true(ok, "corruption at " .. pos .. " must not raise")
        end
    end)

    h.it("does not read an SNI out of a hostile length field", function()
        local evil = "\22\3\1\0\30\1\0\0\26\3\3" .. string.rep("\0", 32)
        local ok, res = pcall(tls.parse_client_hello, evil)
        h.assert_true(ok)
        if res then
            h.assert_nil(res.sni)
        end
    end)
end)

h.describe("tls.version_at_least", function()
    h.it("orders TLS versions correctly", function()
        h.assert_true(tls.version_at_least("1.3", "1.2"))
        h.assert_true(tls.version_at_least("1.2", "1.2"))
        h.assert_false(tls.version_at_least("1.1", "1.2"))
        h.assert_false(tls.version_at_least("1.0", "1.2"))
        h.assert_false(tls.version_at_least("ssl3.0", "1.0"))
        h.assert_false(tls.version_at_least("unknown", "1.2"))
        h.assert_false(tls.version_at_least("1.2", "unknown"))
    end)
end)

h.describe("a ClientHello split across reads is not mistaken for plaintext", function()
    h.it("reports undecided for a prefix too short to judge", function()
        local full = build_client_hello({ sni = "evil.example.com" })
        for _, n in ipairs({ 1, 2, 3, 5 }) do
            local is_hello, undecided = tls.looks_like_client_hello(full:sub(1, n))
            h.assert_false(is_hello)
            h.assert_true(undecided)
        end
    end)

    h.it("reports a decided verdict for traffic that is not TLS", function()
        for _, s in ipairs({ "GET / HTTP/1.1\r\n\r\n", "SSH-2.0-OpenSSH_9.0\r\n" }) do
            local is_hello, undecided = tls.looks_like_client_hello(s)
            h.assert_false(is_hello)
            h.assert_false(undecided)
        end
    end)

    h.it("recognises the hello once enough of it has arrived", function()
        local full = build_client_hello({ sni = "evil.example.com" })
        local is_hello, undecided = tls.looks_like_client_hello(full)
        h.assert_true(is_hello)
        h.assert_false(undecided)
        local parsed = tls.parse_client_hello(full)
        h.assert_eq(parsed.sni, "evil.example.com")
        h.assert_false(parsed.truncated)
    end)

    h.it("marks an incomplete hello as truncated rather than complete", function()
        local full = build_client_hello({ sni = "evil.example.com" })
        local parsed = tls.parse_client_hello(full:sub(1, #full - 8))
        if parsed then
            h.assert_true(parsed.truncated)
        end
    end)
end)

h.describe("the TLS floor is judged on the lowest version offered", function()
    h.it("refuses a hello that hides TLS 1.0 behind supported_versions", function()
        local parsed = tls.parse_client_hello(build_client_hello({
            legacy_version = 0x0301, supported_versions = { 0x0304 },
        }))
        h.assert_eq(parsed.min_version_name, "1.0")
        h.assert_false(tls.version_at_least(parsed.min_version_name, "1.2"))
    end)

    h.it("does not penalise a real TLS 1.3 client for its legacy field", function()
        local parsed = tls.parse_client_hello(build_client_hello({
            legacy_version = 0x0303, supported_versions = { 0x0304 },
        }))
        h.assert_eq(parsed.min_version_name, "1.3")
        h.assert_true(tls.version_at_least(parsed.min_version_name, "1.3"))
    end)

    h.it("judges a plain TLS 1.2 client at 1.2", function()
        local parsed = tls.parse_client_hello(build_client_hello({
            legacy_version = 0x0303,
        }))
        h.assert_eq(parsed.min_version_name, "1.2")
        h.assert_true(tls.version_at_least(parsed.min_version_name, "1.2"))
    end)
end)

h.describe("duplicate ClientHello extensions", function()
    h.it("refuses a hello carrying two server_name extensions", function()
        local name = "evil.example.com"
        local decoy = "allowed.example.com"
        local function sni_ext(n)
            local entry = string.char(0) .. u16(#n) .. n
            local list = u16(#entry) .. entry
            return u16(0x0000) .. u16(#list) .. list
        end
        local exts = sni_ext(name) .. sni_ext(decoy)
        local ext_block = u16(#exts) .. exts
        local body = u16(0x0303) .. string.rep("\0", 32) .. string.char(0)
            .. u16(2) .. u16(0x1301) .. string.char(1) .. string.char(0) .. ext_block
        local hs = string.char(0x01)
            .. string.char(math.floor(#body / 65536) % 256,
                           math.floor(#body / 256) % 256, #body % 256) .. body
        local raw = string.char(0x16) .. u16(0x0301) .. u16(#hs) .. hs
        local parsed, err = tls.parse_client_hello(raw)
        h.assert_nil(parsed)
        h.assert_eq(err, "duplicate ClientHello extension")
    end)
end)
