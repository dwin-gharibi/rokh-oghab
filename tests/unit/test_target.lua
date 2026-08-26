local h = require("harness")
local target = require("ro.target")

h.describe("target.normalize_hostname", function()
    h.it("lowercases and strips one trailing dot", function()
        h.assert_eq(target.normalize_hostname("EXAMPLE.COM"), "example.com")
        h.assert_eq(target.normalize_hostname("example.com."), "example.com")
        h.assert_eq(target.normalize_hostname("Files.PythonHosted.org"),
            "files.pythonhosted.org")
    end)

    h.it("accepts valid label characters", function()
        h.assert_eq(target.normalize_hostname("a-b.c-d.example.com"),
            "a-b.c-d.example.com")
        h.assert_eq(target.normalize_hostname("registry-1.docker.io"),
            "registry-1.docker.io")
        h.assert_eq(target.normalize_hostname("localhost"), "localhost")
    end)

    h.it("rejects structurally invalid hostnames", function()
        h.assert_nil(target.normalize_hostname("-leading.com"))
        h.assert_nil(target.normalize_hostname("trailing-.com"))
        h.assert_nil(target.normalize_hostname("double..dot.com"))
        h.assert_nil(target.normalize_hostname(".leading.dot"))
        h.assert_nil(target.normalize_hostname(""))
        h.assert_nil(target.normalize_hostname("example.com.."))
        h.assert_nil(target.normalize_hostname(string.rep("a", 64) .. ".com"))
        h.assert_nil(target.normalize_hostname(string.rep("a.", 200) .. "com"))
    end)

    h.it("rejects illegal and non-ascii characters", function()
        h.assert_nil(target.normalize_hostname("exa mple.com"))
        h.assert_nil(target.normalize_hostname("exa\tmple.com"))
        h.assert_nil(target.normalize_hostname("exa\0mple.com"))
        h.assert_nil(target.normalize_hostname("exa\nmple.com"))
        h.assert_nil(target.normalize_hostname("ex\xc3\xa4mple.com"))
        h.assert_nil(target.normalize_hostname("example.com/path"))
        h.assert_nil(target.normalize_hostname("example.com:443"))
        h.assert_nil(target.normalize_hostname("exa%6dple.com"))
    end)
end)

h.describe("target.classify_host", function()
    h.it("classifies plain hostnames", function()
        local info = target.classify_host("pypi.org")
        h.assert_eq(info.kind, "hostname")
        h.assert_eq(info.canonical, "pypi.org")
        h.assert_false(info.literal)
        h.assert_false(info.obfuscated)
    end)

    h.it("classifies canonical ipv4 literals", function()
        local info = target.classify_host("93.184.216.34")
        h.assert_eq(info.kind, "ipv4")
        h.assert_eq(info.canonical, "93.184.216.34")
        h.assert_true(info.literal)
        h.assert_false(info.obfuscated)
    end)

    h.it("flags obfuscated ipv4 literals as addresses, not hostnames", function()
        local cases = {
            { "2130706433", "127.0.0.1" },
            { "0x7f000001", "127.0.0.1" },
            { "017700000001", "127.0.0.1" },
            { "127.1", "127.0.0.1" },
            { "0177.0.0.1", "127.0.0.1" },
            { "2852039166", "169.254.169.254" },
            { "0xa9fea9fe", "169.254.169.254" },
            { "169.254.43518", "169.254.169.254" },
        }
        for _, c in ipairs(cases) do
            local info = target.classify_host(c[1])
            h.assert_eq(info.kind, "ipv4", c[1] .. " should be ipv4")
            h.assert_eq(info.canonical, c[2], c[1] .. " canonical")
            h.assert_true(info.obfuscated, c[1] .. " should be flagged obfuscated")
        end
    end)

    h.it("classifies bracketed ipv6 literals", function()
        local info = target.classify_host("[::1]")
        h.assert_eq(info.kind, "ipv6")
        h.assert_eq(info.canonical, "::1")
        h.assert_false(info.obfuscated)

        info = target.classify_host("[2001:db8::1]")
        h.assert_eq(info.canonical, "2001:db8::1")
    end)

    h.it("flags bare ipv6 literals as obfuscated", function()
        local info = target.classify_host("::1")
        h.assert_eq(info.kind, "ipv6")
        h.assert_true(info.obfuscated)
    end)

    h.it("rejects control characters and malformed hosts", function()
        h.assert_nil(target.classify_host(""))
        h.assert_nil(target.classify_host("host\r\nX: 1"))
        h.assert_nil(target.classify_host("ho st"))
        h.assert_nil(target.classify_host("[::1"))
        h.assert_nil(target.classify_host("[not-ipv6]"))
        h.assert_nil(target.classify_host("a:b:c"))
    end)
end)

h.describe("target.parse_authority", function()
    h.it("splits host and port", function()
        local info, port = target.parse_authority("pypi.org:443")
        h.assert_eq(info.canonical, "pypi.org")
        h.assert_eq(port, 443)
    end)

    h.it("applies the default port when absent", function()
        local info, port = target.parse_authority("pypi.org", 80)
        h.assert_eq(info.canonical, "pypi.org")
        h.assert_eq(port, 80)
    end)

    h.it("handles bracketed ipv6 authorities", function()
        local info, port = target.parse_authority("[2001:db8::1]:8443")
        h.assert_eq(info.kind, "ipv6")
        h.assert_eq(info.canonical, "2001:db8::1")
        h.assert_eq(port, 8443)

        info, port = target.parse_authority("[::1]", 443)
        h.assert_eq(info.canonical, "::1")
        h.assert_eq(port, 443)
    end)

    h.it("rejects userinfo smuggling", function()
        local info, _, err = target.parse_authority("pypi.org@evil.com:443")
        h.assert_nil(info)
        h.assert_match(err, "userinfo")
    end)

    h.it("rejects path and control characters", function()
        h.assert_nil(target.parse_authority("pypi.org:443/x"))
        h.assert_nil(target.parse_authority("pypi.org:443\\x"))
        h.assert_nil(target.parse_authority("pypi.org:443#f"))
        h.assert_nil(target.parse_authority("pypi.org:443?a=b"))
        h.assert_nil(target.parse_authority("pypi.org:443\r\nHost: evil"))
        h.assert_nil(target.parse_authority(" pypi.org:443"))
    end)

    h.it("rejects malformed ports", function()
        h.assert_nil(target.parse_authority("pypi.org:0"))
        h.assert_nil(target.parse_authority("pypi.org:65536"))
        h.assert_nil(target.parse_authority("pypi.org:080"))
        h.assert_nil(target.parse_authority("pypi.org:44a"))
        h.assert_nil(target.parse_authority("pypi.org:"))
        h.assert_nil(target.parse_authority("pypi.org:-1"))
        h.assert_nil(target.parse_authority("pypi.org:443:443"))
    end)

    h.it("requires a port when no default is given", function()
        local info, _, err = target.parse_authority("pypi.org")
        h.assert_nil(info)
        h.assert_match(err, "port")
    end)
end)

h.describe("target.parse_port", function()
    h.it("accepts valid ports", function()
        h.assert_eq(target.parse_port("1"), 1)
        h.assert_eq(target.parse_port("443"), 443)
        h.assert_eq(target.parse_port("65535"), 65535)
    end)

    h.it("rejects invalid ports", function()
        h.assert_nil(target.parse_port("0"))
        h.assert_nil(target.parse_port("65536"))
        h.assert_nil(target.parse_port("00443"))
        h.assert_nil(target.parse_port("443 "))
        h.assert_nil(target.parse_port(""))
        h.assert_nil(target.parse_port("+443"))
    end)
end)
