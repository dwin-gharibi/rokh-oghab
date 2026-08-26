local h = require("harness")
local ip = require("ro.ipaddr")

local LOCALHOST = 2130706433
local METADATA = 2852039166

h.describe("ipaddr.parse_ipv4 (strict dotted quad)", function()
    h.it("accepts canonical addresses", function()
        h.assert_eq(ip.parse_ipv4("127.0.0.1"), LOCALHOST)
        h.assert_eq(ip.parse_ipv4("0.0.0.0"), 0)
        h.assert_eq(ip.parse_ipv4("255.255.255.255"), 4294967295)
        h.assert_eq(ip.parse_ipv4("1.2.3.4"), 16909060)
        h.assert_eq(ip.parse_ipv4("169.254.169.254"), METADATA)
    end)

    h.it("rejects leading zero octets (octal ambiguity)", function()
        h.assert_nil(ip.parse_ipv4("01.2.3.4"))
        h.assert_nil(ip.parse_ipv4("127.0.0.01"))
        h.assert_nil(ip.parse_ipv4("0177.0.0.1"))
    end)

    h.it("rejects short, long and out-of-range forms", function()
        h.assert_nil(ip.parse_ipv4("1.2.3"))
        h.assert_nil(ip.parse_ipv4("1.2.3.4.5"))
        h.assert_nil(ip.parse_ipv4("256.1.1.1"))
        h.assert_nil(ip.parse_ipv4("1.2.3.256"))
        h.assert_nil(ip.parse_ipv4("999.999.999.999"))
    end)

    h.it("rejects whitespace and hex forms", function()
        h.assert_nil(ip.parse_ipv4(" 1.2.3.4"))
        h.assert_nil(ip.parse_ipv4("1.2.3.4 "))
        h.assert_nil(ip.parse_ipv4("1.2.3.4\n"))
        h.assert_nil(ip.parse_ipv4("0x7f.0.0.1"))
        h.assert_nil(ip.parse_ipv4("127.0.0.1."))
    end)

    h.it("rejects non-string input", function()
        h.assert_nil(ip.parse_ipv4(nil))
        h.assert_nil(ip.parse_ipv4(12345))
        h.assert_nil(ip.parse_ipv4({}))
    end)
end)

h.describe("ipaddr.parse_ipv4_any (obfuscated literal detection)", function()
    h.it("decodes bare decimal integers", function()
        h.assert_eq(ip.parse_ipv4_any("2130706433"), LOCALHOST)
        h.assert_eq(ip.parse_ipv4_any("2852039166"), METADATA)
        h.assert_eq(ip.parse_ipv4_any("0"), 0)
        h.assert_eq(ip.parse_ipv4_any("4294967295"), 4294967295)
    end)

    h.it("decodes hexadecimal forms", function()
        h.assert_eq(ip.parse_ipv4_any("0x7f000001"), LOCALHOST)
        h.assert_eq(ip.parse_ipv4_any("0X7F000001"), LOCALHOST)
        h.assert_eq(ip.parse_ipv4_any("0x7f.0x0.0x0.0x1"), LOCALHOST)
        h.assert_eq(ip.parse_ipv4_any("0xa9fea9fe"), METADATA)
    end)

    h.it("decodes octal forms", function()
        h.assert_eq(ip.parse_ipv4_any("017700000001"), LOCALHOST)
        h.assert_eq(ip.parse_ipv4_any("0177.0.0.1"), LOCALHOST)
        h.assert_eq(ip.parse_ipv4_any("0251.0376.0251.0376"), METADATA)
    end)

    h.it("decodes short dotted forms", function()
        h.assert_eq(ip.parse_ipv4_any("127.1"), LOCALHOST)
        h.assert_eq(ip.parse_ipv4_any("127.0.1"), LOCALHOST)
        h.assert_eq(ip.parse_ipv4_any("169.254.43518"), METADATA)
    end)

    h.it("rejects overflow and malformed input", function()
        h.assert_nil(ip.parse_ipv4_any("4294967296"))
        h.assert_nil(ip.parse_ipv4_any("0x100000000"))
        h.assert_nil(ip.parse_ipv4_any("1.2.3.4.5"))
        h.assert_nil(ip.parse_ipv4_any("256.256.256.256"))
        h.assert_nil(ip.parse_ipv4_any("127.0.0.1."))
        h.assert_nil(ip.parse_ipv4_any("0.0.0.0.0"))
        h.assert_nil(ip.parse_ipv4_any("09"))
        h.assert_nil(ip.parse_ipv4_any("example.com"))
        h.assert_nil(ip.parse_ipv4_any(""))
        h.assert_nil(ip.parse_ipv4_any("0x"))
        h.assert_nil(ip.parse_ipv4_any("-1"))
        h.assert_nil(ip.parse_ipv4_any("1e9"))
    end)
end)

h.describe("ipaddr.parse_ipv6", function()
    h.it("parses compressed and full forms", function()
        h.assert_deep_eq(ip.parse_ipv6("::1"), { 0, 0, 0, 0, 0, 0, 0, 1 })
        h.assert_deep_eq(ip.parse_ipv6("::"), { 0, 0, 0, 0, 0, 0, 0, 0 })
        h.assert_deep_eq(ip.parse_ipv6("1:2:3:4:5:6:7:8"),
            { 1, 2, 3, 4, 5, 6, 7, 8 })
        h.assert_deep_eq(ip.parse_ipv6("2001:db8::1"),
            { 0x2001, 0x0db8, 0, 0, 0, 0, 0, 1 })
        h.assert_deep_eq(ip.parse_ipv6("fe80::1"),
            { 0xfe80, 0, 0, 0, 0, 0, 0, 1 })
        h.assert_deep_eq(ip.parse_ipv6("1:2:3:4:5:6:7::"),
            { 1, 2, 3, 4, 5, 6, 7, 0 })
    end)

    h.it("parses embedded ipv4 suffixes", function()
        h.assert_deep_eq(ip.parse_ipv6("::ffff:127.0.0.1"),
            { 0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001 })
        h.assert_deep_eq(ip.parse_ipv6("0:0:0:0:0:ffff:1.2.3.4"),
            { 0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304 })
        h.assert_deep_eq(ip.parse_ipv6("64:ff9b::169.254.169.254"),
            { 0x0064, 0xff9b, 0, 0, 0, 0, 0xa9fe, 0xa9fe })
    end)

    h.it("rejects malformed addresses", function()
        h.assert_nil(ip.parse_ipv6("1::2::3"))
        h.assert_nil(ip.parse_ipv6(":::"))
        h.assert_nil(ip.parse_ipv6("1:2:3:4:5:6:7:8:9"))
        h.assert_nil(ip.parse_ipv6("12345::"))
        h.assert_nil(ip.parse_ipv6("1:2:3:4:5:6:7:8::"))
        h.assert_nil(ip.parse_ipv6("fe80::1%eth0"))
        h.assert_nil(ip.parse_ipv6("1.2.3.4"))
        h.assert_nil(ip.parse_ipv6("::gg"))
        h.assert_nil(ip.parse_ipv6(":1:2:3:4:5:6:7"))
        h.assert_nil(ip.parse_ipv6("1:2:3:4:5:6:7:"))
        h.assert_nil(ip.parse_ipv6("::1.2.3.4.5"))
        h.assert_nil(ip.parse_ipv6("::1:2.3.4.5:6"))
    end)
end)

h.describe("ipaddr string rendering", function()
    h.it("renders ipv4", function()
        h.assert_eq(ip.ipv4_to_string(LOCALHOST), "127.0.0.1")
        h.assert_eq(ip.ipv4_to_string(0), "0.0.0.0")
        h.assert_eq(ip.ipv4_to_string(4294967295), "255.255.255.255")
        h.assert_eq(ip.ipv4_to_string(METADATA), "169.254.169.254")
    end)

    h.it("renders ipv6 with zero compression", function()
        h.assert_eq(ip.ipv6_to_string({ 0, 0, 0, 0, 0, 0, 0, 1 }), "::1")
        h.assert_eq(ip.ipv6_to_string({ 0, 0, 0, 0, 0, 0, 0, 0 }), "::")
        h.assert_eq(ip.ipv6_to_string({ 0x2001, 0xdb8, 0, 0, 0, 0, 0, 1 }),
            "2001:db8::1")
        h.assert_eq(ip.ipv6_to_string({ 1, 2, 3, 4, 5, 6, 7, 8 }),
            "1:2:3:4:5:6:7:8")
    end)

    h.it("round trips parse and render", function()
        local samples = { "::1", "::", "2001:db8::1", "fe80::1",
                          "1:2:3:4:5:6:7:8", "64:ff9b::" }
        for _, s in ipairs(samples) do
            h.assert_eq(ip.ipv6_to_string(ip.parse_ipv6(s)), s, "round trip " .. s)
        end
    end)
end)

h.describe("ipaddr.embedded_ipv4 (tunnel unwrapping)", function()
    local function embeds(addr6, want_v4)
        local g = ip.parse_ipv6(addr6)
        h.assert_true(g, "parse " .. addr6)
        local list, n = ip.embedded_ipv4(g)
        for i = 1, n do
            if list[i] == want_v4 then return true end
        end
        error(addr6 .. " did not embed " .. ip.ipv4_to_string(want_v4)
            .. " (got " .. h.fmt(list) .. ")")
    end

    h.it("unwraps v4-mapped addresses", function()
        embeds("::ffff:127.0.0.1", LOCALHOST)
        embeds("::ffff:169.254.169.254", METADATA)
    end)

    h.it("unwraps v4-compatible addresses", function()
        embeds("::127.0.0.1", LOCALHOST)
    end)

    h.it("unwraps v4-translated addresses", function()
        embeds("::ffff:0:127.0.0.1", LOCALHOST)
    end)

    h.it("unwraps 6to4 addresses", function()
        embeds("2002:7f00:0001::", LOCALHOST)
        embeds("2002:a9fe:a9fe::", METADATA)
    end)

    h.it("unwraps NAT64 addresses", function()
        embeds("64:ff9b::169.254.169.254", METADATA)
        embeds("64:ff9b::127.0.0.1", LOCALHOST)
    end)

    h.it("unwraps ISATAP addresses", function()
        embeds("fe80::5efe:127.0.0.1", LOCALHOST)
        embeds("fe80::200:5efe:169.254.169.254", METADATA)
    end)

    h.it("unwraps Teredo client addresses", function()
        embeds("2001:0:4136:e378:8000:63bf:3fff:fdd2", 4294967295 - 0x3ffffdd2)
    end)

    h.it("returns nothing for plain global addresses", function()
        local g = ip.parse_ipv6("2606:4700:4700::1111")
        local _, n = ip.embedded_ipv4(g)
        h.assert_eq(n, 0)
    end)
end)

h.describe("ipaddr masking and CIDR parsing", function()
    h.it("masks ipv4 prefixes", function()
        h.assert_eq(ip.mask_ipv4(LOCALHOST, 8), 2130706432)
        h.assert_eq(ip.mask_ipv4(LOCALHOST, 32), LOCALHOST)
        h.assert_eq(ip.mask_ipv4(LOCALHOST, 0), 0)
        h.assert_eq(ip.mask_ipv4(3232235777, 16), 3232235520)
    end)

    h.it("masks ipv6 prefixes", function()
        h.assert_deep_eq(ip.mask_ipv6({ 0x2001, 0xdb8, 1, 2, 3, 4, 5, 6 }, 32),
            { 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0 })
        h.assert_deep_eq(ip.mask_ipv6({ 0xfe80, 1, 1, 1, 1, 1, 1, 1 }, 10),
            { 0xfe80, 0, 0, 0, 0, 0, 0, 0 })
    end)

    h.it("parses CIDR notation", function()
        local kind, net, prefix = ip.parse_cidr("10.0.0.0/8")
        h.assert_eq(kind, "ipv4")
        h.assert_eq(net, 167772160)
        h.assert_eq(prefix, 8)

        kind, net, prefix = ip.parse_cidr("192.168.1.5/24")
        h.assert_eq(net, 3232235776)
        h.assert_eq(prefix, 24)

        kind, _, prefix = ip.parse_cidr("1.2.3.4")
        h.assert_eq(kind, "ipv4")
        h.assert_eq(prefix, 32)

        kind, _, prefix = ip.parse_cidr("fc00::/7")
        h.assert_eq(kind, "ipv6")
        h.assert_eq(prefix, 7)
    end)

    h.it("rejects invalid CIDR notation", function()
        h.assert_nil(ip.parse_cidr("10.0.0.0/33"))
        h.assert_nil(ip.parse_cidr("fc00::/129"))
        h.assert_nil(ip.parse_cidr("10.0.0.0/"))
        h.assert_nil(ip.parse_cidr("not-an-ip/8"))
        h.assert_nil(ip.parse_cidr(""))
        h.assert_nil(ip.parse_cidr("10.0.0.0/008"))
    end)
end)
