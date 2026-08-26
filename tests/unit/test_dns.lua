local h = require("harness")
local dns = require("ro.dns")

local function u16(n)
    return string.char(math.floor(n / 256) % 256, n % 256)
end

local function encode_name(name)
    local out = {}
    for label in name:gmatch("[^%.]+") do
        out[#out + 1] = string.char(#label) .. label
    end
    return table.concat(out) .. "\0"
end

local function query_packet(name, qtype, id)
    return u16(id or 1) .. u16(0x0100) .. u16(1) .. u16(0) .. u16(0) .. u16(0)
        .. encode_name(name) .. u16(qtype or 1) .. u16(1)
end

h.describe("dns name encoding", function()
    h.it("round trips names", function()
        for _, name in ipairs({ "a.example.com", "pypi.org", "x.y.z.w.test" }) do
            local encoded = dns.encode_name(name)
            local decoded = dns.decode_name(encoded, 1)
            h.assert_eq(decoded, name)
        end
    end)

    h.it("encodes the root", function()
        h.assert_eq(dns.encode_name("."), "\0")
        h.assert_eq(dns.encode_name(""), "\0")
    end)

    h.it("rejects oversized names and labels", function()
        h.assert_nil(dns.encode_name(string.rep("a", 64) .. ".com"))
        h.assert_nil(dns.encode_name(string.rep("a.", 200) .. "com"))
        h.assert_nil(dns.encode_name("a..b"))
    end)

    h.it("lowercases decoded names", function()
        h.assert_eq(dns.decode_name(encode_name("EXAMPLE.COM"), 1), "example.com")
    end)
end)

h.describe("dns compression pointer safety", function()
    h.it("rejects self-referencing pointers", function()
        local msg = string.rep("\0", 12) .. "\192\012"
        local name, err = dns.decode_name(msg, 13)
        h.assert_nil(name)
        h.assert_true(err)
    end)

    h.it("rejects forward pointers", function()
        local msg = string.rep("\0", 12) .. "\192\200" .. string.rep("\0", 100)
        local name, err = dns.decode_name(msg, 13)
        h.assert_nil(name)
        h.assert_match(err, "forward")
    end)

    h.it("follows a legitimate backward pointer", function()
        local msg = string.rep("\0", 12) .. encode_name("example.com")
        local target = #msg
        msg = msg .. "\192\012"
        local name = dns.decode_name(msg, target + 1)
        h.assert_eq(name, "example.com")
    end)

    h.it("rejects invalid label length prefixes", function()
        local msg = string.rep("\0", 12) .. "\128abc\0"
        h.assert_nil(dns.decode_name(msg, 13))
    end)
end)

h.describe("dns.parse_message", function()
    h.it("parses a query", function()
        local msg = dns.parse_message(query_packet("pypi.org", 1, 0x1234))
        h.assert_eq(msg.id, 0x1234)
        h.assert_false(msg.qr)
        h.assert_eq(msg.opcode, 0)
        h.assert_true(msg.rd)
        h.assert_eq(#msg.questions, 1)
        h.assert_eq(msg.questions[1].name, "pypi.org")
        h.assert_eq(msg.questions[1].qtype, dns.TYPE.A)
        h.assert_eq(msg.questions[1].qclass, dns.CLASS_IN)
    end)

    h.it("parses A and AAAA answers", function()
        local response = dns.build_response(
            { id = 7, rd = true, questions = { {
                name = "a.example.com", qtype = 1, qclass = 1 } } },
            0, { {
                name = "a.example.com", rtype = dns.TYPE.A, rclass = 1,
                ttl = 30, rdata = dns.encode_a(16909060),
            } })
        local msg = dns.parse_message(response)
        h.assert_eq(msg.id, 7)
        h.assert_true(msg.qr)
        h.assert_eq(#msg.answers, 1)
        h.assert_eq(msg.answers[1].family, "ipv4")
        h.assert_eq(msg.answers[1].address, 16909060)
        h.assert_eq(msg.answers[1].ttl, 30)
    end)

    h.it("parses AAAA rdata into groups", function()
        local groups = { 0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111 }
        local response = dns.build_response(
            { id = 8, questions = { { name = "v6.test", qtype = 28, qclass = 1 } } },
            0, { {
                name = "v6.test", rtype = dns.TYPE.AAAA, rclass = 1, ttl = 10,
                rdata = dns.encode_aaaa(groups),
            } })
        local msg = dns.parse_message(response)
        h.assert_eq(msg.answers[1].family, "ipv6")
        h.assert_deep_eq(msg.answers[1].groups, groups)
    end)

    h.it("rejects malformed messages", function()
        h.assert_nil(dns.parse_message(""))
        h.assert_nil(dns.parse_message("short"))
        h.assert_nil(dns.parse_message(string.rep("\0", 8)))
        h.assert_nil(dns.parse_message(string.rep("A", 5000)))
        h.assert_nil(dns.parse_message(nil))
    end)

    h.it("rejects unreasonable record counts", function()
        local hostile = u16(1) .. u16(0x8180) .. u16(1) .. u16(9999)
            .. u16(0) .. u16(0) .. encode_name("a.test") .. u16(1) .. u16(1)
        h.assert_nil(dns.parse_message(hostile))
    end)

    h.it("rejects truncated resource records", function()
        local truncated = u16(1) .. u16(0x8180) .. u16(1) .. u16(1)
            .. u16(0) .. u16(0) .. encode_name("a.test") .. u16(1) .. u16(1)
            .. encode_name("a.test") .. u16(1) .. u16(1) .. "\0\0\0\30" .. u16(4)
            .. "\1\2"
        h.assert_nil(dns.parse_message(truncated))
    end)

    h.it("never raises on random corruption", function()
        local base = dns.build_response(
            { id = 3, questions = { { name = "a.example.com",
                                      qtype = 1, qclass = 1 } } },
            0, { { name = "a.example.com", rtype = 1, rclass = 1, ttl = 5,
                   rdata = dns.encode_a(16909060) } })
        math.randomseed(1234)
        for _ = 1, 400 do
            local pos = math.random(1, #base)
            local corrupted = base:sub(1, pos - 1)
                .. string.char(math.random(0, 255)) .. base:sub(pos + 1)
            local ok = pcall(dns.parse_message, corrupted)
            h.assert_true(ok, "corruption at " .. pos .. " must not raise")
        end
    end)

    h.it("never raises on truncation", function()
        local base = dns.build_response(
            { id = 3, questions = { { name = "a.example.com",
                                      qtype = 1, qclass = 1 } } },
            0, { { name = "a.example.com", rtype = 1, rclass = 1, ttl = 5,
                   rdata = dns.encode_a(16909060) } })
        for cut = 1, #base do
            local ok = pcall(dns.parse_message, base:sub(1, cut))
            h.assert_true(ok, "truncation at " .. cut .. " must not raise")
        end
    end)
end)

h.describe("dns.build_query and build_response", function()
    h.it("builds a well formed query", function()
        local packet = dns.build_query(0x2222, "pypi.org", dns.TYPE.A)
        local msg = dns.parse_message(packet)
        h.assert_eq(msg.id, 0x2222)
        h.assert_eq(msg.qdcount, 1)
        h.assert_eq(msg.questions[1].name, "pypi.org")
    end)

    h.it("refuses to build a query for an invalid name", function()
        h.assert_nil(dns.build_query(1, string.rep("a", 64) .. ".com", 1))
    end)

    h.it("echoes the question and sets response flags", function()
        local query = dns.parse_message(query_packet("a.example.com", 1, 99))
        local response = dns.build_response(query, dns.RCODE.NXDOMAIN, {})
        local parsed = dns.parse_message(response)
        h.assert_eq(parsed.id, 99)
        h.assert_true(parsed.qr)
        h.assert_eq(parsed.rcode, dns.RCODE.NXDOMAIN)
        h.assert_eq(parsed.qdcount, 1)
        h.assert_eq(parsed.ancount, 0)
        h.assert_eq(parsed.questions[1].name, "a.example.com")
    end)

    h.it("builds a truncated response", function()
        local query = dns.parse_message(query_packet("a.example.com", 1, 5))
        local parsed = dns.parse_message(dns.truncated_response(query))
        h.assert_eq(parsed.id, 5)
        h.assert_true(parsed.tc)
    end)
end)

h.describe("dns address encoding", function()
    h.it("encodes IPv4 rdata", function()
        h.assert_eq(dns.encode_a(16909060), "\1\2\3\4")
        h.assert_eq(dns.encode_a(0), "\0\0\0\0")
        h.assert_eq(dns.encode_a(4294967295), "\255\255\255\255")
    end)

    h.it("encodes IPv6 rdata", function()
        local rdata = dns.encode_aaaa({ 0, 0, 0, 0, 0, 0, 0, 1 })
        h.assert_eq(#rdata, 16)
        h.assert_eq(rdata:byte(16), 1)
    end)
end)
