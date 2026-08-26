local h = require("harness")
local cidr = require("ro.cidr")
local ipaddr = require("ro.ipaddr")

local function build(list)
    local set = cidr.new()
    for _, entry in ipairs(list or {}) do
        set:add(entry)
    end
    return set
end

local function permitted(set, addr)
    if not set or set:size() == 0 then
        return false
    end
    local v4 = ipaddr.parse_ipv4(addr)
    if v4 then
        return set:match_v4(v4) ~= nil
    end
    local g = ipaddr.parse_ipv6(addr)
    if g then
        if set:match_v6(g) then
            return true
        end
        local mapped = ipaddr.ipv4_mapped(g)
        if mapped then
            return set:match_v4(mapped) ~= nil
        end
    end
    return false
end

h.describe("an empty admin source list means nobody, never everybody", function()
    h.it("refuses every source when the list is empty", function()
        local set = build({})
        for _, addr in ipairs({ "127.0.0.1", "10.0.0.1", "8.8.8.8",
                                "::1", "192.168.1.1" }) do
            h.assert_false(permitted(set, addr),
                addr .. " must be refused when no source is configured")
        end
    end)

    h.it("admits only what the list names", function()
        local set = build({ "127.0.0.1/32", "::1/128" })
        h.assert_true(permitted(set, "127.0.0.1"))
        h.assert_true(permitted(set, "::1"))
        h.assert_false(permitted(set, "127.0.0.2"))
        h.assert_false(permitted(set, "10.0.0.1"))
        h.assert_false(permitted(set, "8.8.8.8"))
    end)

    h.it("does not let a v4-mapped address slip past a v4 rule", function()
        local set = build({ "10.0.0.0/8" })
        h.assert_true(permitted(set, "10.1.2.3"))
        h.assert_true(permitted(set, "::ffff:10.1.2.3"),
            "a mapped address is the same address and must be treated as one")
        h.assert_false(permitted(set, "::ffff:8.8.8.8"))
    end)

    h.it("refuses an address it cannot parse", function()
        local set = build({ "0.0.0.0/0" })
        h.assert_false(permitted(set, "not-an-address"))
        h.assert_false(permitted(set, ""))
    end)

    h.it("admits everything only when that is written out explicitly", function()
        local set = build({ "0.0.0.0/0" })
        h.assert_true(permitted(set, "8.8.8.8"))
        h.assert_true(permitted(set, "127.0.0.1"))
    end)
end)
