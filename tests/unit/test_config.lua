local h = require("harness")
local config = require("ro.config")

h.describe("config defaults", function()
    local defaults = config.defaults()

    h.it("ships fail-closed values", function()
        h.assert_eq(defaults.mode, "explicit")
        h.assert_eq(defaults.identities.allowAnonymous, false)
        h.assert_eq(defaults.guard.includeDefaults, true)
        h.assert_eq(defaults.guard.blockObfuscated, true)
        h.assert_eq(defaults.controller.failClosed, true)
    end)

    h.it("enables strict protocol handling by default", function()
        h.assert_eq(defaults.strict.path, true)
        h.assert_eq(defaults.strict.sniMatch, true)
        h.assert_eq(defaults.strict.hostMatch, true)
        h.assert_eq(defaults.strict.redirectGuard, true)
        h.assert_eq(defaults.strict.blockPlaintextOnTlsPorts, true)
        h.assert_eq(defaults.strict.minTlsVersion, "1.2")
    end)

    h.it("returns an independent copy each time", function()
        local a = config.defaults()
        local b = config.defaults()
        a.mode = "mutated"
        h.assert_eq(b.mode, "explicit")
    end)

    h.it("restricts DNS record types by default", function()
        h.assert_deep_eq(defaults.dns.allowedTypes, { "A", "AAAA" })
    end)
end)

h.describe("config.deep_merge", function()
    h.it("merges nested tables without dropping siblings", function()
        local base = { a = { b = 1, c = 2 }, d = 3 }
        config.deep_merge(base, { a = { c = 9 } })
        h.assert_eq(base.a.b, 1)
        h.assert_eq(base.a.c, 9)
        h.assert_eq(base.d, 3)
    end)

    h.it("replaces arrays wholesale", function()
        local base = { list = { 1, 2, 3 } }
        config.deep_merge(base, { list = { 9 } })
        h.assert_deep_eq(base.list, { 9 })
    end)

    h.it("ignores non-table overrides", function()
        local base = { a = 1 }
        config.deep_merge(base, nil)
        config.deep_merge(base, "string")
        h.assert_eq(base.a, 1)
    end)
end)

h.describe("config.parse_servers", function()
    h.it("parses host:port strings", function()
        h.assert_deep_eq(config.parse_servers({ "1.1.1.1:53" }),
            { { host = "1.1.1.1", port = 53 } })
        h.assert_deep_eq(config.parse_servers({ "8.8.8.8" }),
            { { host = "8.8.8.8", port = 53 } })
    end)

    h.it("parses bracketed IPv6 servers", function()
        h.assert_deep_eq(config.parse_servers({ "[2606:4700:4700::1111]:5353" }),
            { { host = "2606:4700:4700::1111", port = 5353 } })
    end)

    h.it("accepts object form", function()
        h.assert_deep_eq(config.parse_servers({ { host = "10.0.0.1", port = 5300 } }),
            { { host = "10.0.0.1", port = 5300 } })
    end)

    h.it("returns an empty list for bad input", function()
        h.assert_deep_eq(config.parse_servers(nil), {})
        h.assert_deep_eq(config.parse_servers("nope"), {})
    end)
end)

h.describe("config.validate", function()
    h.it("accepts the shipped defaults", function()
        local ok, err = config.validate(config.defaults())
        h.assert_true(ok, tostring(err))
    end)

    h.it("rejects unknown modes", function()
        local c = config.defaults()
        c.mode = "wide-open"
        local ok, err = config.validate(c)
        h.assert_nil(ok)
        h.assert_match(err, "mode")
    end)

    h.it("requires at least one resolver", function()
        local c = config.defaults()
        c.resolver.servers = {}
        local ok, err = config.validate(c)
        h.assert_nil(ok)
        h.assert_match(err, "resolver")
    end)

    h.it("rejects an invalid minimum TLS version", function()
        local c = config.defaults()
        c.strict.minTlsVersion = "2.0"
        local ok, err = config.validate(c)
        h.assert_nil(ok)
        h.assert_match(err, "minTlsVersion")
    end)

    h.it("accepts the transparent modes", function()
        for _, mode in ipairs({ "transparent_http", "transparent_tls" }) do
            local c = config.defaults()
            c.mode = mode
            h.assert_true(config.validate(c), mode)
        end
    end)

    h.it("rejects non-table input", function()
        h.assert_nil(config.validate(nil))
        h.assert_nil(config.validate("string"))
    end)
end)
