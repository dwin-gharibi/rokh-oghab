local h = require("harness")
local identity = require("ro.identity")
local util = require("ro.util")

local PY_TOKEN = "ro-unit-python-token-000000001"
local NODE_TOKEN = "ro-unit-node-token-00000000001"

local function config()
    return {
        allowAnonymous = false,
        tokens = {
            [util.sha256_hex(PY_TOKEN)] = {
                id = "sandbox-1", namespace = "execution",
                profile = "untrusted-python", serviceAccount = "runner",
                labels = { tenant = "acme" },
            },
            [util.sha256_hex(NODE_TOKEN)] = {
                id = "sandbox-2", namespace = "execution",
                profile = "untrusted-node", serviceAccount = "runner",
            },
        },
        sources = {
            { cidr = "10.42.0.0/16", id = "by-source", namespace = "execution",
              profile = "untrusted-python", serviceAccount = "runner" },
            { cidr = "fd00:1::/64", id = "by-source-v6", namespace = "execution",
              profile = "untrusted-node", serviceAccount = "runner" },
        },
        trustedHeaderSources = { "10.43.0.0/16" },
    }
end

h.describe("identity token resolution", function()
    local ident = assert(identity.new(config()))

    h.it("maps a valid token to its identity", function()
        local who = ident:resolve({
            proxy_authorization = "Bearer " .. PY_TOKEN,
        })
        h.assert_eq(who.id, "sandbox-1")
        h.assert_eq(who.profile, "untrusted-python")
        h.assert_eq(who.namespace, "execution")
        h.assert_eq(who.source, "token")
        h.assert_eq(who.key, "execution/untrusted-python/runner/sandbox-1")
    end)

    h.it("accepts basic credentials", function()
        local encoded = ngx.encode_base64("user:" .. NODE_TOKEN)
        local who = ident:resolve({
            proxy_authorization = "Basic " .. encoded,
        })
        h.assert_eq(who.profile, "untrusted-node")
    end)

    h.it("is case insensitive about the scheme", function()
        h.assert_true(ident:resolve({ proxy_authorization = "bearer " .. PY_TOKEN }))
        h.assert_true(ident:resolve({ proxy_authorization = "BEARER " .. PY_TOKEN }))
    end)

    h.it("rejects unknown and malformed credentials", function()
        local who, err = ident:resolve({
            proxy_authorization = "Bearer ro-unit-wrong-token-000000",
        })
        h.assert_nil(who)
        h.assert_eq(err, "identity.invalid_token")

        who, err = ident:resolve({ proxy_authorization = "Bearer" })
        h.assert_nil(who)
        h.assert_eq(err, "identity.malformed_credentials")

        who, err = ident:resolve({ proxy_authorization = "Negotiate abc" })
        h.assert_nil(who)
        h.assert_eq(err, "identity.malformed_credentials")

        who, err = ident:resolve({ proxy_authorization = "Basic !!!!not-base64" })
        h.assert_nil(who)
    end)

    h.it("does not fall back to source identity when a token is presented", function()
        local who, err = ident:resolve({
            proxy_authorization = "Bearer ro-unit-wrong-token-000000",
            remote_addr = "10.42.0.9",
        })
        h.assert_nil(who, "a bad token must not silently downgrade to source auth")
        h.assert_eq(err, "identity.invalid_token")
    end)

    h.it("rejects tokens that are too short or too long", function()
        h.assert_nil(ident:from_token("short"))
        h.assert_nil(ident:from_token(string.rep("a", 600)))
        h.assert_nil(ident:from_token(nil))
    end)
end)

h.describe("identity source resolution", function()
    local ident = assert(identity.new(config()))

    h.it("maps a source address inside the range", function()
        local who = ident:resolve({ remote_addr = "10.42.7.9" })
        h.assert_eq(who.id, "by-source")
        h.assert_eq(who.source, "source")
    end)

    h.it("maps IPv6 sources", function()
        local who = ident:resolve({ remote_addr = "fd00:1::5" })
        h.assert_eq(who.id, "by-source-v6")
    end)

    h.it("maps v4-mapped IPv6 sources to their IPv4 range", function()
        local who = ident:resolve({ remote_addr = "::ffff:10.42.7.9" })
        h.assert_eq(who.id, "by-source")
    end)

    h.it("denies addresses outside every range", function()
        local who, err = ident:resolve({ remote_addr = "10.43.0.1" })
        h.assert_nil(who)
        h.assert_eq(err, "identity.unknown")

        who, err = ident:resolve({ remote_addr = "203.0.113.5" })
        h.assert_nil(who)
        h.assert_eq(err, "identity.unknown")
    end)

    h.it("denies when nothing identifies the caller", function()
        local who, err = ident:resolve({})
        h.assert_nil(who)
        h.assert_eq(err, "identity.unknown")
    end)
end)

h.describe("identity header trust", function()
    h.it("ignores identity headers from untrusted sources", function()
        local ident = assert(identity.new(config()))
        local who = ident:resolve({
            remote_addr = "10.42.0.5",
            headers = { ["x-ro-profile"] = "admin-profile" },
        })
        h.assert_eq(who.profile, "untrusted-python",
            "headers from an untrusted source must not override identity")
    end)

    h.it("honours identity headers only from trusted sources", function()
        local cfg = config()
        cfg.sources[#cfg.sources + 1] = {
            cidr = "10.43.0.0/16", id = "injector", namespace = "system",
            profile = "placeholder", serviceAccount = "injector",
        }
        local ident = assert(identity.new(cfg))
        local who = ident:resolve({
            remote_addr = "10.43.0.5",
            headers = {
                ["x-ro-profile"] = "untrusted-node",
                ["x-ro-namespace"] = "tenant-a",
                ["x-ro-identity"] = "pod-123",
            },
        })
        h.assert_eq(who.profile, "untrusted-node")
        h.assert_eq(who.namespace, "tenant-a")
        h.assert_eq(who.id, "pod-123")
        h.assert_eq(who.source, "trusted-header")
    end)
end)

h.describe("identity anonymous handling", function()
    h.it("denies anonymous callers by default", function()
        local ident = assert(identity.new({}))
        local who, err = ident:resolve({ remote_addr = "203.0.113.9" })
        h.assert_nil(who)
        h.assert_eq(err, "identity.unknown")
    end)

    h.it("permits anonymous callers only when explicitly enabled", function()
        local ident = assert(identity.new({ allowAnonymous = true }))
        local who = ident:resolve({ remote_addr = "203.0.113.9" })
        h.assert_true(who)
        h.assert_true(who.anonymous)
        h.assert_eq(who.profile, "-")
    end)
end)

h.describe("identity configuration validation", function()
    h.it("rejects non-hex token keys", function()
        local ident, err = identity.new({ tokens = { ["not-a-digest"] = {} } })
        h.assert_nil(ident)
        h.assert_match(err, "hex")
    end)

    h.it("rejects sources without a cidr", function()
        local ident, err = identity.new({ sources = { { profile = "x" } } })
        h.assert_nil(ident)
        h.assert_match(err, "cidr")
    end)

    h.it("rejects invalid source cidrs", function()
        local ident, err = identity.new({ sources = { { cidr = "999.0.0.0/8" } } })
        h.assert_nil(ident)
        h.assert_true(err)
    end)

    h.it("reports statistics", function()
        local ident = assert(identity.new(config()))
        local stats = ident:stats()
        h.assert_eq(stats.tokens, 2)
        h.assert_eq(stats.sources, 2)
        h.assert_eq(stats.allowAnonymous, false)
    end)
end)

h.describe("identity field sanitisation", function()
    h.it("drops fields containing dangerous characters", function()
        local ident = assert(identity.new({
            tokens = {
                [util.sha256_hex(PY_TOKEN)] = {
                    id = "bad id with spaces",
                    namespace = "ns\r\ninjected",
                    profile = "ok-profile",
                },
            },
        }))
        local who = ident:resolve({ proxy_authorization = "Bearer " .. PY_TOKEN })
        h.assert_eq(who.id, "unnamed")
        h.assert_eq(who.namespace, "-")
        h.assert_eq(who.profile, "ok-profile")
    end)
end)
