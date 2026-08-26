local h = require("harness")
local util = require("ro.util")
local config = require("ro.config")

h.describe("hmac-sha256 matches the standard vectors", function()
    h.it("computes RFC 4231 test case 2", function()
        h.assert_eq(
            util.hmac_sha256_hex("Jefe", "what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    end)

    h.it("computes RFC 4231 test case 1", function()
        h.assert_eq(
            util.hmac_sha256_hex(string.rep(string.char(0x0b), 20), "Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    end)

    h.it("changes when the key changes", function()
        local a = util.hmac_sha256_hex("key-one-abcdefgh", "same message")
        local b = util.hmac_sha256_hex("key-two-abcdefgh", "same message")
        h.assert_ne(a, b)
    end)

    h.it("changes when a single byte of the message changes", function()
        local a = util.hmac_sha256_hex("shared-signing-key", "bundle-body-a")
        local b = util.hmac_sha256_hex("shared-signing-key", "bundle-body-b")
        h.assert_ne(a, b)
    end)
end)

h.describe("a signed bundle round-trips between controller and gateway", function()
    h.it("verifies the exact bytes the controller served", function()
        local key = "a-strong-shared-signing-key"
        local body = '{"version":7,"policies":[]}'
        local served = util.hmac_sha256_hex(key, body)
        h.assert_true(util.const_eq(served, util.hmac_sha256_hex(key, body)))
    end)

    h.it("refuses a body a tamperer rewrote in flight", function()
        local key = "a-strong-shared-signing-key"
        local served = util.hmac_sha256_hex(key, '{"version":7,"policies":[]}')
        local forged = util.hmac_sha256_hex(key,
            '{"version":7,"policies":[{"action":"allow"}]}')
        h.assert_false(util.const_eq(served, forged))
    end)

    h.it("refuses a body signed with the wrong key", function()
        local body = '{"version":7,"policies":[]}'
        local served = util.hmac_sha256_hex("the-real-signing-key", body)
        local attacker = util.hmac_sha256_hex("an-attackers-key", body)
        h.assert_false(util.const_eq(served, attacker))
    end)
end)

h.describe("config validates the control-channel options", function()
    h.it("accepts a strong signing key", function()
        local c = config.defaults()
        c.controller.signingKey = "a-strong-shared-signing-key"
        h.assert_true(config.validate(c))
    end)

    h.it("refuses a signing key shorter than 16 characters", function()
        local c = config.defaults()
        c.controller.signingKey = "too-short"
        h.assert_nil(config.validate(c))
    end)

    h.it("refuses requireSignature without a key", function()
        local c = config.defaults()
        c.controller.requireSignature = true
        h.assert_nil(config.validate(c))
    end)

    h.it("accepts an https controller url", function()
        local c = config.defaults()
        c.controller.url = "https://ro-controller:8081"
        h.assert_true(config.validate(c))
    end)

    h.it("refuses a controller url that is neither http nor https", function()
        local c = config.defaults()
        c.controller.url = "file:///etc/passwd"
        h.assert_nil(config.validate(c))
    end)
end)

h.describe("a key rotation never strands a gateway", function()
    h.it("ships with no additional accepted keys", function()
        h.assert_deep_eq(config.defaults().controller.acceptSigningKeys, {})
    end)

    h.it("accepts a rotation window holding both keys", function()
        local c = config.defaults()
        c.controller.signingKey = "the-old-signing-key-0001"
        c.controller.acceptSigningKeys = { "the-new-signing-key-0002" }
        c.controller.requireSignature = true
        h.assert_true(config.validate(c))
    end)

    h.it("lets requireSignature stand on an accepted key alone", function()
        local c = config.defaults()
        c.controller.acceptSigningKeys = { "the-new-signing-key-0002" }
        c.controller.requireSignature = true
        h.assert_true(config.validate(c))
    end)

    h.it("refuses a weak key in the rotation list", function()
        local c = config.defaults()
        c.controller.signingKey = "the-old-signing-key-0001"
        c.controller.acceptSigningKeys = { "short" }
        h.assert_nil(config.validate(c))
    end)

    h.it("refuses a rotation list that is not an array of keys", function()
        local c = config.defaults()
        c.controller.acceptSigningKeys = { key = "the-new-signing-key-0002" }
        h.assert_nil(config.validate(c))
    end)

    h.it("verifies a bundle signed with either key of the window", function()
        local body = '{"version":9,"policies":[]}'
        local old_sig = util.hmac_sha256_hex("the-old-signing-key-0001", body)
        local new_sig = util.hmac_sha256_hex("the-new-signing-key-0002", body)
        h.assert_ne(old_sig, new_sig)
        h.assert_true(util.const_eq(old_sig,
            util.hmac_sha256_hex("the-old-signing-key-0001", body)))
        h.assert_true(util.const_eq(new_sig,
            util.hmac_sha256_hex("the-new-signing-key-0002", body)))
        h.assert_false(util.const_eq(old_sig,
            util.hmac_sha256_hex("a-third-unrelated-key-03", body)))
    end)
end)
