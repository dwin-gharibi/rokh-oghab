local h = require("harness")
local util = require("ro.util")
local cjson = require("cjson.safe")

h.describe("a content digest does not depend on key order", function()
    h.it("gives one answer for two spellings of one document", function()
        local a = { zeta = 1, alpha = "two", middle = { 3, 2, 1 } }
        local b = { middle = { 3, 2, 1 }, alpha = "two", zeta = 1 }
        h.assert_eq(util.canonical_json(a), util.canonical_json(b))
        h.assert_eq(util.content_digest(a), util.content_digest(b))
    end)

    h.it("survives a round trip through the json encoder", function()
        local doc = {
            version = 12,
            policies = {
                { name = "b", rules = { { action = "deny", ports = { 80, 443 } } } },
                { name = "a", rules = { { action = "allow" } } },
            },
            identities = { allowAnonymous = false, tokens = {} },
        }
        local first = util.content_digest(doc)
        for _ = 1, 40 do
            local decoded = cjson.decode(cjson.encode(doc))
            h.assert_eq(util.content_digest(decoded), first,
                "a decoded copy must digest the same as the original")
        end
    end)

    h.it("agrees across two json spellings of one document", function()
        local a = [[{"alpha":1,"beta":2,"gamma":{"x":1,"y":2},"zeta":[1,2,3]}]]
        local b = [[{"zeta":[1,2,3],"gamma":{"y":2,"x":1},"beta":2,"alpha":1}]]
        local da, db = cjson.decode(a), cjson.decode(b)
        h.assert_eq(util.content_digest(da), util.content_digest(db),
            "two controller workers can serialise one bundle differently; "
            .. "a gateway that digests the encoding rather than the content "
            .. "recompiles and republishes unchanged policy on every poll")
    end)

    h.it("is reproducible from the document alone", function()
        local doc = cjson.decode(
            [[{"zeta":[1,2,3],"gamma":{"y":2,"x":1},"beta":2,"alpha":1}]])
        local expected =
            [[{"alpha":1,"beta":2,"gamma":{"x":1,"y":2},"zeta":[1,2,3]}]]
        h.assert_eq(util.canonical_json(doc), expected)
        h.assert_eq(util.content_digest(doc), util.sha256_hex(expected),
            "the digest must be the hash of the one canonical spelling, so "
            .. "anyone holding the same bundle can recompute it and compare "
            .. "two gateways; a digest of whatever the encoder happened to "
            .. "emit cannot be reproduced")
    end)

    h.it("keeps array order, which is meaningful", function()
        h.assert_ne(util.canonical_json({ 1, 2, 3 }),
            util.canonical_json({ 3, 2, 1 }))
    end)

    h.it("separates documents that differ only in one value", function()
        h.assert_ne(util.content_digest({ a = 1 }), util.content_digest({ a = 2 }))
        h.assert_ne(util.content_digest({ a = 1 }), util.content_digest({ b = 1 }))
        h.assert_ne(util.content_digest({ a = "1" }), util.content_digest({ a = 1 }))
        h.assert_ne(util.content_digest({ a = true }),
            util.content_digest({ a = "true" }))
    end)

    h.it("cannot be confused by a key that looks like a separator", function()
        h.assert_ne(util.content_digest({ ['a":1,"b'] = 2 }),
            util.content_digest({ a = 1, b = 2 }))
    end)

    h.it("escapes control characters rather than emitting them raw", function()
        local out = util.canonical_json({ s = "a\nb\tc\1d" })
        h.assert_match(out, "\\n")
        h.assert_match(out, "\\t")
        h.assert_match(out, "\\u0001")
        h.assert_nil(out:find("\n", 1, true))
    end)

    h.it("digests a string as itself", function()
        h.assert_eq(util.content_digest("abc"), util.sha256_hex("abc"))
    end)

    h.it("does not recurse without bound", function()
        local deep = {}
        local cur = deep
        for _ = 1, 200 do
            cur.next = {}
            cur = cur.next
        end
        local ok = pcall(util.canonical_json, deep)
        h.assert_eq(ok, true, "a deeply nested document must not blow the stack")
    end)
end)

h.describe("randomness that matters is not the predictable kind", function()
    h.it("gives different bytes on every call", function()
        local seen = {}
        for _ = 1, 200 do
            local raw = util.random_bytes(16)
            h.assert_true(raw ~= nil, "a strong random source must be present")
            h.assert_eq(#raw, 16)
            h.assert_nil(seen[raw], "random_bytes repeated a value")
            seen[raw] = true
        end
    end)

    h.it("cannot be replayed by seeding the standard generator", function()
        local function draw(seed)
            math.randomseed(seed)
            local out = {}
            for i = 1, 12 do out[i] = util.random_int(1, 65535) end
            return out
        end
        local first, second = draw(4242), draw(4242)
        local same = 0
        for i = 1, 12 do
            if first[i] == second[i] then same = same + 1 end
        end
        h.assert_true(same < 4,
            "the same seed reproduced the same values, so this generator is "
            .. "the standard one. Unseeded, it yields one fixed sequence on "
            .. "every process start: a dns query id drawn from it is known in "
            .. "advance, which is half of what a spoofed answer needs, and a "
            .. "token minted from it is the same token every controller mints")
    end)

    h.it("does not repeat a captured sequence after a restart", function()
        local function draw()
            local out = {}
            for i = 1, 12 do out[i] = util.random_int(1, 65535) end
            return out
        end
        math.randomseed(1)
        local a = draw()
        math.randomseed(1)
        local b = draw()
        h.assert_ne(table.concat(a, ","), table.concat(b, ","))
    end)

    h.it("stays inside the range it was given", function()
        for _ = 1, 500 do
            local n = util.random_int(1, 65535)
            h.assert_true(n ~= nil)
            h.assert_true(n >= 1 and n <= 65535, "out of range: " .. tostring(n))
        end
        h.assert_eq(util.random_int(7, 7), 7)
        h.assert_nil(util.random_int(9, 8))
    end)

    h.it("spreads across the range rather than clustering", function()
        local buckets = {}
        for _ = 1, 2000 do
            local n = util.random_int(1, 65535)
            local b = math.floor((n - 1) / 8192) + 1
            buckets[b] = (buckets[b] or 0) + 1
        end
        local filled = 0
        for _ = 1, 8 do end
        for i = 1, 8 do
            if (buckets[i] or 0) > 100 then filled = filled + 1 end
        end
        h.assert_eq(filled, 8, "every eighth of the range should be reached")
    end)
end)
