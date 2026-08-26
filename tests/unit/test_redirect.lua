local h = require("harness")
local proxy = require("ro.proxy")

local function authority_of(loc, scheme)
    local s, rest, off = proxy.redirect_authority(loc, scheme or "http")
    return s, rest, off
end

h.describe("redirect targets that leave the origin are always evaluated", function()
    h.it("treats a plain path as same-origin", function()
        for _, loc in ipairs({ "/", "/path", "/a/b?c=d", "/x#frag" }) do
            local _, _, off = authority_of(loc)
            h.assert_false(off, loc .. " is same-origin and needs no evaluation")
        end
    end)

    h.it("treats a relative reference as same-origin", function()
        for _, loc in ipairs({ "foo", "foo/bar", "?a=1", "#frag" }) do
            local _, _, off = authority_of(loc)
            h.assert_false(off, loc .. " is same-origin")
        end
    end)

    h.it("catches a protocol-relative redirect, which also begins with a slash",
    function()
        local scheme, rest, off = authority_of("//evil.example.com/steal")
        h.assert_true(off, "//host must be evaluated, not waved through")
        h.assert_eq(scheme, "http")
        h.assert_eq(rest, "evil.example.com/steal")
    end)

    h.it("inherits the scheme of the request it is answering", function()
        local scheme = authority_of("//evil.example.com/", "https")
        h.assert_eq(scheme, "https")
    end)

    h.it("catches the backslash spellings browsers also follow", function()
        for _, loc in ipairs({ "/\\evil.example.com/", "\\\\evil.example.com/",
                               "\\/evil.example.com/" }) do
            local _, _, off = authority_of(loc)
            h.assert_true(off, loc .. " must be evaluated")
        end
    end)

    h.it("evaluates an absolute redirect", function()
        local scheme, rest, off = authority_of("http://evil.example.com/x")
        h.assert_true(off)
        h.assert_eq(scheme, "http")
        h.assert_eq(rest, "evil.example.com/x")
    end)

    h.it("lowercases the scheme so case cannot hide it", function()
        h.assert_eq(authority_of("HTTPS://Evil.Example.COM/"), "https")
    end)

    h.it("surfaces a non-http scheme rather than ignoring it", function()
        for _, loc in ipairs({ "javascript:alert(1)", "data:text/html,x",
                               "file:///etc/passwd", "gopher://x/" }) do
            local scheme, _, off = authority_of(loc)
            h.assert_true(off, loc .. " must not be treated as same-origin")
            h.assert_true(scheme ~= "http" and scheme ~= "https",
                loc .. " must not be mistaken for http")
        end
    end)
end)
