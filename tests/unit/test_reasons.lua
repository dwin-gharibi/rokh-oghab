local h = require("harness")
local reasons = require("ro.reasons")

h.describe("reason labels are bounded so a sandbox cannot flood the registry", function()
    h.it("passes through every reason the gateway declares", function()
        for _, group in ipairs({ reasons.POLICY, reasons.IDENTITY, reasons.PROTOCOL,
                                 reasons.TLS, reasons.DNS, reasons.LIMIT,
                                 reasons.REDIRECT, reasons.UPSTREAM, reasons.GUARD,
                                 reasons.OTHER }) do
            for _, reason in ipairs(group) do
                h.assert_eq(reasons.label(reason), reason,
                    reason .. " must survive as its own label")
            end
        end
    end)

    h.it("keeps the guard set label, which is closed", function()
        h.assert_eq(reasons.label("guard.blocked:cloud-metadata"),
            "guard.blocked:cloud-metadata")
        h.assert_eq(reasons.label("guard.blocked:embedded-v4:cloud-metadata"),
            "guard.blocked:embedded-v4:cloud-metadata")
    end)

    h.it("collapses an unknown suffix onto its known prefix", function()
        h.assert_eq(reasons.label("guard.blocked:something-new"), "guard.blocked")
        h.assert_eq(reasons.label("upstream.connect_failed:connection refused"),
            "upstream.connect_failed")
        h.assert_eq(reasons.label("protocol.chunk:invalid chunk size"),
            "protocol.chunk")
    end)

    h.it("refuses a label it has never heard of", function()
        h.assert_eq(reasons.label("redirect.scheme:javascript"), "other")
        h.assert_eq(reasons.label("totally.made.up"), "other")
        h.assert_eq(reasons.label(""), "other")
        h.assert_eq(reasons.label(nil), "other")
        h.assert_eq(reasons.label(12345), "other")
    end)

    h.it("cannot be grown by attacker-supplied text", function()
        local seen = {}
        for i = 1, 5000 do
            seen[reasons.label("guard.blocked:evil-" .. i)] = true
            seen[reasons.label("attacker.controlled." .. i)] = true
            seen[reasons.label(string.rep("a", 200) .. i)] = true
        end
        local distinct = 0
        for _ in pairs(seen) do distinct = distinct + 1 end
        h.assert_true(distinct <= 2,
            "15000 hostile reasons produced " .. distinct .. " labels")
    end)

    h.it("declares a bounded number of labels in total", function()
        h.assert_true(reasons.count() > 40, "the catalogue should be complete")
        h.assert_true(reasons.count() < 200, "the catalogue must stay small")
    end)
end)
