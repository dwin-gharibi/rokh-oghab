local h = require("harness")
local store = require("roc.store")
local policy = require("ro.policy")

h.describe("store.valid_name", function()
    h.it("accepts conventional resource names", function()
        h.assert_true(store.valid_name("python-sandbox"))
        h.assert_true(store.valid_name("global-baseline"))
        h.assert_true(store.valid_name("tenant.acme_1"))
        h.assert_true(store.valid_name("a"))
    end)

    h.it("rejects names that could escape the store layout", function()
        h.assert_false(store.valid_name("../etc/passwd"))
        h.assert_false(store.valid_name("a/b"))
        h.assert_false(store.valid_name("Upper"))
        h.assert_false(store.valid_name("-leading"))
        h.assert_false(store.valid_name(""))
        h.assert_false(store.valid_name(string.rep("a", 200)))
        h.assert_false(store.valid_name("has space"))
        h.assert_false(store.valid_name("null\0byte"))
        h.assert_false(store.valid_name(nil))
    end)
end)

h.describe("store.normalize_policy", function()
    h.it("accepts the kubernetes-style document form", function()
        local out = assert(store.normalize_policy({
            apiVersion = "rokhoghab.io/v1",
            kind = "EgressPolicy",
            metadata = { name = "python", tier = "profile", priority = 15 },
            spec = {
                defaultAction = "deny",
                selector = { profiles = { "untrusted-python" } },
                rules = { { name = "r", action = "allow",
                            destinations = { hostnames = { "pypi.org" } },
                            ports = { 443 } } },
            },
        }))
        h.assert_eq(out.name, "python")
        h.assert_eq(out.tier, "profile")
        h.assert_eq(out.priority, 15)
        h.assert_eq(#out.rules, 1)
    end)

    h.it("accepts the flat form", function()
        local out = assert(store.normalize_policy({
            name = "flat", tier = "global",
            rules = { { name = "d", action = "deny",
                        destinations = { cidrs = { "169.254.0.0/16" } } } },
        }))
        h.assert_eq(out.name, "flat")
        h.assert_eq(out.tier, "global")
    end)

    h.it("falls back to the supplied name", function()
        local out = assert(store.normalize_policy({ spec = { rules = {} } },
            "fallback"))
        h.assert_eq(out.name, "fallback")
        h.assert_eq(out.tier, "profile")
    end)

    h.it("rejects other kinds and invalid names", function()
        local out, err = store.normalize_policy({ kind = "Deployment" }, "x")
        h.assert_nil(out)
        h.assert_match(err, "kind")

        out, err = store.normalize_policy({ metadata = { name = "../evil" } })
        h.assert_nil(out)
        h.assert_match(err, "name")

        out, err = store.normalize_policy("not a table", "x")
        h.assert_nil(out)
    end)

    h.it("produces a document the policy engine accepts", function()
        local normalized = assert(store.normalize_policy({
            kind = "EgressPolicy",
            metadata = { name = "ok", tier = "profile" },
            spec = { rules = { { name = "r", action = "allow",
                                 destinations = { hostnames = { "pypi.org" } },
                                 ports = { 443 } } } },
        }))
        local compiled, err = policy.compile({ version = 1,
            policies = { normalized } })
        h.assert_true(compiled, tostring(err))
    end)
end)

h.describe("store.normalize_profile", function()
    h.it("expands a sandbox profile into allow rules", function()
        local out = assert(store.normalize_profile({
            apiVersion = "rokhoghab.io/v1",
            kind = "SandboxProfile",
            metadata = { name = "untrusted-python" },
            spec = {
                egress = {
                    default = "deny",
                    allow = {
                        { host = "pypi.org", port = 443, protocol = "https" },
                        { domain = "pythonhosted.org", ports = { 443 },
                          protocols = { "https" } },
                    },
                },
            },
        }))
        h.assert_eq(out.name, "profile/untrusted-python")
        h.assert_eq(out.tier, "profile")
        h.assert_deep_eq(out.selector.profiles, { "untrusted-python" })
        h.assert_eq(#out.rules, 2)
        h.assert_deep_eq(out.rules[1].destinations.hostnames, { "pypi.org" })
        h.assert_deep_eq(out.rules[1].ports, { 443 })
        h.assert_deep_eq(out.rules[2].destinations.hostnameSuffixes,
            { "pythonhosted.org" })
    end)

    h.it("expands deny entries too", function()
        local out = assert(store.normalize_profile({
            kind = "SandboxProfile",
            metadata = { name = "p" },
            spec = { egress = {
                allow = { { host = "a.example.com", port = 443 } },
                deny = { { domain = "telemetry.example.com" } },
            } },
        }))
        h.assert_eq(#out.rules, 2)
        h.assert_eq(out.rules[2].action, "deny")
    end)

    h.it("refuses a profile that tries to default to allow", function()
        local out, err = store.normalize_profile({
            kind = "SandboxProfile",
            metadata = { name = "p" },
            spec = { egress = { default = "allow" } },
        })
        h.assert_nil(out)
        h.assert_match(err, "deny")
    end)

    h.it("rejects other kinds and bad names", function()
        local out, err = store.normalize_profile({ kind = "EgressPolicy" }, "x")
        h.assert_nil(out)
        h.assert_match(err, "kind")

        out, err = store.normalize_profile({ metadata = { name = "BAD NAME" } })
        h.assert_nil(out)
        h.assert_match(err, "name")
    end)

    h.it("produces rules the policy engine accepts", function()
        local normalized = assert(store.normalize_profile({
            kind = "SandboxProfile",
            metadata = { name = "compiles" },
            spec = { egress = { allow = {
                { host = "pypi.org", port = 443, protocol = "https" } } } },
        }))
        local compiled, err = policy.compile({ version = 1,
            policies = { normalized } })
        h.assert_true(compiled, tostring(err))
    end)

    h.it("rejects a profile whose allow entry has no destination", function()
        local normalized = assert(store.normalize_profile({
            kind = "SandboxProfile",
            metadata = { name = "broken" },
            spec = { egress = { allow = { { port = 443 } } } },
        }))
        local compiled, err = policy.compile({ version = 1,
            policies = { normalized } })
        h.assert_nil(compiled)
        h.assert_match(err, "destination")
    end)
end)

h.describe("store.compile_bundle", function()
    local data = {
        policies = {
            ["global-baseline"] = {
                kind = "EgressPolicy",
                metadata = { name = "global-baseline", tier = "global" },
                spec = { rules = { { name = "deny-imds", action = "deny",
                        destinations = { cidrs = { "169.254.0.0/16" } } } } },
            },
        },
        profiles = {
            ["untrusted-python"] = {
                kind = "SandboxProfile",
                metadata = { name = "untrusted-python" },
                spec = { egress = { allow = {
                    { host = "pypi.org", port = 443, protocol = "https" } } } },
            },
        },
        identities = { allowAnonymous = false, tokens = {}, sources = {} },
        settings = { ttlSeconds = 120, emergencyDeny = false,
                     defaults = { maxStalenessSeconds = 600 },
                     guard = { blocked = {}, allowExceptions = {} } },
    }

    h.it("merges policies and profiles into one bundle", function()
        local bundle = assert(store.compile_bundle(data, 12))
        h.assert_eq(bundle.version, 12)
        h.assert_eq(bundle.ttlSeconds, 120)
        h.assert_eq(bundle.emergencyDeny, false)
        h.assert_eq(#bundle.policies, 2)
    end)

    h.it("produces a bundle the policy engine validates", function()
        local bundle = assert(store.compile_bundle(data, 1))
        local compiled, err = store.validate_bundle(bundle)
        h.assert_true(compiled, tostring(err))
        h.assert_eq(compiled.rule_count, 2)
    end)

    h.it("surfaces the offending document when one is invalid", function()
        local broken = {
            policies = { bad = { metadata = { name = "bad" },
                spec = { rules = { { action = "allow", ports = { 443 } } } } } },
            profiles = {}, identities = {}, settings = {},
        }
        local bundle = assert(store.compile_bundle(broken, 1))
        local compiled, err = store.validate_bundle(bundle)
        h.assert_nil(compiled)
        h.assert_match(err, "destination")
    end)

    h.it("carries the emergency deny switch into the bundle", function()
        local emergency = {
            policies = {}, profiles = {}, identities = {},
            settings = { emergencyDeny = true },
        }
        local bundle = assert(store.compile_bundle(emergency, 3))
        h.assert_eq(bundle.emergencyDeny, true)
        local compiled = assert(store.validate_bundle(bundle))
        h.assert_true(compiled.emergency_deny)
    end)
end)

h.describe("the store refuses a data directory it would have to shell out with",
function()
    h.it("accepts an ordinary absolute path", function()
        for _, dir in ipairs({ "/var/lib/rokh-oghab", "/data", "/srv/ro_store-1",
                               "/a/b/c.d/e_f-g" }) do
            h.assert_eq(store.safe_data_dir(dir), dir, dir .. " should be accepted")
        end
    end)

    h.it("refuses a quote that would break out of the command", function()
        for _, dir in ipairs({
            "/var/lib/x'; rm -rf /; echo '",
            "/var/lib/x'",
            '/var/lib/x"',
            "/var/lib/x`id`",
            "/var/lib/x$(id)",
            "/var/lib/x;id",
            "/var/lib/x|id",
            "/var/lib/x&id",
            "/var/lib/x\nid",
            "/var/lib/x id",
            "/var/lib/x>out",
            "/var/lib/x*",
        }) do
            local ok, err = store.safe_data_dir(dir)
            h.assert_nil(ok, string.format("%q must be refused", dir))
            h.assert_true(err ~= nil)
        end
    end)

    h.it("refuses a parent reference", function()
        h.assert_nil(store.safe_data_dir("/var/lib/../../etc"))
        h.assert_nil(store.safe_data_dir("/.."))
    end)

    h.it("refuses a relative path", function()
        h.assert_nil(store.safe_data_dir("var/lib/ro"))
        h.assert_nil(store.safe_data_dir("./ro"))
        h.assert_nil(store.safe_data_dir(""))
    end)

    h.it("refuses a non-string and an absurd length", function()
        h.assert_nil(store.safe_data_dir(nil))
        h.assert_nil(store.safe_data_dir(42))
        h.assert_nil(store.safe_data_dir({}))
        h.assert_nil(store.safe_data_dir("/" .. string.rep("a", 5000)))
    end)
end)
