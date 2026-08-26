local h = require("harness")
local policy = require("ro.policy")
local target = require("ro.target")

local function bundle(policies, extra)
    local raw = { version = 1, policies = policies }
    if extra then
        for k, v in pairs(extra) do raw[k] = v end
    end
    return policy.compile(raw)
end

local function req(host, port, protocol, method, path)
    local info = assert(target.classify_host(host))
    return {
        host_info = info,
        port = port or 443,
        protocol = protocol or "https",
        method = method,
        path = path,
    }
end

local PY_IDENT = {
    id = "sandbox-1", namespace = "execution",
    profile = "untrusted-python", serviceAccount = "sandbox-runner",
}

h.describe("policy.compile validation", function()
    h.it("requires a version", function()
        local b, err = policy.compile({ policies = {} })
        h.assert_nil(b)
        h.assert_match(err, "version")
    end)

    h.it("rejects allow rules without destinations", function()
        local b, err = bundle({
            { name = "p", rules = { { action = "allow", ports = { 443 } } } },
        })
        h.assert_nil(b)
        h.assert_match(err, "destination")
    end)

    h.it("rejects allow rules without ports", function()
        local b, err = bundle({
            { name = "p", rules = { {
                action = "allow",
                destinations = { hostnames = { "pypi.org" } },
            } } },
        })
        h.assert_nil(b)
        h.assert_match(err, "ports")
    end)

    h.it("rejects unknown fields to catch typos", function()
        local b, err = bundle({
            { name = "p", rules = { {
                action = "allow",
                destination = { hostnames = { "pypi.org" } },
                ports = { 443 },
            } } },
        })
        h.assert_nil(b)
        h.assert_match(err, "unknown field")

        b, err = bundle({ { name = "p", rulez = {} } })
        h.assert_nil(b)
        h.assert_match(err, "unknown field")
    end)

    h.it("rejects invalid hostnames and cidrs", function()
        local b, err = bundle({
            { name = "p", rules = { {
                action = "allow",
                destinations = { hostnames = { "not a host" } },
                ports = { 443 },
            } } },
        })
        h.assert_nil(b)
        h.assert_match(err, "invalid hostname")

        b, err = bundle({
            { name = "p", rules = { {
                action = "allow",
                destinations = { cidrs = { "999.0.0.0/8" } },
                ports = { 443 },
            } } },
        })
        h.assert_nil(b)
        h.assert_match(err, "cidr")
    end)

    h.it("rejects dangerously broad allow suffixes", function()
        local b, err = bundle({
            { name = "p", rules = { {
                action = "allow",
                destinations = { hostnameSuffixes = { "com" } },
                ports = { 443 },
            } } },
        })
        h.assert_nil(b)
        h.assert_match(err, "too broad")
    end)

    h.it("refuses defaultAction allow", function()
        local b, err = bundle({ { name = "p", defaultAction = "allow", rules = {} } })
        h.assert_nil(b)
        h.assert_match(err, "refused")
    end)

    h.it("rejects unknown tiers, protocols and methods", function()
        local b, err = bundle({ { name = "p", tier = "galaxy", rules = {} } })
        h.assert_nil(b)
        h.assert_match(err, "tier")

        b, err = bundle({ { name = "p", rules = { {
            action = "allow", ports = { 443 }, protocols = { "gopher" },
            destinations = { hostnames = { "a.example.com" } },
        } } } })
        h.assert_nil(b)
        h.assert_match(err, "protocol")

        b, err = bundle({ { name = "p", rules = { {
            action = "allow", ports = { 443 }, methods = { "BREW" },
            destinations = { hostnames = { "a.example.com" } },
        } } } })
        h.assert_nil(b)
        h.assert_match(err, "method")
    end)

    h.it("rejects duplicate policy names and bad ports", function()
        local b, err = bundle({ { name = "p", rules = {} }, { name = "p", rules = {} } })
        h.assert_nil(b)
        h.assert_match(err, "duplicate")

        b, err = bundle({ { name = "p", rules = { {
            action = "allow", ports = { 70000 },
            destinations = { hostnames = { "a.example.com" } },
        } } } })
        h.assert_nil(b)
        h.assert_match(err, "port")
    end)

    h.it("accepts a well formed bundle", function()
        local b, err = bundle({ {
            name = "python-sandbox",
            tier = "profile",
            selector = { profiles = { "untrusted-python" } },
            rules = { {
                name = "pypi",
                action = "allow",
                destinations = {
                    hostnames = { "pypi.org" },
                    hostnameSuffixes = { "pythonhosted.org" },
                },
                ports = { 443 },
                protocols = { "https" },
                rateLimit = { requestsPerSecond = 20 },
            } },
        } })
        h.assert_true(b, tostring(err))
        h.assert_eq(b.rule_count, 1)
        h.assert_eq(b:summary().policyCount, 1)
    end)
end)

h.describe("policy evaluation: default deny", function()
    local b = assert(bundle({}))

    h.it("denies everything when no policy matches", function()
        local d = b:evaluate(PY_IDENT, req("pypi.org", 443))
        h.assert_eq(d.action, "deny")
        h.assert_eq(d.reason, "policy.default_deny")
    end)

    h.it("denies even with a matching-looking destination", function()
        local d = b:evaluate(PY_IDENT, req("example.com", 80, "http"))
        h.assert_eq(d.action, "deny")
    end)
end)

h.describe("policy evaluation: allow rules", function()
    local b = assert(bundle({ {
        name = "python",
        tier = "profile",
        selector = { profiles = { "untrusted-python" } },
        rules = { {
            name = "pypi",
            action = "allow",
            destinations = {
                hostnames = { "pypi.org" },
                hostnameSuffixes = { "pythonhosted.org" },
            },
            ports = { 443 },
            protocols = { "https" },
        } },
    } }))

    h.it("allows exact hostname matches", function()
        local d = b:evaluate(PY_IDENT, req("pypi.org", 443))
        h.assert_eq(d.action, "allow")
        h.assert_eq(d.rule, "pypi")
    end)

    h.it("allows suffix apex and subdomains", function()
        h.assert_eq(b:evaluate(PY_IDENT, req("pythonhosted.org", 443)).action, "allow")
        h.assert_eq(b:evaluate(PY_IDENT, req("files.pythonhosted.org", 443)).action, "allow")
        h.assert_eq(b:evaluate(PY_IDENT, req("a.b.files.pythonhosted.org", 443)).action, "allow")
    end)

    h.it("does not let suffixes match by substring", function()
        h.assert_eq(b:evaluate(PY_IDENT, req("evilpythonhosted.org", 443)).action, "deny")
        h.assert_eq(b:evaluate(PY_IDENT, req("pythonhosted.org.evil.com", 443)).action, "deny")
        h.assert_eq(b:evaluate(PY_IDENT, req("notpypi.org", 443)).action, "deny")
        h.assert_eq(b:evaluate(PY_IDENT, req("pypi.org.evil.com", 443)).action, "deny")
    end)

    h.it("enforces ports", function()
        h.assert_eq(b:evaluate(PY_IDENT, req("pypi.org", 80, "http")).action, "deny")
        h.assert_eq(b:evaluate(PY_IDENT, req("pypi.org", 8443)).action, "deny")
    end)

    h.it("enforces protocols", function()
        h.assert_eq(b:evaluate(PY_IDENT, req("pypi.org", 443, "tcp")).action, "deny")
        h.assert_eq(b:evaluate(PY_IDENT, req("pypi.org", 443, "tunnel")).action, "allow")
    end)

    h.it("does not apply to other identities", function()
        local other = { id = "x", namespace = "execution",
                        profile = "untrusted-node", serviceAccount = "sa" }
        h.assert_eq(b:evaluate(other, req("pypi.org", 443)).action, "deny")
    end)

    h.it("never matches hostname rules against ip literals", function()
        h.assert_eq(b:evaluate(PY_IDENT, req("151.101.0.223", 443)).action, "deny")
    end)
end)

h.describe("policy evaluation: deny overrides", function()
    local b = assert(bundle({
        {
            name = "global-baseline",
            tier = "global",
            rules = { {
                name = "no-metadata",
                action = "deny",
                destinations = { cidrs = { "169.254.0.0/16" } },
            }, {
                name = "no-telemetry",
                action = "deny",
                destinations = { hostnameSuffixes = { "telemetry.example.com" } },
            } },
        },
        {
            name = "permissive-profile",
            tier = "profile",
            selector = { profiles = { "untrusted-python" } },
            rules = { {
                name = "wide-allow",
                action = "allow",
                destinations = {
                    hostnameSuffixes = { "example.com" },
                    cidrs = { "0.0.0.0/0" },
                },
                ports = { 80, 443 },
            } },
        },
    }))

    h.it("allows what only the profile tier permits", function()
        h.assert_eq(b:evaluate(PY_IDENT, req("api.example.com", 443)).action, "allow")
    end)

    h.it("lets a global deny override a profile allow", function()
        local d = b:evaluate(PY_IDENT, req("telemetry.example.com", 443))
        h.assert_eq(d.action, "deny")
        h.assert_eq(d.reason, "policy.explicit_deny")
        h.assert_eq(d.rule, "no-telemetry")

        d = b:evaluate(PY_IDENT, req("sub.telemetry.example.com", 443))
        h.assert_eq(d.action, "deny")
    end)

    h.it("lets a global cidr deny override a wildcard allow", function()
        local d = b:evaluate(PY_IDENT, req("169.254.169.254", 80, "http"))
        h.assert_eq(d.action, "deny")
        h.assert_eq(d.rule, "no-metadata")
    end)

    h.it("denies on any port when the deny rule omits ports", function()
        h.assert_eq(b:evaluate(PY_IDENT, req("telemetry.example.com", 80, "http")).action,
            "deny")
    end)
end)

h.describe("policy evaluation: methods and paths", function()
    local b = assert(bundle({ {
        name = "github",
        tier = "profile",
        selector = { profiles = { "untrusted-python" } },
        rules = { {
            name = "repos-read",
            action = "allow",
            destinations = { hostnames = { "api.github.com" } },
            ports = { 80 },
            protocols = { "http" },
            methods = { "GET", "HEAD" },
            paths = { "/repos/*", "/repos/**" },
        } },
    } }))

    h.it("allows matching method and path", function()
        h.assert_eq(b:evaluate(PY_IDENT,
            req("api.github.com", 80, "http", "GET", "/repos/foo")).action, "allow")
        h.assert_eq(b:evaluate(PY_IDENT,
            req("api.github.com", 80, "http", "GET", "/repos/a/b/c")).action, "allow")
    end)

    h.it("denies other methods and paths", function()
        h.assert_eq(b:evaluate(PY_IDENT,
            req("api.github.com", 80, "http", "POST", "/repos/foo")).action, "deny")
        h.assert_eq(b:evaluate(PY_IDENT,
            req("api.github.com", 80, "http", "GET", "/users/foo")).action, "deny")
        h.assert_eq(b:evaluate(PY_IDENT,
            req("api.github.com", 80, "http", "GET", "/users")).action, "deny")
    end)

    h.it("denies when method or path is unknown but required", function()
        h.assert_eq(b:evaluate(PY_IDENT,
            req("api.github.com", 443, "https", nil, nil)).action, "deny")
    end)
end)

h.describe("policy limit merging", function()
    local b = assert(bundle({
        {
            name = "base", tier = "namespace",
            selector = { namespaces = { "execution" } },
            rules = { {
                name = "wide", action = "allow",
                destinations = { hostnameSuffixes = { "example.com" } },
                ports = { 443 },
                rateLimit = { requestsPerSecond = 100 },
                connections = { max = 50 },
                bandwidth = { bytesPerSecond = "10M" },
            } },
        },
        {
            name = "tight", tier = "profile",
            selector = { profiles = { "untrusted-python" } },
            rules = { {
                name = "narrow", action = "allow",
                destinations = { hostnames = { "api.example.com" } },
                ports = { 443 },
                rateLimit = { requestsPerSecond = 5 },
                connections = { max = 3 },
                bandwidth = { bytesPerSecond = "1M" },
            } },
        },
    }))

    h.it("takes the most restrictive limits across matching rules", function()
        local d = b:evaluate(PY_IDENT, req("api.example.com", 443))
        h.assert_eq(d.action, "allow")
        h.assert_eq(d.rate_limit.rps, 5)
        h.assert_eq(d.max_connections, 3)
        h.assert_eq(d.bandwidth, 1048576)
        h.assert_eq(#d.matched, 2)
    end)

    h.it("uses the single matching rule's limits otherwise", function()
        local d = b:evaluate(PY_IDENT, req("cdn.example.com", 443))
        h.assert_eq(d.rate_limit.rps, 100)
        h.assert_eq(d.max_connections, 50)
        h.assert_eq(d.bandwidth, 10485760)
    end)
end)

h.describe("policy selectors", function()
    local b = assert(bundle({
        { name = "ns", tier = "namespace", selector = { namespaces = { "execution" } },
          rules = { { name = "a", action = "allow",
                      destinations = { hostnames = { "ns.example.com" } }, ports = { 443 } } } },
        { name = "sa", tier = "pod",
          selector = { serviceAccounts = { "sandbox-runner" } },
          rules = { { name = "b", action = "allow",
                      destinations = { hostnames = { "sa.example.com" } }, ports = { 443 } } } },
        { name = "lbl", tier = "pod", selector = { labels = { tenant = "acme" } },
          rules = { { name = "c", action = "allow",
                      destinations = { hostnames = { "lbl.example.com" } }, ports = { 443 } } } },
    }))

    h.it("matches by namespace and service account", function()
        h.assert_eq(b:evaluate(PY_IDENT, req("ns.example.com", 443)).action, "allow")
        h.assert_eq(b:evaluate(PY_IDENT, req("sa.example.com", 443)).action, "allow")
    end)

    h.it("does not match a different namespace", function()
        local other = { id = "y", namespace = "other", profile = "p", serviceAccount = "z" }
        h.assert_eq(b:evaluate(other, req("ns.example.com", 443)).action, "deny")
    end)

    h.it("matches on labels only when present", function()
        h.assert_eq(b:evaluate(PY_IDENT, req("lbl.example.com", 443)).action, "deny")
        local tagged = { id = "t", namespace = "execution", profile = "p",
                         serviceAccount = "z", labels = { tenant = "acme" } }
        h.assert_eq(b:evaluate(tagged, req("lbl.example.com", 443)).action, "allow")
    end)
end)

h.describe("policy emergency deny", function()
    h.it("denies everything when the switch is engaged", function()
        local b = assert(bundle({ {
            name = "p", tier = "global",
            rules = { { name = "a", action = "allow",
                        destinations = { hostnames = { "pypi.org" } }, ports = { 443 } } },
        } }, { emergencyDeny = true }))
        local d = b:evaluate(PY_IDENT, req("pypi.org", 443))
        h.assert_eq(d.action, "deny")
        h.assert_eq(d.reason, "emergency.deny")
    end)
end)

h.describe("policy resolved cidr constraints", function()
    local b = assert(bundle({ {
        name = "pinned", tier = "profile",
        selector = { profiles = { "untrusted-python" } },
        rules = { { name = "r", action = "allow",
                    destinations = {
                        hostnames = { "api.example.com" },
                        resolvedCidrs = { "203.0.113.0/24" },
                    },
                    ports = { 443 } } },
    } }))

    h.it("accepts resolved addresses inside the constraint", function()
        local d = b:evaluate(PY_IDENT, req("api.example.com", 443))
        h.assert_eq(d.action, "allow")
        h.assert_true(b:check_resolved(d, "ipv4", 3405803777))
    end)

    h.it("rejects resolved addresses outside the constraint", function()
        local d = b:evaluate(PY_IDENT, req("api.example.com", 443))
        local ok, reason = b:check_resolved(d, "ipv4", 16909060)
        h.assert_false(ok)
        h.assert_eq(reason, "policy.resolved_cidr")
    end)
end)

h.describe("policy glob compilation", function()
    h.it("anchors patterns and keeps * inside a path segment", function()
        h.assert_true(string.find("/repos/a", policy.glob_to_pattern("/repos/*")))
        h.assert_false(string.find("/repos/a/b", policy.glob_to_pattern("/repos/*")))
        h.assert_true(string.find("/repos/a/b", policy.glob_to_pattern("/repos/**")))
        h.assert_false(string.find("/x/repos/a", policy.glob_to_pattern("/repos/*")))
    end)

    h.it("escapes regex metacharacters", function()
        h.assert_true(string.find("/a.b", policy.glob_to_pattern("/a.b")))
        h.assert_false(string.find("/axb", policy.glob_to_pattern("/a.b")))
    end)
end)

h.describe("a staleness budget that would disable the check is refused", function()
    local function compile_with(defaults)
        return policy.compile({ version = 1, defaults = defaults, policies = {} })
    end

    h.it("accepts a sensible budget", function()
        h.assert_true(compile_with({ maxStalenessSeconds = 900 }))
        h.assert_true(compile_with({ maxStalenessSeconds = 60 }))
        h.assert_true(compile_with({ maxStalenessSeconds = 86400 }))
    end)

    h.it("refuses zero, which reads as strict and behaves as off", function()
        local ok, err = compile_with({ maxStalenessSeconds = 0 })
        h.assert_nil(ok)
        h.assert_match(err, "greater than zero")
    end)

    h.it("refuses a negative budget", function()
        h.assert_nil(compile_with({ maxStalenessSeconds = -1 }))
        h.assert_nil(compile_with({ maxStalenessSeconds = -900 }))
    end)

    h.it("refuses a budget that is not a number", function()
        h.assert_nil(compile_with({ maxStalenessSeconds = "soon" }))
        h.assert_nil(compile_with({ maxStalenessSeconds = {} }))
        h.assert_nil(compile_with({ maxStalenessSeconds = true }))
    end)

    h.it("refuses a budget longer than a day", function()
        local ok, err = compile_with({ maxStalenessSeconds = 86401 })
        h.assert_nil(ok)
        h.assert_match(err, "fail%-closed budget")
    end)

    h.it("leaves the budget absent when it is not declared", function()
        h.assert_true(compile_with({}))
        h.assert_true(policy.compile({ version = 1, policies = {} }))
    end)

    h.it("refuses a non-positive ttl", function()
        h.assert_nil(policy.compile({ version = 1, ttlSeconds = 0, policies = {} }))
        h.assert_nil(policy.compile({ version = 1, ttlSeconds = -5, policies = {} }))
        h.assert_true(policy.compile({ version = 1, ttlSeconds = 300, policies = {} }))
    end)

    h.it("refuses defaults that are not an object", function()
        h.assert_nil(policy.compile({ version = 1, defaults = "none", policies = {} }))
    end)
end)

h.describe("an empty constraint list is refused rather than read as 'any'",
function()
    local function rule_with(extra)
        local r = {
            name = "probe", action = "allow",
            destinations = { hostnames = { "example.com" } },
            ports = { 443 },
        }
        for k, v in pairs(extra) do r[k] = v end
        return policy.compile({
            version = 1,
            policies = { { name = "p", tier = "profile", rules = { r } } },
        })
    end

    h.it("compiles when the fields are simply absent", function()
        h.assert_true(rule_with({}))
    end)

    h.it("refuses an empty protocols list, which would widen the rule", function()
        local ok, err = rule_with({ protocols = {} })
        h.assert_nil(ok, "protocols: [] must not silently mean every protocol")
        h.assert_match(err, "empty")
    end)

    h.it("refuses an empty methods list", function()
        local ok, err = rule_with({ methods = {} })
        h.assert_nil(ok, "methods: [] must not silently mean every method")
        h.assert_match(err, "empty")
    end)

    h.it("refuses an empty paths list", function()
        local ok, err = rule_with({ paths = {} })
        h.assert_nil(ok, "paths: [] must not silently mean every path")
        h.assert_match(err, "empty")
    end)

    h.it("refuses an empty ports list on an allow rule", function()
        local ok, err = policy.compile({
            version = 1,
            policies = { { name = "p", tier = "profile", rules = { {
                name = "probe", action = "allow",
                destinations = { hostnames = { "example.com" } },
                ports = {},
            } } } },
        })
        h.assert_nil(ok)
        h.assert_match(err, "empty")
    end)

    h.it("still compiles a populated list", function()
        h.assert_true(rule_with({ protocols = { "https" } }))
        h.assert_true(rule_with({ protocols = { "http" }, methods = { "GET" } }))
        h.assert_true(rule_with({ protocols = { "http" }, paths = { "/a/**" } }))
    end)

    h.it("applies to deny rules too, where an empty list widens the deny",
    function()
        local ok = policy.compile({
            version = 1,
            policies = { { name = "p", tier = "global", rules = { {
                name = "probe", action = "deny",
                destinations = { hostnames = { "example.com" } },
                protocols = {},
            } } } },
        })
        h.assert_nil(ok, "a surprising deny is still a surprise")
    end)
end)

h.describe("a policy cannot escape its own selector", function()
    local function with_selector(sel)
        return policy.compile({
            version = 1,
            policies = { {
                name = "scoped", tier = "profile", selector = sel,
                rules = { {
                    name = "r", action = "allow",
                    destinations = { hostnames = { "example.com" } },
                    ports = { 443 }, protocols = { "https" },
                } },
            } },
        })
    end

    h.it("compiles a populated selector", function()
        h.assert_true(with_selector({ profiles = { "untrusted-python" } }))
        h.assert_true(with_selector({ namespaces = { "execution" } }))
        h.assert_true(with_selector(nil))
    end)

    h.it("refuses an empty selector list, which would match everyone", function()
        for _, sel in ipairs({
            { profiles = {} }, { namespaces = {} },
            { serviceAccounts = {} }, { identities = {} },
        }) do
            local ok, err = with_selector(sel)
            h.assert_nil(ok, "an empty selector list must not compile")
            h.assert_match(err, "empty")
        end
    end)

    h.it("a scoped policy does not apply to an identity outside it", function()
        local b = assert(with_selector({ profiles = { "untrusted-python" } }))
        local inside = { id = "a", namespace = "-", profile = "untrusted-python",
            serviceAccount = "-", key = "a" }
        local outside = { id = "b", namespace = "-", profile = "agent-sandbox",
            serviceAccount = "-", key = "b" }
        h.assert_eq(b:evaluate(inside,
            req("example.com", 443, "https")).action, "allow")
        h.assert_eq(b:evaluate(outside,
            req("example.com", 443, "https")).action, "deny")
    end)
end)

h.describe("label-scoped policy does not leak between identities", function()
    local b = assert(policy.compile({
        version = 1,
        policies = { {
            name = "acme-only", tier = "profile",
            selector = { labels = { tenant = "acme" } },
            rules = { {
                name = "r", action = "allow",
                destinations = { hostnames = { "artifacts.acme.internal" } },
                ports = { 443 }, protocols = { "https" },
            } },
        } },
    }))

    local function ident(labels)
        return { id = "agent", namespace = "execution", profile = "-",
            serviceAccount = "-", key = "k", labels = labels }
    end

    h.it("allows the identity the labels select", function()
        h.assert_eq(b:evaluate(ident({ tenant = "acme" }),
            req("artifacts.acme.internal", 443, "https")).action, "allow")
    end)

    h.it("denies an identity that differs only by label", function()
        h.assert_eq(b:evaluate(ident({ tenant = "dev" }),
            req("artifacts.acme.internal", 443, "https")).action, "deny")
    end)

    h.it("does not leak the cached decision in either arrival order", function()
        local fresh = assert(policy.compile({
            version = 1,
            policies = { {
                name = "acme-only", tier = "profile",
                selector = { labels = { tenant = "acme" } },
                rules = { {
                    name = "r", action = "allow",
                    destinations = { hostnames = { "artifacts.acme.internal" } },
                    ports = { 443 }, protocols = { "https" },
                } },
            } },
        }))
        h.assert_eq(fresh:evaluate(ident({ tenant = "acme" }),
            req("artifacts.acme.internal", 443, "https")).action, "allow")
        h.assert_eq(fresh:evaluate(ident({ tenant = "dev" }),
            req("artifacts.acme.internal", 443, "https")).action, "deny",
            "the dev identity must not inherit acme's cached rule set")

        local reverse = assert(policy.compile({
            version = 1,
            policies = { {
                name = "acme-only", tier = "profile",
                selector = { labels = { tenant = "acme" } },
                rules = { {
                    name = "r", action = "allow",
                    destinations = { hostnames = { "artifacts.acme.internal" } },
                    ports = { 443 }, protocols = { "https" },
                } },
            } },
        }))
        h.assert_eq(reverse:evaluate(ident({ tenant = "dev" }),
            req("artifacts.acme.internal", 443, "https")).action, "deny")
        h.assert_eq(reverse:evaluate(ident({ tenant = "acme" }),
            req("artifacts.acme.internal", 443, "https")).action, "allow",
            "the acme identity must not inherit dev's cached denial")
    end)

    h.it("separates identities with no labels from labelled ones", function()
        h.assert_eq(b:evaluate(ident(nil),
            req("artifacts.acme.internal", 443, "https")).action, "deny")
    end)
end)

h.describe("a constraint the gateway cannot read is refused, not ignored",
function()
    local function rule(extra)
        local r = {
            name = "probe", action = "allow",
            destinations = { hostnames = { "example.com" } },
            ports = { 443 },
        }
        for k, v in pairs(extra) do r[k] = v end
        return policy.compile({
            version = 1,
            policies = { { name = "p", tier = "profile", rules = { r } } },
        })
    end

    h.it("refuses methods on an https rule", function()
        local ok, err = rule({ protocols = { "https" }, methods = { "GET" } })
        h.assert_nil(ok, "the gateway never sees a method inside a tunnel")
        h.assert_match(err, "tunnelled")
    end)

    h.it("refuses paths on an https rule", function()
        h.assert_nil(rule({ protocols = { "https" }, paths = { "/a/**" } }))
    end)

    h.it("refuses methods on a tcp rule", function()
        h.assert_nil(rule({ protocols = { "tcp" }, methods = { "GET" } }))
    end)

    h.it("refuses methods on a rule with no protocol constraint", function()
        h.assert_nil(rule({ methods = { "GET" } }),
            "no protocol constraint means the rule can match a tunnel")
    end)

    h.it("refuses them on deny rules too, where the silence was a bypass",
    function()
        local ok, err = policy.compile({
            version = 1,
            policies = { { name = "p", tier = "global", rules = { {
                name = "deny-writes", action = "deny",
                destinations = { hostnameSuffixes = { "npmjs.org" } },
                ports = { 443 }, protocols = { "https" },
                methods = { "PUT", "POST" },
            } } } },
        })
        h.assert_nil(ok, "an inert deny rule is worse than no deny rule")
        h.assert_match(err, "tunnelled")
    end)

    h.it("accepts them on a plaintext http rule", function()
        h.assert_true(rule({ ports = { 80 }, protocols = { "http" },
            methods = { "GET" }, paths = { "/a/**" } }))
    end)

    h.it("refuses tls.inspect, which nothing implements", function()
        local ok, err = rule({ protocols = { "https" },
            tls = { inspect = true } })
        h.assert_nil(ok)
        h.assert_match(err, "not implemented")
    end)
end)

h.describe("requireSni merges toward the stricter setting", function()
    h.it("a global rule cannot switch off a pod rule's requirement", function()
        local b = assert(policy.compile({
            version = 1,
            policies = {
                { name = "pod-rule", tier = "pod", rules = { {
                    name = "strict", action = "allow",
                    destinations = { hostnames = { "api.vendor.com" } },
                    ports = { 443 }, protocols = { "https" },
                    tls = { requireSni = true },
                } } },
                { name = "global-rule", tier = "global", rules = { {
                    name = "lax", action = "allow",
                    destinations = { hostnames = { "api.vendor.com" } },
                    ports = { 443 }, protocols = { "https" },
                    tls = { requireSni = false },
                } } },
            },
        }))
        local d = b:evaluate(PY_IDENT, req("api.vendor.com", 443, "https"))
        h.assert_eq(d.action, "allow")
        h.assert_true(d.tls and d.tls.require_sni,
            "the stricter requireSni must survive the merge")
    end)
end)

h.describe("a limit that does not parse is refused, never dropped", function()
    local function with_limit(field, value)
        local rule = {
            name = "r", action = "allow",
            destinations = { hostnames = { "a.test" } },
            ports = { "443" }, protocols = { "https" },
        }
        for k, v in pairs(value) do rule[k] = v end
        return bundle({ {
            name = "p", priority = 1, selector = {},
            rules = { rule },
        } })
    end

    h.it("refuses a request size it cannot read", function()
        for _, bad in ipairs({ "unlimited", "10 megabytes", "-5", "1e6",
            "ten", "", "0x10", true }) do
            local b, err = with_limit("requestSize", { requestSize = bad })
            h.assert_nil(b, "requestSize " .. tostring(bad)
                .. " must not compile")
            h.assert_match(err, "requestSize")
        end
    end)

    h.it("refuses a response size it cannot read", function()
        local b, err = with_limit("responseSize", { responseSize = "big" })
        h.assert_nil(b)
        h.assert_match(err, "responseSize")
    end)

    h.it("still accepts the sizes an operator actually writes", function()
        for _, good in ipairs({ "1M", "10MB", "512K", "2G", "1048576", 4096 }) do
            local b = with_limit("requestSize", { requestSize = good })
            h.assert_true(b ~= nil, "requestSize " .. tostring(good)
                .. " must compile")
        end
    end)

    h.it("bounds a request size", function()
        h.assert_nil(with_limit("requestSize", { requestSize = "0" }))
        h.assert_nil(with_limit("requestSize", { requestSize = "2048G" }))
    end)

    h.it("refuses a bandwidth it cannot read", function()
        local b, err = with_limit("bandwidth",
            { bandwidth = { bytesPerSecond = "fast" } })
        h.assert_nil(b)
        h.assert_match(err, "bandwidth")
    end)

    h.it("bounds a burst", function()
        local b, err = with_limit("rateLimit", { rateLimit = {
            requestsPerSecond = 10, burst = 999999999 } })
        h.assert_nil(b, "an unbounded burst defeats the rate limit")
        h.assert_match(err, "burst")

        h.assert_nil(with_limit("rateLimit", { rateLimit = {
            requestsPerSecond = 10, burst = 0 } }))
        h.assert_nil(with_limit("rateLimit", { rateLimit = {
            requestsPerSecond = 10, burst = -1 } }))
        h.assert_nil(with_limit("rateLimit", { rateLimit = {
            requestsPerSecond = 100, burst = 10 } }),
            "a burst below the rate would throttle below what the rule says")
        h.assert_nil(with_limit("rateLimit", { rateLimit = {
            requestsPerSecond = "ten" } }))
    end)

    h.it("keeps a burst an operator would write", function()
        local b = with_limit("rateLimit", { rateLimit = {
            requestsPerSecond = 10, burst = 20 } })
        h.assert_true(b ~= nil)
    end)
end)
