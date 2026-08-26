local h = require("harness")
local yaml = require("roc.yaml")

h.describe("yaml scalars", function()
    h.it("parses simple key/value maps", function()
        h.assert_deep_eq(yaml.parse("a: 1\nb: two\n"), { a = 1, b = "two" })
    end)

    h.it("parses booleans and nulls", function()
        local v = yaml.parse("t: true\nf: false\ny: yes\nn: no\nz: null\nw: ~\n")
        h.assert_eq(v.t, true)
        h.assert_eq(v.f, false)
        h.assert_eq(v.y, true)
        h.assert_eq(v.n, false)
        h.assert_nil(v.z)
        h.assert_nil(v.w)
    end)

    h.it("parses quoted strings", function()
        local v = yaml.parse([[
a: "hello world"
b: 'single'
c: "with: colon"
d: "escaped \"quote\""
e: "123"
]])
        h.assert_eq(v.a, "hello world")
        h.assert_eq(v.b, "single")
        h.assert_eq(v.c, "with: colon")
        h.assert_eq(v.d, 'escaped "quote"')
        h.assert_eq(v.e, "123")
    end)

    h.it("strips comments outside quotes", function()
        local v = yaml.parse('a: 1 # trailing\n# whole line\nb: "x # y"\n')
        h.assert_eq(v.a, 1)
        h.assert_eq(v.b, "x # y")
    end)

    h.it("rejects tab indentation", function()
        local v, err = yaml.parse("a:\n\tb: 1\n")
        h.assert_nil(v)
        h.assert_match(err, "tab")
    end)
end)

h.describe("yaml collections", function()
    h.it("parses nested maps", function()
        h.assert_deep_eq(yaml.parse([[
spec:
  defaultAction: deny
  limits:
    connections: 50
]]), { spec = { defaultAction = "deny", limits = { connections = 50 } } })
    end)

    h.it("parses sequences of scalars", function()
        h.assert_deep_eq(yaml.parse([[
ports:
  - 80
  - 443
hosts:
  - pypi.org
  - files.pythonhosted.org
]]), {
            ports = { 80, 443 },
            hosts = { "pypi.org", "files.pythonhosted.org" },
        })
    end)

    h.it("parses sequences of maps", function()
        h.assert_deep_eq(yaml.parse([[
rules:
  - name: pypi
    action: allow
    ports:
      - 443
  - name: block
    action: deny
]]), {
            rules = {
                { name = "pypi", action = "allow", ports = { 443 } },
                { name = "block", action = "deny" },
            },
        })
    end)

    h.it("parses flow collections", function()
        local v = yaml.parse('ports: [80, 443]\nmeta: {a: 1, b: two}\nempty: []\n')
        h.assert_deep_eq(v.ports, { 80, 443 })
        h.assert_deep_eq(v.meta, { a = 1, b = "two" })
        h.assert_deep_eq(v.empty, {})
    end)

    h.it("parses a realistic egress policy document", function()
        local doc = yaml.parse([[
apiVersion: rokhoghab.io/v1
kind: EgressPolicy
metadata:
  name: python-sandbox
  tier: profile
spec:
  defaultAction: deny
  selector:
    profiles:
      - untrusted-python
  rules:
    - name: python-package-index
      action: allow
      destinations:
        hostnames:
          - pypi.org
        hostnameSuffixes:
          - pythonhosted.org
      ports: [443]
      protocols:
        - https
      rateLimit:
        requestsPerSecond: 20
      bandwidth:
        bytesPerSecond: 10M
]])
        h.assert_eq(doc.apiVersion, "rokhoghab.io/v1")
        h.assert_eq(doc.kind, "EgressPolicy")
        h.assert_eq(doc.metadata.name, "python-sandbox")
        h.assert_eq(doc.spec.defaultAction, "deny")
        h.assert_deep_eq(doc.spec.selector.profiles, { "untrusted-python" })
        h.assert_eq(#doc.spec.rules, 1)
        local rule = doc.spec.rules[1]
        h.assert_eq(rule.name, "python-package-index")
        h.assert_eq(rule.action, "allow")
        h.assert_deep_eq(rule.destinations.hostnames, { "pypi.org" })
        h.assert_deep_eq(rule.destinations.hostnameSuffixes, { "pythonhosted.org" })
        h.assert_deep_eq(rule.ports, { 443 })
        h.assert_deep_eq(rule.protocols, { "https" })
        h.assert_eq(rule.rateLimit.requestsPerSecond, 20)
        h.assert_eq(rule.bandwidth.bytesPerSecond, "10M")
    end)

    h.it("handles a leading document marker", function()
        h.assert_deep_eq(yaml.parse("---\na: 1\n"), { a = 1 })
    end)

    h.it("handles empty documents", function()
        h.assert_deep_eq(yaml.parse(""), {})
        h.assert_deep_eq(yaml.parse("# only a comment\n"), {})
    end)

    h.it("rejects inconsistent indentation", function()
        local v, err = yaml.parse("a: 1\n  b: 2\n")
        h.assert_nil(v)
        h.assert_match(err, "indentation")
    end)

    h.it("distinguishes yaml from json input", function()
        h.assert_true(yaml.looks_like_yaml("a: 1"))
        h.assert_false(yaml.looks_like_yaml('{"a":1}'))
        h.assert_false(yaml.looks_like_yaml("  [1,2]"))
    end)
end)

h.describe("the parser refuses documents that would be read wrongly", function()
    h.it("refuses a duplicate mapping key rather than taking the last", function()
        local doc, err = yaml.parse(
            "spec:\n  rules:\n    - name: r\n      action: deny\n      action: allow\n")
        h.assert_nil(doc)
        h.assert_true(err ~= nil and err:find("duplicate mapping key") ~= nil)
    end)

    h.it("refuses an unterminated flow instead of dropping the key", function()
        local doc, err = yaml.parse(
            "spec:\n  rules:\n    - name: r\n      paths: [\"/repos/**\"\n")
        h.assert_nil(doc)
        h.assert_true(err ~= nil)
    end)

    h.it("bounds flow nesting instead of overflowing the stack", function()
        local deep = "k: " .. string.rep("[", 5000) .. string.rep("]", 5000)
        local doc, err = yaml.parse(deep)
        h.assert_nil(doc)
        h.assert_true(err ~= nil)
    end)

    h.it("still parses an ordinary policy document", function()
        local doc = yaml.parse(
            "metadata: {name: p, tier: profile}\n" ..
            "spec:\n  rules:\n    - name: pypi\n      action: allow\n" ..
            "      ports: [443]\n      destinations: {hostnames: [pypi.org]}\n")
        h.assert_eq(doc.spec.rules[1].name, "pypi")
        h.assert_eq(doc.spec.rules[1].ports[1], 443)
        h.assert_eq(doc.spec.rules[1].destinations.hostnames[1], "pypi.org")
    end)
end)
