local h = require("harness")

local modules = {
    "test_ipaddr",
    "test_target",
    "test_guard",
    "test_policy",
    "test_http",
    "test_yaml",
    "test_reader",
    "test_digest",
    "test_otel",
    "test_tls",
    "test_dns",
    "test_identity",
    "test_metrics",
    "test_limits",
    "test_config",
    "test_httpd",
    "test_store",
    "test_reasons",
    "test_redirect",
    "test_adminsource",
    "test_httpc",
    "test_signing",
}

io.write("Rokh Oghab unit test suite\n")
io.write(string.rep("=", 62), "\n")

for _, name in ipairs(modules) do
    require(name)
end

h.summary()
os.exit(h.exit_code())
