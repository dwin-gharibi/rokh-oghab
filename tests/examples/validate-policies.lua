local yaml = require("roc.yaml")
local store = require("roc.store")
local policy = require("ro.policy")

local function say(fmt, ...)
    io.stdout:write(string.format(fmt, ...), "\n")
end

local files = {}
for i = 1, #arg do
    files[#files + 1] = arg[i]
end

local failed = 0
local checked = 0

for _, path in ipairs(files) do
    checked = checked + 1
    local fh = io.open(path, "r")
    if not fh then
        say("    FAIL %s: cannot open", path)
        failed = failed + 1
    else
        local text = fh:read("*a")
        fh:close()
        local doc, err = yaml.parse(text)
        if not doc then
            say("    FAIL %s\n         yaml: %s", path, tostring(err))
            failed = failed + 1
        else
            local name = (doc.metadata and doc.metadata.name) or "unnamed"
            local normalized, nerr = store.normalize_policy(doc, name)
            if not normalized then
                say("    FAIL %s\n         normalize: %s", path, tostring(nerr))
                failed = failed + 1
            else
                local compiled, cerr = policy.compile({
                    version = 1,
                    policies = { normalized },
                })
                if not compiled then
                    say("    FAIL %s\n         compile: %s", path, tostring(cerr))
                    failed = failed + 1
                else
                    local allows, denies = 0, 0
                    for _, p in ipairs(compiled.policies) do
                        allows = allows + #p.allow_rules
                        denies = denies + #p.deny_rules
                    end
                    say("    ok   %-44s tier=%-9s allow=%d deny=%d",
                        path, normalized.tier, allows, denies)
                end
            end
        end
    end
end

say("")
say("checked=%d failed=%d", checked, failed)
os.exit(failed == 0 and 0 or 1)
