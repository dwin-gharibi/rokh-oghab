local M = { _VERSION = "1.0.0" }

local state = {
    suites = {},
    current = nil,
    passed = 0,
    failed = 0,
    skipped = 0,
    failures = {},
    filter = os.getenv("RO_TEST_FILTER"),
}

local function fmt(v, depth)
    depth = depth or 0
    local t = type(v)
    if t == "string" then return string.format("%q", v) end
    if t == "number" or t == "boolean" or t == "nil" then return tostring(v) end
    if t == "table" then
        if depth > 3 then return "{...}" end
        local parts = {}
        local n = 0
        local keys = {}
        for k in pairs(v) do keys[#keys + 1] = k end
        table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
        for _, k in ipairs(keys) do
            n = n + 1
            if n > 12 then parts[#parts + 1] = "..." break end
            parts[#parts + 1] = tostring(k) .. "=" .. fmt(v[k], depth + 1)
        end
        return "{" .. table.concat(parts, ", ") .. "}"
    end
    return tostring(v)
end

M.fmt = fmt

local function deep_equal(a, b)
    if a == b then return true end
    if type(a) ~= "table" or type(b) ~= "table" then return false end
    for k, v in pairs(a) do
        if not deep_equal(v, b[k]) then return false end
    end
    for k in pairs(b) do
        if a[k] == nil then return false end
    end
    return true
end

M.deep_equal = deep_equal

local function record_pass(name)
    state.passed = state.passed + 1
    io.write("    ok   ", name, "\n")
end

local function record_fail(name, detail)
    state.failed = state.failed + 1
    state.failures[#state.failures + 1] = { suite = state.current, name = name, detail = detail }
    io.write("    FAIL ", name, "\n         ", tostring(detail), "\n")
end

function M.describe(name, fn)
    if state.filter and not string.find(name, state.filter, 1, true) then
        return
    end
    state.current = name
    io.write("\n  ", name, "\n")
    local ok, err = pcall(fn)
    if not ok then
        record_fail(name .. " <suite body>", err)
    end
    state.current = nil
end

function M.it(name, fn)
    local ok, err = pcall(fn)
    if ok then
        record_pass(name)
    else
        record_fail(name, err)
    end
end

local function fail(msg)
    error(msg, 3)
end

function M.assert_true(v, msg)
    if not v then
        fail((msg or "expected truthy") .. " (got " .. fmt(v) .. ")")
    end
end

function M.assert_false(v, msg)
    if v then
        fail((msg or "expected falsy") .. " (got " .. fmt(v) .. ")")
    end
end

function M.assert_nil(v, msg)
    if v ~= nil then
        fail((msg or "expected nil") .. " (got " .. fmt(v) .. ")")
    end
end

function M.assert_eq(got, want, msg)
    if got ~= want then
        fail((msg or "values differ") .. ": got " .. fmt(got) .. ", want " .. fmt(want))
    end
end

function M.assert_ne(got, other, msg)
    if got == other then
        fail((msg or "values should differ") .. ": both " .. fmt(got))
    end
end

function M.assert_deep_eq(got, want, msg)
    if not deep_equal(got, want) then
        fail((msg or "tables differ") .. ": got " .. fmt(got) .. ", want " .. fmt(want))
    end
end

function M.assert_match(s, pattern, msg)
    if type(s) ~= "string" or not string.find(s, pattern) then
        fail((msg or "pattern not found") .. ": " .. fmt(s) .. " !~ " .. fmt(pattern))
    end
end

function M.assert_error(fn, msg)
    local ok = pcall(fn)
    if ok then
        fail(msg or "expected error but call succeeded")
    end
end

function M.skip(name, why)
    state.skipped = state.skipped + 1
    io.write("    skip ", name, " (", tostring(why or ""), ")\n")
end

function M.summary()
    io.write("\n")
    io.write(string.rep("-", 62), "\n")
    io.write(string.format("passed=%d failed=%d skipped=%d\n",
        state.passed, state.failed, state.skipped))
    if state.failed > 0 then
        io.write("\nFAILURES:\n")
        for _, f in ipairs(state.failures) do
            io.write(string.format("  [%s] %s\n    %s\n",
                tostring(f.suite), f.name, tostring(f.detail)))
        end
    end
    io.write(string.rep("-", 62), "\n")
    return state.failed
end

function M.exit_code()
    return state.failed == 0 and 0 or 1
end

return M
