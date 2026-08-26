local h = require("harness")
local limits = require("ro.limits")

h.describe("limits initialisation", function()
    h.it("binds to a shared dictionary", function()
        h.assert_true(limits.init("ro_limits"))
    end)

    h.it("reports a missing dictionary", function()
        local ok, err = limits.init("no_such_dict")
        h.assert_nil(ok)
        h.assert_match(err, "shared dict")
        limits.init("ro_limits")
    end)
end)

h.describe("limits.check_rate", function()
    h.it("permits traffic under the limit", function()
        local key = "rate-under-" .. tostring(math.random(1, 1e9))
        for i = 1, 5 do
            h.assert_true(limits.check_rate(key, 100, 100), "request " .. i)
        end
    end)

    h.it("rejects traffic over the limit", function()
        local key = "rate-over-" .. tostring(math.random(1, 1e9))
        local rejected = 0
        for _ = 1, 40 do
            if not limits.check_rate(key, 5, 5) then
                rejected = rejected + 1
            end
        end
        h.assert_true(rejected > 0, "expected some rejections")
    end)

    h.it("keeps separate budgets per key", function()
        local a = "rate-a-" .. tostring(math.random(1, 1e9))
        local b = "rate-b-" .. tostring(math.random(1, 1e9))
        for _ = 1, 30 do
            limits.check_rate(a, 2, 2)
        end
        h.assert_true(limits.check_rate(b, 100, 100),
            "one identity's budget must not affect another")
    end)

    h.it("is a no-op when no rate is configured", function()
        h.assert_true(limits.check_rate("anything", nil))
        h.assert_true(limits.check_rate("anything", 0))
    end)

    h.it("returns a retry hint when rejecting", function()
        local key = "rate-hint-" .. tostring(math.random(1, 1e9))
        for _ = 1, 50 do
            local ok, remaining, retry = limits.check_rate(key, 1, 1)
            if not ok then
                h.assert_true(retry ~= nil and retry >= 0, "retry hint present")
                return
            end
        end
        error("expected a rejection within 50 attempts")
    end)
end)

h.describe("limits connection counting", function()
    h.it("counts up and down", function()
        local key = "conn-" .. tostring(math.random(1, 1e9))
        limits.reset(key)
        local ok, current = limits.acquire_conn(key, 3)
        h.assert_true(ok)
        h.assert_eq(current, 1)
        ok, current = limits.acquire_conn(key, 3)
        h.assert_eq(current, 2)
        limits.release_conn(key)
        h.assert_eq(limits.conn_count(key), 1)
        limits.release_conn(key)
        h.assert_eq(limits.conn_count(key), 0)
    end)

    h.it("refuses connections beyond the cap and does not leak the count", function()
        local key = "conn-cap-" .. tostring(math.random(1, 1e9))
        limits.reset(key)
        h.assert_true(limits.acquire_conn(key, 2))
        h.assert_true(limits.acquire_conn(key, 2))
        local ok = limits.acquire_conn(key, 2)
        h.assert_false(ok)
        h.assert_eq(limits.conn_count(key), 2,
            "a refused acquire must not inflate the counter")
        limits.release_conn(key)
        h.assert_true(limits.acquire_conn(key, 2),
            "a slot must be reusable after release")
    end)

    h.it("never lets the counter go negative", function()
        local key = "conn-neg-" .. tostring(math.random(1, 1e9))
        limits.reset(key)
        limits.release_conn(key)
        limits.release_conn(key)
        h.assert_true(limits.conn_count(key) >= 0)
    end)

    h.it("is a no-op when no cap is configured", function()
        local key = "conn-none-" .. tostring(math.random(1, 1e9))
        limits.reset(key)
        for _ = 1, 20 do
            h.assert_true(limits.acquire_conn(key, nil))
        end
    end)
end)

h.describe("limits bandwidth throttle", function()
    h.it("returns no delay when under the configured rate", function()
        local t = limits.throttle(1000000)
        h.assert_eq(t:consume(10), 0)
    end)

    h.it("returns a delay once the budget is exceeded", function()
        local t = limits.throttle(1000)
        local delay = t:consume(100000)
        h.assert_true(delay > 0, "expected a positive delay, got " .. tostring(delay))
    end)

    h.it("caps a single delay so a connection cannot stall forever", function()
        local t = limits.throttle(1)
        h.assert_true(t:consume(1000000) <= 5)
    end)

    h.it("is inert when no bandwidth cap is set", function()
        local t = limits.throttle(nil)
        h.assert_eq(t:consume(1000000), 0)
        t = limits.throttle(0)
        h.assert_eq(t:consume(1000000), 0)
    end)

    h.it("reports an observed rate", function()
        local t = limits.throttle(1000)
        t:consume(500)
        h.assert_true(t:rate() >= 0)
    end)
end)

h.describe("a limit that cannot be enforced refuses rather than passes", function()
    h.it("denies a configured rate limit when the store is gone", function()
        h.assert_true(limits.init("no_such_dict") == nil)
        h.assert_false(limits.available())
        local ok, _, _, err = limits.check_rate("k", 10, 10)
        h.assert_false(ok, "a configured rate limit must not silently vanish")
        h.assert_eq(err, "limit.unavailable")
        h.assert_true(limits.init("ro_limits"))
    end)

    h.it("denies a configured connection limit when the store is gone", function()
        h.assert_true(limits.init("no_such_dict") == nil)
        local ok, _, err = limits.acquire_conn("k", 4)
        h.assert_false(ok, "a configured connection limit must not silently vanish")
        h.assert_eq(err, "limit.unavailable")
        h.assert_true(limits.init("ro_limits"))
    end)

    h.it("stays inert when no limit was configured at all", function()
        h.assert_true(limits.init("no_such_dict") == nil)
        h.assert_true(limits.check_rate("k", nil))
        h.assert_true(limits.check_rate("k", 0))
        h.assert_true(limits.acquire_conn("k", nil))
        h.assert_true(limits.acquire_conn("k", 0))
        h.assert_true(limits.init("ro_limits"))
    end)

    h.it("reports the store as available once bound", function()
        h.assert_true(limits.init("ro_limits"))
        h.assert_true(limits.available())
    end)
end)

h.describe("a held connection slot does not expire out from under the limit", function()
    h.it("keeps counting while the slot is held", function()
        h.assert_true(limits.init("ro_limits"))
        local key = "ttl-probe-" .. tostring(math.floor(os.time()))
        limits.reset(key)
        local ok1 = limits.acquire_conn(key, 2)
        local ok2 = limits.acquire_conn(key, 2)
        h.assert_true(ok1)
        h.assert_true(ok2)
        local ok3 = limits.acquire_conn(key, 2)
        h.assert_false(ok3, "a third connection must be refused")
        h.assert_eq(limits.conn_count(key), 2)
        limits.release_conn(key)
        limits.release_conn(key)
        h.assert_eq(limits.conn_count(key), 0)
        limits.reset(key)
    end)

    h.it("never lets the count drift below zero", function()
        local key = "drift-probe"
        limits.reset(key)
        limits.release_conn(key)
        limits.release_conn(key)
        h.assert_true(limits.conn_count(key) >= 0)
        limits.reset(key)
    end)
end)
