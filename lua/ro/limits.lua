local util = require("ro.util")

local _M = { _VERSION = "1.0.0" }

local floor = math.floor
local dict

local WINDOW_TTL = 3
local CONN_TTL = 3600
local MIN_THROTTLE_DELAY = 0.001

function _M.init(dict_name)
    dict = ngx.shared[dict_name or "ro_limits"]
    if not dict then
        return nil, "shared dict not configured: " .. tostring(dict_name)
    end
    return true
end

function _M.available()
    return dict ~= nil
end

function _M.check_rate(key, rps, burst)
    if not rps or rps <= 0 then
        return true
    end
    if not dict then
        return false, 0, 1, "limit.unavailable"
    end
    burst = burst or rps
    local now = util.now()
    local window = floor(now)
    local fraction = now - window

    local cur_key = "r:" .. key .. ":" .. window
    local prev_key = "r:" .. key .. ":" .. (window - 1)

    local prev = dict:get(prev_key) or 0
    local cur = dict:incr(cur_key, 1, 0, WINDOW_TTL)
    if not cur then
        return false, 0, 1, "ratelimit-store-error"
    end

    local estimated = prev * (1 - fraction) + cur
    local ceiling = rps + (burst > rps and (burst - rps) or 0)
    if estimated > ceiling then
        return false, 0, 1 - fraction
    end
    local remaining = ceiling - estimated
    if remaining < 0 then remaining = 0 end
    return true, remaining
end

function _M.acquire_conn(key, max)
    if not max or max <= 0 then
        return true, 0
    end
    if not dict then
        return false, 0, "limit.unavailable"
    end
    local ckey = "c:" .. key
    local current, err = dict:incr(ckey, 1, 0, CONN_TTL)
    if not current then
        return false, 0, err or "conn-store-error"
    end
    if dict.expire then
        pcall(dict.expire, dict, ckey, CONN_TTL)
    end
    if current > max then
        dict:incr(ckey, -1)
        return false, current - 1
    end
    return true, current
end

function _M.release_conn(key)
    if not dict then
        return
    end
    local ckey = "c:" .. key
    local current = dict:incr(ckey, -1)
    if current and current < 0 then
        dict:set(ckey, 0, CONN_TTL)
    end
end

function _M.conn_count(key)
    if not dict then return 0 end
    return dict:get("c:" .. key) or 0
end

function _M.reset(key)
    if not dict then return end
    dict:delete("c:" .. key)
end

local throttle_mt = {}
throttle_mt.__index = throttle_mt

function _M.throttle(bytes_per_second)
    return setmetatable({
        bps = bytes_per_second,
        bytes = 0,
        start = util.monotonic(),
    }, throttle_mt)
end

function throttle_mt:consume(n)
    if not self.bps or self.bps <= 0 then
        return 0
    end
    self.bytes = self.bytes + n
    local elapsed = util.monotonic() - self.start
    if elapsed <= 0 then
        elapsed = 0.000001
    end
    local allowed_time = self.bytes / self.bps
    local delay = allowed_time - elapsed
    if delay >= MIN_THROTTLE_DELAY then
        if delay > 5 then
            delay = 5
        end
        return delay
    end
    if elapsed > 60 then
        self.bytes = 0
        self.start = util.monotonic()
    end
    return 0
end

function throttle_mt:rate()
    local elapsed = util.monotonic() - self.start
    if elapsed <= 0 then return 0 end
    return self.bytes / elapsed
end

function _M.stats()
    if not dict then
        return {}
    end
    return {
        capacity = dict.capacity and dict:capacity() or nil,
        free = dict.free_space and dict:free_space() or nil,
    }
end

return _M
