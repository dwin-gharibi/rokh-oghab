local cjson = require("cjson.safe")
local util = require("ro.util")

local _M = { _VERSION = "1.0.0" }

local concat = table.concat

local conf = {
    path = "/dev/stdout",
    buffer_max = 64,
    flush_interval = 0.2,
    capacity = 4096,
    log_paths = false,
    log_query = false,
    enabled = true,
    component = "ro-gateway",
}

local handle
local buffer = {}
local buffer_n = 0
local audit_dict
local timer_started = false

local LEVELS = { debug = 1, info = 2, warn = 3, error = 4 }
local level_num = 2

local function ngx_log(level, msg)
    if not ngx or not ngx.log then
        io.stderr:write(msg, "\n")
        return
    end
    if level == "error" then
        ngx.log(ngx.ERR, msg)
    elseif level == "warn" then
        ngx.log(ngx.WARN, msg)
    elseif level == "debug" then
        ngx.log(ngx.DEBUG, msg)
    else
        ngx.log(ngx.NOTICE, msg)
    end
end

function _M.init(opts)
    opts = opts or {}
    for k, v in pairs(opts) do
        if conf[k] ~= nil and v ~= nil then
            conf[k] = v
        end
    end
    if opts.level and LEVELS[opts.level] then
        level_num = LEVELS[opts.level]
    end
    if opts.dict then
        audit_dict = ngx.shared[opts.dict]
    end
    if conf.path and conf.path ~= "" and conf.path ~= "none" then
        local fh, err = io.open(conf.path, "a")
        if fh then
            fh:setvbuf("line")
            handle = fh
        else
            ngx_log("warn", "ro: cannot open audit sink " .. tostring(conf.path)
                .. ": " .. tostring(err) .. ", falling back to error log")
        end
    end
    return true
end

function _M.flush()
    if buffer_n == 0 then
        return
    end
    local payload = concat(buffer, "\n", 1, buffer_n)
    buffer_n = 0
    buffer = {}
    if handle then
        local ok = pcall(function()
            handle:write(payload, "\n")
            handle:flush()
        end)
        if ok then
            return
        end
        handle = nil
    end
    ngx_log("info", payload)
end

local function schedule_flush()
    if timer_started or not ngx or not ngx.timer then
        return
    end
    timer_started = true
    local function tick(premature)
        if premature then
            _M.flush()
            return
        end
        _M.flush()
        local ok = ngx.timer.at(conf.flush_interval, tick)
        if not ok then
            timer_started = false
        end
    end
    local ok = ngx.timer.at(conf.flush_interval, tick)
    if not ok then
        timer_started = false
    end
end

function _M.start()
    schedule_flush()
end

local function push(line, force)
    buffer_n = buffer_n + 1
    buffer[buffer_n] = line
    if force or buffer_n >= conf.buffer_max then
        _M.flush()
    else
        schedule_flush()
    end
end

local function ring_store(line)
    if not audit_dict then
        return
    end
    local seq = audit_dict:incr("__seq", 1, 0)
    if not seq then
        return
    end
    audit_dict:set("e:" .. (seq % conf.capacity), line)
end

function _M.audit(ev)
    if not conf.enabled or type(ev) ~= "table" then
        return
    end
    ev.ts = ev.ts or util.now()
    ev.component = ev.component or conf.component
    if not conf.log_paths then
        ev.path = nil
    end
    if not conf.log_query then
        ev.query = nil
    end
    ev.authorization = nil
    ev.token = nil
    ev.cookie = nil
    local line = cjson.encode(ev)
    if not line then
        return
    end
    ring_store(line)
    push(line, ev.action == "deny" or ev.severity == "high")
end

function _M.recent(limit, filter)
    if not audit_dict then
        return {}
    end
    limit = util.clamp(tonumber(limit) or 100, 1, conf.capacity)
    local seq = audit_dict:get("__seq") or 0
    local out, n = {}, 0
    local i = seq
    local scanned = 0
    while i > 0 and n < limit and scanned < conf.capacity do
        local line = audit_dict:get("e:" .. (i % conf.capacity))
        if line then
            local ev = cjson.decode(line)
            if ev then
                local keep = true
                if filter then
                    for k, v in pairs(filter) do
                        if tostring(ev[k]) ~= tostring(v) then
                            keep = false
                            break
                        end
                    end
                end
                if keep then
                    n = n + 1
                    out[n] = ev
                end
            end
        end
        i = i - 1
        scanned = scanned + 1
    end
    return out
end

local function emit(level, msg, fields)
    if LEVELS[level] < level_num then
        return
    end
    local ev = fields and util.shallow_copy(fields) or {}
    ev.level = level
    ev.msg = msg
    ev.ts = util.now()
    ev.component = conf.component
    local line = cjson.encode(ev)
    ngx_log(level, line or ("ro: " .. tostring(msg)))
end

function _M.debug(msg, fields) emit("debug", msg, fields) end
function _M.info(msg, fields) emit("info", msg, fields) end
function _M.warn(msg, fields) emit("warn", msg, fields) end
function _M.error(msg, fields) emit("error", msg, fields) end

function _M.config()
    return util.shallow_copy(conf)
end

return _M
