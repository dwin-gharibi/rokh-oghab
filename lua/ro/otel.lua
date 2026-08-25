local cjson = require("cjson.safe")
local util = require("ro.util")
local httpc = require("ro.httpc")

local _M = { _VERSION = "1.0.0" }

local byte = string.byte
local format = string.format
local sub = string.sub
local lower = string.lower
local floor = math.floor
local concat = table.concat

local SPAN_KIND_CLIENT = 3
local SPAN_KIND_SERVER = 2
local STATUS_UNSET = 0
local STATUS_OK = 1
local STATUS_ERROR = 2

local ZERO_TRACE = "00000000000000000000000000000000"
local ZERO_SPAN = "0000000000000000"

local conf = {
    enabled = false,
    endpoint = "",
    tracesPath = "/v1/traces",
    metricsPath = "/v1/metrics",
    serviceName = "rokh-oghab-gateway",
    serviceNamespace = "rokh-oghab",
    node = "",
    headers = {},
    sampleRatio = 1.0,
    maxQueue = 512,
    maxBatch = 128,
    timeoutMs = 2000,
    exportIntervalSeconds = 5,
    trustIncomingTrace = false,
    recordDestination = false,
    exportMetrics = false,
}

local queue = {}
local queue_n = 0
local dropped = 0
local started = false
local metrics

local function counter(name, by)
    if not metrics then
        local ok, m = pcall(require, "ro.metrics")
        if not ok then
            return
        end
        metrics = m
    end
    pcall(metrics.inc, name, nil, by or 1)
end

local function hex(raw)
    return util.to_hex(raw)
end

function _M.new_trace_id()
    local raw = util.random_bytes(16)
    if not raw then
        return nil
    end
    local id = hex(raw)
    if id == ZERO_TRACE then
        return nil
    end
    return id
end

function _M.new_span_id()
    local raw = util.random_bytes(8)
    if not raw then
        return nil
    end
    local id = hex(raw)
    if id == ZERO_SPAN then
        return nil
    end
    return id
end

local function is_hex(s, n)
    if type(s) ~= "string" or #s ~= n then
        return false
    end
    for i = 1, n do
        local c = byte(s, i)
        local ok = (c >= 48 and c <= 57) or (c >= 97 and c <= 102)
        if not ok then
            return false
        end
    end
    return true
end

function _M.parse_traceparent(value)
    if type(value) ~= "string" then
        return nil
    end
    value = lower(util.trim(value))
    if #value < 55 then
        return nil
    end
    local version = sub(value, 1, 2)
    if not is_hex(version, 2) or version == "ff" then
        return nil
    end
    if sub(value, 3, 3) ~= "-" or sub(value, 36, 36) ~= "-"
        or sub(value, 53, 53) ~= "-" then
        return nil
    end
    local trace_id = sub(value, 4, 35)
    local span_id = sub(value, 37, 52)
    local flags = sub(value, 54, 55)
    if not is_hex(trace_id, 32) or not is_hex(span_id, 16)
        or not is_hex(flags, 2) then
        return nil
    end
    if trace_id == ZERO_TRACE or span_id == ZERO_SPAN then
        return nil
    end
    if version == "00" and #value ~= 55 then
        return nil
    end
    return {
        trace_id = trace_id,
        span_id = span_id,
        sampled = (tonumber(flags, 16) % 2) == 1,
    }
end

function _M.traceparent(trace_id, span_id, sampled)
    return format("00-%s-%s-%s", trace_id, span_id, sampled and "01" or "00")
end

local function sampled_for(trace_id)
    local ratio = tonumber(conf.sampleRatio) or 0
    if ratio >= 1 then
        return true
    end
    if ratio <= 0 then
        return false
    end
    local n = tonumber(sub(trace_id, 25, 32), 16)
    if not n then
        return false
    end
    return (n / 4294967295) < ratio
end

function _M.enabled()
    return conf.enabled == true and conf.endpoint ~= ""
end

function _M.start_span(name, parent_header)
    if not _M.enabled() then
        return nil
    end
    local trace_id, parent_span
    if conf.trustIncomingTrace then
        local parsed = _M.parse_traceparent(parent_header)
        if parsed then
            trace_id = parsed.trace_id
            parent_span = parsed.span_id
        end
    end
    trace_id = trace_id or _M.new_trace_id()
    if not trace_id then
        return nil
    end
    local span_id = _M.new_span_id()
    if not span_id then
        return nil
    end
    if not sampled_for(trace_id) then
        return nil
    end
    return {
        name = name,
        trace_id = trace_id,
        span_id = span_id,
        parent_span_id = parent_span,
        kind = SPAN_KIND_SERVER,
        start_ns = util.now_ns(),
        attributes = {},
        events = {},
    }
end

function _M.child(span, name)
    if not span then
        return nil
    end
    local span_id = _M.new_span_id()
    if not span_id then
        return nil
    end
    return {
        name = name,
        trace_id = span.trace_id,
        span_id = span_id,
        parent_span_id = span.span_id,
        kind = SPAN_KIND_CLIENT,
        start_ns = util.now_ns(),
        attributes = {},
        events = {},
    }
end

function _M.attr(span, key, value)
    if not span or value == nil then
        return
    end
    local t = type(value)
    if t ~= "string" and t ~= "number" and t ~= "boolean" then
        return
    end
    if t == "string" then
        value = util.safe_str(value, 200)
    end
    span.attributes[#span.attributes + 1] = { key = key, value = value }
end

function _M.event(span, name)
    if not span then
        return
    end
    if #span.events >= 16 then
        return
    end
    span.events[#span.events + 1] = {
        name = name, time_ns = util.now_ns(),
    }
end

function _M.finish(span, status, message)
    if not span then
        return
    end
    span.end_ns = util.now_ns()
    span.status = status or STATUS_UNSET
    span.status_message = message
    if queue_n >= (conf.maxQueue or 512) then
        dropped = dropped + 1
        counter("ro_otel_spans_dropped_total")
        return
    end
    queue_n = queue_n + 1
    queue[queue_n] = span
    counter("ro_otel_spans_queued_total")
end

_M.KIND_CLIENT = SPAN_KIND_CLIENT
_M.KIND_SERVER = SPAN_KIND_SERVER
_M.STATUS_OK = STATUS_OK
_M.STATUS_ERROR = STATUS_ERROR
_M.STATUS_UNSET = STATUS_UNSET

local function encode_value(v)
    local t = type(v)
    if t == "boolean" then
        return { boolValue = v }
    end
    if t == "number" then
        if v == floor(v) and v < 9007199254740992 and v > -9007199254740992 then
            return { intValue = format("%d", v) }
        end
        return { doubleValue = v }
    end
    return { stringValue = tostring(v) }
end

local function encode_attributes(list)
    local out = {}
    for i = 1, #list do
        out[i] = { key = list[i].key, value = encode_value(list[i].value) }
    end
    return out
end

local function resource()
    local attrs = {
        { key = "service.name", value = conf.serviceName },
        { key = "service.namespace", value = conf.serviceNamespace },
        { key = "service.version", value = _M._VERSION },
    }
    if conf.node and conf.node ~= "" then
        attrs[#attrs + 1] = { key = "host.name", value = conf.node }
    end
    return { attributes = encode_attributes(attrs) }
end

function _M.encode_spans(spans)
    local out = {}
    for i = 1, #spans do
        local s = spans[i]
        out[i] = {
            traceId = s.trace_id,
            spanId = s.span_id,
            parentSpanId = s.parent_span_id,
            name = s.name,
            kind = s.kind,
            startTimeUnixNano = format("%d", s.start_ns or 0),
            endTimeUnixNano = format("%d", s.end_ns or s.start_ns or 0),
            attributes = encode_attributes(s.attributes),
            status = {
                code = s.status or STATUS_UNSET,
                message = s.status_message,
            },
        }
        if #s.events > 0 then
            local evs = {}
            for j = 1, #s.events do
                evs[j] = {
                    name = s.events[j].name,
                    timeUnixNano = format("%d", s.events[j].time_ns or 0),
                }
            end
            out[i].events = evs
        end
    end
    return {
        resourceSpans = { {
            resource = resource(),
            scopeSpans = { {
                scope = { name = "rokh-oghab", version = _M._VERSION },
                spans = out,
            } },
        } },
    }
end

function _M.drain(limit)
    limit = limit or conf.maxBatch or 128
    if queue_n == 0 then
        return nil
    end
    local take = queue_n < limit and queue_n or limit
    local batch = {}
    for i = 1, take do
        batch[i] = queue[i]
    end
    local rest = {}
    local n = 0
    for i = take + 1, queue_n do
        n = n + 1
        rest[n] = queue[i]
    end
    queue = rest
    queue_n = n
    return batch
end

function _M.flush()
    if not _M.enabled() then
        return
    end
    local batch = _M.drain()
    if not batch then
        return
    end
    local url = conf.endpoint .. conf.tracesPath
    local ok, res, err = pcall(httpc.request, url, {
        method = "POST",
        json = _M.encode_spans(batch),
        headers = conf.headers,
        timeout = conf.timeoutMs,
        max_body = 65536,
    })
    if not ok or not res then
        counter("ro_otel_export_failures_total")
        return
    end
    if res.status >= 300 then
        counter("ro_otel_export_failures_total")
        return
    end
    counter("ro_otel_spans_exported_total", #batch)
end

local function tick(premature)
    if premature then
        return
    end
    pcall(_M.flush)
    local ok = ngx.timer.at(conf.exportIntervalSeconds or 5, tick)
    if not ok then
        started = false
    end
end

function _M.configure(c)
    if type(c) ~= "table" then
        return conf
    end
    for k, v in pairs(c) do
        if conf[k] ~= nil and v ~= nil then
            conf[k] = v
        end
    end
    if type(conf.headers) ~= "table" then
        conf.headers = {}
    end
    return conf
end

function _M.start()
    if started or not _M.enabled() then
        return
    end
    if not ngx or not ngx.timer then
        return
    end
    started = true
    local ok = ngx.timer.at(conf.exportIntervalSeconds or 5, tick)
    if not ok then
        started = false
    end
end

function _M.stats()
    return { queued = queue_n, dropped = dropped, enabled = _M.enabled() }
end

function _M.reset()
    queue = {}
    queue_n = 0
    dropped = 0
end

function _M.config()
    return conf
end

return _M
