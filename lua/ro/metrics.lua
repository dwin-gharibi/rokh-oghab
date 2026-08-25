local util = require("ro.util")

local _M = { _VERSION = "1.0.0" }

local format = string.format
local concat = table.concat
local sort = table.sort
local sub = string.sub
local gsub = string.gsub

local dict
local defs = {}
local def_order = {}
local max_series = 20000
local series_key = "__ro_series_count"

local DEFAULT_BUCKETS = { 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30 }

local function escape_label(v)
    v = tostring(v)
    v = gsub(v, "[%z\1-\31\127]", "")
    if #v > 96 then
        v = sub(v, 1, 96)
    end
    v = gsub(v, "\\", "\\\\")
    v = gsub(v, '"', '\\"')
    return v
end

local function encode_labels(labels)
    if not labels then
        return ""
    end
    local keys, n = util.sorted_keys(labels)
    if n == 0 then
        return ""
    end
    local parts = {}
    for i = 1, n do
        local k = keys[i]
        local v = labels[k]
        if v ~= nil then
            parts[#parts + 1] = tostring(k) .. '="' .. escape_label(v) .. '"'
        end
    end
    if #parts == 0 then
        return ""
    end
    return "{" .. concat(parts, ",") .. "}"
end

_M.encode_labels = encode_labels

function _M.init(dict_name, opts)
    opts = opts or {}
    dict = ngx.shared[dict_name or "ro_metrics"]
    if not dict then
        return nil, "shared dict not configured: " .. tostring(dict_name)
    end
    max_series = opts.max_series or max_series
    return true
end

function _M.define(name, mtype, help, buckets)
    if defs[name] then
        return true
    end
    defs[name] = {
        name = name,
        type = mtype,
        help = help or name,
        buckets = buckets or DEFAULT_BUCKETS,
    }
    def_order[#def_order + 1] = name
    return true
end

local function series_full()
    local n = dict:get(series_key)
    return n ~= nil and n >= max_series
end

local function bump(key, by)
    local newval = dict:incr(key, by)
    if newval then
        return newval
    end
    local ok = dict:add(key, by)
    if ok then
        dict:incr(series_key, 1, 0)
        return by
    end
    return dict:incr(key, by, 0)
end

local function resolve_key(name, labels)
    local suffix = encode_labels(labels)
    local key = name .. suffix
    if dict:get(key) == nil and series_full() then
        return name .. '{ro_overflow="true"}'
    end
    return key
end

function _M.inc(name, labels, by)
    if not dict then return end
    by = by or 1
    if by <= 0 then return end
    bump(resolve_key(name, labels), by)
end

function _M.set(name, labels, value)
    if not dict then return end
    local key = resolve_key(name, labels)
    if dict:get(key) == nil then
        if dict:add(key, value) then
            dict:incr(series_key, 1, 0)
            return
        end
    end
    dict:set(key, value)
end

function _M.observe(name, labels, value)
    if not dict then return end
    local d = defs[name]
    local buckets = d and d.buckets or DEFAULT_BUCKETS
    local base_labels = labels and util.shallow_copy(labels) or {}
    for i = 1, #buckets do
        if value <= buckets[i] then
            base_labels.le = format("%g", buckets[i])
            bump(resolve_key(name .. "_bucket", base_labels), 1)
        end
    end
    base_labels.le = "+Inf"
    bump(resolve_key(name .. "_bucket", base_labels), 1)
    base_labels.le = nil
    bump(resolve_key(name .. "_sum", base_labels), value)
    bump(resolve_key(name .. "_count", base_labels), 1)
end

function _M.get(name, labels)
    if not dict then return nil end
    return dict:get(name .. encode_labels(labels))
end

function _M.reset()
    if dict then
        dict:flush_all()
        dict:flush_expired()
    end
end

local function metric_base(key)
    local brace = key:find("{", 1, true)
    if brace then
        return sub(key, 1, brace - 1)
    end
    return key
end

function _M.render()
    if not dict then
        return "", "metrics not initialised"
    end
    local keys = dict:get_keys(0)
    sort(keys)
    local buckets = {}
    for i = 1, #keys do
        local key = keys[i]
        if key ~= series_key then
            local base = metric_base(key)
            local owner = base
            local d = defs[base]
            if not d then
                for _, suffix in ipairs({ "_bucket", "_sum", "_count" }) do
                    if util.ends_with(base, suffix) then
                        local root = sub(base, 1, #base - #suffix)
                        if defs[root] then
                            owner = root
                            break
                        end
                    end
                end
            end
            local list = buckets[owner]
            if not list then
                list = {}
                buckets[owner] = list
            end
            list[#list + 1] = key
        end
    end

    local out = {}
    for _, name in ipairs(def_order) do
        local list = buckets[name]
        local d = defs[name]
        out[#out + 1] = "# HELP " .. name .. " " .. d.help
        out[#out + 1] = "# TYPE " .. name .. " " .. d.type
        if list then
            for _, key in ipairs(list) do
                local v = dict:get(key)
                if v ~= nil then
                    out[#out + 1] = key .. " " .. format("%.17g", v)
                end
            end
        end
        buckets[name] = nil
    end

    local leftovers = {}
    for name in pairs(buckets) do
        leftovers[#leftovers + 1] = name
    end
    sort(leftovers)
    for _, name in ipairs(leftovers) do
        for _, key in ipairs(buckets[name]) do
            local v = dict:get(key)
            if v ~= nil then
                out[#out + 1] = key .. " " .. format("%.17g", v)
            end
        end
    end

    out[#out + 1] = "# HELP ro_metrics_series_total Number of distinct metric series tracked."
    out[#out + 1] = "# TYPE ro_metrics_series_total gauge"
    out[#out + 1] = "ro_metrics_series_total " .. tostring(dict:get(series_key) or 0)
    out[#out + 1] = ""
    return concat(out, "\n")
end

function _M.bootstrap()
    _M.define("ro_build_info", "gauge", "Rokh Oghab build information.")
    _M.define("ro_requests_total", "counter",
        "Total proxied requests evaluated by the policy engine.")
    _M.define("ro_allowed_total", "counter", "Requests allowed by policy.")
    _M.define("ro_denied_total", "counter", "Requests denied by policy.")
    _M.define("ro_otel_spans_queued_total", "counter",
        "Spans placed on the export queue.")
    _M.define("ro_otel_spans_exported_total", "counter",
        "Spans successfully delivered to the collector.")
    _M.define("ro_otel_spans_dropped_total", "counter",
        "Spans discarded because the export queue was full. Telemetry is "
        .. "never allowed to slow a request, so it is dropped instead.")
    _M.define("ro_otel_export_failures_total", "counter",
        "Failed exports to the collector. Egress enforcement is unaffected.")
    _M.define("ro_admin_denied_total", "counter",
        "Admin API requests refused for want of a role.")
    _M.define("ro_uncatalogued_reasons_total", "counter",
        "Denials whose reason has no entry in the reason catalogue, so the "
        .. "cause is invisible in ro_denied_total. Any value above zero is a "
        .. "defect in the gateway, not in the traffic.")
    _M.define("ro_connections_total", "counter", "Client connections accepted.")
    _M.define("ro_connections_active", "gauge", "Client connections currently open.")
    _M.define("ro_connection_failures_total", "counter",
        "Upstream connection failures.")
    _M.define("ro_bytes_sent_total", "counter", "Bytes forwarded to upstream.")
    _M.define("ro_bytes_received_total", "counter", "Bytes forwarded to client.")
    _M.define("ro_policy_denials_total", "counter", "Denials by policy reason.")
    _M.define("ro_dns_requests_total", "counter", "DNS queries handled.")
    _M.define("ro_dns_denials_total", "counter", "DNS queries denied by policy.")
    _M.define("ro_dns_answers_filtered_total", "counter",
        "DNS answer records stripped by the address guard.")
    _M.define("ro_ratelimit_rejected_total", "counter",
        "Requests rejected by rate or connection limits.")
    _M.define("ro_policy_version", "gauge", "Active policy bundle version.")
    _M.define("ro_policy_reload_total", "counter", "Policy bundle reloads.")
    _M.define("ro_policy_reload_failures_total", "counter",
        "Policy bundle reload failures.")
    _M.define("ro_policy_stale", "gauge",
        "Set to 1 when the policy bundle is stale and the gateway fails closed.")
    _M.define("ro_emergency_deny", "gauge",
        "Set to 1 when the global emergency deny switch is engaged.")
    _M.define("ro_limits_unavailable", "gauge",
        "Set to 1 when the limit store is unavailable and configured limits refuse.")
    _M.define("ro_request_duration_seconds", "histogram",
        "Policy decision and proxy setup latency.")
    _M.define("ro_upstream_duration_seconds", "histogram",
        "Time spent connected to the upstream destination.")
    _M.define("ro_policy_eval_seconds", "histogram",
        "Policy evaluation latency.", { 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.05 })
    _M.define("ro_tls_handshakes_total", "counter", "TLS client hellos inspected.")
    _M.define("ro_protocol_violations_total", "counter",
        "Requests rejected by strict protocol validation.")
    return true
end

return _M
