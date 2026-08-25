local dns = require("ro.dns")
local ipaddr = require("ro.ipaddr")
local util = require("ro.util")
local log = require("ro.log")

local _M = { _VERSION = "1.0.0" }
local mt = { __index = _M }

local cjson = require("cjson.safe")
local floor = math.floor

local RCODE_REASON = {
    [1] = "dns.malformed_query",
    [2] = "dns.server_failure",
    [3] = "dns.nxdomain",
    [4] = "dns.not_implemented",
    [5] = "dns.refused",
}

local MIN_TTL = 5
local MAX_TTL = 300

function _M.new(opts)
    opts = opts or {}
    local self = setmetatable({
        servers = opts.servers or { { host = "1.1.1.1", port = 53 } },
        timeout = opts.timeout or 2000,
        retries = opts.retries or 2,
        cache = opts.cache_dict and ngx.shared[opts.cache_dict] or nil,
        guard = opts.guard,
        min_ttl = opts.min_ttl or MIN_TTL,
        max_ttl = opts.max_ttl or MAX_TTL,
        negative_ttl = opts.negative_ttl or 10,
        prefer_ipv6 = opts.prefer_ipv6 == true,
        allow_ipv6 = opts.allow_ipv6 ~= false,
        max_addresses = opts.max_addresses or 8,
    }, mt)
    if #self.servers == 0 then
        return nil, "resolver requires at least one server"
    end
    return self
end

local function cache_key(name, want6)
    return "d:" .. name .. (want6 and ":6" or ":4")
end

function _M:cache_get(name, want6)
    if not self.cache then
        return nil
    end
    local raw = self.cache:get(cache_key(name, want6))
    if not raw then
        return nil
    end
    local entry = cjson.decode(raw)
    if type(entry) ~= "table" then
        return nil
    end
    return entry
end

function _M:cache_set(name, want6, addresses, ttl)
    if not self.cache then
        return
    end
    ttl = util.clamp(ttl or self.min_ttl, self.min_ttl, self.max_ttl)
    local raw = cjson.encode({ addresses = addresses, ts = util.now() })
    if raw then
        self.cache:set(cache_key(name, want6), raw, ttl)
    end
end

function _M:query_server(server, packet)
    local sock = ngx.socket.udp()
    sock:settimeout(self.timeout)
    local ok, err = sock:setpeername(server.host, server.port or 53)
    if not ok then
        sock:close()
        return nil, "dns.unreachable", tostring(err)
    end
    ok, err = sock:send(packet)
    if not ok then
        sock:close()
        return nil, "dns.unreachable", tostring(err)
    end
    local data, rerr = sock:receive(4096)
    sock:close()
    if not data then
        return nil, "dns.timeout", tostring(rerr)
    end
    return data
end

function _M:lookup_type(name, qtype)
    local id, iderr = util.random_int(1, 65535)
    if not id then
        return nil, "dns.no_entropy", tostring(iderr)
    end
    local packet, err = dns.build_query(id, name, qtype)
    if not packet then
        return nil, err
    end

    local last_err, last_detail
    for attempt = 1, self.retries do
        local server = self.servers[((attempt - 1) % #self.servers) + 1]
        local data, qerr, qdetail = self:query_server(server, packet)
        if data then
            local msg, perr = dns.parse_message(data)
            if not msg then
                last_err, last_detail = "dns.malformed_answer", tostring(perr)
            elseif msg.id ~= id then
                last_err, last_detail = "dns.answer_mismatch", "transaction id"
            elseif not msg.qr then
                last_err, last_detail = "dns.answer_mismatch", "not a response"
            elseif #msg.questions ~= 1
                or msg.questions[1].name ~= name
                or msg.questions[1].qtype ~= qtype then
                last_err, last_detail = "dns.answer_mismatch", "question section"
            elseif msg.rcode ~= dns.RCODE.NOERROR then
                return nil, RCODE_REASON[msg.rcode] or "dns.failed",
                    "rcode " .. tostring(msg.rcode), msg.rcode
            else
                return msg
            end
        else
            last_err, last_detail = qerr, qdetail
        end
    end
    return nil, last_err or "dns.failed", last_detail
end

function _M:resolve(name, opts)
    opts = opts or {}
    local want6 = opts.ipv6 == true
    if want6 and not self.allow_ipv6 then
        return nil, "dns.ipv6_disabled"
    end

    local cached = self:cache_get(name, want6)
    if cached and cached.addresses then
        if #cached.addresses == 0 then
            return nil, "dns.no_permitted_address"
        end
        return cached.addresses, nil, true
    end

    local qtype = want6 and dns.TYPE.AAAA or dns.TYPE.A
    local msg, err, detail = self:lookup_type(name, qtype)
    if not msg then
        return nil, err, false, nil, detail
    end

    local out, n = {}, 0
    local min_ttl = self.max_ttl
    local filtered = 0

    for _, rec in ipairs(msg.answers) do
        if rec.family == "ipv4" or rec.family == "ipv6" then
            local kind = rec.family
            local value = kind == "ipv4" and rec.address or rec.groups
            local permitted = true
            local reason
            if self.guard then
                permitted, reason = self.guard:check_resolved(kind, value)
            end
            if permitted then
                n = n + 1
                out[n] = {
                    kind = kind,
                    v4 = kind == "ipv4" and rec.address or nil,
                    v6 = kind == "ipv6" and rec.groups or nil,
                    address = kind == "ipv4" and ipaddr.ipv4_to_string(rec.address)
                        or ipaddr.ipv6_to_string(rec.groups),
                    ttl = rec.ttl,
                }
                if rec.ttl and rec.ttl < min_ttl then
                    min_ttl = rec.ttl
                end
                if n >= self.max_addresses then
                    break
                end
            else
                filtered = filtered + 1
                log.warn("dns answer filtered by address guard", {
                    name = name,
                    address = kind == "ipv4" and ipaddr.ipv4_to_string(rec.address)
                        or ipaddr.ipv6_to_string(rec.groups),
                    reason = reason,
                })
            end
        end
    end

    if n == 0 then
        self:cache_set(name, want6, {}, self.negative_ttl)
        if filtered > 0 then
            return nil, "dns.all_answers_blocked", false, filtered
        end
        return nil, "dns.no_address"
    end

    self:cache_set(name, want6, out, min_ttl)
    return out, nil, false, filtered
end

function _M:resolve_any(name, opts)
    opts = opts or {}
    local order
    if self.prefer_ipv6 and self.allow_ipv6 then
        order = { true, false }
    else
        order = { false, true }
    end
    local first_err, first_detail
    for _, want6 in ipairs(order) do
        if want6 and not self.allow_ipv6 then
        else
            local addrs, err, cached, filtered, detail = self:resolve(name,
                { ipv6 = want6 })
            if addrs then
                return addrs, nil, cached, filtered
            end
            if not first_err then
                first_err, first_detail = err, detail
            end
            if err == "dns.all_answers_blocked" then
                return nil, err, false, nil, detail
            end
        end
    end
    return nil, first_err or "dns.no_address", false, nil, first_detail
end

function _M:flush(name)
    if not self.cache then return end
    if name then
        self.cache:delete(cache_key(name, false))
        self.cache:delete(cache_key(name, true))
    else
        self.cache:flush_all()
    end
end

return _M
