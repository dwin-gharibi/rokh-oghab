local dns = require("ro.dns")
local target_mod = require("ro.target")
local state = require("ro.state")
local metrics = require("ro.metrics")
local log = require("ro.log")
local util = require("ro.util")

local _M = { _VERSION = "1.0.0" }

local byte = string.byte
local char = string.char
local sub = string.sub
local floor = math.floor

local function allowed_types(conf)
    local set = {}
    for _, name in ipairs(conf.dns.allowedTypes or { "A", "AAAA" }) do
        local t = dns.TYPE[name]
        if t then
            set[t] = true
        end
    end
    return set
end

local function deny_rcode(conf)
    local mode = conf.dns.denyResponse or "nxdomain"
    if mode == "refused" then
        return dns.RCODE.REFUSED
    end
    if mode == "servfail" then
        return dns.RCODE.SERVFAIL
    end
    return dns.RCODE.NXDOMAIN
end

local function identity_for(conf, remote_addr)
    local st = state.get()
    if not st then
        return nil, "policy.not_loaded"
    end
    local ident, err = st.identities:resolve({ remote_addr = remote_addr })
    if not ident then
        return nil, err or "identity.unknown"
    end
    return ident
end

function _M.handle_query(conf, packet, remote_addr)
    state.sync()
    local st = state.get()
    local usable, ureason = state.is_usable()

    local query, perr = dns.parse_message(packet)
    if not query then
        metrics.inc("ro_dns_denials_total", { reason = "malformed" })
        log.warn("malformed dns query", { client = remote_addr, error = perr })
        return nil
    end

    if query.qr or query.opcode ~= 0 or #query.questions ~= 1 then
        metrics.inc("ro_dns_denials_total", { reason = "unsupported" })
        return dns.build_response(query, dns.RCODE.REFUSED, {})
    end

    local q = query.questions[1]
    metrics.inc("ro_dns_requests_total", {
        type = dns.TYPE_NAME[q.qtype] or "other",
    })

    if not usable then
        metrics.inc("ro_dns_denials_total", { reason = ureason })
        return dns.build_response(query, dns.RCODE.SERVFAIL, {})
    end

    if q.qclass ~= dns.CLASS_IN then
        metrics.inc("ro_dns_denials_total", { reason = "class" })
        return dns.build_response(query, dns.RCODE.REFUSED, {})
    end

    local types = allowed_types(conf)
    if not types[q.qtype] then
        metrics.inc("ro_dns_denials_total", { reason = "qtype" })
        log.audit({
            event = "dns", action = "deny", reason = "dns.qtype_not_allowed",
            client = remote_addr, name = util.safe_str(q.name, 253),
            qtype = dns.TYPE_NAME[q.qtype] or tostring(q.qtype),
            severity = "high",
        })
        return dns.build_response(query, deny_rcode(conf), {})
    end

    local ident, ierr = identity_for(conf, remote_addr)
    if not ident then
        metrics.inc("ro_dns_denials_total", { reason = "identity" })
        log.audit({
            event = "dns", action = "deny", reason = ierr,
            client = remote_addr, name = util.safe_str(q.name, 253),
            severity = "high",
        })
        return dns.build_response(query, deny_rcode(conf), {})
    end

    local info, herr = target_mod.classify_host(q.name)
    if not info or info.kind ~= "hostname" then
        metrics.inc("ro_dns_denials_total", { reason = "name" })
        log.audit({
            event = "dns", action = "deny", reason = "dns.invalid_name",
            client = remote_addr, name = util.safe_str(q.name, 253),
            detail = tostring(herr), identity = ident.id,
        })
        return dns.build_response(query, deny_rcode(conf), {})
    end

    local permitted, reason, rule = st.bundle:hostname_permitted(ident, info)
    if not permitted then
        metrics.inc("ro_dns_denials_total", { reason = reason or "policy" })
        log.audit({
            event = "dns", action = "deny", reason = reason or "policy.default_deny",
            client = remote_addr, name = info.canonical,
            qtype = dns.TYPE_NAME[q.qtype], identity = ident.id,
            namespace = ident.namespace, profile = ident.profile,
            severity = "high",
        })
        return dns.build_response(query, deny_rcode(conf), {})
    end

    local want6 = q.qtype == dns.TYPE.AAAA
    local addrs, rerr, cached, filtered = st.resolver:resolve(info.canonical,
        { ipv6 = want6 })
    if filtered and filtered > 0 then
        metrics.inc("ro_dns_answers_filtered_total", { name = "filtered" }, filtered)
    end
    if not addrs then
        local rcode = dns.RCODE.NXDOMAIN
        if rerr == "dns.all_answers_blocked" then
            rcode = deny_rcode(conf)
            log.audit({
                event = "dns", action = "deny", reason = rerr,
                client = remote_addr, name = info.canonical,
                identity = ident.id, severity = "high",
            })
        end
        return dns.build_response(query, rcode, {})
    end

    local answers = {}
    local max_answers = conf.dns.maxAnswers or 8
    for i = 1, #addrs do
        if i > max_answers then break end
        local a = addrs[i]
        if want6 and a.kind == "ipv6" then
            answers[#answers + 1] = {
                name = info.canonical, rtype = dns.TYPE.AAAA,
                rclass = dns.CLASS_IN, ttl = a.ttl or 60,
                rdata = dns.encode_aaaa(a.v6),
            }
        elseif not want6 and a.kind == "ipv4" then
            answers[#answers + 1] = {
                name = info.canonical, rtype = dns.TYPE.A,
                rclass = dns.CLASS_IN, ttl = a.ttl or 60,
                rdata = dns.encode_a(a.v4),
            }
        end
    end

    log.audit({
        event = "dns", action = "allow", reason = reason, rule = rule,
        client = remote_addr, name = info.canonical,
        qtype = dns.TYPE_NAME[q.qtype], identity = ident.id,
        namespace = ident.namespace, profile = ident.profile,
        answers = #answers, cached = cached and true or false,
    })

    return dns.build_response(query, dns.RCODE.NOERROR, answers)
end

function _M.run_udp(conf)
    conf = conf or state.config()
    local sock, err = ngx.req.socket()
    if not sock then
        log.error("dns: cannot obtain udp socket", { error = tostring(err) })
        return
    end
    sock:settimeout(conf.dns.upstreamTimeoutMs or 2000)

    local packet, rerr = sock:receive()
    if not packet then
        return
    end

    local remote_addr = ngx.var.remote_addr
    local ok, response = pcall(_M.handle_query, conf, packet, remote_addr)
    if not ok then
        log.error("dns handler crashed", { error = tostring(response) })
        return
    end
    if response then
        if #response > 512 then
            local query = dns.parse_message(packet)
            if query then
                response = dns.truncated_response(query)
            end
        end
        sock:send(response)
    end
end

function _M.run_tcp(conf)
    conf = conf or state.config()
    local sock, err = ngx.req.socket(true)
    if not sock then
        log.error("dns: cannot obtain tcp socket", { error = tostring(err) })
        return
    end
    sock:settimeout(conf.dns.upstreamTimeoutMs or 2000)

    local remote_addr = ngx.var.remote_addr
    local served = 0
    while served < 32 do
        local prefix, perr = sock:receive(2)
        if not prefix or #prefix < 2 then
            return
        end
        local length = byte(prefix, 1) * 256 + byte(prefix, 2)
        if length == 0 or length > 4096 then
            return
        end
        local packet, qerr = sock:receive(length)
        if not packet then
            return
        end
        served = served + 1
        local ok, response = pcall(_M.handle_query, conf, packet, remote_addr)
        if not ok then
            log.error("dns handler crashed", { error = tostring(response) })
            return
        end
        if not response then
            return
        end
        local n = #response
        local out = char(floor(n / 256), n % 256) .. response
        local sent = sock:send(out)
        if not sent then
            return
        end
    end
end

return _M
