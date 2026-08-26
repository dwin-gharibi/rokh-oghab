local dns = require("ro.dns")
local cjson = require("cjson.safe")
local ipaddr = require("ro.ipaddr")

local _M = {}

local zone

local function load_zone()
    if zone then return zone end
    local fh = io.open("/etc/testdns/zone.json", "r")
    if not fh then
        zone = {}
        return zone
    end
    local body = fh:read("*a")
    fh:close()
    zone = cjson.decode(body) or {}
    return zone
end

function _M.run()
    local sock = ngx.req.socket()
    if not sock then return end
    sock:settimeout(2000)
    local packet = sock:receive()
    if not packet then return end

    local query = dns.parse_message(packet)
    if not query or #query.questions ~= 1 then
        return
    end
    local q = query.questions[1]
    local z = load_zone()
    local entry = z[q.name]

    if not entry then
        sock:send(dns.build_response(query, dns.RCODE.NXDOMAIN, {}))
        return
    end

    local answers = {}
    local want6 = q.qtype == dns.TYPE.AAAA
    local list = want6 and (entry.aaaa or {}) or (entry.a or {})
    for _, addr in ipairs(list) do
        if want6 then
            local g = ipaddr.parse_ipv6(addr)
            if g then
                answers[#answers + 1] = {
                    name = q.name, rtype = dns.TYPE.AAAA, rclass = dns.CLASS_IN,
                    ttl = entry.ttl or 5, rdata = dns.encode_aaaa(g),
                }
            end
        else
            local v4 = ipaddr.parse_ipv4(addr)
            if v4 then
                answers[#answers + 1] = {
                    name = q.name, rtype = dns.TYPE.A, rclass = dns.CLASS_IN,
                    ttl = entry.ttl or 5, rdata = dns.encode_a(v4),
                }
            end
        end
    end
    if entry.txt and q.qtype == dns.TYPE.TXT then
        local t = entry.txt
        answers[#answers + 1] = {
            name = q.name, rtype = dns.TYPE.TXT, rclass = dns.CLASS_IN,
            ttl = 5, rdata = string.char(#t) .. t,
        }
    end
    sock:send(dns.build_response(query, dns.RCODE.NOERROR, answers))
end

return _M
