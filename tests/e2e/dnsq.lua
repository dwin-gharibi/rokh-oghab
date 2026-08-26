local dns = require("ro.dns")
local ipaddr = require("ro.ipaddr")
local cjson = require("cjson.safe")

local name = arg[1]
local qtype = tonumber(arg[2]) or 1
local server = arg[3] or "10.99.0.5"
local port = tonumber(arg[4]) or 5353
local tid = tonumber(arg[5]) or 4321

local packet = dns.build_query(tid, name, qtype)
local sock = ngx.socket.udp()
sock:settimeout(4000)
local ok, err = sock:setpeername(server, port)
if not ok then
    print(cjson.encode({ error = tostring(err) }))
    return
end
sock:send(packet)
local data, rerr = sock:receive(4096)
sock:close()
if not data then
    print(cjson.encode({ error = tostring(rerr) }))
    return
end
local msg, perr = dns.parse_message(data)
if not msg then
    print(cjson.encode({ error = tostring(perr) }))
    return
end
local answers = {}
for _, rec in ipairs(msg.answers) do
    if rec.family == "ipv4" then
        answers[#answers + 1] = ipaddr.ipv4_to_string(rec.address)
    elseif rec.family == "ipv6" then
        answers[#answers + 1] = ipaddr.ipv6_to_string(rec.groups)
    else
        answers[#answers + 1] = "type" .. tostring(rec.rtype)
    end
end
print(cjson.encode({
    id = msg.id, rcode = msg.rcode, count = msg.ancount, answers = answers,
}))
