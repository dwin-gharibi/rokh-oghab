local _M = { _VERSION = "1.0.0" }

local byte = string.byte
local char = string.char
local sub = string.sub
local find = string.find
local lower = string.lower
local concat = table.concat
local floor = math.floor

_M.TYPE = {
    A = 1, NS = 2, CNAME = 5, SOA = 6, PTR = 12, MX = 15,
    TXT = 16, AAAA = 28, SRV = 33, NAPTR = 35, OPT = 41,
    DS = 43, RRSIG = 46, NSEC = 47, DNSKEY = 48, HTTPS = 65, ANY = 255,
    NULL = 10, CAA = 257,
}

_M.TYPE_NAME = {}
for k, v in pairs(_M.TYPE) do
    _M.TYPE_NAME[v] = k
end

_M.CLASS_IN = 1

_M.RCODE = {
    NOERROR = 0, FORMERR = 1, SERVFAIL = 2, NXDOMAIN = 3,
    NOTIMP = 4, REFUSED = 5,
}

local MAX_NAME = 255
local MAX_LABEL = 63
local MAX_MESSAGE = 4096
local MAX_POINTERS = 16

local function u16(s, i)
    if i + 1 > #s then return nil end
    return byte(s, i) * 256 + byte(s, i + 1)
end

local function u32(s, i)
    if i + 3 > #s then return nil end
    return byte(s, i) * 16777216 + byte(s, i + 1) * 65536
        + byte(s, i + 2) * 256 + byte(s, i + 3)
end

local function put16(v)
    return char(floor(v / 256) % 256, v % 256)
end

local function put32(v)
    return char(floor(v / 16777216) % 256, floor(v / 65536) % 256,
        floor(v / 256) % 256, v % 256)
end

_M.put16 = put16
_M.put32 = put32

function _M.decode_name(data, pos)
    local labels, n = {}, 0
    local jumps = 0
    local total = 0
    local next_pos = nil
    local len = #data

    while true do
        if pos > len then
            return nil, "name runs past end of message"
        end
        local b = byte(data, pos)
        if b == 0 then
            pos = pos + 1
            break
        end
        local kind = b - (b % 64)
        if kind == 192 then
            local ptr = u16(data, pos)
            if not ptr then
                return nil, "truncated compression pointer"
            end
            local offset = (ptr % 16384) + 1
            if next_pos == nil then
                next_pos = pos + 2
            end
            jumps = jumps + 1
            if jumps > MAX_POINTERS then
                return nil, "too many compression pointers"
            end
            if offset >= pos then
                return nil, "forward or self compression pointer"
            end
            pos = offset
        elseif b <= MAX_LABEL then
            local label = sub(data, pos + 1, pos + b)
            if #label ~= b then
                return nil, "truncated label"
            end
            if find(label, "[%z\1-\32\127]") then
                return nil, "control characters in label"
            end
            total = total + b + 1
            if total > MAX_NAME then
                return nil, "name too long"
            end
            n = n + 1
            labels[n] = label
            pos = pos + 1 + b
        else
            return nil, "invalid label length"
        end
    end

    local name
    if n == 0 then
        name = "."
    else
        name = lower(concat(labels, "."))
    end
    return name, next_pos or pos
end

function _M.encode_name(name)
    if type(name) ~= "string" then
        return nil, "name must be a string"
    end
    if name == "." or name == "" then
        return "\0"
    end
    if #name > MAX_NAME then
        return nil, "name too long"
    end
    local out, n = {}, 0
    local pos = 1
    local len = #name
    while pos <= len do
        local dot = find(name, ".", pos, true) or (len + 1)
        local label = sub(name, pos, dot - 1)
        if #label == 0 or #label > MAX_LABEL then
            return nil, "invalid label length"
        end
        n = n + 1
        out[n] = char(#label) .. label
        pos = dot + 1
    end
    n = n + 1
    out[n] = "\0"
    return concat(out)
end

function _M.parse_message(data, opts)
    opts = opts or {}
    if type(data) ~= "string" then
        return nil, "no data"
    end
    if #data < 12 then
        return nil, "message too short"
    end
    if #data > (opts.max_size or MAX_MESSAGE) then
        return nil, "message too large"
    end

    local msg = {
        id = u16(data, 1),
        flags = u16(data, 3),
        qdcount = u16(data, 5),
        ancount = u16(data, 7),
        nscount = u16(data, 9),
        arcount = u16(data, 11),
        questions = {},
        answers = {},
        authority = {},
        additional = {},
    }

    msg.qr = msg.flags >= 32768
    msg.opcode = floor(msg.flags / 2048) % 16
    msg.rd = floor(msg.flags / 256) % 2 == 1
    msg.tc = floor(msg.flags / 512) % 2 == 1
    msg.rcode = msg.flags % 16

    if msg.qdcount > 8 or msg.ancount > 128
        or msg.nscount > 128 or msg.arcount > 128 then
        return nil, "unreasonable record counts"
    end

    local pos = 13
    for _ = 1, msg.qdcount do
        local name, npos = _M.decode_name(data, pos)
        if not name then
            return nil, npos
        end
        pos = npos
        local qtype = u16(data, pos)
        local qclass = u16(data, pos + 2)
        if not qtype or not qclass then
            return nil, "truncated question"
        end
        pos = pos + 4
        msg.questions[#msg.questions + 1] = {
            name = name, qtype = qtype, qclass = qclass,
        }
    end

    local function read_records(count, into)
        for _ = 1, count do
            local name, npos = _M.decode_name(data, pos)
            if not name then
                return nil, npos
            end
            pos = npos
            local rtype = u16(data, pos)
            local rclass = u16(data, pos + 2)
            local ttl = u32(data, pos + 4)
            local rdlength = u16(data, pos + 8)
            if not rtype or not rclass or not ttl or not rdlength then
                return nil, "truncated resource record"
            end
            pos = pos + 10
            local rdata = sub(data, pos, pos + rdlength - 1)
            if #rdata ~= rdlength then
                return nil, "truncated rdata"
            end
            local rec = {
                name = name, rtype = rtype, rclass = rclass,
                ttl = ttl, rdlength = rdlength, rdata = rdata,
            }
            if rtype == _M.TYPE.A and rdlength == 4 then
                rec.address = byte(rdata, 1) * 16777216 + byte(rdata, 2) * 65536
                    + byte(rdata, 3) * 256 + byte(rdata, 4)
                rec.family = "ipv4"
            elseif rtype == _M.TYPE.AAAA and rdlength == 16 then
                local g = {}
                for i = 1, 8 do
                    g[i] = byte(rdata, i * 2 - 1) * 256 + byte(rdata, i * 2)
                end
                rec.groups = g
                rec.family = "ipv6"
            elseif rtype == _M.TYPE.CNAME then
                local cname = _M.decode_name(data, pos)
                rec.cname = cname
            end
            pos = pos + rdlength
            into[#into + 1] = rec
        end
        return true
    end

    local ok, err = read_records(msg.ancount, msg.answers)
    if not ok then return nil, err end
    ok, err = read_records(msg.nscount, msg.authority)
    if not ok then return nil, err end
    ok, err = read_records(msg.arcount, msg.additional)
    if not ok then return nil, err end

    return msg
end

function _M.build_query(id, name, qtype)
    local qname, err = _M.encode_name(name)
    if not qname then
        return nil, err
    end
    local flags = 256
    return concat({
        put16(id), put16(flags), put16(1), put16(0), put16(0), put16(0),
        qname, put16(qtype), put16(_M.CLASS_IN),
    })
end

function _M.build_response(query, rcode, answers, opts)
    opts = opts or {}
    local flags = 33792
    if query.rd then
        flags = flags + 256
    end
    if opts.no_recursion_available then
        flags = flags - 128
    end
    flags = flags + (rcode % 16)

    local parts = {}
    local qcount = 0
    local qsection = {}
    for _, q in ipairs(query.questions or {}) do
        local qname, err = _M.encode_name(q.name)
        if not qname then
            return nil, err
        end
        qsection[#qsection + 1] = qname .. put16(q.qtype) .. put16(q.qclass)
        qcount = qcount + 1
    end

    local asection = {}
    local acount = 0
    for _, a in ipairs(answers or {}) do
        local aname, err = _M.encode_name(a.name)
        if not aname then
            return nil, err
        end
        local rdata = a.rdata
        if not rdata then
            return nil, "answer missing rdata"
        end
        asection[#asection + 1] = aname .. put16(a.rtype) .. put16(a.rclass or _M.CLASS_IN)
            .. put32(a.ttl or 60) .. put16(#rdata) .. rdata
        acount = acount + 1
    end

    parts[#parts + 1] = put16(query.id or 0)
    parts[#parts + 1] = put16(flags)
    parts[#parts + 1] = put16(qcount)
    parts[#parts + 1] = put16(acount)
    parts[#parts + 1] = put16(0)
    parts[#parts + 1] = put16(0)
    parts[#parts + 1] = concat(qsection)
    parts[#parts + 1] = concat(asection)
    return concat(parts)
end

function _M.encode_a(addr)
    return char(floor(addr / 16777216) % 256, floor(addr / 65536) % 256,
        floor(addr / 256) % 256, addr % 256)
end

function _M.encode_aaaa(groups)
    local out = {}
    for i = 1, 8 do
        out[i] = put16(groups[i])
    end
    return concat(out)
end

function _M.truncated_response(query)
    local flags = 33792 + 512
    if query.rd then
        flags = flags + 256
    end
    return concat({
        put16(query.id or 0), put16(flags), put16(0), put16(0), put16(0), put16(0),
    })
end

return _M
