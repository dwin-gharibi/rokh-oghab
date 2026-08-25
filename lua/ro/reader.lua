local _M = { _VERSION = "1.0.0" }
local mt = { __index = _M }

local sub = string.sub
local find = string.find
local concat = table.concat

function _M.wrap(sock, opts)
    opts = opts or {}
    return setmetatable({
        sock = sock,
        buf = "",
        pos = 1,
        closed = false,
        total = 0,
        max_chunk = opts.max_chunk or 65536,
    }, mt)
end

function _M.from_string(s, chunk)
    local offset = 1
    local fake = {
        receiveany = function(_, max)
            if offset > #s then
                return nil, "closed"
            end
            local n = math.min(max, chunk or #s, #s - offset + 1)
            local out = sub(s, offset, offset + n - 1)
            offset = offset + n
            return out
        end,
        receive = function(_, n)
            if type(n) ~= "number" then
                return nil, "unsupported"
            end
            if offset > #s then
                return nil, "closed"
            end
            local avail = #s - offset + 1
            if avail < n then
                local out = sub(s, offset)
                offset = #s + 1
                return nil, "closed", out
            end
            local out = sub(s, offset, offset + n - 1)
            offset = offset + n
            return out
        end,
        send = function(_, data) return #data end,
        close = function() return true end,
    }
    return _M.wrap(fake)
end

function _M:pending()
    return #self.buf - self.pos + 1
end

local function compact(self)
    if self.pos > 1 then
        self.buf = sub(self.buf, self.pos)
        self.pos = 1
    end
end

function _M:fill()
    if self.closed then
        return nil, "closed"
    end
    local data, err = self.sock:receiveany(self.max_chunk)
    if not data then
        if err ~= "timeout" then
            self.closed = true
        end
        return nil, err or "closed"
    end
    compact(self)
    self.buf = self.buf .. data
    self.total = self.total + #data
    return #data
end

function _M:read_until(delim, max_size)
    local search_from = 1
    while true do
        local hay = self.buf
        local start = self.pos + search_from - 1
        if start < self.pos then start = self.pos end
        local i = find(hay, delim, start, true)
        if i then
            local out = sub(hay, self.pos, i + #delim - 1)
            self.pos = i + #delim
            return out
        end
        local buffered = self:pending()
        if buffered >= max_size then
            return nil, "head-too-large"
        end
        search_from = buffered - #delim + 2
        if search_from < 1 then search_from = 1 end
        local n, err = self:fill()
        if not n then
            return nil, err
        end
    end
end

function _M:read_exact(n)
    if n <= 0 then
        return ""
    end
    while self:pending() < n do
        local ok, err = self:fill()
        if not ok then
            return nil, err
        end
    end
    local out = sub(self.buf, self.pos, self.pos + n - 1)
    self.pos = self.pos + n
    return out
end

function _M:read_some(max)
    if self:pending() > 0 then
        local avail = self:pending()
        local n = avail < max and avail or max
        local out = sub(self.buf, self.pos, self.pos + n - 1)
        self.pos = self.pos + n
        return out
    end
    if self.closed then
        return nil, "closed"
    end
    local data, err = self.sock:receiveany(max)
    if not data then
        if err ~= "timeout" then
            self.closed = true
        end
        return nil, err or "closed"
    end
    self.total = self.total + #data
    return data
end

function _M:leftover()
    if self:pending() <= 0 then
        return ""
    end
    return sub(self.buf, self.pos)
end

function _M:discard_buffer()
    self.buf = ""
    self.pos = 1
end

function _M:is_closed()
    return self.closed and self:pending() == 0
end

return _M
