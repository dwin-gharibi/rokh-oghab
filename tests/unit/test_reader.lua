local h = require("harness")
local reader = require("ro.reader")

h.describe("reader.read_until", function()
    h.it("returns data up to and including the delimiter", function()
        local r = reader.from_string("HEAD\r\n\r\nBODY")
        local out = r:read_until("\r\n\r\n", 1024)
        h.assert_eq(out, "HEAD\r\n\r\n")
        h.assert_eq(r:leftover(), "BODY")
    end)

    h.it("works when the delimiter is split across reads", function()
        local r = reader.from_string("HEAD\r\n\r\nBODY", 1)
        local out = r:read_until("\r\n\r\n", 1024)
        h.assert_eq(out, "HEAD\r\n\r\n")
        h.assert_eq(r:read_exact(4), "BODY")
    end)

    h.it("finds a delimiter that straddles chunk boundaries", function()
        for chunk = 1, 6 do
            local r = reader.from_string("AAAA\r\n\r\nBB", chunk)
            h.assert_eq(r:read_until("\r\n\r\n", 1024), "AAAA\r\n\r\n",
                "chunk size " .. chunk)
        end
    end)

    h.it("enforces the size limit", function()
        local r = reader.from_string(string.rep("x", 5000) .. "\r\n\r\n", 100)
        local out, err = r:read_until("\r\n\r\n", 512)
        h.assert_nil(out)
        h.assert_eq(err, "head-too-large")
    end)

    h.it("reports closure when the delimiter never arrives", function()
        local r = reader.from_string("no delimiter here")
        local out, err = r:read_until("\r\n\r\n", 1024)
        h.assert_nil(out)
        h.assert_true(err)
    end)

    h.it("supports repeated reads on one stream", function()
        local r = reader.from_string("A\r\n\r\nB\r\n\r\nC\r\n\r\n", 4)
        h.assert_eq(r:read_until("\r\n\r\n", 64), "A\r\n\r\n")
        h.assert_eq(r:read_until("\r\n\r\n", 64), "B\r\n\r\n")
        h.assert_eq(r:read_until("\r\n\r\n", 64), "C\r\n\r\n")
    end)

    h.it("handles a single-byte delimiter", function()
        local r = reader.from_string("line one\nline two\n", 3)
        h.assert_eq(r:read_until("\n", 64), "line one\n")
        h.assert_eq(r:read_until("\n", 64), "line two\n")
    end)
end)

h.describe("reader.read_exact", function()
    h.it("returns exactly the requested bytes", function()
        local r = reader.from_string("0123456789", 3)
        h.assert_eq(r:read_exact(4), "0123")
        h.assert_eq(r:read_exact(6), "456789")
    end)

    h.it("returns nil when the stream ends early", function()
        local r = reader.from_string("012")
        h.assert_nil(r:read_exact(10))
    end)

    h.it("treats a zero-length read as empty", function()
        local r = reader.from_string("abc")
        h.assert_eq(r:read_exact(0), "")
    end)
end)

h.describe("reader.read_some", function()
    h.it("drains buffered bytes before touching the socket", function()
        local r = reader.from_string("abcdefgh", 8)
        r:read_until("cd", 64)
        h.assert_eq(r:read_some(2), "ef")
        h.assert_eq(r:read_some(64), "gh")
    end)

    h.it("returns nil at end of stream", function()
        local r = reader.from_string("ab", 8)
        h.assert_eq(r:read_some(8), "ab")
        h.assert_nil(r:read_some(8))
    end)
end)

h.describe("reader buffer bookkeeping", function()
    h.it("tracks and discards leftovers", function()
        local r = reader.from_string("HEAD\r\n\r\nTAIL", 32)
        r:read_until("\r\n\r\n", 64)
        h.assert_eq(r:pending(), 4)
        h.assert_eq(r:leftover(), "TAIL")
        r:discard_buffer()
        h.assert_eq(r:pending(), 0)
        h.assert_eq(r:leftover(), "")
    end)
end)

h.describe("reader timeouts are transient, not terminal", function()
    local function scripted(steps)
        local i = 0
        local sock = {
            receiveany = function(_, _)
                i = i + 1
                local step = steps[i]
                if step == nil then
                    return nil, "closed"
                end
                if step == "timeout" then
                    return nil, "timeout"
                end
                if step == "closed" then
                    return nil, "closed"
                end
                return step
            end,
            receive = function() return nil, "unsupported" end,
            send = function(_, d) return #d end,
            close = function() return true end,
        }
        return reader.wrap(sock)
    end

    h.it("keeps reading after a read timeout", function()
        local r = scripted({ "timeout", "HEAD\r\n\r\n" })
        local out, err = r:read_until("\r\n\r\n", 1024)
        h.assert_nil(out)
        h.assert_eq(err, "timeout")
        h.assert_eq(r:read_until("\r\n\r\n", 1024), "HEAD\r\n\r\n",
            "a timeout must not poison the reader for later reads")
    end)

    h.it("keeps serving read_some after a timeout", function()
        local r = scripted({ "timeout", "payload" })
        local out, err = r:read_some(16)
        h.assert_nil(out)
        h.assert_eq(err, "timeout")
        h.assert_eq(r:read_some(16), "payload")
    end)

    h.it("still latches a real close", function()
        local r = scripted({ "closed", "unreachable" })
        local out, err = r:read_some(16)
        h.assert_nil(out)
        h.assert_eq(err, "closed")
        local out2, err2 = r:read_some(16)
        h.assert_nil(out2)
        h.assert_eq(err2, "closed",
            "an end of stream stays an end of stream")
    end)

    h.it("survives a run of timeouts before the peer speaks", function()
        local r = scripted({ "timeout", "timeout", "timeout", "220 ready\r\n" })
        for _ = 1, 3 do
            local out, err = r:read_some(64)
            h.assert_nil(out)
            h.assert_eq(err, "timeout")
        end
        h.assert_eq(r:read_some(64), "220 ready\r\n",
            "a server-first peer that pauses must still be readable")
    end)
end)
