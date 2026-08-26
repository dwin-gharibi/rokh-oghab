local h = require("harness")
local otel = require("ro.otel")
local cjson = require("cjson.safe")

local function fresh(overrides)
    otel.reset()
    local base = {
        enabled = true, endpoint = "http://collector.invalid:4318",
        serviceName = "ro-test", node = "node-a", sampleRatio = 1.0,
        trustIncomingTrace = false, maxQueue = 8, maxBatch = 4,
    }
    for k, v in pairs(overrides or {}) do base[k] = v end
    otel.configure(base)
end

h.describe("a traceparent from a workload is parsed strictly", function()
    h.it("accepts a well-formed header", function()
        local p = otel.parse_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
        h.assert_eq(p.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736")
        h.assert_eq(p.span_id, "00f067aa0ba902b7")
        h.assert_eq(p.sampled, true)
    end)

    h.it("reads the sampled bit", function()
        local p = otel.parse_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
        h.assert_eq(p.sampled, false)
    end)

    h.it("refuses anything malformed", function()
        for _, bad in ipairs({
            "",
            "garbage",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz",
            "00-4bf92f3577b34da6a3ce929d0e0e4736_00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nX: 1",
            "00-ZZZZ2f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        }) do
            h.assert_nil(otel.parse_traceparent(bad),
                "must refuse " .. string.format("%q", bad))
        end
        h.assert_nil(otel.parse_traceparent(nil))
        h.assert_nil(otel.parse_traceparent(12345))
        h.assert_nil(otel.parse_traceparent({}))
    end)
end)

h.describe("a workload cannot choose its own trace", function()
    h.it("ignores an incoming traceparent by default", function()
        fresh()
        local span = otel.start_span("proxy.request",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
        h.assert_true(span ~= nil)
        h.assert_ne(span.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736",
            "a sandbox that picks its own trace id can pollute or correlate "
            .. "an operator's tracing backend")
        h.assert_nil(span.parent_span_id)
    end)

    h.it("continues the trace only when told to", function()
        fresh({ trustIncomingTrace = true })
        local span = otel.start_span("proxy.request",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
        h.assert_eq(span.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736")
        h.assert_eq(span.parent_span_id, "00f067aa0ba902b7")
    end)

    h.it("starts a fresh trace when the header is junk", function()
        fresh({ trustIncomingTrace = true })
        local span = otel.start_span("proxy.request", "not-a-traceparent")
        h.assert_true(span ~= nil)
        h.assert_eq(#span.trace_id, 32)
        h.assert_nil(span.parent_span_id)
    end)
end)

h.describe("identifiers are unpredictable and well formed", function()
    h.it("mints distinct ids", function()
        local seen = {}
        for _ = 1, 200 do
            local id = otel.new_trace_id()
            h.assert_eq(#id, 32)
            h.assert_nil(seen[id], "a trace id repeated")
            seen[id] = true
        end
    end)

    h.it("never mints the all-zero id", function()
        for _ = 1, 100 do
            h.assert_ne(otel.new_trace_id(),
                "00000000000000000000000000000000")
            h.assert_ne(otel.new_span_id(), "0000000000000000")
        end
    end)

    h.it("round-trips through the header form", function()
        local t, s = otel.new_trace_id(), otel.new_span_id()
        local p = otel.parse_traceparent(otel.traceparent(t, s, true))
        h.assert_eq(p.trace_id, t)
        h.assert_eq(p.span_id, s)
        h.assert_eq(p.sampled, true)
    end)
end)

h.describe("the span queue is bounded and never blocks a request", function()
    h.it("drops rather than growing without limit", function()
        fresh({ maxQueue = 4 })
        for i = 1, 50 do
            local s = otel.start_span("s" .. i)
            otel.finish(s, otel.STATUS_OK)
        end
        local stats = otel.stats()
        h.assert_eq(stats.queued, 4, "the queue must stop at its ceiling")
        h.assert_eq(stats.dropped, 46)
    end)

    h.it("drains in batches", function()
        fresh({ maxQueue = 16, maxBatch = 4 })
        for i = 1, 10 do
            otel.finish(otel.start_span("s" .. i), otel.STATUS_OK)
        end
        h.assert_eq(#otel.drain(), 4)
        h.assert_eq(otel.stats().queued, 6)
        h.assert_eq(#otel.drain(), 4)
        h.assert_eq(#otel.drain(), 2)
        h.assert_nil(otel.drain())
    end)

    h.it("does nothing at all when disabled", function()
        fresh({ enabled = false })
        h.assert_nil(otel.start_span("s"))
        otel.finish(nil, otel.STATUS_OK)
        h.assert_eq(otel.stats().queued, 0)
        h.assert_false(otel.enabled())
    end)

    h.it("is disabled without an endpoint", function()
        fresh({ endpoint = "" })
        h.assert_false(otel.enabled())
        h.assert_nil(otel.start_span("s"))
    end)
end)

h.describe("sampling is deterministic per trace", function()
    h.it("keeps everything at ratio one", function()
        fresh({ sampleRatio = 1.0 })
        local kept = 0
        for _ = 1, 100 do
            if otel.start_span("s") then kept = kept + 1 end
        end
        h.assert_eq(kept, 100)
    end)

    h.it("keeps nothing at ratio zero", function()
        fresh({ sampleRatio = 0 })
        local kept = 0
        for _ = 1, 100 do
            if otel.start_span("s") then kept = kept + 1 end
        end
        h.assert_eq(kept, 0)
    end)

    h.it("keeps roughly the ratio in between", function()
        fresh({ sampleRatio = 0.5 })
        local kept = 0
        for _ = 1, 600 do
            if otel.start_span("s") then kept = kept + 1 end
        end
        h.assert_true(kept > 200 and kept < 400,
            "expected about half of 600, kept " .. kept)
    end)
end)

h.describe("the exported payload is valid OTLP json", function()
    h.it("carries the resource, scope and span shape", function()
        fresh()
        local span = otel.start_span("proxy.request")
        otel.attr(span, "ro.decision", "deny")
        otel.attr(span, "ro.port", 443)
        otel.attr(span, "ro.tls", true)
        otel.event(span, "policy.evaluated")
        otel.finish(span, otel.STATUS_ERROR, "policy.default_deny")

        local payload = otel.encode_spans(otel.drain())
        local text = cjson.encode(payload)
        h.assert_true(text ~= nil, "the payload must encode as json")
        local back = cjson.decode(text)

        local rs = back.resourceSpans[1]
        h.assert_true(rs ~= nil)
        local names = {}
        for _, a in ipairs(rs.resource.attributes) do
            names[a.key] = a.value.stringValue
        end
        h.assert_eq(names["service.name"], "ro-test")
        h.assert_eq(names["host.name"], "node-a")

        local s = rs.scopeSpans[1].spans[1]
        h.assert_eq(s.name, "proxy.request")
        h.assert_eq(#s.traceId, 32)
        h.assert_eq(#s.spanId, 16)
        h.assert_eq(s.status.code, otel.STATUS_ERROR)
        h.assert_eq(s.status.message, "policy.default_deny")
        h.assert_eq(s.events[1].name, "policy.evaluated")
        h.assert_true(tonumber(s.endTimeUnixNano)
            >= tonumber(s.startTimeUnixNano))

        local attrs = {}
        for _, a in ipairs(s.attributes) do attrs[a.key] = a.value end
        h.assert_eq(attrs["ro.decision"].stringValue, "deny")
        h.assert_eq(attrs["ro.port"].intValue, "443")
        h.assert_eq(attrs["ro.tls"].boolValue, true)
    end)

    h.it("bounds an attribute a workload could influence", function()
        fresh()
        local span = otel.start_span("proxy.request")
        otel.attr(span, "ro.detail", string.rep("a", 5000))
        otel.attr(span, "ro.control", "a\nb\0c")
        otel.finish(span, otel.STATUS_OK)
        local s = otel.encode_spans(otel.drain())
            .resourceSpans[1].scopeSpans[1].spans[1]
        for _, a in ipairs(s.attributes) do
            if a.key == "ro.detail" then
                h.assert_true(#a.value.stringValue <= 210,
                    "an unbounded attribute lets a workload inflate every "
                    .. "export: got " .. #a.value.stringValue)
            end
            if a.key == "ro.control" then
                h.assert_nil(a.value.stringValue:find("\n", 1, true))
                h.assert_nil(a.value.stringValue:find("\0", 1, true))
            end
        end
    end)

    h.it("refuses an attribute type it cannot encode", function()
        fresh()
        local span = otel.start_span("proxy.request")
        otel.attr(span, "bad", {})
        otel.attr(span, "worse", print)
        otel.attr(span, "nothing", nil)
        h.assert_eq(#span.attributes, 0)
    end)

    h.it("caps the events on one span", function()
        fresh()
        local span = otel.start_span("proxy.request")
        for i = 1, 100 do otel.event(span, "e" .. i) end
        h.assert_eq(#span.events, 16)
    end)

    h.it("links a child to its parent in the same trace", function()
        fresh()
        local parent = otel.start_span("proxy.request")
        local child = otel.child(parent, "dns.resolve")
        h.assert_eq(child.trace_id, parent.trace_id)
        h.assert_eq(child.parent_span_id, parent.span_id)
        h.assert_ne(child.span_id, parent.span_id)
        h.assert_eq(child.kind, otel.KIND_CLIENT)
        h.assert_nil(otel.child(nil, "x"))
    end)
end)
