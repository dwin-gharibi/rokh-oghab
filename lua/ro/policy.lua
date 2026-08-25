local target = require("ro.target")
local cidr = require("ro.cidr")
local util = require("ro.util")

local _M = { _VERSION = "1.0.0" }

local bundle_mt = {}
bundle_mt.__index = bundle_mt

local find = string.find
local sub = string.sub
local gsub = string.gsub
local concat = table.concat
local sort = table.sort

local TIER_ORDER = {
    global = 0,
    cluster = 1,
    namespace = 2,
    profile = 3,
    pod = 4,
}

local VALID_ACTIONS = { allow = true, deny = true }
local VALID_PROTOCOLS = { http = true, https = true, tcp = true }
local VALID_METHODS = {
    GET = true, HEAD = true, POST = true, PUT = true, DELETE = true,
    PATCH = true, OPTIONS = true, TRACE = true, CONNECT = true,
}

local RULE_KEYS = {
    name = true, action = true, destinations = true, ports = true,
    protocols = true, methods = true, paths = true, rateLimit = true,
    connections = true, bandwidth = true, tls = true, description = true,
    requestSize = true, responseSize = true,
}
local DEST_KEYS = {
    hostnames = true, hostnameSuffixes = true, cidrs = true, resolvedCidrs = true,
}
local POLICY_KEYS = {
    name = true, tier = true, priority = true, selector = true,
    defaultAction = true, rules = true, description = true,
}
local SELECTOR_KEYS = {
    namespaces = true, profiles = true, serviceAccounts = true,
    identities = true, labels = true,
}
local TLS_KEYS = { minVersion = true, requireSni = true, inspect = true }

local function verr(fmt, ...)
    return nil, string.format(fmt, ...)
end

local function check_keys(tbl, allowed, where)
    for k in pairs(tbl) do
        if not allowed[k] then
            return verr("unknown field %q in %s", tostring(k), where)
        end
    end
    return true
end

local function as_list(v, where)
    if v == nil then
        return nil
    end
    if type(v) ~= "table" or not util.is_array(v) then
        return verr("%s must be an array", where)
    end
    return v
end

local function parse_port_spec(spec, where)
    if type(spec) == "number" then
        if spec < 1 or spec > 65535 or spec ~= math.floor(spec) then
            return verr("%s: port out of range", where)
        end
        return { from = spec, to = spec }
    end
    if type(spec) == "string" then
        local a, b = spec:match("^(%d+)%s*%-%s*(%d+)$")
        if a then
            local from, to = tonumber(a), tonumber(b)
            if not from or not to or from < 1 or to > 65535 or from > to then
                return verr("%s: invalid port range %q", where, spec)
            end
            return { from = from, to = to }
        end
        local p = target.parse_port(spec)
        if not p then
            return verr("%s: invalid port %q", where, spec)
        end
        return { from = p, to = p }
    end
    if type(spec) == "table" then
        local from = tonumber(spec.from)
        local to = tonumber(spec.to)
        if not from or not to or from < 1 or to > 65535 or from > to then
            return verr("%s: invalid port object", where)
        end
        return { from = from, to = to }
    end
    return verr("%s: unsupported port specification", where)
end

local function glob_to_pattern(glob)
    local out = { "^" }
    local i = 1
    local n = #glob
    while i <= n do
        local c = sub(glob, i, i)
        if c == "*" then
            if sub(glob, i + 1, i + 1) == "*" then
                out[#out + 1] = ".*"
                i = i + 2
            else
                out[#out + 1] = "[^/]*"
                i = i + 1
            end
        elseif c == "?" then
            out[#out + 1] = "[^/]"
            i = i + 1
        elseif find(c, "[%^%$%(%)%%%.%[%]%+%-]") then
            out[#out + 1] = "%" .. c
            i = i + 1
        else
            out[#out + 1] = c
            i = i + 1
        end
    end
    out[#out + 1] = "$"
    return concat(out)
end

_M.glob_to_pattern = glob_to_pattern

local function reject_empty_list(rule_name, field, value)
    if value == nil then
        return true
    end
    if type(value) == "table" and #value == 0 and next(value) == nil then
        return nil, string.format(
            "rule %q: %s is present but empty; an empty list is not the same "
            .. "as omitting the field, which would mean 'any'. Remove the "
            .. "field to place no constraint, or name what it covers.",
            rule_name or "?", field)
    end
    return true
end

local function compile_rule(raw, policy_name, index, opts)
    if type(raw) ~= "table" then
        return verr("policy %q rule #%d is not an object", policy_name, index)
    end
    local ok, err = check_keys(raw, RULE_KEYS,
        string.format("policy %q rule #%d", policy_name, index))
    if not ok then return nil, err end

    local rule = {
        name = raw.name or string.format("%s#%d", policy_name, index),
        policy = policy_name,
        index = index,
    }

    if type(raw.action) ~= "string" or not VALID_ACTIONS[raw.action] then
        return verr("rule %q: action must be \"allow\" or \"deny\"", rule.name)
    end
    rule.action = raw.action

    local dest = raw.destinations
    rule.hostnames = {}
    rule.suffixes = {}
    rule.cidrs = nil
    rule.resolved_cidrs = nil
    local has_dest = false

    if dest ~= nil then
        if type(dest) ~= "table" then
            return verr("rule %q: destinations must be an object", rule.name)
        end
        ok, err = check_keys(dest, DEST_KEYS, "rule " .. rule.name .. " destinations")
        if not ok then return nil, err end

        local hostnames, herr = as_list(dest.hostnames, "destinations.hostnames")
        if dest.hostnames ~= nil and not hostnames then return nil, herr end
        if hostnames then
            for _, hn in ipairs(hostnames) do
                local norm, nerr = target.normalize_hostname(hn)
                if not norm then
                    return verr("rule %q: invalid hostname %q (%s)",
                        rule.name, tostring(hn), tostring(nerr))
                end
                rule.hostnames[norm] = true
                has_dest = true
            end
        end

        local suffixes, serr = as_list(dest.hostnameSuffixes, "destinations.hostnameSuffixes")
        if dest.hostnameSuffixes ~= nil and not suffixes then return nil, serr end
        if suffixes then
            for _, sfx in ipairs(suffixes) do
                local clean = sfx
                if type(clean) == "string" and sub(clean, 1, 2) == "*." then
                    clean = sub(clean, 3)
                end
                if type(clean) == "string" and sub(clean, 1, 1) == "." then
                    clean = sub(clean, 2)
                end
                local norm, nerr = target.normalize_hostname(clean)
                if not norm then
                    return verr("rule %q: invalid hostname suffix %q (%s)",
                        rule.name, tostring(sfx), tostring(nerr))
                end
                local _, labels = util.split(norm, ".")
                local min_labels = (opts and opts.min_suffix_labels) or 2
                if rule.action == "allow" and labels < min_labels then
                    return verr("rule %q: hostname suffix %q is too broad (needs >= %d labels)",
                        rule.name, norm, min_labels)
                end
                rule.suffixes[norm] = true
                has_dest = true
            end
        end

        local cidrs, cerr = as_list(dest.cidrs, "destinations.cidrs")
        if dest.cidrs ~= nil and not cidrs then return nil, cerr end
        if cidrs and #cidrs > 0 then
            rule.cidrs = cidr.new()
            for _, c in ipairs(cidrs) do
                local added, aerr = rule.cidrs:add(c, rule.name)
                if not added then
                    return verr("rule %q: %s", rule.name, tostring(aerr))
                end
                has_dest = true
            end
        end

        local rcidrs, rerr = as_list(dest.resolvedCidrs, "destinations.resolvedCidrs")
        if dest.resolvedCidrs ~= nil and not rcidrs then return nil, rerr end
        if rcidrs and #rcidrs > 0 then
            rule.resolved_cidrs = cidr.new()
            for _, c in ipairs(rcidrs) do
                local added, aerr = rule.resolved_cidrs:add(c, rule.name)
                if not added then
                    return verr("rule %q: %s", rule.name, tostring(aerr))
                end
            end
        end
    end

    rule.any_destination = not has_dest

    if rule.action == "allow" and not has_dest then
        return verr("rule %q: allow rules must declare at least one destination",
            rule.name)
    end

    local eok, eerr = reject_empty_list(rule.name, "ports", raw.ports)
    if not eok then return nil, eerr end
    local ports, perr = as_list(raw.ports, "ports")
    if raw.ports ~= nil and not ports then return nil, perr end
    if ports and #ports > 0 then
        rule.ports = {}
        for _, spec in ipairs(ports) do
            local range, rerr2 = parse_port_spec(spec, "rule " .. rule.name)
            if not range then return nil, rerr2 end
            rule.ports[#rule.ports + 1] = range
        end
    end
    if rule.action == "allow" and not rule.ports then
        return verr("rule %q: allow rules must declare ports", rule.name)
    end

    eok, eerr = reject_empty_list(rule.name, "protocols", raw.protocols)
    if not eok then return nil, eerr end
    local protocols, prerr = as_list(raw.protocols, "protocols")
    if raw.protocols ~= nil and not protocols then return nil, prerr end
    if protocols and #protocols > 0 then
        rule.protocols = {}
        for _, p in ipairs(protocols) do
            if type(p) ~= "string" or not VALID_PROTOCOLS[p] then
                return verr("rule %q: unsupported protocol %q", rule.name, tostring(p))
            end
            rule.protocols[p] = true
        end
    end

    eok, eerr = reject_empty_list(rule.name, "methods", raw.methods)
    if not eok then return nil, eerr end
    local methods, merr = as_list(raw.methods, "methods")
    if raw.methods ~= nil and not methods then return nil, merr end
    if methods and #methods > 0 then
        rule.methods = {}
        for _, m in ipairs(methods) do
            if type(m) ~= "string" or not VALID_METHODS[m:upper()] then
                return verr("rule %q: unsupported method %q", rule.name, tostring(m))
            end
            rule.methods[m:upper()] = true
        end
    end

    eok, eerr = reject_empty_list(rule.name, "paths", raw.paths)
    if not eok then return nil, eerr end
    local paths, pterr = as_list(raw.paths, "paths")
    if raw.paths ~= nil and not paths then return nil, pterr end
    if paths and #paths > 0 then
        rule.paths = {}
        for _, p in ipairs(paths) do
            if type(p) ~= "string" or #p == 0 or #p > 1024 then
                return verr("rule %q: invalid path pattern", rule.name)
            end
            rule.paths[#rule.paths + 1] = glob_to_pattern(p)
        end
    end

    if raw.rateLimit ~= nil then
        if type(raw.rateLimit) ~= "table" then
            return verr("rule %q: rateLimit must be an object", rule.name)
        end
        if raw.rateLimit.requestsPerSecond ~= nil
            and not tonumber(raw.rateLimit.requestsPerSecond) then
            return verr("rule %q: rateLimit.requestsPerSecond is not a number",
                rule.name)
        end
        if raw.rateLimit.burst ~= nil and not tonumber(raw.rateLimit.burst) then
            return verr("rule %q: rateLimit.burst is not a number", rule.name)
        end
        local rps = tonumber(raw.rateLimit.requestsPerSecond)
        local burst = tonumber(raw.rateLimit.burst)
        if rps and (rps <= 0 or rps > 1000000) then
            return verr("rule %q: rateLimit.requestsPerSecond out of range", rule.name)
        end
        if burst and (burst < 1 or burst > 1000000) then
            return verr("rule %q: rateLimit.burst out of range (1 to 1000000); "
                .. "an unbounded burst lets a workload spend the whole budget "
                .. "at once, which is what the limit exists to prevent",
                rule.name)
        end
        if burst and rps and burst < rps then
            return verr("rule %q: rateLimit.burst is below "
                .. "requestsPerSecond, which would throttle below the rate "
                .. "the rule declares", rule.name)
        end
        rule.rate_limit = { rps = rps, burst = burst or (rps and math.ceil(rps)) }
    end

    if raw.connections ~= nil then
        if type(raw.connections) ~= "table" then
            return verr("rule %q: connections must be an object", rule.name)
        end
        local maxc = tonumber(raw.connections.max)
        if maxc and (maxc < 1 or maxc > 1000000) then
            return verr("rule %q: connections.max out of range", rule.name)
        end
        rule.max_connections = maxc
    end

    if raw.bandwidth ~= nil then
        if type(raw.bandwidth) ~= "table" then
            return verr("rule %q: bandwidth must be an object", rule.name)
        end
        local declared = raw.bandwidth.bytesPerSecond or raw.bandwidth.max
        local bps = util.parse_size(declared, nil)
        if declared ~= nil and not bps then
            return verr("rule %q: bandwidth %s is not a size; a value that "
                .. "does not parse would silently leave the rule with no "
                .. "bandwidth limit at all", rule.name,
                util.safe_str(declared, 40))
        end
        if bps and bps < 1024 then
            return verr("rule %q: bandwidth too small (min 1024 bytes/s)", rule.name)
        end
        if bps and bps > 68719476736 then
            return verr("rule %q: bandwidth out of range (max 64GiB/s)",
                rule.name)
        end
        rule.bandwidth = bps
    end

    for field, target in pairs({ requestSize = "max_request_size",
        responseSize = "max_response_size" }) do
        if raw[field] ~= nil then
            local size = util.parse_size(raw[field], nil)
            if not size then
                return verr("rule %q: %s %s is not a size; a value that does "
                    .. "not parse would silently leave the rule with no size "
                    .. "limit at all", rule.name, field,
                    util.safe_str(raw[field], 40))
            end
            if size < 1 or size > 1099511627776 then
                return verr("rule %q: %s out of range (1 byte to 1TiB)",
                    rule.name, field)
            end
            rule[target] = size
        end
    end

    if raw.tls ~= nil then
        if type(raw.tls) ~= "table" then
            return verr("rule %q: tls must be an object", rule.name)
        end
        ok, err = check_keys(raw.tls, TLS_KEYS, "rule " .. rule.name .. " tls")
        if not ok then return nil, err end
        if raw.tls.inspect ~= nil and raw.tls.inspect ~= false then
            return verr("rule %q: tls.inspect is not implemented; this gateway "
                .. "passes TLS through and never terminates it, so there is no "
                .. "configuration in which it can read a method or a path "
                .. "inside a tunnel", rule.name)
        end
        rule.tls = {
            min_version = raw.tls.minVersion,
            require_sni = raw.tls.requireSni,
        }
        if rule.tls.min_version ~= nil then
            local mv = tostring(rule.tls.min_version)
            if mv ~= "1.0" and mv ~= "1.1" and mv ~= "1.2" and mv ~= "1.3" then
                return verr("rule %q: tls.minVersion must be 1.0, 1.1, 1.2 or 1.3",
                    rule.name)
            end
            rule.tls.min_version = mv
        end
    end

    if rule.methods or rule.paths then
        local tunnelled = not rule.protocols
            or rule.protocols.https == true or rule.protocols.tcp == true
        if tunnelled then
            local which = rule.methods and "methods" or "paths"
            return verr("rule %q: %s cannot be enforced on a tunnelled "
                .. "protocol. The gateway does not terminate TLS, so it never "
                .. "sees the method or path inside an https or tcp connection, "
                .. "and a constraint it cannot read would be silently ignored. "
                .. "Scope this rule to protocols: [http], or drop the "
                .. "constraint and control the destination instead.",
                rule.name, which)
        end
    end

    return rule
end

local function compile_policy(raw, index, opts)
    if type(raw) ~= "table" then
        return verr("policy #%d is not an object", index)
    end
    local name = raw.name
    if type(name) ~= "string" or name == "" or #name > 128
        or find(name, "[^%w%.%-_/]") then
        return verr("policy #%d: invalid name", index)
    end
    local ok, err = check_keys(raw, POLICY_KEYS, "policy " .. name)
    if not ok then return nil, err end

    local tier = raw.tier or "profile"
    if TIER_ORDER[tier] == nil then
        return verr("policy %q: unknown tier %q", name, tostring(tier))
    end

    local default_action = raw.defaultAction or "deny"
    if not VALID_ACTIONS[default_action] then
        return verr("policy %q: invalid defaultAction", name)
    end
    if default_action == "allow" and not (opts and opts.allow_default_allow) then
        return verr("policy %q: defaultAction \"allow\" is refused by this build", name)
    end

    local selector = raw.selector or {}
    if type(selector) ~= "table" then
        return verr("policy %q: selector must be an object", name)
    end
    ok, err = check_keys(selector, SELECTOR_KEYS, "policy " .. name .. " selector")
    if not ok then return nil, err end

    local compiled = {
        name = name,
        tier = tier,
        tier_order = TIER_ORDER[tier],
        priority = tonumber(raw.priority) or 0,
        default_action = default_action,
        selector = {
            namespaces = {},
            profiles = {},
            service_accounts = {},
            identities = {},
            labels = selector.labels,
        },
        allow_rules = {},
        deny_rules = {},
        rules = {},
    }

    local function fill(setname, list, where)
        if list == nil then return true end
        local arr, aerr = as_list(list, where)
        if not arr then return nil, aerr end
        if #arr == 0 then
            return verr("policy %q: %s is present but empty; an empty selector "
                .. "list would match every identity rather than none. Remove "
                .. "the field to leave the policy unscoped, or name what it "
                .. "selects.", name, where)
        end
        compiled.selector[setname .. "_count"] = 0
        for _, v in ipairs(arr) do
            if type(v) ~= "string" or v == "" or #v > 253 then
                return verr("policy %q: invalid %s entry", name, where)
            end
            compiled.selector[setname][v] = true
            compiled.selector[setname .. "_count"] =
                (compiled.selector[setname .. "_count"] or 0) + 1
        end
        return true
    end

    ok, err = fill("namespaces", selector.namespaces, "selector.namespaces")
    if not ok then return nil, err end
    ok, err = fill("profiles", selector.profiles, "selector.profiles")
    if not ok then return nil, err end
    ok, err = fill("service_accounts", selector.serviceAccounts, "selector.serviceAccounts")
    if not ok then return nil, err end
    ok, err = fill("identities", selector.identities, "selector.identities")
    if not ok then return nil, err end

    if selector.labels ~= nil then
        if type(selector.labels) ~= "table" then
            return verr("policy %q: selector.labels must be an object", name)
        end
        local labelled = false
        for _ in pairs(selector.labels) do
            labelled = true
            break
        end
        if not labelled then
            return verr("policy %q: selector.labels is present but empty; an "
                .. "empty label selector would match every identity rather "
                .. "than none. Remove the field to leave the policy unscoped, "
                .. "or name what it selects.", name)
        end
    end

    local rules, rerr = as_list(raw.rules, "policy " .. name .. " rules")
    if raw.rules ~= nil and not rules then return nil, rerr end
    rules = rules or {}
    if #rules > 4096 then
        return verr("policy %q: too many rules", name)
    end
    for i, rr in ipairs(rules) do
        local rule, cerr = compile_rule(rr, name, i, opts)
        if not rule then return nil, cerr end
        rule.tier_order = compiled.tier_order
        rule.policy_priority = compiled.priority
        compiled.rules[#compiled.rules + 1] = rule
        if rule.action == "deny" then
            compiled.deny_rules[#compiled.deny_rules + 1] = rule
        else
            compiled.allow_rules[#compiled.allow_rules + 1] = rule
        end
    end

    return compiled
end

local function selector_matches(sel, identity)
    if sel.namespaces_count and sel.namespaces_count > 0 then
        if not identity.namespace or not sel.namespaces[identity.namespace] then
            return false
        end
    end
    if sel.profiles_count and sel.profiles_count > 0 then
        if not identity.profile or not sel.profiles[identity.profile] then
            return false
        end
    end
    if sel.service_accounts_count and sel.service_accounts_count > 0 then
        if not identity.serviceAccount or not sel.service_accounts[identity.serviceAccount] then
            return false
        end
    end
    if sel.identities_count and sel.identities_count > 0 then
        if not identity.id or not sel.identities[identity.id] then
            return false
        end
    end
    if sel.labels then
        local labels = identity.labels
        for k, v in pairs(sel.labels) do
            if not labels or tostring(labels[k]) ~= tostring(v) then
                return false
            end
        end
    end
    return true
end

_M.selector_matches = selector_matches

local function port_matches(rule, port)
    if not rule.ports then
        return true
    end
    local list = rule.ports
    for i = 1, #list do
        local r = list[i]
        if port >= r.from and port <= r.to then
            return true
        end
    end
    return false
end

local function protocol_matches(rule, protocol)
    if not rule.protocols then
        return true
    end
    if protocol == "tunnel" then
        return rule.protocols.https == true or rule.protocols.tcp == true
    end
    return rule.protocols[protocol] == true
end

local function method_matches(rule, method)
    if not rule.methods then
        return true
    end
    if not method then
        return false
    end
    return rule.methods[method] == true
end

local function path_matches(rule, path)
    if not rule.paths then
        return true
    end
    if not path then
        return false
    end
    for i = 1, #rule.paths do
        if find(path, rule.paths[i]) then
            return true
        end
    end
    return false
end

local function destination_matches(rule, req)
    if rule.any_destination then
        return true
    end
    local info = req.host_info
    if info.kind == "hostname" then
        local host = info.canonical
        if rule.hostnames[host] then
            return true
        end
        if rule.suffixes[host] then
            return true
        end
        if next(rule.suffixes) ~= nil then
            local start = 1
            while true do
                local i = find(host, ".", start, true)
                if not i then break end
                local candidate = sub(host, i + 1)
                if rule.suffixes[candidate] then
                    return true
                end
                start = i + 1
            end
        end
        return false
    end
    if rule.cidrs then
        if info.kind == "ipv4" then
            return rule.cidrs:match_v4(info.v4) ~= nil
        end
        if info.kind == "ipv6" then
            return rule.cidrs:match_v6(info.v6) ~= nil
        end
    end
    return false
end

_M.destination_matches = destination_matches

local function rule_matches(rule, req)
    if not port_matches(rule, req.port) then return false end
    if not protocol_matches(rule, req.protocol) then return false end
    if not destination_matches(rule, req) then return false end
    if rule.methods and not method_matches(rule, req.method) then return false end
    if rule.paths and not path_matches(rule, req.path) then return false end
    return true
end

_M.rule_matches = rule_matches

local function merge_limits(decision, rule)
    if rule.rate_limit and rule.rate_limit.rps then
        if not decision.rate_limit or rule.rate_limit.rps < decision.rate_limit.rps then
            decision.rate_limit = rule.rate_limit
        end
    end
    if rule.max_connections then
        if not decision.max_connections or rule.max_connections < decision.max_connections then
            decision.max_connections = rule.max_connections
        end
    end
    if rule.bandwidth then
        if not decision.bandwidth or rule.bandwidth < decision.bandwidth then
            decision.bandwidth = rule.bandwidth
        end
    end
    if rule.max_request_size then
        if not decision.max_request_size or rule.max_request_size < decision.max_request_size then
            decision.max_request_size = rule.max_request_size
        end
    end
    if rule.max_response_size then
        if not decision.max_response_size or rule.max_response_size < decision.max_response_size then
            decision.max_response_size = rule.max_response_size
        end
    end
    if rule.tls then
        decision.tls = decision.tls or {}
        if rule.tls.inspect then decision.tls.inspect = true end
        if rule.tls.require_sni then
            decision.tls.require_sni = true
        end
        if rule.tls.min_version then
            local cur = decision.tls.min_version
            if not cur or tonumber(rule.tls.min_version) > tonumber(cur) then
                decision.tls.min_version = rule.tls.min_version
            end
        end
    end
    if rule.resolved_cidrs then
        decision.resolved_cidrs = decision.resolved_cidrs or {}
        decision.resolved_cidrs[#decision.resolved_cidrs + 1] = rule.resolved_cidrs
    end
end

local function label_key(labels)
    if type(labels) ~= "table" then
        return "-"
    end
    local names = util.sorted_keys(labels)
    if #names == 0 then
        return "-"
    end
    local parts = {}
    for i = 1, #names do
        parts[i] = names[i] .. "\1" .. tostring(labels[names[i]])
    end
    return concat(parts, "\2")
end

function bundle_mt:effective(identity)
    local key = concat({
        identity.namespace or "-",
        identity.profile or "-",
        identity.serviceAccount or "-",
        identity.id or "-",
        label_key(identity.labels),
    }, "\0")
    local cached = self.effective_cache[key]
    if cached then
        return cached
    end
    local eff = { deny_rules = {}, allow_rules = {}, policies = {} }
    for i = 1, #self.policies do
        local p = self.policies[i]
        if selector_matches(p.selector, identity) then
            eff.policies[#eff.policies + 1] = p.name
            for j = 1, #p.deny_rules do
                eff.deny_rules[#eff.deny_rules + 1] = p.deny_rules[j]
            end
            for j = 1, #p.allow_rules do
                eff.allow_rules[#eff.allow_rules + 1] = p.allow_rules[j]
            end
        end
    end
    sort(eff.allow_rules, function(a, b)
        if a.tier_order ~= b.tier_order then return a.tier_order > b.tier_order end
        if a.policy_priority ~= b.policy_priority then
            return a.policy_priority > b.policy_priority
        end
        return a.index < b.index
    end)
    if self.effective_cache_n >= 4096 then
        self.effective_cache = {}
        self.effective_cache_n = 0
    end
    self.effective_cache[key] = eff
    self.effective_cache_n = self.effective_cache_n + 1
    return eff
end

function bundle_mt:evaluate(identity, req)
    if self.emergency_deny then
        return { action = "deny", reason = "emergency.deny", rule = nil }
    end
    local eff = self:effective(identity)

    for i = 1, #eff.deny_rules do
        local rule = eff.deny_rules[i]
        if rule_matches(rule, req) then
            return {
                action = "deny",
                reason = "policy.explicit_deny",
                rule = rule.name,
                policy = rule.policy,
            }
        end
    end

    local decision = nil
    for i = 1, #eff.allow_rules do
        local rule = eff.allow_rules[i]
        if rule_matches(rule, req) then
            if not decision then
                decision = {
                    action = "allow",
                    reason = "policy.allow",
                    rule = rule.name,
                    policy = rule.policy,
                    matched = {},
                }
            end
            decision.matched[#decision.matched + 1] = rule.name
            merge_limits(decision, rule)
        end
    end

    if decision then
        return decision
    end

    return {
        action = "deny",
        reason = "policy.default_deny",
        rule = nil,
        policies = eff.policies,
    }
end

function bundle_mt:hostname_permitted(identity, host_info)
    if self.emergency_deny then
        return false, "emergency.deny"
    end
    local eff = self:effective(identity)
    local probe = { host_info = host_info, port = 0, protocol = "any" }

    for i = 1, #eff.deny_rules do
        local rule = eff.deny_rules[i]
        if destination_matches(rule, probe) then
            return false, "policy.explicit_deny", rule.name
        end
    end
    for i = 1, #eff.allow_rules do
        local rule = eff.allow_rules[i]
        if destination_matches(rule, probe) then
            return true, "policy.allow", rule.name
        end
    end
    return false, "policy.default_deny"
end

function bundle_mt:check_resolved(decision, kind, value)
    if not decision.resolved_cidrs then
        return true
    end
    for i = 1, #decision.resolved_cidrs do
        local set = decision.resolved_cidrs[i]
        local hit
        if kind == "ipv4" then
            hit = set:match_v4(value)
        else
            hit = set:match_v6(value)
        end
        if hit then
            return true
        end
    end
    return false, "policy.resolved_cidr"
end

function bundle_mt:summary()
    local out = {
        version = self.version,
        issuedAt = self.issued_at,
        ttlSeconds = self.ttl_seconds,
        emergencyDeny = self.emergency_deny,
        policyCount = #self.policies,
        ruleCount = self.rule_count,
        policies = {},
    }
    for i = 1, #self.policies do
        local p = self.policies[i]
        out.policies[i] = {
            name = p.name,
            tier = p.tier,
            priority = p.priority,
            rules = #p.rules,
            allowRules = #p.allow_rules,
            denyRules = #p.deny_rules,
        }
    end
    return out
end

function _M.compile(raw, opts)
    opts = opts or {}
    if type(raw) ~= "table" then
        return verr("bundle must be an object")
    end

    local version = tonumber(raw.version)
    if not version or version < 0 then
        return verr("bundle: version must be a non-negative number")
    end

    local defaults_raw = raw.defaults
    if defaults_raw ~= nil and type(defaults_raw) ~= "table" then
        return verr("bundle: defaults must be an object")
    end
    if defaults_raw and defaults_raw.maxStalenessSeconds ~= nil then
        local staleness = tonumber(defaults_raw.maxStalenessSeconds)
        if not staleness then
            return verr("bundle: defaults.maxStalenessSeconds must be a number")
        end
        if staleness <= 0 then
            return verr("bundle: defaults.maxStalenessSeconds must be greater "
                .. "than zero; a gateway needs some budget to survive a "
                .. "controller restart, and zero would disable the check "
                .. "rather than tighten it. To stop enforcing staleness at "
                .. "all, set controller.failClosed to false on the gateway.")
        end
        if staleness > 86400 then
            return verr("bundle: defaults.maxStalenessSeconds of %d is longer "
                .. "than a day, which is not a fail-closed budget", staleness)
        end
    end

    local ttl_raw = raw.ttlSeconds
    if ttl_raw ~= nil then
        local ttl = tonumber(ttl_raw)
        if not ttl or ttl <= 0 then
            return verr("bundle: ttlSeconds must be a positive number")
        end
    end

    local policies_raw = raw.policies
    if policies_raw ~= nil and (type(policies_raw) ~= "table"
        or not util.is_array(policies_raw)) then
        return verr("bundle: policies must be an array")
    end
    policies_raw = policies_raw or {}
    if #policies_raw > 1024 then
        return verr("bundle: too many policies")
    end

    local compiled = setmetatable({
        version = version,
        issued_at = tonumber(raw.issuedAt) or util.now(),
        ttl_seconds = tonumber(raw.ttlSeconds) or 300,
        emergency_deny = raw.emergencyDeny == true,
        policies = {},
        rule_count = 0,
        effective_cache = {},
        effective_cache_n = 0,
        raw_defaults = raw.defaults or {},
        guard_config = raw.guard or {},
        identities_config = raw.identities or {},
    }, bundle_mt)

    local names = {}
    for i, praw in ipairs(policies_raw) do
        local p, err = compile_policy(praw, i, opts)
        if not p then return nil, err end
        if names[p.name] then
            return verr("bundle: duplicate policy name %q", p.name)
        end
        names[p.name] = true
        compiled.policies[#compiled.policies + 1] = p
        compiled.rule_count = compiled.rule_count + #p.rules
    end

    sort(compiled.policies, function(a, b)
        if a.tier_order ~= b.tier_order then return a.tier_order < b.tier_order end
        if a.priority ~= b.priority then return a.priority < b.priority end
        return a.name < b.name
    end)

    return compiled
end

_M.TIER_ORDER = TIER_ORDER

return _M
