local _M = { _VERSION = "1.0.0" }

local find = string.find
local sub = string.sub

local KNOWN = {}

local function declare(list)
    for i = 1, #list do
        KNOWN[list[i]] = true
    end
end

_M.POLICY = {
    "policy.allow",
    "policy.default_deny",
    "policy.explicit_deny",
    "policy.resolved_cidr",
    "policy.stale",
    "policy.not_loaded",
}

_M.IDENTITY = {
    "identity.unknown",
    "identity.invalid_token",
    "identity.malformed_credentials",
}

_M.PROTOCOL = {
    "protocol.malformed_request",
    "protocol.framing",
    "protocol.bad_path",
    "protocol.path_not_normalized",
    "protocol.missing_host",
    "protocol.bad_host_header",
    "protocol.host_mismatch",
    "protocol.bad_authority",
    "protocol.not_a_proxy_request",
    "protocol.origin_form_required",
    "protocol.request_body",
    "protocol.chunk",
    "protocol.chunk_terminator",
    "protocol.chunk_trailers",
}

_M.TLS = {
    "tls.required",
    "tls.expected_on_tls_port",
    "tls.expected_client_hello",
    "tls.handshake_incomplete",
    "tls.sni_missing",
    "tls.sni_invalid",
    "tls.sni_mismatch",
    "tls.sni_not_allowed",
    "tls.version_too_low",
}

_M.DNS = {
    "dns.invalid_name",
    "dns.qtype_not_allowed",
    "dns.no_address",
    "dns.no_permitted_address",
    "dns.all_answers_blocked",
    "dns.ipv6_disabled",
    "dns.nxdomain",
    "dns.server_failure",
    "dns.refused",
    "dns.not_implemented",
    "dns.malformed_query",
    "dns.malformed_answer",
    "dns.answer_mismatch",
    "dns.unreachable",
    "dns.timeout",
    "dns.no_entropy",
    "dns.failed",
}

_M.LIMIT = {
    "limit.rate",
    "limit.connections",
    "limit.global_connections",
    "limit.source_connections",
    "limit.body_size",
    "limit.unavailable",
}

_M.REDIRECT = {
    "redirect.policy_denied",
    "redirect.malformed",
    "redirect.bad_scheme",
    "redirect.blocked",
    "redirect.not_loaded",
}

_M.UPSTREAM = {
    "upstream.no_response",
    "upstream.bad_response",
    "upstream.head_too_large",
    "upstream.response_framing",
    "upstream.write_failed",
    "upstream.connect_failed",
    "upstream.interim_framing",
    "upstream.interim_flood",
    "upstream.protocol_upgrade",
}

_M.GUARD = {
    "denied",
    "guard.blocked",
    "guard.blocked:cloud-metadata",
    "guard.blocked:default-private-v4",
    "guard.blocked:default-private-v6",
    "guard.blocked:configured-block",
    "guard.blocked:obfuscated-address-literal",
    "guard.blocked:not-an-address",
    "guard.blocked:invalid-target",
    "guard.blocked:ipv6-disabled",
    "guard.blocked:unknown-address-family",
    "guard.blocked:embedded-v4:cloud-metadata",
    "guard.blocked:embedded-v4:default-private-v4",
    "guard.blocked:embedded-v4:configured-block",
}

_M.OTHER = {
    "emergency.deny",
    "transparent.name_address_mismatch",
    "client.write_failed",
    "other",
}

declare(_M.POLICY)
declare(_M.IDENTITY)
declare(_M.PROTOCOL)
declare(_M.TLS)
declare(_M.DNS)
declare(_M.LIMIT)
declare(_M.REDIRECT)
declare(_M.UPSTREAM)
declare(_M.GUARD)
declare(_M.OTHER)

function _M.is_known(reason)
    return type(reason) == "string" and KNOWN[reason] == true
end

function _M.label(reason)
    if type(reason) ~= "string" or reason == "" then
        return "other"
    end
    if KNOWN[reason] then
        return reason
    end
    local colon = find(reason, ":", 1, true)
    while colon do
        local prefix = sub(reason, 1, colon - 1)
        if KNOWN[prefix] then
            return prefix
        end
        colon = find(reason, ":", colon + 1, true)
    end
    return "other"
end

function _M.public(reason)
    if type(reason) ~= "string" or reason == "" then
        return "denied"
    end
    if KNOWN[reason] then
        return reason
    end
    local colon = find(reason, ":", 1, true)
    local longest
    while colon do
        local prefix = sub(reason, 1, colon - 1)
        if KNOWN[prefix] then
            longest = prefix
        end
        colon = find(reason, ":", colon + 1, true)
    end
    if longest then
        return longest
    end
    return "denied"
end

function _M.count()
    local n = 0
    for _ in pairs(KNOWN) do
        n = n + 1
    end
    return n
end

return _M
