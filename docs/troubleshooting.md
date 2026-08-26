# Troubleshooting

Rokh Oghab refuses things for a living. Most of what looks like a fault is the
gateway doing its job, so the first question is always *which* reason it gave,
not whether it was right to give one.

Every refusal carries a stable machine-readable reason code. This document is
the catalogue.

---

## Start here

```bash
roctl gateway audit --action deny --limit 50 -o json \
  | jq -c '{ts, identity, profile, host, port, protocol, reason}'
```

The `reason` field answers the question. Find it below.

If you cannot reach the gateway admin API, the same events are on stdout:

```bash
kubectl -n rokh-oghab logs -l app=ro-gateway --since=15m \
  | jq -c 'select(.action=="deny") | {ts, profile, host, reason}'
```

And a workload sees the reason too, on refusals the gateway can answer in-band:

```
HTTP/1.1 403 Forbidden
Content-Type: application/json
Proxy-Agent: rokh-oghab
X-Rokh-Oghab-Reason: policy.default_deny
Connection: close

{"error":"forbidden_by_rokh_oghab","reason":"policy.default_deny","detail":""}
```

The status code narrows it further before you read the reason at all:

| Status | Category |
| --- | --- |
| `400` | the request was malformed — a `protocol.*` reason |
| `403` | identified, understood, and refused — usually `policy.*`, `guard.*` or `tls.*` |
| `407` | not identified — an `identity.*` reason, with `Proxy-Authenticate` |
| `429` | a per-identity limiter refused it — `limit.rate` or `limit.connections` |
| `502` | the destination failed — an `upstream.*` reason |
| `503` | the gateway cannot serve it — `policy.stale`, `policy.not_loaded` or `limit.global_connections` |
| `504` | the destination timed out |

`429` and `503` say different things about a limit. `429` means *this identity*
is asking for too much and should back off. `503` means *this gateway* is full,
which is a capacity problem rather than a caller problem.

---

## Reason codes

### `policy.*` — the policy engine decided

| Code | Meaning |
| --- | --- |
| `policy.default_deny` | no rule permitted this destination |
| `policy.explicit_deny` | a deny rule matched |
| `policy.resolved_cidr` | the name resolved, but every address it resolved to was outside `resolvedCidrs` |
| `policy.stale` | the bundle exceeded `maxStalenessSeconds` and the gateway is failing closed |
| `policy.not_loaded` | the gateway has never successfully loaded a bundle |

**`policy.default_deny`** is the system working. Nothing is permitted until a
rule says so, so this is what an unlisted destination looks like.

Confirm the policy really is missing the destination:

```bash
roctl simulate --host files.pythonhosted.org --profile untrusted-python
```

If simulate also says deny, add a rule. If simulate says allow but requests are
denied, the identity is not what you think it is — check the `profile` and
`namespace` fields on the audit event against the rule's selector.

**`policy.explicit_deny`** means a rule refused it on purpose. Deny wins over
allow across every tier, so a global deny cannot be overridden by a profile
allow. That is deliberate: it is what makes a cluster-wide prohibition
meaningful. The audit event names the rule and the policy that produced it.

**`policy.resolved_cidr`** is the interesting one. The hostname matched, the
port matched, DNS answered — and every address that came back was outside the
`resolvedCidrs` the rule requires. This is the anti-rebinding check working:
someone published a DNS record pointing a permitted name at an address the rule
does not allow.

Investigate rather than widening the rule:

```bash
dig +short internal-api.example.com
roctl simulate --host <the address it resolved to> --profile ci-runner
```

**`policy.stale`** means the gateway cannot reach its controller and the bundle
it holds has aged out. Every request is now denied.

```bash
kubectl -n rokh-oghab get pods -l app=ro-controller
kubectl -n rokh-oghab logs -l app=ro-gateway --tail=50 | grep -i controller
```

Restarting the controller is enough — gateways refresh on their next poll and
recover without a restart of their own.

**`policy.not_loaded`** means this gateway never got a bundle at all. It is
usually a fresh pod that cannot reach the controller, or a controller with no
published version. Check `roctl status` for `activeVersion`.

---

### `identity.*` — the gateway does not know who is asking

| Code | Meaning |
| --- | --- |
| `identity.unknown` | no token and no source mapping matched |
| `identity.invalid_token` | a token was presented and did not match any known digest |
| `identity.malformed_credentials` | the `Proxy-Authorization` header could not be parsed |

**`identity.unknown`** has three common causes, in order of likelihood:

1. **The token was issued but not published.**

   ```bash
   roctl publish
   ```

   Issuing writes the identity to the store; gateways learn it at the next
   publish. This is the single most common cause.

2. **The workload is not sending the header.** Many clients do not attach
   `Proxy-Authorization` from an environment variable alone.

   ```bash
   curl -x http://ro-gateway:3128 \
     -H "Proxy-Authorization: Bearer $RO_PROXY_TOKEN" http://example.com/
   ```

3. **Transparent mode, and the source address does not match a mapping.** Check
   the `client` field on the audit event against your `sources` list, and
   remember that a NAT between the sandbox and the gateway rewrites it.

**`identity.invalid_token`** means a token arrived and does not match. Either it
was revoked, or it belongs to a different controller.

```bash
roctl identity list
```

Anonymous identity is refused by default and the shipped-defaults audit checks
it stays that way. There is no configuration in which an unidentified workload
is permitted by accident.

---

### `guard.blocked:*` — the address guard refused the destination

The reason names which set matched:

| Reason | Meaning |
| --- | --- |
| `guard.blocked:cloud-metadata` | a known cloud metadata endpoint |
| `guard.blocked:default-private-v4` | a built-in IPv4 range: loopback, link-local, RFC 1918, CGNAT, multicast, reserved, documentation |
| `guard.blocked:default-private-v6` | a built-in IPv6 range: loopback, unique-local, link-local, documentation |
| `guard.blocked:configured-block` | a range you added in `guard.blocked` |
| `guard.blocked:obfuscated-address-literal` | the address was written in a non-canonical form |
| `guard.blocked:embedded-v4:<set>` | an IPv6 address carrying a blocked IPv4 address inside it |
| `guard.blocked:ipv6-disabled` | IPv6 destinations are turned off |
| `guard.blocked:not-an-address` | the destination was neither a hostname nor a parseable literal |
| `guard.blocked:invalid-target` | the guard was handed something that is not a destination at all |
| `guard.blocked:unknown-address-family` | a resolved address was neither IPv4 nor IPv6 |

This is the SSRF defence. It runs before policy and refuses regardless of what
policy says, because a rule that accidentally permits `169.254.169.254` should
not be able to hand over cloud credentials.

**`guard.blocked:metadata`** — the workload reached for a cloud metadata
endpoint: `169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `192.0.0.192`
or `fd00:ec2::254`. Treat a sustained rate of this as an indicator, not a
misconfiguration. Legitimate workloads do not repeatedly probe metadata
services.

**`guard.blocked:obfuscated-address-literal`** — the destination was an address
written in a non-canonical form: `2852039166`, `0xa9fea9fe`,
`0251.0376.0251.0376`, `169.254.43518`. These decode to real addresses and exist
in requests for exactly one reason. The gateway refuses them by form rather than
by value, so a form nobody has thought of yet is still refused.

**`guard.blocked:embedded-v4:*`** — an IPv6 address carrying an IPv4 address
inside it: v4-mapped, v4-compatible, v4-translated, 6to4, NAT64, ISATAP or
Teredo. The guard unwraps every one of these and checks what is inside, so
`[::ffff:169.254.169.254]` is refused as the metadata endpoint it is.

The last two should never appear. `guard.blocked:invalid-target` and
`guard.blocked:unknown-address-family` mean the guard was asked about something
that is not a destination, which is an internal inconsistency rather than a
workload doing anything. They are in the catalogue because the guard refuses
rather than guessing when it cannot make sense of its input — the fail-closed
choice — but seeing either is worth reporting.

**When the destination is genuinely internal and genuinely needed**, add an
explicit exception rather than turning the guard off:

```json
{ "guard": {
    "includeDefaults": true,
    "allowExceptions": ["10.20.30.40/32"] } }
```

Narrow it to the single address. `includeDefaults: false` removes every built-in
protection at once, including the metadata endpoints, and the defaults audit
will flag it.

---

### `protocol.*` — the request was malformed

| Code | Meaning |
| --- | --- |
| `protocol.malformed_request` | the request line or headers did not parse |
| `protocol.framing` | conflicting or invalid message framing |
| `protocol.bad_path` | the path contained something illegal |
| `protocol.path_not_normalized` | the path was not in normalised form |
| `protocol.missing_host` | no `Host` header |
| `protocol.bad_host_header` | the `Host` header did not parse |
| `protocol.host_mismatch` | `Host` disagreed with the request target |
| `protocol.bad_authority` | a `CONNECT` authority did not parse |
| `protocol.not_a_proxy_request` | an origin-form request arrived on the proxy port |
| `protocol.origin_form_required` | an absolute-form request arrived in transparent mode |
| `protocol.request_body` | a body arrived where none is permitted |
| `protocol.chunk` | a chunk header was malformed |
| `protocol.chunk_terminator` | a chunk was not followed by CRLF |
| `protocol.chunk_trailers` | the trailer section was too long or never ended |

The parser is deliberately strict — bare CR or LF, obs-fold continuation lines,
invalid header tokens, both `Content-Length` and `Transfer-Encoding`, duplicate
`Content-Length`, a `Transfer-Encoding` that is not `chunked`. Each of those is
a request-smuggling primitive, and the gateway refuses rather than guessing.

**`protocol.framing`** almost always means a client is sending something a
tolerant proxy would have accepted and a strict one will not. Reproduce with a
raw request rather than the client library, and compare against the rules above.

**`protocol.path_not_normalized`** means the path contained `..`, `//`, or an
encoded separator such as `%2e` or `%2f`. Path-scoped rules are matched against
the normalised form, so accepting an unnormalised path would let `/repos/../admin`
match a rule written for `/repos/*`. If your application genuinely needs an
encoded separator in a path, that rule cannot be path-scoped safely.

**`protocol.host_mismatch`** means the absolute-form target and the `Host`
header named different destinations. Which one is authoritative is precisely the
ambiguity smuggling attacks exploit, so the gateway refuses both.

**`protocol.not_a_proxy_request`** is a sandbox talking to the proxy port as if
it were an origin server. Usually a client that has not been told to use a
proxy, or code deliberately probing what `3128` is. It is also what you get if
you try to reach the admin API through the proxy port.

---

### `tls.*` — the TLS layer refused

| Code | Meaning |
| --- | --- |
| `tls.required` | policy requires TLS on this destination and the connection was plaintext |
| `tls.expected_on_tls_port` | plaintext arrived on a port configured as TLS |
| `tls.expected_client_hello` | the tunnel did not begin with a TLS ClientHello |
| `tls.handshake_incomplete` | a TLS handshake began but never completed, so the SNI and version could not be checked |
| `tls.sni_missing` | the ClientHello carried no SNI |
| `tls.sni_invalid` | the SNI was not a valid hostname |
| `tls.sni_mismatch` | the SNI disagreed with the `CONNECT` authority |
| `tls.sni_not_allowed` | the SNI itself is not permitted by policy |
| `tls.version_too_low` | the lowest version the ClientHello would accept is below `strict.minTlsVersion` |

**`tls.sni_mismatch`** is the important one. A workload issued
`CONNECT allowed.example.com:443`, got a tunnel, and then sent a ClientHello for
a different host. Without this check a CONNECT tunnel is a hole: policy
evaluates the authority, and the actual destination is whatever the ClientHello
says. Rokh Oghab binds the two and tears down the connection when they differ.

Legitimate causes exist but are rare — a client with a stale connection pool
reusing a tunnel for a different host. A sustained rate is not a client bug.

**`tls.expected_client_hello`** means the tunnel opened and then carried
something that is not TLS. That is a tunnel being used as a generic transport,
which is the other way a CONNECT proxy becomes a hole.

**`tls.version_too_low`** — the floor is TLS 1.2 in the shipped configuration.
Raise it to `1.3` if your destinations support it:

```json
{ "strict": { "minTlsVersion": "1.3" } }
```

---

### `dns.*` — name resolution refused

| Code | Meaning |
| --- | --- |
| `dns.invalid_name` | the queried name is not a valid hostname |
| `dns.qtype_not_allowed` | a record type outside `dns.allowedTypes` was requested |
| `dns.no_address` | the name did not resolve |
| `dns.no_permitted_address` | the name resolved, but to no address family the policy or configuration allows |
| `dns.all_answers_blocked` | every address returned was refused by the address guard |
| `dns.ipv6_disabled` | an `AAAA` lookup was asked for while `resolver.allowIPv6` is false |
| `dns.nxdomain` | the resolver answered that the name does not exist |
| `dns.server_failure` | the resolver answered `SERVFAIL` |
| `dns.refused` | the resolver declined to answer |
| `dns.not_implemented` | the resolver does not support the query |
| `dns.malformed_query` | the resolver rejected the query as malformed |
| `dns.malformed_answer` | the answer did not parse as a DNS message |
| `dns.answer_mismatch` | the answer did not match the question that was asked |
| `dns.unreachable` | the resolver could not be reached |
| `dns.timeout` | the resolver did not answer in time |
| `dns.no_entropy` | no strong random source was available to pick a query id |
| `dns.failed` | resolution failed for a reason with no more specific code |

**These are the vocabulary, and nothing outside it reaches a workload.** A
resolver failure carries an internal message — an OS error, a parser
complaint, a transaction id that did not match — and none of that is the
workload's business. Each maps to one of the codes above before it leaves the
gateway; the original text goes to the audit log, where an operator can read
it. The same rule holds everywhere: the `X-Rokh-Oghab-Reason` header and the
`reason` field in a deny body are always drawn from
`lua/ro/reasons.lua`, and `ro_uncatalogued_reasons_total` counts any denial the
gateway could not name, which should always be zero.

**`dns.answer_mismatch`** deserves attention when it appears. It means an
answer arrived whose transaction id, question section or response bit did not
match what was sent. That is what an off-path spoofing attempt looks like, and
the query id is drawn from the platform's strong random source precisely so
that guessing it is not practical.

**`dns.no_entropy`** is the gateway failing closed rather than picking a
predictable query id. It should never happen on a working host.

**`dns.qtype_not_allowed`** — only `A` and `AAAA` are served by default. `TXT`,
`NULL` and `CNAME` chains are how DNS becomes a data channel, and a sandbox that
can ask for arbitrary record types has a covert channel out regardless of what
the proxy allows.

**`dns.all_answers_blocked`** is worth a closer look. A permitted name resolved
entirely to addresses the guard refuses. Sometimes it is a legitimate
split-horizon setup; sometimes it is a rebinding attempt.

```bash
dig +short the-name.example.com
```

`ro_dns_answers_filtered_total` counts the individual records dropped, so it
rises before this reason appears.

**`dns.no_address`** is an ordinary resolution failure — the name does not
exist, or the upstream resolver did not answer. Check `resolver.servers` and
whether the gateway can reach them.

---

### `limit.*` — a limiter refused

| Code | Meaning |
| --- | --- |
| `limit.rate` | the identity exceeded its requests per second |
| `limit.connections` | the identity exceeded its concurrent connections |
| `limit.global_connections` | the gateway hit `globalMaxConnections` |
| `limit.source_connections` | one source address hit `maxConnectionsPerSource` |
| `limit.body_size` | a request body exceeded the configured ceiling |
| `limit.unavailable` | a limit is configured but its store is unreachable |

**`limit.rate`** and **`limit.connections`** are per identity and **per
gateway**. Six replicas means a limit of 20 allows up to 120 across the fleet
for a workload whose connections spread out. Size accordingly.

Raise a limit in the rule rather than globally:

```yaml
rateLimit:
  requestsPerSecond: 50
  burst: 100
maxConnections: 64
```

**`limit.global_connections`** is a gateway-wide ceiling being hit. Add replicas
or raise `limits.globalMaxConnections`. Alert on this approaching rather than on
it being reached — by the time it is reached, everything on that gateway is
affected.

**`limit.source_connections`** means one source address has too many
connections open at once. It is applied before anything is parsed, so it catches
a workload holding connections without completing requests — which is the shape
of a slowloris, and also of a client leaking sockets. Check the `client` field
on the audit event to find which workload, then either fix the leak or raise
`limits.maxConnectionsPerSource`.

Behind a NAT that puts many workloads on one address, they share this budget.
If that is your topology, size it for the number of workloads behind the
address, or give them individual addresses.

**`limit.unavailable`** means the shared dictionary backing the limiters is not
present, so a limit you configured cannot be enforced. The gateway refuses
rather than passing traffic it cannot account for, and `ro_limits_unavailable`
goes to 1. This is a deployment fault: the `ro_limits` shared dictionary is
declared in `nginx.conf`, so seeing this means a modified configuration. Note
that a request with *no* configured limit is unaffected — only a limit that
exists and cannot be applied causes a refusal.

---

### `redirect.*` — a redirect was refused

| Code | Meaning |
| --- | --- |
| `redirect.policy_denied` | the redirect target is not permitted by policy |
| `redirect.malformed` | the `Location` header did not parse |
| `redirect.bad_scheme` | the `Location` named a scheme that is not `http` or `https` |
| `redirect.blocked` | the redirect target is in a blocked address range |
| `redirect.not_loaded` | no policy was loaded, so the redirect could not be evaluated |

With `strict.redirectGuard` on, a `3xx` response has its `Location` evaluated
against policy before it reaches the workload. Otherwise a permitted destination
could redirect a sandbox anywhere, and the sandbox's HTTP client would follow.

**`redirect.policy_denied`** means an allowed destination tried to send the
workload somewhere that is not allowed. Add the redirect target to policy if it
is legitimate — and if it is not, you have just caught something.

**`redirect.blocked`** carries the guard rule that fired after the colon, the
same vocabulary a direct request uses: `redirect.blocked:cloud-metadata`,
`redirect.blocked:default-private-v4`, and so on. The metric label is the part
before the colon, so `ro_denied_total{reason="redirect.blocked"}` counts every
redirect the address guard refused regardless of which range it landed in.

**`redirect.not_loaded`** means the gateway held no usable policy at the moment
the redirect arrived. It fails closed, and the fix is whatever is keeping policy
from loading rather than anything about the redirect itself.

The guard evaluates a redirect whenever the target leaves the current origin,
including the spellings that merely look relative. `//other.example.com/` and
`/\other.example.com/` both begin with a slash and both point at a different
host, so both are evaluated against policy and inherit the scheme of the
request they answer. Only a genuine same-origin reference — `/path`, `foo/bar`,
`?a=1`, `#frag` — passes through unexamined.

**`redirect.bad_scheme`** means the `Location` named something that is not
`http` or `https`: `javascript:`, `data:`, `file:` and so on. These are refused
rather than forwarded, because what a client does with them is the client's
business and none of the possibilities are good.

---

### `upstream.*` — the destination misbehaved

| Code | Meaning |
| --- | --- |
| `upstream.no_response` | the destination accepted the connection and sent nothing |
| `upstream.bad_response` | the response did not parse as HTTP |
| `upstream.head_too_large` | the response head exceeded `limits.maxHeadBytes` |
| `upstream.response_framing` | the response framing was invalid or conflicting |
| `upstream.write_failed` | the connection failed while forwarding |
| `upstream.connect_failed` | no resolved address accepted a connection |
| `upstream.interim_framing` | a 1xx response declared a body, which it may not |
| `upstream.interim_flood` | more than eight interim responses arrived |
| `upstream.protocol_upgrade` | the destination answered a proxied request with 101 |

These are about the destination, not the sandbox. `upstream.response_framing`
gets the same strictness as requests, because response smuggling is smuggling.

**The three interim codes are the same defence one layer down.** A `1xx`
response is provisional: the gateway reads past it to the first final status
rather than handing it to the workload as the answer. That makes the interim
head a place to hide a second response, so it is held to the same rules. A
`1xx` ends at its header section and may not declare `Content-Length` or
`Transfer-Encoding` — a destination that declares one is trying to have the
bytes that follow read as the real response. Interim responses are capped at
eight so a destination cannot hold a worker open by trickling them. And a `101`
turns the connection into an opaque tunnel, which a proxied request never
agreed to, so it is refused rather than spliced.

**`upstream.connect_failed`** means every address the name resolved to refused
or timed out. `ro_connection_failures_total` counts these — usually DNS,
routing, or a firewall between the gateway and the destination rather than
anything about the gateway.

**`dns.no_permitted_address`** is narrower than it looks: the name resolved, but
only to addresses of a family that is turned off. It is what an IPv6-only name
produces when `resolver.allowIPv6` is false.

One reason never reaches a workload: `client.write_failed`. It means the client
disconnected while the gateway was replying, so there is nobody left to tell. It
appears in the audit trail only.

---

### `emergency.deny`

Someone engaged the emergency switch. Every destination is refused.

```bash
roctl status
roctl emergency-deny off
```

If `roctl status` shows `emergencyDeny: false` but gateways still report this
reason, a gateway-local switch was set through its admin API and does not clear
from the controller:

```bash
roctl --gateway http://127.0.0.1:9145 gateway emergency-deny off
```

---

### `transparent.name_address_mismatch`

In transparent mode, the SNI named a host that does not resolve to the address
the connection is actually going to. The gateway will not let the name it
evaluates and the address it connects to diverge.

---

## Symptoms

### The metrics endpoint returns 403

The scraper's address is not in `admin.allowFrom`. The source check runs before
the token check and applies to `/metrics`, `/healthz` and `/readyz` as well as
the authenticated endpoints.

```json
{ "admin": { "allowFrom": ["10.42.0.0/16", "127.0.0.1/32"] } }
```

An empty list refuses everything rather than admitting everything, so a
configuration that sets `allowFrom: []` intending to remove the restriction has
in fact locked the listener. Write `["0.0.0.0/0", "::/0"]` if that is genuinely
what you want.

### Everything is denied, all at once

Check, in order:

```bash
roctl status                   # emergencyDeny true?
roctl gateway status           # policy version, stale?
kubectl -n rokh-oghab get pods -l app=ro-controller
```

Three causes: the emergency switch is on, the bundle went stale, or no bundle
was ever loaded. The reason code distinguishes them —  `emergency.deny`,
`policy.stale`, `policy.not_loaded`.

### A policy change had no effect

```bash
roctl status
```

Compare `activeVersion` against what `publish` returned. If you never published,
that is the answer:

```bash
roctl publish
```

If it was published, check the gateways adopted it:

```promql
max(roc_active_version) - min(ro_policy_version)
```

If one gateway lags, look at its `ro_policy_reload_failures_total{reason=...}`.

`reason="signature"` means the gateway fetched a bundle whose HMAC did not
verify against its `controller.signingKey`, so it refused to adopt it and kept
the last good one. Either the controller and that gateway hold different keys —
check a rotation that reached only one side — or something on the network path
altered the response. The gateway logs `controller bundle signature did not
verify; refusing to adopt it` with each attempt.

`reason="fetch"` with `no resolver defined to resolve` in the gateway log means
the gateway cannot resolve the controller's hostname. The stream block reads
`/etc/resolv.conf` through `resolver local=on`; if the pod has no usable
resolver configuration, point `controller.url` at an address instead of a name.

### It works from one pod and not another

The two pods have different identities. Compare:

```bash
roctl gateway audit --limit 100 -o json \
  | jq -c '{client, identity, namespace, profile, reason}' | sort -u
```

Usually one pod has the token secret mounted and the other does not, or they are
in different namespaces and a selector matches only one.

### It works with `curl` and not from the application

The application is not sending `Proxy-Authorization`. Environment variables like
`HTTPS_PROXY` route traffic through the proxy; they do not add credentials.
Language runtimes differ:

```python
import urllib.request
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
opener.addheaders = [("Proxy-Authorization", "Bearer " + TOKEN)]
```

```python
import requests
requests.get(url, proxies={"https": PROXY},
             headers={"Proxy-Authorization": "Bearer " + TOKEN})
```

For `pip`, put the credential in the proxy URL:

```bash
pip install --proxy "http://ro:$RO_PROXY_TOKEN@ro-gateway:3128" requests
```

### The sandbox has no network at all, not even a refusal

A refusal means the gateway saw the request. No refusal at all means the traffic
is not reaching the gateway.

```bash
kubectl -n execution exec deploy/sandbox -- nc -zv ro-gateway 3128
kubectl -n rokh-oghab get pods -l app=ro-gateway
sudo nft list table inet rokh_oghab
```

Check in this order: is the gateway running, does the NetworkPolicy permit the
sandbox to reach it, and does the node ruleset permit the path. Remember that
this is the designed behaviour when the gateway is down — no gateway means no
network, not free network.

### DNS resolves nothing

```bash
kubectl -n execution exec deploy/sandbox -- nslookup allowed.test
```

The gateway's resolver answers only for names policy permits, and returns
`NXDOMAIN` for the rest. A name that does not resolve is usually a name that is
not in policy — check with `roctl simulate` before assuming DNS is broken.

### TLS fails only for some hosts

Almost always `tls.sni_mismatch` from connection reuse, or `tls.version_too_low`
against a destination that only offers TLS 1.0 or 1.1. The audit event says
which.

---

## Tools

**What is this gateway enforcing?**

```bash
roctl gateway status
roctl gateway audit --limit 20
```

**What would policy decide?**

```bash
roctl simulate --host example.com --port 443 --protocol https \
               --profile untrusted-python --namespace execution
```

**Is the node ruleset intact?**

```bash
sudo ./bin/ro-agent status
sudo ./bin/ro-agent check
sudo ./bin/ro-agent print | head -40
```

`check` validates inputs and exits non-zero when they are wrong. `print` emits
the ruleset without applying it.

**Can this sandbox get out any other way?**

```bash
sudo make test-bypass
```

Seventeen escape attempts from a sandbox deliberately granted `NET_RAW`. If any
of them succeeds against your configuration, that is a finding — see
[SECURITY.md](../SECURITY.md).

**Is the configuration itself sound?**

```bash
make audit-defaults
```

---

## Getting help

Include the reason code, the audit event with credentials removed, and the
output of `roctl status` and `roctl gateway status`. Those four things answer
most questions without a round trip.

If you have found a way past the gateway, do not open a public issue — see
[SECURITY.md](../SECURITY.md).
