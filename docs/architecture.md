# Architecture

Rokh Oghab is three programs and a policy document.

![Rokh Oghab egress architecture](diagrams/architecture.png)

| Program | Where it runs | What it owns |
| --- | --- | --- |
| `ro-gateway` | Next to the workloads, horizontally scaled | Every packet a sandbox sends outward |
| `ro-controller` | Once, with durable storage | What policy says and which version is live |
| `ro-agent` | On every node | Whether a packet may leave the node at all |

The split exists so that a bug in one cannot become a bypass in another. The
gateway can be compromised and the node still drops traffic that did not come
from the gateway. The controller can be unreachable and the gateway keeps
enforcing the last bundle it validated.

## Why the data plane lives in nginx's stream subsystem

The gateway is written in Lua on OpenResty, but it does not use nginx's HTTP
subsystem for the proxy path. Every byte a sandbox sends is parsed by code in
`lua/ro/http.lua` rather than by nginx.

That is deliberate. A forward proxy for hostile clients has to be strict about
things a web server is deliberately lenient about:

- nginx rejects `CONNECT` outright, so tunnelling needs raw socket control
- request smuggling defences depend on rejecting inputs a normal server
  tolerates, such as a bare LF line ending or an obsolete folded header
- the proxy has to decide policy *before* deciding where to connect, which
  means it needs the request target and the resolved address in the same place

Writing the protocol by hand means the parser can be as strict as the boundary
needs, and it can be tested directly. It also means one shared-memory space for
the whole gateway: shared dictionaries are per-subsystem in nginx, so putting
the proxy, the DNS server, the admin API and the metrics endpoint all in the
stream subsystem lets them see the same policy and the same counters.

## How one request is decided

![How one request is decided](diagrams/request-path.png)

```
sandbox
   |
   |  1. strict protocol parse
   |     method, target and version are validated as tokens; bare LF,
   |     obsolete folding, conflicting Content-Length and Transfer-Encoding,
   |     and whitespace tricks are all refused before anything else happens
   |
   |  2. identity
   |     a proxy token, a source address or a header from a trusted injector.
   |     No identity means no request. There is no anonymous default.
   |
   |  3. destination
   |     the host is canonicalised. 2852039166, 0xa9fea9fe, 0251.0376.0251.0376
   |     and 169.254.43518 all become 169.254.169.254 before anything looks at
   |     them. IPv6 tunnel encodings are unwrapped and the embedded IPv4 is
   |     checked too.
   |
   |  4. address guard
   |     private, loopback, link-local, carrier-grade NAT, multicast, reserved
   |     and cloud metadata ranges are refused unless an operator has made an
   |     explicit exception.
   |
   |  5. resolution and pinning
   |     the gateway resolves the name itself, filters answers that point at
   |     internal space, and connects to the address it resolved. The client
   |     never supplies the address, so DNS rebinding has nothing to rebind.
   |
   |  6. policy
   |     tiers are merged. Any explicit deny wins. Otherwise an explicit allow
   |     is required. Otherwise the request is denied.
   |
   |  7. limits
   |     requests per second, concurrent connections and bandwidth, all keyed
   |     by identity rather than by address.
   |
   |  8. transport
   |     for a tunnel, the TLS ClientHello is read before a byte is forwarded.
   |     The SNI must match the authority in the CONNECT line, the negotiated
   |     version must meet the floor, and plaintext on a TLS port is refused.
   |
   v
upstream
```

Every step that can refuse writes an audit record with a reason code, and every
refusal increments a metric labelled with that reason.

## Keep-alive is not a loophole

A connection that has been authorised once is not authorised forever. The
gateway re-parses and re-evaluates every request on a keep-alive connection,
including the identity, so a client cannot send one permitted request and then
reuse the connection for a denied destination. It also cannot present a wider
token halfway through: the decision follows the credentials on the request in
front of it, not the connection.

Request bodies are framed exactly. Bytes beyond a declared `Content-Length` are
not forwarded — they are parsed as the next request and evaluated on their own
merits.

## Policy composition

![How a decision is composed](diagrams/policy-tiers.png)

Policies carry a tier: `global`, `cluster`, `namespace`, `profile`, `pod`.
Tiers do not override each other in the usual sense. The rule is simpler and
harder to get wrong:

1. If any rule at any tier explicitly denies, the answer is deny.
2. Otherwise, if any rule at any tier explicitly allows, the answer is allow.
3. Otherwise the answer is deny.

A platform team can put "never reach cloud metadata" in the global tier and be
certain no team below can undo it, while application teams add what they need
without needing to understand the whole hierarchy.

When several allow rules match, their limits are merged by taking the most
restrictive of each: the lowest rate, the lowest connection cap, the lowest
bandwidth.

## The control plane

![Publishing and rolling back policy](diagrams/control-plane.png)

Documents are staged, then compiled into a bundle, then validated, then written
as an immutable version, and only then does the active pointer move. A bundle
that does not compile is rejected before it can reach a gateway.

Gateways poll the controller and adopt a new bundle by digest, not by version
number. Adoption happens at the start of every connection, so there is no skew
between nginx workers: a revoked token stops working on the next connection,
not up to a second later.

Rollback moves the active pointer to an earlier version. It deliberately does
not revert the staged documents, so the next publish reapplies whatever is
staged. This is documented because it surprises people, and there is a test
that asserts it.

## Failure behaviour

![What happens when something breaks](diagrams/failure-modes.png)

| What breaks | What happens |
| --- | --- |
| The gateway stops | Sandboxes have no network at all, because the gateway was their only route |
| The controller stops | Gateways keep enforcing the last validated bundle, then fail closed once it goes stale |
| A bundle is malformed | It is rejected at compile time; the running policy is untouched |
| The policy store is corrupt | The gateway keeps the bundle it already holds |
| Someone flushes nftables | The agent reconciles it back within its interval |
| An operator needs everything stopped | The emergency deny switch refuses every destination for every identity |

## Kubernetes topology

Generated from the chart this repository ships:

![Kubernetes topology](diagrams/kubernetes-helm.png)

Regenerate every diagram with:

```bash
bash docs/diagrams/generate.sh
```
