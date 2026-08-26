# Transparent mode

The gateway has two ways of receiving traffic, and they differ in what the
workload has to know rather than in how strongly it is confined.

| | Explicit | Transparent |
| --- | --- | --- |
| The workload knows | it is behind a proxy | nothing |
| Configuration in the pod | `HTTP_PROXY`, `HTTPS_PROXY`, a token | none |
| Identity from | a bearer token | the source address |
| Ports | `3128` | `3080` (HTTP), `3443` (TLS) |
| Traffic arrives by | the workload connecting to the proxy | the node redirecting it |

Both are enforced by the same policy engine, the same address guard and the
same node ruleset. Transparent mode is not the weaker option — it is the option
for workloads you cannot modify, and for the case where you do not want the
workload to know a boundary exists.

![Layers a sandbox has to get past](diagrams/enforcement-layers.png)

---

## When to use it

**Use transparent mode when:**

- You cannot modify the workload. A vendor image, a legacy container, a binary
  that ignores proxy environment variables.
- The code is hostile and you do not want to depend on it cooperating. Explicit
  mode is not weaker here — node enforcement is what actually confines a
  sandbox either way — but transparent mode removes the question entirely.
- You want the sandbox to be unaware. Code that cannot see proxy settings cannot
  reason about them.

**Use explicit mode when:**

- You want per-workload identity that does not depend on addressing. A token is
  a credential; a source address is an assertion about the network.
- Several workloads share a source address. Behind a NAT, source-address
  identity cannot tell them apart.
- You want the workload to see refusals as HTTP responses it can log. In
  transparent mode a refusal is a closed connection, which is harder to debug
  from inside.

Running both at once is normal. The listeners are independent, and one policy
bundle governs all of them.

---

## How it works

```
sandbox                node (nftables)              gateway
   |                         |                          |
   |-- connect 93.184.x:443 -+                          |
   |                         |-- dnat -> gateway:3443 ->|
   |                         |                          |-- read ClientHello
   |                         |                          |-- SNI = example.com
   |                         |                          |-- identity from source
   |                         |                          |-- policy decides
   |                         |                          |-- resolve example.com
   |                         |                          |-- guard the address
   |                         |                          |-- connect and splice
```

The step that matters: **the destination comes from the SNI, not from the
address the workload dialled.** The gateway reads the name, checks it against
policy, resolves it with its own resolver, checks the resolved address against
the guard, and connects there. A workload that dials `169.254.169.254` with an
SNI of `pypi.org` does not reach the metadata endpoint; it reaches whatever
`pypi.org` resolves to, if policy permits it.

For plain HTTP on `3080` the same holds with the `Host` header in place of the
SNI.

### Enabling it

On the node agent:

```bash
sudo RO_GATEWAY_ADDR=10.43.0.10 \
     RO_SANDBOX_CIDRS=10.244.0.0/16 \
     RO_TRANSPARENT=true \
     RO_DNS_REDIRECT=true \
     ./bin/ro-agent apply
```

`RO_TRANSPARENT=true` redirects ports 80 and 443 from the sandbox ranges into
the gateway's `3080` and `3443`. `RO_DNS_REDIRECT=true` sends port 53 into the
gateway's resolver, which is what stops a workload resolving names the policy
does not permit.

In Kubernetes this is the agent DaemonSet's configuration; see
[the Kubernetes guide](deployment/kubernetes.md).

### Giving the workload an identity

Transparent workloads carry no token, so identity comes from where the traffic
originates:

```yaml
sources:
  - cidr: 10.244.7.13/32
    id: enforced-sandbox
    namespace: execution
    profile: enforced
    serviceAccount: sandbox-runner
```

```bash
roctl identity sources -f sources.yaml
roctl publish
```

`roctl identity sources` **replaces** the whole set. Read the current one first
if you are adding to it.

A source with no mapping gets `identity.unknown` and is refused, because
anonymous identity is off by default. There is no configuration in which an
unmapped transparent workload is permitted by accident.

---

## What source-address identity is worth

It is exactly as trustworthy as the layer that assigns and enforces addresses.

**It is sound when** a CNI assigns each pod its own address, the node agent
drops packets whose source address does not belong to the interface they
arrived on, and reverse path filtering is on. Then a source address is a pod,
and a pod is a workload. The bypass suite tests this directly: it grants a
sandbox `NET_RAW`, has it forge source addresses, and confirms the forged
packets never arrive.

**It is unsound when** workloads share an address — several containers in one
pod, a NAT between the sandbox and the gateway, or a flat L2 segment where
anything can claim any address. There, source-address identity cannot separate
one workload from another, and per-identity limits are shared.

Prefer tokens where you have the choice. Use transparent mode where you do not,
and make sure the two conditions above hold.

---

## Configuration

```json
{
  "mode": "explicit",
  "strict": {
    "verifyOriginalDestination": false,
    "sniMatch": true,
    "hostMatch": true,
    "blockPlaintextOnTlsPorts": true
  }
}
```

`mode` names the listener a bare `ro.proxy.run(conf)` serves. The shipped
`nginx.conf` starts all three explicitly, so every listener is available and
`mode` only sets the default.

### `verifyOriginalDestination`

Off by default, and the reason is worth understanding rather than flipping.

When on, the gateway compares the address the connection was originally headed
for against the addresses the SNI resolves to, and refuses the connection with
`transparent.name_address_mismatch` when they disagree.

**This only works under TPROXY.** The shipped node agent uses `dnat`, and under
DNAT the original destination is not recoverable from inside nginx —
`server_addr` is the gateway's own address, so the comparison would fail for
every legitimate connection. Turning it on with the shipped agent breaks
transparent mode entirely.

Turn it on only if you have replaced the redirection with TPROXY, where the
socket keeps the original destination. Under DNAT, leave it off: the security
property you would be adding is already provided by the fact that the gateway
resolves the SNI itself and never connects to the address the workload chose.

---

## What a refusal looks like from inside

This is the practical difference between the two modes, and the reason to keep
the audit trail close by.

**Explicit mode** — the workload gets an HTTP response it can read:

```
HTTP/1.1 403 Forbidden
X-Rokh-Oghab-Reason: policy.default_deny

{"error":"forbidden_by_rokh_oghab","reason":"policy.default_deny","detail":""}
```

**Transparent TLS** — the workload gets a closed connection. There is no way to
send an HTTP error inside a TLS handshake that has not happened, so the gateway
tears the connection down. From inside the sandbox it looks like the destination
refused to talk.

**Transparent HTTP** — the workload does get an error response, because the
gateway is speaking HTTP to it.

So when a transparent workload reports "connection reset", ask the gateway:

```bash
roctl gateway audit --action deny --limit 50 -o json \
  | jq -c 'select(.mode | startswith("transparent"))
           | {ts, client, identity, sni, destination, reason}'
```

The `client` field is the source address, which is how you map a refusal back to
a pod.

---

## Custom ports

Redirection covers 80 and 443. For anything else, add rules for the ports you
need and declare them in policy:

```yaml
- name: internal-api-on-a-custom-port
  action: allow
  destinations:
    hostnames: [api.internal.example.com]
    resolvedCidrs: [10.40.0.0/16]
  ports: [8443, 9443, "10000-10010"]
  protocols: [https]
```

See [`examples/policies/transparent-sandbox.yaml`](../examples/policies/transparent-sandbox.yaml)
for a worked example covering custom TLS ports, plaintext ports with a path
scope, and opaque TCP.

Opaque TCP — `protocols: [tcp]` — is the escape hatch for a protocol the gateway
does not parse. Policy still decides the destination and port, and limits still
apply, but the gateway cannot see inside the stream and so cannot enforce
anything about its content. Use it deliberately and narrowly.

---

## Testing it

```bash
sudo make test-sandbox-demo
```

Builds an isolated network, programs enforcement with DNS redirection, runs
untrusted Python inside it, and prints what the workload could and could not
reach. The sandbox has no proxy environment at all.

```bash
sudo make test-bypass
```

Seventeen escape attempts from a sandbox holding `NET_RAW`, including forged
source addresses, which is the attack source-address identity has to survive.

---

## Things that will bite you

**DNS redirection is not optional.** Without `RO_DNS_REDIRECT=true` a workload
resolves names with whatever resolver it can reach, and a name that policy
refuses still resolves. Redirection is what makes the gateway's resolver the
only one available.

**A refusal is a closed connection.** In transparent TLS there is nowhere to put
an error. Do not expect the workload's logs to explain anything; use the audit
trail.

**Identity is the source address.** Two containers in one pod share it. So do
workloads behind a NAT. Check `roctl identity list` against your actual pod
addressing before assuming per-workload policy is being applied.

**`verifyOriginalDestination` breaks DNAT deployments.** It is off for a reason.

**Per-source connection limits are per address.** `maxConnectionsPerSource`
bounds a source, so workloads sharing an address share the budget. See
[operations](operations.md).
