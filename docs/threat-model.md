# Threat model

## The attacker

Someone who can run arbitrary code inside a sandbox. They can:

- read and modify every file the workload can reach
- start any process the workload can start
- open any socket the kernel will give them
- read the workload's environment, including its proxy token
- send arbitrary bytes on any connection they open
- run for as long as the workload runs, and coordinate across many sandboxes

Assume they have read this repository.

## What they are trying to do

| Goal | Example |
| --- | --- |
| Reach an internal service | The cloud metadata endpoint, the Kubernetes API, a database |
| Exfiltrate data | Push a dataset to a host they control |
| Establish a channel | A reverse shell, a command-and-control beacon |
| Pivot | Reach another tenant's sandbox |
| Deny service | Exhaust the gateway so other tenants lose egress |
| Escape observation | Reach a permitted destination without leaving an audit record |

## In scope

Rokh Oghab is responsible for all of these.

| Threat | Where it is stopped |
| --- | --- |
| A workload that ignores proxy environment variables | Node nftables and NetworkPolicy |
| Connecting straight to an address | Node nftables |
| A forged source address | Interface-scoped rules; reverse path filtering where the platform allows the agent to set it (see the security model) |
| Reaching cloud metadata, in any encoding | The address guard, before policy |
| DNS rebinding | Gateway-side resolution and pinning |
| DNS used as a tunnel | Only `A` and `AAAA` records are served |
| Request smuggling through the proxy | Strict parsing |
| A tunnel repurposed for another destination | SNI bound to the authority |
| A tunnel repurposed as a TCP relay on 443 | Plaintext refused on TLS ports |
| Path traversal past a path-constrained rule | Normalised matching and strict form |
| A redirect into internal space | The redirect guard |
| Reusing a connection to reach a denied host | Per-request re-evaluation |
| Presenting a wider token mid-connection | Per-request identity resolution |
| Spoofing identity with headers | Headers honoured only from trusted sources |
| One tenant exhausting egress for others | Per-identity rate, connection and bandwidth limits |
| Reaching the gateway's own admin API | Address guard, NetworkPolicy and node rules |
| Tampering with policy in flight from the controller | HMAC-SHA256 signing over the bundle, verified by the gateway before it adopts |
| Impersonating the controller to a gateway | The gateway adopts only a bundle signed with the shared key; set `controller.requireSignature` to refuse anything unsigned |
| Turning off enforcement | Pod Security, capability drops and agent reconciliation |

## Out of scope

Rokh Oghab does not solve these, and pretending otherwise would be worse than
saying so.

| Not covered | Why, and what does cover it |
| --- | --- |
| Container escape | If the workload breaks the container it is on the node, outside this boundary. Use a hardened runtime such as gVisor or Kata, and keep the node patched |
| A compromised node | An attacker with root on the node can flush nftables. Node integrity is a prerequisite |
| A compromised control plane | Whoever holds an operator token, or the bundle signing key, can publish or forge permissive policy. Signing stops a network attacker who has neither, but not an attacker who holds the key. Protect the signing key as you protect the tokens, rotate it, and watch the audit trail |
| Data leaving through a permitted destination | If policy allows a destination, data may leave through it. Narrow the allow list; consider TLS inspection where you can accept its cost |
| Covert channels through timing or volume | Not addressed. Bandwidth limits reduce throughput but do not eliminate the channel |
| Malicious content coming back | This is an egress boundary, not a content scanner |
| Supply chain compromise of the images | Mitigated by pinned bases, SBOM, scanning, provenance and signing, not eliminated |
| Denial of service against the gateway itself | Limits, timeouts and bounded buffers reduce the blast radius. Capacity planning is still yours |

## Residual risks worth naming

**A stolen proxy token is a valid identity.** Rotate tokens, scope profiles
narrowly, and watch the audit trail for an identity appearing from an
unexpected source address. Where you can, prefer source-based identity so a
leaked token is useless from elsewhere.

**Policy is only as good as it is written.** A rule allowing a broad suffix
allows everything under it. The compiler refuses suffixes shorter than two
labels for allow rules, but it cannot know that `example.com` is broader than
you meant. Use `roctl simulate` before publishing.

**TLS is passed through by default.** Rokh Oghab sees the destination, the SNI
and the version, but not the request inside the tunnel. Path and method rules
therefore apply to plaintext HTTP and to inspected traffic only. Inspection is
available but off by default, because it means holding a certificate authority
that every sandbox trusts, which is a large piece of attack surface to add.

**IPv6 is dropped at the node by default.** That is the safe choice, but it
means an IPv6-only destination is unreachable until you deliberately enable it
and review the guard's IPv6 ranges.

**Sandboxes sharing a bridge need `br_netfilter`.** Traffic between two
workloads on one Linux bridge is switched, not routed, so it reaches the node
rules only when `net.bridge.bridge-nf-call-iptables` is `1`. At `0` the node
still blocks everything routed off the box, so the boundary looks intact while
a sandbox freely reaches its neighbours and the gateway's admin port. The agent
sets the sysctl where it can and warns where it cannot; load `br_netfilter` on
the node so it has something to set.

**The node rules assume packets traverse netfilter.** An eBPF dataplane that
redirects pod traffic before the `forward` hook can skip the node rules
entirely. Run `RO_HOOK=both` and a CNI-native egress policy on such a
dataplane, and confirm with `sudo make test-bypass` on the real node image
before trusting the boundary. See the [security model](security-model.md) for
which dataplanes are affected.

**The bundle signing key is a shared secret.** Every gateway holds it, so a
gateway that is itself compromised could mint a bundle. Signing defends the
path between an honest controller and an honest gateway; it does not make a
gateway trustworthy on its own. Keep the key in a secret store, rotate it, and
scope who can read it.

## How to report a bypass

See [SECURITY.md](../SECURITY.md). Every confirmed bypass should end up as a
permanent test in `tests/e2e/security_driver.py` or
`tests/enforcement/bypass.sh`, so it can never regress silently.
