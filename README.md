<div align="center">

<img src="docs/brand/cover.svg" alt="Rokh Oghab — a default-deny egress gateway for untrusted workloads. Denied streams stop at the boundary; permitted streams pass through the one gate the eagle watches." width="100%">

# Rokh Oghab

**A default-deny egress gateway for untrusted sandbox workloads.**

[![CI](https://github.com/dwin-gharibi/rokh-oghab/actions/workflows/ci.yml/badge.svg)](https://github.com/dwin-gharibi/rokh-oghab/actions/workflows/ci.yml)
[![End to end](https://github.com/dwin-gharibi/rokh-oghab/actions/workflows/e2e.yml/badge.svg)](https://github.com/dwin-gharibi/rokh-oghab/actions/workflows/e2e.yml)
[![Enforcement](https://github.com/dwin-gharibi/rokh-oghab/actions/workflows/enforcement.yml/badge.svg)](https://github.com/dwin-gharibi/rokh-oghab/actions/workflows/enforcement.yml)
[![Security](https://github.com/dwin-gharibi/rokh-oghab/actions/workflows/security.yml/badge.svg)](https://github.com/dwin-gharibi/rokh-oghab/actions/workflows/security.yml)
[![Infrastructure](https://github.com/dwin-gharibi/rokh-oghab/actions/workflows/iac.yml/badge.svg)](https://github.com/dwin-gharibi/rokh-oghab/actions/workflows/iac.yml)

[![Licence](https://img.shields.io/badge/licence-Apache%202.0-blue.svg)](LICENSE)
[![Lua](https://img.shields.io/badge/lua-OpenResty%20%7C%20LuaJIT-2C2D72.svg)](https://openresty.org/)
[![Tests](https://img.shields.io/badge/tests-840%20across%2011%20suites-brightgreen.svg)](#testing)
[![Default](https://img.shields.io/badge/default-deny-critical.svg)](#the-one-sentence-it-exists-to-make-true)
[![Fails](https://img.shields.io/badge/on%20failure-closed-critical.svg)](#when-things-break-they-break-closed)
[![Kubernetes](https://img.shields.io/badge/kubernetes-Helm%20%7C%20kustomize-326CE5.svg)](docs/deployment/kubernetes.md)
[![OpenTelemetry](https://img.shields.io/badge/tracing-OpenTelemetry-425CC7.svg)](docs/observability.md#tracing)

</div>

---

## What is Rokh Oghab?

Rokh Oghab sits between code you did not write and
the network.

You are running something you cannot trust. A customer's notebook. A CI job
building a pull request from a stranger. An agent executing scripts a model
just wrote. The code needs *some* network — it has to fetch packages, call an
API you approve of — but it must not be able to reach your database, your cloud
metadata endpoint, or anything else on your internal network.

The usual answer is a proxy and an environment variable. That works right up
until the code decides not to use it, which is the only case that matters.

![Rokh Oghab egress architecture](docs/diagrams/architecture.png)


Rokh Oghab is the other kind of answer. A workload behind it has exactly one
route to the outside world, and that route is a gateway that checks every
request against a policy you wrote. There is no second route. If the gateway
says no, there is nowhere else to ask.

---

## The one sentence it exists to make true

<div align="center">
<img src="docs/brand/banner-invariant.svg" alt="An untrusted workload cannot reach a destination unless the network path, the destination, the protocol, the identity and the active policy all authorise it. Any one of them saying no is enough." width="100%">
</div>

That is five conditions, not one, and they are checked by five different pieces
of machinery. Any one of them saying no is enough.

**The network path.** Before anything else, the workload has to be able to get
a packet out. On the node, `nftables` drops everything a sandbox sends except
traffic to the gateway. In the cluster, a NetworkPolicy says the same thing
again. A sandbox that tries to open a raw socket to an address does not get
refused by the gateway — the packet never reaches a wire.

**The destination.** Names are not the point; addresses are. The gateway does
the resolving itself, checks every address the answer contains, and then
connects to the address it checked. A name that resolves to your metadata
endpoint is refused no matter how it is spelled, and a name whose answer
changes a moment later cannot be used to reach somewhere else.

**The protocol.** Whatever is spoken on a port has to be what the policy said
would be spoken there. Plaintext on a TLS port is refused. A `CONNECT` tunnel
is bound to the SNI inside it, so a tunnel opened to one host cannot carry a
handshake for another.

**The identity.** Every request is attributed to a specific workload before
policy is consulted. That attribution comes from a token the controller minted
or a source address an operator mapped — never from a header the workload set
about itself.

**The active policy.** Nothing is allowed until a rule says so, and the rule
that decides comes from the bundle that gateway is currently running. Policy is
versioned, published atomically, and rolled back byte for byte.

There is no path through any of this where something unknown becomes something
allowed. When the answer is not clearly yes, it is no.

<div align="center">
<img src="docs/brand/guardian.svg" alt="One guarded gate is the only way out — traffic is stopped at the boundary, and one controlled stream passes through the gate the eagle watches" width="100%">
</div>

---

## Why an ordinary proxy is not enough

A proxy asks the workload to cooperate. Untrusted code has no reason to.

Rokh Oghab is built as layers that hold whether or not the workload plays
along, and the interesting question is what happens when it does not.

![What a workload can try, and what stops it](docs/diagrams/threat-model.png)

| A workload tries | What actually happens |
| --- | --- |
| Opening a raw socket to an address | The node drops the packet. It never reaches a wire. |
| Using its own DNS resolver | Port 53 is redirected into the gateway, which answers only for names policy permits |
| Forging its source address | Reverse path filtering rejects it at the node |
| A hostname that resolves inward | The gateway resolves it, sees the address, and refuses |
| Following a redirect to metadata | Every `3xx` has its `Location` checked before the workload sees it |
| Flooding to knock the gateway over | Connections are capped per source before anything is parsed |
| Killing the gateway | It loses all network, because the gateway was the only way out |

That last one is worth sitting with. In most designs, breaking the security
component means the security is gone. Here, breaking it means the sandbox has
no network at all — because the enforcement is not the gateway alone, it is the
node that refuses to route anywhere else. There is a test that stops the
gateway and then tries to connect, so this is checked rather than asserted.

### Three things that follow from the design

**One noisy workload cannot hurt the others.** Connection limits apply per
source before a single byte is parsed, and an unfinished request head is
dropped on a budget of its own. A workload that floods exhausts its own
allowance and nobody else's.

**A name is never trusted, only an address.** Resolution happens inside the
gateway, every answer is checked, and the connection is pinned to the address
that passed. The classic trick — resolve to something harmless, then flip the
answer before the connection opens — has nothing to work with.

**Failure means less access, never more.** Controller unreachable, no policy
ever loaded, the limit counters unavailable, no strong randomness: each one
makes the gateway refuse rather than pass. The choices are listed further down,
and each was made deliberately.

---

## Quick start

```bash
git clone https://github.com/dwin-gharibi/rokh-oghab
cd rokh-oghab

make build          # gateway, controller and node agent images
make up             # a complete local stack with test origins and DNS
make smoke          # prove it allows what it should and denies what it should
```

> [!TIP]
> The local stack needs nothing but Docker — no cluster, no credentials, no
> cloud account. `make smoke` finishes in seconds and is the fastest way to
> see a decision being made before you commit to a deployment.

### Watch it decide

```bash
# a permitted destination
curl -x http://127.0.0.1:13128 \
     -H 'Proxy-Authorization: Bearer ro-e2e-python-token-0000000001' \
     http://allowed.test/

# a destination outside the policy
curl -x http://127.0.0.1:13128 \
     -H 'Proxy-Authorization: Bearer ro-e2e-python-token-0000000001' \
     http://denied.test/
# {"error":"forbidden_by_rokh_oghab","reason":"policy.default_deny"}
```

### The metadata endpoint, six ways

Cloud metadata is the destination that matters most, so it is worth seeing that
spelling it differently does not help:

```bash
for host in 169.254.169.254 2852039166 0xa9fea9fe 0251.0376.0251.0376 \
            169.254.43518 '[::ffff:169.254.169.254]'; do
  curl -s -x http://127.0.0.1:13128 \
       -H 'Proxy-Authorization: Bearer ro-e2e-python-token-0000000001' \
       "http://$host/latest/meta-data/"
done
# every one is refused, each with the guard rule that caught it
```

### See the whole boundary, not just the proxy

```bash
sudo make test-sandbox-demo
```

That builds an isolated network, programs `nftables`, redirects DNS into the
gateway, runs untrusted Python inside it, and finishes by stopping the gateway
to show the sandbox is left with no network rather than open network.

---

## What happens to a single request

![How one request is decided](docs/diagrams/request-path.png)

A request goes through the same seven steps every time, and the order is the
whole point — each step assumes the one before it succeeded.

**First, is there room?** Connection limits are applied before a single byte is
read. A workload cannot make the gateway do parsing work it has not earned.

**Then, is this even HTTP?** A hand-written parser reads the request, and it is
deliberately unforgiving. A bare `LF` where the spec wants `CRLF`, a folded
header, a space before a colon, two `Content-Length` headers, a
`Transfer-Encoding` that is not `chunked` — every one of these is a refusal,
never a repair. Being lenient here is how request smuggling gets in.

**Then, who is asking?** A token the controller minted, or a source address an
operator mapped. If the gateway cannot say which workload this is, it stops
here.

**Then, does policy allow it?** The compiled bundle decides. A deny in any tier
beats an allow in every other.

**Then, where does that name actually point?** The gateway resolves it with its
own resolver, and every address in the answer goes past the address guard.

**Then it connects** — to the address it just checked, not to the name. Nothing
gets a second chance to change its mind between the check and the connection.

**And finally the response is read as carefully as the request was.** Framing
is validated the same way, and if the response is a redirect, the `Location`
goes through policy before the workload ever sees it.

### Identity comes first, and it is not up for negotiation

![How a workload is identified](docs/diagrams/identity-flow.png)

The gateway will believe two things about who a workload is: a bearer token the
controller minted, or a source address an operator explicitly mapped. It will
not believe a header the workload set about itself, no matter how official the
header looks. Anything claiming an identity it cannot prove gets a `407` and
nothing else.

### The layers, side by side

![Enforcement layers](docs/diagrams/enforcement-layers.png)

## Writing a policy

Policy is a document. Nothing is permitted until a rule says so.

```yaml
apiVersion: rokhoghab.io/v1
kind: EgressPolicy
metadata:
  name: untrusted-python
  tier: profile
spec:
  defaultAction: deny
  selector:
    profiles: [untrusted-python]
  rules:
    - name: python-package-index
      action: allow
      destinations:
        hostnames: [pypi.org]
        hostnameSuffixes: [pythonhosted.org]
      ports: [443]
      protocols: [https]
      rateLimit:
        requestsPerSecond: 20
      bandwidth:
        bytesPerSecond: 10M
```

```bash
roctl policy apply -f untrusted-python.yaml
roctl publish
roctl identity issue --namespace execution --profile untrusted-python
roctl publish
```

### Ask before you ship

```bash
roctl simulate --host files.pythonhosted.org --profile untrusted-python
# ALLOW  files.pythonhosted.org:443 (https)
#   reason: policy.allow
#   rule:   python-package-index (policy untrusted-python)
#   limits: {"requestsPerSecond": 20, "bandwidthBytesPerSecond": 10485760}
```

`simulate` exits `0` for an allow and `3` for a deny, so it fits in a pipeline
that must fail when a policy change would break something.

> [!IMPORTANT]
> `roctl policy apply` only stages a document. Nothing a gateway enforces
> changes until `roctl publish`, and a revoked token stays valid until then
> too. If you are cutting off a leaked credential, publish before you walk
> away from the incident.

### Tiers, and why deny wins

![Policy tiers](docs/diagrams/policy-tiers.png)

Policies stack in five tiers — global, cluster, namespace, profile, pod — and a
deny in any tier beats an allow in every other. A platform team can forbid
something globally and know that no team below them can grant it back.

See [docs/policy-reference.md](docs/policy-reference.md) for every field, with
worked examples.

---

## The control plane

![Control plane](docs/diagrams/control-plane.png)

Policy is edited as staged documents, compiled, and published as an immutable
numbered bundle. Gateways poll for it and adopt it atomically.

| Property | How it works |
| --- | --- |
| **Immutable versions** | Publishing assigns the next number from the highest ever issued, and a version that exists is never overwritten |
| **Atomic activation** | A gateway either holds the whole bundle or the previous one; there is no partial state |
| **Rollback** | Re-activates a stored bundle byte for byte, rather than re-deriving it from the current documents |
| **Reproducible digests** | A bundle's digest is the hash of one canonical serialisation, so two gateways holding the same bundle can be compared |
| **Emergency deny** | One request stops all egress on a gateway or across the fleet, and one request lifts it |

### Roles, on both surfaces

The controller and the gateway each enforce the same three tiers, so a
monitoring system that reads status is never holding the credential that can
replace policy.

| Role | Controller | Gateway admin |
| --- | --- | --- |
| `reader` | read policies, profiles, identities, versions | health, readiness, metrics, status, policy summary |
| `operator` | everything a reader can, plus staging, publishing, rollback, tokens | plus the audit trail, DNS flush, emergency deny, validation |
| `admin` | everything, including settings | plus the effective configuration and applying a bundle |

---

## When things break, they break closed

![Failure modes](docs/diagrams/failure-modes.png)

Most systems fail in whatever direction the code happened to take. Here each
failure was a decision, and the decision was always the same: when the gateway
cannot be sure, it says no.

> [!NOTE]
> Fail-closed means outages land on the workload, not on the boundary. A
> gateway that cannot reach its controller past `maxStalenessSeconds`, a node
> whose agent fails to start, an emergency deny left engaged — each one leaves
> sandboxes with no egress rather than open egress. That is the intended
> behaviour; alert on it so you can tell a deliberate stop from a broken one.

**The controller goes away.** The gateway keeps enforcing the bundle it already
has — an outage upstream should not open the boundary. But it does not do that
forever. Past `maxStalenessSeconds` it starts refusing, because a policy nobody
has confirmed in fifteen minutes is a policy you cannot rely on.

**No policy ever loaded.** Everything is denied and `/readyz` reports
`not_ready`, so a load balancer takes the gateway out of rotation rather than
sending it traffic it will only refuse.

**The counters that enforce limits are unavailable.** Requests are refused
rather than passed. A rate limit that cannot count is not a rate limit, and
quietly ignoring it would be the worst of both worlds.

**A size or a rate in a policy does not parse.** The policy is rejected when it
compiles. `requestSize: unlimited` used to mean no limit at all, which is
exactly the opposite of what someone writing it intended.

**No strong randomness.** The gateway refuses to mint a token or send a DNS
query rather than using a predictable value. A guessable DNS transaction id is
half of a spoofed answer.

**The tracing collector is unreachable.** Spans are dropped and traffic carries
on. Telemetry is never allowed to gate a decision — an egress control that
fails when its monitoring fails is worse than one with no monitoring.

**The gateway process dies.** The sandbox has no network, because the gateway
was the only way out.

---

## Knowing what it did

![What the gateway tells you](docs/diagrams/observability.png)

Three channels, each answering a different question.

### Metrics: is it healthy, and what is it refusing?

Prometheus at `:9145/metrics`. Every label comes from a fixed vocabulary — 86
named reasons, and never a hostname — so a workload cannot make the series
count grow by inventing destinations. That is not a hope; 300 distinct
destinations were thrown at it and the series count moved by zero.

One counter is worth an alert on its own: `ro_uncatalogued_reasons_total`
should always read zero. Anything else means the gateway refused something and
could not say why, which is a bug in the gateway rather than a fact about the
traffic. A check in CI fails the build if a reason is ever added without a name.

### The audit trail: what was decided, one line at a time

Structured JSON, one line per decision, to stdout or a file. Plus a small
in-memory ring you can read live with `roctl gateway audit` when you are
debugging.

Credentials are never in it. Request paths are off by default, because paths
carry secrets more often than people expect.

### Traces: where did the time go, and why was it refused?

OpenTelemetry over OTLP to any collector, off until you configure one. Each
request is a span, with children for the DNS lookup and the upstream dial, and
the decision attached: allowed or denied, which reason, which workload, which
policy version. A denied request is marked `ERROR`, so searching your tracing
backend for failures surfaces policy refusals alongside upstream ones.

Two deliberate limits. It ignores the `traceparent` a workload sends, because a
sandbox that chooses its own trace id can bury its requests inside someone
else's. And it never sits on the request path: with the collector stopped,
sixty requests took 419ms against 413ms healthy.

[docs/observability.md](docs/observability.md) has the full metric catalogue,
the alert expressions and a dashboard.

---

## Deploying it

![Three ways to run it](docs/diagrams/deployment-shapes.png)

| Shape | What you get | Guide |
| --- | --- | --- |
| **Kubernetes** | Helm chart with a values schema, or a kustomize base | [kubernetes.md](docs/deployment/kubernetes.md) |
| **Docker Compose** | A complete stack, including a transparent-mode variant | [docker.md](docs/deployment/docker.md) |
| **Bare metal and VMs** | Ansible roles, systemd units, node agent | [ansible.md](docs/deployment/ansible.md) |
| **Infrastructure as code** | A Terraform module and the same module as an OpenTofu root | [terraform.md](docs/deployment/terraform.md) |

### Two commands on a real cluster

The chart cannot guess two things: a free address in your service CIDR for the
gateway, and the pod CIDR the node agent should confine. Neither has a default
that works everywhere, and getting them wrong is the difference between a
boundary and a decoration. So rather than a default that is right on kind and
wrong on EKS, there is a script that reads them off the cluster:

```bash
bash scripts/ro-preflight.sh
```

> [!WARNING]
> Check the pod CIDR the script reports before you install. On a multi-node
> cluster the per-node `.spec.podCIDR` is one slice of the cluster range, and a
> range that covers only some nodes confines only those nodes — silently. The
> ruleset applies cleanly, `ro-agent status` succeeds, the probe passes, and
> every sandbox elsewhere has unrestricted egress.

It finds the service CIDR, picks a free address in it, reads the pod CIDR,
checks that your CNI enforces NetworkPolicy and that you can create a
DaemonSet, then prints the install command with everything filled in. The chart
refuses to install with an empty gateway address while the agent is enabled,
rather than programming nftables with nothing and confining nothing.

Then put a workload behind it:

```bash
bash scripts/ro-onboard.sh --workload my-sandbox --apply
```

That mints an identity, publishes it, stores the token as a Secret in the
workload's namespace, prints the pod spec fragment to paste, and — with
`--apply` — runs a pod that proves a permitted destination works and a direct
one does not.

> [!CAUTION]
> If your workloads can hold `NET_RAW`, set `sandbox.interfaces` (for example
> `["cali+"]` or `["veth+"]`). That list is what rejects a forged source
> address inside a container: the agent also tries to enable
> `net.ipv4.conf.all.rp_filter`, but a non-privileged DaemonSet cannot write
> `/proc/sys` under a standard runtime, so on Kubernetes it logs a warning and
> carries on. The shipped `restricted` Pod Security level forbids `NET_RAW`
> and covers the same ground — set both if the workload is genuinely hostile.

### Transparent mode

A workload that does not know the gateway exists can still be confined: the
node redirects `80`, `443` and `53` into the gateway, which identifies the
workload by its source address. See
[docs/transparent-mode.md](docs/transparent-mode.md).

---

## Components

| Component | Role |
| --- | --- |
| `ro-gateway` | Data plane. OpenResty and Lua in nginx's stream subsystem: forward proxy, `CONNECT` tunnels, controlled DNS, metrics, audit, tracing |
| `ro-controller` | Control plane. Versioned policy store, validation, atomic activation, rollback, emergency deny |
| `ro-agent` | Node enforcement. Programs `nftables` so a sandbox has exactly one way out |
| `roctl` | Command line interface over the control-plane REST API |

---

## Repository layout

```
lua/ro                  data plane and shared modules
lua/roc                 control plane modules
openresty/              the control-plane nginx configuration
nginx.conf              the data-plane nginx configuration
config/                 shipped configuration and the bootstrap bundle
bin/roctl               control-plane command line interface
bin/ro-agent            node enforcement agent
scripts/                developer and operator helpers
deploy/docker           Compose stacks
deploy/kubernetes       manifests and a kustomize base
deploy/helm             a chart with a values schema
deploy/ansible          roles and playbooks
deploy/terraform        a Kubernetes module
deploy/opentofu         the same module as an OpenTofu root
examples/               policies, sandbox pods and runnable demonstrations
tests/                  unit, end-to-end, adversarial, enforcement and perf suites
docs/                   architecture, security model, deployment, operations
docs/diagrams           generated diagrams and the script that draws them
Dockerfile              one multi-target build for all three components
Makefile                build, lint, test and deploy targets
start.sh                validates configuration before starting
gen-ca.sh               generates the private control-plane PKI
```

---

## Testing

The claims above are not prose, they are tests. **840 checks across eleven
suites**, and every one of them was watched failing against the code before its
fix — a test that has never failed is not evidence of anything, it is
decoration.

| Suite | Command | Checks | What it covers |
| --- | --- | --- | --- |
| Unit | `make test-unit` | 433 | address parsing, policy evaluation, HTTP framing, DNS, TLS, identity, limits, metrics, canonical digests, tracing, YAML |
| Gateway | `make test-e2e` | 68 | a live gateway against real origins |
| Adversarial | `make test-security` | 98 | smuggling, SSRF, tunnel abuse, DNS abuse, exhaustion, information leaks, RBAC, tracing |
| Control plane | `make test-control` | 28 | roles, versioning, rollback, live propagation, controller outage, concurrent writers |
| Command line | `make test-cli` | 10 | flag handling, name resolution, credential isolation, exit codes |
| Node agent | `make test-agent` | 48 | generated `nftables` rulesets and input validation |
| Manifests | `make test-manifests` | 36 | kustomize, seventeen chart permutations and six values the schema must reject |
| Examples | `make test-examples` | 25 | every example policy compiles, every example pod is hardened |
| Defaults | `make audit-defaults` | 62 | nothing shipped weakens the boundary |
| Enforcement | `sudo make test-enforcement` | 13 | the node really confines a sandbox, including behind a load balancer |
| Bypass | `sudo make test-bypass` | 19 | escape attempts from a sandbox holding `NET_RAW` |

And the ones that do not produce a check count, because they are looking for
something rather than confirming it:

| Suite | Command | What it does |
| --- | --- | --- |
| Chaos | `make chaos` | Twenty-one bypass shapes attacked continuously while the gateway, controller, DNS and origins are killed and restarted underneath them |
| Fuzz | `make fuzz` | Malformed traffic at the request parser, the tunnel, the DNS server and the response path |
| Ratchet | `make ratchet` | No suite is allowed to shrink |
| Reasons | `make check-reasons` | Every deny reason has a name, so none is invisible in metrics |
| Sandbox demo | `sudo make test-sandbox-demo` | Untrusted Python end to end, finishing with the gateway stopped |
| Kubernetes | `make test-k8s` | The chart in a real cluster, with escape attempts from a real pod |
| Benchmark | `make bench` | Latency, throughput, and what the gateway costs |

```bash
make test-all               # everything that does not need root
sudo make test-privileged   # the suites that program nftables
```

The chaos suite deserves a note, because it is the one that tests the thing
nobody usually tests: what happens *during* a failure rather than after it. It
attacks the gateway from several threads while another thread kills and
restarts everything around it. A refusal counts as a pass and so does a
timeout; the only failure is a request that policy did not permit succeeding.
Across four seeds, 183,285 probes through 105 chaos rounds produced no breach.

[docs/testing.md](docs/testing.md) explains how to run and extend each one.

---

## Documentation

### Start here

| Document | What it answers |
| --- | --- |
| [docs/README.md](docs/README.md) | An index organised by what you are trying to do |
| [Architecture](docs/architecture.md) | How the pieces fit and why the data plane lives in the stream subsystem |
| [Security model](docs/security-model.md) | The invariant, the layers and the specific attacks each one stops |
| [Threat model](docs/threat-model.md) | What is in scope, what is not, and the residual risks |

### Using it

| Document | What it answers |
| --- | --- |
| [Policy reference](docs/policy-reference.md) | Every field, with worked examples |
| [CLI](docs/cli.md) | Every `roctl` command |
| [API](docs/api.md) | The control-plane and gateway REST surfaces, and the roles on each |
| [Examples](examples/README.md) | Working policies, sandbox pods and runnable demonstrations |

### Running it

| Document | What it answers |
| --- | --- |
| [Kubernetes](docs/deployment/kubernetes.md) | Helm, kustomize and how to place a workload behind the gateway |
| [Docker](docs/deployment/docker.md) | Compose and standalone deployment |
| [Ansible](docs/deployment/ansible.md) | Virtual machines and bare metal |
| [Terraform and OpenTofu](docs/deployment/terraform.md) | Infrastructure as code |
| [Transparent mode](docs/transparent-mode.md) | Confining a workload that does not know the gateway exists |

### Operating it

| Document | What it answers |
| --- | --- |
| [Operations](docs/operations.md) | Publishing, rollback, emergency deny, capacity, upgrades |
| [Observability](docs/observability.md) | Metrics, audit trail, tracing, alerts, dashboards |
| [Troubleshooting](docs/troubleshooting.md) | What each deny reason means and what to do about it |
| [Testing](docs/testing.md) | How to run and extend every suite |

---

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the working agreement. The short
version: a change that touches the boundary needs a test that fails without it,
and the adversarial suite must stay green.

---

## Licence

Apache 2.0. See [LICENSE](LICENSE).

<div align="center">
<br>
<img src="docs/brand/footer.svg" alt="Rokh Oghab — the eagle watches the one way out" width="640">
</div>
