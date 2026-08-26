# Examples

Working configuration you can copy. Everything here is validated in CI — every
policy compiles through the real policy engine, every manifest parses, every
script runs — so an example that is broken is a build failure rather than
something you find out the hard way.

```bash
make test-examples
```

---

## Policies

Six profiles covering the shapes most sandboxes take. All of them default to
deny; none of them ships a credential.

| File | Tier | What it is for |
| --- | --- | --- |
| [`global-baseline.yaml`](policies/global-baseline.yaml) | global | The prohibitions that apply to everything. Start here. |
| [`cluster-baseline.yaml`](policies/cluster-baseline.yaml) | cluster | Cluster-internal ranges, the Kubernetes API, exfiltration endpoints, DoH resolvers |
| [`untrusted-python.yaml`](policies/untrusted-python.yaml) | profile | A Python sandbox that may reach the package index |
| [`untrusted-node.yaml`](policies/untrusted-node.yaml) | profile | A Node sandbox that may read from npm but not publish to it |
| [`ci-runner.yaml`](policies/ci-runner.yaml) | profile | A build job: source control, package registries, an internal mirror, pull-only registry access |
| [`ml-training.yaml`](policies/ml-training.yaml) | profile | A training job: read models and datasets, write checkpoints, never upload to the model hub |
| [`agent-sandbox.yaml`](policies/agent-sandbox.yaml) | profile | Code an agent generated: one model API, documentation, and an explicit block on tunnelling services |
| [`transparent-sandbox.yaml`](policies/transparent-sandbox.yaml) | namespace | Transparent mode with custom L7 ports, a port range, and opaque TCP |

Apply and publish:

```bash
roctl policy apply -f examples/policies/global-baseline.yaml
roctl policy apply -f examples/policies/cluster-baseline.yaml
roctl policy apply -f examples/policies/untrusted-python.yaml
roctl publish --note "baseline plus the python profile"
```

### What each one demonstrates

**`global-baseline.yaml`** — the shortest useful policy. One deny rule for the
cloud metadata ranges. This runs *underneath* every other tier, and because deny
wins over allow everywhere, nothing further down can undo it.

**`cluster-baseline.yaml`** — deny rules with no allow rules at all. It shows
that a tier can be purely prohibitive: cluster-internal service and pod ranges,
the API server by both address and name, file-drop sites, and DNS-over-HTTPS
resolvers. That last group matters — a sandbox that can reach a DoH endpoint has
a name-resolution channel the gateway does not control.

**`untrusted-python.yaml`** — the minimal useful allow. One rule, one
destination set, a rate limit and a bandwidth ceiling.

**`untrusted-node.yaml`** — read-only access built from a method restriction:
`GET` and `HEAD` are permitted, and a separate deny rule refuses `PUT`, `POST`,
`DELETE` and `PATCH` on the same destination. The deny rule is not redundant. It
is what makes the intent explicit and survives someone later broadening the
allow rule's methods.

**`ci-runner.yaml`** — the realistic case. Source control, several package
registries, an internal mirror constrained by `resolvedCidrs`, and a container
registry that can be pulled from but not pushed to. Note `resolvedCidrs` on the
internal destinations: the hostname is permitted *and* it must resolve inside
`10.20.0.0/16`, so repointing that DNS record at something else does not open a
path.

**`ml-training.yaml`** — large transfers with path scoping. Reads are restricted
by path glob to the model and dataset APIs, checkpoint writes go to one internal
destination, and a deny rule refuses uploads to the public model hub. The
`requestSize: 32G` on checkpoint writes and `responseSize: 8G` on model reads
show limits sized for the workload rather than left at defaults.

**`agent-sandbox.yaml`** — for code you did not write and did not review. One
model API scoped to `/v1/**`, documentation reads, TLS 1.3 required, and an
explicit deny list of request-capture and tunnelling services. The tunnelling
deny is the interesting part: those hosts are how generated code exfiltrates
without needing a destination that looks suspicious.

**`transparent-sandbox.yaml`** — arbitrary custom L7 ports and schemes. HTTPS on
`8443` and `9443` plus the range `10000-10010`, plaintext HTTP on `8080` and
`8081` with a path scope, and opaque TCP to a database replica on `5432`. This
is the example to read if your destinations are not on 80 and 443.

See [the policy reference](../docs/policy-reference.md) for every field.

---

## Kubernetes

| File | What it is |
| --- | --- |
| [`00-sandbox-secret.yaml`](kubernetes/00-sandbox-secret.yaml) | The Secret shape a sandbox's proxy token goes into |
| [`01-python-sandbox-pod.yaml`](kubernetes/01-python-sandbox-pod.yaml) | A single hardened sandbox pod with proxy environment and gateway DNS |
| [`02-sandbox-deployment.yaml`](kubernetes/02-sandbox-deployment.yaml) | The same as a Deployment, with the proxy settings in a ConfigMap |
| [`03-untrusted-code-job.yaml`](kubernetes/03-untrusted-code-job.yaml) | A Job running untrusted code, with the code itself in a ConfigMap |
| [`04-sandbox-with-nodeagent.yaml`](kubernetes/04-sandbox-with-nodeagent.yaml) | A sandbox with **no** proxy environment, confined entirely by node enforcement |
| [`05-ci-runner.yaml`](kubernetes/05-ci-runner.yaml) | A build job installing packages through the gateway |

```bash
kubectl apply -f examples/kubernetes/00-sandbox-secret.yaml
kubectl apply -f examples/kubernetes/01-python-sandbox-pod.yaml
```

Replace the placeholder token first:

```bash
TOKEN="$(roctl identity issue --namespace execution \
  --profile untrusted-python -o json | jq -r .token)"
roctl publish
kubectl -n execution create secret generic sandbox-egress \
  --from-literal=token="$TOKEN"
```

### Two ways to place a workload behind the gateway

**Explicit** (`01`, `02`, `03`, `05`) — the pod gets `HTTP_PROXY`, `HTTPS_PROXY`
and a token. Cooperative, legible, and gives you per-identity policy and limits.

**Transparent** (`04`) — the pod gets nothing. No proxy variables, no token, no
awareness that a gateway exists. The node agent redirects its traffic, and
identity comes from its source address.

The important thing about `04` is that it is not *less* enforced. Explicit proxy
settings are a convenience for the workload, not the enforcement mechanism —
`03` deletes its own proxy environment as part of the demonstration and still
cannot get out. Node enforcement is what actually holds; the proxy variables
just mean the workload's own HTTP client cooperates instead of hitting a wall.

### What every example has in common

Read these lines rather than the manifests, because they are the ones that
matter:

```yaml
automountServiceAccountToken: false   # nothing to steal
runAsNonRoot: true
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
```

Every workload here satisfies Pod Security `restricted`, and the examples suite
checks that they still do. A sandbox that runs as root with a service account
token mounted has undone several layers before the gateway is even involved.

`03-untrusted-code-job.yaml` also sets `backoffLimit: 0` and
`activeDeadlineSeconds: 900`. Untrusted code that fails should not be retried
automatically, and it should not run forever.

---

## Docker

[`docker/enforced-sandbox.sh`](docker/enforced-sandbox.sh) builds the whole
boundary on one machine: an isolated network, a gateway, an origin, a DNS
server, node enforcement through `nftables`, DNS redirection, and a Python
sandbox inside it. Then it runs untrusted code and shows what happened.

```bash
sudo bash examples/docker/enforced-sandbox.sh
```

It finishes by stopping the gateway and trying again, which is the part worth
watching: the sandbox is left with **no** network rather than open network.

This is the fastest way to see the whole thing working without a cluster.

---

## Python

[`python-sandbox/sandbox_demo.py`](python-sandbox/sandbox_demo.py) is what a
workload sees. Run it inside any sandbox that has been placed behind the
gateway:

```bash
kubectl -n execution exec -it python-sandbox -- python /workspace/sandbox_demo.py
```

It exercises permitted destinations, denied destinations, the metadata endpoint
in several encodings, the gateway's own admin API, raw sockets that route around
the proxy, and DNS. Every attempt has an expected outcome, and a denial counts
as a pass:

```
  ok   plain HTTP to a permitted host          expected=allowed  got=allowed
  ok   a host outside the policy               expected=denied   got=denied
  ok   the cloud metadata endpoint             expected=denied   got=denied
  ok   metadata as 2852039166                  expected=denied   got=denied
  ok   a raw socket to a public address        expected=blocked  got=blocked
  ok   a name outside the policy does not resolve  expected=unresolved got=unresolved
```

Configure it with `RO_DEMO_ALLOWED_HTTP`, `RO_DEMO_DENIED_HTTP`,
`RO_DEMO_DIRECT_HOST` and `RO_PROXY_TOKEN`. `RO_DEMO_JSON=1` prints machine
-readable results, which is how you turn it into a deployment check.

---

## Making a client send its credential

Routing traffic through the proxy and authenticating to it are two different
things. `HTTP_PROXY` does the first; nothing does the second automatically.

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

```bash
pip install --proxy "http://ro:$RO_PROXY_TOKEN@rokh-oghab-gateway.rokh-oghab.svc:3128" requests
```

```bash
curl -x "http://rokh-oghab-gateway.rokh-oghab.svc:3128" \
     -H "Proxy-Authorization: Bearer $RO_PROXY_TOKEN" https://pypi.org/simple/
```

```javascript
const { HttpsProxyAgent } = require('https-proxy-agent');
const agent = new HttpsProxyAgent(process.env.HTTPS_PROXY, {
  headers: { 'Proxy-Authorization': `Bearer ${process.env.RO_PROXY_TOKEN}` },
});
```

A request that reaches the gateway without a credential is refused with `407`
and the reason `identity.unknown`. That is the single most common first-run
problem, and it is not a gateway fault.

---

## Where to go next

| | |
| --- | --- |
| [Policy reference](../docs/policy-reference.md) | Every field these examples use |
| [Kubernetes deployment](../docs/deployment/kubernetes.md) | Getting the gateway itself running |
| [Troubleshooting](../docs/troubleshooting.md) | What each refusal means |
| [Testing](../docs/testing.md) | Proving it holds against your configuration |
