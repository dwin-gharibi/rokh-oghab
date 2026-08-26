# The `roctl` command line

`roctl` is a thin, dependency-free client for the control-plane REST API. It is
a single Python 3 file with no third-party imports, so it runs anywhere Python
runs and can be copied into a CI image without a package manager.

Everything `roctl` does is an HTTP request to the controller. There is no
back-channel and no local state: if `roctl` can do it, so can `curl`, and the
same authorisation rules apply either way.

---

## Connecting

`roctl` resolves its endpoint and credentials from three places, in order of
precedence:

1. command line flags
2. environment variables
3. a configuration file

| Flag | Environment | Config key | Default |
| --- | --- | --- | --- |
| `--endpoint` | `ROCTL_ENDPOINT` | `endpoint` | `http://127.0.0.1:8081` |
| `--token` | `ROCTL_TOKEN` | `token` | none |
| `--gateway` | `ROCTL_GATEWAY` | `gateway` | `http://127.0.0.1:9145` |
| `--gateway-token` | `ROCTL_GATEWAY_TOKEN` | `gatewayToken` | none |

The configuration file is JSON. The first of these that exists is used:

```
$ROCTL_CONFIG
~/.rokh-oghab/config.json
/etc/rokh-oghab/roctl.json
```

```json
{
  "endpoint": "https://ro-controller.rokh-oghab.svc:8443",
  "token": "ro-operator-...",
  "gateway": "http://ro-gateway.rokh-oghab.svc:9145",
  "gatewayToken": "ro-admin-..."
}
```

Give that file mode `0600`. The token in it is a credential that can rewrite
what every sandbox in the cluster is allowed to reach.

### Global flags

| Flag | Meaning |
| --- | --- |
| `-o`, `--output` | `table` (default) or `json` |
| `--timeout` | request timeout in seconds, default `15` |
| `--version` | print the client version |

`-o json` prints the raw server response with sorted keys, which is the form to
use in scripts. The table form is for humans and its columns are not a stable
interface.

Every flag in both tables above may be written before or after the subcommand.
`roctl status -o json` and `roctl -o json status` mean the same thing, and when
a flag appears in both places the one after the subcommand wins.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | the command succeeded |
| `1` | the request failed, the server refused it, or the document was invalid |
| `2` | the arguments did not parse |
| `3` | `simulate` ran successfully and the answer was **deny** |
| `130` | interrupted |

Exit code `3` is worth noting: `roctl simulate` distinguishes "I could not ask"
from "I asked and the answer was no". A CI gate that must fail on a denial
checks for `3`, and one that must fail only on an error checks for `1`.

`roctl` never exits `0` on a server error. A non-2xx response is turned into
`roctl: server returned 403: ...` on stderr and exit code `1`, so `set -e` in a
pipeline does the right thing.

---

## Reading the current state

### `roctl status`

The single most useful command. It reports what the controller thinks is
active.

```bash
roctl status
```

```
FIELD          VALUE
-------------  -----
activeVersion  47
revision       128
policies       6
profiles       3
tokens         12
sources        2
emergencyDeny  false
```

`activeVersion` is the bundle the gateways are enforcing. `revision` counts
every change made to the store, published or not. When `revision` has moved but
`activeVersion` has not, there are staged changes that no gateway has seen —
which is almost always what someone is confused about when a policy change "did
not take effect". The fix is `roctl publish`.

### `roctl versions` and `roctl version N`

```bash
roctl versions
roctl version 46 -o json | jq '.policies[].name'
```

Every publish produces an immutable numbered bundle. `versions` lists them with
their digest, timestamp, author and note. `version N` prints the compiled
bundle exactly as the gateways received it — not the source documents, but the
flattened result. When you want to know what was *actually* enforced at 03:00
last Tuesday, this is the answer.

---

## Policies and profiles

### `roctl policy list | get | apply | delete`

```bash
roctl policy list
roctl policy get untrusted-python
roctl policy apply -f policies/untrusted-python.yaml
roctl policy delete untrusted-python
```

`apply` accepts YAML or JSON, and `-f -` reads from stdin:

```bash
cat policy.yaml | roctl policy apply -f -
```

The name comes from `metadata.name` in the document — the key at `metadata`'s
own level, not a `name` nested inside `metadata.labels` or
`metadata.annotations`. If the document indents with tabs, `roctl` declines to
guess and asks for an explicit name. Pass `--name` to override, which is also
how you stage the same document twice under different names.

Two flags matter for workflow:

| Flag | Effect |
| --- | --- |
| `--publish` | publish immediately after staging, in one step |
| `--note` | attach a note to the resulting version |

Without `--publish`, `apply` only *stages* the change. Nothing reaches a
gateway until `roctl publish` runs. This is deliberate: it lets you assemble a
multi-document change and activate it atomically.

```bash
roctl policy apply -f base.yaml
roctl policy apply -f overrides.yaml
roctl profile apply -f ml-training.yaml
roctl publish --note "add the training profile"
```

### `roctl profile list | get | apply | delete`

Profiles carry the limits and defaults that a class of sandbox inherits.
Identical semantics to `policy`, including `--publish` and `--note`.

---

## Identities

### `roctl identity issue`

Mint a proxy token for a sandbox.

```bash
roctl identity issue \
  --namespace execution \
  --profile untrusted-python \
  --service-account sandbox-runner \
  --label team=research \
  --label ticket=RES-4412
```

```
token issued for ro-id-8f2c1d (profile untrusted-python)

  ro-p-9d41c0a37fbe4a1e8c5502fb7d1a6e93

This value is shown once. Store it in the sandbox's secret now.
Publish to activate:  roctl publish
```

**The token is printed once.** The controller stores only its digest, so there
is no command that recovers it later. Capture it into a Secret at the moment you
issue it:

```bash
TOKEN="$(roctl identity issue --namespace execution --profile untrusted-python \
         -o json | jq -r .token)"
kubectl -n execution create secret generic sandbox-egress \
  --from-literal=token="$TOKEN"
unset TOKEN
```

`--label` is repeatable and takes `key=value`. Labels are for your own
bookkeeping — who asked for this identity, which ticket, which team. They are
recorded in the audit trail alongside every decision made under that identity,
which turns "something exfiltrated data" into a name.

`--id` sets the identity string explicitly instead of letting the controller
generate one. Use it when you are reconciling from a system that already has
its own identifiers.

A newly issued identity does not exist for the gateways until you publish:

```bash
roctl identity issue --namespace execution --profile untrusted-python
roctl publish
```

### `roctl identity list` and `roctl identity revoke`

```bash
roctl identity list
roctl identity revoke 4b1e...c07a
roctl publish
```

`list` shows digests, never tokens. `revoke` takes the digest. Revocation is a
policy change like any other and needs a publish to take effect; when it does,
the token is refused at the gateway on its very next request.

### `roctl identity sources`

Identity by source address, for workloads that cannot carry a token — a
transparent-mode sandbox, or a legacy container you cannot modify.

```bash
roctl identity sources -f sources.yaml
```

```yaml
sources:
  - cidr: 10.42.7.0/24
    id: build-farm
    namespace: execution
    profile: ci-runner
    serviceAccount: builder
```

This **replaces** the whole set rather than merging into it. Read the current
set first if you are adding to it:

```bash
roctl identity list -o json | jq '{sources}' > sources.json
```

Source-address identity is weaker than a token: it is only as trustworthy as
the layer that assigns addresses. It is sound when the CNI assigns pod IPs and
the node agent drops forged sources, and unsound on a shared L2 segment where
anything can claim any address. Prefer tokens where you have the choice.

---

## Publishing and rollback

### `roctl publish`

```bash
roctl publish --note "allow the internal artefact mirror"
```

Publish compiles the entire staged configuration into one immutable bundle,
validates it, assigns it the next version number, and flips the active pointer.
Gateways notice within their poll interval and adopt it atomically — a gateway
is never half on the old bundle and half on the new one, and neither is a
worker process within a gateway.

If compilation fails, nothing changes. The running policy is untouched, the
version number is not consumed, and the error names the document and field:

```
roctl: server returned 422: rule "mirror" in policy "ci-runner":
       an allow rule must name at least one destination
```

### `roctl rollback N`

```bash
roctl versions
roctl rollback 46
```

Rollback re-activates a previously published bundle by number. It does not
reconstruct anything: bundle 46 is stored byte for byte, so rolling back to it
restores exactly what was enforced, not an approximation.

Rollback is itself a versioned event. Rolling back to 46 from 47 produces
version 48 whose content equals 46. The history stays append-only, so the audit
trail never loses the fact that 47 existed.

### `roctl emergency-deny on|off`

```bash
roctl emergency-deny on
```

Stop all egress everywhere, immediately, without touching a single policy
document. Every gateway refuses every destination while it is on.

```bash
roctl emergency-deny off
```

Turn it off and the previously active policy resumes — the switch overrides
policy rather than replacing it, so nothing needs to be re-published.

Use it when you know something is wrong and do not yet know what. It is faster
to reason about a stopped network than a leaking one, and turning it off costs
one command.

---

## Asking before you ship

### `roctl validate -f FILE`

```bash
roctl validate -f policies/untrusted-python.yaml
```

Compile a document and report whether it is valid, without staging it. This is
the command for a pull request check — it needs only the `reader` role, so CI
can run it with credentials that cannot change anything.

```yaml
- name: Validate egress policies
  run: |
    for f in policies/*.yaml; do
      roctl validate -f "$f"
    done
```

### `roctl preview`

```bash
roctl preview
```

Compile the *staged* configuration and report what publishing it would produce
— version number, rule counts, and any error — without activating it. Run it
between the last `apply` and the `publish`.

### `roctl simulate`

The command that answers "would this be allowed?" without generating traffic.

```bash
roctl simulate --host files.pythonhosted.org --profile untrusted-python
```

```
ALLOW  files.pythonhosted.org:443 (https)
  reason: policy.allow
  rule:   python-package-index (policy untrusted-python)
  limits: {"requestsPerSecond": 20, "bandwidthBytesPerSecond": 10485760}
  bundle: version 47
```

```bash
roctl simulate --host 169.254.169.254 --port 80 --protocol http \
               --profile untrusted-python
```

```
DENY   169.254.169.254:80 (http)
  reason: policy.default_deny
  bundle: version 47
```

and exits `3`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--host` | required | hostname or address literal |
| `--port` | `443` | destination port |
| `--protocol` | `https` | `http`, `https` or `tcp` |
| `--profile` | `-` | the profile to evaluate as |
| `--namespace` | `-` | the namespace to evaluate as |
| `--service-account` | `-` | the service account to evaluate as |
| `--identity` | none | a specific identity id |
| `--method` | none | HTTP method, for method-scoped rules |
| `--path` | none | request path, for path-scoped rules |

Simulation runs the policy engine — the same code, over the same active bundle
— and it canonicalises the host first. `--host 2852039166` and
`--host 0xa9fea9fe` are evaluated as `169.254.169.254`, because that is what
they are.

**Simulation is a lower bound on denial, not an upper bound on permission.** It
answers one question: what would the policy engine decide? A real request has
to survive several checks that simulation does not perform:

| Also enforced at request time | Not visible to `simulate` |
| --- | --- |
| The address guard | blocked ranges, metadata endpoints, obfuscated literals |
| DNS resolution | what the hostname actually resolves to |
| The resolved-address check | a permitted name pointing into a blocked range |
| Protocol strictness | the SNI, the Host header, the request framing |
| Limits | rate, connection count and bandwidth ceilings |

So `simulate` saying DENY means the request will be denied. `simulate` saying
ALLOW means the policy permits it and the remaining checks still apply. When a
hostname matters, simulate the address it resolves to as well:

```bash
roctl simulate --host internal-api.example.com --profile ci-runner
roctl simulate --host 10.0.5.12 --profile ci-runner
```

If the second one is denied, so is the first — a rule that permits a name does
not permit an address the guard refuses.

---

## Inspecting a live gateway

These commands talk to a gateway's admin listener rather than the controller,
using `--gateway` and `--gateway-token`. That listener is reachable only from
the sources the gateway's configuration permits, so in a cluster this normally
means port-forwarding.

A gateway admin token is a separate credential from the controller token, and
`roctl` never substitutes one for the other: without `--gateway-token` these
commands refuse to run rather than send a controller credential — which can
rewrite policy for every sandbox in the cluster — to a different service.

```bash
kubectl -n rokh-oghab port-forward svc/ro-gateway 9145:9145 &
export ROCTL_GATEWAY=http://127.0.0.1:9145
export ROCTL_GATEWAY_TOKEN="$(kubectl -n rokh-oghab get secret ro-gateway-admin \
  -o jsonpath='{.data.token}' | base64 -d)"
```

### `roctl gateway status`

```bash
roctl gateway status
```

What this specific gateway is enforcing right now: node name, mode, active
bundle version and digest, staleness, emergency state, worker id and uptime.
Compare its version against `roctl status` when you suspect a propagation
problem.

### `roctl gateway audit`

```bash
roctl gateway audit --limit 100
roctl gateway audit --action deny --limit 200
```

Read the in-memory audit ring buffer directly, newest last. `--action deny`
filters to refusals, which is the fast path when a workload reports a failure
and you want the reason before opening a log aggregator.

The ring buffer is bounded and per-worker. It is a debugging convenience, not
the audit record — see [observability](observability.md) for the durable trail.

### `roctl gateway metrics`

```bash
roctl gateway metrics
```

The raw Prometheus exposition from this one gateway. Useful for a quick check
of `ro_policy_version` and `ro_policy_stale` across replicas.

### `roctl gateway emergency-deny on|off`

```bash
roctl gateway emergency-deny on
```

The emergency switch on a **single** gateway. This is the break-glass path for
when the controller itself is unreachable and you need this data plane stopped
now. Under normal conditions use the controller-wide `roctl emergency-deny`,
which reaches every gateway and survives a restart.

A gateway-local switch does not survive a restart of that gateway. If you set
it because something is wrong, set the controller-wide one too as soon as the
controller is reachable.

---

## Roles

Every control-plane credential carries exactly one role, and the roles are
ordered. A credential with a higher role can do everything a lower one can.

| Role | Can |
| --- | --- |
| `gateway` | fetch the active bundle, nothing else |
| `reader` | read state, list, validate, preview, simulate |
| `operator` | everything `reader` can, plus apply, delete, publish, rollback, emergency deny, issue and revoke identities |
| `admin` | everything `operator` can, plus change global settings |

Two consequences worth planning around:

- **CI should hold `reader`.** Validating policies in a pull request needs
  nothing more, and a leaked pipeline credential that can only validate is not
  an incident.
- **The gateways hold `gateway`.** A compromised gateway can read the bundle it
  was already enforcing. It cannot write policy, issue an identity, or read the
  audit trail of any other gateway.

Configure principals in `config/controller.json`. Nothing ships with the image:
a controller with no principals configured accepts no authenticated request at
all, which is the correct state for an unconfigured deployment.

---

## Recipes

**Give a new sandbox network access, from nothing:**

```bash
roctl policy apply -f policies/untrusted-python.yaml
roctl publish --note "the python sandbox profile"
TOKEN="$(roctl identity issue --namespace execution \
  --profile untrusted-python -o json | jq -r .token)"
roctl publish --note "identity for the research sandbox"
kubectl -n execution create secret generic sandbox-egress \
  --from-literal=token="$TOKEN"
```

**Find out why a workload is failing:**

```bash
roctl gateway audit --action deny --limit 50 -o json \
  | jq '.events[] | select(.profile=="untrusted-python")
        | {ts, host, port, reason, rule}'
```

**Add one destination safely:**

```bash
roctl policy get ci-runner -o json > /tmp/before.json
$EDITOR ci-runner.yaml
roctl validate -f ci-runner.yaml
roctl policy apply -f ci-runner.yaml
roctl preview
roctl simulate --host mirror.internal.example.com --profile ci-runner
roctl publish --note "add the internal mirror"
```

**Undo the last change:**

```bash
roctl versions
roctl rollback "$(roctl versions -o json | jq '.versions[1].version')"
```

**Check that every gateway adopted a publish:**

```bash
for pod in $(kubectl -n rokh-oghab get pods -l app=ro-gateway -o name); do
  kubectl -n rokh-oghab exec "$pod" -- \
    wget -qO- --header="Authorization: Bearer $RO_ADMIN_TOKEN" \
    http://127.0.0.1:9145/v1/status | jq -r '.policy.version'
done
```

See [the API reference](api.md) for the endpoints behind each of these
commands.
