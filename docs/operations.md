# Operations

Running Rokh Oghab day to day. This is the document for the person on call.

The one thing worth internalising before anything else: **when Rokh Oghab
breaks, sandboxes lose network access — they do not gain it.** A stopped
gateway, a stale bundle, an unreachable controller and a malformed policy all
converge on the same outcome, which is that nothing gets out. That makes most
incidents an availability problem rather than a security problem, and it is a
deliberate trade.

---

## The daily loop

### Changing what a sandbox can reach

```bash
roctl policy apply -f policies/untrusted-python.yaml
roctl preview
roctl publish --note "add the internal artefact mirror"
```

Three steps, and the middle one is the one people skip. `apply` stages;
`publish` activates. Between them nothing has reached a gateway, which is
exactly the window in which to check your work.

Before publishing anything that widens access, ask what it will decide:

```bash
roctl simulate --host mirror.internal.example.com --profile ci-runner
roctl simulate --host mirror.internal.example.com --port 80 --protocol http \
               --profile ci-runner
```

Simulate the port and protocol you actually intend, and simulate the ones you
do not. A rule that accidentally permits plain HTTP on port 80 as well as HTTPS
on 443 looks identical in the document and different in the simulation.

### Confirming a publish landed

```bash
roctl status
```

`activeVersion` should be the number `publish` returned. Then check the
gateways agree:

```promql
max(roc_active_version) - min(ro_policy_version)
```

Zero means everyone adopted. Non-zero for more than a poll interval means a
gateway is not fetching, which is the beginning of a stale-policy incident.

Without Prometheus:

```bash
for pod in $(kubectl -n rokh-oghab get pods -l app=ro-gateway -o name); do
  printf '%s ' "$pod"
  kubectl -n rokh-oghab exec "$pod" -- \
    wget -qO- --header="Authorization: Bearer $RO_ADMIN_TOKEN" \
    http://127.0.0.1:9145/v1/status | jq -r '.policy.version'
done
```

### Onboarding a workload

```bash
roctl profile apply -f profiles/untrusted-python.yaml
roctl policy apply -f policies/untrusted-python.yaml
roctl publish --note "the python sandbox profile"

TOKEN="$(roctl identity issue \
  --namespace execution \
  --profile untrusted-python \
  --service-account sandbox-runner \
  --label team=research \
  -o json | jq -r .token)"
roctl publish --note "identity for the research sandbox"

kubectl -n execution create secret generic sandbox-egress \
  --from-literal=token="$TOKEN"
unset TOKEN
```

The token is shown once. If you lose it, revoke the digest and issue another —
there is no recovery path, by design.

Both the profile and the identity need a publish. An identity that exists in the
store but not in a published bundle authenticates nothing, and the symptom is
`identity.unknown` on every request.

---

## When something is wrong

### Stop everything

```bash
roctl emergency-deny on
```

Every gateway refuses every destination, immediately, without touching a policy
document. Turn it off and the previous policy resumes unchanged:

```bash
roctl emergency-deny off
```

Use it when you know something is wrong and do not yet know what. A stopped
network is a state you can reason about. The cost of pulling it unnecessarily is
an outage; the cost of not pulling it when you should have is whatever the
workload was doing.

If the **controller** is unreachable and you need a specific gateway stopped:

```bash
roctl --gateway http://127.0.0.1:9145 gateway emergency-deny on
```

That is per-gateway and does not survive a restart of that gateway. Set the
controller-wide switch as well as soon as the controller is reachable.

The switch is held in the shared dictionary every worker reads, so one request
sets it for the whole gateway and one request lifts it for the whole gateway.
If that dictionary is unavailable the endpoint answers `503` rather than
setting the switch for whichever worker happened to answer: a switch that
engages on one worker in four is worse than one that visibly refuses.

The local switch can only add denial, never remove it. A bundle that carries
`emergencyDeny` stops every gateway that loads it, and lifting the local switch
on one of them does not resume egress there: the controller is the higher
authority, and someone holding a single gateway's admin token must not be able
to opt that gateway out of a fleet-wide stop. `POST /v1/emergency-deny` reports
the effective state in `emergencyDeny` and what you just set in
`localOverride`, so lifting a local switch while a bundle-level stop is in
force answers `{"emergencyDeny": true, "localOverride": false}`.

The local switch exists for the case where the controller is unreachable and
one gateway needs stopping. To resume a fleet-wide stop, clear it where it was
set — at the controller.

### Undo the last change

```bash
roctl versions
roctl rollback 46
```

Rollback re-activates a stored bundle byte for byte. It is not a re-derivation,
so what you get is exactly what was running, not an approximation of it.

Rollback is itself versioned: rolling back to 46 from 47 produces version 48
whose content equals 46. The history stays append-only, so nothing about the
incident disappears from the record.

**Rollback does not revert the store.** The documents that produced 47 are still
staged. If you publish again without fixing them you will re-publish the problem.
Fix the documents, then publish:

```bash
roctl rollback 46
roctl policy get ci-runner -o json | jq .      # what is still staged
$EDITOR policies/ci-runner.yaml
roctl policy apply -f policies/ci-runner.yaml
roctl preview
roctl publish --note "fix the mirror rule properly"
```

### A workload says it cannot reach something

Ask the gateway before you ask the workload:

```bash
roctl gateway audit --action deny --limit 50 -o json \
  | jq -c 'select(.profile=="untrusted-python")
           | {ts, host, port, protocol, reason}'
```

The `reason` is the answer. Every reason code and what to do about it is in
[troubleshooting](troubleshooting.md). The three you will see most:

| Reason | Means |
| --- | --- |
| `policy.default_deny` | no rule permits it — this is the system working |
| `identity.unknown` | the token is missing, wrong, or not published |
| `policy.stale` | the gateway lost its controller and is failing closed |

---

## Capacity

### What one gateway costs

A gateway is nginx's stream subsystem with Lua on the connection path. Per
connection it holds one client socket, one upstream socket, and a small amount
of Lua state. Policy evaluation is `ro_policy_eval_seconds`, bucketed from 100µs
to 50ms because it must not be where time goes.

The limits that matter:

| Setting | Default | Meaning |
| --- | --- | --- |
| `limits.globalMaxConnections` | `20000` | connections per gateway before new ones are refused |
| `limits.maxConnectionsPerSource` | `256` | concurrent connections from one source address |
| `limits.headTimeoutMs` | `10000` | how long an unfinished request head is held |
| `limits.maxHeadBytes` | `65536` | ceiling on a request or response head |
| `limits.maxRequestsPerConnection` | `256` | requests on one keep-alive connection |
| `limits.clientTimeoutMs` | `60000` | client socket timeout |
| `limits.upstreamTimeoutMs` | `30000` | upstream socket timeout |
| `limits.connectTimeoutMs` | `5000` | upstream connect timeout |
| `limits.idleTimeoutMs` | `120000` | idle tunnel timeout |
| `limits.defaultRequestsPerSecond` | `0` (off) | per-identity default, overridable per rule |
| `limits.defaultMaxConnections` | `0` (off) | per-identity default, overridable per rule |

`maxHeadBytes` and `maxRequestsPerConnection` are memory bounds as much as
protocol ones: they are what stops a sandbox from pinning a worker with an
endless header block or an unbounded pipeline.

`globalMaxConnections` is a fail-closed ceiling, not a target. When it is hit,
new connections are refused with `limit.global_connections` — the gateway sheds
load rather than degrading for everyone. Alert on it approaching, not on it
being hit.

`maxConnectionsPerSource` is what stops one workload taking the whole gateway
down. It is applied at accept time, before anything is parsed, which matters
because the per-identity limits cannot help here: identity comes from a request
header, and a connection that never finishes its head never has one. Without a
per-source cap, a sandbox opening connections and sending half a request each
consumes global slots that every other sandbox needs.

It is deliberately per **source address** rather than per identity. In the
designed topology each sandbox is a pod with its own address, so a source is a
workload. Behind a NAT that collapses many workloads onto one address they share
the budget, so raise it if your sandboxes are not individually addressed.

The cost of flooding falls on the flooder: a source at its cap is refused with
`limit.source_connections` and a `429`, and every other source is unaffected.
This is tested by opening 400 partial connections and confirming the gateway
stays healthy and its admin plane stays reachable.

`headTimeoutMs` bounds the slowloris window. A connection that has sent part of
a request head but not the blank line is dropped after this long, rather than
after the full `clientTimeoutMs`. No real client takes ten seconds to send a
request head, so the shorter budget costs nothing and cuts the window by a
factor of three.

### Scaling out

Gateways are stateless with respect to policy: each one polls the controller and
holds the same bundle. Add replicas freely.

```bash
kubectl -n rokh-oghab scale deploy/ro-gateway --replicas=6
```

Two things do **not** scale with replicas, and both are per-gateway:

- **Rate and connection limits.** A limit of 20 requests per second is 20 per
  gateway, so six gateways allow up to 120 for a workload whose connections
  spread across them. Size limits with replica count in mind, or pin a
  workload's connections to one gateway with session affinity.
- **The audit ring buffer.** It is per-pod and per-worker. `roctl gateway audit`
  shows one pod's recent history, never the fleet's. Use the log pipeline for
  anything fleet-wide.

The controller does not need to scale with the gateways. It serves a poll per
gateway per interval and a handful of operator requests. One replica is enough
for correctness; run two for availability, sharing the same policy volume.

### Tuning the poll interval

```json
{
  "controller": {
    "url": "http://ro-controller:8081",
    "token": "...",
    "pollSeconds": 10,
    "timeoutMs": 3000,
    "failClosed": true
  }
}
```

Shorter means policy changes land faster and the controller takes more load.
Longer means the reverse. Ten seconds is a reasonable default: a publish reaches
every gateway within ten seconds, and a hundred gateways cost ten requests a
second.

Do not set `pollSeconds` anywhere near `maxStalenessSeconds`. The gateway needs many
chances to refresh before it decides it has gone stale; a poll interval close to
the staleness budget turns one transient failure into an outage.

---

## Failure modes

Each of these is tested, not asserted. The tests are named in
[testing](testing.md).

### The gateway stops

Sandboxes lose all network access. Not "fall back to direct" — the node's
nftables ruleset has no rule that permits anything except the gateway, so with
the gateway gone there is nothing left that is permitted.

This is verified by a test that stops the gateway container and then attempts
both a direct connection to a known origin and a connection to a public address.
Both must fail.

**Recovery:** restart the gateway. There is no state to restore; it fetches the
active bundle and resumes.

### The controller stops

Gateways keep enforcing the last bundle they hold. Traffic is unaffected while
the bundle is fresh.

Once the bundle exceeds `defaults.maxStalenessSeconds` (900 by default), each
gateway sets `ro_policy_stale` to 1 and begins denying every request. Enforcing
policy that might be fifteen minutes out of date is a decision the system makes
for you: it does not.

```json
{ "controller": { "failClosed": true } }
```

`failClosed` is `true` in the shipped configuration and the defaults audit
checks that it stays that way.

**Recovery:** restart the controller. Gateways refresh on their next poll,
`ro_policy_stale` returns to 0, and traffic resumes without a gateway restart.

**Prevention:** run two controller replicas over the same policy volume, and
alert on `RokhOghabReloadFailing` long before staleness is reached.

### A bundle is malformed

Publishing compiles first. A document that does not compile is refused with
`422`, the version number is not consumed, and the running policy is untouched.

```
roctl: server returned 422: rule "mirror" in policy "ci-runner":
       an allow rule must name at least one destination
```

There is no path by which a bad policy reaches a gateway, because gateways
receive compiled bundles and the compiler runs before storage.

### A gateway cannot reach its upstream

Connection failures increment `ro_connection_failures_total` and are audited per
request. This is a destination problem, not a gateway problem — but a sustained
rate against one destination usually means a firewall or DNS change somewhere
downstream that nobody told you about.

### The node agent's ruleset is removed

If something flushes nftables, enforcement is gone until the agent reapplies.
`ro-agent run` reconciles on an interval and restores it.

The bypass suite tests exactly this: it deletes the table, confirms egress opens
(proving the ruleset was what was enforcing), reapplies, and confirms egress
closes again.

Run the agent as a DaemonSet with `run` rather than a one-shot `apply`, so drift
self-repairs. Alert on the DaemonSet being unhealthy — a node whose agent is
dead is a node whose sandboxes may not be confined.

---

## Upgrades

### Order

Controller first, then gateways, then agents.

The controller's bundle format is backwards compatible within a major version,
so a new controller serves bundles that older gateways understand. The reverse
is not guaranteed: a new gateway may expect a field an older controller does not
send.

```bash
kubectl -n rokh-oghab set image deploy/ro-controller \
  controller=ghcr.io/rokh-oghab/controller:1.1.0
kubectl -n rokh-oghab rollout status deploy/ro-controller

kubectl -n rokh-oghab set image deploy/ro-gateway \
  gateway=ghcr.io/rokh-oghab/gateway:1.1.0
kubectl -n rokh-oghab rollout status deploy/ro-gateway

kubectl -n rokh-oghab set image ds/ro-agent \
  agent=ghcr.io/rokh-oghab/agent:1.1.0
kubectl -n rokh-oghab rollout status ds/ro-agent
```

### Gateway rollout

A rolling update is safe. Each replica is independent, and connections through a
terminating pod are drained rather than cut — up to the grace period, after
which they are closed. Sandboxes retry.

Watch `ro_policy_version` during the rollout. A new pod that comes up and does
not reach the current version has a controller connectivity problem, and you
want to know that while one pod is affected rather than all of them.

### Agent rollout

Updating the agent DaemonSet reprograms nftables on each node. The ruleset is
replaced atomically — nftables applies a table as a unit — so there is no window
in which the node is unprotected.

Verify before you roll it everywhere:

```bash
sudo RO_SANDBOX_CIDRS=10.42.0.0/16 RO_GATEWAY_ADDR=10.43.0.10 \
  ./bin/ro-agent print
```

`print` emits the ruleset without applying it. `check` validates the inputs and
exits non-zero if they are wrong.

### Rolling back an upgrade

Images and policy roll back independently:

```bash
kubectl -n rokh-oghab rollout undo deploy/ro-gateway
roctl rollback 46
```

Do the image rollback first if you suspect the image, and the policy rollback
first if you suspect the policy. If you are not sure, `emergency-deny on` costs
you an outage and buys you time to find out.

---

## Backup and restore

The controller's state is a directory: policy documents, profiles, identity
digests, settings, published bundles and the active pointer.

```bash
kubectl -n rokh-oghab exec deploy/ro-controller -- \
  tar czf - -C /var/lib/rokh-oghab . > ro-backup-$(date +%F).tar.gz
```

Restore:

```bash
kubectl -n rokh-oghab scale deploy/ro-controller --replicas=0
kubectl -n rokh-oghab exec deploy/ro-controller -- \
  tar xzf - -C /var/lib/rokh-oghab < ro-backup-2026-08-01.tar.gz
kubectl -n rokh-oghab scale deploy/ro-controller --replicas=1
```

What the backup does **not** contain: proxy tokens. Only digests are stored, so
a restore brings back the identity records but not the credentials. Sandboxes
holding the old tokens keep working — the digests still match — but a token you
never captured is gone for good.

The better practice is to keep policy documents in git and treat the controller
store as a cache:

```bash
for f in policies/*.yaml; do roctl policy apply -f "$f"; done
for f in profiles/*.yaml; do roctl profile apply -f "$f"; done
roctl publish --note "restored from git $(git rev-parse --short HEAD)"
```

That reconstructs everything except identities, which you re-issue. It is also
the only version of the store that has code review attached to it.

---

## Rotating credentials

### A sandbox token

```bash
NEW="$(roctl identity issue --namespace execution \
  --profile untrusted-python -o json | jq -r .token)"
roctl publish
kubectl -n execution create secret generic sandbox-egress \
  --from-literal=token="$NEW" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n execution rollout restart deploy/sandbox
roctl identity revoke <old-digest>
roctl publish
```

Issue and publish the new token before revoking the old one. Both are valid in
between, so there is no window in which the workload has no working credential.

### The gateway admin token

```bash
kubectl -n rokh-oghab create secret generic ro-gateway-admin \
  --from-literal=token="$(openssl rand -hex 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n rokh-oghab rollout restart deploy/ro-gateway
```

This one has a real window: metrics scraping and health probes fail between the
secret change and the rollout completing. Do it during a rollout you were doing
anyway.

### A control-plane principal

Edit `config/controller.json`, add the new token alongside the old, restart, move
consumers across, then remove the old one and restart again. Two restarts, no
window.

### The control-plane PKI

```bash
./gen-ca.sh --verify
```

Regenerating the CA invalidates every issued certificate at once. Plan it as a
maintenance window: new CA, reissue every certificate, restart the controller,
then the gateways.

---

## Routine checks

**Weekly**

```bash
roctl status
roctl identity list
```

Look for identities nobody remembers issuing. An identity that exists for a
workload that was decommissioned is a credential nobody is watching.

**On every policy change**

```bash
roctl validate -f <file>
roctl preview
roctl simulate --host <the destination> --profile <the profile>
```

**Monthly**

```bash
make test-all
sudo make test-privileged
```

Run the adversarial and bypass suites against the version you are actually
running, not just in CI against `main`. The suites take minutes; a bypass that
your specific configuration allows takes rather longer to notice otherwise.

**After any incident**

Add the thing that went wrong to the test suite. The bypass suite exists because
every bypass found during development became a permanent regression test, and
that is the only mechanism that stops the same hole reopening.

---

## Things that will bite you

**Publishing is not automatic.** `apply` stages. Every "the policy did not take
effect" report starts here.

**An identity needs a publish too.** Issuing a token writes it to the store. The
gateways learn about it at the next publish. Until then: `identity.unknown`.

**Rate limits are per gateway.** Six replicas multiply the effective limit by
six for a workload whose connections spread out.

**Rollback does not revert the store.** It changes what is active, not what is
staged. Publishing again re-publishes the problem.

**`maxStalenessSeconds` is an availability budget.** It is how long sandboxes
keep working after the controller dies. Fifteen minutes is a compromise; make it
longer and you enforce staler policy, shorter and you have less time to fix a
controller outage.

**The proxy port is not the admin port.** `3128` proxies, `9145` administers,
and a sandbox can reach only the first. A request for `/v1/status` sent to
`3128` is treated as a request to fetch that path from somewhere, and refused.

**Transparent mode identifies by source address.** That is only as trustworthy
as the layer assigning addresses. It is sound with a CNI and a node agent
dropping forged sources, and unsound on a flat network. Prefer tokens.
