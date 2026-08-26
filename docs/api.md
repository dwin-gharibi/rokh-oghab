# REST API reference

Rokh Oghab exposes two independent HTTP surfaces. They serve different
audiences, listen on different ports, and trust different credentials.

| Surface | Default port | Audience | Credential |
| --- | --- | --- | --- |
| Control plane (`ro-controller`) | `8081` (`8443` with TLS) | operators, CI, gateways | a control-plane bearer token with a role |
| Gateway admin (`ro-gateway`) | `9145` | operators, Prometheus, health probes | a gateway admin token, in one of three roles |

Neither is reachable from a sandbox. The proxy port a sandbox talks to
(`3128`) serves no administrative endpoint at all: a request to it is a proxy
request, and `GET /v1/status` sent to the proxy port is parsed as an attempt to
fetch the path `/v1/status` from a destination that policy then refuses. This
is verified by a test that tries exactly that from inside a sandbox.

---

## Authentication

Both surfaces use `Authorization: Bearer <token>`.

```
Authorization: Bearer ro-operator-9d41c0a37fbe4a1e8c5502fb7d1a6e93
```

Tokens are compared in constant time. A wrong token, a malformed header, and a
missing header all produce the same `401` with the same body and the same
timing, so the response cannot be used to probe for a valid prefix.

The gateway admin listener additionally checks the **source address** against
`admin.allowFrom` before it looks at the token, and does so for every endpoint
including the public ones. A request from an address outside that list gets
`403` whether or not it carried a valid token.

**An empty `admin.allowFrom` means nobody, not everybody.** The gateway refuses
every request to its admin listener when no source is configured, health probes
and metrics included. To admit any source you write it out:

```json
{ "admin": { "allowFrom": ["0.0.0.0/0", "::/0"] } }
```

The shipped configuration is `["127.0.0.1/32", "::1/128"]`, which lets a
probe inside the pod work and nothing else. Widen it to your monitoring
network, not to the world.

The two listeners differ here, deliberately. The gateway's admin port sits on
the same network as the sandboxes, so a mistake there is reachable by the code
you least trust, and an empty list has to fail closed. The controller has no
sandbox on its network, restricts ingress with a NetworkPolicy, and requires a
bearer token on every endpoint that does anything; an empty `allowFrom` there
means "rely on the token and the network policy", and the controller logs that
choice at startup so it cannot be made silently.

An empty admin token does not mean "no authentication required". It means the
listener cannot be authenticated and therefore refuses every non-public
endpoint. This is checked by the shipped-defaults audit, because the opposite
behaviour — empty token meaning open — is a classic way for a hardened system to
ship wide open.

---

## Control plane

Base path `/v1`. Every response is JSON. Every mutating endpoint records an
audit event with the acting principal.

### Roles

| Role | Rank |
| --- | --- |
| `gateway` | 1 |
| `reader` | 2 |
| `operator` | 3 |
| `admin` | 4 |

A route names a minimum role, and a principal whose rank is at least that may
call it. The `gateway` role is deliberately the lowest: it can fetch the active
bundle and do nothing else.

Principals are configured in `config/controller.json`:

```json
{
  "principals": [
    { "name": "ci",        "role": "reader",   "token": "..." },
    { "name": "platform",  "role": "operator", "token": "..." },
    { "name": "break-glass","role": "admin",   "token": "..." },
    { "name": "gateway-a", "role": "gateway",  "token": "..." }
  ]
}
```

No principal ships in the image. A controller with an empty list authenticates
nobody.

### Unauthenticated endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | liveness — the process is up |
| `GET` | `/readyz` | readiness — the store is loadable and a bundle is active |
| `GET` | `/metrics` | Prometheus exposition for the controller |

`/readyz` returns `503` when the store cannot be read. A controller that cannot
read its store must not receive traffic, because a gateway that polls it would
otherwise be told there is no bundle.

### Bundle distribution

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| `GET` | `/v1/bundle` | `gateway` | fetch the active compiled bundle |

This is the only endpoint a gateway calls. The response is the flattened,
validated bundle with its version and digest:

```json
{
  "version": 47,
  "digest": "f3c1a9e2...",
  "ttlSeconds": 300,
  "emergencyDeny": false,
  "identities": { "allowAnonymous": false, "tokens": {}, "sources": [] },
  "policies": [ ... ],
  "defaults": { "maxStalenessSeconds": 900 }
}
```

Gateways compare the digest against what they are running and adopt only when
it differs, so a poll costs one comparison in the common case.

### State

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| `GET` | `/v1/status` | `reader` | active version, revision, counts, emergency state |
| `GET` | `/v1/versions` | `reader` | the published version index |
| `GET` | `/v1/versions/{n}` | `reader` | one published bundle, verbatim |
| `GET` | `/v1/settings` | `reader` | global settings |
| `PUT` | `/v1/settings` | `admin` | replace global settings |

```bash
curl -sS -H "Authorization: Bearer $ROCTL_TOKEN" \
  http://127.0.0.1:8081/v1/status
```

```json
{
  "component": "ro-controller",
  "activeVersion": 47,
  "revision": 128,
  "policyCount": 6,
  "profileCount": 3,
  "tokenCount": 12,
  "sourceCount": 2,
  "emergencyDeny": false,
  "updatedAt": 1756039271
}
```

`activeVersion` is what the gateways enforce; `revision` counts every staged
change. A gap between them means there is something unpublished.

### Policies

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| `GET` | `/v1/policies` | `reader` | list names, tiers, priorities, rule counts |
| `GET` | `/v1/policies/{name}` | `reader` | one policy document |
| `PUT` | `/v1/policies/{name}` | `operator` | stage a policy |
| `DELETE` | `/v1/policies/{name}` | `operator` | remove a policy from the store |

`PUT` accepts `application/json` or `application/yaml`. The document is
normalised and compiled before it is stored, so an invalid policy is rejected at
the point of writing rather than at the point of publishing:

```bash
curl -sS -X PUT \
  -H "Authorization: Bearer $ROCTL_TOKEN" \
  -H 'Content-Type: application/yaml' \
  --data-binary @untrusted-python.yaml \
  http://127.0.0.1:8081/v1/policies/untrusted-python
```

A success reports that the change is staged, not live:

```json
{ "name": "untrusted-python", "revision": 129, "staged": true }
```

A rejection names what is wrong and changes nothing:

```json
{
  "error": "invalid_policy",
  "message": "rule \"mirror\": an allow rule must name at least one destination"
}
```

The policy is compiled twice: once here, alone, so a bad document is refused at
the point of writing, and again at publish time together with every other
document, so a combination that is individually valid but collectively invalid
is also refused.

Staging changes the store, not the network. Nothing reaches a gateway until
`/v1/publish`.

### Profiles

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| `GET` | `/v1/profiles` | `reader` | list profiles |
| `GET` | `/v1/profiles/{name}` | `reader` | one profile |
| `PUT` | `/v1/profiles/{name}` | `operator` | stage a profile |
| `DELETE` | `/v1/profiles/{name}` | `operator` | remove a profile |

### Identities

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| `GET` | `/v1/identities` | `reader` | list token digests and source mappings |
| `POST` | `/v1/identities/tokens` | `operator` | mint a token |
| `DELETE` | `/v1/identities/tokens/{digest}` | `operator` | revoke a token |
| `PUT` | `/v1/identities/sources` | `operator` | replace the source-address mappings |

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $ROCTL_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"namespace":"execution","profile":"untrusted-python",
       "serviceAccount":"sandbox-runner","labels":{"team":"research"}}' \
  http://127.0.0.1:8081/v1/identities/tokens
```

```json
{
  "token": "ro-p-9d41c0a37fbe4a1e8c5502fb7d1a6e93",
  "identity": {
    "id": "ro-id-8f2c1d",
    "namespace": "execution",
    "profile": "untrusted-python",
    "serviceAccount": "sandbox-runner",
    "labels": { "team": "research" }
  },
  "digest": "4b1e...c07a",
  "revision": 129
}
```

**The `token` field appears in this one response and nowhere else.** The store
holds only the digest. `GET /v1/identities` returns digests; there is no
endpoint that returns a token, by design, so a compromised `reader` credential
cannot harvest the credentials of every sandbox in the cluster.

`PUT /v1/identities/sources` replaces the entire set:

```json
{ "sources": [
  { "cidr": "10.42.7.0/24", "id": "build-farm",
    "namespace": "execution", "profile": "ci-runner",
    "serviceAccount": "builder" }
] }
```

### Publishing

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| `POST` | `/v1/publish` | `operator` | compile, version and activate the staged configuration |
| `POST` | `/v1/rollback` | `operator` | re-activate a previous version |
| `POST` | `/v1/emergency-deny` | `operator` | stop or resume all egress |

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $ROCTL_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"note":"allow the internal artefact mirror"}' \
  http://127.0.0.1:8081/v1/publish
```

```json
{
  "version": 48,
  "summary": {
    "version": 48,
    "issuedAt": 1756039271,
    "ttlSeconds": 300,
    "emergencyDeny": false,
    "policyCount": 6,
    "ruleCount": 31,
    "policies": [
      { "name": "global-baseline", "tier": "global", "priority": 0,
        "rules": 4, "allowRules": 0, "denyRules": 4 },
      { "name": "untrusted-python", "tier": "profile", "priority": 0,
        "rules": 3, "allowRules": 3, "denyRules": 0 }
    ]
  }
}
```

The summary is the fastest way to sanity-check a publish: if `allowRules` grew
when you expected it to shrink, do not wait for a workload to notice.

Publish is atomic: the whole staged configuration compiles or nothing changes.
A failure returns `422`, consumes no version number, and leaves the running
policy exactly as it was.

```bash
curl -sS -X POST -H "Authorization: Bearer $ROCTL_TOKEN" \
  -H 'Content-Type: application/json' -d '{"version":46}' \
  http://127.0.0.1:8081/v1/rollback

curl -sS -X POST -H "Authorization: Bearer $ROCTL_TOKEN" \
  -H 'Content-Type: application/json' -d '{"enabled":true}' \
  http://127.0.0.1:8081/v1/emergency-deny
```

Rollback stores and activates a *new* version whose content equals the old one,
so the history stays append-only.

The version **index** keeps the most recent 200 entries, so `GET /v1/versions`
is bounded no matter how often you publish. The bundle files themselves are not
deleted, so `GET /v1/versions/{n}` and a rollback to `n` still work for a
version that has aged out of the index. If you need the full publish history
beyond 200 entries, ship the controller's audit events somewhere durable — they
record every publish with its actor, note and version.

### Validation without change

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| `POST` | `/v1/validate` | `reader` | compile one document, change nothing |
| `POST` | `/v1/preview` | `reader` | compile the staged configuration, change nothing |
| `POST` | `/v1/simulate` | `reader` | ask what the active policy would decide |

All three need only `reader`, which is what makes them safe for CI.

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $CI_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"host":"files.pythonhosted.org","port":443,"protocol":"https",
       "profile":"untrusted-python","namespace":"execution"}' \
  http://127.0.0.1:8081/v1/simulate
```

```json
{
  "decision": "allow",
  "reason": "policy.allow",
  "rule": "python-package-index",
  "policy": "untrusted-python",
  "limits": {
    "requestsPerSecond": 20,
    "maxConnections": 32,
    "bandwidthBytesPerSecond": 10485760
  },
  "destination": {
    "host": "files.pythonhosted.org", "kind": "hostname", "port": 443
  },
  "identity": {
    "id": "simulated", "namespace": "execution",
    "profile": "untrusted-python", "serviceAccount": "-"
  },
  "bundleVersion": 47
}
```

Simulation evaluates the policy engine only. The address guard, DNS resolution,
the resolved-address check, protocol strictness and the limiters all run at
request time and can still deny something simulation permitted. A `deny` from
simulate is final; an `allow` is a statement about policy, not a guarantee about
a specific request.

### Errors

| Status | When |
| --- | --- |
| `400` | the body is not valid JSON or YAML |
| `401` | the token is missing, malformed or wrong |
| `403` | the token is valid but its role is too low |
| `404` | no such route, policy, profile or version |
| `422` | the document parsed but does not compile, or a publish or rollback was refused |
| `500` | the store could not be read or written |
| `503` | there is no active bundle to serve |

```json
{ "error": "forbidden", "message": "this endpoint requires role operator" }
```

Errors carry a stable machine-readable `error` and a human `message`. Match on
`error`; the wording of `message` may change.

---

## Gateway admin

Base URL `http://<gateway>:9145`. Two gates stand in front of every request:
the source address must be inside `admin.allowFrom`, and the bearer token must
carry the role the endpoint requires.

### Roles

The gateway has the same three-tier model as the controller, and for the same
reason: a monitoring system that reads `/v1/status` should not be holding the
credential that can replace policy.

| Role | Token | Reaches |
| --- | --- | --- |
| `reader` | `admin.readerToken` / `RO_ADMIN_READER_TOKEN` | health, readiness, metrics, status, policy summary |
| `operator` | `admin.operatorToken` / `RO_ADMIN_OPERATOR_TOKEN` | everything a reader reaches, plus the audit trail, DNS flush, emergency deny and validation |
| `admin` | `admin.token` / `RO_ADMIN_TOKEN` | everything, including the effective configuration and applying a bundle |

Roles are cumulative and a token gets the highest role it matches. Configuring
only `admin.token` gives exactly the behaviour of earlier versions: one token
that reaches everything. Set the other two when you want the separation.

A refused request answers `401` and increments `ro_admin_denied_total`, so an
operator can alert on someone probing with the wrong credential.

The audit trail sits behind `operator` rather than `reader` on purpose: it
names destinations and workload identities, which is more than a dashboard
needs to know.

### Endpoints that can answer without a role

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | the worker is alive |
| `GET` | `/readyz` | a usable policy bundle is loaded |
| `GET` | `/metrics` | Prometheus exposition |

These three are listed in `admin.public`, which defaults to all three so that
liveness probes and Prometheus work out of the box. Remove any of them — or set
`RO_ADMIN_PUBLIC=none` — and it requires the `reader` role like everything
else. In Kubernetes a probe can carry the token with `httpGet.httpHeaders`, and
Prometheus with `authorization.credentials_file`, so locking all three down is
practical rather than theoretical.

Public here means only "no token"; it never means unrestricted. The
source-address check applies to these as well, so Prometheus must still be
inside `admin.allowFrom` to scrape.

`/readyz` returns `503` with a reason when the gateway has no usable bundle —
because it never loaded one, or because the one it has has gone stale past
`maxStalenessSeconds`. A gateway in that state denies every request, so taking
it out of service is correct rather than merely tidy.

```json
{ "status": "not_ready", "reason": "policy.stale" }
```

### Endpoints that require a role

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| `GET` | `/v1/status` | `reader` | node, mode, policy summary, emergency state, worker, uptime |
| `GET` | `/v1/policy` | `reader` | a summary of the loaded bundle |
| `GET` | `/v1/audit` | `operator` | recent audit events from the ring buffer |
| `POST` | `/v1/validate` | `operator` | compile a bundle without applying it |
| `POST` | `/v1/emergency-deny` | `operator` | stop egress on this gateway, or clear a stop set here |
| `POST` | `/v1/dns/flush` | `operator` | drop cached DNS answers |
| `GET` | `/v1/config` | `admin` | the effective configuration, with secrets redacted |
| `POST` | `/v1/bundle` | `admin` | apply a bundle directly to this gateway |

```bash
curl -sS -H "Authorization: Bearer $RO_ADMIN_TOKEN" \
  'http://127.0.0.1:9145/v1/audit?limit=20&action=deny'
```

`/v1/audit` takes `limit`, `action` (`allow` or `deny`) and `identity`. It
reads a bounded in-memory ring buffer that is per-worker and per-pod. It is a
debugging convenience; the durable record is the audit sink described in
[observability](observability.md).

`/v1/config` redacts every token — `admin.token`, `admin.readerToken`,
`admin.operatorToken` and `controller.token` — to `***`. It reports whether a
token is set, never what it is. It sits behind `admin` rather than `operator`
because the full effective configuration describes the whole topology.

`POST /v1/bundle` applies policy to one gateway without going through the
controller. It exists for air-gapped and single-node deployments where there is
no controller at all. **In a controller-managed deployment it is a foot-gun**:
the next successful poll overwrites what you applied, so the change appears to
work and then silently reverts. Every use of it is audited at `severity: high`.

`POST /v1/emergency-deny` sets a switch that only ever adds denial. It stops
this gateway when the controller cannot be reached, and clearing it resumes
egress only if nothing else is stopping the gateway — a bundle carrying
`emergencyDeny` is a fleet-wide stop that a single gateway's operator cannot
opt out of. The response reports both: `emergencyDeny` is the effective state
and `localOverride` is what you just set.

```json
{ "emergencyDeny": true, "localOverride": false }
```

`POST /v1/dns/flush` accepts `{"name":"example.com"}` to drop one entry, or an
empty body to drop everything. Flushing does not weaken anything — the next
lookup is re-resolved and re-checked against policy exactly as the first one
was.

---

## Using the API without `roctl`

Everything `roctl` does is one of these calls. A minimal deployment pipeline
needs three:

```bash
API=http://ro-controller:8081
AUTH="Authorization: Bearer $ROCTL_TOKEN"

for f in policies/*.yaml; do
  name="$(basename "$f" .yaml)"
  curl -fsS -X PUT -H "$AUTH" -H 'Content-Type: application/yaml' \
    --data-binary @"$f" "$API/v1/policies/$name"
done

curl -fsS -X POST -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{}' "$API/v1/preview"

curl -fsS -X POST -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"note\":\"$GIT_SHA\"}" "$API/v1/publish"
```

`curl -f` turns a non-2xx into a non-zero exit, which with `set -e` means a
rejected policy fails the pipeline instead of silently skipping the publish.

---

## What is deliberately absent

Some endpoints do not exist, and their absence is a design decision rather than
an omission:

- **No endpoint returns a token.** Only the digest is stored.
- **No endpoint disables the address guard.** It is configuration, applied at
  start-up, not a runtime toggle a compromised credential can flip.
- **No endpoint makes a policy default to `allow`.** The compiler rejects it, so
  there is no path — API, file or CLI — that produces a permissive default.
- **The proxy port serves no administrative endpoint.** A sandbox that can reach
  the proxy cannot reach an API through it.
- **No endpoint deletes a published version.** History is append-only, so the
  audit trail cannot be rewritten by whoever caused the incident.
