# Policy reference

Policy is a set of documents. Nothing is permitted until a rule says so.

## Document shapes

Rokh Oghab accepts two kinds of document, in YAML or JSON.

### EgressPolicy

Full control. Use this when you need deny rules, tiers, selectors, methods,
paths or limits.

```yaml
apiVersion: rokhoghab.io/v1
kind: EgressPolicy
metadata:
  name: untrusted-python
  tier: profile          # global | cluster | namespace | profile | pod
  priority: 10           # higher wins when two rules in the same tier match
spec:
  defaultAction: deny    # only "deny" is accepted
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
```

### SandboxProfile

A simpler shape for the common case. The controller expands it into an
`EgressPolicy` in the `profile` tier selected by its own name.

```yaml
apiVersion: rokhoghab.io/v1
kind: SandboxProfile
metadata:
  name: untrusted-python
spec:
  egress:
    default: deny        # only "deny" is accepted
    allow:
      - host: pypi.org
        port: 443
        protocol: https
      - domain: pythonhosted.org
        ports: [443]
        protocols: [https]
    deny:
      - domain: telemetry.example.com
```

## Evaluation

1. Every rule at every tier whose selector matches the identity is considered.
2. If any of them explicitly denies, the answer is **deny**.
3. Otherwise, if any of them explicitly allows, the answer is **allow**.
4. Otherwise the answer is **deny**.

Deny always wins, regardless of tier. A platform team can put an absolute deny
in the `global` tier and no team below can undo it.

When several allow rules match, their limits merge by taking the most
restrictive of each.

## Selectors

```yaml
selector:
  namespaces:      [execution, training]
  profiles:        [untrusted-python]
  serviceAccounts: [sandbox-runner]
  identities:      [sandbox-7]
  labels:
    tenant: acme
```

An empty selector matches every identity, which is what a `global` tier policy
usually wants. Every field present must match; fields absent are wildcards.

## Rules

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | Appears in audit records and metrics |
| `action` | `allow` or `deny` | Required |
| `destinations` | object | Where the rule applies. Required on allow rules |
| `ports` | array | Ports or ranges. Required on allow rules |
| `protocols` | array | `http`, `https`, `tcp` |
| `methods` | array | HTTP methods, for plaintext HTTP and inspected traffic |
| `paths` | array | Glob patterns, matched against the normalised path |
| `rateLimit` | object | `requestsPerSecond`, `burst` |
| `connections` | object | `max` concurrent connections for this identity |
| `bandwidth` | object | `bytesPerSecond`, accepting `10M` style suffixes |
| `requestSize` | size | Largest request body |
| `responseSize` | size | Largest response body |
| `tls` | object | `minVersion`, `requireSni`, `inspect` |

An allow rule without destinations or without ports is refused at compile time.
That is deliberate: a typo such as `destination:` instead of `destinations:`
would otherwise silently produce a rule matching everything.

For the same reason, **an empty list is refused wherever it would be read as
"any"**. Omitting `protocols` places no protocol constraint; writing
`protocols: []` is rejected rather than treated as the same thing:

```
rule "mirror": protocols is present but empty; an empty list is not the same
as omitting the field, which would mean 'any'. Remove the field to place no
constraint, or name what it covers.
```

This matters most under templating. A Helm or kustomize expression that
resolves to nothing produces `protocols: []`, and the difference between "no
constraint" and "the constraint the author wrote" is the difference between a
rule that permits HTTPS and one that permits anything on that port.

### destinations

```yaml
destinations:
  hostnames:        [pypi.org, api.github.com]
  hostnameSuffixes: [pythonhosted.org]        # the apex and every subdomain
  cidrs:            [203.0.113.0/24]          # matches address literals only
  resolvedCidrs:    [203.0.113.0/24]          # constrains where a name may resolve
```

`hostnameSuffixes: [example.com]` matches `example.com`, `api.example.com` and
`a.b.example.com`. It does **not** match `evilexample.com` or
`example.com.evil.io`, because matching happens on label boundaries.

Hostname rules never match an address literal, and CIDR rules never match a
hostname. If you want a sandbox to reach an address directly, say so with a
CIDR rule.

For allow rules a suffix must have at least two labels, so `com` is refused.

`resolvedCidrs` is the strongest destination constraint available: the name
must resolve inside the range, or the request is refused. Use it when you know
the address range a vendor publishes from.

### ports

```yaml
ports: [80, 443]
ports: ["8000-8100"]
ports: [{ from: 9000, to: 9100 }]
ports: [443, "8443", { from: 9000, to: 9100 }]
```

### protocols

| Value | Means |
| --- | --- |
| `http` | Plaintext HTTP through the proxy |
| `https` | A TLS session inside a `CONNECT` tunnel |
| `tcp` | A non-TLS session inside a `CONNECT` tunnel |

The protocol is determined by what actually happens, not by what the client
claims. A tunnel is evaluated once when it opens and again once the gateway has
seen whether the first bytes are a TLS ClientHello, so a rule listing only
`https` refuses a plaintext tunnel on the same port.

### paths and methods

```yaml
methods: [GET, HEAD]
paths:
  - /repos/*      # one segment
  - /repos/**     # any depth
```

Matched against the normalised path. `/repos/../users` is `/users`, so it does
not match `/repos/*`. Requests must arrive already normalised when
`strict.path` is on, which is the default.

These apply to plaintext HTTP and to inspected TLS. They do not apply to a
passed-through tunnel, because the gateway does not see inside it.

### limits

```yaml
rateLimit:
  requestsPerSecond: 20
  burst: 40
connections:
  max: 50
bandwidth:
  bytesPerSecond: 10M
requestSize: 32M
responseSize: 512M
```

Limits are keyed by identity, so one sandbox cannot spend another's budget.

### tls

```yaml
tls:
  minVersion: "1.2"
  requireSni: true
  inspect: false
```

## Global settings

```yaml
ttlSeconds: 300
emergencyDeny: false
defaults:
  maxStalenessSeconds: 900
guard:
  blocked:         [10.0.0.0/8, 172.16.0.0/12]
  allowExceptions: [10.20.30.0/24]
```

`guard.blocked` adds to the built-in ranges. `guard.allowExceptions` is the
only way to reach internal space, and it is checked before the block list so an
operator can carve out one internal service deliberately.

`defaults.maxStalenessSeconds` is how long a gateway keeps enforcing a bundle
after it loses contact with the controller, before it starts denying every
request. It must be greater than zero and no more than a day; both bounds are
enforced at compile time.

Zero is refused rather than accepted, because it reads as the strictest setting
and would behave as the most permissive one — disabling the staleness check
instead of tightening it. To stop enforcing staleness at all, the switch is
`controller.failClosed: false` on the gateway, which is an explicit and audited
choice rather than a number that happens to mean something unexpected.

Size it as an availability budget: it is how long your sandboxes keep working
while you fix a controller outage. Fifteen minutes is the shipped default.

`ttlSeconds` must likewise be positive.

## Identities

```yaml
identities:
  allowAnonymous: false
  tokens:
    "<sha256 of the token>":
      id: sandbox-7
      namespace: execution
      profile: untrusted-python
      serviceAccount: sandbox-runner
      labels:
        tenant: acme
  sources:
    - cidr: 10.244.5.0/24
      id: sandbox-pool
      namespace: execution
      profile: untrusted-python
  trustedHeaderSources:
    - 10.244.9.0/24
```

Tokens are stored as digests. Issue one with `roctl identity issue`, which is
the only moment the plaintext exists.

`trustedHeaderSources` should contain only an identity injector you operate. A
request from one of those ranges may set `X-RO-Profile`, `X-RO-Namespace`,
`X-RO-Identity`, `X-RO-Service-Account` and `X-RO-Pod`.

## Worked examples

### A Python sandbox that may install packages

```yaml
apiVersion: rokhoghab.io/v1
kind: EgressPolicy
metadata:
  name: untrusted-python
  tier: profile
spec:
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
      rateLimit: { requestsPerSecond: 20 }
      bandwidth: { bytesPerSecond: 10M }
```

### A read-only slice of one API

```yaml
    - name: github-repos-read-only
      action: allow
      destinations:
        hostnames: [api.github.com]
      ports: [443]
      protocols: [https]
      methods: [GET, HEAD]
      paths: ["/repos/**"]
      tls: { minVersion: "1.3", inspect: true }
```

Path and method rules need `inspect: true` to apply to a TLS destination.
Without inspection the gateway can only see the destination.

### An absolute floor no team can lower

```yaml
apiVersion: rokhoghab.io/v1
kind: EgressPolicy
metadata:
  name: global-baseline
  tier: global
spec:
  rules:
    - name: deny-cloud-metadata
      action: deny
      destinations:
        cidrs:
          - 169.254.0.0/16
          - 100.100.100.200/32
          - 192.0.0.192/32
          - fd00:ec2::254/128
    - name: deny-cluster-internals
      action: deny
      destinations:
        cidrs: [10.96.0.0/12, 10.244.0.0/16]
    - name: deny-quarantined-vendor
      action: deny
      destinations:
        hostnameSuffixes: [vendor-under-investigation.example]
```

### A vendor pinned to their published range

```yaml
    - name: payments-vendor
      action: allow
      destinations:
        hostnames: [api.payments.example]
        resolvedCidrs: [203.0.113.0/24]
      ports: [443]
      protocols: [https]
      tls: { minVersion: "1.3" }
```

## Validating before you publish

```bash
roctl validate -f policy.yaml    # compile one document
roctl preview                    # compile everything staged
roctl simulate --host files.pythonhosted.org --profile untrusted-python
roctl simulate --host 169.254.169.254 --port 80 --protocol http \
               --profile untrusted-python
```

`roctl simulate` exits `0` for allow and `3` for deny, so it works in a script:

```bash
roctl simulate --host "$candidate" --profile untrusted-python >/dev/null \
  || echo "$candidate would be denied"
```
