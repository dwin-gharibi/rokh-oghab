# Observability

An egress gateway that cannot tell you what it decided is a gateway you cannot
trust. Rokh Oghab exports three things: **metrics** for what is happening now,
an **audit trail** for what happened and to whom, and **logs** for what went
wrong inside the gateway itself.

The design rule throughout is that observability must not become a side channel.
A sandbox can influence hostnames, paths, headers and request rates. None of
those may become an unbounded metric label, none may be echoed back to the
sandbox, and no credential may appear in any of the three.

---

## Metrics

Prometheus exposition at `GET /metrics` on the gateway admin listener (`:9145`)
and on the controller (`:8081`). The endpoint needs no bearer token, but the
gateway still checks the source address against `admin.allowFrom`, so Prometheus
must be inside that list.

```bash
curl -s http://ro-gateway:9145/metrics | head -40
roctl gateway metrics
```

### Gateway metrics

**Traffic and decisions**

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `ro_requests_total` | counter | `profile`, `namespace`, `protocol` | requests evaluated by the policy engine |
| `ro_allowed_total` | counter | `profile`, `namespace`, `protocol` | requests policy permitted |
| `ro_denied_total` | counter | `profile`, `namespace`, `reason` | requests refused, by reason |
| `ro_policy_denials_total` | counter | `profile`, `namespace`, `reason` | refusals attributed to a policy decision |
| `ro_ratelimit_rejected_total` | counter | `profile`, `namespace` | requests refused by a rate, connection or bandwidth limit |
| `ro_protocol_violations_total` | counter | `kind` | requests refused by strict protocol validation |

**Connections and bytes**

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `ro_connections_total` | counter | `mode` | client connections accepted, by `explicit`, `transparent_http`, `transparent_tls` |
| `ro_connections_active` | gauge | `profile`, `namespace` | connections currently open |
| `ro_connection_failures_total` | counter | `profile`, `namespace` | upstream connections that could not be established |
| `ro_bytes_sent_total` | counter | `profile`, `namespace` | bytes forwarded to upstream |
| `ro_bytes_received_total` | counter | `profile`, `namespace` | bytes forwarded to the client |
| `ro_tls_handshakes_total` | counter | `profile`, `namespace` | TLS client hellos inspected |

**DNS**

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `ro_dns_requests_total` | counter | `qtype` | queries handled by the gateway resolver |
| `ro_dns_denials_total` | counter | `reason` | queries refused: `policy`, `qtype`, `name`, `identity`, `class`, `malformed`, `unsupported` |
| `ro_dns_answers_filtered_total` | counter | — | answer records stripped because the address guard refused them |

`ro_dns_answers_filtered_total` deserves attention. A non-zero rate means a name
your policy permits is resolving to an address the guard blocks — either a
misconfiguration, or someone pointing a permitted name at `169.254.169.254`.

**Policy state**

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `ro_policy_version` | gauge | — | the active bundle version |
| `ro_policy_stale` | gauge | — | `1` when the bundle is stale and the gateway is failing closed |
| `ro_policy_reload_total` | counter | — | successful bundle adoptions |
| `ro_policy_reload_failures_total` | counter | `reason` | failed fetches: `fetch`, `status`, `json` |
| `ro_emergency_deny` | gauge | — | `1` when the emergency switch is engaged |
| `ro_limits_unavailable` | gauge | — | `1` when the limit store is missing and configured limits refuse |
| `ro_build_info` | gauge | `version`, `node` | always `1`; carries the build as labels |

**Latency**

| Metric | Type | Meaning |
| --- | --- | --- |
| `ro_request_duration_seconds` | histogram | decision and proxy setup |
| `ro_upstream_duration_seconds` | histogram | time connected to the destination |
| `ro_policy_eval_seconds` | histogram | policy evaluation alone |

`ro_policy_eval_seconds` is bucketed from 100µs to 50ms because policy
evaluation is the part that must not become the bottleneck. It measures the
engine only, so when latency rises this metric tells you whether the cause is
inside the gateway or out on the network.

### Cardinality is bounded on purpose

Every label above comes from a **closed set**: profile and namespace names come
from the policy bundle, protocols and modes are enumerations, and reason labels
are drawn from a fixed catalogue in `lua/ro/reasons.lua`. A hostname is never a
label. A path is never a label. An identity id is never a label. A DNS record
type the gateway does not recognise becomes `other` rather than its numeric
value.

The reason catalogue matters more than it looks. Several internal error strings
carry detail appended after a colon — `upstream.connect_failed: timeout`,
`guard.blocked:cloud-metadata`. Before a label reaches the registry it is
matched against the catalogue: a known reason survives whole, an unknown suffix
collapses onto its known prefix, and anything unrecognised becomes `other`. The
full detail still reaches the audit trail. That means no code path — present or
future — can turn attacker-influenced text into a metric series.

That is not an oversight. A sandbox can invent hostnames as fast as it can
issue requests. If hostnames were labels, arbitrary code could grow the metric
registry without bound and take out Prometheus — a denial of service against the
monitoring system, launched from inside the thing being monitored.

There is a second line of defence. The registry has a hard series cap. Once it
is reached, a new label combination is not created — its value is folded into a
single overflow series instead:

```
ro_denied_total{ro_overflow="true"} 4172
ro_metrics_series_total 8192
```

Nothing is lost and nothing grows without bound: counts still accumulate, they
just stop being broken down. If you ever see a series carrying
`ro_overflow="true"`, a label somewhere is unbounded. Find it and fix it — the
gateway keeps forwarding traffic throughout, because metrics must never be able
to take down the data plane.

`ro_metrics_series_total` is the gauge to graph. Watching it approach the cap
gives you warning before the fold happens.

Hostnames belong in the audit trail, which is bounded by retention rather than
by cardinality. That is the right place for high-dimensional data.

### Controller metrics

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `roc_requests_total` | counter | `method` | control-plane API requests |
| `roc_api_errors_total` | counter | `code` | API responses by HTTP status |
| `roc_publish_total` | counter | `result` | publishes, `ok` or `rejected` |
| `roc_bundle_served_total` | counter | `version` | bundle fetches by gateways |
| `roc_active_version` | gauge | — | the version the controller has activated |

`roc_api_errors_total{code="401"}` and `{code="403"}` are the two to watch.
A sustained rate of either means something is presenting credentials the
controller does not accept — a misconfigured pipeline, or someone trying tokens.

`roc_bundle_served_total` rising steadily is normal: it counts polls, not
changes.

`roc_active_version` against `ro_policy_version` is the propagation check:

```promql
max(roc_active_version) - min(ro_policy_version)
```

Zero means every gateway is current. A number that stays non-zero means a
gateway is not adopting, which is the condition that eventually becomes
`ro_policy_stale`.

### Scraping

```yaml
- job_name: rokh-oghab-gateway
  kubernetes_sd_configs:
    - role: pod
      namespaces: { names: [rokh-oghab] }
  relabel_configs:
    - source_labels: [__meta_kubernetes_pod_label_app]
      action: keep
      regex: ro-gateway
    - source_labels: [__address__]
      action: replace
      regex: '([^:]+)(?::\d+)?'
      replacement: '$1:9145'
      target_label: __address__
```

Scrape **every** gateway pod, not a service endpoint. The metrics that matter
most during an incident — `ro_policy_version`, `ro_policy_stale` — are per-pod,
and load balancing across replicas would hide exactly the disagreement you are
looking for.

Prometheus must be inside `admin.allowFrom` or the scrape gets `403`:

```json
{ "admin": { "allowFrom": ["10.42.0.0/16", "127.0.0.1/32"] } }
```

The source check applies to `/metrics` even though it needs no token, and an
empty list refuses every source rather than admitting every source. The shipped
default is loopback only, so scraping from outside the pod is something you
enable deliberately.

---

## Alerts

These are the alerts worth having. The first two are about the boundary
failing; the rest are about the boundary working and telling you something.

```yaml
groups:
  - name: rokh-oghab
    rules:
      - alert: RokhOghabPolicyStale
        expr: ro_policy_stale > 0
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "A gateway is failing closed on a stale policy bundle"
          description: >
            {{ $labels.instance }} has not refreshed its bundle within
            maxStalenessSeconds and is now denying every request. Check the
            controller and the network path between them.

      - alert: RokhOghabEmergencyDeny
        expr: ro_emergency_deny > 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Emergency deny is engaged — all egress is stopped"

      - alert: RokhOghabPolicyDivergence
        expr: max(roc_active_version) - min(ro_policy_version) > 0
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "A gateway has not adopted the current bundle"

      - alert: RokhOghabReloadFailing
        expr: rate(ro_policy_reload_failures_total[10m]) > 0
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "A gateway cannot fetch its bundle ({{ $labels.reason }})"

      - alert: RokhOghabDenialSpike
        expr: |
          sum by (profile, reason) (rate(ro_denied_total[5m]))
            > 10 * sum by (profile, reason) (rate(ro_denied_total[1h] offset 1h))
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: >
            Denials for {{ $labels.profile }} are far above normal
            ({{ $labels.reason }})

      - alert: RokhOghabGuardHits
        expr: rate(ro_denied_total{reason=~"guard\\..*"}[15m]) > 0
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "A workload is repeatedly reaching for a blocked address range"

      - alert: RokhOghabProtocolViolations
        expr: rate(ro_protocol_violations_total[15m]) > 0.1
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "Sustained malformed requests ({{ $labels.kind }})"

      - alert: RokhOghabDnsAnswersFiltered
        expr: rate(ro_dns_answers_filtered_total[15m]) > 0
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "A permitted name is resolving into a blocked range"

      - alert: RokhOghabLimitsUnavailable
        expr: ro_limits_unavailable > 0
        labels: { severity: critical }
        annotations:
          summary: >
            The limit store is unavailable, so every configured rate and
            connection limit is refusing traffic

      - alert: RokhOghabMetricsOverflow
        expr: count({ro_overflow="true"}) > 0
        labels: { severity: warning }
        annotations:
          summary: "The metric registry hit its series cap — a label is unbounded"
```

Two notes on tuning:

**`RokhOghabPolicyStale` is critical.** It does not mean the gateway is broken;
it means the gateway is denying everything. Workloads are already failing when
this fires.

**`RokhOghabGuardHits` is not noise.** A workload attempting to reach the
metadata endpoint or a link-local address is either badly configured or doing
something it should not. Either way someone should look. `ro_denied_total` with
`reason` starting `guard.` is the SSRF signal.

---

## The audit trail

One JSON object per line, one line per decision.

```json
{
  "ts": 1756039271,
  "component": "ro-gateway",
  "event": "request",
  "action": "deny",
  "reason": "policy.default_deny",
  "request_id": "b41f9c02",
  "node": "gw-node-3",
  "mode": "explicit",
  "client": "10.42.7.19",
  "client_port": 51402,
  "identity": "ro-id-8f2c1d",
  "namespace": "execution",
  "profile": "untrusted-python",
  "service_account": "sandbox-runner",
  "policy_version": 47,
  "host": "evil.example.com",
  "port": 443,
  "protocol": "https"
}
```

### Fields

| Field | Present on | Meaning |
| --- | --- | --- |
| `ts` | every event | Unix seconds |
| `component` | every event | `ro-gateway` or `ro-controller` |
| `event` | every event | `request`, `tunnel_open`, `tunnel_close`, `dns`, `admin` |
| `action` | every event | `allow` or `deny` |
| `reason` | every event | the stable reason code |
| `request_id` | data plane | correlates the events of one connection |
| `node`, `mode` | data plane | which gateway, and which listening mode |
| `client`, `client_port` | data plane | the sandbox's source address |
| `identity`, `namespace`, `profile`, `service_account` | when identified | who asked |
| `policy_version` | data plane | the bundle that made the decision |
| `host`, `port`, `protocol` | request events | the destination |
| `rule`, `policy` | allow events | which rule permitted it, and from which document |
| `bytes_sent`, `bytes_received` | `tunnel_close` | how much moved |
| `severity` | admin events | `high` for anything that changes enforcement |

Every decision carries both an **identity** and a **policy version**. That pair
is what makes the trail usable after the fact: "who did this" and "under what
rules", without having to reconstruct which bundle was active at the time.

### What is never in it

`log.audit` strips `authorization`, `token` and `cookie` from every event before
serialising. Paths are recorded only when `audit.logPaths` is on, and query
strings only when `audit.logQuery` is on — both default to off, because a URL is
one of the most common places for a credential to end up.

Turning them on is a real trade-off, not a formality. A path is often the most
useful field during an investigation and is also where an API key lives. Turn
them on deliberately, for a bounded period, knowing where the logs go.

### Configuration

```json
{
  "audit": {
    "path": "/dev/stdout",
    "level": "info",
    "logPaths": false,
    "logQuery": false,
    "capacity": 4096,
    "bufferMax": 64,
    "flushInterval": 0.2
  }
}
```

| Field | Default | Meaning |
| --- | --- | --- |
| `path` | `/dev/stdout` | where events are written; stdout for a container |
| `level` | `info` | `debug`, `info`, `warn`, `error` |
| `logPaths` | `false` | record request paths |
| `logQuery` | `false` | record query strings |
| `capacity` | `4096` | size of the in-memory ring buffer served by `/v1/audit` |
| `bufferMax` | `64` | events buffered before a flush |
| `flushInterval` | `0.2` | seconds between timed flushes |

Environment overrides exist for the fields you are most likely to set per
deployment: `RO_AUDIT_PATH`, `RO_AUDIT_LEVEL` and `RO_AUDIT_LOG_PATHS`.

Denials are never buffered. A gateway that is killed mid-incident has still
written every refusal it made, because those are the events you need and the
allowed ones are the events you can afford to lose.

### Reading it live

```bash
kubectl -n rokh-oghab logs -f -l app=ro-gateway \
  | jq -c 'select(.action=="deny")
           | {ts, profile, host, port, reason}'
```

```bash
roctl gateway audit --action deny --limit 100
```

`roctl gateway audit` reads the ring buffer, which is bounded, per-worker and
per-pod. It is a debugging convenience. The durable record is `audit.path` and
whatever ships it onward — the ring buffer is not, and is not intended to be, an
audit log.

### Questions it answers

**What is this sandbox failing to reach?**

```bash
kubectl -n rokh-oghab logs -l app=ro-gateway --since=1h \
  | jq -r 'select(.action=="deny" and .profile=="untrusted-python")
           | "\(.host):\(.port) \(.reason)"' \
  | sort | uniq -c | sort -rn
```

**Which identity is generating the denials?**

```bash
kubectl -n rokh-oghab logs -l app=ro-gateway --since=1h \
  | jq -r 'select(.action=="deny") | .identity' \
  | sort | uniq -c | sort -rn | head
```

**Did anything reach for the metadata endpoint?**

```bash
kubectl -n rokh-oghab logs -l app=ro-gateway --since=24h \
  | jq -c 'select(.reason | startswith("guard."))
           | {ts, identity, namespace, host, reason}'
```

**What changed enforcement, and who did it?**

```bash
kubectl -n rokh-oghab logs -l app=ro-controller --since=7d \
  | jq -c 'select(.event=="admin")
           | {ts, actor, action, policy, version, note}'
```

**How much data left through a given profile?**

```bash
kubectl -n rokh-oghab logs -l app=ro-gateway --since=24h \
  | jq -s 'map(select(.event=="tunnel_close" and .profile=="ml-training"))
           | map(.bytes_sent) | add'
```

That last one matters more than it looks. Policy controls *where* a sandbox can
send data; it does not control *how much*. A workload permitted to reach one
storage endpoint can exfiltrate through it. Bandwidth limits bound the rate;
`tunnel_close` events are how you notice the volume.

---

## Tracing

Off by default. Turned on, the gateway emits OpenTelemetry spans over OTLP/HTTP
in JSON to any collector that speaks it.

```json
"telemetry": {
  "enabled": true,
  "endpoint": "http://otel-collector.observability.svc:4318",
  "serviceName": "rokh-oghab-gateway",
  "sampleRatio": 1.0,
  "trustIncomingTrace": false,
  "recordDestination": false,
  "headers": {},
  "maxQueue": 512,
  "maxBatch": 128,
  "timeoutMs": 2000,
  "exportIntervalSeconds": 5
}
```

Every field also has an environment variable — `RO_OTEL_ENABLED`,
`RO_OTEL_ENDPOINT`, `RO_OTEL_SERVICE_NAME`, `RO_OTEL_SAMPLE_RATIO`,
`RO_OTEL_TRUST_INCOMING_TRACE`, `RO_OTEL_RECORD_DESTINATION` — and the Helm
chart exposes them under `telemetry`.

### What a trace contains

One span per request, `rokh-oghab proxy request` or `rokh-oghab proxy connect`,
with children for the work that can be slow or can fail on its own:

| Span | What it covers |
| --- | --- |
| `rokh-oghab proxy request` | the whole request, from parsed head to final byte |
| `rokh-oghab proxy connect` | the same for a `CONNECT` tunnel |
| `dns.resolve` | resolution, including the answer count |
| `upstream.connect` | dialling the pinned addresses, including which family won |

The parent span carries the decision: `ro.decision` is `allow` or `deny`,
`ro.reason` carries the deny reason, `ro.identity`, `ro.namespace` and
`ro.profile` name the workload, and `ro.policy_version` says which bundle
decided. A denied request produces a span with status `ERROR`, so a trace
search for failures finds policy refusals as well as upstream ones.

### Two things a trace deliberately does not do

**It does not take the workload's word for which trace it belongs to.** A
sandbox can send any `traceparent` it likes. Adopting it would let a workload
choose its own trace and span ids: enough to bury its own requests among
someone else's, to make a search return traffic that was never related, or to
push arbitrary ids into an operator's tracing backend. The header is ignored
and a fresh trace is started. `trustIncomingTrace` turns adoption on for
deployments where the caller is trusted — and even then the header is parsed
strictly and a malformed one starts a fresh trace rather than being repaired.

**It does not record destinations by default.** `ro.destination` and `ro.port`
are the one pair of attributes with unbounded values, and a tracing backend is
usually a different trust boundary from the audit sink. `recordDestination`
turns them on when the trace is where you want that detail.

Every other attribute is drawn from the same bounded vocabulary the Prometheus
labels use, and a string attribute is truncated and stripped of control
characters before it is recorded, so a workload cannot inflate an export by
sending a large header.

### Telemetry never slows or blocks a request

Spans are appended to a bounded per-worker queue and shipped by a background
timer. A request never waits for an exporter. If the queue is full the span is
dropped; if the collector is unreachable the batch is lost. Neither one is
allowed to change what the gateway does with traffic — an egress control that
fails when its telemetry fails is worse than one with no telemetry.

Measured with the collector stopped, sixty requests took 419ms against 413ms
with it healthy, and policy decisions were unchanged.

Four counters make the health of the pipeline visible:

| Metric | Meaning |
| --- | --- |
| `ro_otel_spans_queued_total` | spans handed to the exporter |
| `ro_otel_spans_exported_total` | spans the collector accepted |
| `ro_otel_spans_dropped_total` | spans discarded because the queue was full |
| `ro_otel_export_failures_total` | batches the collector did not accept |

A rising `ro_otel_spans_dropped_total` means the queue is too small or the
collector too slow for the request rate. Raise `maxQueue`, lower
`sampleRatio`, or accept the loss — none of it affects enforcement.

### Sampling

`sampleRatio` is applied per trace, derived from the trace id, so the decision
is stable: either a whole trace is recorded or none of it is, and a child span
is never orphaned by a parent that was dropped.

---

## Logs

Operational logs — start-up, configuration validation, controller reachability,
internal errors — go to nginx's error log at `audit.level`. They are for the
health of the gateway process, not for decisions; every decision is in the audit
trail.

Two lines are worth recognising at start-up:

```
ro: cannot open audit sink /var/log/ro/audit.log, falling back to error log
```

The audit path is not writable. Decisions are still recorded, but somewhere you
are probably not collecting. Fix the volume or the permissions.

```
ro: no admin token configured, the admin listener will refuse every request
```

Exactly what it says, and the correct behaviour — but the admin API, metrics and
health probes are all unusable until a token is set.

---

## A dashboard that is worth having

Six panels, in this order:

1. **`ro_policy_version` by pod** — a stat panel per replica. Disagreement here
   explains most "the policy did not apply" reports.
2. **`ro_policy_stale` and `ro_emergency_deny`** — two indicators that should be
   flat zero. Anything else means the network is stopped.
3. **Allow versus deny rate** — `rate(ro_allowed_total[5m])` against
   `rate(ro_denied_total[5m])`, stacked. The shape of normal is worth knowing
   before an incident.
4. **Top denial reasons** —
   `topk(10, sum by (reason) (rate(ro_denied_total[15m])))`. This is the panel
   an operator actually reads. Every reason is documented in
   [troubleshooting](troubleshooting.md).
5. **Latency** — the 50th, 95th and 99th percentiles of
   `ro_request_duration_seconds`, with `ro_policy_eval_seconds` alongside so you
   can tell the gateway apart from the network.
6. **Bytes by profile** — `rate(ro_bytes_sent_total[5m])` by `profile`. This is
   the exfiltration-shaped panel.

Deliberately absent: a top-destinations panel. That would need hostname labels,
and hostname labels are how a sandbox takes down your monitoring. Ask the audit
trail instead.

---

## Retention

| Signal | Where | Suggested retention |
| --- | --- | --- |
| Metrics | Prometheus | 15–30 days |
| Audit — denials | log pipeline | 90 days minimum |
| Audit — admin events | log pipeline | as long as you keep change records |
| Audit — allows | log pipeline | 30 days, or sample |
| Ring buffer | gateway memory | seconds to minutes; not retention |

Denials and admin events are the two categories to keep longest. Denials are the
record of what was attempted; admin events are the record of who changed what
was possible. Between them they answer the question an incident actually asks,
which is not "what happened" but "what could have happened, and who allowed it".
