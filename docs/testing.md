# Testing

The security claims in this repository are tests, not prose. This document
covers how to run them, what each one proves, and how to add to them.

The rule the project follows: **every bypass found becomes a permanent
regression test.** The adversarial and bypass suites are not a checklist someone
wrote from a threat model — they are the accumulated record of things that once
worked and now must never work again.

---

## Running everything

```bash
make test-all          # everything that does not need root
sudo make test-privileged   # the suites that program nftables
```

`make test-all` runs the linters, the shipped-defaults audit, and the unit,
agent, manifest, gateway, adversarial and control-plane suites. It needs Docker
and takes a few minutes.

`make test-privileged` runs the three suites that build real networks and
program real firewall rules. They need root and `nft` on the host, and they
create and destroy Docker networks, so run them somewhere you do not mind that
happening.

| Suite | Command | Tests | Needs |
| --- | --- | --- | --- |
| Lint | `make lint` | — | Docker, Python |
| Ratchet | `make ratchet` | 8 | nothing |
| Unit | `make test-unit` | 339 | Docker |
| Gateway | `make test-e2e` | 62 | Docker |
| Adversarial | `make test-security` | 73 | Docker |
| Control plane | `make test-control` | 21 | Docker |
| Node agent | `make test-agent` | 40 | Docker |
| Manifests | `make test-manifests` | 32 | helm, kubectl |
| Examples | `make test-examples` | 24 | Docker |
| Defaults | `make audit-defaults` | 50 | Python, helm |
| Enforcement | `sudo make test-enforcement` | 11 | root, nft, Docker |
| Bypass | `sudo make test-bypass` | 17 | root, nft, Docker |
| Sandbox demo | `sudo make test-sandbox-demo` | 13 | root, nft, Docker |
| Fuzz | `make fuzz` | — | Docker |
| Kubernetes | `make test-k8s` | — | a cluster |
| Benchmark | `make bench` | — | Docker |

---

## The suites

### Lint — `make lint`

Five checks, and the first one exists because of a real incident:

| Target | What it does |
| --- | --- |
| `lint-lua` | byte-compiles every Lua module |
| `lint-nginx` | validates the nginx configuration inside the image |
| `lint-shell` | syntax-checks every shell script |
| `lint-yaml` | parses every YAML document |
| `lint-python` | compiles every Python file |

`lint-lua` was added after a syntax error in a rarely-taken branch crashed the
gateway at start-up. Lua does not compile a function body until it is called, so
a typo can sit in an error path indefinitely. Byte-compiling every module is the
cheap check that catches it.

### Unit — `make test-unit`

292 tests over the security-critical logic, run inside the OpenResty image so
they exercise the same Lua and the same libraries as production.

| File | Covers |
| --- | --- |
| `test_ipaddr.lua` | address parsing, every `inet_aton` form, IPv6, embedded IPv4, masking, CIDR |
| `test_target.lua` | hostname normalisation, authority parsing, obfuscation detection |
| `test_guard.lua` | blocked ranges, metadata endpoints, exceptions, tunnel unwrapping |
| `test_policy.lua` | compilation, strict schema, tier merging, deny-overrides, limits |
| `test_http.lua` | request and response parsing, framing, path normalisation, chunking |
| `test_httpd.lua` | the admin HTTP server |
| `test_dns.lua` | message encoding and decoding, compression pointers, answer filtering |
| `test_tls.lua` | ClientHello parsing, SNI extraction, version negotiation |
| `test_identity.lua` | token and source-address resolution |
| `test_limits.lua` | rate, connection and bandwidth limiting |
| `test_metrics.lua` | counters, gauges, histograms, label encoding, the series cap |
| `test_config.lua` | configuration loading, defaults, environment overrides |
| `test_reader.lua` | the bounded buffered reader |
| `test_store.lua` | the control-plane store, versioning, publish, rollback |
| `test_yaml.lua` | the YAML subset parser |

Run one file:

```bash
docker run --rm -v "$PWD:/src" -w /src \
  openresty/openresty:1.27.1.2-0-alpine-fat \
  /usr/local/openresty/bin/resty -I lua tests/unit/test_ipaddr.lua
```

`test_ipaddr.lua` is the one to read first. It is the largest, and it is where
the difference between "parses an IP address" and "parses every string that a
kernel will treat as an IP address" lives: `2852039166`, `0xa9fea9fe`,
`0251.0376.0251.0376`, `169.254.43518`, `[::ffff:169.254.169.254]` — all of
which reach `169.254.169.254`.

### Gateway — `make test-e2e`

62 tests against a live gateway in a Docker network with real origins, a real
DNS server and a real controller. Nothing is mocked.

Covers the happy paths and their edges: HTTP proxying, CONNECT tunnels, TLS
inspection, keep-alive, chunked encoding, custom L7 ports and schemes, DNS
resolution, identity resolution, limits, metrics and the admin API.

```bash
make e2e-up
cd tests/e2e && python3 driver.py
cd tests/e2e && python3 driver.py --filter connect
make e2e-down
```

`make e2e-up` leaves the stack running, so you can iterate on the driver without
paying the start-up cost each time.

### Adversarial — `make test-security`

61 attacks against a running gateway. This is the suite that matters.

| Group | Attempts |
| --- | --- |
| Request smuggling | `CL.TE`, `TE.CL`, duplicate `Content-Length`, non-chunked `Transfer-Encoding`, bare CR, bare LF, obs-fold, invalid tokens |
| SSRF | metadata endpoints in every encoding, decimal, octal, hex and short-form IPv4, IPv6 tunnel encodings, DNS pointing at blocked ranges |
| Tunnel abuse | SNI that disagrees with the CONNECT authority, non-TLS payloads in a tunnel, downgrade attempts |
| Path traversal | `..`, `%2e%2e`, `%2f`, `%5c`, encoded nulls, over-long paths |
| Host confusion | `Host` disagreeing with the target, missing `Host`, multiple `Host`, IPv6 literal handling |
| Identity | forged tokens, revoked tokens, malformed credentials, anonymous access |
| Resource exhaustion | slowloris, over-long heads, unbounded pipelining, connection floods |
| Information disclosure | error bodies, timing, the admin API from the proxy port, metric label injection |
| Redirect abuse | a permitted destination redirecting to a denied one |

```bash
make e2e-up
cd tests/e2e && python3 security_driver.py
```

A failure here is a security finding, not a broken test. Treat it accordingly.

### Control plane — `make test-control`

21 tests over the controller and `roctl`: role enforcement across all four
roles, staging and publishing, atomic activation, rollback, emergency deny,
live propagation to a running gateway, and behaviour when the controller
disappears.

The last one is the interesting one: it stops the controller and confirms the
gateway keeps enforcing its last bundle, then that it begins denying once that
bundle goes stale.

### Node agent — `make test-agent`

32 tests over the generated nftables ruleset and the agent's input handling.

Ruleset structure: that the default policy is drop, that only the gateway is
reachable, that DNS is redirected, that anti-spoofing rules are present, that
IPv6 is handled.

Input handling: that malformed CIDRs are rejected, that shell metacharacters in
environment variables cannot inject commands, that empty sets do not produce
invalid nftables syntax, that unterminated final lines are read correctly.

That last group exists because each one was a real bug. The agent takes input
from environment variables and turns it into a firewall ruleset — an injection
there is a full bypass.

### Manifests — `make test-manifests`

32 checks over the rendered Kubernetes output: the kustomize base and fourteen
Helm value permutations, validated with `kubeconform` where available.

Checks that every permutation produces valid manifests, that no permutation
drops a NetworkPolicy, that security contexts survive, and that the namespaces
are labelled for Pod Security `restricted`.

### Defaults — `make audit-defaults`

35 checks that nothing shipped in the repository weakens the boundary.

Verifies that anonymous identity is refused, the address guard keeps its
built-in ranges, obfuscated literals are refused, strict parsing is on, the TLS
floor is 1.2, the gateway fails closed without a controller, no admin token is
baked into an image, DNS serves only address records, the shipped bundle
contains **zero** allow rules and **zero** identities, no principal ships with
the controller, and no private key is committed anywhere.

It also renders the Helm chart and checks the same properties survive default
values.

This is the suite that catches a well-meant "make it work out of the box"
change, which is the most likely way for a hardened system to become an
unhardened one.

### Enforcement — `sudo make test-enforcement`

11 checks that the node agent really confines a sandbox. Builds an isolated
Docker network, programs nftables, and verifies the ruleset does what the agent
says it does.

### Bypass — `sudo make test-bypass`

17 escape attempts from a sandbox **deliberately granted `NET_RAW`**, which is
more privilege than a real sandbox should ever have.

| Attempt | Expected |
| --- | --- |
| direct TCP to the origin | blocked |
| direct TCP to a public address | blocked |
| direct TCP to a neighbouring sandbox | blocked |
| direct TCP to the gateway admin port | blocked |
| UDP to a public address | blocked |
| ICMP echo to a public address | blocked |
| IPv6 to a public address | blocked |
| ignoring the proxy environment entirely | blocked |
| DNS to an external resolver | captured by the gateway |
| a forged source address | never arrives |
| reverse path filtering | active |
| removing the ruleset | egress opens, proving it was enforcing |
| reapplying the ruleset | egress closes again |
| a direct connection once the gateway is stopped | blocked |
| a public connection once the gateway is stopped | blocked |

Two of these are worth calling out.

**Removing the ruleset must open egress.** A test that only checks "traffic is
blocked" passes just as well when the network is broken for an unrelated reason.
Deleting the table and confirming traffic then flows proves the ruleset is what
was doing the blocking.

**Stopping the gateway must not open the network.** This is the fail-closed
property stated as a test. A sandbox whose only route out is the gateway has no
route out when the gateway is gone.

```bash
sudo make test-bypass
```

If you have extended or reconfigured the gateway, run this against your
configuration rather than trusting that it passed in CI against the defaults.

### Sandbox demo — `sudo make test-sandbox-demo`

13 checks running genuinely untrusted Python end to end: builds the network,
programs enforcement, redirects DNS, runs `examples/python-sandbox/sandbox_demo.py`
inside the sandbox, and finishes by stopping the gateway to show what is left.

This is the suite to run when someone asks what the boundary actually does. It
is legible in a way the others are not, because the output is a workload's own
report of what it could and could not reach.

### Kubernetes — `make test-k8s`

Deploys the chart into whatever cluster `kubectl` is pointed at, places the
example sandbox pod behind the gateway, and tries to escape from it: direct
connections to public addresses, to the metadata endpoint, to the API server, to
the gateway's own admin port, and DNS to an external resolver. It also checks
that no service account token is mounted, that the pods are hardened, and that
denials reach the audit trail.

```bash
kind create cluster --config tests/k8s/kind-config.yaml
make build
kind load docker-image rokh-oghab/gateway:dev rokh-oghab/controller:dev \
     rokh-oghab/agent:dev --name rokh-oghab
make test-k8s
```

Check your context first — it installs into the current one:

```bash
kubectl config current-context
```

`RO_K8S_KEEP=1` leaves the release in place for inspection.

### Ratchet — `make ratchet`

Not a test of the gateway. A test of the tests.

It counts the test declarations in each suite against a committed baseline in
`tests/coverage-baseline.txt` and fails when any count drops. The way an
adversarial suite decays is not that someone argues for removing a test; it is
that a test starts failing and quietly disappears in a commit about something
else, and no reviewer notices a file got shorter.

```bash
make ratchet          # check
make ratchet-update   # record the new floor after adding tests
```

Run `ratchet-update` in the same commit as the new tests. Removing a test then
requires deliberately lowering a number someone will ask about.

### Fuzz — `make fuzz`

Throws structurally hostile input at the request parser, the CONNECT tunnel, the
TLS ClientHello peek, the DNS server and the response path, and reports anything
that is not a clean refusal: a hang, a `500`, internal Lua error text in a
response, an echoed credential, a DNS reply far larger than its query, or a
gateway that stops serving.

The response pass attacks the half a request fuzzer cannot reach. A permitted
destination is not trusted either, so the raw test origin has a route that
replays whatever bytes the fuzzer hands it and the gateway has to carry the
result. What it checks is narrow on purpose: a second response inside the body
of a first is not a finding, because a response with no framing headers runs to
the close and those bytes are its content. The defect is a second response
reaching the client as a *head* — the gateway framing something the destination
did not send as the answer — along with an interim response handed over as the
final one, a `1xx` or `101` that should have been refused and was not, a head
carrying two status lines, and a stall.

```bash
make fuzz
make fuzz FUZZ_ROUNDS=1000 FUZZ_SEED=7
python3 tests/fuzz/fuzz.py --rounds 500 --seed 42
```

It is seeded, so a finding is reproducible: the seed is printed in the summary
and rerunning with it replays the same inputs.

The threshold for calling something a hang is deliberately above
`limits.headTimeoutMs`. An unfinished request head is not malformed, it is
incomplete, and the gateway is right to wait — briefly. A report means the
gateway never gave up at all.

The denial-of-service fixed in the per-source connection cap was found this way,
by chasing what the fuzzer called a hang. The response pass was written after a
smuggling bug in the interim-response handling was found by hand, and it finds
the same bug on its own: reverting the fix makes it report within a hundred
rounds.

### Chaos — `make chaos`

Attacks the gateway from several threads while a separate thread breaks things
around it. Twenty-one probe shapes, none of which the active policy permits:
denied hosts, cloud metadata in six spellings, private ranges, missing and
forged credentials, self-asserted identity headers, host header mismatches,
undeclared ports, `CONNECT` to the admin and controller ports, names that
resolve inward, request smuggling, interim-response smuggling, redirects to
metadata, and unauthenticated calls to the admin API.

While those run, the chaos thread picks from eleven scenarios: restarting the
gateway, killing it and starting it again, stopping the controller, the DNS
server, the trace collector or an origin, toggling emergency deny, flushing the
DNS cache, republishing the bundle, flooding with half-open connections, and
holding connections with partial heads.

```bash
make chaos
make chaos CHAOS_ROUNDS=40 CHAOS_WORKERS=12 CHAOS_SEED=7
python3 tests/chaos/run.py --rounds 30 --workers 8
```

**The property is not that the gateway keeps serving.** Under chaos it is
entitled to refuse everything, and it often does. The property is that it never
serves something policy did not authorise: a refusal passes, a timeout passes,
and a success is the only failure. That distinction is what makes the run
meaningful, because a gateway that is simply down would otherwise look perfect.

Before it trusts a clean run, the campaign checks that its own probes can see a
success — it fetches a destination the policy does permit and aborts if that
does not register. A run that reports no breaches while the probe machinery is
broken would be worse than no run at all.

Measured across four seeds, 183,000 probes through 105 chaos rounds produced no
breach, and the gateway decided correctly again once everything was restored.

### Benchmark — `make bench`

Not a pass/fail suite. Measures latency for allowed and denied requests,
sustained throughput under concurrency, bulk transfer rate, and what the gateway
measured about itself — including what share of a request is policy evaluation.

```bash
make e2e-up
python3 tests/perf/bench.py --iterations 500 --workers 32
python3 tests/perf/bench.py --json > before.json
```

Run it before and after a change and compare. The number that matters is the
policy evaluation share: if it climbs above about a fifth of a request, look at
rule counts and destination set sizes.

---

## Writing tests

### A unit test

Tests use the harness in `tests/lib/harness.lua`, which gives you `describe`,
`it` and a set of assertions:

```lua
local h = require("harness")
local guard = require("ro.guard")
local target = require("ro.target")

h.describe("guard refuses obfuscated address literals", function()
    local g = assert(guard.new())

    h.it("refuses the metadata endpoint written as a decimal integer", function()
        local info = assert(target.classify_host("2852039166"))
        local ok, reason = g:check(info)
        h.assert_false(ok, "2852039166 must be blocked")
        h.assert_match(reason, "obfuscated")
    end)
end)
```

| Assertion | Checks |
| --- | --- |
| `assert_true` / `assert_false` | truthiness |
| `assert_nil` | absence |
| `assert_eq` / `assert_ne` | equality |
| `assert_deep_eq` | structural equality of tables |
| `assert_match` | a Lua pattern matches |
| `assert_error` | the function raises |
| `skip` | record a test as skipped, with a reason |

Every assertion takes an optional message as its last argument. Use it — a
failure that says `2852039166 must be blocked` is worth more than one that says
`expected false, got true`.

Register the new file in `tests/unit/run_all.lua`.

### An adversarial test

Add it to `tests/e2e/security_driver.py`. Tests are registered with a decorator
that takes a category and a description, and receive an assertion object:

```python
@test("ssrf", "the metadata endpoint written as a short-form address is refused")
def t_metadata_shortform(a):
    res = proxy_req("http://169.254.43518/latest/meta-data/")
    a.eq(res["status"], 403)
    a.contains(res["reason"], "guard.blocked")
```

The category groups related attacks in the output, which matters when you are
reading 61 results and want to know whether the smuggling group as a whole still
holds.

Name the test after the attack, not the mechanism. A year from now the useful
question is "do we still stop this?", not "does this function still return
false?".

### An escape attempt

Add it to `tests/enforcement/bypass.sh`:

```bash
escape_blocked "a connection over an unusual protocol number" "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 47)
    s.settimeout(3)
    s.sendto(b'x' * 16, ('1.1.1.1', 0))
    print('ESCAPED')
except OSError as e:
    print('blocked:', e)
"
```

The convention is that the script prints `ESCAPED` if it got out. Anything else
counts as blocked, which means a script that errors for an unrelated reason
reports a pass — so make the failure path explicit and print what happened.

---

## Continuous integration

| Workflow | Runs |
| --- | --- |
| `ci.yml` | lint, unit, agent, manifests, defaults audit |
| `e2e.yml` | the gateway, adversarial and control-plane suites |
| `enforcement.yml` | enforcement and bypass, on a privileged runner |
| `iac.yml` | Terraform, OpenTofu, Helm and kustomize validation |
| `security.yml` | dependency and image scanning |
| `release.yml` | multi-architecture image builds |

`make ci` runs locally what `ci.yml` runs remotely.

The enforcement workflow needs a runner that can program nftables. If yours
cannot, run those suites manually before every release — they are the ones that
test the property the whole project exists to provide.

---

## When a test fails

**Lint** — a syntax error. The message names the file and line.

**Unit** — logic. The harness prints the expected and actual values.

**Gateway** — check the stack is up (`make e2e-up`) and read the gateway logs
(`make e2e-logs`). A driver failure and a gateway failure look similar from the
outside; the audit trail distinguishes them.

**Adversarial** — a security finding. Do not adjust the test to pass. Work out
what the gateway did, why, and whether the attack actually succeeded. If it did,
see [SECURITY.md](../SECURITY.md).

**Agent** — run `bin/ro-agent print` with the same inputs and read the ruleset.

**Manifests** — run `make helm-template` or `make kustomize-build` and look at
the output.

**Defaults** — something shipped got more permissive. That is the point of the
suite; check whether the change was intended.

**Enforcement or bypass** — the boundary did not hold. Everything else is less
important than this.

**Kubernetes** — check the cluster, the images are loaded, and the CNI enforces
NetworkPolicy. Not every CNI does, and one that does not will fail these tests
for a reason that is about the cluster rather than about Rokh Oghab.
