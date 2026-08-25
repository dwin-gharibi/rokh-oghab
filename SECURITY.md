# Security policy

Rokh Oghab exists to stop untrusted code from reaching the network. A way past
it is the most serious kind of bug this project can have, and it is treated that
way.

---

## Reporting a bypass

**Do not open a public issue.**

Report privately through GitHub's private vulnerability reporting on this
repository (Security → Report a vulnerability), or by email to
`security@rokh-oghab.io`.

What to include, in rough order of usefulness:

1. **A reproduction.** Ideally a test in the shape of
   `tests/e2e/security_driver.py` or `tests/enforcement/bypass.sh`. If not, the
   exact requests, the configuration and the policy bundle.
2. **Which layer failed.** Protocol parsing, address canonicalisation, the
   address guard, policy evaluation, identity, DNS, TLS or node enforcement.
3. **The configuration.** A bypass that needs `guard.includeDefaults: false` is
   a different severity from one that works against the shipped defaults.
4. **What it reaches.** Arbitrary internet, one specific internal host, the
   metadata endpoint, or another sandbox.

You do not need a fix. A clear reproduction is worth more than a patch.

### What to expect

| | |
| --- | --- |
| Acknowledgement | within 3 working days |
| Initial assessment | within 7 days |
| Fix for a critical bypass | as fast as we can, with a regression test |
| Public disclosure | after a fix is available, coordinated with you |

You will be credited unless you would rather not be.

---

## What counts as a vulnerability

**Yes — report these:**

- A sandbox reaches a destination policy does not permit.
- A sandbox reaches the network without going through the gateway, given the
  documented node and cluster enforcement.
- A destination is authorised as something other than what it actually is —
  address canonicalisation, DNS rebinding, SNI confusion, a redirect.
- A request is attributed to the wrong identity, or to none.
- A workload reads another workload's policy, identity or audit data.
- The gateway can be made to **allow** by crashing, exhausting or confusing it.
- The control plane accepts a change from a credential whose role should not
  permit it.
- A credential leaks — into logs, metrics, error bodies or the API.
- Node enforcement can be removed, disabled or evaded from inside a sandbox.

**No — these are not vulnerabilities:**

- **A sandbox cannot reach the network when the gateway is down.** That is the
  designed behaviour. Fail-closed means closed.
- **A policy that permits something you did not intend.** Check with
  `roctl simulate`. A rule doing what it says is not a bug.
- **Denial of service against the gateway itself** that results in *denial*.
  Making the gateway refuse everything is not an escalation. Making it *allow*
  something is.
- **A bypass that requires privileges the threat model excludes** — root on the
  node, `CAP_NET_ADMIN`, control of the CNI, or the ability to modify the
  gateway's own configuration. See [the threat model](docs/threat-model.md).
- **A finding against a deliberately weakened configuration** —
  `guard.includeDefaults: false`, `identities.allowAnonymous: true`, a policy
  that permits `0.0.0.0/0`. Say so if you are unsure; a configuration that is
  easy to weaken *by accident* is itself worth reporting.
- **Missing hardening with no exploit path.** Useful, welcome as a normal issue,
  not a vulnerability report.

If you are unsure which side of the line something falls on, report it
privately. Over-reporting costs a few minutes; under-reporting costs more.

---

## Severity

| Severity | Meaning |
| --- | --- |
| **Critical** | A sandbox reaches arbitrary destinations, or the cloud metadata endpoint, against the shipped defaults |
| **High** | A sandbox reaches a specific unauthorised destination, or is attributed to the wrong identity |
| **Medium** | A bypass that needs a non-default configuration, or an information leak with no direct escalation |
| **Low** | Hardening gaps, defence-in-depth improvements |

---

## Our commitments

**Every fix ships with a regression test.** A bypass that is fixed but not
tested will come back. Every known bypass in this repository's history is a test
in `tests/e2e/security_driver.py` or `tests/enforcement/bypass.sh`, and that is
not going to change.

**Fail closed.** Where the design permits a choice between denying and allowing,
it denies. If a fix requires making something less available, it will be made
less available.

**No silent weakening.** `make audit-defaults` is a test suite whose only job is
to fail when something shipped becomes more permissive. A change that relaxes a
default has to change that suite too, in a visible commit.

---

## What you can verify yourself

You do not have to take any of this on trust:

```bash
make audit-defaults          # nothing shipped weakens the boundary
make test-security           # 61 adversarial tests
sudo make test-bypass        # 17 escape attempts with NET_RAW
sudo make test-sandbox-demo  # untrusted Python, end to end
```

Run these against **your** configuration, not just the defaults. A policy or
guard exception that is safe in isolation may not be in combination.

---

## Known limitations

Stated plainly, because a security policy that only lists strengths is not one:

- **This has not had an independent security review.** It is defence in depth
  with an explicit invariant and an adversarial suite. That is not the same as
  an audit.
- **TLS inspection sees only what the ClientHello reveals** unless you enable
  inspection mode with a private CA. Encrypted Client Hello, when it is
  widespread, will erode SNI-based decisions.
- **Policy controls destinations, not volume.** A workload permitted to reach a
  storage endpoint can exfiltrate through it. Bandwidth limits bound the rate;
  they do not bound the total.
- **Identity by source address is only as good as the layer assigning
  addresses.** Sound with a CNI and node enforcement; unsound on a flat network.
- **The node agent depends on the host kernel's netfilter.** A kernel bug there
  is outside what this project can defend against.
- **A sandbox with `CAP_NET_ADMIN` or host network access is out of scope.** The
  manifests refuse both; a deployment that grants them has removed a layer the
  model depends on.

Before treating Rokh Oghab as a hard isolation boundary for genuinely hostile
code, get an independent security review, and keep running the adversarial suite
against every change you make.

---

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | yes |
| < 1.0 | no |

Security fixes land on the latest minor release. Run a supported version.
