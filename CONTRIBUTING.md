# Contributing

Thanks for wanting to help. Rokh Oghab is a security boundary, so the bar for
changes is higher than for most projects — not because contributions are
unwelcome, but because a mistake here is a mistake in the thing standing between
untrusted code and someone's network.

**If you have found a way past the gateway, do not open a pull request.** Read
[SECURITY.md](SECURITY.md) first.

---

## Getting set up

You need Docker, Python 3, and GNU make. For the privileged suites you also need
root and `nft`. For the manifest suites, `helm` and `kubectl`.

```bash
git clone https://github.com/dwin-gharibi/rokh-oghab
cd rokh-oghab

make build      # gateway, controller and agent images
make test-unit  # should be 292 passing
make up         # a local stack with test origins and DNS
make smoke      # prove it allows and denies correctly
```

`make help` lists every target.

---

## Before you open a pull request

```bash
make lint
make test-all
sudo make test-privileged
```

`make ci` runs what CI runs. If you cannot run the privileged suites locally,
say so in the pull request — CI runs them, but the reviewer needs to know your
change was not tested against real enforcement on your machine.

---

## What a good change looks like

**It has a test.** Not "the existing tests still pass" — a test that fails
before your change and passes after it. For anything touching a security
boundary, that test belongs in the adversarial or bypass suite.

**It fails closed.** Where a change introduces a choice between denying and
allowing on an error path, it denies. Every ambiguity in this codebase resolves
toward refusing.

**It does not add a comment.** This codebase carries no code comments by
design. Names and structure carry the meaning; if a piece of code needs a
comment to be understood, it needs to be rewritten or moved into a document
under `docs/`.

**It keeps the defaults strict.** If your change touches anything the
shipped-defaults audit checks, expect to justify it. `make audit-defaults`
failing is a signal, not an obstacle.

**It is scoped.** A change that fixes one thing is reviewable. A change that
fixes one thing and refactors three others is not.

---

## Where things live

```
lua/ro/          data plane and shared modules
lua/roc/         control plane modules
openresty/       the control-plane nginx configuration
nginx.conf       the data-plane nginx configuration
config/          shipped configuration and the bootstrap bundle
bin/roctl        the control-plane CLI
bin/ro-agent     the node enforcement agent
scripts/         developer and operator helpers
deploy/          docker, kubernetes, helm, ansible, terraform, opentofu
examples/        policies, sandbox pods, runnable demonstrations
tests/           unit, e2e, adversarial, enforcement, perf, k8s
docs/            architecture, security, deployment, operations
```

The modules where mistakes are most expensive, in order:

1. `lua/ro/ipaddr.lua` — address parsing. Everything downstream trusts it.
2. `lua/ro/target.lua` — hostname and authority classification.
3. `lua/ro/guard.lua` — the blocked-range and metadata defence.
4. `lua/ro/http.lua` — the strict HTTP parser.
5. `lua/ro/policy.lua` — compilation and evaluation.
6. `bin/ro-agent` — the nftables ruleset.

A change to any of these needs tests in the corresponding unit suite *and* a
run of the adversarial suite.

---

## Style

**Lua** — two-space indent, `local` everything, no globals. Modules return a
table named `_M` and declare `_VERSION`. Errors are `nil, "reason"` rather than
raised, except where a raise is caught by a `pcall` you can see.

**Shell** — POSIX `sh` for `bin/ro-agent` (it runs in a minimal container),
`bash` for tests and scripts. `set -uo pipefail` at minimum. Quote every
expansion. Never build a command by interpolating an unquoted variable — the
agent's input handling tests exist because of exactly that class of bug.

**Python** — the standard library only, for `bin/roctl` and the test drivers.
They have to run in a bare CI image without a package manager.

**Reason codes** are stable interfaces. `policy.default_deny` appears in
dashboards, alerts and runbooks. Add new ones freely; do not rename existing
ones without a deprecation.

---

## Commit messages

Say what the change does and why, in a sentence someone reading `git log` in a
year can act on.

```
Reject IPv4 addresses with leading zeros in decimal form

An octal-looking literal such as 0177.0.0.1 was parsed as decimal by the
policy engine and as octal by the kernel, so a rule that denied 127.0.0.1
did not deny this. Both forms now canonicalise identically.
```

Not:

```
fix parsing bug
```

---

## Adding a test

See [docs/testing.md](docs/testing.md) for the harness APIs and worked examples
for each suite.

Two conventions worth repeating:

**Name a security test after the attack**, not the mechanism. In a year the
useful question is "do we still stop this?", not "does this function still
return false?".

**Make the failure path explicit.** In the bypass suite a script that errors for
an unrelated reason counts as blocked, which means a badly written escape
attempt silently passes. Print what actually happened.

---

## Documentation

Documentation lives in `docs/` and is expected to be accurate, not aspirational.
If you change behaviour, change the document that describes it in the same pull
request.

Diagrams are generated, and they are drawn with the brand's icon tiles:

```bash
pip install diagrams KubeDiagrams cairosvg pillow
python3 docs/brand/render.py       # once, to produce the icon tiles
bash docs/diagrams/generate.sh
```

Commit the regenerated PNGs alongside the change. The brand itself —
logo, banners, illustrations — lives in [docs/brand/](docs/brand/README.md).

---

## Review

Every pull request needs a review. Changes to the six modules listed above need
a review from someone who did not write them, and a reviewer will ask:

- What is the new failure mode, and does it fail closed?
- Can arbitrary code influence this input? What is the worst it can send?
- What test would have caught this being wrong?
- Does this make any shipped default more permissive?

These are not gatekeeping questions. They are the questions worth asking about
any change to a boundary, and answering them in the pull request description
saves a round trip.

---

## Reporting a bug that is not a bypass

Open an issue with what you expected, what happened, and how to reproduce it.
Include the reason code if the gateway produced one, and the output of
`roctl status` and `roctl gateway status`.

For anything that lets code reach a destination it should not, see
[SECURITY.md](SECURITY.md) instead.
