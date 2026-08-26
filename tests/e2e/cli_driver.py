import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

import driver
from driver import Assert

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROCTL = os.path.join(ROOT, "bin", "roctl")
NO_CONFIG = os.path.join(
    tempfile.gettempdir(), "roctl-cli-suite-absent-config.json")

CONTROLLER = "http://%s:%s" % (
    os.environ.get("RO_CONTROLLER_HOST", "127.0.0.1"),
    os.environ.get("RO_CONTROLLER_PORT", "18081"))
GATEWAY = "http://127.0.0.1:%s" % os.environ.get("RO_MANAGED_ADMIN_PORT", "19146")

ADMIN = "ctl-admin-token-0000000000001"
OPERATOR = "ctl-operator-token-00000000001"
READER = "ctl-reader-token-000000000001"
GATEWAY_TOKEN = "ro-e2e-admin-token-000000000001"

TESTS = []


def test(category, name):
    def deco(fn):
        TESTS.append((category, name, fn))
        return fn
    return deco


def roctl(*argv, **kwargs):
    env = dict(os.environ)
    env.pop("ROCTL_ENDPOINT", None)
    env.pop("ROCTL_TOKEN", None)
    env.pop("ROCTL_GATEWAY", None)
    env.pop("ROCTL_GATEWAY_TOKEN", None)
    env["ROCTL_CONFIG"] = kwargs.get("config", NO_CONFIG)
    env.update(kwargs.get("env", {}))
    cmd = [sys.executable, ROCTL]
    if kwargs.get("endpoint", True):
        cmd += ["--endpoint", CONTROLLER]
    token = kwargs.get("token", ADMIN)
    if token:
        cmd += ["--token", token]
    cmd += list(argv)
    proc = subprocess.run(cmd, capture_output=True, timeout=kwargs.get("timeout", 30),
                          env=env, cwd=ROOT)
    return {
        "rc": proc.returncode,
        "out": proc.stdout.decode("utf-8", "replace"),
        "err": proc.stderr.decode("utf-8", "replace"),
    }


def roctl_json(a, *argv, **kwargs):
    res = roctl(*argv, **kwargs)
    a.eq(res["rc"], 0, "roctl %s failed: %s" % (" ".join(argv), res["err"]))
    try:
        return json.loads(res["out"])
    except ValueError:
        raise AssertionError("roctl %s did not print json: %r"
                             % (" ".join(argv), res["out"][:400]))


def write_temp(text, suffix=".yaml"):
    fh = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    fh.write(text)
    fh.close()
    return fh.name


@test("cli", "the output flag is accepted before and after the subcommand")
def t_output_flag_placement(a):
    commands = [
        ["status"],
        ["policy", "list"],
        ["profile", "list"],
        ["identity", "list"],
        ["settings", "get"],
        ["versions"],
    ]
    for cmd in commands:
        after = roctl(*(cmd + ["-o", "json"]))
        a.eq(after["rc"], 0,
             "roctl %s -o json must work; every example in docs/cli.md "
             "writes it this way: %s" % (" ".join(cmd), after["err"].strip()))
        json.loads(after["out"])

        before = roctl("-o", "json", *cmd)
        a.eq(before["rc"], 0, "roctl -o json %s must work too" % " ".join(cmd))
        a.eq(json.loads(before["out"]), json.loads(after["out"]),
             "the flag must mean the same thing in both places")

        table = roctl(*cmd)
        a.eq(table["rc"], 0)
        a.true(not table["out"].lstrip().startswith("{"),
               "the default output is a table, not json")


@test("cli", "an explicit flag after the subcommand wins over one before it")
def t_flag_precedence(a):
    res = roctl("-o", "table", "status", "-o", "json")
    a.eq(res["rc"], 0)
    json.loads(res["out"])

    res = roctl("--timeout", "30", "status", "--timeout", "20", "-o", "json")
    a.eq(res["rc"], 0)


@test("cli", "a nested name never wins over the document's own name")
def t_document_name_nesting(a):
    cases = [
        ("labels before the real name", """
apiVersion: rokhoghab.io/v1
kind: EgressPolicy
metadata:
  labels:
    name: wrong-nested-name
  name: cli-nesting-a
spec:
  selector:
    namespaces: [execution]
  rules:
    - name: allow-one
      action: allow
      destinations:
        hostnames: [allowed.test]
      ports: ["80"]
      protocols: [http]
""", "cli-nesting-a"),
        ("annotations before the real name", """
apiVersion: rokhoghab.io/v1
kind: EgressPolicy
metadata:
  annotations:
    name: wrong-nested-name
  name: cli-nesting-b
spec:
  selector:
    namespaces: [execution]
  rules:
    - name: allow-one
      action: allow
      destinations:
        hostnames: [allowed.test]
      ports: ["80"]
      protocols: [http]
""", "cli-nesting-b"),
    ]
    created = ["cli-nesting-a", "cli-nesting-b", "wrong-nested-name"]
    try:
        for label, doc, want in cases:
            path = write_temp(doc)
            try:
                res = roctl("policy", "apply", "-f", path, token=OPERATOR)
                a.eq(res["rc"], 0, "%s: %s" % (label, res["err"].strip()))
                a.contains(res["out"] + res["err"], want,
                           "%s: roctl reported the wrong name" % label)
            finally:
                os.unlink(path)

            listing = roctl_json(a, "policy", "list", "-o", "json",
                                 token=READER)
            names = [p.get("name") for p in listing.get("policies", [])]
            a.true(want in names,
                   "%s: the policy must be stored under its metadata.name, "
                   "not a name lifted from a nested block; stored: %s"
                   % (label, names))
            a.true("wrong-nested-name" not in names,
                   "%s: a nested name must never become the resource name; "
                   "an operator who thinks they updated one policy would "
                   "have created another and left the first in force"
                   % label)
    finally:
        for name in created:
            roctl("policy", "delete", name, token=OPERATOR)


@test("cli", "a resource name is encoded before it reaches the wire")
def t_name_encoding(a):
    hostile = [
        "../../../etc/passwd",
        "a/b",
        "a b",
        "a?b=c",
        "a#b",
        "a%2fb",
    ]
    for name in hostile:
        res = roctl("policy", "get", name, token=READER)
        a.ne(res["rc"], 0,
             "%r must not resolve to a policy" % name)
        a.true("Traceback" not in res["err"],
               "%r crashed roctl instead of being refused: %s"
               % (name, res["err"][:300]))
        a.true("/etc/passwd" not in res["out"],
               "%r must never read a file" % name)

    before = roctl_json(a, "policy", "list", "-o", "json", token=READER)
    for name in hostile:
        roctl("policy", "delete", name, token=OPERATOR)
    after = roctl_json(a, "policy", "list", "-o", "json", token=READER)
    a.eq(json.dumps(after, sort_keys=True), json.dumps(before, sort_keys=True),
         "a hostile name must not delete anything")


@test("cli", "the controller token is never sent to a gateway")
def t_gateway_token_isolation(a):
    for sub in (["status"], ["metrics"], ["audit"]):
        res = roctl("gateway", *sub, env={"ROCTL_GATEWAY": GATEWAY})
        a.ne(res["rc"], 0,
             "roctl gateway %s must refuse to run without a gateway token; "
             "falling back to the controller token sends a more privileged "
             "credential to a different service" % " ".join(sub))
        a.contains(res["err"], "gateway admin token",
                   "the error must say what is missing")
        a.not_contains(res["err"], ADMIN,
                       "the error must not echo the controller token")

    for sub in (["status"], ["metrics"]):
        res = roctl("gateway", *sub,
                    env={"ROCTL_GATEWAY": GATEWAY,
                         "ROCTL_GATEWAY_TOKEN": GATEWAY_TOKEN})
        a.eq(res["rc"], 0,
             "roctl gateway %s must work with the gateway's own token: %s"
             % (" ".join(sub), res["err"].strip()))


@test("cli", "a hostile flag value is refused, not turned into a traceback")
def t_hostile_flag_values(a):
    for timeout in ("-5", "0", "nan", "-inf", "1e400"):
        res = roctl("status", "--timeout", timeout)
        a.ne(res["rc"], 0, "--timeout %s must be refused" % timeout)
        a.not_contains(res["err"], "Traceback",
                       "--timeout %s crashed roctl: %s"
                       % (timeout, res["err"][:300]))

    res = roctl("status", "--timeout", "5")
    a.eq(res["rc"], 0, "a sane timeout still works: %s" % res["err"].strip())


@test("cli", "roctl only speaks to a control plane")
def t_endpoint_scheme(a):
    for endpoint in ("file:///etc/passwd", "ftp://example.test/",
                     "javascript:alert(1)", "//evil.test", "http://",
                     "gopher://example.test/"):
        res = roctl("status", "--endpoint", endpoint, endpoint=False)
        a.ne(res["rc"], 0, "%r must be refused" % endpoint)
        a.not_contains(res["err"], "Traceback",
                       "%r crashed roctl: %s" % (endpoint, res["err"][:300]))
        a.not_contains(res["out"], "root:",
                       "%r read a local file" % endpoint)

    res = roctl("gateway", "status", endpoint=False,
                env={"ROCTL_GATEWAY": "file:///etc/shadow",
                     "ROCTL_GATEWAY_TOKEN": "x"})
    a.ne(res["rc"], 0, "the gateway address is held to the same rule")
    a.not_contains(res["out"], ":",
                   "a gateway address must never read a local file")


@test("cli", "roles are carried through to the controller")
def t_roles(a):
    res = roctl("policy", "delete", "managed-python", token=READER)
    a.ne(res["rc"], 0, "a reader cannot delete a policy")
    a.contains(res["err"].lower(), "403")

    res = roctl("status", token=READER)
    a.eq(res["rc"], 0, "a reader can read status")

    res = roctl("status", token="not-a-real-token")
    a.ne(res["rc"], 0, "an invalid token is refused")
    a.contains(res["err"], "401")


@test("cli", "simulate reports a deny with a distinct exit code")
def t_simulate_exit_code(a):
    res = roctl("simulate", "--namespace", "execution",
                "--profile", "managed-python",
                "--host", "denied.test", "--port", "443",
                "--protocol", "https", token=READER)
    a.eq(res["rc"], 3, "a simulated deny exits 3, not 0 and not 1")
    a.contains(res["out"], "DENY")

    res = roctl("simulate", "--namespace", "execution",
                "--profile", "managed-python",
                "--host", "allowed.test", "--port", "80",
                "--protocol", "http", token=READER)
    a.eq(res["rc"], 0, "a simulated allow exits 0")
    a.contains(res["out"], "ALLOW")


@test("cli", "a minted token is printed once and never echoed again")
def t_token_hygiene(a):
    res = roctl("identity", "issue", "--namespace", "execution",
                "--profile", "managed-python", "--id", "cli-hygiene",
                "-o", "json", token=OPERATOR)
    a.eq(res["rc"], 0, res["err"])
    payload = json.loads(res["out"])
    token = payload["token"]
    digest = payload["digest"]
    a.eq(len(digest), 64)

    listing = roctl("identity", "list", "-o", "json", token=READER)
    a.eq(listing["rc"], 0)
    a.not_contains(listing["out"], token,
                   "the plaintext token must never be readable again")

    res = roctl("identity", "revoke", digest, token=OPERATOR)
    a.eq(res["rc"], 0, res["err"])

    res = roctl("identity", "revoke", digest[:2], token=OPERATOR)
    a.ne(res["rc"], 0, "a two-character prefix must not revoke anything")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--category", action="append", default=None)
    parser.add_argument("--filter", default=None)
    args = parser.parse_args()

    selected = [t for t in TESTS
                if (not args.category or t[0] in args.category)
                and (not args.filter or args.filter in t[1])]

    print("Rokh Oghab command-line suite")
    print("=" * 72)
    started = time.time()
    passed = failed = 0
    failures = []
    current = None
    for category, name, fn in selected:
        if category != current:
            current = category
            print("\n  [%s]" % category)
        a = Assert()
        t0 = time.time()
        try:
            fn(a)
            print("    ok   %-62s %6.0fms (%d checks)"
                  % (name, (time.time() - t0) * 1000, a.checks))
            passed += 1
        except Exception as exc:
            print("    FAIL %-62s %6.0fms" % (name, (time.time() - t0) * 1000))
            print("         %s: %s" % (type(exc).__name__, exc))
            failures.append((category, name, "%s: %s" % (type(exc).__name__, exc)))
            failed += 1

    print("\n" + "=" * 72)
    print("passed=%d failed=%d elapsed=%.1fs"
          % (passed, failed, time.time() - started))
    if failures:
        print("\nFAILURES:")
        for category, name, detail in failures:
            print("  [%s] %s\n    %s" % (category, name, detail))
    print("=" * 72)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
