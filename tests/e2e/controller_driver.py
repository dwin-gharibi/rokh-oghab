import argparse
import json
import os
import socket
import subprocess
import sys
import time

import driver
from driver import Assert, ProxyError, parse_head, read_body, recv_head

CONTROLLER_HOST = os.environ.get("RO_CONTROLLER_HOST", "127.0.0.1")
CONTROLLER_PORT = int(os.environ.get("RO_CONTROLLER_PORT", "18081"))

ADMIN = "ctl-admin-token-0000000000001"
OPERATOR = "ctl-operator-token-00000000001"
READER = "ctl-reader-token-000000000001"
GATEWAY = "ctl-gateway-token-000000000001"

MANAGED_PROXY_PORT = int(os.environ.get("RO_MANAGED_PROXY_PORT", "13129"))
MANAGED_ADMIN_PORT = int(os.environ.get("RO_MANAGED_ADMIN_PORT", "19146"))
MANAGED_ADMIN_TOKEN = "ro-e2e-admin-token-000000000001"

TIMEOUT = 15.0


def ctl(method, path, body=None, token=ADMIN, content_type="application/json",
        timeout=TIMEOUT):
    sock = socket.create_connection((CONTROLLER_HOST, CONTROLLER_PORT),
                                    timeout=timeout)
    sock.settimeout(timeout)
    try:
        if body is None:
            payload = None
        elif isinstance(body, bytes):
            payload = body
        else:
            payload = json.dumps(body).encode()
        lines = ["%s %s HTTP/1.1" % (method, path),
                 "Host: %s:%d" % (CONTROLLER_HOST, CONTROLLER_PORT),
                 "Connection: close"]
        if token:
            lines.append("Authorization: Bearer %s" % token)
        if payload is not None:
            lines.append("Content-Type: " + content_type)
            lines.append("Content-Length: %d" % len(payload))
        head = ("\r\n".join(lines) + "\r\n\r\n").encode()
        sock.sendall(head + (payload or b""))
        raw_head, rest = recv_head(sock)
        status, headers, order, sl = parse_head(raw_head)
        raw = read_body(sock, headers, rest, method=method, status=status)
        try:
            parsed = json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            parsed = None
        return {"status": status, "json": parsed, "body": raw}
    finally:
        sock.close()


def managed_admin(path, token=MANAGED_ADMIN_TOKEN):
    sock = socket.create_connection(("127.0.0.1", MANAGED_ADMIN_PORT), timeout=10)
    sock.settimeout(10)
    try:
        lines = ["GET %s HTTP/1.1" % path,
                 "Host: 127.0.0.1:%d" % MANAGED_ADMIN_PORT,
                 "Authorization: Bearer %s" % token,
                 "Connection: close"]
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        raw_head, rest = recv_head(sock)
        status, headers, order, sl = parse_head(raw_head)
        raw = read_body(sock, headers, rest, status=status)
        try:
            return {"status": status, "json": json.loads(raw.decode())}
        except (ValueError, UnicodeDecodeError):
            return {"status": status, "json": None}
    finally:
        sock.close()


def managed_http(url, token, timeout=TIMEOUT):
    saved = driver.PROXY_PORT
    driver.PROXY_PORT = MANAGED_PROXY_PORT
    try:
        return driver.http_via_proxy(url, token, timeout=timeout)
    finally:
        driver.PROXY_PORT = saved


def wait_for_version(want, deadline=25.0, interval=0.4, digest=None):
    started = time.time()
    last = None
    while time.time() - started < deadline:
        try:
            res = managed_admin("/v1/status")
            if res["status"] == 200:
                policy = res["json"]["policy"]
                last = policy.get("version")
                if last == want and (digest is None or policy.get("digest") == digest):
                    return True, last
        except (OSError, ProxyError, KeyError, TypeError):
            pass
        time.sleep(interval)
    return False, last


TESTS = []


def test(category, name):
    def deco(fn):
        TESTS.append((category, name, fn))
        return fn
    return deco


PY_POLICY = """
apiVersion: rokhoghab.io/v1
kind: EgressPolicy
metadata:
  name: managed-python
  tier: profile
  priority: 10
spec:
  defaultAction: deny
  selector:
    profiles:
      - managed-python
  rules:
    - name: allowed-origin
      action: allow
      destinations:
        hostnames:
          - allowed.test
      ports: [80]
      protocols:
        - http
"""

BASELINE_POLICY = """
apiVersion: rokhoghab.io/v1
kind: EgressPolicy
metadata:
  name: managed-baseline
  tier: global
spec:
  defaultAction: deny
  rules:
    - name: deny-metadata
      action: deny
      destinations:
        cidrs:
          - 169.254.0.0/16
"""

STATE = {}


@test("controller", "health and readiness are reported")
def t_health(a):
    res = ctl("GET", "/healthz", token=None)
    a.eq(res["status"], 200)
    a.eq(res["json"]["component"], "ro-controller")


@test("controller", "unauthenticated requests are refused")
def t_unauth(a):
    for path in ("/v1/status", "/v1/policies", "/v1/bundle", "/v1/settings"):
        res = ctl("GET", path, token=None)
        a.eq(res["status"], 401, path)
    res = ctl("GET", "/v1/status", token="not-a-real-token-000000000")
    a.eq(res["status"], 401)


@test("controller", "roles are enforced")
def t_rbac(a):
    res = ctl("GET", "/v1/status", token=READER)
    a.eq(res["status"], 200, "reader may read")

    res = ctl("POST", "/v1/publish", {"note": "nope"}, token=READER)
    a.eq(res["status"], 403, "reader may not publish")

    res = ctl("PUT", "/v1/policies/reader-attempt",
              PY_POLICY.encode(), token=READER, content_type="application/yaml")
    a.eq(res["status"], 403, "reader may not write policies")

    res = ctl("GET", "/v1/policies", token=GATEWAY)
    a.eq(res["status"], 403, "a gateway token may not list policies")

    res = ctl("PUT", "/v1/settings", {"ttlSeconds": 60}, token=OPERATOR)
    a.eq(res["status"], 403, "operator may not change global settings")

    res = ctl("PUT", "/v1/settings", {"ttlSeconds": 300}, token=ADMIN)
    a.eq(res["status"], 200, "admin may change global settings")


@test("controller", "policies can be staged as YAML and JSON")
def t_policy_crud(a):
    res = ctl("PUT", "/v1/policies/managed-python", PY_POLICY.encode(),
              token=OPERATOR, content_type="application/yaml")
    a.eq(res["status"], 200)
    a.eq(res["json"]["staged"], True)

    res = ctl("PUT", "/v1/policies/managed-baseline", BASELINE_POLICY.encode(),
              token=OPERATOR, content_type="application/yaml")
    a.eq(res["status"], 200)

    res = ctl("PUT", "/v1/policies/json-policy", {
        "kind": "EgressPolicy",
        "metadata": {"name": "json-policy", "tier": "namespace"},
        "spec": {"rules": [{"name": "r", "action": "deny",
                            "destinations": {"hostnameSuffixes": ["blocked.test"]}}]},
    }, token=OPERATOR)
    a.eq(res["status"], 200)

    res = ctl("GET", "/v1/policies", token=READER)
    names = [p["name"] for p in res["json"]["policies"]]
    a.contains(json.dumps(names), "managed-python")
    a.contains(json.dumps(names), "json-policy")

    res = ctl("GET", "/v1/policies/managed-python", token=READER)
    a.eq(res["status"], 200)
    a.eq(res["json"]["metadata"]["name"], "managed-python")

    res = ctl("DELETE", "/v1/policies/json-policy", token=OPERATOR)
    a.eq(res["status"], 200)
    res = ctl("GET", "/v1/policies/json-policy", token=READER)
    a.eq(res["status"], 404)


@test("controller", "invalid documents are refused before they can be staged")
def t_policy_validation(a):
    cases = [
        ("allow without destination", {
            "kind": "EgressPolicy", "metadata": {"name": "bad1"},
            "spec": {"rules": [{"action": "allow", "ports": [443]}]}}),
        ("allow without ports", {
            "kind": "EgressPolicy", "metadata": {"name": "bad2"},
            "spec": {"rules": [{"action": "allow",
                                "destinations": {"hostnames": ["a.example.com"]}}]}}),
        ("unknown field", {
            "kind": "EgressPolicy", "metadata": {"name": "bad3"},
            "spec": {"rules": [{"action": "allow", "ports": [443],
                                "destination": {"hostnames": ["a.example.com"]}}]}}),
        ("bad cidr", {
            "kind": "EgressPolicy", "metadata": {"name": "bad4"},
            "spec": {"rules": [{"action": "allow", "ports": [443],
                                "destinations": {"cidrs": ["999.0.0.0/8"]}}]}}),
        ("overbroad suffix", {
            "kind": "EgressPolicy", "metadata": {"name": "bad5"},
            "spec": {"rules": [{"action": "allow", "ports": [443],
                                "destinations": {"hostnameSuffixes": ["com"]}}]}}),
        ("default allow", {
            "kind": "EgressPolicy", "metadata": {"name": "bad6"},
            "spec": {"defaultAction": "allow", "rules": []}}),
        ("wrong kind", {"kind": "Deployment", "metadata": {"name": "bad7"}}),
    ]
    for label, doc in cases:
        res = ctl("PUT", "/v1/policies/bad-doc", doc, token=OPERATOR)
        a.true(res["status"] in (400, 422),
               "%s must be refused, got %s" % (label, res["status"]))


@test("controller", "resource names cannot escape the store layout")
def t_name_traversal(a):
    for name in ("..", "%2e%2e", "a%2Fb", "UPPER", "-lead"):
        res = ctl("PUT", "/v1/policies/" + name, PY_POLICY.encode(),
                  token=OPERATOR, content_type="application/yaml")
        a.true(res["status"] in (400, 404, 422),
               "name %r must be refused, got %s" % (name, res["status"]))


@test("controller", "malformed YAML is refused with a clear error")
def t_bad_yaml(a):
    res = ctl("PUT", "/v1/policies/bad-yaml", b"metadata:\n\tname: x\n",
              token=OPERATOR, content_type="application/yaml")
    a.eq(res["status"], 400)
    a.contains(json.dumps(res["json"]), "tab")


@test("controller", "sandbox profiles expand into policies")
def t_profiles(a):
    profile = """
apiVersion: rokhoghab.io/v1
kind: SandboxProfile
metadata:
  name: managed-node
spec:
  egress:
    default: deny
    allow:
      - host: api.allowed.test
        port: 80
        protocol: http
"""
    res = ctl("PUT", "/v1/profiles/managed-node", profile.encode(),
              token=OPERATOR, content_type="application/yaml")
    a.eq(res["status"], 200)

    res = ctl("GET", "/v1/profiles", token=READER)
    a.contains(json.dumps(res["json"]), "managed-node")

    bad = """
kind: SandboxProfile
metadata:
  name: too-open
spec:
  egress:
    default: allow
"""
    res = ctl("PUT", "/v1/profiles/too-open", bad.encode(),
              token=OPERATOR, content_type="application/yaml")
    a.eq(res["status"], 422, "a profile may not default to allow")


@test("controller", "tokens are minted, listed and revoked")
def t_identities(a):
    res = ctl("POST", "/v1/identities/tokens", {
        "namespace": "execution", "profile": "managed-python",
        "serviceAccount": "sandbox-runner", "id": "managed-sandbox-1",
    }, token=OPERATOR)
    a.eq(res["status"], 201)
    token = res["json"]["token"]
    a.true(token.startswith("ro_"), "token has the expected prefix")
    a.true(len(token) >= 64, "token has adequate entropy")
    STATE["token"] = token
    STATE["digest"] = res["json"]["digest"]

    res = ctl("GET", "/v1/identities", token=READER)
    a.eq(res["status"], 200)
    a.contains(json.dumps(res["json"]), "managed-sandbox-1")
    a.not_contains(res["body"], token.encode(),
                   "the plaintext token must never be readable again")

    res = ctl("POST", "/v1/identities/tokens", {"profile": "x"}, token=OPERATOR)
    a.eq(res["status"], 422, "namespace is required")

    throwaway = ctl("POST", "/v1/identities/tokens", {
        "namespace": "execution", "profile": "managed-python",
        "id": "throwaway",
    }, token=OPERATOR)
    digest = throwaway["json"]["digest"]
    res = ctl("DELETE", "/v1/identities/tokens/" + digest, token=OPERATOR)
    a.eq(res["status"], 200)
    res = ctl("GET", "/v1/identities", token=READER)
    a.not_contains(res["body"], b"throwaway")


@test("controller", "staged configuration can be previewed before publishing")
def t_preview(a):
    res = ctl("POST", "/v1/preview", {}, token=READER)
    a.eq(res["status"], 200)
    a.eq(res["json"]["valid"], True)
    a.true(res["json"]["summary"]["policyCount"] >= 3)


@test("controller", "publishing creates an immutable version")
def t_publish(a):
    before = ctl("GET", "/v1/versions", token=READER)["json"]["active"]
    res = ctl("POST", "/v1/publish", {"note": "e2e publish"}, token=OPERATOR)
    a.eq(res["status"], 200)
    version = res["json"]["version"]
    a.eq(version, before + 1)
    STATE["version"] = version

    res = ctl("GET", "/v1/versions", token=READER)
    a.eq(res["json"]["active"], version)
    entry = [v for v in res["json"]["versions"] if v["version"] == version][0]
    a.eq(entry["note"], "e2e publish")
    a.eq(entry["actor"], "bootstrap-operator")
    a.true(entry["digest"], "each version records a digest")

    res = ctl("GET", "/v1/versions/%d" % version, token=READER)
    a.eq(res["status"], 200)
    a.eq(res["json"]["version"], version)

    res = ctl("GET", "/v1/bundle", token=GATEWAY)
    a.eq(res["status"], 200)
    a.eq(res["json"]["version"], version)


@test("controller", "the active policy can be simulated")
def t_simulate(a):
    res = ctl("POST", "/v1/simulate", {
        "host": "allowed.test", "port": 80, "protocol": "http",
        "profile": "managed-python", "namespace": "execution",
    }, token=READER)
    a.eq(res["status"], 200)
    a.eq(res["json"]["decision"], "allow")
    a.eq(res["json"]["rule"], "allowed-origin")

    res = ctl("POST", "/v1/simulate", {
        "host": "169.254.169.254", "port": 80, "protocol": "http",
        "profile": "managed-python", "namespace": "execution",
    }, token=READER)
    a.eq(res["json"]["decision"], "deny")
    a.eq(res["json"]["reason"], "policy.explicit_deny")

    res = ctl("POST", "/v1/simulate", {
        "host": "allowed.test", "port": 80, "protocol": "http",
        "profile": "some-other-profile", "namespace": "execution",
    }, token=READER)
    a.eq(res["json"]["decision"], "deny")
    a.eq(res["json"]["reason"], "policy.default_deny")


@test("control-loop", "a published bundle reaches the gateway and takes effect")
def t_propagation(a):
    version = STATE.get("version")
    a.true(version, "a bundle must have been published")
    ok, seen = wait_for_version(version)
    a.true(ok, "gateway did not converge on version %s (saw %s)" % (version, seen))

    res = managed_http("http://allowed.test/", STATE["token"])
    a.allowed(res, "the newly published policy must permit this destination")
    a.contains(res["body"], "origin-a")


@test("control-loop", "the gateway enforces the published policy's boundaries")
def t_propagated_denials(a):
    res = managed_http("http://denied.test/", STATE["token"])
    a.denied(res, "a destination outside the published policy")

    res = managed_http("http://169.254.169.254/", STATE["token"])
    a.denied(res, "metadata denied by the published global tier")

    res = managed_http("http://allowed.test/", None)
    a.eq(res["status"], 407, "identity is still required")


def mint_and_publish(a, identity_id):
    res = ctl("POST", "/v1/identities/tokens", {
        "namespace": "execution", "profile": "managed-python",
        "serviceAccount": "sandbox-runner", "id": identity_id,
    }, token=OPERATOR)
    a.eq(res["status"], 201)
    token = res["json"]["token"]
    digest = res["json"]["digest"]
    pub = ctl("POST", "/v1/publish", {"note": "mint " + identity_id},
              token=OPERATOR)
    a.eq(pub["status"], 200)
    ok, seen = wait_for_version(pub["json"]["version"])
    a.true(ok, "gateway did not converge on %s (saw %s)"
           % (pub["json"]["version"], seen))
    return token, digest, pub["json"]["version"]


@test("control-loop", "rollback restores the previous bundle on the gateway")
def t_rollback(a):
    target = STATE["version"]
    res = ctl("POST", "/v1/rollback", {"version": target}, token=OPERATOR)
    a.eq(res["status"], 200)
    a.eq(res["json"]["version"], target)

    ok, seen = wait_for_version(target)
    a.true(ok, "gateway did not roll back to %s (saw %s)" % (target, seen))

    res = managed_http("http://allowed.test/", STATE["token"])
    a.allowed(res, "the rolled-back bundle is the one now in force")


@test("control-loop", "rolling back to an unknown version is refused")
def t_rollback_unknown(a):
    res = ctl("POST", "/v1/rollback", {"version": 9999}, token=OPERATOR)
    a.eq(res["status"], 422)
    res = ctl("POST", "/v1/rollback", {"version": "abc"}, token=OPERATOR)
    a.eq(res["status"], 422)


@test("control-loop", "revoking a token cuts the sandbox off at the next publish")
def t_revocation(a):
    digest = STATE["digest"]
    res = ctl("DELETE", "/v1/identities/tokens/" + digest, token=OPERATOR)
    a.eq(res["status"], 200)
    res = ctl("POST", "/v1/publish", {"note": "revoke"}, token=OPERATOR)
    a.eq(res["status"], 200)
    version = res["json"]["version"]

    ok, seen = wait_for_version(version)
    a.true(ok, "gateway did not converge on version %s (saw %s)" % (version, seen))

    res = managed_http("http://allowed.test/", STATE["token"])
    a.eq(res["status"], 407, "a revoked token must stop working")
    a.eq(res["reason"], "identity.invalid_token")


@test("control-loop", "rollback re-activates a bundle without reverting the store")
def t_rollback_does_not_unstage(a):
    target = STATE["version"]
    res = ctl("POST", "/v1/rollback", {"version": target}, token=OPERATOR)
    a.eq(res["status"], 200)
    ok, seen = wait_for_version(target)
    a.true(ok, "gateway did not roll back (saw %s)" % seen)

    res = managed_http("http://allowed.test/", STATE["token"])
    a.allowed(res, "the older bundle still carries the revoked token")

    res = ctl("POST", "/v1/publish", {"note": "re-publish staged state"},
              token=OPERATOR)
    a.eq(res["status"], 200)
    ok, seen = wait_for_version(res["json"]["version"])
    a.true(ok, "gateway did not converge (saw %s)" % seen)

    res = managed_http("http://allowed.test/", STATE["token"])
    a.eq(res["status"], 407,
         "publishing after a rollback re-applies the staged revocation")


@test("controller", "a publish after a rollback never reuses a version number")
def t_version_after_rollback(a):
    active = ctl("GET", "/v1/status", token=READER)["json"]["activeVersion"]

    first = ctl("POST", "/v1/publish", {"note": "before rollback"},
                token=OPERATOR)
    a.eq(first["status"], 200)
    v1 = first["json"]["version"]
    a.true(v1 > active, "a publish must advance the version")

    back = ctl("POST", "/v1/rollback", {"version": active}, token=OPERATOR)
    a.eq(back["status"], 200, "rollback to the previously active version")

    second = ctl("POST", "/v1/publish", {"note": "after rollback"},
                 token=OPERATOR)
    a.eq(second["status"], 200)
    v2 = second["json"]["version"]
    a.true(v2 != v1,
           "publishing after a rollback reused version %s, which overwrites a "
           "stored bundle an operator may later roll back to" % v1)
    a.true(v2 > v1, "version numbers must only ever increase")

    stored = ctl("GET", "/v1/versions/%d" % v1, token=READER)
    a.eq(stored["status"], 200, "the earlier version must still be readable")


@test("controller", "the version index contains no duplicate numbers")
def t_version_index_unique(a):
    versions = ctl("GET", "/v1/versions", token=READER)["json"]["versions"]
    seen = {}
    for entry in versions:
        n = entry["version"]
        seen[n] = seen.get(n, 0) + 1
    dupes = sorted(n for n, count in seen.items() if count > 1)
    a.true(not dupes,
           "these version numbers appear more than once, so an immutable "
           "bundle was overwritten: %s" % dupes)


@test("controller", "a token digest prefix never mass-revokes")
def t_revoke_prefix(a):
    minted = []
    for i in range(6):
        res = ctl("POST", "/v1/identities/tokens", {
            "namespace": "execution", "profile": "managed-python",
            "id": "prefix-victim-%d" % i,
        }, token=OPERATOR)
        a.eq(res["status"], 201)
        minted.append(res["json"]["digest"])

    for digest in minted:
        a.eq(len(digest), 64, "a token digest is a full sha256")

    res = ctl("DELETE", "/v1/identities/tokens/" + minted[0][:2],
              token=OPERATOR)
    a.eq(res["status"], 422,
         "a two-character prefix must be refused, not matched")

    res = ctl("DELETE", "/v1/identities/tokens/" + "a" * 15, token=OPERATOR)
    a.eq(res["status"], 422, "a short prefix is refused before any lookup")

    res = ctl("DELETE", "/v1/identities/tokens/" + "b" * 65, token=OPERATOR)
    a.true(res["status"] in (404, 422),
           "an over-long digest is never routed to a match")

    listing = ctl("GET", "/v1/identities", token=READER)["body"]
    for i in range(6):
        a.contains(listing.decode("utf-8", "replace"), "prefix-victim-%d" % i,
                   "no identity may be revoked by a refused prefix")

    res = ctl("DELETE", "/v1/identities/tokens/" + minted[3], token=OPERATOR)
    a.eq(res["status"], 200, "the full digest still revokes exactly one")
    a.eq(res["json"]["revoked"], minted[3])

    listing = ctl("GET", "/v1/identities", token=READER)["body"].decode(
        "utf-8", "replace")
    a.not_contains(listing.encode(), b"prefix-victim-3")
    for i in (0, 1, 2, 4, 5):
        a.contains(listing, "prefix-victim-%d" % i,
                   "revoking one token must not disturb its neighbours")

    res = ctl("DELETE", "/v1/identities/tokens/" + minted[3], token=OPERATOR)
    a.eq(res["status"], 404, "a second revoke of the same digest is a miss")

    for i in (0, 1, 2, 4, 5):
        ctl("DELETE", "/v1/identities/tokens/" + minted[i], token=OPERATOR)


@test("controller", "a mutation that changes nothing never bumps the revision")
def t_failed_mutation_not_cached(a):
    def revision():
        res = ctl("GET", "/v1/status", token=READER)
        a.eq(res["status"], 200)
        return res["json"]["revision"]

    baseline = revision()

    for _ in range(5):
        res = ctl("DELETE", "/v1/identities/tokens/" + "f" * 64, token=OPERATOR)
        a.eq(res["status"], 404, "no such token")
    a.eq(revision(), baseline,
         "a revoke that matched nothing must not write to the store; a bumped "
         "revision forces every gateway to re-sync for no reason")

    for _ in range(5):
        res = ctl("DELETE", "/v1/policies/no-such-policy-here", token=OPERATOR)
        a.eq(res["status"], 404)
    a.eq(revision(), baseline,
         "deleting a policy that does not exist must not write to the store")

    for _ in range(5):
        res = ctl("DELETE", "/v1/profiles/no-such-profile-here", token=OPERATOR)
        a.eq(res["status"], 404)
    a.eq(revision(), baseline,
         "deleting a profile that does not exist must not write to the store")

    res = ctl("PUT", "/v1/identities/sources", {"sources": [
        {"cidr": "203.0.113.0/24", "namespace": "execution",
         "profile": "managed-python"},
        {"cidr": "not-a-cidr", "namespace": "execution"},
    ]}, token=OPERATOR)
    a.eq(res["status"], 422, "a source list with a bad entry is refused whole")
    a.eq(revision(), baseline,
         "a refused source list must not be partially applied")

    listing = ctl("GET", "/v1/identities", token=READER)
    a.eq(listing["status"], 200)
    a.not_contains(listing["body"], b"not-a-cidr",
                   "the rejected value must never become readable")
    a.not_contains(listing["body"], b"203.0.113.0/24",
                   "the accepted half of a refused list must not survive either")


@test("controller", "concurrent writers never lose an update")
def t_concurrent_writes(a):
    import threading

    template = {
        "apiVersion": "rokhoghab.io/v1", "kind": "EgressPolicy",
        "metadata": {"name": "X", "tier": "profile", "priority": 50},
        "spec": {"selector": {"namespaces": ["execution"]},
                 "rules": [{"name": "r", "action": "allow",
                            "destinations": {"hostnames": ["allowed.test"]},
                            "ports": ["443"], "protocols": ["https"]}]},
    }
    names = ["race-%02d" % i for i in range(24)]
    outcome = {}

    def put(name):
        doc = json.loads(json.dumps(template))
        doc["metadata"]["name"] = name
        try:
            res = ctl("PUT", "/v1/policies/" + name, doc, token=OPERATOR)
            outcome[name] = (res["status"], (res["json"] or {}).get("revision"))
        except Exception as exc:
            outcome[name] = ("error", str(exc))

    threads = [threading.Thread(target=put, args=(n,)) for n in names]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)

        for name in names:
            a.true(name in outcome, "%s never returned" % name)
            a.eq(outcome[name][0], 200, "%s: %s" % (name, outcome[name]))

        listing = ctl("GET", "/v1/policies", token=READER)
        a.eq(listing["status"], 200)
        stored = {p["name"] for p in listing["json"]["policies"]}
        lost = [n for n in names if n not in stored]
        a.true(not lost,
               "these writes returned success but are not in the store, so "
               "one writer's copy overwrote another's: %s" % lost)

        revisions = [rev for _, rev in outcome.values() if isinstance(rev, int)]
        a.eq(len(set(revisions)), len(revisions),
             "two writers were handed the same revision number, which means "
             "their mutations were not serialised")
    finally:
        for name in names:
            ctl("DELETE", "/v1/policies/" + name, token=OPERATOR)

    listing = ctl("GET", "/v1/policies", token=READER)
    left = [p["name"] for p in listing["json"]["policies"]
            if p["name"].startswith("race-")]
    a.true(not left, "cleanup left %s behind" % left)


@test("control-loop", "unchanged policy is not republished on every poll")
def t_no_spurious_republish(a):
    token, _, version = mint_and_publish(a, "stable-digest-sandbox")

    first = managed_admin("/v1/status")
    a.eq(first["status"], 200)
    digest = first["json"]["policy"]["digest"]
    a.true(bool(digest), "the gateway must report a bundle digest")

    seen = {digest}
    deadline = time.time() + 12
    while time.time() < deadline:
        time.sleep(2)
        res = managed_admin("/v1/status")
        a.eq(res["status"], 200)
        a.eq(res["json"]["policy"]["version"], version,
             "no publish happened, so the version must not move")
        seen.add(res["json"]["policy"]["digest"])

    a.eq(len(seen), 1,
         "the digest of one bundle changed while nothing was published, so "
         "the gateway is recompiling and republishing unchanged policy on "
         "every poll and two gateways can never be compared: %s"
         % sorted(d[:16] for d in seen))


@test("control-loop", "a local bundle file cannot override the controller")
def t_controller_beats_local_file(a):
    token, digest, version = mint_and_publish(a, "file-override-sandbox")

    res = managed_http("http://allowed.test/", token)
    a.allowed(res, "the controller bundle is in force")

    before = managed_admin("/v1/status")
    a.eq(before["status"], 200)
    active_digest = before["json"]["policy"]["digest"]

    forged = {
        "version": 999999,
        "generatedAt": 0,
        "defaultAction": "allow",
        "emergencyDeny": False,
        "identities": {"allowAnonymous": True, "tokens": {}, "sources": []},
        "policies": [{
            "name": "forged-allow-everything",
            "priority": 1,
            "selector": {},
            "rules": [{"name": "open", "action": "allow",
                       "destinations": {"cidrs": ["0.0.0.0/0"]},
                       "ports": ["1-65535"],
                       "protocols": ["http", "https", "tcp"]}],
        }],
    }
    payload = json.dumps(forged)
    proc = subprocess.run(
        ["docker", "exec", "-i", "ro-e2e-gateway-managed", "sh", "-c",
         "cat > /var/lib/rokh-oghab/bundle.json && "
         "test -s /var/lib/rokh-oghab/bundle.json && echo WROTE"],
        input=payload.encode(), capture_output=True, timeout=30)
    a.contains(proc.stdout or b"", b"WROTE",
               "the probe must actually place a bundle where the gateway "
               "reads one, or it proves nothing: %r %r"
               % (proc.stdout, proc.stderr))

    try:
        time.sleep(8)
        res = managed_admin("/v1/status")
        a.eq(res["status"], 200)
        a.eq(res["json"]["policy"]["version"], version,
             "the gateway must still be running the controller's version; a "
             "bundle written into the container must never replace it")
        a.eq(res["json"]["policy"]["digest"], active_digest,
             "the active bundle digest must be the controller's")

        res = managed_http("http://denied.test/", token)
        a.denied(res,
                 "a forged local bundle must not open a denied destination")
    finally:
        subprocess.run(
            ["docker", "exec", "ro-e2e-gateway-managed", "sh", "-c",
             "rm -f /var/lib/rokh-oghab/bundle.json"],
            capture_output=True, timeout=30)


@test("control-loop", "emergency deny propagates and stops all egress")
def t_emergency(a):
    token, digest, version = mint_and_publish(a, "emergency-sandbox")

    res = managed_http("http://allowed.test/", token)
    a.allowed(res, "traffic flows before the switch")

    res = ctl("POST", "/v1/emergency-deny", {"enabled": True}, token=OPERATOR)
    a.eq(res["status"], 200)
    a.eq(res["json"]["emergencyDeny"], True)
    try:
        ok, seen = wait_for_version(res["json"]["version"])
        a.true(ok, "gateway did not converge (saw %s)" % seen)
        blocked = managed_http("http://allowed.test/", token)
        a.denied(blocked, "emergency deny must stop permitted traffic")
        a.eq(blocked["reason"], "emergency.deny")
        dns_blocked = managed_http("http://api.allowed.test/", token)
        a.denied(dns_blocked, "every destination is denied while engaged")
    finally:
        lift = ctl("POST", "/v1/emergency-deny", {"enabled": False},
                   token=OPERATOR)
        if lift["status"] == 200:
            wait_for_version(lift["json"]["version"])

    res = managed_http("http://allowed.test/", token)
    a.allowed(res, "egress resumes once the switch is lifted")
    STATE["live_token"] = token


@test("control-loop", "a gateway that loses its controller keeps enforcing policy")
def t_controller_outage(a):
    token = STATE.get("live_token")
    a.true(token, "a live token is required for this test")

    subprocess.run(["docker", "stop", "ro-e2e-controller"],
                   capture_output=True, timeout=60)
    try:
        time.sleep(3)
        res = managed_http("http://allowed.test/", token)
        a.allowed(res, "the last good bundle keeps working during an outage")
        res = managed_http("http://denied.test/", token)
        a.denied(res, "denials still hold during an outage")
        res = managed_http("http://169.254.169.254/", token)
        a.denied(res, "the address guard still holds during an outage")
        res = managed_http("http://allowed.test/", None)
        a.eq(res["status"], 407, "identity is still required during an outage")
    finally:
        subprocess.run(["docker", "start", "ro-e2e-controller"],
                       capture_output=True, timeout=60)
        time.sleep(5)


@test("control-loop", "a gateway rejects a bundle the controller could not have signed")
def t_gateway_rejects_bad_bundle(a):
    res = driver.admin("POST", "/v1/validate", {
        "version": 99, "policies": [{"name": "x", "rules": [
            {"action": "allow", "ports": [443]}]}],
    })
    a.eq(res["status"], 200)
    a.eq(res["json"]["valid"], False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--category", action="append", default=None)
    parser.add_argument("--filter", default=None)
    args = parser.parse_args()

    selected = [t for t in TESTS
                if (not args.category or t[0] in args.category)
                and (not args.filter or args.filter in t[1])]

    print("Rokh Oghab control-plane suite")
    print("=" * 72)
    passed = failed = 0
    failures = []
    current = None
    started = time.time()

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
