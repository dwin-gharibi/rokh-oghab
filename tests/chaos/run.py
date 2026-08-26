import argparse
import json
import os
import random
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "e2e"))

import driver
from driver import PYTHON_TOKEN, PROXY_HOST, PROXY_PORT

ADMIN = ("127.0.0.1", 19145)
ADMIN_TOKEN = "ro-e2e-admin-token-000000000001"

STOP = threading.Event()
LOCK = threading.Lock()
BREACHES = []
STATS = {"probes": 0, "refused": 0, "errors": 0, "served": 0}
EVENTS = []


def note(kind, detail):
    with LOCK:
        EVENTS.append((time.time(), kind, detail))
    print("  ..%-22s %s" % (kind, detail), flush=True)


def breach(probe, detail):
    with LOCK:
        BREACHES.append((probe, detail))
    print("  BREACH  %-28s %s" % (probe, detail), flush=True)


def bump(key):
    with LOCK:
        STATS[key] += 1


def proxy_raw(payload, timeout=8, read=16384):
    sock = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(payload if isinstance(payload, bytes) else payload.encode())
        data = b""
        while len(data) < read:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        return data
    finally:
        try:
            sock.close()
        except OSError:
            pass


def status_of(data):
    if not data:
        return 0
    try:
        return int(data.split(b" ")[1])
    except (IndexError, ValueError):
        return -1


def get(target, host, token=PYTHON_TOKEN, extra=None):
    lines = ["GET %s HTTP/1.1" % target, "Host: %s" % host]
    if token:
        lines.append("Proxy-Authorization: Bearer %s" % token)
    if extra:
        lines.extend(extra)
    lines.append("Connection: close")
    return proxy_raw("\r\n".join(lines) + "\r\n\r\n")


def connect(authority, token=PYTHON_TOKEN, timeout=8):
    sock = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=timeout)
    sock.settimeout(timeout)
    lines = ["CONNECT %s HTTP/1.1" % authority, "Host: %s" % authority]
    if token:
        lines.append("Proxy-Authorization: Bearer %s" % token)
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    head = b""
    try:
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                break
            head += chunk
    except socket.timeout:
        pass
    return status_of(head), sock


def admin_call(method, path, body=None, token=ADMIN_TOKEN, timeout=8):
    sock = socket.create_connection(ADMIN, timeout=timeout)
    sock.settimeout(timeout)
    try:
        payload = json.dumps(body).encode() if body is not None else None
        lines = ["%s %s HTTP/1.1" % (method, path), "Host: a",
                 "Connection: close"]
        if token:
            lines.append("Authorization: Bearer %s" % token)
        if payload is not None:
            lines.append("Content-Type: application/json")
            lines.append("Content-Length: %d" % len(payload))
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode()
                     + (payload or b""))
        data = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        return status_of(data), data
    finally:
        try:
            sock.close()
        except OSError:
            pass


def served_body(data):
    status = status_of(data)
    if status != 200:
        return False
    body = data.partition(b"\r\n\r\n")[2]
    return b"origin" in body or b"meta-data" in body or len(body) > 0


def probe_denied_host():
    return served_body(get("http://denied.test/", "denied.test"))


def probe_metadata():
    for host in ("169.254.169.254", "2852039166", "0xa9fea9fe",
                 "0251.0376.0251.0376", "169.254.43518",
                 "[::ffff:169.254.169.254]"):
        if served_body(get("http://%s/latest/meta-data/" % host, host)):
            return True
    return False


def probe_private():
    for host in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"):
        if served_body(get("http://%s/" % host, host)):
            return True
    return False


def probe_no_token():
    return served_body(get("http://allowed.test/", "allowed.test", token=None))


def probe_bad_token():
    return served_body(get("http://allowed.test/", "allowed.test",
                           token="not-a-real-token"))


def probe_asserted_identity():
    return served_body(get("http://allowed.test/", "allowed.test", token=None,
                           extra=["X-RO-Identity: sandbox-python-1",
                                  "X-RO-Namespace: execution",
                                  "X-RO-Profile: untrusted-python"]))


def probe_host_mismatch():
    return served_body(get("http://allowed.test/", "denied.test"))


def probe_undeclared_port():
    return served_body(get("http://allowed.test:9999/", "allowed.test:9999"))


def probe_connect_denied():
    status, sock = connect("denied.test:443")
    try:
        sock.close()
    except OSError:
        pass
    return status == 200


def probe_connect_admin():
    status, sock = connect("10.99.0.5:9145")
    try:
        sock.close()
    except OSError:
        pass
    return status == 200


def probe_connect_controller():
    status, sock = connect("10.99.0.6:8081")
    try:
        sock.close()
    except OSError:
        pass
    return status == 200


def probe_rebind():
    return served_body(get("http://rebind.test/", "rebind.test"))


def probe_loopback_name():
    return served_body(get("http://loopback.test/", "loopback.test"))


def probe_internal_name():
    return served_body(get("http://internal.test/", "internal.test"))


def probe_smuggle():
    payload = (
        "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
        "Proxy-Authorization: Bearer %s\r\n"
        "Content-Length: 0\r\nContent-Length: 44\r\nConnection: close\r\n\r\n"
        "GET http://denied.test/ HTTP/1.1\r\nHost: denied.test\r\n\r\n"
        % PYTHON_TOKEN)
    data = proxy_raw(payload)
    return b"origin-b" in data


def probe_te_cl():
    payload = (
        "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
        "Proxy-Authorization: Bearer %s\r\n"
        "Transfer-Encoding: chunked\r\nContent-Length: 5\r\n"
        "Connection: close\r\n\r\n0\r\n\r\n" % PYTHON_TOKEN)
    return status_of(proxy_raw(payload)) == 200


def probe_redirect_metadata():
    data = get("http://raw.test/redirect-internal", "raw.test")
    return b"169.254" in data and status_of(data) in (301, 302, 307, 308)


def probe_interim_smuggle():
    data = get("http://raw.test/interim-with-body", "raw.test")
    return b"SMUGGLED!" in data.partition(b"\r\n\r\n")[0]


def probe_admin_without_token():
    status, _ = admin_call("GET", "/v1/config", token=None)
    return status == 200


def probe_admin_with_sandbox_token():
    status, _ = admin_call("GET", "/v1/config", token=PYTHON_TOKEN)
    return status == 200


def probe_bundle_push_unauthenticated():
    status, _ = admin_call("POST", "/v1/bundle",
                           {"version": 424242, "policies": []}, token=None)
    return status == 200


PROBES = [
    ("denied host", probe_denied_host),
    ("cloud metadata, six spellings", probe_metadata),
    ("private ranges", probe_private),
    ("no token", probe_no_token),
    ("invalid token", probe_bad_token),
    ("self-asserted identity", probe_asserted_identity),
    ("host header mismatch", probe_host_mismatch),
    ("undeclared port", probe_undeclared_port),
    ("CONNECT to a denied host", probe_connect_denied),
    ("CONNECT to the admin port", probe_connect_admin),
    ("CONNECT to the controller", probe_connect_controller),
    ("a name that resolves to metadata", probe_rebind),
    ("a name that resolves to loopback", probe_loopback_name),
    ("a name that resolves inward", probe_internal_name),
    ("request smuggling", probe_smuggle),
    ("TE and CL together", probe_te_cl),
    ("redirect to metadata", probe_redirect_metadata),
    ("interim response smuggling", probe_interim_smuggle),
    ("admin API with no token", probe_admin_without_token),
    ("admin API with a sandbox token", probe_admin_with_sandbox_token),
    ("unauthenticated bundle push", probe_bundle_push_unauthenticated),
]


def probe_worker(rng_seed):
    rng = random.Random(rng_seed)
    while not STOP.is_set():
        name, fn = rng.choice(PROBES)
        bump("probes")
        try:
            got_through = fn()
        except (OSError, ssl.SSLError):
            bump("errors")
            time.sleep(0.25)
            continue
        except Exception as exc:
            bump("errors")
            note("probe-crashed", "%s: %s" % (name, exc))
            continue
        if got_through:
            bump("served")
            breach(name, "policy does not permit this and it succeeded")
        else:
            bump("refused")
        time.sleep(rng.uniform(0.005, 0.03))


def self_check():
    served = served_body(get("http://allowed.test/", "allowed.test"))
    return served


def docker(*args, check=False):
    return subprocess.run(["docker"] + list(args), capture_output=True,
                          timeout=120, check=check)


def chaos_worker(scenarios, rounds, seed):
    rng = random.Random(seed)
    for round_no in range(rounds):
        if STOP.is_set():
            return
        name, fn = rng.choice(scenarios)
        note("chaos", "round %d: %s" % (round_no + 1, name))
        try:
            fn(rng)
        except Exception as exc:
            note("chaos-failed", "%s: %s" % (name, exc))
        time.sleep(rng.uniform(1.0, 2.5))


def c_restart_gateway(rng):
    docker("restart", "-t", "1", "ro-e2e-gateway")
    time.sleep(rng.uniform(1.0, 3.0))


def c_kill_gateway_then_start(rng):
    docker("kill", "ro-e2e-gateway")
    time.sleep(rng.uniform(0.5, 2.0))
    docker("start", "ro-e2e-gateway")
    time.sleep(2.0)


def c_stop_controller(rng):
    docker("stop", "-t", "1", "ro-e2e-controller")
    time.sleep(rng.uniform(1.0, 3.0))
    docker("start", "ro-e2e-controller")


def c_stop_dns(rng):
    docker("stop", "-t", "1", "ro-e2e-testdns")
    time.sleep(rng.uniform(1.0, 3.0))
    docker("start", "ro-e2e-testdns")


def c_stop_collector(rng):
    docker("stop", "-t", "1", "ro-e2e-collector")
    time.sleep(rng.uniform(0.5, 2.0))
    docker("start", "ro-e2e-collector")


def c_stop_origin(rng):
    docker("stop", "-t", "1", "ro-e2e-origin-a")
    time.sleep(rng.uniform(0.5, 2.0))
    docker("start", "ro-e2e-origin-a")


def c_toggle_emergency(rng):
    admin_call("POST", "/v1/emergency-deny", {"enabled": True})
    time.sleep(rng.uniform(0.3, 1.5))
    admin_call("POST", "/v1/emergency-deny", {"enabled": False})


def c_flush_dns(rng):
    admin_call("POST", "/v1/dns/flush", {})


def c_republish_bundle(rng):
    root = os.path.dirname(os.path.dirname(HERE))
    with open(os.path.join(root, "tests", "e2e", "config",
                           "bundle.json")) as fh:
        bundle = json.load(fh)
    bundle["version"] = bundle["version"] + rng.randrange(1, 500)
    admin_call("POST", "/v1/bundle", bundle)


def c_connection_flood(rng):
    socks = []
    try:
        for _ in range(rng.randrange(120, 260)):
            try:
                s = socket.create_connection((PROXY_HOST, PROXY_PORT),
                                             timeout=2)
                s.sendall(b"GET http://allo")
                socks.append(s)
            except OSError:
                break
        time.sleep(rng.uniform(0.5, 1.5))
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


def c_slow_loris(rng):
    socks = []
    try:
        for _ in range(rng.randrange(40, 90)):
            try:
                s = socket.create_connection((PROXY_HOST, PROXY_PORT),
                                             timeout=2)
                s.sendall(b"GET http://allowed.test/ HTTP/1.1\r\nHost: a\r\n")
                socks.append(s)
            except OSError:
                break
        time.sleep(rng.uniform(0.5, 1.5))
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


SCENARIOS = [
    ("restart the gateway", c_restart_gateway),
    ("kill the gateway, then start it", c_kill_gateway_then_start),
    ("stop the controller", c_stop_controller),
    ("stop the DNS server", c_stop_dns),
    ("stop the trace collector", c_stop_collector),
    ("stop an origin", c_stop_origin),
    ("toggle emergency deny", c_toggle_emergency),
    ("flush the DNS cache", c_flush_dns),
    ("republish the bundle", c_republish_bundle),
    ("flood with half-open connections", c_connection_flood),
    ("hold connections with partial heads", c_slow_loris),
]


def restore():
    for name in ("ro-e2e-gateway", "ro-e2e-controller", "ro-e2e-testdns",
                 "ro-e2e-collector", "ro-e2e-origin-a", "ro-e2e-origin-b",
                 "ro-e2e-origin-raw", "ro-e2e-gateway-managed"):
        docker("start", name)
    time.sleep(6)
    for _ in range(20):
        status, _ = admin_call("POST", "/v1/emergency-deny",
                               {"enabled": False})
        if status == 200:
            break
        time.sleep(1)
    root = os.path.dirname(os.path.dirname(HERE))
    with open(os.path.join(root, "tests", "e2e", "config",
                           "bundle.json")) as fh:
        bundle = json.load(fh)
    for _ in range(20):
        status, _ = admin_call("POST", "/v1/bundle", bundle)
        if status == 200:
            break
        time.sleep(1)


def sanity_after():
    problems = []
    for _ in range(30):
        data = get("http://allowed.test/", "allowed.test")
        if status_of(data) == 200:
            break
        time.sleep(1)
    else:
        problems.append("a permitted destination never came back")

    data = get("http://denied.test/", "denied.test")
    if served_body(data):
        problems.append("a denied destination is reachable after the run")
    data = get("http://169.254.169.254/latest/meta-data/", "169.254.169.254")
    if served_body(data):
        problems.append("cloud metadata is reachable after the run")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=14)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--seed", type=int, default=20260825)
    args = parser.parse_args()

    print("Rokh Oghab chaos and bypass campaign")
    print("=" * 78)
    print("  probes      %d shapes, none of them permitted by policy"
          % len(PROBES))
    print("  workers     %d" % args.workers)
    print("  chaos       %d rounds over %d scenarios"
          % (args.rounds, len(SCENARIOS)))
    print("  seed        %d" % args.seed)
    print("\n  a refusal is a pass, a timeout is a pass, a success is a "
          "breach\n")

    problems = driver.preflight()
    if problems:
        for problem in problems:
            print("  cannot start: %s" % problem)
        return 2

    if not self_check():
        print("  the probe machinery cannot see a permitted destination "
              "succeed, so a clean run would prove nothing; aborting")
        return 2
    print("  self check   the probes can see a success\n")

    started = time.time()
    threads = [threading.Thread(target=probe_worker, args=(args.seed + i,),
                                daemon=True)
               for i in range(args.workers)]
    for t in threads:
        t.start()

    chaos = threading.Thread(target=chaos_worker,
                             args=(SCENARIOS, args.rounds, args.seed),
                             daemon=True)
    chaos.start()
    chaos.join()

    STOP.set()
    for t in threads:
        t.join(20)

    print("\n  restoring the stack")
    restore()
    after = sanity_after()

    elapsed = time.time() - started
    print("\n" + "=" * 78)
    print("probes=%d refused=%d errors=%d breaches=%d elapsed=%.0fs"
          % (STATS["probes"], STATS["refused"], STATS["errors"],
             len(BREACHES), elapsed))
    if BREACHES:
        print("\nBREACHES:")
        seen = set()
        for name, detail in BREACHES:
            if name in seen:
                continue
            seen.add(name)
            count = sum(1 for n, _ in BREACHES if n == name)
            print("  %-34s %d times: %s" % (name, count, detail))
    if after:
        print("\nAFTER THE RUN:")
        for problem in after:
            print("  %s" % problem)
    if not BREACHES and not after:
        print("\nnothing policy refuses ever succeeded, through %d chaos "
              "rounds" % args.rounds)
    print("=" * 78)
    return 1 if (BREACHES or after) else 0


if __name__ == "__main__":
    sys.exit(main())
