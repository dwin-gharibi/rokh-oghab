import argparse
import random
import socket
import string
import binascii
import struct
import sys
import traceback
import time

import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e"))

import driver
from driver import (PROXY_HOST, PROXY_PORT, DNS_HOST, DNS_PORT,
                    PYTHON_TOKEN, admin, http_via_proxy)

HEAD_TIMEOUT_SECONDS = 10.0
STALL_SECONDS = HEAD_TIMEOUT_SECONDS + 5.0
QUICK_SECONDS = 5.0
DNS_TIMEOUT_SECONDS = 0.75

FINDINGS = []
SENT = 0


def finding(kind, detail, payload):
    FINDINGS.append((kind, detail, payload))
    print("  FINDING %s: %s" % (kind, detail))
    print("          payload: %r" % (payload[:220],))


def rand_text(rng, n, alphabet=None):
    alphabet = alphabet or (string.printable + "\x00\x01\x7f\xff")
    return "".join(rng.choice(alphabet) for _ in range(n))


def rand_bytes(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


METHODS = ["GET", "POST", "CONNECT", "HEAD", "PUT", "DELETE", "OPTIONS",
           "TRACE", "PATCH", "get", "", "G" * 200, "GET\x00", "GE T"]

TARGETS = [
    "http://allowed.test/", "https://allowed.test/", "allowed.test:443",
    "/", "*", "", "http://", "http:///", "//allowed.test/",
    "http://allowed.test:99999/", "http://allowed.test:-1/",
    "http://[::1]/", "http://[fe80::1%25eth0]/", "http://user@allowed.test/",
    "http://allowed.test/%2e%2e/%2e%2e/etc/passwd",
    "http://allowed.test/" + "a" * 4000,
    "http://" + "b" * 300 + ".test/",
    "http://allowed.test/?" + "c" * 2000,
    "http://169.254.169.254/", "http://2852039166/", "http://0x7f000001/",
]

VERSIONS = ["HTTP/1.1", "HTTP/1.0", "HTTP/2.0", "HTTP/0.9", "HTTP/9.9",
            "HTTP/1.1\x00", "", "ICY", "RTSP/1.0"]

HEADER_NAMES = ["Host", "Content-Length", "Transfer-Encoding", "Connection",
                "Proxy-Authorization", "X-Ro-Identity", "X-Ro-Profile",
                "Expect", "Upgrade", "TE", "Trailer", "Content-Length ",
                " Host", "Host\x00", "X" * 300, ""]

HEADER_VALUES = ["allowed.test", "0", "-1", "999999999999999999999", "chunked",
                 "chunked, identity", "identity", "keep-alive", "close",
                 "Bearer " + PYTHON_TOKEN, "Bearer wrong", "",
                 "a" * 5000, "a\x00b", "a\rb", "a\nb", "a\r\n b",
                 "100-continue", "websocket", "\x7f", "\xff\xfe"]

SEPARATORS = ["\r\n", "\n", "\r", "\n\r", "\r\n\r\n", "\x00"]


def build_request(rng):
    method = rng.choice(METHODS)
    target = rng.choice(TARGETS)
    version = rng.choice(VERSIONS)
    sep = rng.choice(SEPARATORS) if rng.random() < 0.25 else "\r\n"
    lines = ["%s %s %s" % (method, target, version)]
    for _ in range(rng.randrange(0, 8)):
        lines.append("%s: %s" % (rng.choice(HEADER_NAMES),
                                 rng.choice(HEADER_VALUES)))
    if rng.random() < 0.6:
        lines.append("Proxy-Authorization: Bearer " + PYTHON_TOKEN)
    head = sep.join(lines) + "\r\n\r\n"
    body = ""
    if rng.random() < 0.3:
        body = rand_text(rng, rng.randrange(0, 200))
    return (head + body).encode("latin-1", "replace")


def send_payload(payload, timeout=STALL_SECONDS, read=True, complete=True):
    started = time.time()
    sock = None
    try:
        sock = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(payload)
        if not read:
            return "sent", time.time() - started, b""
        data = b""
        try:
            while len(data) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            return "stalled", time.time() - started, data
        return "closed", time.time() - started, data
    except socket.timeout:
        return "timeout", time.time() - started, b""
    except OSError as exc:
        return "error:%s" % exc, time.time() - started, b""
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def classify(outcome, elapsed, data, payload):
    global SENT
    SENT += 1
    if outcome == "timeout":
        finding("hang", "no response and no close within %.0fs" % STALL_SECONDS,
                payload.decode("latin-1", "replace"))
        return
    if outcome == "stalled" and not data:
        finding("hang", "held open with no response for %.0fs, past the %.0fs "
                        "head timeout" % (elapsed, HEAD_TIMEOUT_SECONDS),
                payload.decode("latin-1", "replace"))
        return
    if data.startswith(b"HTTP/1.1 5") and not data.startswith(b"HTTP/1.1 50"):
        finding("server-error", data.split(b"\r\n")[0].decode("latin-1", "replace"),
                payload.decode("latin-1", "replace"))
        return
    if b"HTTP/1.1 500" in data:
        finding("server-error", "the gateway returned 500",
                payload.decode("latin-1", "replace"))
        return
    for leak in (b"lua entry thread", b"stack traceback", b"attempt to index",
                 b"/usr/local/openresty", b"attempt to compare",
                 b"attempt to perform", b"bad argument"):
        if leak in data:
            finding("internal-leak", "the response leaked %r" % leak,
                    payload.decode("latin-1", "replace"))
            return
    if PYTHON_TOKEN.encode() in data:
        finding("credential-leak", "the response echoed the proxy token",
                payload.decode("latin-1", "replace"))


def fuzz_http(rng, rounds):
    print("\n  fuzzing the request parser (%d rounds)" % rounds)
    for _ in range(rounds):
        payload = build_request(rng)
        outcome, elapsed, data = send_payload(payload, timeout=QUICK_SECONDS)
        if outcome == "timeout" or (outcome == "stalled" and not data):
            outcome, elapsed, data = send_payload(payload)
        classify(outcome, elapsed, data, payload)


def fuzz_incomplete(rng, rounds):
    print("\n  checking that unfinished heads are dropped (%d rounds)" % rounds)
    for _ in range(rounds):
        payload = build_request(rng)
        payload = payload.rstrip(b"\r\n")[:max(1, len(payload) // 2)]
        outcome, elapsed, data = send_payload(payload)
        if outcome == "timeout":
            finding("hang", "an unfinished head was held past %.0fs"
                    % STALL_SECONDS, payload.decode("latin-1", "replace"))
        elif elapsed > HEAD_TIMEOUT_SECONDS + 3.0:
            finding("slow-drop", "an unfinished head was held for %.1fs, longer "
                    "than the %.0fs head timeout"
                    % (elapsed, HEAD_TIMEOUT_SECONDS),
                    payload.decode("latin-1", "replace"))


def fuzz_binary(rng, rounds):
    print("\n  fuzzing with raw binary on the proxy port (%d rounds)" % rounds)
    for _ in range(rounds):
        payload = rand_bytes(rng, rng.randrange(1, 2048)) + b"\r\n\r\n"
        outcome, elapsed, data = send_payload(payload, timeout=QUICK_SECONDS)
        if outcome == "timeout" or (outcome == "stalled" and not data):
            outcome, elapsed, data = send_payload(payload)
        classify(outcome, elapsed, data, payload)


def fuzz_connect_tunnel(rng, rounds):
    print("\n  fuzzing the CONNECT tunnel and ClientHello peek (%d rounds)"
          % rounds)
    for _ in range(rounds):
        head = ("CONNECT allowed.test:443 HTTP/1.1\r\n"
                "Host: allowed.test:443\r\n"
                "Proxy-Authorization: Bearer %s\r\n\r\n" % PYTHON_TOKEN)
        sock = None
        started = time.time()
        try:
            sock = socket.create_connection((PROXY_HOST, PROXY_PORT),
                                            timeout=STALL_SECONDS)
            sock.settimeout(STALL_SECONDS)
            sock.sendall(head.encode())
            sock.settimeout(QUICK_SECONDS)
            try:
                first = sock.recv(4096)
            except socket.timeout:
                finding("hang", "CONNECT never answered", head)
                continue
            sock.settimeout(STALL_SECONDS)
            if not first.startswith(b"HTTP/1.1 200"):
                continue
            kind = rng.randrange(4)
            if kind == 0:
                blob = rand_bytes(rng, rng.randrange(1, 900))
            elif kind == 1:
                length = rng.randrange(0, 65536)
                blob = b"\x16\x03\x01" + struct.pack(">H", length) + \
                    rand_bytes(rng, rng.randrange(0, 400))
            elif kind == 2:
                blob = b"\x16\x03\x01\xff\xff\x01" + rand_bytes(rng, 40)
            else:
                blob = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
            sock.sendall(blob)
            try:
                sock.recv(4096)
            except socket.timeout:
                if time.time() - started > STALL_SECONDS:
                    finding("hang", "tunnel held open after a bad ClientHello",
                            repr(blob[:120]))
        except OSError:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass


def fuzz_dns(rng, rounds):
    print("\n  fuzzing the DNS server (%d rounds)" % rounds)
    for _ in range(rounds):
        kind = rng.randrange(5)
        if kind == 0:
            packet = rand_bytes(rng, rng.randrange(1, 600))
        elif kind == 1:
            packet = struct.pack(">HHHHHH", rng.randrange(65536), 0x0100,
                                 rng.randrange(0, 40), rng.randrange(0, 40),
                                 rng.randrange(0, 40), rng.randrange(0, 40))
            packet += rand_bytes(rng, rng.randrange(0, 200))
        elif kind == 2:
            packet = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
            packet += b"\xc0\x0c" + struct.pack(">HH", 1, 1)
        elif kind == 3:
            packet = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
            for _ in range(rng.randrange(1, 60)):
                n = rng.randrange(1, 64)
                packet += bytes([n]) + rand_bytes(rng, n)
            packet += b"\x00" + struct.pack(">HH", rng.randrange(65536), 1)
        else:
            packet = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
            packet += b"\x07allowed\x04test\x00"
            packet += struct.pack(">HH", rng.randrange(65536),
                                 rng.randrange(65536))
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(DNS_TIMEOUT_SECONDS)
        try:
            s.sendto(packet, (DNS_HOST, DNS_PORT))
            try:
                reply, _ = s.recvfrom(4096)
                if len(reply) > 4096:
                    finding("dns-amplification",
                            "a %d byte query produced a %d byte reply"
                            % (len(packet), len(reply)), repr(packet[:80]))
            except socket.timeout:
                pass
        except OSError:
            pass
        finally:
            s.close()


def still_alive():
    last = None
    for attempt in range(3):
        try:
            res = http_via_proxy("http://allowed.test/", PYTHON_TOKEN, timeout=10)
            if res["status"] in (200, 429, 503):
                return True
            last = "status %s reason %s" % (res["status"], res.get("reason"))
        except Exception as exc:
            last = "%s: %s" % (type(exc).__name__, exc)
        time.sleep(1.0 + attempt)
    print("  the gateway did not answer after three tries: %s" % last)
    return False


RESPONSE_STATUS = [b"100 Continue", b"101 Switching Protocols",
                   b"102 Processing", b"103 Early Hints", b"199 Whatever",
                   b"200 OK", b"204 No Content", b"301 Moved", b"302 Found",
                   b"304 Not Modified", b"401 Unauthorized", b"500 Oops"]

RESPONSE_HEADERS = [
    b"Content-Length: 0", b"Content-Length: 5", b"Content-Length: -1",
    b"Content-Length: 99999999999", b"Content-Length: 5\r\nContent-Length: 6",
    b"Transfer-Encoding: chunked", b"Transfer-Encoding: identity",
    b"Transfer-Encoding: chunked\r\nContent-Length: 5",
    b"Connection: keep-alive", b"Connection: close", b"Connection: upgrade",
    b"Upgrade: websocket", b"Location: http://169.254.169.254/",
    b"Location: //denied.test/", b"Location: /relative",
    b"X-Pad: " + b"a" * 200, b"Trailer: X-Thing", b"Content-Encoding: gzip",
]

SECOND_RESPONSE = (b"HTTP/1.1 200 OK\r\nX-Smuggled: yes\r\n"
                   b"Content-Length: 9\r\n\r\nSMUGGLED!")


def build_response(rng):
    status = rng.choice(RESPONSE_STATUS)
    headers = [rng.choice(RESPONSE_HEADERS) for _ in range(rng.randrange(0, 4))]
    head = b"\r\n".join([b"HTTP/1.1 " + status] + headers) + b"\r\n\r\n"

    tail = b""
    roll = rng.randrange(0, 10)
    if roll < 3:
        tail = SECOND_RESPONSE
    elif roll < 5:
        tail = b"5\r\nEVIL!\r\n0\r\n\r\n" + SECOND_RESPONSE
    elif roll < 6:
        tail = rand_bytes(rng, rng.randrange(1, 64))
    elif roll < 7:
        tail = b"hello"

    code = int(status.split(b" ")[0])
    joined = b"\r\n".join(headers).lower()
    framed = b"content-length" in joined or b"transfer-encoding" in joined
    if code == 101:
        must = 502
    elif 100 <= code < 200 and framed:
        must = 502
    else:
        must = None
    return head + tail, must


def expected_head(payload):
    rest = payload
    for _ in range(16):
        head, sep, rest = rest.partition(b"\r\n\r\n")
        if not sep:
            return None
        try:
            status = int(head.split(b" ")[1])
        except (IndexError, ValueError):
            return None
        if status >= 200:
            return head
        lowered = head.lower()
        if b"content-length" in lowered or b"transfer-encoding" in lowered:
            return None
    return None


def replay_once(payload, timeout=QUICK_SECONDS):
    sock = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=timeout)
    sock.settimeout(timeout)
    try:
        req = (b"GET http://raw.test/replay HTTP/1.1\r\nHost: raw.test\r\n"
               b"X-Replay: " + binascii.hexlify(payload) + b"\r\n"
               b"Proxy-Authorization: Bearer " + PYTHON_TOKEN.encode() +
               b"\r\nConnection: close\r\n\r\n")
        sock.sendall(req)
        data = b""
        while len(data) < 262144:
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


def fuzz_responses(rng, rounds):
    global SENT
    print("\n  fuzzing upstream responses (%d rounds)" % rounds)
    for _ in range(rounds):
        payload, must = build_response(rng)
        SENT += 1
        started = time.time()
        try:
            data = replay_once(payload)
        except OSError as exc:
            finding("response-refused",
                    "the gateway would not carry a response: %s" % exc,
                    repr(payload))
            continue
        elapsed = time.time() - started
        if elapsed > QUICK_SECONDS - 0.5:
            finding("response-stall",
                    "a response took %.1fs to resolve" % elapsed, repr(payload))
        if not data:
            finding("response-empty",
                    "the gateway sent nothing at all", repr(payload))
            continue

        head = data.split(b"\r\n\r\n", 1)[0]
        if not head.startswith(b"HTTP/1.1 "):
            finding("response-not-http",
                    "the client got something that is not a response head",
                    repr(data[:200]))
            continue
        if head.count(b"HTTP/1.1 ") > 1:
            finding("response-double-head",
                    "two status lines in one response head", repr(payload))
        expected = expected_head(payload)
        if b"X-Smuggled" in head and (expected is None
                                      or b"X-Smuggled" not in expected):
            finding("response-smuggling",
                    "a header from a later response was framed into the head "
                    "the client received", repr(payload))

        try:
            status = int(head.split(b" ")[1])
        except (IndexError, ValueError):
            finding("response-bad-status",
                    "the status line does not parse", repr(head[:120]))
            continue
        if 100 <= status < 200:
            finding("response-interim-final",
                    "an interim response was handed to the client as the "
                    "answer", repr(payload))
        if must is not None and status != must:
            finding("response-not-refused",
                    "expected %d, got %d" % (must, status), repr(payload))


def run(rng, rounds):
    passes = (
        ("http", lambda: fuzz_http(rng, rounds)),
        ("incomplete", lambda: fuzz_incomplete(rng, max(1, rounds // 40))),
        ("binary", lambda: fuzz_binary(rng, max(1, rounds // 2))),
        ("tunnel", lambda: fuzz_connect_tunnel(rng, max(1, rounds // 5))),
        ("dns", lambda: fuzz_dns(rng, max(1, rounds // 2))),
        ("responses", lambda: fuzz_responses(rng, max(1, rounds // 2))),
    )
    broken = []
    for name, fn in passes:
        try:
            fn()
        except Exception as exc:
            broken.append(name)
            print("  FUZZER BUG in the %s pass: %s: %s"
                  % (name, type(exc).__name__, exc))
            traceback.print_exc()
            continue
        if not still_alive():
            finding("gateway-down",
                    "the gateway stopped serving after the %s pass" % name, "")
    return broken


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=250)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    seed = args.seed if args.seed is not None else 20260824
    rng = random.Random(seed)

    print("Rokh Oghab fuzz run")
    print("=" * 78)
    print("  proxy   %s:%d" % (PROXY_HOST, PROXY_PORT))
    print("  dns     %s:%d" % (DNS_HOST, DNS_PORT))
    print("  seed    %d" % seed)

    problems = driver.preflight()
    if problems:
        for problem in problems:
            print("  cannot start: %s" % problem)
        print("\n" + "=" * 78)
        print("sent=0 findings=0 elapsed=0.0s seed=%d ABORTED" % seed)
        print("=" * 78)
        return 2

    if not still_alive():
        print("  the gateway is not serving before the run; aborting")
        print("\n" + "=" * 78)
        print("sent=0 findings=0 elapsed=0.0s seed=%d ABORTED" % seed)
        print("=" * 78)
        return 2

    started = time.time()
    broken = run(rng, args.rounds)

    print("\n  the gateway still reports its own state")
    try:
        res = admin("GET", "/v1/status")
        if res["status"] != 200:
            finding("admin-down", "the admin API returned %d" % res["status"], "")
    except Exception as exc:
        finding("admin-down", "the admin API is unreachable: %s" % exc, "")

    elapsed = time.time() - started
    print("\n" + "=" * 78)
    print("sent=%d findings=%d elapsed=%.1fs seed=%d%s"
          % (SENT, len(FINDINGS), elapsed, seed,
             (" FUZZER-BUGS=" + ",".join(broken)) if broken else ""))
    if FINDINGS:
        print("\nFINDINGS:")
        for kind, detail, payload in FINDINGS:
            print("  [%s] %s" % (kind, detail))
    if broken:
        print("\nThese passes did not run to completion because the fuzzer "
              "itself failed: %s" % ", ".join(broken))
        print("That is a defect in tests/fuzz/fuzz.py, not a finding about "
              "the gateway.")
    print("=" * 78)
    if broken:
        return 2
    return 1 if FINDINGS else 0


if __name__ == "__main__":
    sys.exit(main())
