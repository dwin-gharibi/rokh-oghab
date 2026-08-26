import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

PROXY = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or ""
TOKEN = os.environ.get("RO_PROXY_TOKEN", "")

ALLOWED_HTTP = os.environ.get("RO_DEMO_ALLOWED_HTTP", "http://allowed.test/")
ALLOWED_HTTPS = os.environ.get("RO_DEMO_ALLOWED_HTTPS", "https://allowed.test/")
DENIED_HTTP = os.environ.get("RO_DEMO_DENIED_HTTP", "http://denied.test/")
DIRECT_HOST = os.environ.get("RO_DEMO_DIRECT_HOST", "10.99.0.10")
DIRECT_PORT = int(os.environ.get("RO_DEMO_DIRECT_PORT", "80"))
METADATA = "http://169.254.169.254/latest/meta-data/"

RESULTS = []


def record(name, expectation, outcome, detail=""):
    passed = expectation == outcome
    RESULTS.append((name, expectation, outcome, detail, passed))
    marker = "ok  " if passed else "FAIL"
    print("  %s %-46s expected=%-8s got=%-8s %s"
          % (marker, name, expectation, outcome, detail))


def build_opener():
    handlers = []
    if PROXY:
        handlers.append(urllib.request.ProxyHandler({
            "http": PROXY, "https": PROXY,
        }))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    context = ssl.create_default_context()
    if os.environ.get("RO_DEMO_INSECURE_TLS") == "1":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    if TOKEN:
        opener.addheaders = [("Proxy-Authorization", "Bearer " + TOKEN)]
    return opener


def fetch(url, timeout=10):
    opener = build_opener()
    request = urllib.request.Request(url)
    if TOKEN:
        request.add_header("Proxy-Authorization", "Bearer " + TOKEN)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(2048)
            return "allowed", "HTTP %d, %d bytes" % (response.status, len(body))
    except urllib.error.HTTPError as exc:
        reason = exc.headers.get("X-Rokh-Oghab-Reason") if exc.headers else None
        if reason:
            return "denied", "HTTP %d, reason %s" % (exc.code, reason)
        return "denied", "HTTP %d" % exc.code
    except urllib.error.URLError as exc:
        detail = str(exc.reason)
        if "407" in detail or "403" in detail:
            return "denied", detail[:70]
        return "blocked", detail[:70]
    except (OSError, ssl.SSLError) as exc:
        return "blocked", str(exc)[:70]


def direct_connect(host, port, timeout=4):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return "connected", "the sandbox opened a socket outside the gateway"
    except OSError as exc:
        return "blocked", str(exc)[:70]


def resolve(name):
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET)
        return "resolved", ", ".join(sorted({i[4][0] for i in infos}))
    except socket.gaierror as exc:
        return "unresolved", str(exc)[:70]


def section(title):
    print("\n  %s" % title)


def main():
    print("Rokh Oghab sandbox demonstration")
    print("=" * 78)
    print("  proxy      %s" % (PROXY or "<not configured>"))
    print("  identity   %s" % ("a token is present" if TOKEN else "no token"))

    section("destinations the policy permits")
    outcome, detail = fetch(ALLOWED_HTTP)
    record("plain HTTP to a permitted host", "allowed", outcome, detail)

    outcome, detail = fetch(ALLOWED_HTTPS)
    record("HTTPS through a CONNECT tunnel", "allowed", outcome, detail)

    section("destinations the policy refuses")
    outcome, detail = fetch(DENIED_HTTP)
    record("a host outside the policy", "denied", outcome, detail)

    outcome, detail = fetch(METADATA, timeout=6)
    record("the cloud metadata endpoint", "denied", outcome, detail)

    for encoded in ("http://2852039166/latest/meta-data/",
                    "http://0xa9fea9fe/latest/meta-data/",
                    "http://169.254.43518/latest/meta-data/"):
        outcome, detail = fetch(encoded, timeout=6)
        record("metadata as %s" % encoded.split("/")[2], "denied", outcome, detail)

    outcome, detail = fetch("http://127.0.0.1:9145/v1/status", timeout=6)
    record("the gateway's own admin API", "denied", outcome, detail)

    section("paths that route around the gateway")
    outcome, detail = direct_connect(DIRECT_HOST, DIRECT_PORT)
    record("a raw socket straight to an origin", "blocked", outcome, detail)

    outcome, detail = direct_connect("1.1.1.1", 443)
    record("a raw socket to a public address", "blocked", outcome, detail)

    outcome, detail = direct_connect("1.1.1.1", 53)
    record("a raw socket to port 53 is captured, not free",
           os.environ.get("RO_DEMO_DNS_REDIRECTED", "blocked"), outcome, detail)

    section("name resolution")
    outcome, detail = resolve("allowed.test")
    record("a permitted name resolves", "resolved", outcome, detail)

    outcome, detail = resolve("denied.test")
    record("a name outside the policy does not resolve", "unresolved",
           outcome, detail)

    print("\n" + "=" * 78)
    passed = sum(1 for r in RESULTS if r[4])
    failed = len(RESULTS) - passed
    print("passed=%d failed=%d" % (passed, failed))
    if failed:
        print("\nUnexpected outcomes:")
        for name, expectation, outcome, detail, ok in RESULTS:
            if not ok:
                print("  %s: expected %s, got %s (%s)"
                      % (name, expectation, outcome, detail))
    print("=" * 78)

    if os.environ.get("RO_DEMO_JSON") == "1":
        print(json.dumps([
            {"check": r[0], "expected": r[1], "got": r[2],
             "detail": r[3], "passed": r[4]}
            for r in RESULTS
        ], indent=2))

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
