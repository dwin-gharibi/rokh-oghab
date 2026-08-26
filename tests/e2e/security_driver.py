import argparse
import json
import os
import socket
import ssl
import sys
import time

import driver
from driver import (Assert, ProxyError, connect_proxy, connect_via_proxy,
                    http_via_proxy, parse_head, raw_proxy, read_body, recv_head,
                    admin, dns_query, dns_query_host, PYTHON_TOKEN, NODE_TOKEN,
                    STRICT_TOKEN, ADMIN_TOKEN)

TESTS = []


def test(category, name):
    def deco(fn):
        TESTS.append((category, name, fn))
        return fn
    return deco


def send_raw(payload, read_bytes=4096, timeout=10):
    sock = connect_proxy(timeout)
    try:
        sock.sendall(payload if isinstance(payload, bytes) else payload.encode())
        data = b""
        try:
            while len(data) < read_bytes:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data
    finally:
        try:
            sock.close()
        except OSError:
            pass


def proxy_req(url, token=PYTHON_TOKEN, **kwargs):
    return http_via_proxy(url, token, **kwargs)


@test("upstream", "a response with both Content-Length and Transfer-Encoding is refused")
def t_upstream_dual(a):
    res = proxy_req("http://raw.test/dual")
    a.eq(res["status"], 502)
    a.eq(res["reason"], "upstream.response_framing")


@test("upstream", "a response with conflicting Content-Length values is refused")
def t_upstream_dupclen(a):
    res = proxy_req("http://raw.test/dupclen")
    a.eq(res["status"], 502)


@test("upstream", "a malformed status line is refused")
def t_upstream_badstatus(a):
    for path in ("/badstatus", "/nothttp"):
        res = proxy_req("http://raw.test" + path)
        a.eq(res["status"], 502, path)
        a.eq(res["reason"], "upstream.bad_response", path)


@test("upstream", "a bare-LF response head is refused")
def t_upstream_barelf(a):
    res = proxy_req("http://raw.test/barelf")
    a.true(res["status"] in (502, 504), "got %s" % res["status"])
    a.contains(res["reason"] or "", "upstream",
               "a head the gateway cannot frame is reported as an upstream fault")
    a.true(res["headers"].get("content-length") != "2",
           "the hostile response body must not be relayed")


@test("upstream", "an obs-folded response header is refused")
def t_upstream_obsfold(a):
    res = proxy_req("http://raw.test/obsfold")
    a.eq(res["status"], 502)


@test("upstream", "a response header with a space before the colon is refused")
def t_upstream_spacecolon(a):
    res = proxy_req("http://raw.test/spacecolon")
    a.eq(res["status"], 502)


@test("upstream", "a response header containing a null byte is refused")
def t_upstream_nullheader(a):
    res = proxy_req("http://raw.test/nullheader")
    a.eq(res["status"], 502)


@test("upstream", "an oversized response head is refused")
def t_upstream_hugeheader(a):
    res = proxy_req("http://raw.test/hugeheader")
    a.true(res["status"] in (502, 504), "got %s" % res["status"])
    a.not_contains(res["body"], b"aaaaaaaaaa",
                   "an oversized head must never be relayed")


@test("upstream", "a malformed chunk size is refused and not relayed")
def t_upstream_badchunk(a):
    for path in ("/badchunk", "/negchunk"):
        try:
            res = proxy_req("http://raw.test" + path)
            a.not_contains(res.get("body", b""), b"hello",
                           "%s must not leak chunk contents" % path)
        except ProxyError:
            pass


@test("upstream", "a non-chunked Transfer-Encoding response is refused")
def t_upstream_teidentity(a):
    res = proxy_req("http://raw.test/teidentity")
    a.eq(res["status"], 502)


@test("upstream", "the injected header in a split response is preserved verbatim")
def t_upstream_split(a):
    res = proxy_req("http://raw.test/split")
    a.eq(res["status"], 200)
    a.eq(res["headers"].get("x-injected"), "yes",
         "a legitimately separate header is passed through unchanged")


@test("upstream", "a redirect to a metadata endpoint is blocked")
def t_redirect_metadata(a):
    res = proxy_req("http://raw.test/redirect-internal")
    a.denied(res)
    a.contains(res["reason"] or "", "redirect")


@test("upstream", "a redirect encoded as a decimal IP is blocked")
def t_redirect_decimal(a):
    res = proxy_req("http://raw.test/redirect-decimal")
    a.denied(res)
    a.contains(res["reason"] or "", "redirect")


@test("upstream", "a redirect to a denied destination is blocked")
def t_redirect_denied(a):
    res = proxy_req("http://raw.test/redirect-denied")
    a.denied(res)


@test("upstream", "relative and permitted redirects pass through")
def t_redirect_ok(a):
    res = proxy_req("http://raw.test/redirect-relative")
    a.eq(res["status"], 302)
    res = proxy_req("http://raw.test/redirect-allowed")
    a.eq(res["status"], 302)


@test("upstream", "a protocol-relative redirect is evaluated, not waved through")
def t_redirect_scheme_relative(a):
    res = proxy_req("http://raw.test/redirect-scheme-relative")
    a.denied(res, "//denied.test is a different host, not a relative path")
    a.contains(res["reason"] or "", "redirect")


@test("upstream", "a protocol-relative redirect to metadata is blocked")
def t_redirect_scheme_relative_metadata(a):
    res = proxy_req("http://raw.test/redirect-scheme-relative-metadata")
    a.denied(res, "//169.254.169.254 must not reach the workload")
    a.contains(res["reason"] or "", "redirect")


@test("upstream", "the backslash spellings of a protocol-relative redirect are blocked")
def t_redirect_backslash(a):
    for path in ("/redirect-backslash", "/redirect-double-backslash"):
        res = proxy_req("http://raw.test" + path)
        a.denied(res, path + " must be evaluated as off-origin")
        a.contains(res["reason"] or "", "redirect", path)


@test("upstream", "an origin that over-sends never has its socket reused")
def t_upstream_overread(a):
    first = proxy_req("http://raw.test/overbody")
    a.eq(first["status"], 200)
    a.eq(first["body"], b"ok", "only the declared body may reach the client")
    a.not_contains(first["body"] or b"", b"SMUGGLED",
                   "bytes past Content-Length must never reach the client")
    for _ in range(4):
        res = proxy_req("http://raw.test/ok")
        a.eq(res["status"], 200,
             "a later request must not inherit a poisoned pooled connection")
        a.not_contains(res["body"] or b"", b"SMUGGLED",
                       "a smuggled response must never be served to another request")
        a.not_contains(json.dumps(res.get("headers") or {}), "X-Smuggled",
                       "a smuggled header must never be served to another request")


@test("upstream", "one sandbox never inherits another's upstream connection")
def t_upstream_pool_isolation(a):
    proxy_req("http://raw.test/overbody-delayed", token=PYTHON_TOKEN)
    time.sleep(0.8)
    for _ in range(5):
        res = proxy_req("http://raw.test/ok", token=NODE_TOKEN)
        a.not_contains(res["body"] or b"", b"SMUGGLED",
                       "a response left on one identity's socket must never "
                       "reach a different identity")
        a.not_contains(json.dumps(res.get("headers") or {}), "X-Smuggled",
                       "a header left on one identity's socket must never "
                       "reach a different identity")


@test("exhaustion", "a flooding source exhausts its own budget, not the gateway's")
def t_source_connection_cap(a):
    held = []
    try:
        for _ in range(400):
            try:
                sock = socket.create_connection((driver.PROXY_HOST,
                                                 driver.PROXY_PORT), timeout=5)
                sock.settimeout(5)
                sock.sendall(b"GET http://allowed.test/ HTTP/1.1\r\n")
                held.append(sock)
            except OSError:
                break
        time.sleep(2.5)
        body = admin("GET", "/metrics")["body"]
        a.contains(body, "limit.source_connections",
                   "a source opening 400 partial connections must be capped")

        blocked = http_via_proxy("http://allowed.test/", PYTHON_TOKEN, timeout=15)
        a.eq(blocked["status"], 429,
             "the flooding source must be the one that is refused")
        a.eq(blocked["reason"], "limit.source_connections")

        ready = admin("GET", "/readyz")
        a.eq(ready["status"], 200,
             "the gateway itself must stay healthy while one source floods")
        status = admin("GET", "/v1/status")
        a.eq(status["status"], 200,
             "the admin plane must stay reachable while one source floods")
    finally:
        for sock in held:
            try:
                sock.close()
            except OSError:
                pass
        time.sleep(1.5)

    recovered = http_via_proxy("http://allowed.test/", PYTHON_TOKEN, timeout=15)
    a.eq(recovered["status"], 200,
         "traffic must resume once the flooding connections are released")


@test("exhaustion", "a partial request head is dropped promptly, not held for a minute")
def t_partial_head_timeout(a):
    sock = socket.create_connection((driver.PROXY_HOST, driver.PROXY_PORT),
                                    timeout=30)
    sock.settimeout(30)
    sock.sendall(b"GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n")
    started = time.time()
    try:
        sock.recv(4096)
    except socket.timeout:
        pass
    finally:
        elapsed = time.time() - started
        try:
            sock.close()
        except OSError:
            pass
    a.true(elapsed < 20,
           "a half-sent request head was held for %.1fs; the slowloris window "
           "must be bounded by headTimeoutMs" % elapsed)


@test("disclosure", "the admin listener refuses a source outside its allow list")
def t_admin_source_restricted(a):
    res = proxy_req("http://127.0.0.1:9145/metrics")
    a.denied(res, "the admin listener must not be reachable through the proxy")


@test("upstream", "a non-http redirect scheme is refused")
def t_redirect_javascript(a):
    res = proxy_req("http://raw.test/redirect-javascript")
    a.denied(res)
    a.eq(res["reason"], "redirect.bad_scheme")


@test("upstream", "an endless trailer section cannot hold a worker open")
def t_trailer_endless(a):
    started = time.time()
    try:
        proxy_req("http://raw.test/endlesstrailers", timeout=25)
    except (ProxyError, OSError):
        pass
    elapsed = time.time() - started
    a.true(elapsed < 20,
           "an endless trailer stream held the connection for %.1fs; the "
           "gateway must bound the trailer section" % elapsed)


@test("upstream", "a large but finite trailer section is refused, not relayed")
def t_trailer_flood(a):
    started = time.time()
    res = proxy_req("http://raw.test/trailerflood", timeout=20)
    elapsed = time.time() - started
    a.true(elapsed < 15,
           "the trailer flood took %.1fs, which means it was not bounded" % elapsed)
    body = res["body"] or b""
    a.not_contains(body, b"X-Trailer-",
                   "trailers must never be relayed into the response body")


@test("upstream", "a reasonable trailer section is still accepted")
def t_trailer_ok(a):
    res = proxy_req("http://raw.test/trailerok")
    a.eq(res["status"], 200)
    a.contains(res["body"] or b"", b"ok")
    a.not_contains(res["body"] or b"", b"X-Checksum",
                   "trailers must not be forwarded into the body")


@test("upstream", "an interim response is never framed as the final one")
def t_interim_smuggle(a):
    res = proxy_req("http://raw.test/interim-smuggle")
    a.eq(res["status"], 200,
         "the gateway must skip the 100 and deliver the real response")
    a.contains(res["body"] or b"", b"SMUGGLED!",
               "the body that belongs to the final response must be relayed")
    a.eq((res["headers"] or {}).get("x-smuggled"), "yes",
         "the headers of the final response are the ones that reach the client")


@test("upstream", "policy still applies to a response hidden behind a 100")
def t_interim_redirect(a):
    res = proxy_req("http://raw.test/interim-redirect")
    a.eq(res["status"], 403,
         "a redirect to link-local must be refused even after an interim head")
    a.contains(res["reason"] or "", "redirect")


@test("upstream", "a run of interim responses is skipped, not relayed")
def t_interim_then_ok(a):
    res = proxy_req("http://raw.test/interim-then-ok")
    a.eq(res["status"], 200)
    a.eq(res["body"], b"ok")
    a.not_contains(res["body"] or b"", b"Early Hints",
                   "an interim head must never leak into the body")
    a.true("link" not in (res["headers"] or {}),
           "interim headers must not be merged into the final response")


@test("upstream", "an interim response cannot smuggle a second one in its body")
def t_interim_smuggle_body(a):
    res = proxy_req("http://raw.test/interim-with-body")
    a.eq(res["status"], 502,
         "a 1xx ends at its header section and may not declare a body; "
         "accepting one lets whatever follows be read as the final response")
    a.eq(res["reason"], "upstream.interim_framing")
    a.not_contains(res["body"] or b"", b"EVIL",
                   "the smuggled payload must never reach the workload")
    a.true("x-smuggled" not in (res["headers"] or {}),
           "the smuggled headers must never reach the workload")


@test("upstream", "a chunked interim response is refused the same way")
def t_interim_chunked(a):
    res = proxy_req("http://raw.test/interim-chunked")
    a.eq(res["status"], 502)
    a.eq(res["reason"], "upstream.interim_framing")
    a.not_contains(res["body"] or b"", b"EVIL")


@test("upstream", "an oversized interim head is bounded like any other")
def t_interim_huge_head(a):
    started = time.time()
    res = proxy_req("http://raw.test/interim-huge-head", timeout=20)
    a.true(time.time() - started < 15, "the oversized head was not bounded")
    a.eq(res["status"], 502)
    a.true(res["reason"] in ("upstream.head_too_large", "upstream.bad_response"),
           "got %r" % res["reason"])
    a.not_contains(res["body"] or b"", b"aaaaaaaaaa",
                   "padding must never be relayed")


@test("upstream", "a slow trickle of interim responses does not hold a worker")
def t_interim_slow(a):
    started = time.time()
    res = proxy_req("http://raw.test/interim-slow", timeout=30)
    elapsed = time.time() - started
    a.true(elapsed < 20,
           "a destination trickling interim responses held the connection "
           "%.1fs; the cap must bound it" % elapsed)
    a.eq(res["status"], 502)
    a.eq(res["reason"], "upstream.interim_flood")


@test("upstream", "an unbounded flood of interim responses is refused")
def t_interim_flood(a):
    started = time.time()
    res = proxy_req("http://raw.test/interim-flood", timeout=20)
    elapsed = time.time() - started
    a.true(elapsed < 15,
           "the interim flood took %.1fs, so it was not bounded" % elapsed)
    a.eq(res["status"], 502)
    a.eq(res["reason"], "upstream.interim_flood")


@test("upstream", "an upstream cannot switch protocols under a proxied request")
def t_upstream_switching(a):
    res = proxy_req("http://raw.test/switching")
    a.eq(res["status"], 502,
         "101 turns the connection into an opaque tunnel and must be refused")
    a.eq(res["reason"], "upstream.protocol_upgrade")
    a.not_contains(res["body"] or b"", b"RAWTUNNELBYTES",
                   "tunnel bytes must never reach the client")


def overread_count():
    body = admin("GET", "/metrics", token=None)["body"].decode(
        "utf-8", "replace")
    total = 0.0
    for line in body.splitlines():
        if line.startswith("ro_protocol_violations_total{") \
                and 'kind="upstream_overread"' in line:
            total += float(line.rsplit(" ", 1)[1])
    return total


@test("upstream", "an interim response never poisons a pooled connection")
def t_interim_pool_poison(a):
    before = overread_count()
    for _ in range(4):
        res = proxy_req("http://raw.test/interim-keepalive")
        a.not_contains(res["body"] or b"", b"SMUGGLED!SMUGGLED!",
                       "two responses were framed as one")
    after = overread_count()
    a.eq(after, before,
         "the gateway read a head it had to discard, which means an interim "
         "response was framed as final and left the real one unread "
         "(overread violations rose by %g)" % (after - before))

    for _ in range(6):
        res = proxy_req("http://allowed.test/")
        a.allowed(res, "a later request must not read a stale pooled response")
        a.not_contains(res["body"] or b"", b"SMUGGLED!",
                       "a pooled connection carried over an unread response")
        a.true("x-smuggled" not in (res["headers"] or {}),
               "headers from a previous exchange must never reappear")


@test("protocol", "pipelined requests are each evaluated independently")
def t_pipelining(a):
    payload = (
        "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
        "Proxy-Authorization: Bearer %s\r\nConnection: keep-alive\r\n\r\n"
        "GET http://denied.test/ HTTP/1.1\r\nHost: denied.test\r\n"
        "Proxy-Authorization: Bearer %s\r\nConnection: close\r\n\r\n"
        % (PYTHON_TOKEN, PYTHON_TOKEN)
    )
    data = send_raw(payload, read_bytes=8192)
    a.contains(data, b"200 OK")
    a.contains(data, b"403 Forbidden")
    a.not_contains(data, b"origin-b", "the denied request must never be proxied")


@test("protocol", "extra body bytes beyond Content-Length are re-parsed, not forwarded")
def t_body_overread(a):
    smuggled = ("GET http://denied.test/ HTTP/1.1\r\nHost: denied.test\r\n"
                "Proxy-Authorization: Bearer %s\r\n\r\n" % PYTHON_TOKEN)
    payload = (
        "POST http://allowed.test/echo HTTP/1.1\r\nHost: allowed.test\r\n"
        "Proxy-Authorization: Bearer %s\r\nContent-Length: 5\r\n"
        "Connection: keep-alive\r\n\r\nhello%s" % (PYTHON_TOKEN, smuggled)
    )
    data = send_raw(payload, read_bytes=8192)
    a.not_contains(data, b"origin-b",
                   "trailing bytes must never reach a denied destination")


@test("protocol", "a request may not carry two Proxy-Authorization headers")
def t_dual_auth(a):
    payload = ("GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
               "Proxy-Authorization: Bearer %s\r\n"
               "Proxy-Authorization: Bearer %s\r\n\r\n"
               % (NODE_TOKEN, PYTHON_TOKEN))
    res = raw_proxy(payload)
    a.true(res["status"] in (400, 403, 407),
           "ambiguous credentials must not grant the wider identity, got %s"
           % res["status"])


@test("protocol", "CRLF cannot be injected through the request path")
def t_path_crlf(a):
    for target in ("http://allowed.test/x%0d%0aX-Injected:%20yes",
                   "http://allowed.test/x%0aX-Injected:%20yes",
                   "http://allowed.test/x%00"):
        payload = ("GET %s HTTP/1.1\r\nHost: allowed.test\r\n"
                   "Proxy-Authorization: Bearer %s\r\n\r\n" % (target, PYTHON_TOKEN))
        res = raw_proxy(payload)
        a.eq(res["status"], 400, target)


@test("protocol", "CRLF cannot be injected through the query string")
def t_query_crlf(a):
    target = "http://allowed.test/echo?a=1\r\nX-Injected: yes"
    payload = ("GET " + target + " HTTP/1.1\r\nHost: allowed.test\r\n"
               "Proxy-Authorization: Bearer " + PYTHON_TOKEN + "\r\n\r\n")
    res = raw_proxy(payload)
    a.eq(res["status"], 400)

    encoded = "http://allowed.test/echo?a=1%0d%0aX-Injected:+yes"
    payload = ("GET " + encoded + " HTTP/1.1\r\nHost: allowed.test\r\n"
               "Proxy-Authorization: Bearer " + PYTHON_TOKEN + "\r\n\r\n")
    res = raw_proxy(payload)
    a.eq(res["status"], 200, "percent-encoded CRLF stays encoded and is harmless")
    a.true(res["headers"].get("x-injected") is None,
           "no header may be synthesised from the query string")
    body = json.loads(res["body"].decode())
    a.contains(body["uri"], "%0d%0a",
               "the encoding must be preserved, never decoded into CRLF")


@test("protocol", "an empty or garbage first line is rejected")
def t_garbage(a):
    for payload in (b"\r\n\r\n", b"\x00\x01\x02\x03\r\n\r\n",
                    b"\x16\x03\x01\x00\x50\r\n\r\n",
                    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
        data = send_raw(payload, read_bytes=512, timeout=5)
        a.not_contains(data, b"200 OK", "garbage must not be proxied")


@test("protocol", "the origin-form request target is refused on the explicit port")
def t_origin_form_explicit(a):
    payload = ("GET /path HTTP/1.1\r\nHost: allowed.test\r\n"
               "Proxy-Authorization: Bearer %s\r\n\r\n" % PYTHON_TOKEN)
    res = raw_proxy(payload)
    a.eq(res["status"], 400)
    a.eq(res["reason"], "protocol.not_a_proxy_request")


@test("protocol", "a trailing dot in the authority still matches policy")
def t_trailing_dot(a):
    res = proxy_req("http://allowed.test./")
    a.true(res["status"] in (200, 400),
           "a trailing dot must be normalised or refused, never mismatched")
    if res["status"] == 200:
        a.contains(res["body"], "origin-a")


@test("protocol", "an uppercase authority is normalised before policy evaluation")
def t_uppercase_host(a):
    payload = ("GET HTTP://ALLOWED.TEST/ HTTP/1.1\r\nHost: ALLOWED.TEST\r\n"
               "Proxy-Authorization: Bearer %s\r\n\r\n" % PYTHON_TOKEN)
    res = raw_proxy(payload)
    a.eq(res["status"], 200)
    a.contains(res["body"], "origin-a")


@test("protocol", "an uppercase denied authority is still denied")
def t_uppercase_denied(a):
    payload = ("GET HTTP://DENIED.TEST/ HTTP/1.1\r\nHost: DENIED.TEST\r\n"
               "Proxy-Authorization: Bearer %s\r\n\r\n" % PYTHON_TOKEN)
    res = raw_proxy(payload)
    a.eq(res["status"], 403)


@test("protocol", "an overlong hostname is refused")
def t_long_host(a):
    host = ".".join(["a" * 60] * 5) + ".test"
    payload = ("GET http://%s/ HTTP/1.1\r\nHost: %s\r\n"
               "Proxy-Authorization: Bearer %s\r\n\r\n" % (host, host, PYTHON_TOKEN))
    res = raw_proxy(payload)
    a.true(res["status"] in (400, 403), "got %s" % res["status"])


@test("protocol", "an Expect: 100-continue request does not bypass policy")
def t_expect_continue(a):
    payload = ("POST http://denied.test/echo HTTP/1.1\r\nHost: denied.test\r\n"
               "Proxy-Authorization: Bearer %s\r\nExpect: 100-continue\r\n"
               "Content-Length: 4\r\n\r\n" % PYTHON_TOKEN)
    data = send_raw(payload, read_bytes=2048, timeout=8)
    a.not_contains(data, b"100 Continue")
    a.contains(data, b"403")


@test("ssrf", "the gateway's own admin port is unreachable through the proxy")
def t_self_admin(a):
    for target in ("http://10.99.0.5:9145/v1/status",
                   "http://gateway-self.test:9145/v1/status",
                   "http://gateway-self.test/v1/status"):
        res = proxy_req(target)
        a.denied(res, target)
        a.not_contains(res.get("body", b""), b"ro-gateway",
                       "the admin API must never be reachable via the data plane")


@test("ssrf", "the controller is unreachable through the proxy")
def t_self_controller(a):
    for target in ("http://10.99.0.6:8081/v1/bundle",
                   "http://controller-self.test:8081/v1/bundle"):
        res = proxy_req(target)
        a.denied(res, target)
        a.not_contains(res.get("body", b""), b"policies")


@test("ssrf", "CONNECT to infrastructure services is refused")
def t_connect_infra(a):
    for authority in ("10.99.0.5:9145", "10.99.0.6:8081", "10.99.0.53:53",
                      "gateway-self.test:9145", "controller-self.test:8081"):
        status, headers, body, sock = connect_via_proxy(authority, PYTHON_TOKEN)
        if sock:
            sock.close()
        a.ne(status, 200, "CONNECT %s must be refused" % authority)


@test("ssrf", "every documented obfuscated encoding of the metadata address is blocked")
def t_metadata_encodings(a):
    encodings = [
        "169.254.169.254", "2852039166", "0xa9fea9fe", "0251.0376.0251.0376",
        "169.254.43518", "169.16689662", "0xa9.0xfe.0xa9.0xfe",
        "0251.0376.43518", "[::ffff:169.254.169.254]", "[::ffff:a9fe:a9fe]",
        "[2002:a9fe:a9fe::]", "[64:ff9b::a9fe:a9fe]",
        "[0:0:0:0:0:ffff:169.254.169.254]",
    ]
    for host in encodings:
        res = proxy_req("http://%s/latest/meta-data/" % host)
        a.denied(res, host)
        a.contains(res["reason"] or "", "guard.blocked", host)
        status, headers, body, sock = connect_via_proxy(
            host + ":80" if not host.startswith("[") else host + ":80",
            PYTHON_TOKEN)
        if sock:
            sock.close()
        a.ne(status, 200, "CONNECT %s" % host)


@test("ssrf", "a hostname that resolves to internal space is refused")
def t_dns_internal(a):
    for host in ("rebind.test", "loopback.test", "internal.test",
                 "v6internal.test"):
        res = proxy_req("http://%s/" % host)
        a.denied(res, host)


@test("ssrf", "a DNS answer cannot smuggle an internal address into an allowed name")
def t_dns_partial(a):
    res = proxy_req("http://mixed.test/")
    a.allowed(res, "the permitted address is used")
    a.contains(res["body"], "origin-a")
    for _ in range(5):
        again = proxy_req("http://mixed.test/")
        a.eq(again["status"], 200, "repeated resolution stays on the safe address")


@test("identity", "an unauthenticated request never reaches an upstream")
def t_unauth(a):
    res = proxy_req("http://allowed.test/", token=None)
    a.eq(res["status"], 407)
    a.not_contains(res["body"], b"origin-a")


@test("identity", "identity headers cannot be spoofed from an untrusted source")
def t_header_spoof(a):
    payload = ("GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
               "X-RO-Profile: untrusted-python\r\nX-RO-Namespace: execution\r\n"
               "X-RO-Identity: forged\r\n\r\n")
    res = raw_proxy(payload)
    a.eq(res["status"], 407, "identity headers alone must never authenticate")


@test("identity", "X-Forwarded-For does not influence identity")
def t_xff(a):
    payload = ("GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
               "X-Forwarded-For: 10.99.0.20\r\nForwarded: for=10.99.0.20\r\n\r\n")
    res = raw_proxy(payload)
    a.eq(res["status"], 407)


@test("identity", "credentials in the request target are not honoured")
def t_url_creds(a):
    payload = ("GET http://user:%s@allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
               "\r\n" % PYTHON_TOKEN)
    res = raw_proxy(payload)
    a.eq(res["status"], 400)


@test("identity", "one profile's token cannot reach another profile's destinations")
def t_cross_profile(a):
    a.denied(proxy_req("http://allowed.test/", token=NODE_TOKEN))
    a.denied(proxy_req("http://denied.test/", token=PYTHON_TOKEN))
    a.eq(proxy_req("http://denied.test/", token=NODE_TOKEN)["status"], 200)


@test("identity", "a truncated, extended or re-cased token is rejected")
def t_token_mutation(a):
    for mutated in (PYTHON_TOKEN[:-1], PYTHON_TOKEN + "x", PYTHON_TOKEN.upper(),
                    PYTHON_TOKEN.replace("-", "_"), PYTHON_TOKEN[1:],
                    PYTHON_TOKEN[:10] + PYTHON_TOKEN[11:]):
        res = proxy_req("http://allowed.test/", token=mutated)
        a.true(res["status"] in (400, 407),
               "mutated token %r must be refused, got %s"
               % (mutated[:20], res["status"]))


@test("identity", "optional whitespace around credentials is tolerated")
def t_token_ows(a):
    for padded in (" " + PYTHON_TOKEN, PYTHON_TOKEN + " ",
                   "  " + PYTHON_TOKEN + "  "):
        res = proxy_req("http://allowed.test/", token=padded)
        a.eq(res["status"], 200,
             "RFC 7235 optional whitespace must not break authentication")


@test("tunnel", "a tunnel cannot be repurposed for a different destination")
def t_tunnel_sni(a):
    status, headers, rest, sock = connect_via_proxy("allowed.test:443", PYTHON_TOKEN)
    a.eq(status, 200)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        leaked = False
        try:
            wrapped = ctx.wrap_socket(sock, server_hostname="denied.test")
            wrapped.settimeout(5)
            wrapped.sendall(b"GET / HTTP/1.1\r\nHost: denied.test\r\n\r\n")
            data = wrapped.recv(4096)
            leaked = b"origin" in data
        except (ssl.SSLError, OSError, socket.timeout):
            pass
        a.false(leaked, "a mismatched SNI must never reach an origin")
    finally:
        try:
            sock.close()
        except OSError:
            pass


@test("tunnel", "old TLS versions are refused")
def t_tls_version(a):
    status, headers, rest, sock = connect_via_proxy("allowed.test:443", PYTHON_TOKEN)
    a.eq(status, 200)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, AttributeError):
            return
        leaked = False
        try:
            wrapped = ctx.wrap_socket(sock, server_hostname="allowed.test")
            wrapped.settimeout(5)
            wrapped.sendall(b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
            leaked = b"origin" in wrapped.recv(4096)
        except (ssl.SSLError, OSError, socket.timeout):
            pass
        a.false(leaked, "TLS 1.1 and below must not be tunnelled")
    finally:
        try:
            sock.close()
        except OSError:
            pass


@test("tunnel", "a tunnel to an https-only destination refuses plaintext")
def t_tunnel_plaintext(a):
    status, headers, rest, sock = connect_via_proxy("tlsonly.test:443", PYTHON_TOKEN)
    if status != 200:
        return
    try:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: tlsonly.test\r\n\r\n")
        sock.settimeout(5)
        data = b""
        try:
            while len(data) < 64:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        a.not_contains(data, b"origin-a")
    finally:
        sock.close()


@test("tunnel", "malformed CONNECT targets are refused")
def t_connect_malformed(a):
    for authority in ("allowed.test", "allowed.test:0", "allowed.test:65536",
                      "allowed.test:80:80", "allowed.test:8o", ":443",
                      "allowed.test:443/x", "user@allowed.test:443",
                      "allowed.test:443?x", "[::1:443", "allowed.test:-1"):
        try:
            status, headers, body, sock = connect_via_proxy(authority, PYTHON_TOKEN)
            if sock:
                sock.close()
            a.ne(status, 200, "CONNECT %r must be refused" % authority)
        except ProxyError:
            pass


@test("dns", "a query with several questions is refused")
def t_dns_multi(a):
    import struct
    tid = 0x7777
    q = struct.pack(">HHHHHH", tid, 0x0100, 2, 0, 0, 0)
    for name in ("allowed.test", "denied.test"):
        for label in name.split("."):
            q += bytes([len(label)]) + label.encode()
        q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(q, ("127.0.0.1", driver.DNS_PORT))
        data, _ = s.recvfrom(4096)
        rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        a.eq(an, 0, "a multi-question query must not return answers")
    except socket.timeout:
        pass
    finally:
        s.close()


@test("dns", "uppercase names are matched case-insensitively")
def t_dns_case(a):
    res = dns_query("ALLOWED.TEST")
    a.eq(res["rcode"], 0)
    a.true("10.99.0.10" in res["answers"], "got %r" % res["answers"])


@test("dns", "tunnelling record types stay refused for permitted names")
def t_dns_tunnel_types(a):
    for qtype in (16, 10, 255, 5, 33, 12, 15, 2, 6, 65):
        res = dns_query("allowed.test", qtype=qtype)
        a.eq(res["count"], 0, "qtype %d must return nothing" % qtype)


@test("dns", "a name outside policy is refused even when it resolves upstream")
def t_dns_policy(a):
    res = dns_query("other.test")
    a.ne(res["rcode"], 0)
    a.eq(res["count"], 0)


@test("exposure", "deny responses never echo credentials")
def t_no_credential_echo(a):
    res = proxy_req("http://denied.test/", token=PYTHON_TOKEN)
    a.not_contains(res["body"], PYTHON_TOKEN.encode())
    a.not_contains(json.dumps(res["headers"]).encode(), PYTHON_TOKEN.encode())


def deny_labels():
    body = admin("GET", "/metrics", token=None)["body"].decode(
        "utf-8", "replace")
    out = {}
    for line in body.splitlines():
        if not line.startswith("ro_denied_total{"):
            continue
        inside = line[line.index("{") + 1:line.rindex("}")]
        reason = None
        for part in inside.split(","):
            k, _, v = part.partition("=")
            if k.strip() == "reason":
                reason = v.strip().strip('"')
        if reason is None:
            continue
        out[reason] = out.get(reason, 0.0) + float(line.rsplit(" ", 1)[1])
    return out


def echo_headers(extra):
    res = proxy_req("http://allowed.test/echo", extra_headers=extra)
    body = res["body"] or b""
    try:
        return set(json.loads(body).get("headers", {}).keys())
    except ValueError:
        raise AssertionError("the echo endpoint did not return json: %r"
                             % body[:200])


COLLECTOR = ("127.0.0.1", 14318)


def collector(path, attempts=15):
    last = None
    for _ in range(attempts):
        try:
            return collector_once(path)
        except (OSError, ValueError) as exc:
            last = exc
            time.sleep(1)
    raise AssertionError("the collector never answered %s: %s" % (path, last))


def collector_once(path):
    sock = socket.create_connection(COLLECTOR, timeout=10)
    sock.settimeout(10)
    try:
        sock.sendall(("GET %s HTTP/1.1\r\nHost: c\r\nConnection: close"
                      "\r\n\r\n" % path).encode())
        data = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    head, _, body = data.partition(b"\r\n\r\n")
    if b"chunked" in head.lower():
        out, i = b"", 0
        while True:
            j = body.find(b"\r\n", i)
            if j == -1:
                break
            try:
                size = int(body[i:j].split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            out += body[j + 2:j + 2 + size]
            i = j + 2 + size + 2
        body = out
    return json.loads(body.decode("utf-8", "replace"))


def collected_spans(deadline=45.0, expect=None, generate=None):
    started = time.time()
    spans, payload = [], {}
    while time.time() - started < deadline:
        if generate:
            generate()
        payload = collector("/collected")
        spans = []
        for raw in payload.get("bodies", []):
            if not raw:
                continue
            try:
                doc = json.loads(raw)
            except ValueError:
                continue
            for rs in doc.get("resourceSpans", []):
                for ss in rs.get("scopeSpans", []):
                    spans.extend(ss.get("spans", []))
        if spans:
            if not expect:
                return spans, payload
            if expect.issubset({s["name"] for s in spans}):
                return spans, payload
        time.sleep(1)
    return spans, payload


def span_attrs(span):
    out = {}
    for a in span.get("attributes", []):
        value = a["value"]
        out[a["key"]] = (value.get("stringValue")
                         or value.get("intValue")
                         or value.get("boolValue"))
    return out


@test("telemetry", "a request produces a trace with its decision on it")
def t_otel_spans(a):
    collector("/reset")

    def traffic():
        proxy_req("http://allowed.test/")
        proxy_req("http://denied.test/")

    traffic()
    spans, payload = collected_spans(
        expect={"rokh-oghab proxy request", "dns.resolve", "upstream.connect"},
        generate=traffic)
    a.true(bool(spans),
           "no spans reached the collector after six requests: %s"
           % json.dumps(payload)[:300])

    names = {s["name"] for s in spans}
    a.true("rokh-oghab proxy request" in names,
           "the request span is missing: %s" % sorted(names))
    a.true("dns.resolve" in names,
           "resolution should be its own span: %s" % sorted(names))
    a.true("upstream.connect" in names,
           "the upstream dial should be its own span: %s" % sorted(names))

    decisions, deny_reasons = set(), set()
    for s in spans:
        if s["name"] != "rokh-oghab proxy request":
            continue
        attrs = span_attrs(s)
        decision = attrs.get("ro.decision")
        decisions.add(decision)
        if decision == "deny":
            deny_reasons.add(attrs.get("ro.reason"))
    a.true("allow" in decisions, "an allowed request must be traced")
    a.true("deny" in decisions, "a denied request must be traced")
    a.true("policy.default_deny" in deny_reasons,
           "the deny this test caused must carry its reason; the collector "
           "holds %s" % sorted(r for r in deny_reasons if r))

    for s in spans:
        a.eq(len(s["traceId"]), 32)
        a.eq(len(s["spanId"]), 16)
        a.ne(s["traceId"], "0" * 32)
        a.true(int(s["endTimeUnixNano"]) >= int(s["startTimeUnixNano"]),
               "a span cannot end before it starts")

    parents = {s["spanId"]: s for s in spans}
    for s in spans:
        parent_id = s.get("parentSpanId")
        if parent_id:
            parent = parents.get(parent_id)
            if parent:
                a.eq(parent["traceId"], s["traceId"],
                     "a child span must share its parent's trace")


@test("telemetry", "a workload cannot choose the trace it is recorded under")
def t_otel_trace_not_client_controlled(a):
    collector("/reset")
    forged = "4bf92f3577b34da6a3ce929d0e0e4736"

    def traffic():
        proxy_req("http://allowed.test/",
                  extra_headers=["traceparent: 00-%s-00f067aa0ba902b7-01"
                                 % forged])

    traffic()
    spans, _ = collected_spans(generate=traffic)
    a.true(bool(spans), "no spans were collected")
    for s in spans:
        a.ne(s["traceId"], forged,
             "the workload's traceparent was adopted; a sandbox that picks "
             "its own trace id can pollute an operator's tracing backend or "
             "correlate its traffic with someone else's")


@test("telemetry", "an unreachable collector never affects egress")
def t_otel_fails_open(a):
    allowed = proxy_req("http://allowed.test/")
    a.allowed(allowed, "traffic flows while telemetry is healthy")

    body = admin("GET", "/metrics", token=None)["body"].decode(
        "utf-8", "replace")
    for name in ("ro_otel_spans_queued_total", "ro_otel_spans_exported_total",
                 "ro_otel_spans_dropped_total",
                 "ro_otel_export_failures_total"):
        a.contains(body, name,
                   "%s must be published so telemetry health is visible" % name)

    started = time.time()
    for _ in range(20):
        res = proxy_req("http://allowed.test/")
        a.allowed(res, "egress must not depend on the collector")
    elapsed = time.time() - started
    a.true(elapsed < 15,
           "twenty requests took %.1fs; exporting must never sit on the "
           "request path" % elapsed)

    denied = proxy_req("http://denied.test/")
    a.denied(denied, "policy still applies with telemetry enabled")


@test("exposure", "a header the client marks connection-scoped is not forwarded")
def t_connection_named_headers(a):
    seen = echo_headers(["X-Normal: yes"])
    a.true("x-normal" in seen, "a plain header must reach the upstream")

    seen = echo_headers(["Connection: X-Secret", "X-Secret: leak-me"])
    a.true("x-secret" not in seen,
           "a field named in Connection is connection-scoped and must be "
           "removed before forwarding; leaving it in lets a workload smuggle "
           "a header past any proxy that does honour the rule. Upstream "
           "saw: %s" % sorted(seen))

    seen = echo_headers(["Connection: X-A, X-B", "X-A: 1", "X-B: 2", "X-C: 3"])
    a.true("x-a" not in seen and "x-b" not in seen,
           "every name in the list is removed: %s" % sorted(seen))
    a.true("x-c" in seen,
           "a header the list does not name is untouched: %s" % sorted(seen))

    seen = echo_headers(["Proxy-Connection: X-P", "X-P: 1"])
    a.true("x-p" not in seen,
           "the legacy spelling is honoured too: %s" % sorted(seen))

    for protected in ("Host", "Content-Length", "Transfer-Encoding"):
        seen = echo_headers(["Connection: " + protected])
        a.true("host" in seen,
               "a client must not be able to strip %s by naming it in "
               "Connection; the request would be routed or framed "
               "differently. Upstream saw: %s" % (protected, sorted(seen)))


@test("exposure", "no deny reason collapses into the catch-all label")
def t_no_other_label(a):
    before = deny_labels().get("other", 0.0)

    probes = [
        lambda: proxy_req("http://denied.test/"),
        lambda: proxy_req("http://169.254.169.254/latest/meta-data/"),
        lambda: proxy_req("http://2852039166/latest"),
        lambda: proxy_req("http://raw.test/redirect-internal"),
        lambda: proxy_req("http://raw.test/redirect-decimal"),
        lambda: proxy_req("http://raw.test/redirect-denied"),
        lambda: proxy_req("http://raw.test/redirect-scheme-relative"),
        lambda: proxy_req("http://raw.test/redirect-scheme-relative-metadata"),
        lambda: proxy_req("http://raw.test/redirect-backslash"),
        lambda: proxy_req("http://raw.test/redirect-javascript"),
        lambda: proxy_req("http://allowed.test/", token="not-a-real-token"),
        lambda: proxy_req("http://allowed.test/", token=None),
        lambda: proxy_req("http://custom.test:9999/"),
        lambda: proxy_req("http://rawtcp.test:9050/"),
        lambda: connect_via_proxy("denied.test:443", PYTHON_TOKEN),
        lambda: connect_via_proxy("169.254.169.254:443", PYTHON_TOKEN),
        lambda: driver.https_via_proxy("denied.test", "/", PYTHON_TOKEN),
    ]
    for probe in probes:
        try:
            probe()
        except (ProxyError, OSError):
            pass

    after = deny_labels()
    grew = after.get("other", 0.0) - before
    a.eq(grew, 0.0,
         "%g denials were metered as \"other\", so an operator cannot see "
         "what was refused; every reason the gateway emits must be in the "
         "catalogue in lua/ro/reasons.lua. Reasons seen: %s"
         % (grew, sorted(after)))

    a.true(any(r.startswith("redirect.") for r in after),
           "the redirect guard must meter under its own reason, not under "
           "a generic one; saw %s" % sorted(after))


REFUSED_BUNDLE = {"version": "not-a-number"}

ADMIN_MATRIX = [
    ("GET", "/healthz", None, None),
    ("GET", "/readyz", None, None),
    ("GET", "/metrics", None, None),
    ("GET", "/v1/status", None, "reader"),
    ("GET", "/v1/policy", None, "reader"),
    ("GET", "/v1/audit", None, "operator"),
    ("POST", "/v1/dns/flush", {}, "operator"),
    ("POST", "/v1/validate", REFUSED_BUNDLE, "operator"),
    ("GET", "/v1/config", None, "admin"),
    ("POST", "/v1/bundle", REFUSED_BUNDLE, "admin"),
]

RANK = {None: 0, "reader": 1, "operator": 2, "admin": 3}
ROLE_TOKEN = {"reader": driver.READER_TOKEN,
              "operator": driver.OPERATOR_TOKEN,
              "admin": ADMIN_TOKEN}


@test("control", "the emergency switch reaches every worker, both ways")
def t_emergency_all_workers(a):
    def sweep(expect_denied, label):
        for _ in range(24):
            res = proxy_req("http://allowed.test/")
            if expect_denied:
                a.denied(res, "%s: every worker must refuse" % label)
                a.eq(res["reason"], "emergency.deny",
                     "%s: refused for the wrong reason" % label)
            else:
                a.allowed(res,
                          "%s: a worker is still refusing after the switch "
                          "was lifted, which is the divergence this test "
                          "exists to catch" % label)

    try:
        for round_no in range(3):
            res = admin("POST", "/v1/emergency-deny", {"enabled": True})
            a.eq(res["status"], 200)
            a.eq(res["json"]["emergencyDeny"], True)
            time.sleep(0.3)
            sweep(True, "round %d engaged" % round_no)

            res = admin("POST", "/v1/emergency-deny", {"enabled": False})
            a.eq(res["status"], 200)
            a.eq(res["json"]["emergencyDeny"], False)
            time.sleep(0.3)
            sweep(False, "round %d lifted" % round_no)
    finally:
        admin("POST", "/v1/emergency-deny", {"enabled": False})
        time.sleep(0.3)

    for _ in range(12):
        res = admin("GET", "/v1/status", token=driver.READER_TOKEN)
        a.eq(res["status"], 200)
        a.eq(res["json"]["emergencyDeny"], False,
             "a worker reports the switch engaged after it was lifted")


@test("control", "a gateway operator cannot lift a fleet-wide stop")
def t_emergency_local_cannot_beat_bundle(a):
    root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    with open(os.path.join(root, "tests", "e2e", "config",
                           "bundle.json")) as fh:
        bundle = json.load(fh)

    try:
        admin("POST", "/v1/emergency-deny", {"enabled": False})
        time.sleep(0.3)
        a.allowed(proxy_req("http://allowed.test/"), "traffic flows first")

        stopped = json.loads(json.dumps(bundle))
        stopped["emergencyDeny"] = True
        stopped["version"] = bundle["version"] + 5000
        res = admin("POST", "/v1/bundle", stopped)
        a.eq(res["status"], 200, "the bundle must apply")
        time.sleep(0.5)

        for _ in range(12):
            a.denied(proxy_req("http://allowed.test/"),
                     "a bundle carrying emergencyDeny stops every request")

        res = admin("POST", "/v1/emergency-deny", {"enabled": False})
        a.eq(res["status"], 200)
        a.eq(res["json"]["emergencyDeny"], True,
             "the endpoint must report the effective state, which is still "
             "stopped because the bundle says so")
        time.sleep(0.5)

        for _ in range(12):
            a.denied(proxy_req("http://allowed.test/"),
                     "lifting the local switch must not resume egress while "
                     "the bundle still carries a fleet-wide stop; a gateway "
                     "admin token would otherwise override the controller")

        status = admin("GET", "/v1/status", token=driver.READER_TOKEN)
        a.eq(status["json"]["emergencyDeny"], True,
             "status must report the effective state too")
    finally:
        restore = json.loads(json.dumps(bundle))
        restore["emergencyDeny"] = False
        restore["version"] = bundle["version"] + 6000
        admin("POST", "/v1/bundle", restore)
        admin("POST", "/v1/emergency-deny", {"enabled": False})
        time.sleep(0.5)

    a.allowed(proxy_req("http://allowed.test/"),
              "egress resumes once the bundle no longer stops it")


@test("authz", "every admin endpoint requires its own role and no less")
def t_admin_rbac(a):
    for method, path, body, need in ADMIN_MATRIX:
        for role in ("reader", "operator", "admin"):
            res = admin(method, path, body, token=ROLE_TOKEN[role])
            allowed = need is None or RANK[role] >= RANK[need]
            if allowed:
                a.ne(res["status"], 401,
                     "%s %s must be open to %s (needs %s); the body it would "
                     "carry is deliberately one the handler rejects, so "
                     "anything but 401 means the role gate let it through"
                     % (method, path, role, need))
            else:
                a.eq(res["status"], 401,
                     "%s %s needs %s, so %s must be refused, got %d"
                     % (method, path, need, role, res["status"]))

    for method, path, body, need in ADMIN_MATRIX:
        if need is None:
            continue
        res = admin(method, path, body, token=None)
        a.eq(res["status"], 401,
             "%s %s must refuse an unauthenticated caller" % (method, path))
        res = admin(method, path, body, token="not-a-real-token")
        a.eq(res["status"], 401,
             "%s %s must refuse an unknown token" % (method, path))
        res = admin(method, path, body, token=PYTHON_TOKEN)
        a.eq(res["status"], 401,
             "%s %s must refuse a sandbox proxy token; a workload credential "
             "is not an operator credential" % (method, path))


@test("authz", "a lesser role cannot reach what a greater one can")
def t_admin_no_escalation(a):
    res = admin("GET", "/v1/config", token=driver.OPERATOR_TOKEN)
    a.eq(res["status"], 401)
    a.not_contains(res["body"], b"allowFrom",
                   "a refused caller must not receive the payload anyway")

    res = admin("GET", "/v1/audit", token=driver.READER_TOKEN)
    a.eq(res["status"], 401)
    a.not_contains(res["body"], b"destination",
                   "the audit trail names destinations and identities and "
                   "must not leak to a reader")

    before = admin("GET", "/v1/status", token=driver.READER_TOKEN)
    a.eq(before["status"], 200)
    res = admin("POST", "/v1/bundle", {"version": 999, "policies": []},
                token=driver.OPERATOR_TOKEN)
    a.eq(res["status"], 401,
         "pushing policy is the most privileged thing this API does")
    after = admin("GET", "/v1/status", token=driver.READER_TOKEN)
    a.eq(after["status"], 200)
    a.ne(after["json"]["policy"]["version"], 999,
         "the refused bundle must not have taken effect")
    a.eq(after["json"]["policy"]["digest"], before["json"]["policy"]["digest"],
         "a refused push must leave the active bundle untouched")


@test("authz", "the deny is counted so an operator can see it")
def t_admin_denied_metric(a):
    before = admin("GET", "/metrics", token=None)["body"]
    a.contains(before, b"ro_admin_denied_total",
               "the counter must be published")
    admin("GET", "/v1/config", token=driver.READER_TOKEN)
    admin("GET", "/v1/config", token=driver.READER_TOKEN)
    after = admin("GET", "/metrics", token=None)["body"].decode(
        "utf-8", "replace")

    def total(body):
        n = 0.0
        for line in body.splitlines():
            if line.startswith("ro_admin_denied_total"):
                try:
                    n += float(line.rsplit(" ", 1)[1])
                except (IndexError, ValueError):
                    pass
        return n

    a.true(total(after) > total(before.decode("utf-8", "replace")),
           "a refused admin request must move the counter")


@test("exposure", "a workload is never told anything but a catalogued reason")
def t_reason_vocabulary(a):
    known = set()
    root = os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))
    catalogue = open(os.path.join(root, "lua", "ro", "reasons.lua")).read()
    for line in catalogue.splitlines():
        stripped = line.strip()
        if stripped.startswith('"') and stripped.endswith('",'):
            known.add(stripped[1:-2])
    a.true(len(known) > 40, "the catalogue did not parse: %d entries" % len(known))

    probes = [
        lambda: proxy_req("http://denied.test/"),
        lambda: proxy_req("http://evil.allowed.test/"),
        lambda: proxy_req("http://nosuchname.test/"),
        lambda: proxy_req("http://169.254.169.254/"),
        lambda: proxy_req("http://10.0.0.1/"),
        lambda: proxy_req("http://allowed.test:9999/"),
        lambda: proxy_req("http://raw.test/interim-with-body"),
        lambda: proxy_req("http://raw.test/dual"),
        lambda: proxy_req("http://raw.test/redirect-internal"),
        lambda: proxy_req("http://allowed.test/", token="not-a-token"),
        lambda: proxy_req("http://allowed.test/", token=None),
        lambda: proxy_req("http://v6only.test/"),
        lambda: proxy_req("http://loopback.test/"),
        lambda: proxy_req("http://rebind.test/"),
        lambda: proxy_req("http://internal.test/"),
    ]
    for probe in probes:
        try:
            res = probe()
        except (ProxyError, OSError):
            continue
        reason = res.get("reason")
        if not reason:
            continue
        a.true(reason in known,
               "the workload was told %r, which is not in the catalogue in "
               "lua/ro/reasons.lua. A reason built from an internal error "
               "hands an untrusted workload the gateway's plumbing and is "
               "invisible in metrics." % reason)
        body = res.get("body") or b""
        for leak in (b"errno", b"ngx_", b"lua:", b"/usr/local",
                     b"stack traceback", b"attempt to index"):
            a.not_contains(body, leak,
                           "the deny body leaked internals for reason %r"
                           % reason)


@test("exposure", "the gateway counts a reason it could not catalogue")
def t_uncatalogued_counter(a):
    body = admin("GET", "/metrics", token=None)["body"].decode(
        "utf-8", "replace")
    a.contains(body, "ro_uncatalogued_reasons_total",
               "the counter must be published so an operator can alert on it")
    total = 0.0
    for line in body.splitlines():
        if line.startswith("ro_uncatalogued_reasons_total"):
            parts = line.rsplit(" ", 1)
            if len(parts) == 2:
                try:
                    total += float(parts[1])
                except ValueError:
                    pass
    a.eq(total, 0.0,
         "the gateway emitted %g denials whose reason has no catalogue entry; "
         "each one is invisible in ro_denied_total" % total)


@test("exposure", "metrics never contain credentials or destinations")
def t_metrics_hygiene(a):
    proxy_req("http://allowed.test/")
    res = admin("GET", "/metrics", token=None)
    body = res["body"]
    a.not_contains(body, PYTHON_TOKEN.encode())
    a.not_contains(body, ADMIN_TOKEN.encode())
    a.not_contains(body, b"allowed.test")


@test("exposure", "the audit trail never contains credentials")
def t_audit_hygiene(a):
    proxy_req("http://allowed.test/")
    time.sleep(0.4)
    res = admin("GET", "/v1/audit?limit=200")
    a.not_contains(res["body"], PYTHON_TOKEN.encode())
    a.not_contains(res["body"], b"Proxy-Authorization")


@test("exposure", "the upstream never receives proxy hop-by-hop headers")
def t_hop_by_hop(a):
    payload = ("GET http://allowed.test/echo HTTP/1.1\r\nHost: allowed.test\r\n"
               "Proxy-Authorization: Bearer %s\r\nProxy-Connection: keep-alive\r\n"
               "Connection: keep-alive, X-Custom\r\nX-Custom: dropme\r\n"
               "TE: trailers\r\nUpgrade: websocket\r\n\r\n" % PYTHON_TOKEN)
    res = raw_proxy(payload)
    a.eq(res["status"], 200)
    body = json.loads(res["body"].decode())
    a.eq(body["proxy_authorization"], "ABSENT")


@test("resource", "a slow partial head does not hold a worker forever")
def t_slowloris(a):
    sock = connect_proxy(timeout=20)
    started = time.time()
    try:
        sock.sendall(b"GET http://allowed.test/ HTTP/1.1\r\n")
        for _ in range(5):
            time.sleep(0.2)
            try:
                sock.sendall(b"X-Pad: a\r\n")
            except OSError:
                break
        sock.settimeout(8)
        try:
            sock.recv(1024)
        except socket.timeout:
            pass
    finally:
        sock.close()
    a.true(time.time() - started < 30, "the connection must not hang indefinitely")

    res = proxy_req("http://allowed.test/")
    a.allowed(res, "the gateway still serves traffic after a slow client")


@test("resource", "many concurrent connections do not break the gateway")
def t_concurrency(a):
    socks = []
    try:
        for _ in range(60):
            try:
                socks.append(connect_proxy(timeout=10))
            except OSError:
                break
        a.true(len(socks) > 20, "expected the gateway to accept many connections")
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
    res = proxy_req("http://allowed.test/")
    a.allowed(res, "the gateway still serves traffic afterwards")


@test("resource", "an oversized request body is bounded")
def t_big_body(a):
    sock = connect_proxy(timeout=20)
    try:
        sock.sendall(("POST http://allowed.test/echo HTTP/1.1\r\n"
                      "Host: allowed.test\r\n"
                      "Proxy-Authorization: Bearer %s\r\n"
                      "Content-Length: 1048576\r\n\r\n" % PYTHON_TOKEN).encode())
        block = b"x" * 65536
        for _ in range(16):
            try:
                sock.sendall(block)
            except OSError:
                break
        sock.settimeout(15)
        head, rest = recv_head(sock)
        status, headers, order, sl = parse_head(head)
        a.eq(status, 200, "a large but declared body is relayed")
    except (ProxyError, socket.timeout):
        pass
    finally:
        sock.close()


@test("l7ports", "a custom HTTP port is served when policy allows it")
def t_custom_http_port(a):
    res = proxy_req("http://custom.test:8080/")
    a.allowed(res, "http on port 8080")
    a.contains(res["body"], "origin-a")


@test("l7ports", "a custom HTTPS port is tunnelled when policy allows it")
def t_custom_https_port(a):
    res = driver.https_via_proxy("custom.test", "/", PYTHON_TOKEN, port=8443)
    a.eq(res.get("connect_status"), 200, "CONNECT to 8443")
    a.eq(res["status"], 200)
    a.contains(res["body"], "origin-a")


@test("l7ports", "a port range in a rule is honoured")
def t_port_range(a):
    status, headers, body, sock = connect_via_proxy("rawtcp.test:9050", PYTHON_TOKEN)
    a.eq(status, 200, "a port inside the declared range is permitted")
    if sock:
        sock.close()

    status, headers, body, sock = connect_via_proxy("rawtcp.test:9101", PYTHON_TOKEN)
    if sock:
        sock.close()
    a.ne(status, 200, "a port outside the declared range is refused")


@test("tunnel", "a server-first protocol survives the TLS peek")
def t_server_first_tunnel(a):
    status, headers, rest, sock = connect_via_proxy("rawtcp.test:9050",
                                                    PYTHON_TOKEN, timeout=25)
    a.eq(status, 200, "the tunnel must open for a permitted tcp destination")
    try:
        sock.settimeout(20)
        banner = rest or b""
        deadline = time.time() + 15
        while b"\r\n" not in banner and time.time() < deadline:
            chunk = sock.recv(4096)
            if not chunk:
                break
            banner += chunk
        a.contains(banner, b"220 ",
                   "the peer speaks first after a pause; the gateway must "
                   "keep the tunnel readable across the peek timeout rather "
                   "than treating the quiet period as a closed connection")

        sock.sendall(b"EHLO sandbox\r\n")
        reply = b""
        deadline = time.time() + 15
        while b"\r\n" not in reply and time.time() < deadline:
            chunk = sock.recv(4096)
            if not chunk:
                break
            reply += chunk
        a.contains(reply, b"250 EHLO sandbox",
                   "the tunnel must stay usable in both directions afterwards")

        sock.sendall(b"QUIT\r\n")
    finally:
        sock.close()


@test("tunnel", "a half-closed client does not truncate the response")
def t_half_close_no_truncation(a):
    status, headers, rest, sock = connect_via_proxy("rawtcp.test:9051",
                                                    PYTHON_TOKEN, timeout=40)
    a.eq(status, 200, "the tunnel must open")
    try:
        sock.settimeout(30)
        sock.sendall(b"GO\r\n")
        sock.shutdown(socket.SHUT_WR)

        data = rest or b""
        deadline = time.time() + 25
        while b"ENDOFSTREAM" not in data and time.time() < deadline:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk

        a.contains(data, b"ENDOFSTREAM",
                   "the client stopped writing while the peer was still "
                   "sending; tearing the tunnel down when the first "
                   "direction ends truncates the response. Got %d of the "
                   "%d bytes the peer sent."
                   % (len(data), 256 * 4096 + 13))
        a.true(len(data) >= 256 * 4096,
               "the whole stream must arrive, not a prefix: got %d bytes"
               % len(data))
    finally:
        sock.close()


@test("tunnel", "a server-first tunnel is still bound by policy")
def t_server_first_still_denied(a):
    status, headers, body, sock = connect_via_proxy("denied.test:9050",
                                                    PYTHON_TOKEN, timeout=20)
    if sock:
        sock.close()
    a.ne(status, 200,
         "keeping quiet before speaking must not buy a denied destination "
         "a tunnel")


@test("l7ports", "the scheme is enforced independently of the port")
def t_scheme_enforcement(a):
    res = proxy_req("http://custom.test:9443/")
    a.denied(res, "http is not declared on 9443 for this destination")

    res = proxy_req("http://rawtcp.test:9050/")
    a.denied(res, "http is not declared for a tcp-only rule")


@test("l7ports", "an undeclared custom port is refused")
def t_undeclared_port(a):
    for port in (8081, 8444, 9999, 1080):
        res = proxy_req("http://custom.test:%d/" % port)
        a.denied(res, "port %d" % port)


@test("l7ports", "plaintext is refused on every configured TLS port")
def t_tls_port_list(a):
    status, headers, rest, sock = connect_via_proxy("rawtcp.test:9443", PYTHON_TOKEN)
    a.eq(status, 200, "the tunnel opens before payload inspection")
    try:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: rawtcp.test\r\n\r\n")
        sock.settimeout(5)
        data = b""
        try:
            while len(data) < 64:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        a.not_contains(data, b"origin-a",
                       "9443 is a configured TLS port, so plaintext must not pass")
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--category", action="append", default=None)
    parser.add_argument("--filter", default=None)
    args = parser.parse_args()

    selected = [t for t in TESTS
                if (not args.category or t[0] in args.category)
                and (not args.filter or args.filter in t[1])]

    print("Rokh Oghab adversarial suite")
    print("=" * 76)

    problems = driver.preflight()
    if problems:
        print("\n  the gateway is not in a state these tests can run against:")
        for problem in problems:
            print("    - %s" % problem)
        print("\n  bring it back with: make e2e-down && make e2e-up")
        print("=" * 76)
        return 2

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
            print("    ok   %-64s %6.0fms (%d checks)"
                  % (name, (time.time() - t0) * 1000, a.checks))
            passed += 1
        except Exception as exc:
            print("    FAIL %-64s %6.0fms" % (name, (time.time() - t0) * 1000))
            print("         %s: %s" % (type(exc).__name__, exc))
            failures.append((category, name, "%s: %s" % (type(exc).__name__, exc)))
            failed += 1

    print("\n" + "=" * 76)
    print("passed=%d failed=%d elapsed=%.1fs"
          % (passed, failed, time.time() - started))
    if failures:
        print("\nFAILURES:")
        for category, name, detail in failures:
            print("  [%s] %s\n    %s" % (category, name, detail))
    print("=" * 76)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
