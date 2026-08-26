import argparse
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time

PROXY_HOST = os.environ.get("RO_PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("RO_PROXY_PORT", "13128"))
ADMIN_HOST = os.environ.get("RO_ADMIN_HOST", "127.0.0.1")
ADMIN_PORT = int(os.environ.get("RO_ADMIN_PORT", "19145"))
DNS_HOST = os.environ.get("RO_DNS_HOST", "127.0.0.1")
DNS_PORT = int(os.environ.get("RO_DNS_PORT", "15353"))
ADMIN_TOKEN = os.environ.get("RO_ADMIN_TOKEN", "ro-e2e-admin-token-000000000001")

READER_TOKEN = os.environ.get("RO_ADMIN_READER_TOKEN",
                              "ro-e2e-reader-token-00000000001")
OPERATOR_TOKEN = os.environ.get("RO_ADMIN_OPERATOR_TOKEN",
                                "ro-e2e-operator-token-000000001")

PYTHON_TOKEN = "ro-e2e-python-token-0000000001"
NODE_TOKEN = "ro-e2e-node-token-00000000001"
STRICT_TOKEN = "ro-e2e-strict-token-0000000001"

TIMEOUT = float(os.environ.get("RO_TEST_TIMEOUT", "15"))


class ProxyError(Exception):
    pass


def connect_proxy(timeout=TIMEOUT):
    s = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=timeout)
    s.settimeout(timeout)
    return s


def recv_head(sock, limit=65536):
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > limit:
            raise ProxyError("response head too large")
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            raise ProxyError("timeout reading response head")
        if not chunk:
            if not buf:
                raise ProxyError("connection closed with no response")
            raise ProxyError("connection closed mid-head: %r" % buf[:200])
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head.decode("latin-1"), rest


def parse_head(head):
    lines = head.split("\r\n")
    status_line = lines[0]
    parts = status_line.split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    headers = {}
    order = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        key = k.strip().lower()
        order.append((key, v.strip()))
        headers.setdefault(key, v.strip())
    return status, headers, order, status_line


def read_body(sock, headers, rest, method="GET", status=200):
    if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
        return rest
    te = headers.get("transfer-encoding", "").lower()
    if te == "chunked":
        data = b""
        buf = rest
        while True:
            while b"\r\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    return data
                buf += chunk
            line, _, buf = buf.partition(b"\r\n")
            size = int(line.split(b";")[0], 16)
            if size == 0:
                while True:
                    while b"\r\n" not in buf:
                        chunk = sock.recv(4096)
                        if not chunk:
                            return data
                        buf += chunk
                    trailer, _, buf = buf.partition(b"\r\n")
                    if trailer == b"":
                        return data
            while len(buf) < size + 2:
                chunk = sock.recv(65536)
                if not chunk:
                    return data
                buf += chunk
            data += buf[:size]
            buf = buf[size + 2:]
    if "content-length" in headers:
        want = int(headers["content-length"])
        data = rest
        while len(data) < want:
            chunk = sock.recv(min(65536, want - len(data)))
            if not chunk:
                break
            data += chunk
        return data[:want]
    data = rest
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def raw_proxy(payload, timeout=TIMEOUT, read_all=False):
    sock = connect_proxy(timeout)
    try:
        sock.sendall(payload if isinstance(payload, bytes) else payload.encode())
        head, rest = recv_head(sock)
        status, headers, order, status_line = parse_head(head)
        body = read_body(sock, headers, rest)
        return {
            "status": status,
            "headers": headers,
            "order": order,
            "status_line": status_line,
            "body": body,
            "reason": headers.get("x-rokh-oghab-reason"),
        }
    finally:
        try:
            sock.close()
        except OSError:
            pass


def http_via_proxy(url, token=None, method="GET", body=None, extra_headers=None,
                   host_header=None, version="HTTP/1.1", timeout=TIMEOUT):
    scheme, _, rest = url.partition("://")
    authority, _, path = rest.partition("/")
    path = "/" + path
    lines = ["%s %s %s" % (method, url, version)]
    lines.append("Host: %s" % (host_header if host_header is not None else authority))
    if token:
        lines.append("Proxy-Authorization: Bearer %s" % token)
    if body is not None:
        lines.append("Content-Length: %d" % len(body))
    lines.append("Connection: close")
    if extra_headers:
        lines.extend(extra_headers)
    payload = "\r\n".join(lines) + "\r\n\r\n"
    if body is not None:
        payload += body
    return raw_proxy(payload, timeout=timeout)


def connect_via_proxy(authority, token=None, timeout=TIMEOUT, extra=None):
    sock = connect_proxy(timeout)
    lines = ["CONNECT %s HTTP/1.1" % authority, "Host: %s" % authority]
    if token:
        lines.append("Proxy-Authorization: Bearer %s" % token)
    if extra:
        lines.extend(extra)
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    head, rest = recv_head(sock)
    status, headers, order, status_line = parse_head(head)
    if status != 200:
        body = read_body(sock, headers, rest)
        sock.close()
        return status, headers, body, None
    return status, headers, rest, sock


def tls_over_tunnel(sock, server_hostname, timeout=TIMEOUT):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    wrapped = ctx.wrap_socket(sock, server_hostname=server_hostname)
    wrapped.settimeout(timeout)
    return wrapped


def https_via_proxy(host, path="/", token=None, sni=None, port=443, timeout=TIMEOUT,
                    min_version=None, max_version=None):
    status, headers, rest, sock = connect_via_proxy("%s:%d" % (host, port), token,
                                                    timeout=timeout)
    if status != 200:
        return {"status": status, "connect_status": status, "body": rest,
                "reason": headers.get("x-rokh-oghab-reason")}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if min_version:
            ctx.minimum_version = min_version
        if max_version:
            ctx.maximum_version = max_version
        tls_sock = ctx.wrap_socket(sock, server_hostname=sni or host)
        tls_sock.settimeout(timeout)
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
               % (path, host)).encode()
        tls_sock.sendall(req)
        head, restb = recv_head(tls_sock)
        st, hdrs, order, sl = parse_head(head)
        body = read_body(tls_sock, hdrs, restb)
        return {"status": st, "connect_status": 200, "headers": hdrs, "body": body}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def admin(method, path, body=None, token=ADMIN_TOKEN, timeout=TIMEOUT):
    sock = socket.create_connection((ADMIN_HOST, ADMIN_PORT), timeout=timeout)
    sock.settimeout(timeout)
    try:
        payload = json.dumps(body) if body is not None else None
        lines = ["%s %s HTTP/1.1" % (method, path),
                 "Host: %s:%d" % (ADMIN_HOST, ADMIN_PORT),
                 "Connection: close"]
        if token:
            lines.append("Authorization: Bearer %s" % token)
        if payload is not None:
            lines.append("Content-Type: application/json")
            lines.append("Content-Length: %d" % len(payload))
        data = "\r\n".join(lines) + "\r\n\r\n" + (payload or "")
        sock.sendall(data.encode())
        head, rest = recv_head(sock)
        status, headers, order, sl = parse_head(head)
        raw = read_body(sock, headers, rest, method=method, status=status)
        try:
            parsed = json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            parsed = None
        return {"status": status, "headers": headers, "body": raw, "json": parsed}
    finally:
        sock.close()


def dns_query_host(name, qtype=1, host=DNS_HOST, port=DNS_PORT, timeout=5, tid=None):
    if tid is None:
        tid = int.from_bytes(os.urandom(2), "big")
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (host, port))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    return {"id": rid, "rcode": flags & 0x0F, "count": an, "answers": []}


def dns_query(name, qtype=1, tid=4321, container="ro-e2e-client"):
    import subprocess
    out = subprocess.run(
        ["docker", "exec", container, "/usr/local/openresty/bin/resty",
         "-I", "/usr/local/rokh-oghab/lua", "/opt/dnsq.lua",
         name, str(qtype), "10.99.0.5", "5353", str(tid)],
        capture_output=True, text=True, timeout=30)
    text = out.stdout.strip().splitlines()
    if not text:
        raise ProxyError("dns helper produced no output: %s" % out.stderr[:300])
    return json.loads(text[-1])


TESTS = []


def test(category, name):
    def deco(fn):
        TESTS.append((category, name, fn))
        return fn
    return deco


class Assert:
    def __init__(self):
        self.checks = 0

    def true(self, cond, msg=""):
        self.checks += 1
        if not cond:
            raise AssertionError(msg or "expected true")

    def eq(self, got, want, msg=""):
        self.checks += 1
        if got != want:
            raise AssertionError("%s: got %r, want %r" % (msg or "value", got, want))

    def ne(self, got, other, msg=""):
        self.checks += 1
        if got == other:
            raise AssertionError("%s: both %r" % (msg or "value", got))

    def false(self, cond, msg=""):
        self.checks += 1
        if cond:
            raise AssertionError(msg or "expected false")

    def contains(self, hay, needle, msg=""):
        self.checks += 1
        if isinstance(hay, bytes) and isinstance(needle, str):
            needle = needle.encode()
        if needle not in hay:
            raise AssertionError("%s: %r not in %r"
                                 % (msg or "substring", needle, hay[:400]))
    def not_contains(self, hay, needle, msg=""):
        self.checks += 1
        if isinstance(hay, bytes) and isinstance(needle, str):
            needle = needle.encode()
        if needle in hay:
            raise AssertionError("%s: %r unexpectedly in %r"
                                 % (msg or "substring", needle, hay[:400]))

    def denied(self, res, msg="", allow_status=(403, 407, 429, 400)):
        self.checks += 1
        status = res.get("connect_status", res.get("status"))
        if status in (502, 503):
            raise AssertionError(
                "%s: got status %s, which means the gateway could not reach the "
                "destination rather than that policy refused it; if that is the "
                "expected outcome use refused_upstream(), and if it is not, the "
                "request escaped policy and merely failed to connect"
                % (msg or "request", status))
        if status not in allow_status:
            raise AssertionError("%s: expected denial, got status %s body %r"
                                 % (msg or "request", status,
                                    res.get("body", b"")[:200]))

    def refused_upstream(self, res, msg=""):
        self.checks += 1
        status = res.get("connect_status", res.get("status"))
        if status not in (502, 503):
            raise AssertionError("%s: expected an upstream failure, got %s"
                                 % (msg or "request", status))

    def allowed(self, res, msg=""):
        self.checks += 1
        if res.get("status") != 200:
            raise AssertionError("%s: expected 200, got %s reason=%s body=%r"
                                 % (msg or "request", res.get("status"),
                                    res.get("reason"), res.get("body", b"")[:200]))


@test("integration", "allowed hostname over plain HTTP is proxied")
def t_allow_http(a):
    res = http_via_proxy("http://allowed.test/", PYTHON_TOKEN)
    a.allowed(res)
    a.contains(res["body"], "origin-a")
    a.contains(res["body"], '"host":"allowed.test"')


@test("integration", "proxy credentials are never forwarded upstream")
def t_credentials_stripped(a):
    res = http_via_proxy("http://allowed.test/echo", PYTHON_TOKEN)
    a.allowed(res)
    payload = json.loads(res["body"].decode())
    a.eq(payload["proxy_authorization"], "ABSENT",
         "Proxy-Authorization must not reach the origin")
    a.not_contains(res["body"], PYTHON_TOKEN)


@test("integration", "request target is rewritten to origin form")
def t_origin_form(a):
    res = http_via_proxy("http://allowed.test/echo?x=1", PYTHON_TOKEN)
    a.allowed(res)
    payload = json.loads(res["body"].decode())
    a.eq(payload["uri"], "/echo?x=1")
    a.eq(payload["host"], "allowed.test")


@test("integration", "hostname suffix rules match subdomains")
def t_suffix(a):
    for host in ("api.allowed.test", "files.allowed.test", "deep.files.allowed.test"):
        res = http_via_proxy("http://%s/" % host, PYTHON_TOKEN)
        a.allowed(res, host)


@test("integration", "POST with a content-length body is relayed intact")
def t_post_body(a):
    body = "x" * 4096
    res = http_via_proxy("http://allowed.test/echo", PYTHON_TOKEN,
                         method="POST", body=body)
    a.allowed(res)
    payload = json.loads(res["body"].decode())
    a.eq(payload["body_length"], 4096)
    a.eq(payload["body_sha"], hashlib.md5(body.encode()).hexdigest())


@test("integration", "chunked request bodies are re-framed and relayed intact")
def t_chunked_request(a):
    body = "y" * 3000
    chunks = b""
    step = 700
    for i in range(0, len(body), step):
        piece = body[i:i + step].encode()
        chunks += ("%x\r\n" % len(piece)).encode() + piece + b"\r\n"
    chunks += b"0\r\n\r\n"
    payload = (
        "POST http://allowed.test/echo HTTP/1.1\r\n"
        "Host: allowed.test\r\n"
        "Proxy-Authorization: Bearer %s\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n" % PYTHON_TOKEN
    ).encode() + chunks
    res = raw_proxy(payload)
    a.allowed(res)
    parsed = json.loads(res["body"].decode())
    a.eq(parsed["body_length"], 3000)
    a.eq(parsed["body_sha"], hashlib.md5(body.encode()).hexdigest())


@test("integration", "large response bodies stream correctly")
def t_big_response(a):
    res = http_via_proxy("http://allowed.test/big?n=3000000", PYTHON_TOKEN,
                         timeout=30)
    a.allowed(res)
    a.eq(len(res["body"]), 3000000)
    a.eq(res["body"][:10], b"AAAAAAAAAA")


@test("integration", "chunked responses are relayed")
def t_chunked_response(a):
    res = http_via_proxy("http://allowed.test/chunked?n=50", PYTHON_TOKEN)
    a.allowed(res)
    a.contains(res["body"], "chunk-0001")
    a.contains(res["body"], "chunk-0050")


@test("integration", "close-delimited responses are relayed")
def t_until_close(a):
    res = http_via_proxy("http://allowed.test/noclen", PYTHON_TOKEN)
    a.allowed(res)
    a.contains(res["body"], "close-delimited-body")


@test("integration", "HEAD responses carry no body")
def t_head(a):
    res = http_via_proxy("http://allowed.test/", PYTHON_TOKEN, method="HEAD")
    a.eq(res["status"], 200)
    a.eq(res["body"], b"")


@test("integration", "upstream status codes are preserved")
def t_status_passthrough(a):
    for code in (201, 404, 418, 500):
        res = http_via_proxy("http://allowed.test/status?code=%d" % code,
                             PYTHON_TOKEN)
        a.eq(res["status"], code, "status %d" % code)


@test("integration", "CONNECT tunnel carries real TLS to the origin")
def t_connect_tls(a):
    res = https_via_proxy("allowed.test", "/", PYTHON_TOKEN)
    a.eq(res.get("connect_status"), 200)
    a.eq(res["status"], 200)
    a.contains(res["body"], "origin-a")
    a.contains(res["body"], '"sni":"allowed.test"')


@test("integration", "HTTP/1.0 requests are supported")
def t_http10(a):
    payload = (
        "GET http://allowed.test/ HTTP/1.0\r\n"
        "Proxy-Authorization: Bearer %s\r\n\r\n" % PYTHON_TOKEN
    )
    res = raw_proxy(payload)
    a.allowed(res)
    a.contains(res["body"], "origin-a")


@test("integration", "keep-alive connections serve several requests")
def t_keepalive(a):
    sock = connect_proxy()
    try:
        for i in range(3):
            req = ("GET http://allowed.test/echo?i=%d HTTP/1.1\r\n"
                   "Host: allowed.test\r\n"
                   "Proxy-Authorization: Bearer %s\r\n"
                   "Connection: keep-alive\r\n\r\n" % (i, PYTHON_TOKEN))
            sock.sendall(req.encode())
            head, rest = recv_head(sock)
            status, headers, order, sl = parse_head(head)
            a.eq(status, 200, "request %d on keep-alive connection" % i)
            body = read_body(sock, headers, rest)
            parsed = json.loads(body.decode())
            a.eq(parsed["uri"], "/echo?i=%d" % i)
    finally:
        sock.close()


@test("integration", "source-address identity works without a token")
def t_source_identity(a):
    import subprocess
    out = subprocess.run(
        ["docker", "exec", "ro-e2e-client", "curl", "-sS", "-m", "10",
         "-x", "http://10.99.0.5:3128", "http://allowed.test/",
         "-w", "\n%{http_code}"],
        capture_output=True, text=True, timeout=30)
    a.contains(out.stdout, "origin-a")
    a.contains(out.stdout, "200")


def in_client(script, timeout=40):
    import subprocess
    return subprocess.run(
        ["docker", "exec", "ro-e2e-client",
         "/usr/local/openresty/bin/resty", "-e", script],
        capture_output=True, text=True, timeout=timeout)


TRANSPARENT_TLS = "10.99.0.5:3443"
TRANSPARENT_HTTP = "10.99.0.5:3080"


def client_hello(sni):
    name = sni.encode()
    server_name = b"\x00" + struct.pack(">H", len(name)) + name
    name_list = struct.pack(">H", len(server_name)) + server_name
    sni_ext = struct.pack(">HH", 0x0000, len(name_list)) + name_list
    versions = b"\x02\x03\x03"
    ver_ext = struct.pack(">HH", 0x002b, len(versions)) + versions
    exts = sni_ext + ver_ext
    body = (b"\x03\x03" + b"\x41" * 32 + b"\x00"
            + struct.pack(">H", 2) + b"\x13\x01"
            + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def transparent_tls_probe(sni):
    hello = client_hello(sni)
    literal = ",".join(str(b) for b in hello)
    script = """
local sock = ngx.socket.tcp()
sock:settimeout(8000)
local ok, err = sock:connect("10.99.0.5", 3443)
if not ok then ngx.print("connect-failed:", err) return end
local bytes = {%s}
local buf = {}
for i = 1, #bytes do buf[i] = string.char(bytes[i]) end
local sent, serr = sock:send(table.concat(buf))
if not sent then ngx.print("send-failed:", serr) return end
local data, rerr, partial = sock:receive(64)
if data then ngx.print("got-bytes:", #data)
elseif partial and #partial > 0 then ngx.print("got-bytes:", #partial)
else ngx.print("closed:", tostring(rerr)) end
sock:close()
""" % literal
    return in_client(script)


@test("transparent", "a permitted SNI is tunnelled without any proxy settings")
def t_transparent_tls_allowed(a):
    out = transparent_tls_probe("allowed.test")
    a.true("connect-failed" not in out.stdout,
           "the transparent TLS listener must accept the connection: %s"
           % out.stdout)
    a.contains(out.stdout, "got-bytes",
               "a permitted SNI must be spliced through to the origin and get "
               "a reply, not torn down; got %r" % out.stdout)


@test("transparent", "an SNI outside the policy is refused on the TLS listener")
def t_transparent_tls_denied(a):
    out = transparent_tls_probe("denied.test")
    a.contains(out.stdout, "closed",
               "a denied SNI must have its connection torn down, got %r"
               % out.stdout)


@test("transparent", "the metadata endpoint cannot be reached by naming it in SNI")
def t_transparent_tls_metadata(a):
    out = transparent_tls_probe("metadata.test")
    a.contains(out.stdout, "closed",
               "an unlisted name must be refused, got %r" % out.stdout)


@test("transparent", "a permitted host is proxied on the plaintext listener")
def t_transparent_http_allowed(a):
    out = in_client("""
local sock = ngx.socket.tcp()
sock:settimeout(8000)
local ok, err = sock:connect("10.99.0.5", 3080)
if not ok then ngx.print("connect-failed:", err) return end
sock:send("GET / HTTP/1.1\\r\\nHost: allowed.test\\r\\nConnection: close\\r\\n\\r\\n")
local line = sock:receive("*l")
ngx.print("status:", tostring(line))
sock:close()
""")
    a.contains(out.stdout, "200",
               "a permitted host must be served, got %r" % out.stdout)


@test("transparent", "a host outside the policy is refused on the plaintext listener")
def t_transparent_http_denied(a):
    out = in_client("""
local sock = ngx.socket.tcp()
sock:settimeout(8000)
local ok, err = sock:connect("10.99.0.5", 3080)
if not ok then ngx.print("connect-failed:", err) return end
sock:send("GET / HTTP/1.1\\r\\nHost: denied.test\\r\\nConnection: close\\r\\n\\r\\n")
local buf = ""
while true do
    local chunk, rerr, partial = sock:receive(4096)
    buf = buf .. (chunk or partial or "")
    if not chunk then break end
end
ngx.print("head:", buf)
sock:close()
""")
    a.not_contains(out.stdout, "200 OK",
                   "a denied host must never return 200")
    a.contains(out.stdout, "403",
               "a transparently intercepted plaintext client speaks HTTP, so "
               "it must be told why it was refused rather than being handed a "
               "bare connection reset it cannot diagnose; got %r" % out.stdout)
    a.contains(out.stdout.lower(), "x-rokh-oghab-reason",
               "the deny reason header must reach a transparent client too")
    a.contains(out.stdout, "policy.default_deny",
               "and it must carry the actual reason")


@test("transparent", "plaintext on the TLS listener is refused, not forwarded")
def t_transparent_tls_plaintext(a):
    out = in_client("""
local sock = ngx.socket.tcp()
sock:settimeout(8000)
local ok, err = sock:connect("10.99.0.5", 3443)
if not ok then ngx.print("connect-failed:", err) return end
sock:send("GET / HTTP/1.1\\r\\nHost: allowed.test\\r\\n\\r\\n")
local data, rerr, partial = sock:receive(32)
if data then ngx.print("got:", data)
elseif partial and #partial > 0 then ngx.print("got:", partial)
else ngx.print("closed:", tostring(rerr)) end
sock:close()
""")
    a.contains(out.stdout, "closed",
               "plaintext on a TLS listener must be torn down, got %r"
               % out.stdout)


@test("security", "requests without identity are denied (fail closed)")
def t_no_identity(a):
    res = http_via_proxy("http://allowed.test/")
    a.eq(res["status"], 407)
    a.eq(res["reason"], "identity.unknown")


@test("security", "invalid tokens are rejected")
def t_bad_token(a):
    res = http_via_proxy("http://allowed.test/", "ro-e2e-not-a-real-token-000001")
    a.eq(res["status"], 407)
    a.eq(res["reason"], "identity.invalid_token")


@test("security", "policies are scoped to the identity that owns them")
def t_identity_isolation(a):
    res = http_via_proxy("http://allowed.test/", NODE_TOKEN)
    a.denied(res, "node profile must not reach the python profile's destination")
    a.eq(res["reason"], "policy.default_deny")
    res = http_via_proxy("http://denied.test/", NODE_TOKEN)
    a.allowed(res, "node profile reaches its own destination")


@test("security", "undeclared destinations are denied by default")
def t_default_deny(a):
    for host in ("denied.test", "unknown.test", "example.com"):
        res = http_via_proxy("http://%s/" % host, PYTHON_TOKEN)
        a.denied(res, host)


@test("security", "a global deny overrides a lower-tier allow")
def t_deny_overrides(a):
    res = http_via_proxy("http://other.test/", NODE_TOKEN)
    a.denied(res)
    res = http_via_proxy("http://other.test/", PYTHON_TOKEN)
    a.denied(res)


@test("security", "suffix rules never match by substring")
def t_suffix_substring(a):
    for host in ("evilallowed.test", "allowed.test.evil.io"):
        res = http_via_proxy("http://%s/" % host, PYTHON_TOKEN)
        a.denied(res, host)
        a.eq(res["reason"], "policy.default_deny", host)


@test("security", "cloud metadata endpoints are blocked as IP literals")
def t_metadata_literal(a):
    for host in ("169.254.169.254", "169.254.170.2", "100.100.100.200",
                 "192.0.0.192", "169.254.169.123"):
        res = http_via_proxy("http://%s/" % host, PYTHON_TOKEN)
        a.denied(res, host)
        a.contains(res["reason"] or "", "guard.blocked", host)


@test("security", "loopback and private ranges are blocked as IP literals")
def t_private_literal(a):
    for host in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
                 "100.64.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1"):
        res = http_via_proxy("http://%s/" % host, PYTHON_TOKEN)
        a.denied(res, host)


@test("security", "obfuscated IP encodings are blocked")
def t_obfuscated(a):
    cases = ["2130706433", "0x7f000001", "017700000001", "127.1", "127.0.1",
             "0177.0.0.1", "2852039166", "0xa9fea9fe", "169.254.43518",
             "0251.0376.0251.0376"]
    for host in cases:
        res = http_via_proxy("http://%s/" % host, PYTHON_TOKEN)
        a.denied(res, host)
        a.contains(res["reason"] or "", "guard", host)


@test("security", "IPv6 literals and tunnel encodings are blocked")
def t_ipv6_literals(a):
    cases = ["[::1]", "[::ffff:127.0.0.1]", "[::ffff:169.254.169.254]",
             "[2002:7f00:0001::]", "[2002:a9fe:a9fe::]",
             "[64:ff9b::169.254.169.254]", "[fe80::5efe:169.254.169.254]",
             "[fc00::1]", "[::127.0.0.1]", "[fd00:ec2::254]"]
    for host in cases:
        res = http_via_proxy("http://%s/" % host, PYTHON_TOKEN)
        a.denied(res, host)


@test("security", "CONNECT to internal addresses is refused")
def t_connect_internal(a):
    for authority in ("169.254.169.254:80", "127.0.0.1:22", "10.0.0.1:443",
                      "[::1]:443", "2130706433:443", "0x7f000001:443"):
        status, headers, body, sock = connect_via_proxy(authority, PYTHON_TOKEN)
        if sock:
            sock.close()
        a.ne(status, 200, "CONNECT %s must be refused" % authority)


@test("security", "DNS answers pointing at internal addresses are dropped")
def t_dns_rebinding(a):
    for host in ("rebind.test", "loopback.test", "internal.test"):
        res = http_via_proxy("http://%s/" % host, PYTHON_TOKEN)
        a.denied(res, host)
        a.contains(res["reason"] or "", "dns", host)


@test("security", "mixed DNS answers keep only permitted addresses")
def t_dns_mixed(a):
    res = http_via_proxy("http://mixed.test/", PYTHON_TOKEN)
    a.allowed(res, "must connect via the one permitted address")
    a.contains(res["body"], "origin-a")


@test("security", "IPv6 answers embedding internal IPv4 are dropped")
def t_dns_v6_internal(a):
    res = http_via_proxy("http://v6internal.test/", PYTHON_TOKEN)
    a.denied(res)


@test("security", "request smuggling vectors are rejected")
def t_smuggling(a):
    vectors = [
        ("CL+TE",
         "POST http://allowed.test/echo HTTP/1.1\r\nHost: allowed.test\r\n"
         "Proxy-Authorization: Bearer %s\r\nContent-Length: 6\r\n"
         "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        ("duplicate CL",
         "POST http://allowed.test/echo HTTP/1.1\r\nHost: allowed.test\r\n"
         "Proxy-Authorization: Bearer %s\r\nContent-Length: 5\r\n"
         "Content-Length: 6\r\n\r\nhello"),
        ("comma CL",
         "POST http://allowed.test/echo HTTP/1.1\r\nHost: allowed.test\r\n"
         "Proxy-Authorization: Bearer %s\r\nContent-Length: 5, 6\r\n\r\nhello"),
        ("bare LF request line",
         "GET http://allowed.test/ HTTP/1.1\nHost: allowed.test\r\n"
         "Proxy-Authorization: Bearer %s\r\n\r\n"),
        ("bare LF header",
         "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\n"
         "Proxy-Authorization: Bearer %s\r\n\r\n"),
        ("obs-fold",
         "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
         " continued\r\nProxy-Authorization: Bearer %s\r\n\r\n"),
        ("space before colon",
         "GET http://allowed.test/ HTTP/1.1\r\nHost : allowed.test\r\n"
         "Proxy-Authorization: Bearer %s\r\n\r\n"),
        ("TE identity",
         "POST http://allowed.test/echo HTTP/1.1\r\nHost: allowed.test\r\n"
         "Proxy-Authorization: Bearer %s\r\nTransfer-Encoding: identity\r\n\r\n"),
        ("TE chunked twice",
         "POST http://allowed.test/echo HTTP/1.1\r\nHost: allowed.test\r\n"
         "Proxy-Authorization: Bearer %s\r\nTransfer-Encoding: chunked\r\n"
         "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        ("double space request line",
         "GET  http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
         "Proxy-Authorization: Bearer %s\r\n\r\n"),
        ("unknown method",
         "TRACK http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
         "Proxy-Authorization: Bearer %s\r\n\r\n"),
        ("lowercase method",
         "get http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
         "Proxy-Authorization: Bearer %s\r\n\r\n"),
        ("HTTP/2 version",
         "GET http://allowed.test/ HTTP/2.0\r\nHost: allowed.test\r\n"
         "Proxy-Authorization: Bearer %s\r\n\r\n"),
        ("duplicate Host",
         "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
         "Host: denied.test\r\nProxy-Authorization: Bearer %s\r\n\r\n"),
    ]
    for label, template in vectors:
        res = raw_proxy(template % PYTHON_TOKEN)
        a.eq(res["status"], 400, "smuggling vector: %s" % label)


@test("security", "Host header must agree with the absolute request target")
def t_host_mismatch(a):
    res = http_via_proxy("http://allowed.test/", PYTHON_TOKEN,
                         host_header="denied.test")
    a.eq(res["status"], 400)
    a.eq(res["reason"], "protocol.host_mismatch")


@test("security", "userinfo in the authority is rejected")
def t_userinfo(a):
    payload = ("GET http://allowed.test@denied.test/ HTTP/1.1\r\n"
               "Host: allowed.test\r\n"
               "Proxy-Authorization: Bearer %s\r\n\r\n" % PYTHON_TOKEN)
    res = raw_proxy(payload)
    a.eq(res["status"], 400)


@test("security", "non-http schemes in the request target are rejected")
def t_schemes(a):
    for tgt in ("https://allowed.test/", "file:///etc/passwd",
                "gopher://allowed.test/", "ftp://allowed.test/"):
        payload = ("GET %s HTTP/1.1\r\nHost: allowed.test\r\n"
                   "Proxy-Authorization: Bearer %s\r\n\r\n" % (tgt, PYTHON_TOKEN))
        res = raw_proxy(payload)
        a.eq(res["status"], 400, tgt)


@test("security", "path traversal cannot escape a path-restricted rule")
def t_path_traversal(a):
    ok = http_via_proxy("http://pathrule.test/public/file", PYTHON_TOKEN)
    a.allowed(ok, "the permitted path must work")

    for path in ("/private/secret", "/public/../private/secret",
                 "/public/%2e%2e/private", "/public/..%2fprivate",
                 "//private/secret", "/public/./../private"):
        res = http_via_proxy("http://pathrule.test%s" % path, PYTHON_TOKEN)
        a.denied(res, "path %s" % path)


@test("security", "methods outside the rule are denied")
def t_method_restriction(a):
    res = http_via_proxy("http://pathrule.test/public/x", PYTHON_TOKEN,
                         method="POST", body="hello")
    a.denied(res)


@test("security", "ports outside the rule are denied")
def t_port_restriction(a):
    res = http_via_proxy("http://allowed.test:8080/", PYTHON_TOKEN)
    a.denied(res)
    status, headers, body, sock = connect_via_proxy("allowed.test:22", PYTHON_TOKEN)
    if sock:
        sock.close()
    a.ne(status, 200, "CONNECT to a non-permitted port")


@test("security", "protocol restrictions are enforced inside the tunnel")
def t_protocol_enforcement(a):
    res = http_via_proxy("http://tlsonly.test/", PYTHON_TOKEN)
    a.denied(res, "plain http to an https-only destination")


@test("security", "plaintext inside a CONNECT tunnel on 443 is refused")
def t_plaintext_on_443(a):
    status, headers, rest, sock = connect_via_proxy("allowed.test:443", PYTHON_TOKEN)
    a.eq(status, 200, "tunnel is established before payload inspection")
    try:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
        sock.settimeout(6)
        data = b""
        try:
            while len(data) < 64:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        a.true(b"origin-a" not in data,
               "plaintext must not be forwarded to the TLS port")
    finally:
        sock.close()


@test("security", "SNI must match the CONNECT authority")
def t_sni_mismatch(a):
    status, headers, rest, sock = connect_via_proxy("allowed.test:443", PYTHON_TOKEN)
    a.eq(status, 200)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            wrapped = ctx.wrap_socket(sock, server_hostname="denied.test")
            wrapped.sendall(b"GET / HTTP/1.1\r\nHost: denied.test\r\n\r\n")
            wrapped.settimeout(6)
            data = wrapped.recv(4096)
            a.true(not data, "mismatched SNI must not reach the origin")
        except (ssl.SSLError, OSError, socket.timeout):
            pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


@test("security", "redirects towards internal addresses are blocked")
def t_redirect_guard(a):
    res = http_via_proxy(
        "http://allowed.test/redirect?to=http%3A%2F%2F169.254.169.254%2Flatest",
        PYTHON_TOKEN)
    a.denied(res, "redirect to metadata must be blocked")
    res = http_via_proxy(
        "http://allowed.test/redirect?to=http%3A%2F%2Fdenied.test%2F",
        PYTHON_TOKEN)
    a.denied(res, "redirect to a denied destination must be blocked")
    res = http_via_proxy(
        "http://allowed.test/redirect?to=http%3A%2F%2Fapi.allowed.test%2F",
        PYTHON_TOKEN)
    a.eq(res["status"], 302, "redirect to a permitted destination is allowed")


@test("security", "every request on a keep-alive connection is re-evaluated")
def t_keepalive_reevaluation(a):
    sock = connect_proxy()
    try:
        sock.sendall(("GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
                      "Proxy-Authorization: Bearer %s\r\n"
                      "Connection: keep-alive\r\n\r\n" % PYTHON_TOKEN).encode())
        head, rest = recv_head(sock)
        status, headers, order, sl = parse_head(head)
        a.eq(status, 200, "first request allowed")
        read_body(sock, headers, rest)

        sock.sendall(("GET http://denied.test/ HTTP/1.1\r\nHost: denied.test\r\n"
                      "Proxy-Authorization: Bearer %s\r\n"
                      "Connection: keep-alive\r\n\r\n" % PYTHON_TOKEN).encode())
        head, rest = recv_head(sock)
        status, headers, order, sl = parse_head(head)
        a.eq(status, 403, "second request on the same connection is re-evaluated")
    finally:
        sock.close()


@test("security", "a token cannot be swapped mid connection to widen access")
def t_token_swap(a):
    sock = connect_proxy()
    try:
        sock.sendall(("GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
                      "Proxy-Authorization: Bearer %s\r\n"
                      "Connection: keep-alive\r\n\r\n" % PYTHON_TOKEN).encode())
        head, rest = recv_head(sock)
        status, headers, order, sl = parse_head(head)
        a.eq(status, 200)
        read_body(sock, headers, rest)

        sock.sendall(("GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
                      "Proxy-Authorization: Bearer %s\r\n"
                      "Connection: keep-alive\r\n\r\n" % NODE_TOKEN).encode())
        head, rest = recv_head(sock)
        status, headers, order, sl = parse_head(head)
        a.eq(status, 403, "the node token must not inherit the python decision")
    finally:
        sock.close()


@test("security", "oversized heads are rejected")
def t_oversized_head(a):
    padding = "\r\n".join("X-Pad-%d: %s" % (i, "a" * 900) for i in range(200))
    payload = ("GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n"
               "Proxy-Authorization: Bearer %s\r\n%s\r\n\r\n"
               % (PYTHON_TOKEN, padding))
    try:
        res = raw_proxy(payload)
        a.ne(res["status"], 200, "oversized head must not be proxied")
    except ProxyError:
        pass


@test("security", "resolvedCidrs pins a hostname to an address range")
def t_resolved_cidr(a):
    res = http_via_proxy("http://allowed.test/", STRICT_TOKEN)
    a.denied(res, "resolved address outside the pinned range must be refused")
    a.contains(res["reason"] or "", "resolved_cidr")


@test("limits", "request rate limits are enforced")
def t_rate_limit(a):
    time.sleep(1.1)
    statuses = []
    for _ in range(12):
        res = http_via_proxy("http://ratelimited.test/", PYTHON_TOKEN)
        statuses.append(res["status"])
    a.true(429 in statuses, "expected at least one 429, got %r" % statuses)
    a.true(200 in statuses, "expected some requests to succeed, got %r" % statuses)


@test("limits", "connection limits are enforced")
def t_connection_limit(a):
    socks = []
    results = []
    try:
        for i in range(5):
            s = connect_proxy(timeout=10)
            s.sendall(("GET http://api.allowed.test/slow?ms=1500 HTTP/1.1\r\n"
                       "Host: api.allowed.test\r\n"
                       "Proxy-Authorization: Bearer %s\r\n"
                       "Connection: keep-alive\r\n\r\n" % STRICT_TOKEN).encode())
            socks.append(s)
        for s in socks:
            try:
                head, rest = recv_head(s)
                status, headers, order, sl = parse_head(head)
                results.append(status)
            except (ProxyError, OSError):
                results.append(0)
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
    a.true(429 in results,
           "expected a connection-limit rejection, got %r" % results)


@test("dns", "permitted names resolve through the gateway resolver")
def t_dns_allow(a):
    res = dns_query("allowed.test")
    a.eq(res["rcode"], 0)
    a.true("10.99.0.10" in res["answers"], "got %r" % res["answers"])


@test("dns", "names outside policy do not resolve")
def t_dns_deny(a):
    res = dns_query("denied.test")
    a.ne(res["rcode"], 0)
    a.eq(res["count"], 0)


@test("dns", "unidentified clients get no resolution at all")
def t_dns_identity(a):
    res = dns_query_host("allowed.test")
    a.ne(res["rcode"], 0, "an unidentified source must not resolve names")
    a.eq(res["count"], 0)


@test("dns", "answers pointing at internal space are filtered out")
def t_dns_filter(a):
    res = dns_query("rebind.test")
    a.eq(res["count"], 0, "internal answers must never be returned")
    res = dns_query("loopback.test")
    a.eq(res["count"], 0, "loopback answers must never be returned")
    res = dns_query("mixed.test")
    a.true("10.99.0.10" in res["answers"], "got %r" % res["answers"])
    a.true("169.254.169.254" not in res["answers"],
           "internal address leaked: %r" % res["answers"])


@test("dns", "tunnelling record types are refused")
def t_dns_qtype(a):
    for qtype in (16, 10, 255, 5, 33):
        res = dns_query("tunnel.test", qtype=qtype)
        a.eq(res["count"], 0, "qtype %d must return no records" % qtype)


@test("dns", "the resolver echoes the transaction id")
def t_dns_id(a):
    res = dns_query("allowed.test", tid=0x4242)
    a.eq(res["id"], 0x4242)


@test("admin", "health and readiness endpoints report status")
def t_admin_health(a):
    res = admin("GET", "/healthz", token=None)
    a.eq(res["status"], 200)
    res = admin("GET", "/readyz", token=None)
    a.eq(res["status"], 200)
    a.eq(res["json"]["status"], "ready")


@test("admin", "metrics are exposed in Prometheus format")
def t_admin_metrics(a):
    res = admin("GET", "/metrics", token=None)
    a.eq(res["status"], 200)
    body = res["body"].decode()
    a.contains(body, "# TYPE ro_requests_total counter")
    a.contains(body, "ro_denied_total")
    a.contains(body, "ro_policy_version")


@test("admin", "privileged endpoints require a bearer token")
def t_admin_auth(a):
    res = admin("GET", "/v1/status", token=None)
    a.eq(res["status"], 401)
    res = admin("GET", "/v1/status", token="wrong-token-value-00000000")
    a.eq(res["status"], 401)
    res = admin("GET", "/v1/status")
    a.eq(res["status"], 200)


@test("admin", "status reports the active policy")
def t_admin_status(a):
    res = admin("GET", "/v1/status")
    a.eq(res["status"], 200)
    a.eq(res["json"]["policy"]["loaded"], True)
    a.eq(res["json"]["policy"]["version"], 7)
    a.true(res["json"]["policy"]["ruleCount"] >= 5)


@test("admin", "the audit trail records decisions")
def t_admin_audit(a):
    http_via_proxy("http://denied.test/", PYTHON_TOKEN)
    time.sleep(0.4)
    res = admin("GET", "/v1/audit?limit=200&action=deny")
    a.eq(res["status"], 200)
    events = res["json"]["events"]
    a.true(len(events) > 0, "expected audit events")
    a.true(any(e.get("destination") == "denied.test" for e in events),
           "expected the denied.test decision in the audit trail")


@test("admin", "invalid bundles are rejected by validation")
def t_admin_validate(a):
    res = admin("POST", "/v1/validate", {
        "version": 1,
        "policies": [{"name": "bad", "rules": [
            {"action": "allow", "ports": [443]}]}],
    })
    a.eq(res["status"], 200)
    a.eq(res["json"]["valid"], False)
    a.contains(res["json"]["error"], "destination")

    res = admin("POST", "/v1/validate", {
        "version": 2,
        "policies": [{"name": "good", "rules": [
            {"action": "allow", "ports": [443],
             "destinations": {"hostnames": ["example.com"]}}]}],
    })
    a.eq(res["json"]["valid"], True)


@test("admin", "the emergency deny switch halts all egress and can be lifted")
def t_admin_emergency(a):
    ok = http_via_proxy("http://allowed.test/", PYTHON_TOKEN)
    a.allowed(ok)
    try:
        res = admin("POST", "/v1/emergency-deny", {"enabled": True})
        a.eq(res["status"], 200)
        a.eq(res["json"]["emergencyDeny"], True)
        time.sleep(0.2)
        blocked = http_via_proxy("http://allowed.test/", PYTHON_TOKEN)
        a.denied(blocked, "emergency deny must stop permitted traffic too")
        a.eq(blocked["reason"], "emergency.deny")
    finally:
        admin("POST", "/v1/emergency-deny", {"enabled": False})
        time.sleep(0.2)
    restored = http_via_proxy("http://allowed.test/", PYTHON_TOKEN)
    a.allowed(restored, "egress must resume after the switch is lifted")


@test("admin", "the DNS cache can be flushed")
def t_admin_dns_flush(a):
    res = admin("POST", "/v1/dns/flush", {"name": "allowed.test"})
    a.eq(res["status"], 200)
    a.eq(res["json"]["flushed"], "allowed.test")


@test("admin", "secrets are redacted from the configuration endpoint")
def t_admin_config(a):
    res = admin("GET", "/v1/config")
    a.eq(res["status"], 200)
    a.eq(res["json"]["admin"]["token"], "***")
    a.not_contains(res["body"], ADMIN_TOKEN)


@test("admin", "unknown endpoints return 404")
def t_admin_404(a):
    res = admin("GET", "/v1/does-not-exist")
    a.eq(res["status"], 404)


def preflight(quiet=False):
    problems = []
    try:
        res = admin("GET", "/v1/status")
    except Exception as exc:
        return ["cannot reach the gateway admin API: %s" % exc]
    if res["status"] != 200:
        return ["the gateway admin API returned %d" % res["status"]]

    status = res.get("json") or {}
    if status.get("emergencyDeny"):
        if not quiet:
            print("  note: the emergency switch was engaged; lifting it")
        try:
            admin("POST", "/v1/emergency-deny", {"enabled": False})
            time.sleep(0.3)
            again = admin("GET", "/v1/status")
            if (again.get("json") or {}).get("emergencyDeny"):
                problems.append("emergency deny is engaged and could not be lifted")
        except Exception as exc:
            problems.append("could not lift emergency deny: %s" % exc)

    policy = status.get("policy") or {}
    if not policy.get("version") and policy.get("version") != 0:
        problems.append("the gateway has no policy bundle loaded")

    try:
        ready = admin("GET", "/readyz")
        if ready["status"] != 200:
            problems.append("the gateway is not ready: %s"
                            % json.dumps(ready.get("json") or {}))
    except Exception as exc:
        problems.append("readiness check failed: %s" % exc)

    return problems


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--category", action="append", default=None)
    parser.add_argument("--filter", default=None)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    selected = []
    for category, name, fn in TESTS:
        if args.category and category not in args.category:
            continue
        if args.filter and args.filter not in name:
            continue
        selected.append((category, name, fn))

    print("Rokh Oghab end-to-end suite")
    print("=" * 72)

    problems = preflight()
    if problems:
        print("\n  the gateway is not in a state these tests can run against:")
        for problem in problems:
            print("    - %s" % problem)
        print("\n  bring it back with: make e2e-down && make e2e-up")
        print("=" * 72)
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
            dt = (time.time() - t0) * 1000
            print("    ok   %-62s %6.0fms (%d checks)" % (name, dt, a.checks))
            passed += 1
        except Exception as exc:
            dt = (time.time() - t0) * 1000
            print("    FAIL %-62s %6.0fms" % (name, dt))
            print("         %s: %s" % (type(exc).__name__, exc))
            failures.append((category, name, "%s: %s" % (type(exc).__name__, exc)))
            failed += 1

    print("\n" + "=" * 72)
    print("passed=%d failed=%d elapsed=%.1fs" % (passed, failed, time.time() - started))
    if failures:
        print("\nFAILURES:")
        for category, name, detail in failures:
            print("  [%s] %s\n    %s" % (category, name, detail))
    print("=" * 72)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
