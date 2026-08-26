import argparse
import json
import os
import socket
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request

PROXY_HOST = os.environ.get("RO_PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("RO_PROXY_PORT", "13128"))
ADMIN_HOST = os.environ.get("RO_ADMIN_HOST", "127.0.0.1")
ADMIN_PORT = int(os.environ.get("RO_ADMIN_PORT", "19145"))
ADMIN_TOKEN = os.environ.get("RO_ADMIN_TOKEN", "ro-e2e-admin-token-000000000001")
TOKEN = os.environ.get("RO_PROXY_TOKEN", "ro-e2e-python-token-0000000001")

ALLOWED = os.environ.get("RO_BENCH_ALLOWED", "http://allowed.test/")
DENIED = os.environ.get("RO_BENCH_DENIED", "http://denied.test/")
BULK = os.environ.get("RO_BENCH_BULK", "http://allowed.test/big?n=8388608")

TIMEOUT = float(os.environ.get("RO_BENCH_TIMEOUT", "20"))


class Failure(Exception):
    pass


def percentile(values, fraction):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[index]


def summarise(name, samples, unit="ms"):
    if not samples:
        print("  %-28s no samples" % name)
        return {}
    stats = {
        "count": len(samples),
        "min": min(samples),
        "mean": statistics.fmean(samples),
        "p50": percentile(samples, 0.50),
        "p95": percentile(samples, 0.95),
        "p99": percentile(samples, 0.99),
        "max": max(samples),
    }
    print("  %-28s n=%-6d min=%-8.3f p50=%-8.3f p95=%-8.3f p99=%-8.3f max=%-8.3f %s"
          % (name, stats["count"], stats["min"], stats["p50"], stats["p95"],
             stats["p99"], stats["max"], unit))
    return stats


def opener():
    handler = urllib.request.ProxyHandler({
        "http": "http://%s:%d" % (PROXY_HOST, PROXY_PORT),
        "https": "http://%s:%d" % (PROXY_HOST, PROXY_PORT),
    })
    built = urllib.request.build_opener(handler)
    built.addheaders = [("Proxy-Authorization", "Bearer " + TOKEN)]
    return built


def fetch(built, url, timeout=TIMEOUT):
    request = urllib.request.Request(url)
    request.add_header("Proxy-Authorization", "Bearer " + TOKEN)
    started = time.perf_counter()
    try:
        with built.open(request, timeout=timeout) as response:
            body = response.read()
        return (time.perf_counter() - started) * 1000.0, len(body), response.status
    except urllib.error.HTTPError as exc:
        body = exc.read()
        return (time.perf_counter() - started) * 1000.0, len(body), exc.code


def admin(path):
    url = "http://%s:%d%s" % (ADMIN_HOST, ADMIN_PORT, path)
    request = urllib.request.Request(url)
    request.add_header("Authorization", "Bearer " + ADMIN_TOKEN)
    direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with direct.open(request, timeout=TIMEOUT) as response:
        return response.read().decode()


def metric_value(text, name):
    total = None
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if line.split("{")[0].split(" ")[0] != name:
            continue
        try:
            value = float(line.rsplit(" ", 1)[1])
        except (IndexError, ValueError):
            continue
        total = value if total is None else total + value
    return total


def histogram_average(text, name):
    total = metric_value(text, name + "_sum")
    count = metric_value(text, name + "_count")
    if not total or not count:
        return None
    return (total / count) * 1000.0


def bench_allowed(built, iterations):
    latencies = []
    for _ in range(iterations):
        elapsed, _, status = fetch(built, ALLOWED)
        if status != 200:
            raise Failure("a permitted request returned %d" % status)
        latencies.append(elapsed)
    return latencies


def bench_denied(built, iterations):
    latencies = []
    for _ in range(iterations):
        elapsed, _, status = fetch(built, DENIED)
        if status not in (403, 407):
            raise Failure("a denied request returned %d" % status)
        latencies.append(elapsed)
    return latencies


def bench_direct(iterations):
    latencies = []
    for _ in range(iterations):
        started = time.perf_counter()
        try:
            sock = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=TIMEOUT)
            sock.close()
        except OSError as exc:
            raise Failure("cannot reach the gateway: %s" % exc)
        latencies.append((time.perf_counter() - started) * 1000.0)
    return latencies


def bench_concurrent(workers, per_worker):
    results = []
    errors = []
    lock = threading.Lock()

    def run():
        built = opener()
        local = []
        try:
            for _ in range(per_worker):
                elapsed, _, status = fetch(built, ALLOWED)
                if status != 200:
                    raise Failure("status %d" % status)
                local.append(elapsed)
        except Exception as exc:
            with lock:
                errors.append(str(exc))
        with lock:
            results.extend(local)

    threads = [threading.Thread(target=run) for _ in range(workers)]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    wall = time.perf_counter() - started
    return results, errors, wall


def bench_throughput(built, rounds):
    rates = []
    for _ in range(rounds):
        started = time.perf_counter()
        elapsed, size, status = fetch(built, BULK, timeout=TIMEOUT * 2)
        wall = time.perf_counter() - started
        if status != 200 or size == 0:
            return []
        rates.append((size / wall) / (1024.0 * 1024.0))
    return rates


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--per-worker", type=int, default=25)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv[1:])

    print("Rokh Oghab benchmark")
    print("=" * 78)
    print("  proxy    %s:%d" % (PROXY_HOST, PROXY_PORT))
    print("  admin    %s:%d" % (ADMIN_HOST, ADMIN_PORT))
    print()

    built = opener()
    try:
        for _ in range(args.warmup):
            fetch(built, ALLOWED)
    except (OSError, urllib.error.URLError) as exc:
        print("cannot reach the gateway: %s" % exc, file=sys.stderr)
        print("run 'make e2e-up' first", file=sys.stderr)
        return 2

    report = {}

    print("  latency")
    try:
        report["connect"] = summarise("tcp connect", bench_direct(args.iterations))
        report["allowed"] = summarise("allowed request",
                                      bench_allowed(built, args.iterations))
        report["denied"] = summarise("denied request",
                                     bench_denied(built, args.iterations))
    except Failure as exc:
        print("  benchmark aborted: %s" % exc, file=sys.stderr)
        return 1

    print()
    print("  concurrency (%d workers x %d requests)"
          % (args.workers, args.per_worker))
    samples, errors, wall = bench_concurrent(args.workers, args.per_worker)
    report["concurrent"] = summarise("under load", samples)
    if wall > 0:
        rps = len(samples) / wall
        report["rps"] = rps
        print("  %-28s %.1f requests/second over %.2fs" % ("sustained", rps, wall))
    if errors:
        print("  %-28s %d workers reported errors: %s"
              % ("errors", len(errors), errors[0]))

    rates = bench_throughput(built, 5)
    if rates:
        report["throughput_mib_s"] = statistics.fmean(rates)
        print()
        print("  throughput")
        print("  %-28s %.1f MiB/s mean over %d transfers"
              % ("bulk transfer", statistics.fmean(rates), len(rates)))

    print()
    print("  what the gateway measured about itself")
    try:
        text = admin("/metrics")
        for label, name in (("policy evaluation", "ro_policy_eval_seconds"),
                            ("request setup", "ro_request_duration_seconds"),
                            ("upstream", "ro_upstream_duration_seconds")):
            average = histogram_average(text, name)
            if average is not None:
                report[name] = average
                print("  %-28s %.3f ms mean" % (label, average))
        for label, name in (("requests", "ro_requests_total"),
                            ("allowed", "ro_allowed_total"),
                            ("denied", "ro_denied_total"),
                            ("series tracked", "ro_metrics_series_total")):
            value = metric_value(text, name)
            if value is not None:
                print("  %-28s %d" % (label, int(value)))
    except (OSError, urllib.error.URLError) as exc:
        print("  admin metrics unavailable: %s" % exc)

    allowed = report.get("allowed", {}).get("p50")
    connect = report.get("connect", {}).get("p50")
    if allowed and connect:
        print()
        print("  reading")
        print("  %-28s %.3f ms" % ("median proxied request", allowed))
        print("  %-28s %.3f ms" % ("median bare tcp connect", connect))
        evaluation = report.get("ro_policy_eval_seconds")
        if evaluation is not None:
            share = (evaluation / allowed) * 100.0 if allowed else 0.0
            print("  %-28s %.3f ms (%.1f%% of a request)"
                  % ("of which policy", evaluation, share))
            if share > 20:
                print("  policy evaluation dominates; look at rule counts "
                      "and destination set sizes")
            else:
                print("  policy evaluation is not the bottleneck")

    print("=" * 78)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
