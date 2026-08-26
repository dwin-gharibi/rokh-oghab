import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CALL = re.compile(
    r'reject\s*\(\s*ctx\s*,\s*[A-Za-z_][\w.]*\s*,\s*\d+\s*,\s*"([^"]+)"')
RETURN = re.compile(r'return\s+nil\s*,\s*"([a-z][a-z0-9_]*\.[a-z0-9_.]+)"')
CONCAT = re.compile(
    r'return\s+nil\s*,\s*"([a-z][a-z0-9_]*\.[a-z0-9_.]*):?"\s*\.\.')
REASON_CALL = re.compile(r'reject\(ctx, client, \d+, "([^"]+)"')
REASON_TABLE = re.compile(
    r"local\s+\w*REASON\w*\s*=\s*\{(.*?)\n\}", re.S)
TABLE_VALUE = re.compile(r'"([a-z][a-z0-9_]*\.[a-z0-9_][a-z0-9_.:-]*)"')


def catalogue():
    text = open(os.path.join(ROOT, "lua", "ro", "reasons.lua")).read()
    return set(re.findall(r'^\s*"([^"]+)",', text, re.M))


def label(reason, known):
    if reason in known:
        return reason
    idx = reason.find(":")
    while idx != -1:
        if reason[:idx] in known:
            return reason[:idx]
        idx = reason.find(":", idx + 1)
    return "other"


REASON_SHAPE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z0-9_][a-z0-9_.:-]*$")
SKIP_FILES = {"reasons.lua", "config.lua"}


def looks_like_a_reason(text):
    if " " in text or "\t" in text:
        return False
    if text.endswith(".") or text.endswith(":"):
        return False
    return REASON_SHAPE.match(text) is not None


def scan():
    found = {}
    for base, _, names in os.walk(os.path.join(ROOT, "lua")):
        for name in names:
            if not name.endswith(".lua") or name in SKIP_FILES:
                continue
            path = os.path.join(base, name)
            text = open(path).read()
            for pattern in (CALL, REASON_CALL, RETURN, CONCAT):
                for match in pattern.finditer(text):
                    reason = match.group(1)
                    if not looks_like_a_reason(reason):
                        continue
                    line = text[:match.start()].count("\n") + 1
                    found.setdefault(reason, []).append(
                        "%s:%d" % (os.path.relpath(path, ROOT), line))
            for table in REASON_TABLE.finditer(text):
                line = text[:table.start()].count("\n") + 1
                for match in TABLE_VALUE.finditer(table.group(1)):
                    reason = match.group(1)
                    if not looks_like_a_reason(reason):
                        continue
                    found.setdefault(reason, []).append(
                        "%s:%d" % (os.path.relpath(path, ROOT), line))
    return found


def main():
    known = catalogue()
    found = scan()
    bad = []
    for reason in sorted(found):
        if label(reason, known) == "other":
            bad.append((reason, found[reason]))

    print("Rokh Oghab reason catalogue check")
    print("=" * 70)
    print("\n  %d distinct reason strings reach a metric label" % len(found))
    if not bad:
        print("    ok   every one of them resolves to a catalogued label")
        print("\n" + "=" * 70)
        print("passed=1 failed=0")
        print("=" * 70)
        return 0

    for reason, sites in bad:
        print("    FAIL %s" % reason)
        print("         emitted at %s" % ", ".join(sites))
        print("         it has no entry in lua/ro/reasons.lua, so every")
        print("         denial for this cause is metered as \"other\" and an")
        print("         operator cannot see it")
    print("\n" + "=" * 70)
    print("passed=0 failed=%d" % len(bad))
    print("=" * 70)
    return 1


if __name__ == "__main__":
    sys.exit(main())
