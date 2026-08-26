import hashlib, json, os, sys

TOKENS = {
    "ro-e2e-python-token-0000000001": {
        "id": "sandbox-python-1", "namespace": "execution",
        "profile": "untrusted-python", "serviceAccount": "sandbox-runner",
        "labels": {"tenant": "acme"},
    },
    "ro-e2e-node-token-00000000001": {
        "id": "sandbox-node-1", "namespace": "execution",
        "profile": "untrusted-node", "serviceAccount": "sandbox-runner",
    },
    "ro-e2e-strict-token-0000000001": {
        "id": "sandbox-strict-1", "namespace": "execution",
        "profile": "strict-profile", "serviceAccount": "sandbox-runner",
    },
}

bundle = {
    "version": 7,
    "issuedAt": 0,
    "ttlSeconds": 300,
    "emergencyDeny": False,
    "defaults": {"maxStalenessSeconds": 900},
    "guard": {"blocked": [], "allowExceptions": []},
    "identities": {
        "allowAnonymous": False,
        "tokens": {
            hashlib.sha256(t.encode()).hexdigest(): spec
            for t, spec in TOKENS.items()
        },
        "sources": [
            {
                "cidr": "10.99.0.20/32",
                "id": "sandbox-by-source",
                "namespace": "execution",
                "profile": "untrusted-python",
                "serviceAccount": "sandbox-runner",
            }
        ],
        "trustedHeaderSources": [],
    },
    "policies": [
        {
            "name": "global-baseline",
            "tier": "global",
            "priority": 0,
            "description": "Absolute denies that no lower tier can override.",
            "rules": [
                {
                    "name": "deny-cloud-metadata",
                    "action": "deny",
                    "destinations": {
                        "cidrs": ["169.254.0.0/16", "100.100.100.200/32",
                                  "192.0.0.192/32"]
                    },
                },
                {
                    "name": "deny-quarantined-domain",
                    "action": "deny",
                    "destinations": {"hostnameSuffixes": ["other.test"]},
                },
            ],
        },
        {
            "name": "python-sandbox",
            "tier": "profile",
            "priority": 10,
            "selector": {"profiles": ["untrusted-python"]},
            "rules": [
                {
                    "name": "allowed-origin",
                    "action": "allow",
                    "destinations": {
                        "hostnames": ["allowed.test", "mixed.test",
                                      "rebind.test", "loopback.test",
                                      "internal.test", "v6only.test",
                                      "v6internal.test", "tunnel.test",
                                      "raw.test"],
                        "hostnameSuffixes": ["allowed.test"],
                    },
                    "ports": [80, 443],
                    "protocols": ["http", "https"],
                },
                {
                    "name": "path-restricted",
                    "action": "allow",
                    "destinations": {"hostnames": ["pathrule.test"]},
                    "ports": [80],
                    "protocols": ["http"],
                    "methods": ["GET", "HEAD"],
                    "paths": ["/public/*", "/public/**"],
                },
                {
                    "name": "rate-limited",
                    "action": "allow",
                    "destinations": {"hostnames": ["ratelimited.test"]},
                    "ports": [80],
                    "protocols": ["http"],
                    "rateLimit": {"requestsPerSecond": 3, "burst": 3},
                },
                {
                    "name": "tls-only",
                    "action": "allow",
                    "destinations": {"hostnames": ["tlsonly.test"]},
                    "ports": [443],
                    "protocols": ["https"],
                    "tls": {"minVersion": "1.2", "requireSni": True},
                },
                {
                    "name": "custom-l7-ports",
                    "action": "allow",
                    "destinations": {"hostnames": ["custom.test"]},
                    "ports": [8080, 8443],
                    "protocols": ["http", "https"],
                },
                {
                    "name": "raw-tcp-port-range",
                    "action": "allow",
                    "destinations": {"hostnames": ["rawtcp.test"]},
                    "ports": [{"from": 9000, "to": 9100}, "9443"],
                    "protocols": ["tcp", "https"],
                },
                {
                    "name": "bandwidth-capped",
                    "action": "allow",
                    "destinations": {"hostnames": ["bandwidth.test"]},
                    "ports": [80],
                    "protocols": ["http"],
                    "bandwidth": {"bytesPerSecond": "64k"},
                },
            ],
        },
        {
            "name": "node-sandbox",
            "tier": "profile",
            "priority": 10,
            "selector": {"profiles": ["untrusted-node"]},
            "rules": [
                {
                    "name": "denied-origin-only",
                    "action": "allow",
                    "destinations": {"hostnames": ["denied.test"]},
                    "ports": [80, 443],
                    "protocols": ["http", "https"],
                },
                {
                    "name": "shared-raw-origin",
                    "action": "allow",
                    "destinations": {"hostnames": ["raw.test"]},
                    "ports": [80],
                    "protocols": ["http"],
                },
            ],
        },
        {
            "name": "strict-profile",
            "tier": "profile",
            "priority": 10,
            "selector": {"profiles": ["strict-profile"]},
            "rules": [
                {
                    "name": "resolved-cidr-pinned",
                    "action": "allow",
                    "destinations": {
                        "hostnames": ["allowed.test"],
                        "resolvedCidrs": ["203.0.113.0/24"],
                    },
                    "ports": [80],
                    "protocols": ["http"],
                },
                {
                    "name": "connection-capped",
                    "action": "allow",
                    "destinations": {"hostnames": ["api.allowed.test"]},
                    "ports": [80],
                    "protocols": ["http"],
                    "connections": {"max": 2},
                },
            ],
        },
    ],
}

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "bundle.json")
with open(out, "w") as fh:
    json.dump(bundle, fh, indent=2)
    fh.write("\n")
print("wrote", out)
for t in TOKENS:
    print("  token", t, "->", hashlib.sha256(t.encode()).hexdigest()[:16], TOKENS[t]["profile"])
