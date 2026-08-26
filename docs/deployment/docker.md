# Deploying on Docker

## The shape that actually holds

A proxy alone is advisory. What makes Docker deployment an enforcement boundary
is the network topology plus the node agent:

```
                       ro_egress (has a route out)
                              |
  ro_sandbox (internal)   ro-gateway   ro_control (internal)
        |                     |               |
   sandboxes            the only route    ro-controller
```

The sandbox network is created with `internal: true`, so Docker gives it no
route off the host. The gateway is attached to both that network and one with a
route out. Nothing else bridges them.

## Compose

```bash
cd deploy/docker
cp .env.example .env
# fill in real tokens
docker compose up -d
```

Then issue an identity:

```bash
export ROCTL_ENDPOINT=http://127.0.0.1:8081
export ROCTL_TOKEN="$RO_CONTROLLER_OPERATOR_TOKEN"

roctl policy apply -f ../../examples/policies/untrusted-python.yaml
roctl identity issue --namespace execution --profile untrusted-python
roctl publish
```

## A single container, no Compose

```bash
docker network create --internal ro_sandbox
docker network create ro_egress

docker run -d --name ro-gateway \
  --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /run/rokh-oghab:uid=65532,gid=65532,mode=0700 \
  --network ro_sandbox \
  -v "$PWD/config/gateway.json:/etc/rokh-oghab/gateway.json:ro" \
  -v "$PWD/config/bootstrap-bundle.json:/etc/rokh-oghab/bundle.json:ro" \
  -e RO_ADMIN_TOKEN="$(openssl rand -hex 24)" \
  ghcr.io/rokh-oghab/gateway:latest

docker network connect ro_egress ro-gateway
```

Sandboxes then join `ro_sandbox` only:

```bash
docker run -d --name sandbox \
  --network ro_sandbox \
  --cap-drop ALL --security-opt no-new-privileges \
  -e HTTP_PROXY=http://ro-gateway:3128 \
  -e HTTPS_PROXY=http://ro-gateway:3128 \
  -e NO_PROXY= \
  -e RO_PROXY_TOKEN="$SANDBOX_TOKEN" \
  python:3.12-alpine sleep infinity
```

## When the sandbox network is not internal

If your sandboxes sit on a network that does have a route out, the topology is
not enough on its own. Run the node agent:

```bash
sudo RO_GATEWAY_ADDR=10.80.0.5 \
     RO_SANDBOX_CIDRS=10.80.0.0/24 \
     RO_DNS_REDIRECT=true \
     ro-agent run
```

`examples/docker/enforced-sandbox.sh` builds exactly this and then proves it:

```bash
sudo bash examples/docker/enforced-sandbox.sh
```

It stands up an isolated network, programs nftables, redirects DNS into the
gateway, runs untrusted Python, and finishes by stopping the gateway to show
the sandbox is left with no network at all.

## Making DNS go through the gateway

The gateway's resolver listens on 5353 because it runs unprivileged. Two ways
to get a container to use it:

**Redirect at the node**, which needs no cooperation from the container:

```bash
sudo RO_DNS_REDIRECT=true RO_DNS_PORT=5353 ... ro-agent run
```

**Point resolv.conf at it directly**, bypassing Docker's embedded resolver:

```bash
printf 'nameserver 10.80.0.5\noptions ndots:0\n' > /tmp/resolv.conf
docker run -v /tmp/resolv.conf:/etc/resolv.conf:ro ...
```

`--dns` alone is not enough: Docker's embedded resolver forwards the query from
the daemon's own namespace, so the gateway sees the bridge address instead of
the sandbox and cannot identify the caller.
