# Rokh Oghab documentation

Start with the [README](../README.md) for what Rokh Oghab is. This directory is
the detail.

---

## By what you are trying to do

**I want to understand how it works**

| Document | |
| --- | --- |
| [Architecture](architecture.md) | The components, the request path, and why the data plane lives in nginx's stream subsystem |
| [Security model](security-model.md) | The invariant, the enforcement layers, and the specific attacks each one stops |
| [Threat model](threat-model.md) | What is in scope, what is not, and the residual risks |

**I want to deploy it**

| Document | |
| --- | --- |
| [Kubernetes](deployment/kubernetes.md) | Helm, kustomize, and placing a workload behind the gateway |
| [Docker](deployment/docker.md) | Compose and standalone |
| [Ansible](deployment/ansible.md) | Virtual machines and bare metal |
| [Terraform and OpenTofu](deployment/terraform.md) | Infrastructure as code |

**I want to configure it**

| Document | |
| --- | --- |
| [Policy reference](policy-reference.md) | Every field of the policy language, with worked examples |
| [Transparent mode](transparent-mode.md) | Confining a workload that does not know the gateway exists |
| [CLI](cli.md) | Every `roctl` command |
| [API](api.md) | The control-plane and gateway REST surfaces |

**I want to run it**

| Document | |
| --- | --- |
| [Operations](operations.md) | Publishing, rollback, emergency deny, capacity, upgrades, backup |
| [Observability](observability.md) | Metrics, audit trail, alerts, dashboards |
| [Troubleshooting](troubleshooting.md) | Every deny reason and what to do about it |

**I want to change it**

| Document | |
| --- | --- |
| [Testing](testing.md) | How to run and extend every suite |
| [Contributing](../CONTRIBUTING.md) | How to propose a change |
| [Security policy](../SECURITY.md) | How to report a bypass |

---

## Diagrams

Generated with [`diagrams`](https://diagrams.mingrammer.com/) and
[KubeDiagrams](https://github.com/philippemerle/KubeDiagrams). Regenerate them
after changing the architecture:

```bash
pip install diagrams KubeDiagrams
bash docs/diagrams/generate.sh
```

| Diagram | Shows |
| --- | --- |
| [architecture.png](diagrams/architecture.png) | The whole system: sandboxes, node enforcement, data plane, control plane, observability |
| [request-path.png](diagrams/request-path.png) | The four stages one request passes through, and where each can be refused |
| [enforcement-layers.png](diagrams/enforcement-layers.png) | The five layers a sandbox has to get past |
| [policy-tiers.png](diagrams/policy-tiers.png) | How global, cluster, namespace, profile and pod tiers compose into one decision |
| [control-plane.png](diagrams/control-plane.png) | Publishing, versioning, adoption and rollback |
| [failure-modes.png](diagrams/failure-modes.png) | What happens when the gateway, the controller, a bundle or an operator's patience fails |
| [kubernetes-base.png](diagrams/kubernetes-base.png) | The rendered kustomize base, drawn from the manifests themselves |
| [kubernetes-helm.png](diagrams/kubernetes-helm.png) | The rendered Helm chart, drawn from the manifests themselves |
| [kubernetes-sandbox.png](diagrams/kubernetes-sandbox.png) | The example sandbox workloads and what they mount |

The three Kubernetes diagrams are generated from the actual rendered manifests
and the example workloads, so they cannot drift from what deploys.

---

## The shortest useful path

If you are evaluating Rokh Oghab and have twenty minutes:

1. Read the [security model](security-model.md) — it is the argument.
2. Run `make up && make smoke` — it is the argument, executed.
3. Run `sudo make test-bypass` — seventeen escape attempts from a sandbox with
   more privilege than yours will have.
4. Read [the honest limitation](../README.md#an-honest-limitation).

If you are deploying it and have an afternoon:

1. [Kubernetes deployment](deployment/kubernetes.md)
2. [Policy reference](policy-reference.md), as far as the first worked example
3. [Operations](operations.md), the "daily loop" and "when something is wrong"
4. [Observability](observability.md), the alerts section — set those up before
   you need them
