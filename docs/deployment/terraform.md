# Deploying with Terraform or OpenTofu

The module is plain HCL with no Terraform-specific features, so OpenTofu
consumes it unchanged.

```
deploy/terraform/modules/rokh-oghab-k8s   the module
deploy/terraform/examples/kubernetes      a Terraform root using it
deploy/opentofu                           an OpenTofu root using the same module
```

## Using it

```hcl
module "rokh_oghab" {
  source = "github.com/dwin-gharibi/rokh-oghab//deploy/terraform/modules/rokh-oghab-k8s"

  sandbox_namespaces = ["execution"]
  sandbox_pod_cidrs  = ["10.244.0.0/16"]

  gateway_replicas = 3

  autoscaling = {
    enabled      = true
    min_replicas = 3
    max_replicas = 30
    target_cpu   = 65
  }

  profiles = {
    untrusted-python = {
      rules = [{
        name      = "python-package-index"
        action    = "allow"
        ports     = [443]
        protocols = ["https"]
        destinations = {
          hostnames        = ["pypi.org"]
          hostnameSuffixes = ["pythonhosted.org"]
        }
      }]
    }
  }
}
```

```bash
terraform init
terraform plan
terraform apply
```

or

```bash
cd deploy/opentofu
tofu init && tofu apply
```

## Variables that matter

| Variable | Why it matters |
| --- | --- |
| `sandbox_pod_cidrs` | The ranges the node agent confines. Must match your cluster |
| `gateway_service_cluster_ip` | A free address in your service CIDR, used as the sandbox resolver |
| `enable_node_agent` | Turn off only if your platform forbids `NET_ADMIN`, and understand you are then relying on NetworkPolicy alone |
| `enable_network_policies` | Turn off only if something else already denies sandbox egress |
| `allow_anonymous` | Leave false. True makes every caller one identity |
| `blocked_cidrs` | Add your service and pod ranges so a sandbox cannot reach cluster internals |

The module validates what it can: at least one sandbox namespace, well-formed
CIDRs, at least one replica, and a TLS version the gateway accepts.

## Outputs

```bash
terraform output -raw  resolver_address
terraform output -json sandbox_pod_template
terraform output -raw  operator_token        # sensitive
```

`sandbox_pod_template` hands back exactly the pod fields needed to place a
workload behind the gateway, so you can splice it into your own manifests
rather than copying values by hand.

## Wiring policy in

Tokens are generated unless you supply them, and every one is marked sensitive.
To feed them to a secret manager:

```hcl
resource "vault_kv_secret_v2" "rokh_oghab" {
  mount = "secret"
  name  = "rokh-oghab"
  data_json = jsonencode({
    admin    = module.rokh_oghab.admin_token
    operator = module.rokh_oghab.operator_token
  })
}
```

Policy itself is usually better managed with `roctl` than with Terraform, since
publishing is a versioned operation with its own rollback. Use `profiles` in
the module for the initial bootstrap, and `roctl` for everything after.
