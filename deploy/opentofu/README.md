# Deploying Rokh Oghab with OpenTofu

The module under `deploy/terraform/modules/rokh-oghab-k8s` is plain HCL with no
Terraform-specific features, so OpenTofu consumes it unchanged. This directory
is a ready-to-run root module that points at it.

```bash
cd deploy/opentofu
tofu init
tofu plan  -var kubeconfig=$HOME/.kube/config
tofu apply -var kubeconfig=$HOME/.kube/config
```

Read the sandbox wiring back out:

```bash
tofu output -json sandbox_pod_template
tofu output -raw  resolver_address
tofu output -raw  operator_token
```
