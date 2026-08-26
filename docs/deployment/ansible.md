# Deploying with Ansible

For virtual machines and bare metal, where there is no Kubernetes to lean on.

## Layout

```
deploy/ansible/
  site.yml               everything in dependency order
  controller.yml         control plane only
  gateway.yml            data plane only, one host at a time
  nodes.yml              node enforcement only, a quarter of the fleet at a time
  verify.yml             prove the deployment behaves
  emergency-deny.yml     stop or resume all sandbox egress
  roles/
    rokh_oghab_controller/
    rokh_oghab_gateway/
    rokh_oghab_host/
```

Each role splits its work into `assert.yml`, `directories.yml`,
`configure.yml`, `service.yml` and `verify.yml`, so you can re-run one concern
with `--tags`.

## Getting started

```bash
cd deploy/ansible
ansible-galaxy collection install -r requirements.yml
cp inventory.example.ini inventory.ini
```

Put real tokens in a vault:

```bash
ansible-vault create group_vars/rokh_oghab_vault.yml
```

```yaml
ro_controller_admin_token: "..."
ro_controller_operator_token: "..."
ro_controller_gateway_token: "..."
ro_gateway_admin_token: "..."
ro_gateway_controller_token: "{{ ro_controller_gateway_token }}"
```

```bash
ansible-playbook site.yml --ask-vault-pass
```

## What the roles refuse to do

They fail rather than deploy something unsafe:

- a gateway with no admin token, which would be unmanageable
- a gateway that trusts anonymous callers, unless you acknowledge it explicitly
- a controller whose admin and gateway tokens are the same value, which would
  let a data-plane node rewrite policy
- a node with no gateway address or sandbox ranges, which would leave the host
  unprotected

Rendered configuration is validated as JSON before it is written, and the
nftables ruleset is validated with `nft` before the service is enabled.

## Verifying

```bash
ansible-playbook verify.yml
```

This asserts that the controller refuses unauthenticated requests, that the
gateway refuses unidentified requests and exposes metrics, that the sandbox
chain ends in a drop, and that reverse path filtering is enabled.

## Stopping egress in a hurry

```bash
ansible-playbook emergency-deny.yml -e ro_emergency_state=on
ansible-playbook emergency-deny.yml -e ro_emergency_state=off
```

## Re-running one concern

```bash
ansible-playbook site.yml --tags config    # re-render configuration
ansible-playbook site.yml --tags agent     # reprogram nftables
ansible-playbook site.yml --tags verify    # only the checks
```
