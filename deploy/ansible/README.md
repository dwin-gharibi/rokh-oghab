# Deploying Rokh Oghab with Ansible

Three roles, each doing one job:

| Role | What it does |
| --- | --- |
| `rokh_oghab_controller` | Runs the policy control plane and its versioned store |
| `rokh_oghab_gateway` | Runs the data plane and verifies it refuses unidentified requests |
| `rokh_oghab_host` | Hardens kernel networking and programs nftables so sandboxes have one way out |

## Before you start

```bash
ansible-galaxy collection install -r requirements.yml
```

Put real tokens in a vault rather than in `group_vars`:

```bash
ansible-vault create group_vars/rokh_oghab_vault.yml
```

```yaml
ro_controller_admin_token: "..."
ro_controller_operator_token: "..."
ro_controller_reader_token: "..."
ro_controller_gateway_token: "..."
ro_gateway_admin_token: "..."
ro_gateway_controller_token: "{{ ro_controller_gateway_token }}"
```

## Running it

```bash
ansible-playbook site.yml                 # everything, in dependency order
ansible-playbook controller.yml           # control plane only
ansible-playbook gateway.yml              # data plane only, one host at a time
ansible-playbook nodes.yml                # node enforcement only
ansible-playbook verify.yml               # prove the deployment behaves
```

Tags let you re-run one concern:

```bash
ansible-playbook site.yml --tags config    # re-render configuration
ansible-playbook site.yml --tags agent     # reprogram nftables
ansible-playbook site.yml --tags verify    # only the checks
```

## Stopping egress in a hurry

```bash
ansible-playbook emergency-deny.yml -e ro_emergency_state=on
ansible-playbook emergency-deny.yml -e ro_emergency_state=off
```

## What the roles refuse to do

The roles fail rather than deploy something unsafe:

- a gateway without an admin token, which would leave its admin surface unmanageable
- a gateway with `allowAnonymous` on, unless you acknowledge it explicitly
- a controller whose admin and gateway tokens are the same value, which would let
  a data-plane node rewrite policy
- a node whose gateway address or sandbox ranges are unset, which would leave the
  host unprotected

`verify.yml` additionally asserts that the sandbox chain ends in a drop and that
reverse path filtering is enabled, so a compromised workload cannot forge a
source address to get around the rules.
