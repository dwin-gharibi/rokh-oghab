module "rokh_oghab" {
  source = "../../modules/rokh-oghab-k8s"

  chart_path = var.chart_path

  sandbox_namespaces = ["execution", "training"]
  sandbox_pod_cidrs  = ["10.244.0.0/16"]

  gateway_replicas = 3

  autoscaling = {
    enabled      = true
    min_replicas = 3
    max_replicas = 30
    target_cpu   = 65
  }

  enable_node_agent       = true
  enable_network_policies = true
  min_tls_version         = "1.2"

  blocked_cidrs = [
    "10.96.0.0/12",
    "10.244.0.0/16",
    "172.20.0.0/16",
  ]

  profiles = {
    untrusted-python = {
      rules = [
        {
          name      = "python-package-index"
          action    = "allow"
          ports     = [443]
          protocols = ["https"]
          destinations = {
            hostnames        = ["pypi.org"]
            hostnameSuffixes = ["pythonhosted.org"]
          }
        },
      ]
    }

    untrusted-node = {
      rules = [
        {
          name      = "npm-registry"
          action    = "allow"
          ports     = [443]
          protocols = ["https"]
          destinations = {
            hostnames = ["registry.npmjs.org"]
          }
        },
      ]
    }
  }

  monitoring = {
    service_monitor = true
    prometheus_rule = true
  }
}

output "proxy_url" {
  value = module.rokh_oghab.proxy_url
}

output "resolver_address" {
  value = module.rokh_oghab.resolver_address
}

output "sandbox_pod_template" {
  value = module.rokh_oghab.sandbox_pod_template
}

output "operator_token" {
  value     = module.rokh_oghab.operator_token
  sensitive = true
}
