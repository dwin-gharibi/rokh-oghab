locals {
  generated_token_length = 40

  tokens = {
    admin         = var.tokens.admin != "" ? var.tokens.admin : random_password.token["admin"].result
    operator      = var.tokens.operator != "" ? var.tokens.operator : random_password.token["operator"].result
    reader        = var.tokens.reader != "" ? var.tokens.reader : random_password.token["reader"].result
    gateway       = var.tokens.gateway != "" ? var.tokens.gateway : random_password.token["gateway"].result
    gateway_admin = var.tokens.gateway_admin != "" ? var.tokens.gateway_admin : random_password.token["gateway_admin"].result
  }

  chart_values = {
    global = {
      imageRegistry = var.image_registry
    }

    namespace = {
      create = var.create_namespace
      name   = var.namespace
    }

    sandbox = {
      namespaces       = var.sandbox_namespaces
      createNamespaces = true
      podCidrs         = var.sandbox_pod_cidrs
    }

    tokens = {
      create = true
      controller = {
        admin    = local.tokens.admin
        operator = local.tokens.operator
        reader   = local.tokens.reader
        gateway  = local.tokens.gateway
      }
      gatewayAdmin = local.tokens.gateway_admin
    }

    gateway = {
      enabled      = true
      replicaCount = var.gateway_replicas
      image        = var.image_tag != "" ? { tag = var.image_tag } : {}
      service = {
        clusterIP = var.gateway_service_cluster_ip
      }
      autoscaling = {
        enabled                        = var.autoscaling.enabled
        minReplicas                    = var.autoscaling.min_replicas
        maxReplicas                    = var.autoscaling.max_replicas
        targetCPUUtilizationPercentage = var.autoscaling.target_cpu
      }
      config = {
        resolver = {
          servers = var.resolvers
        }
        guard = {
          blocked         = var.blocked_cidrs
          allowExceptions = var.allow_exceptions
        }
        strict = {
          minTlsVersion = var.min_tls_version
          tlsPorts      = var.tls_ports
        }
        audit = {
          logPaths = var.log_request_paths
        }
        identities = {
          allowAnonymous = var.allow_anonymous
        }
      }
    }

    controller = {
      enabled = true
      image   = var.image_tag != "" ? { tag = var.image_tag } : {}
    }

    agent = {
      enabled     = var.enable_node_agent
      transparent = var.transparent_interception
      image       = var.image_tag != "" ? { tag = var.image_tag } : {}
    }

    networkPolicy = {
      enabled = var.enable_network_policies
    }

    monitoring = {
      serviceMonitor = {
        enabled = var.monitoring.service_monitor
      }
      prometheusRule = {
        enabled = var.monitoring.prometheus_rule
      }
    }

    profiles = var.profiles
  }
}

resource "random_password" "token" {
  for_each = toset(["admin", "operator", "reader", "gateway", "gateway_admin"])

  length  = local.generated_token_length
  special = false
}

resource "helm_release" "rokh_oghab" {
  name             = var.release_name
  namespace        = var.namespace
  create_namespace = var.create_namespace

  chart      = var.chart_path != "" ? var.chart_path : "rokh-oghab"
  repository = var.chart_path != "" ? null : var.chart_repository
  version    = var.chart_version != "" ? var.chart_version : null

  atomic          = true
  cleanup_on_fail = true
  wait            = true
  timeout         = 600

  values = [
    yamlencode(local.chart_values),
    yamlencode(var.extra_values),
  ]
}
