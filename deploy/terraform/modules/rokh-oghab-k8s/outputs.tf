output "namespace" {
  description = "Namespace holding the Rokh Oghab components."
  value       = var.namespace
}

output "proxy_url" {
  description = "Proxy endpoint a sandbox should be pointed at."
  value       = "http://${var.release_name}-gateway.${var.namespace}.svc.cluster.local:3128"
}

output "resolver_address" {
  description = "Address a sandbox should use as its only nameserver."
  value       = var.gateway_service_cluster_ip
}

output "controller_url" {
  description = "Control-plane endpoint for roctl."
  value       = "http://${var.release_name}-controller.${var.namespace}.svc.cluster.local:8081"
}

output "admin_token" {
  description = "Control-plane administrative token."
  value       = local.tokens.admin
  sensitive   = true
}

output "operator_token" {
  description = "Control-plane operator token, enough to publish policy."
  value       = local.tokens.operator
  sensitive   = true
}

output "reader_token" {
  description = "Read-only control-plane token."
  value       = local.tokens.reader
  sensitive   = true
}

output "gateway_admin_token" {
  description = "Token for the gateway admin API."
  value       = local.tokens.gateway_admin
  sensitive   = true
}

output "sandbox_pod_template" {
  description = "Pod fields that place a workload behind the gateway."
  value = {
    dnsPolicy = "None"
    dnsConfig = {
      nameservers = [var.gateway_service_cluster_ip]
      options     = [{ name = "ndots", value = "2" }]
    }
    env = [
      {
        name  = "HTTP_PROXY"
        value = "http://${var.release_name}-gateway.${var.namespace}.svc.cluster.local:3128"
      },
      {
        name  = "HTTPS_PROXY"
        value = "http://${var.release_name}-gateway.${var.namespace}.svc.cluster.local:3128"
      },
      {
        name  = "NO_PROXY"
        value = ""
      },
    ]
  }
}
