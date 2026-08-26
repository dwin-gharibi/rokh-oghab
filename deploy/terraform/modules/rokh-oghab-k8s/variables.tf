variable "release_name" {
  description = "Helm release name for the Rokh Oghab deployment."
  type        = string
  default     = "rokh-oghab"
}

variable "namespace" {
  description = "Namespace that holds the gateway, controller and node agent."
  type        = string
  default     = "rokh-oghab"
}

variable "create_namespace" {
  description = "Create the namespace rather than expecting it to exist."
  type        = bool
  default     = true
}

variable "chart_path" {
  description = "Path to the Rokh Oghab chart. Leave empty to use chart_repository."
  type        = string
  default     = ""
}

variable "chart_repository" {
  description = "Chart repository used when chart_path is empty."
  type        = string
  default     = ""
}

variable "chart_version" {
  description = "Chart version to install."
  type        = string
  default     = ""
}

variable "image_registry" {
  description = "Registry holding the gateway, controller and agent images."
  type        = string
  default     = "ghcr.io/rokh-oghab"
}

variable "image_tag" {
  description = "Image tag to deploy. Empty uses the chart's appVersion."
  type        = string
  default     = ""
}

variable "sandbox_namespaces" {
  description = "Namespaces whose workloads may only reach the network through the gateway."
  type        = list(string)
  default     = ["execution"]

  validation {
    condition     = length(var.sandbox_namespaces) > 0
    error_message = "At least one sandbox namespace is required, otherwise nothing is confined."
  }
}

variable "sandbox_pod_cidrs" {
  description = "Pod ranges the node agent confines."
  type        = list(string)
  default     = ["10.244.0.0/16"]

  validation {
    condition = alltrue([
      for cidr in var.sandbox_pod_cidrs : can(cidrhost(cidr, 0))
    ])
    error_message = "Every entry in sandbox_pod_cidrs must be a valid CIDR."
  }
}

variable "gateway_replicas" {
  description = "Number of gateway replicas when autoscaling is disabled."
  type        = number
  default     = 3

  validation {
    condition     = var.gateway_replicas >= 1
    error_message = "At least one gateway replica is required."
  }
}

variable "gateway_service_cluster_ip" {
  description = "Stable ClusterIP for the gateway, used as the sandbox resolver address."
  type        = string
  default     = "10.96.0.53"
}

variable "autoscaling" {
  description = "Horizontal autoscaling settings for the gateway."
  type = object({
    enabled      = bool
    min_replicas = number
    max_replicas = number
    target_cpu   = number
  })
  default = {
    enabled      = true
    min_replicas = 3
    max_replicas = 20
    target_cpu   = 70
  }
}

variable "enable_node_agent" {
  description = "Run the nftables enforcement agent on every node."
  type        = bool
  default     = true
}

variable "enable_network_policies" {
  description = "Install the default-deny network policies for sandbox namespaces."
  type        = bool
  default     = true
}

variable "transparent_interception" {
  description = "Redirect plain 80 and 443 into the gateway for workloads that ignore proxy variables."
  type        = bool
  default     = false
}

variable "resolvers" {
  description = "Upstream resolvers the gateway itself uses."
  type        = list(string)
  default     = ["1.1.1.1:53", "8.8.8.8:53"]
}

variable "blocked_cidrs" {
  description = "Extra ranges the address guard refuses on top of its defaults."
  type        = list(string)
  default     = ["10.96.0.0/12", "10.244.0.0/16"]
}

variable "allow_exceptions" {
  description = "Internal ranges deliberately exempted from the address guard."
  type        = list(string)
  default     = []
}

variable "min_tls_version" {
  description = "Lowest TLS version a tunnel may negotiate."
  type        = string
  default     = "1.2"

  validation {
    condition     = contains(["1.0", "1.1", "1.2", "1.3"], var.min_tls_version)
    error_message = "min_tls_version must be 1.0, 1.1, 1.2 or 1.3."
  }
}

variable "tls_ports" {
  description = "Ports treated as TLS, where plaintext inside a tunnel is refused."
  type        = list(number)
  default     = [443, 8443, 9443]
}

variable "allow_anonymous" {
  description = "Treat unidentified callers as one anonymous identity. Leave false."
  type        = bool
  default     = false
}

variable "log_request_paths" {
  description = "Record request paths in the audit trail."
  type        = bool
  default     = false
}

variable "profiles" {
  description = "Sandbox profiles seeded into the bootstrap bundle."
  type = map(object({
    rules = list(object({
      name      = string
      action    = string
      ports     = optional(list(number))
      protocols = optional(list(string))
      methods   = optional(list(string))
      paths     = optional(list(string))
      destinations = object({
        hostnames        = optional(list(string))
        hostnameSuffixes = optional(list(string))
        cidrs            = optional(list(string))
      })
    }))
  }))
  default = {}
}

variable "tokens" {
  description = "Control-plane tokens. Any left empty is generated."
  type = object({
    admin         = optional(string, "")
    operator      = optional(string, "")
    reader        = optional(string, "")
    gateway       = optional(string, "")
    gateway_admin = optional(string, "")
  })
  default   = {}
  sensitive = true
}

variable "monitoring" {
  description = "Prometheus Operator integration."
  type = object({
    service_monitor = bool
    prometheus_rule = bool
  })
  default = {
    service_monitor = false
    prometheus_rule = false
  }
}

variable "extra_values" {
  description = "Additional Helm values merged over everything this module sets."
  type        = any
  default     = {}
}
