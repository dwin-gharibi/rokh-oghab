variable "kubeconfig" {
  description = "Path to the kubeconfig used for this deployment."
  type        = string
  default     = "~/.kube/config"
}

variable "kube_context" {
  description = "Context within the kubeconfig."
  type        = string
  default     = ""
}

variable "chart_path" {
  description = "Path to the Rokh Oghab chart checked out from this repository."
  type        = string
  default     = "../helm/rokh-oghab"
}
