{{- define "rokh-oghab.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "rokh-oghab.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" (include "rokh-oghab.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "rokh-oghab.namespace" -}}
{{- default .Release.Namespace .Values.namespace.name -}}
{{- end -}}

{{- define "rokh-oghab.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "rokh-oghab.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: rokh-oghab
{{- end -}}

{{- define "rokh-oghab.gatewaySelectorLabels" -}}
app.kubernetes.io/name: {{ include "rokh-oghab.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
{{- end -}}

{{- define "rokh-oghab.controllerSelectorLabels" -}}
app.kubernetes.io/name: {{ include "rokh-oghab.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: controller
{{- end -}}

{{- define "rokh-oghab.agentSelectorLabels" -}}
app.kubernetes.io/name: {{ include "rokh-oghab.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end -}}

{{- define "rokh-oghab.image" -}}
{{- $component := index . 0 -}}
{{- $root := index . 1 -}}
{{- $registry := $root.Values.global.imageRegistry -}}
{{- if $component.digest -}}
{{- printf "%s/%s@%s" $registry $component.repository $component.digest -}}
{{- else -}}
{{- printf "%s/%s:%s" $registry $component.repository (default $root.Chart.AppVersion $component.tag) -}}
{{- end -}}
{{- end -}}

{{- define "rokh-oghab.tokenSecretName" -}}
{{- if .Values.tokens.existingSecret -}}
{{- .Values.tokens.existingSecret -}}
{{- else -}}
{{- printf "%s-tokens" (include "rokh-oghab.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "rokh-oghab.controllerUrl" -}}
{{- printf "http://%s-controller.%s.svc.cluster.local:%d" (include "rokh-oghab.fullname" .) (include "rokh-oghab.namespace" .) (int .Values.controller.service.port) -}}
{{- end -}}

{{- define "rokh-oghab.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "rokh-oghab.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop:
    - ALL
{{- end -}}
