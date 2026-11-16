{{- define "diagnosis-reader.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "diagnosis-reader.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "diagnosis-reader.selectorLabels" -}}
app.kubernetes.io/name: {{ include "diagnosis-reader.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "diagnosis-reader.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "diagnosis-reader.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* The service account of route B, and the name of the Role that lets the groups create its tokens. */}}
{{- define "diagnosis-reader.serviceAccountName" -}}{{ include "diagnosis-reader.fullname" . }}{{- end -}}
{{- define "diagnosis-reader.tokenRoleName" -}}{{ include "diagnosis-reader.fullname" . | trunc 52 | trimSuffix "-" }}-token{{- end -}}

{{/* Stops the install on values that would bind nobody, or everybody. */}}
{{- define "diagnosis-reader.validate" -}}
{{- if and (not .Values.bind.groups) (not .Values.bind.serviceAccount) -}}
{{- fail "Nothing is bound. Set bind.groups, or bind.serviceAccount to true." -}}
{{- end -}}
{{- range .Values.bind.groups -}}
{{- if hasPrefix "system:" (lower .) -}}
{{- fail (printf "bind.groups holds %q. A group that starts with system: would give the read role to far more than a read-only identity." .) -}}
{{- end -}}
{{- end -}}
{{- if eq .Values.scope "namespaces" -}}
{{- if not .Values.namespaces -}}{{- fail "scope is namespaces, so list at least one namespace in namespaces." -}}{{- end -}}
{{- else if .Values.namespaces -}}
{{- fail "namespaces is set, but scope is cluster. Set scope to namespaces, or empty namespaces." -}}
{{- end -}}
{{- end -}}

{{/*
The rules of the read role. This is the only place that decides them. The values
choose between two optional reads and nothing else: a verb other than get, list
and watch, and the resources secrets, configmaps, pods/exec, pods/attach and
pods/portforward, cannot be reached from the values.
Pass a dict with "root" (the chart context) and "cluster" (true for a ClusterRole).
*/}}
{{- define "diagnosis-reader.rules" -}}
{{- $values := .root.Values -}}
- apiGroups: [""]
  resources:
    - pods
    {{- if $values.read.podLogs }}
    - pods/log
    {{- end }}
    - events
    - services
    - endpoints
    - persistentvolumeclaims
    {{- if .cluster }}
    - nodes
    - namespaces
    - persistentvolumes
    {{- end }}
  verbs: [get, list, watch]
- apiGroups: [apps]
  resources: [deployments, replicasets, statefulsets, daemonsets, controllerrevisions]
  verbs: [get, list, watch]
- apiGroups: [batch]
  resources: [jobs, cronjobs]
  verbs: [get, list, watch]
- apiGroups: [networking.k8s.io]
  resources: [ingresses, networkpolicies]
  verbs: [get, list, watch]
- apiGroups: [autoscaling]
  resources: [horizontalpodautoscalers]
  verbs: [get, list, watch]
- apiGroups: [policy]
  resources: [poddisruptionbudgets]
  verbs: [get, list, watch]
- apiGroups: [events.k8s.io]
  resources: [events]
  verbs: [get, list, watch]
{{- if $values.read.metrics }}
- apiGroups: [metrics.k8s.io]
  resources:
    - pods
    {{- if .cluster }}
    - nodes
    {{- end }}
  verbs: [get, list]
{{- end }}
{{- end -}}

{{/* The subjects of a binding: the groups, and the service account when route B is on. */}}
{{- define "diagnosis-reader.subjects" -}}
{{- range .Values.bind.groups }}
- kind: Group
  name: {{ . | quote }}
  apiGroup: rbac.authorization.k8s.io
{{- end }}
{{- if .Values.bind.serviceAccount }}
- kind: ServiceAccount
  name: {{ include "diagnosis-reader.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}
{{- end }}
{{- end -}}
