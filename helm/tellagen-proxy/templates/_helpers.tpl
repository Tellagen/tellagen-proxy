{{- define "tellagen-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tellagen-proxy.fullname" -}}
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

{{- define "tellagen-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tellagen-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tellagen-proxy.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "tellagen-proxy.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "tellagen-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tellagen-proxy.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "tellagen-proxy.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if .Values.image.digest -}}
{{- printf "%s:%s@%s" .Values.image.repository $tag .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}

{{/* Where the files of the Secret are mounted. The whole directory is mounted, never a single key with subPath, so that a changed Secret reaches the pod. */}}
{{- define "tellagen-proxy.secretsDir" -}}/etc/tellagen-proxy/secrets{{- end -}}
{{- define "tellagen-proxy.caDir" -}}/etc/tellagen-proxy/ca{{- end -}}
{{- define "tellagen-proxy.policyDir" -}}/etc/tellagen-proxy/policy{{- end -}}

{{/* The Secret that holds the tokens: yours, or the one this chart makes. */}}
{{- define "tellagen-proxy.secretName" -}}
{{- default (include "tellagen-proxy.fullname" .) .Values.existingSecret -}}
{{- end -}}

{{/* The chart makes a Secret only for tokens passed in the values. */}}
{{- define "tellagen-proxy.makesSecret" -}}
{{- if and (not .Values.existingSecret) (or .Values.tellagen.token .Values.grafana.token) -}}true{{- end -}}
{{- end -}}

{{/* True when at least one token is read from the Secret volume. */}}
{{- define "tellagen-proxy.usesSecretVolume" -}}
{{- if or (not .Values.secretFiles.tellagenToken) (not .Values.secretFiles.grafanaToken) -}}true{{- end -}}
{{- end -}}

{{- define "tellagen-proxy.tellagenTokenFile" -}}
{{- if .Values.secretFiles.tellagenToken -}}
{{- if .Values.tellagen.token -}}{{- fail "tellagen.token and secretFiles.tellagenToken are both set. Set only one, so that a rotated token cannot be hidden by a stale one." -}}{{- end -}}
{{- .Values.secretFiles.tellagenToken -}}
{{- else if or .Values.existingSecret .Values.tellagen.token -}}
{{- if and .Values.existingSecret .Values.tellagen.token -}}{{- fail "tellagen.token and existingSecret are both set. Set only one." -}}{{- end -}}
{{- printf "%s/%s" (include "tellagen-proxy.secretsDir" .) .Values.secretKeys.tellagenToken -}}
{{- else -}}
{{- fail "The Tellagen proxy token is missing. Set tellagen.token (with --set-file), existingSecret, or secretFiles.tellagenToken." -}}
{{- end -}}
{{- end -}}

{{- define "tellagen-proxy.grafanaTokenFile" -}}
{{- if .Values.secretFiles.grafanaToken -}}
{{- if .Values.grafana.token -}}{{- fail "grafana.token and secretFiles.grafanaToken are both set. Set only one, so that a rotated token cannot be hidden by a stale one." -}}{{- end -}}
{{- .Values.secretFiles.grafanaToken -}}
{{- else if or .Values.existingSecret .Values.grafana.token -}}
{{- if and .Values.existingSecret .Values.grafana.token -}}{{- fail "grafana.token and existingSecret are both set. Set only one." -}}{{- end -}}
{{- printf "%s/%s" (include "tellagen-proxy.secretsDir" .) .Values.secretKeys.grafanaToken -}}
{{- else -}}
{{- fail "The Grafana service account token is missing. Set grafana.token (with --set-file), existingSecret, or secretFiles.grafanaToken." -}}
{{- end -}}
{{- end -}}

{{/* The settings of the proxy. A secret is only ever a file name. */}}
{{- define "tellagen-proxy.env" -}}
- name: TELLAGEN_PROXY_TOKEN_FILE
  value: {{ include "tellagen-proxy.tellagenTokenFile" . | quote }}
- name: GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE
  value: {{ include "tellagen-proxy.grafanaTokenFile" . | quote }}
- name: GRAFANA_URL
  value: {{ required "grafana.url is required: the address the proxy uses to reach Grafana." .Values.grafana.url | quote }}
{{- with .Values.grafana.publicUrl }}
- name: GRAFANA_PUBLIC_URL
  value: {{ . | quote }}
{{- end }}
{{- if .Values.grafana.orgId }}
- name: GRAFANA_ORG_ID
  value: {{ int .Values.grafana.orgId | quote }}
{{- end }}
{{- if .Values.grafana.allowedDatasourceUids }}
- name: GRAFANA_ALLOWED_DATASOURCE_UIDS
  value: {{ join "," .Values.grafana.allowedDatasourceUids | quote }}
{{- end }}
{{- with .Values.tellagen.url }}
- name: TELLAGEN_URL
  value: {{ . | quote }}
{{- end }}
{{- if .Values.tellagen.labels }}
{{- $pairs := list }}
{{- range $key, $value := .Values.tellagen.labels }}
{{- $pairs = append $pairs (printf "%s=%s" $key (toString $value)) }}
{{- end }}
- name: TELLAGEN_LABELS
  value: {{ join "," $pairs | quote }}
{{- end }}
- name: TELLAGEN_INSTALL_METHOD
  value: helm
{{- with .Values.proxy.httpsProxy }}
- name: HTTPS_PROXY
  value: {{ . | quote }}
{{- end }}
{{- with .Values.proxy.noProxy }}
- name: NO_PROXY
  value: {{ . | quote }}
{{- end }}
{{- with .Values.proxy.grafanaHttpsProxy }}
- name: GRAFANA_HTTPS_PROXY
  value: {{ . | quote }}
{{- end }}
{{- if .Values.caBundle.configMap }}
- name: TELLAGEN_CA_FILE
  value: {{ printf "%s/%s" (include "tellagen-proxy.caDir" .) .Values.caBundle.key | quote }}
- name: GRAFANA_CA_FILE
  value: {{ printf "%s/%s" (include "tellagen-proxy.caDir" .) .Values.caBundle.key | quote }}
{{- end }}
{{- if .Values.policy }}
- name: TELLAGEN_POLICY_FILE
  value: {{ printf "%s/policy.yaml" (include "tellagen-proxy.policyDir" .) | quote }}
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "tellagen-proxy.volumeMounts" -}}
{{- if include "tellagen-proxy.usesSecretVolume" . }}
- name: secrets
  mountPath: {{ include "tellagen-proxy.secretsDir" . }}
  readOnly: true
{{- end }}
{{- if .Values.caBundle.configMap }}
- name: ca
  mountPath: {{ include "tellagen-proxy.caDir" . }}
  readOnly: true
{{- end }}
{{- if .Values.policy }}
- name: policy
  mountPath: {{ include "tellagen-proxy.policyDir" . }}
  readOnly: true
{{- end }}
{{- with .Values.extraVolumeMounts }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "tellagen-proxy.volumes" -}}
{{- if include "tellagen-proxy.usesSecretVolume" . }}
- name: secrets
  secret:
    secretName: {{ include "tellagen-proxy.secretName" . }}
    defaultMode: 0440
{{- end }}
{{- if .Values.caBundle.configMap }}
- name: ca
  configMap:
    name: {{ .Values.caBundle.configMap }}
    defaultMode: 0444
{{- end }}
{{- if .Values.policy }}
- name: policy
  configMap:
    name: {{ include "tellagen-proxy.fullname" . }}-policy
    defaultMode: 0444
{{- end }}
{{- if .Values.serviceAccount.vaultAuth }}
- name: vault-token
  projected:
    sources:
      - serviceAccountToken:
          audience: vault
          expirationSeconds: 3600
          path: token
{{- end }}
{{- with .Values.extraVolumes }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "tellagen-proxy.podSecurityContext" -}}
runAsNonRoot: true
{{- if not .Values.openshift }}
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
{{- end }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "tellagen-proxy.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop:
    - ALL
{{- end -}}

{{/* The annotations of the pod. Vault Agent reads the token volume by name. */}}
{{- define "tellagen-proxy.podAnnotations" -}}
{{- $annotations := dict }}
{{- if .Values.serviceAccount.vaultAuth }}
{{- $_ := set $annotations "vault.hashicorp.com/agent-service-account-token-volume-name" "vault-token" }}
{{- end }}
{{- if .Values.policy }}
{{- $_ := set $annotations "checksum/policy" (include "tellagen-proxy.policyFile" . | sha256sum) }}
{{- end }}
{{- $annotations = merge $annotations (default (dict) .Values.podAnnotations) }}
{{- if $annotations }}
{{- toYaml $annotations }}
{{- end }}
{{- end -}}

{{- define "tellagen-proxy.policyFile" -}}
{{- toYaml .Values.policy -}}
{{- end -}}
