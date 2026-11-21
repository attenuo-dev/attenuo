{{- define "attenuo.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "attenuo.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "attenuo.selectorLabels" -}}
app.kubernetes.io/name: {{ include "attenuo.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "attenuo.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "attenuo.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "attenuo.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "attenuo.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "attenuo.configSecretName" -}}
{{- default (printf "%s-config" (include "attenuo.fullname" .)) .Values.existingConfigSecret }}
{{- end }}

{{- define "attenuo.policyConfigMapName" -}}
{{- default (printf "%s-policy" (include "attenuo.fullname" .)) .Values.existingPolicyConfigMap }}
{{- end }}

{{- define "attenuo.claimName" -}}
{{- default (printf "%s-data" (include "attenuo.fullname" .)) .Values.persistence.existingClaim }}
{{- end }}

{{/* Stop the install with a clear message when a required value is missing or unsafe. */}}
{{- define "attenuo.validate" -}}
{{- if not .Values.publicUrl }}
{{- fail "publicUrl is required: the URL agents use to reach attenuo, for example https://attenuo.example.com" }}
{{- end }}
{{- if not (or (hasPrefix "https://" .Values.publicUrl) (hasPrefix "http://" .Values.publicUrl)) }}
{{- fail "publicUrl must start with https:// (or http:// together with allowInsecureHttp)" }}
{{- end }}
{{- if and (hasPrefix "http://" .Values.publicUrl) (not .Values.allowInsecureHttp) }}
{{- fail "publicUrl is http://: tokens and the admin bearer would cross the network in cleartext. Use an https:// URL, or set allowInsecureHttp=true for a network you trust" }}
{{- end }}
{{- if and (not .Values.config) (not .Values.existingConfigSecret) }}
{{- fail "config is required: the text of attenuo.toml (--set-file config=attenuo.toml), or existingConfigSecret" }}
{{- end }}
{{- if and .Values.config .Values.existingConfigSecret }}
{{- fail "set config or existingConfigSecret, not both" }}
{{- end }}
{{- if and (not .Values.policy) (not .Values.existingPolicyConfigMap) }}
{{- fail "policy is required: the text of the Cedar policy file (--set-file policy=policy.cedar), or existingPolicyConfigMap" }}
{{- end }}
{{- if and .Values.policy .Values.existingPolicyConfigMap }}
{{- fail "set policy or existingPolicyConfigMap, not both" }}
{{- end }}
{{- range .Values.persistence.accessModes }}
{{- if ne . "ReadWriteOnce" }}{{- if ne . "ReadWriteOncePod" }}
{{- fail "persistence.accessModes must be ReadWriteOnce or ReadWriteOncePod: one attenuo process per database file, and never a network filesystem" }}
{{- end }}{{- end }}
{{- end }}
{{- end }}
