{{- define "sluice.name" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sluice.labels" -}}
app.kubernetes.io/name: sluice
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "sluice.selector" -}}
app.kubernetes.io/name: sluice
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}