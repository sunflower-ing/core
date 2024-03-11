{{/*
Expand the name of the chart.
*/}}
{{- define "sunflower.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "sunflower.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "sunflower.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "sunflower.labels.application" -}}
helm.sh/chart: {{ include "sunflower.chart" . }}
{{ include "sunflower.selectorLabels.application" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sunflower.selectorLabels.application" -}}
app.kubernetes.io/name: {{ include "sunflower.name" . }}-application
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "sunflower.serviceAccountName.application" -}}
{{- if .Values.application.serviceAccount.create }}
{{- default (include "sunflower.fullname" .) .Values.application.serviceAccount.name }}-application
{{- else }}
{{- default "default" .Values.application.serviceAccount.name }}
{{- end }}
{{- end }}


{{/*
Common labels
*/}}
{{- define "sunflower.labels.docs" -}}
helm.sh/chart: {{ include "sunflower.chart" . }}
{{ include "sunflower.selectorLabels.docs" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sunflower.selectorLabels.docs" -}}
app.kubernetes.io/name: {{ include "sunflower.name" . }}-docs
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "sunflower.serviceAccountName.docs" -}}
{{- if .Values.docs.serviceAccount.create }}
{{- default (include "sunflower.fullname" .) .Values.docs.serviceAccount.name }}-docs
{{- else }}
{{- default "default" .Values.docs.serviceAccount.name }}
{{- end }}
{{- end }}


{{/*
Common labels
*/}}
{{- define "sunflower.labels.celery" -}}
helm.sh/chart: {{ include "sunflower.chart" . }}
{{ include "sunflower.selectorLabels.celery" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sunflower.selectorLabels.celery" -}}
app.kubernetes.io/name: {{ include "sunflower.name" . }}-celery
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "sunflower.serviceAccountName.celery" -}}
{{- if .Values.celery.serviceAccount.create }}
{{- default (include "sunflower.fullname" .) .Values.celery.serviceAccount.name }}-celery
{{- else }}
{{- default "default" .Values.celery.serviceAccount.name }}
{{- end }}
{{- end }}
