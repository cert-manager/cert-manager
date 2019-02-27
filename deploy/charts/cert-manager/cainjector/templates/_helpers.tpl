{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "cainjector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "cainjector.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cainjector.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cainjector.selfSignedIssuer" -}}
{{ printf "%s-selfsign" (include "cainjector.fullname" .) }}
{{- end -}}

{{- define "cainjector.rootCAIssuer" -}}
{{ printf "%s-ca" (include "cainjector.fullname" .) }}
{{- end -}}

{{- define "cainjector.rootCACertificate" -}}
{{ printf "%s-ca" (include "cainjector.fullname" .) }}
{{- end -}}

{{- define "cainjector.servingCertificate" -}}
{{ printf "%s-cainjector-tls" (include "cainjector.fullname" .) }}
{{- end -}}
