{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "cert-manager.preflight" -}}
  {{- if and (.Values.installCRDs) (or (.Values.crds.install) (.Values.crds.keep)) }}
    {{- fail "ERROR: Cannot set both .Values.installCRDs and .Values.crds.install" }}
  {{- end }}
{{- end -}}
