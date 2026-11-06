{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "cert-manager.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "cert-manager.fullname" -}}
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
Create the name of the service account to use
*/}}
{{- define "cert-manager.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "cert-manager.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Webhook templates
*/}}

{{/*
Expand the name of the chart.
Manually fix the 'app' and 'name' labels to 'webhook' to maintain
compatibility with the v0.9 deployment selector.
*/}}
{{- define "webhook.name" -}}
{{- printf "webhook" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "webhook.fullname" -}}
{{- $trimmedName := printf "%s" (include "cert-manager.fullname" .) | trunc 55 | trimSuffix "-" -}}
{{- printf "%s-webhook" $trimmedName | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "webhook.caRef" -}}
{{- template "cert-manager.namespace" }}/{{ template "webhook.fullname" . }}-ca
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "webhook.serviceAccountName" -}}
{{- if .Values.webhook.serviceAccount.create -}}
    {{ default (include "webhook.fullname" .) .Values.webhook.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.webhook.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
cainjector templates
*/}}

{{/*
Expand the name of the chart.
Manually fix the 'app' and 'name' labels to 'cainjector' to maintain
compatibility with the v0.9 deployment selector.
*/}}
{{- define "cainjector.name" -}}
{{- printf "cainjector" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "cainjector.fullname" -}}
{{- $trimmedName := printf "%s" (include "cert-manager.fullname" .) | trunc 52 | trimSuffix "-" -}}
{{- printf "%s-cainjector" $trimmedName | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "cainjector.serviceAccountName" -}}
{{- if .Values.cainjector.serviceAccount.create -}}
    {{ default (include "cainjector.fullname" .) .Values.cainjector.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.cainjector.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
startupapicheck templates
*/}}

{{/*
Expand the name of the chart.
Manually fix the 'app' and 'name' labels to 'startupapicheck' to maintain
compatibility with the v0.9 deployment selector.
*/}}
{{- define "startupapicheck.name" -}}
{{- printf "startupapicheck" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "startupapicheck.fullname" -}}
{{- $trimmedName := printf "%s" (include "cert-manager.fullname" .) | trunc 52 | trimSuffix "-" -}}
{{- printf "%s-startupapicheck" $trimmedName | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "startupapicheck.serviceAccountName" -}}
{{- if .Values.startupapicheck.serviceAccount.create -}}
    {{ default (include "startupapicheck.fullname" .) .Values.startupapicheck.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.startupapicheck.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "chartName" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Labels that should be added on each resource

Labels are merged as a map, not concatenated as YAML text, so a key in
.Values.global.commonLabels cannot produce a duplicate key. On conflict
.Values.global.commonLabels wins.

IMPORTANT: This function is standardized across all charts in the cert-manager GH organization.
Any changes to this function should also be made in trust-manager, approver-policy, istio-csr, ...
See https://github.com/cert-manager/cert-manager/issues/9348 for a list of linked PRs.
*/}}
{{- define "labels" -}}
{{- $labels := dict "app.kubernetes.io/version" .Chart.AppVersion -}}
{{- if eq .Values.creator "helm" }}
{{- $labels = merge $labels (dict
      "app.kubernetes.io/managed-by" .Release.Service
      "helm.sh/chart" (include "chartName" .)) }}
{{- end }}
{{- toYaml (mergeOverwrite $labels (.Values.global.commonLabels | default dict)) }}
{{- end -}}

{{/*
Labels for a resource that belongs to one component.

Emits the four identity labels alongside the common labels, merged as one map
so no key can be emitted twice. The identity labels are applied at a LOWER
precedence than .Values.global.commonLabels, so they stay overridable exactly
as they were when the labels were concatenated.

Resources whose identity labels are read by a selector must NOT use these.
They use the matching "*MatchedLabels" helper below, which applies the
selector labels at a higher precedence so that overriding them cannot leave
the selector matching nothing.
*/}}
{{- define "cert-manager.controllerLabels" -}}
{{- toYaml (mergeOverwrite
      (dict "app" (include "cert-manager.name" .)
            "app.kubernetes.io/name" (include "cert-manager.name" .)
            "app.kubernetes.io/instance" .Release.Name
            "app.kubernetes.io/component" "controller")
      (include "labels" . | fromYaml)
) }}
{{- end -}}

{{- define "cert-manager.certManagerLabels" -}}
{{- toYaml (mergeOverwrite
      (dict "app" (include "cert-manager.name" .)
            "app.kubernetes.io/name" (include "cert-manager.name" .)
            "app.kubernetes.io/instance" .Release.Name
            "app.kubernetes.io/component" "cert-manager")
      (include "labels" . | fromYaml)
) }}
{{- end -}}

{{- define "cainjector.componentLabels" -}}
{{- toYaml (mergeOverwrite
      (dict "app" (include "cainjector.name" .)
            "app.kubernetes.io/name" (include "cainjector.name" .)
            "app.kubernetes.io/instance" .Release.Name
            "app.kubernetes.io/component" "cainjector")
      (include "labels" . | fromYaml)
) }}
{{- end -}}

{{- define "webhook.componentLabels" -}}
{{- toYaml (mergeOverwrite
      (dict "app" (include "webhook.name" .)
            "app.kubernetes.io/name" (include "webhook.name" .)
            "app.kubernetes.io/instance" .Release.Name
            "app.kubernetes.io/component" "webhook")
      (include "labels" . | fromYaml)
) }}
{{- end -}}

{{- define "startupapicheck.componentLabels" -}}
{{- toYaml (mergeOverwrite
      (dict "app" (include "startupapicheck.name" .)
            "app.kubernetes.io/name" (include "startupapicheck.name" .)
            "app.kubernetes.io/instance" .Release.Name
            "app.kubernetes.io/component" "startupapicheck")
      (include "labels" . | fromYaml)
) }}
{{- end -}}

{{/*
Labels for a resource whose identity labels a selector reads.

app.kubernetes.io/name, app.kubernetes.io/instance and
app.kubernetes.io/component are applied LAST, so .Values.global.commonLabels
cannot override them: the Deployment, PodDisruptionBudget, Service,
NetworkPolicy, PodMonitor and ServiceMonitor selectors all match on those
three, and a pod template that does not match its own Deployment's selector
is rejected by the API server. "app" is not read by any selector, so it stays
overridable.
*/}}
{{- define "cert-manager.controllerMatchedLabels" -}}
{{- toYaml (mergeOverwrite
      (dict "app" (include "cert-manager.name" .))
      (include "labels" . | fromYaml)
      (dict "app.kubernetes.io/name" (include "cert-manager.name" .)
            "app.kubernetes.io/instance" .Release.Name
            "app.kubernetes.io/component" "controller")
) }}
{{- end -}}

{{- define "cainjector.matchedLabels" -}}
{{- toYaml (mergeOverwrite
      (dict "app" (include "cainjector.name" .))
      (include "labels" . | fromYaml)
      (dict "app.kubernetes.io/name" (include "cainjector.name" .)
            "app.kubernetes.io/instance" .Release.Name
            "app.kubernetes.io/component" "cainjector")
) }}
{{- end -}}

{{- define "webhook.matchedLabels" -}}
{{- toYaml (mergeOverwrite
      (dict "app" (include "webhook.name" .))
      (include "labels" . | fromYaml)
      (dict "app.kubernetes.io/name" (include "webhook.name" .)
            "app.kubernetes.io/instance" .Release.Name
            "app.kubernetes.io/component" "webhook")
) }}
{{- end -}}

{{/*
Namespace for all resources to be installed into
If not defined in values file then the helm release namespace is used
By default this is not set so the helm release namespace will be used

This gets around an problem within helm discussed here
https://github.com/helm/helm/issues/5358
*/}}
{{- define "cert-manager.namespace" -}}
    {{ .Values.namespace | default .Release.Namespace }}
{{- end -}}

{{/*
Util function for generating the image URL based on the provided options.
IMPORTANT: This function is standardized across all charts in the cert-manager GH organization.
Any changes to this function should also be made in cert-manager, trust-manager, approver-policy, ...
See https://github.com/cert-manager/cert-manager/issues/6329 for a list of linked PRs.
*/}}
{{- define "cert-manager.image" -}}
{{- /*
Calling convention:

- (tuple <imageValues> <imageRegistry> <imageNamespace> <defaultReference>)

We intentionally pass imageRegistry/imageNamespace as explicit arguments rather than reading
from `.Values` inside this helper, because `helm-tool lint` does not reliably track `.Values.*`
usage through tuple/variable indirection.
*/ -}}

{{- if ne (len .) 4 -}}
    {{- fail (printf "ERROR: template \"cert-manager.image\" expects (tuple <imageValues> <imageRegistry> <imageNamespace> <defaultReference>), got %d arguments" (len .)) -}}
{{- end -}}

{{- $image := index . 0 -}}
{{- $imageRegistry := index . 1 | default "" -}}
{{- $imageNamespace := index . 2 | default "" -}}
{{- $defaultReference := index . 3 -}}

{{- $repository := "" -}}
{{- if $image.repository -}}
    {{- $repository = $image.repository -}}

    {{- /*
        Backwards compatibility: if image.registry is set, additionally prefix the repository with this registry.
    */ -}}
    {{- if $image.registry -}}
        {{- $repository = printf "%s/%s" $image.registry $repository -}}
    {{- end -}}
{{- else -}}
    {{- $name := required "ERROR: image.name must be set when image.repository is empty" $image.name -}}
    {{- $repository = $name -}}

    {{- if $imageNamespace -}}
        {{- $repository = printf "%s/%s" $imageNamespace $repository -}}
    {{- end -}}

    {{- if $imageRegistry -}}
        {{- $repository = printf "%s/%s" $imageRegistry $repository -}}
    {{- end -}}

    {{- /*
        Backwards compatibility: if image.registry is set, additionally prefix the repository with this registry.
    */ -}}
    {{- if $image.registry -}}
        {{- $repository = printf "%s/%s" $image.registry $repository -}}
    {{- end -}}
{{- end -}}

{{- $repository -}}
{{- if and $image.tag $image.digest -}}
    {{- printf ":%s@%s" $image.tag $image.digest -}}
{{- else if $image.tag -}}
    {{- printf ":%s" $image.tag -}}
{{- else if $image.digest -}}
    {{- printf "@%s" $image.digest -}}
{{- else -}}
    {{- printf "%s" $defaultReference -}}
{{- end -}}
{{- end }}

{{/*
Labels for the CRD resources.
*/}}
{{- define "cert-manager.crd-labels" -}}
{{- toYaml (mergeOverwrite
      (dict "app" (include "cert-manager.name" .)
            "app.kubernetes.io/name" (include "cert-manager.name" .)
            "app.kubernetes.io/instance" .Release.Name
            "app.kubernetes.io/component" "crds")
      (include "labels" . | fromYaml)
) }}
{{- end -}}

{{/*
Check that the user has not set both .installCRDs and .crds.enabled or
set .installCRDs and disabled .crds.keep.
.installCRDs is deprecated and users should use .crds.enabled and .crds.keep instead.
*/}}
{{- define "cert-manager.crd-check" -}}
  {{- if and (.Values.installCRDs) (.Values.crds.enabled) }}
    {{- fail "ERROR: the deprecated .installCRDs option cannot be enabled at the same time as its replacement .crds.enabled" }}
  {{- end }}
  {{- if and (.Values.installCRDs) (not .Values.crds.keep) }}
    {{- fail "ERROR: .crds.keep is not compatible with .installCRDs, please use .crds.enabled and .crds.keep instead" }}
  {{- end }}
{{- end -}}
