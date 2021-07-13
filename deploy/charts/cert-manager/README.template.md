<!---
The rendered version of this file can be found in "./README.md".
Please only edit the template "./README.template.md".
-->
# cert-manager

cert-manager is a Kubernetes addon to automate the management and issuance of
TLS certificates from various issuing sources.

It will ensure certificates are valid and up to date periodically, and attempt
to renew certificates at an appropriate time before expiry.

## Prerequisites

- Kubernetes 1.11+

## Installing the Chart

Full installation instructions, including details on how to configure extra
functionality in cert-manager can be found in the [installation docs](https://cert-manager.io/docs/installation/kubernetes/).

Before installing the chart, you must first install the cert-manager CustomResourceDefinition resources.
This is performed in a separate step to allow you to easily uninstall and reinstall cert-manager without deleting your installed custom resources.

```bash
$ kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/{{ .Run.Chart.Version }}/cert-manager.crds.yaml
```

To install the chart with the release name `{{ .Run.Release.Name }}`:

```console
# Add the {{ .Run.Repository.Name }} Helm repository
$ helm repo add {{ .Run.Repository.Name }} {{ .Run.Repository.URL }}

# Install the {{ .Run.Chart.Name }} helm chart
$ helm install {{ .Run.Release.Name }} {{ .Run.Repository.Name }}/{{ .Run.Chart.Name }} -n {{ .Run.Release.Namespace }} --version={{ .Run.Chart.Version }}
```

In order to begin issuing certificates, you will need to set up a ClusterIssuer
or Issuer resource (for example, by creating a 'letsencrypt-staging' issuer).

More information on the different types of issuers and how to configure them
can be found in [our documentation](https://cert-manager.io/docs/configuration/).

For information on how to configure cert-manager to automatically provision
Certificates for Ingress resources, take a look at the
[Securing Ingresses documentation](https://cert-manager.io/docs/usage/ingress/).

> **Tip**: List all releases using `helm list`

## Upgrading the Chart

Special considerations may be required when upgrading the Helm chart, and these
are documented in our full [upgrading guide](https://cert-manager.io/docs/installation/upgrading/).

**Please check here before performing upgrades!**

## Uninstalling the Chart

To uninstall/delete the `{{ .Run.Release.Name }}` deployment:

```console
$ helm delete {{ .Run.Release.Name }}
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

If you want to completely uninstall cert-manager from your cluster, you will also need to
delete the previously installed CustomResourceDefinition resources:

```console
$ kubectl delete -f https://github.com/jetstack/cert-manager/releases/download/{{ .Run.Chart.Version }}/cert-manager.crds.yaml
```

## Configuration

The following table lists the configurable parameters of the cert-manager chart and their default values.

| Parameter | Description | Default |
| --------- | ----------- | ------- |
{{- $valueComments := comments "Values" }}
{{- range $index, $element := $valueComments }}
{{- $parts := regexSplit "Example:\n" ($element.Comment | replace "|" "&#124;") -1 }}
{{- $text := first $parts | replace "\n" " " | regexReplaceAll " *" " " }}
{{- $examples := list }}
{{- range $example := rest $parts }}
{{- $examples = append $examples (list "<pre lang=\"yaml\">" ($example | replace "\n" "<br>") "</pre>" | join "") }}
{{- end}}
| `{{ join "." $element.Path }}` | {{ join "" (prepend $examples $text) }} | `{{ $element.Value }}` |
{{- end }}

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`.

Alternatively, a YAML file that specifies the values for the above parameters can be provided while installing the chart. For example,

```console
$ helm install {{ .Run.Release.Name }} {{ .Run.Repository.Name }}/{{ .Run.Chart.Name }} -n {{ .Run.Release.Namespace }} --version={{ .Run.Chart.Version }} --values values.yaml
```
> **Tip**: You can use the default [values.yaml](https://github.com/jetstack/cert-manager/blob/master/deploy/charts/cert-manager/values.yaml)

## Contributing

This chart is maintained at [github.com/jetstack/cert-manager](https://github.com/jetstack/cert-manager/tree/master/deploy/charts/cert-manager).
