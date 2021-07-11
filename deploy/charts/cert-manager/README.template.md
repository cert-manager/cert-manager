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
$ kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/{{ .Chart.Version }}/cert-manager.crds.yaml
```

To install the chart with the release name `{{ .Release.Name }}`:

```console
## Add the Jetstack Helm repository
$ helm repo add {{ .Repository.Name }} {{ .Repository.URL }}

## Install the cert-manager helm chart
$ helm install {{ .Release.Name }} {{ .Repository.Name }}/{{ .Chart.Name }} -n {{ .Release.Namespace }} --version={{ .Chart.Version }}
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

To uninstall/delete the `{{ .Release.Name }}` deployment:

```console
$ helm delete {{ .Release.Name }}
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

If you want to completely uninstall cert-manager from your cluster, you will also need to
delete the previously installed CustomResourceDefinition resources:

```console
$ kubectl delete -f https://github.com/jetstack/cert-manager/releases/download/{{ .Chart.Version }}/cert-manager.crds.yaml
```

## Configuration

The following table lists the configurable parameters of the cert-manager chart and their default values.

{{ .Chart.Values }}

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`.

Alternatively, a YAML file that specifies the values for the above parameters can be provided while installing the chart. For example,

```console
$ helm install {{ .Release.Name }} {{ .Repository.Name }}/{{ .Chart.Name }} -n {{ .Release.Namespace }} --version={{ .Chart.Version }} --values values.yaml
```
> **Tip**: You can use the default [values.yaml](https://github.com/jetstack/cert-manager/blob/master/deploy/charts/cert-manager/values.yaml)

## Contributing

This chart is maintained at [github.com/jetstack/cert-manager](https://github.com/jetstack/cert-manager/tree/master/deploy/charts/cert-manager).
