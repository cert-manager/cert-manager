# cert-manager

cert-manager is a Kubernetes addon to automate the management and issuance of
TLS certificates from various issuing sources.

It will ensure certificates are valid and up to date periodically, and attempt
to renew certificates at an appropriate time before expiry.

## TL;DR;

```console
$ helm install .
```

## Introduction

This chart creates a cert-manager deployment on a Kubernetes cluster using the Helm package manager.

## Prerequisites

- Kubernetes cluster with support for CustomResourceDefinition or ThirdPartyResource

## Installing the Chart

To install the chart with the release name `my-release`:

```console
$ helm install --name my-release .
```

> **Tip**: List all releases using `helm list`

## Uninstalling the Chart

To uninstall/delete the `my-release` deployment:

```console
$ helm delete my-release
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## Configuration

The following tables lists the configurable parameters of the Drupal chart and their default values.

| Parameter              | Description                             | Default                                        |
| ---------------------- | --------------------------------------- | ---------------------------------------------- |
| `image.repository`     | Image repository                        | `jetstackexperimental/cert-manager-controller` |
| `image.tag`            | Image tag                               | `canary`                                       |
| `image.pullPolicy`     | Image pull policy                       | `Always`                                       |
| `replicaCount`         | Number of cert-manager replicas         | `1`                                            |
| `createCustomResource` | Create CRD/TPR with this release        | `true`                                         |
| `rbac.enabled`         | Create RBAC resources with this release | `true`                                         |
| `resources`            | CPU/Memory resource requests/limits     | `None`                                         |

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`.

Alternatively, a YAML file that specifies the values for the above parameters can be provided while installing the chart. For example,

```console
$ helm install --name my-release -f values.yaml .
```
> **Tip**: You can use the default [values.yaml](values.yaml)
