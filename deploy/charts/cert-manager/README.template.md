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
$ kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/{{RELEASE_VERSION}}/cert-manager.crds.yaml
```

To install the chart with the release name `my-release`:

```console
## Add the Jetstack Helm repository
$ helm repo add jetstack https://charts.jetstack.io

## Install the cert-manager helm chart
$ helm install --name my-release --namespace cert-manager jetstack/cert-manager
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

To uninstall/delete the `my-release` deployment:

```console
$ helm delete my-release
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

If you want to completely uninstall cert-manager from your cluster, you will also need to
delete the previously installed CustomResourceDefinition resources:

```console
$ kubectl delete -f https://github.com/jetstack/cert-manager/releases/download/{{RELEASE_VERSION}}/cert-manager.crds.yaml
```

## Configuration

The following table lists the configurable parameters of the cert-manager chart and their default values.

| Parameter | Description | Default |
| --------- | ----------- | ------- |
| `global.imagePullSecrets` | Reference to one or more secrets to be used when pulling images | `[]` |
| `global.rbac.create` | If `true`, create and use RBAC resources (includes sub-charts) | `true` |
| `global.priorityClassName`| Priority class name for cert-manager and webhook pods | `""` |
| `global.podSecurityPolicy.enabled` | If `true`, create and use PodSecurityPolicy (includes sub-charts) | `false` |
| `global.podSecurityPolicy.useAppArmor` | If `true`, use Apparmor seccomp profile in PSP | `true` |
| `global.leaderElection.namespace` | Override the namespace used to store the ConfigMap for leader election | `kube-system` |
| `global.leaderElection.leaseDuration` | The duration that non-leader candidates will wait after observing a leadership renewal until attempting to acquire leadership of a led but unrenewed leader slot. This is effectively the maximum duration that a leader can be stopped before it is replaced by another candidate |  |
| `global.leaderElection.renewDeadline` | The interval between attempts by the acting master to renew a leadership slot before it stops leading. This must be less than or equal to the lease duration |  |
| `global.leaderElection.retryPeriod` | The duration the clients should wait between attempting acquisition and renewal of a leadership |  |
| `installCRDs` | If true, CRD resources will be installed as part of the Helm chart. If enabled, when uninstalling CRD resources will be deleted causing all installed custom resources to be DELETED | `false` |
| `image.repository` | Image repository | `quay.io/jetstack/cert-manager-controller` |
| `image.tag` | Image tag | `{{RELEASE_VERSION}}` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `replicaCount`  | Number of cert-manager replicas  | `1` |
| `clusterResourceNamespace` | Override the namespace used to store DNS provider credentials etc. for ClusterIssuer resources | Same namespace as cert-manager pod |
| `featureGates` | Comma-separated list of feature gates to enable on the controller pod | `` |
| `extraArgs` | Optional flags for cert-manager | `[]` |
| `extraEnv` | Optional environment variables for cert-manager | `[]` |
| `serviceAccount.create` | If `true`, create a new service account | `true` |
| `serviceAccount.name` | Service account to be used. If not set and `serviceAccount.create` is `true`, a name is generated using the fullname template |  |
| `serviceAccount.annotations` | Annotations to add to the service account |  |
| `volumes` | Optional volumes for cert-manager | `[]` |
| `volumeMounts` | Optional volume mounts for cert-manager | `[]` |
| `resources` | CPU/memory resource requests/limits | `{}` |
| `securityContext` | Optional security context. The yaml block should adhere to the [SecurityContext spec](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.16/#securitycontext-v1-core) | `{}` |
| `securityContext.enabled` | Deprecated (use `securityContext`) - Enable security context | `false` |
| `containerSecurityContext` | Security context to be set on the controller component container | `{}` |
| `nodeSelector` | Node labels for pod assignment | `{}` |
| `affinity` | Node affinity for pod assignment | `{}` |
| `tolerations` | Node tolerations for pod assignment | `[]` |
| `ingressShim.defaultIssuerName` | Optional default issuer to use for ingress resources |  |
| `ingressShim.defaultIssuerKind` | Optional default issuer kind to use for ingress resources |  |
| `ingressShim.defaultIssuerGroup` | Optional default issuer group to use for ingress resources |  |
| `prometheus.enabled` | Enable Prometheus monitoring | `true` |
| `prometheus.servicemonitor.enabled` | Enable Prometheus Operator ServiceMonitor monitoring | `false` |
| `prometheus.servicemonitor.namespace` | Define namespace where to deploy the ServiceMonitor resource | (namespace where you are deploying) |
| `prometheus.servicemonitor.prometheusInstance` | Prometheus Instance definition | `default` |
| `prometheus.servicemonitor.targetPort` | Prometheus scrape port | `9402` |
| `prometheus.servicemonitor.path` | Prometheus scrape path | `/metrics` |
| `prometheus.servicemonitor.interval` | Prometheus scrape interval | `60s` |
| `prometheus.servicemonitor.labels` | Add custom labels to ServiceMonitor | |
| `prometheus.servicemonitor.scrapeTimeout` | Prometheus scrape timeout | `30s` |
| `podAnnotations` | Annotations to add to the cert-manager pod | `{}` |
| `deploymentAnnotations` | Annotations to add to the cert-manager deployment | `{}` |
| `podDnsPolicy` | Optional cert-manager pod [DNS policy](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pods-dns-policy) |  |
| `podDnsConfig` | Optional cert-manager pod [DNS configurations](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pods-dns-config) |  |
| `podLabels` | Labels to add to the cert-manager pod | `{}` |
| `http_proxy` | Value of the `HTTP_PROXY` environment variable in the cert-manager pod | |
| `https_proxy` | Value of the `HTTPS_PROXY` environment variable in the cert-manager pod | |
| `no_proxy` | Value of the `NO_PROXY` environment variable in the cert-manager pod | |
| `webhook.replicaCount` | Number of cert-manager webhook replicas | `1` |
| `webhook.timeoutSeconds` | Seconds the API server should wait the webhook to respond before treating the call as a failure. | `10` |
| `webhook.podAnnotations` | Annotations to add to the webhook pods | `{}` |
| `webhook.podLabels` | Labels to add to the cert-manager webhook pod | `{}` |
| `webhook.deploymentAnnotations` | Annotations to add to the webhook deployment | `{}` |
| `webhook.mutatingWebhookConfigurationAnnotations` | Annotations to add to the mutating webhook configuration | `{}` |
| `webhook.validatingWebhookConfigurationAnnotations` | Annotations to add to the validating webhook configuration | `{}` |
| `webhook.extraArgs` | Optional flags for cert-manager webhook component | `[]` |
| `webhook.serviceAccount.create` | If `true`, create a new service account for the webhook component | `true` |
| `webhook.serviceAccount.name` | Service account for the webhook component to be used. If not set and `webhook.serviceAccount.create` is `true`, a name is generated using the fullname template |  |
| `webhook.serviceAccount.annotations` | Annotations to add to the service account for the webhook component |  |
| `webhook.resources` | CPU/memory resource requests/limits for the webhook pods | `{}` |
| `webhook.nodeSelector` | Node labels for webhook pod assignment | `{}` |
| `webhook.affinity` | Node affinity for webhook pod assignment | `{}` |
| `webhook.tolerations` | Node tolerations for webhook pod assignment | `[]` |
| `webhook.image.repository` | Webhook image repository | `quay.io/jetstack/cert-manager-webhook` |
| `webhook.image.tag` | Webhook image tag | `{{RELEASE_VERSION}}` |
| `webhook.image.pullPolicy` | Webhook image pull policy | `IfNotPresent` |
| `webhook.securePort` | The port that the webhook should listen on for requests. | `10250` |
| `webhook.securityContext` | Security context for webhook pod assignment | `{}` |
| `webhook.containerSecurityContext` | Security context to be set on the webhook component container | `{}` |
| `webhook.hostNetwork` | If `true`, run the Webhook on the host network. | `false` |
| `webhook.livenessProbe.failureThreshold` | The livneness probe failure threshold | `3` |
| `webhook.livenessProbe.initialDelaySeconds` | The livneness probe initial delay (in seconds) | `60` |
| `webhook.livenessProbe.periodSeconds` | The livneness probe period (in seconds) | `10` |
| `webhook.livenessProbe.successThreshold` | The livneness probe success threshold | `1` |
| `webhook.livenessProbe.timeoutSeconds` | The livneness probe timeout (in seconds) | `1` |
| `webhook.readinessProbe.failureThreshold` | The readiness probe failure threshold | `3` |
| `webhook.readinessProbe.initialDelaySeconds` | The readiness probe initial delay (in seconds) | `5` |
| `webhook.readinessProbe.periodSeconds` | The readiness probe period (in seconds) | `5` |
| `webhook.readinessProbe.successThreshold` | The readiness probe success threshold | `1` |
| `webhook.readinessProbe.timeoutSeconds` | The readiness probe timeout (in seconds) | `1` |
| `cainjector.enabled` | Toggles whether the cainjector component should be installed (required for the webhook component to work) | `true` |
| `cainjector.replicaCount` | Number of cert-manager cainjector replicas | `1` |
| `cainjector.podAnnotations` | Annotations to add to the cainjector pods | `{}` |
| `cainjector.podLabels` | Labels to add to the cert-manager cainjector pod | `{}` |
| `cainjector.deploymentAnnotations` | Annotations to add to the cainjector deployment | `{}` |
| `cainjector.extraArgs` | Optional flags for cert-manager cainjector component | `[]` |
| `cainjector.serviceAccount.create` | If `true`, create a new service account for the cainjector component | `true` |
| `cainjector.serviceAccount.name` | Service account for the cainjector component to be used. If not set and `cainjector.serviceAccount.create` is `true`, a name is generated using the fullname template |  |
| `cainjector.serviceAccount.annotations` | Annotations to add to the service account for the cainjector component |  |
| `cainjector.resources` | CPU/memory resource requests/limits for the cainjector pods | `{}` |
| `cainjector.nodeSelector` | Node labels for cainjector pod assignment | `{}` |
| `cainjector.affinity` | Node affinity for cainjector pod assignment | `{}` |
| `cainjector.tolerations` | Node tolerations for cainjector pod assignment | `[]` |
| `cainjector.image.repository` | cainjector image repository | `quay.io/jetstack/cert-manager-cainjector` |
| `cainjector.image.tag` | cainjector image tag | `{{RELEASE_VERSION}}` |
| `cainjector.image.pullPolicy` | cainjector image pull policy | `IfNotPresent` |
| `cainjector.securityContext` | Security context for cainjector pod assignment | `{}` |
| `cainjector.containerSecurityContext` | Security context to be set on cainjector component container | `{}` |

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`.

Alternatively, a YAML file that specifies the values for the above parameters can be provided while installing the chart. For example,

```console
$ helm install --name my-release -f values.yaml .
```
> **Tip**: You can use the default [values.yaml](https://github.com/jetstack/cert-manager/blob/master/deploy/charts/cert-manager/values.yaml)

## Contributing

This chart is maintained at [github.com/jetstack/cert-manager](https://github.com/jetstack/cert-manager/tree/master/deploy/charts/cert-manager).
