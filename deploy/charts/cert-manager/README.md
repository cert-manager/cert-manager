# cert-manager

cert-manager is a Kubernetes addon to automate the management and issuance of
TLS certificates from various issuing sources.

It will ensure certificates are valid and up to date periodically, and attempt
to renew certificates at an appropriate time before expiry.

## Prerequisites

- Kubernetes 1.12+

## Installing the Chart

Full installation instructions, including details on how to configure extra
functionality in cert-manager can be found in the [getting started docs](https://docs.cert-manager.io/en/latest/getting-started/).

To install the chart with the release name `my-release`:

```console
## IMPORTANT: you MUST install the cert-manager CRDs **before** installing the
## cert-manager Helm chart.
$ kubectl apply --validate=false \
    -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.14/deploy/manifests/00-crds.yaml

## If you are installing on openshift :
$ oc create \
    -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.14/deploy/manifests/00-crds.yaml

## NOTE: if you are installing the Helm chart into a namespace other than
## 'cert-manager', you **must** replace all occurrences of 'namespace: cert-manager'
## with 'namespace: custom-namespace-name' in the CRDs manifest.
## The below snippet can be used to automate this, replacing
## CUSTOM-NAMESPACE-NAME with the deployment namespace's name:
##
##   kubectl apply --dry-run -o yaml --validate=false \
##      -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.14/deploy/manifests/00-crds.yaml \
##      | sed 's/namespace\: cert-manager/namespace\: CUSTOM-NAMESPACE-NAME/g' \
##      | kubectl apply -f -

## Add the Jetstack Helm repository
$ helm repo add jetstack https://charts.jetstack.io

## Install the cert-manager helm chart
$ helm install --name my-release --namespace cert-manager jetstack/cert-manager
```

In order to begin issuing certificates, you will need to set up a ClusterIssuer
or Issuer resource (for example, by creating a 'letsencrypt-staging' issuer).

More information on the different types of issuers and how to configure them
can be found in our documentation:

https://docs.cert-manager.io/en/latest/tasks/issuers/index.html

For information on how to configure cert-manager to automatically provision
Certificates for Ingress resources, take a look at the `ingress-shim`
documentation:

https://docs.cert-manager.io/en/latest/tasks/issuing-certificates/ingress-shim.html

> **Tip**: List all releases using `helm list`

## Upgrading the Chart

Special considerations may be required when upgrading the Helm chart, and these
are documented in our full [upgrading guide](https://docs.cert-manager.io/en/latest/tasks/upgrading/index.html).
Please check here before perform upgrades!

## Uninstalling the Chart

To uninstall/delete the `my-release` deployment:

```console
$ helm delete my-release
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

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
| `image.repository` | Image repository | `quay.io/jetstack/cert-manager-controller` |
| `image.tag` | Image tag | `v0.14.0` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `replicaCount`  | Number of cert-manager replicas  | `1` |
| `clusterResourceNamespace` | Override the namespace used to store DNS provider credentials etc. for ClusterIssuer resources | Same namespace as cert-manager pod |
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
| `nodeSelector` | Node labels for pod assignment | `{}` |
| `affinity` | Node affinity for pod assignment | `{}` |
| `tolerations` | Node tolerations for pod assignment | `[]` |
| `ingressShim.defaultIssuerName` | Optional default issuer to use for ingress resources |  |
| `ingressShim.defaultIssuerKind` | Optional default issuer kind to use for ingress resources |  |
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
| `webhook.serviceName` | The name of the Service resource deployed for the webhook pod | `cert-manager-webhook` |
| `webhook.podAnnotations` | Annotations to add to the webhook pods | `{}` |
| `webhook.deploymentAnnotations` | Annotations to add to the webhook deployment | `{}` |
| `webhook.extraArgs` | Optional flags for cert-manager webhook component | `[]` |
| `webhook.resources` | CPU/memory resource requests/limits for the webhook pods | `{}` |
| `webhook.nodeSelector` | Node labels for webhook pod assignment | `{}` |
| `webhook.affinity` | Node affinity for webhook pod assignment | `{}` |
| `webhook.tolerations` | Node tolerations for webhook pod assignment | `[]` |
| `webhook.image.repository` | Webhook image repository | `quay.io/jetstack/cert-manager-webhook` |
| `webhook.image.tag` | Webhook image tag | `v0.14.0` |
| `webhook.image.pullPolicy` | Webhook image pull policy | `IfNotPresent` |
| `webhook.injectAPIServerCA` | if true, the apiserver's CABundle will be automatically injected into the ValidatingWebhookConfiguration resource | `true` |
| `webhook.securePort` | The port that the webhook should listen on for requests. | `10250` |
| `webhook.securityContext` | Security context for webhook pod assignment | `{}` |
| `cainjector.enabled` | Toggles whether the cainjector component should be installed (required for the webhook component to work) | `true` |
| `cainjector.replicaCount` | Number of cert-manager cainjector replicas | `1` |
| `cainjector.podAnnotations` | Annotations to add to the cainjector pods | `{}` |
| `cainjector.deploymentAnnotations` | Annotations to add to the cainjector deployment | `{}` |
| `cainjector.extraArgs` | Optional flags for cert-manager cainjector component | `[]` |
| `cainjector.resources` | CPU/memory resource requests/limits for the cainjector pods | `{}` |
| `cainjector.nodeSelector` | Node labels for cainjector pod assignment | `{}` |
| `cainjector.affinity` | Node affinity for cainjector pod assignment | `{}` |
| `cainjector.tolerations` | Node tolerations for cainjector pod assignment | `[]` |
| `cainjector.image.repository` | cainjector image repository | `quay.io/jetstack/cert-manager-cainjector` |
| `cainjector.image.tag` | cainjector image tag | `v0.14.0` |
| `cainjector.image.pullPolicy` | cainjector image pull policy | `IfNotPresent` |
| `cainjector.securityContext` | Security context for cainjector pod assignment | `{}` |

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`.

Alternatively, a YAML file that specifies the values for the above parameters can be provided while installing the chart. For example,

```console
$ helm install --name my-release -f values.yaml .
```
> **Tip**: You can use the default [values.yaml](values.yaml)

## Contributing

This chart is maintained at [github.com/jetstack/cert-manager](https://github.com/jetstack/cert-manager/tree/master/deploy/charts/cert-manager).
