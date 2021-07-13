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
$ kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v0.0.1/cert-manager.crds.yaml
```

To install the chart with the release name `my-cert-manager`:

```console
# Add the jetstack Helm repository
$ helm repo add jetstack https://charts.jetstack.io

# Install the cert-manager helm chart
$ helm install my-cert-manager jetstack/cert-manager -n cert-manager --version=v0.0.1
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

To uninstall/delete the `my-cert-manager` deployment:

```console
$ helm delete my-cert-manager
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

If you want to completely uninstall cert-manager from your cluster, you will also need to
delete the previously installed CustomResourceDefinition resources:

```console
$ kubectl delete -f https://github.com/jetstack/cert-manager/releases/download/v0.0.1/cert-manager.crds.yaml
```

## Configuration

The following table lists the configurable parameters of the cert-manager chart and their default values.

| Parameter | Description | Default |
| --------- | ----------- | ------- |
| `global.imagePullSecrets` | Reference to one or more secrets to be used when pulling images (ref: https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/) | `[]` |
| `global.priorityClassName` | Priority class name for cert-manager and webhook pods | `""` |
| `global.rbac.create` | If `true`, create and use RBAC resources (includes sub-charts) | `true` |
| `global.podSecurityPolicy.enabled` | If `true`, create and use PodSecurityPolicy (includes sub-charts) | `false` |
| `global.podSecurityPolicy.useAppArmor` | If `true`, use Apparmor seccomp profile in PSP | `true` |
| `global.logLevel` | Set the verbosity of cert-manager. Range of 0 - 6 with 6 being the most verbose. | `2` |
| `global.leaderElection.namespace` | Override the namespace used to store the ConfigMap for leader election | `"kube-system"` |
| `global.leaderElection.leaseDuration` | The duration that non-leader candidates will wait after observing a leadership renewal until attempting to acquire leadership of a led but unrenewed leader slot. This is effectively the maximum duration that a leader can be stopped before it is replaced by another candidate. <pre lang="yaml">leaseDuration: 60s</pre> | `` |
| `global.leaderElection.renewDeadline` | The interval between attempts by the acting master to renew a leadership slot before it stops leading. This must be less than or equal to the lease duration. <pre lang="yaml">renewDeadline: 40s</pre> | `` |
| `global.leaderElection.retryPeriod` | The duration the clients should wait between attempting acquisition and renewal of a leadership. <pre lang="yaml">retryPeriod: 15s</pre> | `` |
| `installCRDs` | If true, CRD resources will be installed as part of the Helm chart. If enabled, when uninstalling CRD resources will be deleted causing all installed custom resources to be DELETED. | `false` |
| `replicaCount` | Number of cert-manager replicas | `1` |
| `strategy` | <pre lang="yaml">strategy:<br>  type: RollingUpdate<br>  rollingUpdate:<br>    maxSurge: 0<br>    maxUnavailable: 1</pre> | `{}` |
| `featureGates` | Comma separated list of feature gates that should be enabled on the controller pod. | `""` |
| `image.repository` | Image repository | `quay.io/jetstack/cert-manager-controller` |
| `image.registry` | You can manage a registry with <pre lang="yaml">registry: quay.io<br>repository: jetstack/cert-manager-controller</pre> | `` |
| `image.tag` | Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion will be used. <pre lang="yaml">tag: canary</pre> | `` |
| `image.digest` | Setting a digest will override any tag <pre lang="yaml">digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20</pre> | `` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `clusterResourceNamespace` | Override the namespace used to store DNS provider credentials etc. for ClusterIssuer resources. By default, the same namespace as cert-manager is deployed within is used. This namespace will not be automatically created by the Helm chart. | `""` |
| `serviceAccount.create` | If `true`, create a new service account for the cert-manager controller | `true` |
| `serviceAccount.name` | The name of the service account for the cert-manager controller to be used. If not set and `serviceAccount.create` is `true`, a name is generated using the fullname template | `` |
| `serviceAccount.annotations` | Annotations to add to the service account for the cert-manager controller | `` |
| `serviceAccount.automountServiceAccountToken` | Automount API credentials for the cert-manager service account | `true` |
| `extraArgs` | Optional additional arguments for cert-manager <pre lang="yaml">extraArgs:<br> # Use this flag to set a namespace that cert-manager will use to store<br> # supporting resources required for each ClusterIssuer (default is kube-system)<br> - --cluster-resource-namespace=kube-system<br> # When this flag is enabled, secrets will be automatically removed when the certificate resource is deleted<br> - --enable-certificate-owner-ref=true<br> # Use this flag to enabled or disable arbitrary controllers, for example, disable the CertificiateRequests approver<br> - --controllers=*,-certificaterequests-approver</pre> | `[]` |
| `extraEnv` | Optional additional environment variables for cert-manager <pre lang="yaml">extraEnv:<br>- name: SOME_VAR<br>  value: 'some value'</pre> | `[]` |
| `resources` | <pre lang="yaml">resources:<br>  requests:<br>    cpu: 10m<br>    memory: 32Mi</pre> | `{}` |
| `securityContext.runAsNonRoot` |  | `true` |
| `containerSecurityContext` | Container Security Context to be set on the controller component container (ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) <pre lang="yaml">containerSecurityContext:<br>  capabilities:<br>    drop:<br>    - ALL<br>  readOnlyRootFilesystem: true<br>  runAsNonRoot: true</pre> | `{}` |
| `volumes` | Volumes to add to cert-manager | `[]` |
| `volumeMounts` | Volume mounts to add to cert-manager | `[]` |
| `deploymentAnnotations` | Annotations to add to the cert-manager deployment | `` |
| `podAnnotations` | Annotations to add to the cert-manager pod | `` |
| `podLabels` | Labels to add to the cert-manager pod | `{}` |
| `serviceLabels` | Labels to add to the cert-manager controller service | `` |
| `podDnsPolicy` | Optional cert-manager pod [DNS policy](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pods-dns-policy) Useful if you have a public and private DNS zone for the same domain on Route 53. What follows is an example of ensuring cert-manager can access an ingress or DNS TXT records at all times. **NOTE:** This requires Kubernetes 1.10 or `CustomPodDNS` feature gate enabled for the cluster to work. <pre lang="yaml">podDnsPolicy: "None"</pre> | `` |
| `podDnsConfig` | Optional cert-manager pod [DNS configurations](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pods-dns-config) <pre lang="yaml">podDnsConfig:<br>  nameservers:<br>    - "1.1.1.1"<br>    - "8.8.8.8"</pre> | `` |
| `nodeSelector` | Node labels for pod assignment | `{}` |
| `ingressShim` | <pre lang="yaml">ingressShim:<br>  defaultIssuerName: ""<br>  defaultIssuerKind: ""<br>  defaultIssuerGroup: ""</pre> | `{}` |
| `prometheus.enabled` | If `true`, enable Prometheus monitoring | `true` |
| `prometheus.servicemonitor.enabled` | Enable Prometheus Operator ServiceMonitor monitoring | `false` |
| `prometheus.servicemonitor.prometheusInstance` | Prometheus Instance definition | `default` |
| `prometheus.servicemonitor.targetPort` | Prometheus scrape port | `9402` |
| `prometheus.servicemonitor.path` | Prometheus scrape path | `/metrics` |
| `prometheus.servicemonitor.interval` | Prometheus scrape interval | `60s` |
| `prometheus.servicemonitor.scrapeTimeout` | Prometheus scrape timeout | `30s` |
| `prometheus.servicemonitor.labels` | Add custom labels to ServiceMonitor | `{}` |
| `http_proxy` | Value of the `HTTP_PROXY` environment variable in the cert-manager pod <pre lang="yaml">http_proxy: "http://proxy:8080"</pre> | `` |
| `https_proxy` | Value of the `HTTPS_PROXY` environment variable in the cert-manager pod <pre lang="yaml">https_proxy: "https://proxy:8080"</pre> | `` |
| `no_proxy` | Value of the `NO_PROXY` environment variable in the cert-manager pod <pre lang="yaml">no_proxy: 127.0.0.1,localhost</pre> | `` |
| `affinity` | Node affinity for pod assignment expects input structure as per specification https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.11/#affinity-v1-core <pre lang="yaml">affinity:<br>  nodeAffinity:<br>    requiredDuringSchedulingIgnoredDuringExecution:<br>      nodeSelectorTerms:<br>      - matchExpressions:<br>        - key: foo.bar.com/role<br>          operator: In<br>          values:<br>          - master</pre> | `{}` |
| `tolerations` | Node tolerations for pod assignment expects input structure as per specification https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.11/#toleration-v1-core <pre lang="yaml">tolerations:<br>- key: foo.bar.com/role<br>  operator: Equal<br>  value: master<br>  effect: NoSchedule</pre> | `[]` |
| `webhook.replicaCount` | Number of cert-manager webhook replicas | `1` |
| `webhook.timeoutSeconds` | Seconds the API server should wait the webhook to respond before treating the call as a failure. | `10` |
| `webhook.strategy` | <pre lang="yaml">strategy:<br>  type: RollingUpdate<br>  rollingUpdate:<br>    maxSurge: 0<br>    maxUnavailable: 1</pre> | `{}` |
| `webhook.securityContext.runAsNonRoot` |  | `true` |
| `webhook.containerSecurityContext` | Container Security Context to be set on the webhook component container (ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) <pre lang="yaml">containerSecurityContext:<br>  capabilities:<br>    drop:<br>    - ALL<br>  readOnlyRootFilesystem: true<br>  runAsNonRoot: true</pre> | `{}` |
| `webhook.deploymentAnnotations` | Annotations to add to the webhook deployment | `` |
| `webhook.podAnnotations` | Annotations to add to the webhook pods | `` |
| `webhook.mutatingWebhookConfigurationAnnotations` | Annotations to add to the webhook MutatingWebhookConfiguration | `` |
| `webhook.validatingWebhookConfigurationAnnotations` | Annotations to add to the webhook ValidatingWebhookConfiguration | `` |
| `webhook.extraArgs` | Optional additional arguments for webhook | `[]` |
| `webhook.resources` | CPU/memory resource requests/limits for the webhook pods <pre lang="yaml">resources:<br>  requests:<br>    cpu: 10m<br>    memory: 32Mi</pre> | `{}` |
| `webhook.livenessProbe.failureThreshold` | The liveness probe failure threshold | `3` |
| `webhook.livenessProbe.initialDelaySeconds` | The liveness probe initial delay (in seconds) | `60` |
| `webhook.livenessProbe.periodSeconds` | The liveness probe period (in seconds) | `10` |
| `webhook.livenessProbe.successThreshold` | The liveness probe success threshold | `1` |
| `webhook.livenessProbe.timeoutSeconds` | The liveness probe timeout (in seconds) | `1` |
| `webhook.readinessProbe.failureThreshold` | The readiness probe failure threshold | `3` |
| `webhook.readinessProbe.initialDelaySeconds` | The readiness probe initial delay (in seconds) | `5` |
| `webhook.readinessProbe.periodSeconds` | The readiness probe period (in seconds) | `5` |
| `webhook.readinessProbe.successThreshold` | The readiness probe success threshold | `1` |
| `webhook.readinessProbe.timeoutSeconds` | The readiness probe timeout (in seconds) | `1` |
| `webhook.nodeSelector` | Node labels for pod assignment | `{}` |
| `webhook.affinity` | Node affinity for pod assignment | `{}` |
| `webhook.tolerations` | Node tolerations for pod assignment | `[]` |
| `webhook.podLabels` | Optional additional labels to add to the Webhook Pods | `{}` |
| `webhook.image.repository` | Image repository | `quay.io/jetstack/cert-manager-webhook` |
| `webhook.image.registry` | You can manage a registry with <pre lang="yaml">registry: quay.io<br>repository: jetstack/cert-manager-webhook</pre> | `` |
| `webhook.image.tag` | Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion will be used. <pre lang="yaml">tag: canary</pre> | `` |
| `webhook.image.digest` | Setting a digest will override any tag <pre lang="yaml">digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20</pre> | `` |
| `webhook.image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `webhook.serviceAccount.create` | If `true`, create a new service account for the webhook component | `true` |
| `webhook.serviceAccount.name` | The name of the service account for the webhook component to be used. If not set and `webhook.serviceAccount.create` is `true`, a name is generated using the fullname template | `` |
| `webhook.serviceAccount.annotations` | Annotations to add to the service account for the webhook component | `` |
| `webhook.serviceAccount.automountServiceAccountToken` | Automount API credentials for the webhook service account | `true` |
| `webhook.securePort` | The port that the webhook should listen on for requests. In GKE private clusters, by default kubernetes apiservers are allowed to talk to the cluster nodes only on 443 and 10250. so configuring securePort: 10250, will work out of the box without needing to add firewall rules or requiring NET_BIND_SERVICE capabilities to bind port numbers <1000 | `10250` |
| `webhook.hostNetwork` | Specifies if the webhook should be started in hostNetwork mode.  Required for use in some managed kubernetes clusters (such as AWS EKS) with custom CNI (such as calico), because control-plane managed by AWS cannot communicate with pods' IP CIDR and admission webhooks are not working  Since the default port for the webhook conflicts with kubelet on the host network, `webhook.securePort` should be changed to an available port if running in hostNetwork mode. | `false` |
| `webhook.serviceType` | The type of the `Service`. Specifies how the service should be handled. Useful if you want to expose the webhook to outside of the cluster. In some cases, the control plane cannot reach internal services. | `ClusterIP` |
| `webhook.loadBalancerIP` | The specific load balancer IP to use (when `serviceType` is `LoadBalancer`). | `` |
| `webhook.url` | Overrides the mutating webhook and validating webhook so they reach the webhook service using the `url` field instead of a service. | `{}` |
| `cainjector.enabled` | If `true`, install the cainjector (required for the webhook component to work) | `true` |
| `cainjector.replicaCount` | Number of cert-manager cainjector replicas | `1` |
| `cainjector.strategy` | <pre lang="yaml">strategy:<br>  type: RollingUpdate<br>  rollingUpdate:<br>    maxSurge: 0<br>    maxUnavailable: 1</pre> | `{}` |
| `cainjector.securityContext.runAsNonRoot` |  | `true` |
| `cainjector.containerSecurityContext` | Container Security Context to be set on the cainjector component container (ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) <pre lang="yaml">containerSecurityContext:<br>  capabilities:<br>    drop:<br>    - ALL<br>  readOnlyRootFilesystem: true<br>  runAsNonRoot: true</pre> | `{}` |
| `cainjector.deploymentAnnotations` | Optional additional annotations to add to the cainjector Deployment | `` |
| `cainjector.podAnnotations` | Optional additional annotations to add to the cainjector Pods | `` |
| `cainjector.extraArgs` | Optional additional arguments for cainjector | `[]` |
| `cainjector.resources` | CPU/memory resource requests/limits for the cainjector pods <pre lang="yaml">resources:<br>  requests:<br>    cpu: 10m<br>    memory: 32Mi</pre> | `{}` |
| `cainjector.nodeSelector` | Node labels for cainjector pod assignment | `{}` |
| `cainjector.affinity` | Node affinity for cainjector pod assignment | `{}` |
| `cainjector.tolerations` | Node tolerations for cainjector pod assignment | `[]` |
| `cainjector.podLabels` | Labels to add to the cert-manager cainjector pod | `{}` |
| `cainjector.image.repository` | Image repository | `quay.io/jetstack/cert-manager-cainjector` |
| `cainjector.image.registry` | You can manage a registry with <pre lang="yaml">registry: quay.io<br>repository: jetstack/cert-manager-cainjector</pre> | `` |
| `cainjector.image.tag` | Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion will be used. <pre lang="yaml">tag: canary</pre> | `` |
| `cainjector.image.digest` | Setting a digest will override any tag <pre lang="yaml">digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20</pre> | `` |
| `cainjector.image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `cainjector.serviceAccount.create` | If `true`, create a new service account for the cainjector component | `true` |
| `cainjector.serviceAccount.name` | The name of the service account for the cainjector component to be used. If not set and `cainjector.serviceAccount.create` is `true`, a name is generated using the fullname template | `` |
| `cainjector.serviceAccount.annotations` | Annotations to add to the service account for the cainjector component | `` |
| `cainjector.serviceAccount.automountServiceAccountToken` | Automount API credentials for the cainjector service account | `true` |

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`.

Alternatively, a YAML file that specifies the values for the above parameters can be provided while installing the chart. For example,

```console
$ helm install my-cert-manager jetstack/cert-manager -n cert-manager --version=v0.0.1 --values values.yaml
```
> **Tip**: You can use the default [values.yaml](https://github.com/jetstack/cert-manager/blob/master/deploy/charts/cert-manager/values.yaml)

## Contributing

This chart is maintained at [github.com/jetstack/cert-manager](https://github.com/jetstack/cert-manager/tree/master/deploy/charts/cert-manager).
